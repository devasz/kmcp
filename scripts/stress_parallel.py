"""Stress: N VMs in ONE kmcp process, driven by N concurrent clients (what N autonomous subagents would do).
Checks isolation (registers, memory, serial), crash containment (one VM triple-faults), footprint (RSS, fds) and clean teardown.
Usage: stress_parallel.py [binary] [vms=10] [iterations=40]"""
import json, os, re, shutil, statistics, subprocess, sys, tempfile, threading, time
HERE = os.path.dirname(os.path.abspath(__file__))
BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "target", "release", "kmcp")
VMS = int(sys.argv[2]) if len(sys.argv) > 2 else 10
ITERS = int(sys.argv[3]) if len(sys.argv) > 3 else 40
RUN_ROOT = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "qmcp")
SCRATCH = 0x200000  # free guest-physical RAM
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        fails.append(name)


class Client:
    """One MCP stdio connection shared by many threads: a reader thread routes responses to waiting callers by id."""

    def __init__(self, binary, *flags):
        self.p = subprocess.Popen([binary, *flags], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.lock, self.n, self.waiting, self.lat = threading.Lock(), 0, {}, []
        threading.Thread(target=self._read, daemon=True).start()
        self.call_raw("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "stress", "version": "0"}})
        self._write({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _write(self, msg):
        with self.lock:
            self.p.stdin.write(json.dumps(msg) + "\n")
            self.p.stdin.flush()

    def _read(self):
        for line in self.p.stdout:
            msg = json.loads(line)
            slot = self.waiting.pop(msg.get("id"), None)
            if slot:
                slot[1].update(msg)
                slot[0].set()

    def call_raw(self, method, params):
        with self.lock:
            self.n += 1
            rid = self.n
        slot = (threading.Event(), {})
        self.waiting[rid] = slot
        self._write({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        slot[0].wait(120)
        return slot[1]

    def ok(self, tool, **args):
        t0 = time.perf_counter()
        msg = self.call_raw("tools/call", {"name": tool, "arguments": args})
        self.lat.append(time.perf_counter() - t0)
        res = msg.get("result") or {}
        text = "".join(c.get("text", "") for c in res.get("content", []))
        if "error" in msg or res.get("isError") or not msg:
            raise RuntimeError(f"{tool}({args}) failed: {msg.get('error') or text}")
        try:
            return json.loads(text)
        except ValueError:
            return text


def proc_kb(pid, field):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith(field):
            return int(line.split()[1])
    return 0


def qemus():
    return subprocess.run(["pgrep", "-c", "-f", "qemu-system-x86_64.*qmcp"], capture_output=True, text=True).stdout.strip() or "0"


def worker(c, idx, vm_id, errors):
    """What one subagent does: poke its own VM many times and verify nothing of another VM leaks in."""
    uid = 0x1000 + idx
    try:
        for i in range(ITERS):
            marker = (uid << 16 | i).to_bytes(4, "little").hex()
            original = c.ok("regs", vm_id=vm_id, names=["rbx"])["rbx"]  # stepping runs real SeaBIOS: probe rbx, then put the guest's value back
            c.ok("regs", vm_id=vm_id, set={"name": "rbx", "value": hex(uid)})
            c.ok("mem", vm_id=vm_id, action="write", at=hex(SCRATCH), hex=marker, phys=True)
            rbx = int(c.ok("regs", vm_id=vm_id, names=["rbx"])["rbx"], 16)
            back = c.ok("mem", vm_id=vm_id, action="read", at=hex(SCRATCH), len=4, phys=True)["hex"]
            if rbx != uid or back != marker:
                errors.append(f"vm{idx} iter{i}: rbx={hex(rbx)} (want {hex(uid)}) mem={back} (want {marker})")
                return
            c.ok("regs", vm_id=vm_id, set={"name": "rbx", "value": original})
            c.ok("step", vm_id=vm_id)
    except Exception as e:  # a worker must report, never die silently
        errors.append(f"vm{idx}: {e}")


def main():
    tmp = tempfile.mkdtemp(prefix="stress-")
    for name in ("idle", "triple"):
        subprocess.run(["nasm", "-f", "bin", f"{HERE}/fixtures/{name}.asm", "-o", f"{tmp}/{name}.img"], check=True)
    c = Client(BIN, "--unsafe")
    pid = c.p.pid
    rss0, fds0 = proc_kb(pid, "VmRSS"), len(os.listdir(f"/proc/{pid}/fd"))
    t0 = time.time()
    ids = []
    try:
        launch_threads, launched, launch_errors = [], {}, []
        def launch(i):
            image = f"{tmp}/vm{i}.img"  # one image per VM: QEMU write-locks a disk, as it should
            shutil.copy(f"{tmp}/{'triple' if i == VMS - 1 else 'idle'}.img", image)
            try:
                launched[i] = c.ok("vm_launch", machine="pc", mem_mb=64, drives=[{"file": image, "format": "raw"}])["vm_id"]
            except RuntimeError as e:
                launch_errors.append(str(e))
        for i in range(VMS):
            t = threading.Thread(target=launch, args=(i,))
            t.start()
            launch_threads.append(t)
        for t in launch_threads:
            t.join()
        check("no launch errors", not launch_errors, "; ".join(launch_errors[:2]))
        ids = [launched[i] for i in range(VMS) if i in launched]
        if launch_errors:
            return
        check(f"{VMS} VMs launched concurrently with distinct ids", len(set(ids)) == VMS, str(ids))
        print(f"INFO launch of {VMS} VMs: {time.time() - t0:.2f}s, qemu processes: {qemus()}")

        c.ok("vm_control", vm_id=ids[VMS - 1], action="continue")  # the last VM runs free into a triple fault
        crash = c.ok("vm_wait", vm_id=ids[VMS - 1], timeout_ms=15000)
        check("one VM's triple fault is detected", re.search(r"triple", json.dumps(crash)) is not None, json.dumps(crash)[:200])

        errors, threads = [], []
        t1 = time.time()
        for i in range(VMS - 1):  # the healthy VMs
            t = threading.Thread(target=worker, args=(c, i, ids[i], errors))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        elapsed = time.time() - t1
        check(f"{VMS - 1} concurrent workers x {ITERS} iterations: registers and memory isolated, no errors", not errors, "; ".join(errors[:3]))
        calls = len(c.lat)
        lat = sorted(c.lat)
        print(f"INFO {calls} tool calls in {elapsed:.1f}s ({calls / elapsed:.0f}/s) under load: p50 {statistics.median(lat) * 1000:.2f} ms, p95 {lat[int(len(lat) * .95)] * 1000:.2f} ms, max {lat[-1] * 1000:.1f} ms")

        healthy = [c.ok("vm_wait", vm_id=ids[i], timeout_ms=300)["state"] for i in range(VMS - 1)]
        check("healthy VMs unaffected by the crashed one", all(s == "stopped" for s in healthy), str(set(healthy)))
        for i in range(VMS - 1):
            c.ok("vm_control", vm_id=ids[i], action="continue")
        for i in range(VMS - 1):  # let SeaBIOS boot the sector; the wait returns as soon as that VM's own HELLO appears
            c.ok("vm_wait", vm_id=ids[i], timeout_ms=20000, serial_regex="HELLO")
        rings = [c.ok("log_read", vm_id=ids[i], source="serial", tail=100)["text"] for i in range(VMS - 1)]
        check("every VM's serial ring holds exactly its own HELLO (no cross-talk)", all(r.count("HELLO") == 1 for r in rings), str([r.count("HELLO") for r in rings]))
        rss, hwm, fds = proc_kb(pid, "VmRSS"), proc_kb(pid, "VmHWM"), len(os.listdir(f"/proc/{pid}/fd"))
        print(f"INFO kmcp with {VMS} VMs: RSS {rss / 1024:.1f} MiB (idle {rss0 / 1024:.1f}), peak {hwm / 1024:.1f} MiB, fds {fds} (idle {fds0}), qemu processes {qemus()}")
        check("kmcp RSS stays under 64 MiB with all VMs live", hwm < 64 * 1024, f"{hwm} KiB")
    finally:
        for vid in ids:
            try:
                c.ok("vm_control", vm_id=vid, action="kill")
            except RuntimeError:
                pass
    time.sleep(1)
    fds_after = len(os.listdir(f"/proc/{pid}/fd"))
    check("all fds released after killing every VM (no leak)", fds_after <= fds0 + 1, f"{fds_after} vs idle {fds0}")
    check("no qemu left, no stale run dirs", qemus() == "0" and not (os.path.isdir(RUN_ROOT) and os.listdir(RUN_ROOT)), f"{qemus()} {os.listdir(RUN_ROOT) if os.path.isdir(RUN_ROOT) else []}")
    c.p.stdin.close()
    c.p.wait(10)
    shutil.rmtree(tmp, ignore_errors=True)
    print("RESULT:", "ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
    sys.exit(1 if fails else 0)


main()
