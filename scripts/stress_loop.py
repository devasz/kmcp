"""Soak: what an unattended agent loop does to one kmcp process: restore a snapshot N times after trashing the guest,
then N launch/kill cycles.  Checks state fidelity every round and that fds, RSS and qemu processes do not grow.
Usage: stress_loop.py [binary] [rounds=100]"""
import os, shutil, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from mcpc import Mcp

BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "target", "release", "kmcp")
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 100
RUN_ROOT = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "qmcp")
SCRATCH = 0x200000
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        fails.append(name)


def footprint(pid):
    rss = next(int(l.split()[1]) for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS"))
    return rss // 1024, len(os.listdir(f"/proc/{pid}/fd"))


def qemus():
    return len(subprocess.run(["pgrep", "-x", "qemu-system-x86"], capture_output=True, text=True).stdout.split())


def launch(m, img):
    m.ok("vm_launch", machine="pc", mem_mb=64, drives=[{"file": img, "format": "raw"}])


def snapshot_rounds(m, img):
    launch(m, img)
    m.ok("vm_wait", timeout_ms=1)  # frozen at reset; snapshot the pristine state
    m.ok("snapshot", action="save", name="clean")
    base = m.ok("regs")
    bad, t0 = [], time.time()
    for i in range(ROUNDS):
        m.ok("mem", action="write", at=hex(SCRATCH), hex="deadbeef", phys=True)
        m.ok("regs", set={"name": "rbx", "value": hex(0x1000 + i)})
        m.ok("snapshot", action="load", name="clean")
        if m.ok("regs") != base or m.ok("mem", action="read", at=hex(SCRATCH), len=4, phys=True)["hex"] == "deadbeef":
            bad.append(i)
    print(f"INFO {ROUNDS} snapshot restores in {time.time() - t0:.1f}s")
    check(f"{ROUNDS} trash-then-restore rounds return the exact saved registers and memory", not bad, str(bad[:5]))
    m.ok("vm_control", action="kill")


def main():
    tmp = tempfile.mkdtemp(prefix="loop-")
    subprocess.run(["nasm", "-f", "bin", f"{HERE}/fixtures/idle.asm", "-o", f"{tmp}/idle.img"], check=True)
    m = Mcp(BIN, "--unsafe")
    pid = m.p.pid
    base_rss, base_fds = footprint(pid)
    try:
        snapshot_rounds(m, f"{tmp}/idle.img")
        mid_rss, mid_fds = footprint(pid)
        t0 = time.time()
        for _ in range(ROUNDS):
            launch(m, f"{tmp}/idle.img")
            m.ok("vm_control", action="kill")
        print(f"INFO {ROUNDS} launch/kill cycles in {time.time() - t0:.1f}s")
        rss, fds = footprint(pid)
        print(f"INFO rss MiB: start {base_rss}, after restores {mid_rss}, after cycles {rss}; fds: {base_fds} / {mid_fds} / {fds}")
        check("no fd leak across the whole soak", fds <= base_fds + 1, f"{fds} vs {base_fds}")
        check("RSS growth stays under 20 MiB", rss - base_rss < 20, f"{base_rss} -> {rss}")
    finally:
        m.close()
    time.sleep(0.5)
    stale = os.listdir(RUN_ROOT) if os.path.isdir(RUN_ROOT) else []
    check("no orphan qemu, no stale run dirs", qemus() == 0 and not stale, f"{qemus()} {stale}")
    shutil.rmtree(tmp, ignore_errors=True)
    print("RESULT:", "ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
    sys.exit(1 if fails else 0)


main()
