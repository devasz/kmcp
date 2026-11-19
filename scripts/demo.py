#!/usr/bin/env python3
"""Live E2E demo + benchmarks for kmcp against real QEMU. Reproduces T1-T5 and the safety gates.

    cargo build --release && python3 scripts/demo.py [path/to/kmcp]

Needs qemu-system-{x86_64,aarch64,riscv64}, qemu-img, nasm and llvm-mc on PATH. Exit code 0 = every check passed.
"""
import json, os, signal, socket, statistics, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from mcpc import Mcp

BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "target", "release", "kmcp")
TMP = tempfile.mkdtemp(prefix="qmcp-demo-")
FAILS = []


def check(name, cond, detail=""):
    print(("  PASS " if cond else "  FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def img(name):
    out = os.path.join(TMP, name + ".img")
    subprocess.run(["nasm", "-f", "bin", os.path.join(HERE, "fixtures", name + ".asm"), "-o", out], check=True)
    return out


def boot(m, name, **kw):
    return m.ok("vm_launch", machine="pc", mem_mb=64, drives=[{"file": img(name), "format": "raw"}], **kw)


def qemu_pids():
    out = subprocess.run(["pgrep", "-f", TMP], capture_output=True, text=True).stdout.split()
    return [int(p) for p in out if int(p) != os.getpid()]


def t1_reset_to_bootsector():
    print("T1 reset vector, memory, step, breakpoint at linear 0x7c00")
    m = Mcp(BIN, "--unsafe")
    boot(m, "idle")
    w = m.ok("vm_wait", timeout_ms=100)
    check("reset pc=0xfff0 cs=0xf000", w["pc"] == "0xfff0" and w["regs"]["cs"] == "0xf000")
    check("linear pc 0xfffffff0", w["linear_pc"] == "0xfffffff0")
    mem = m.ok("mem", action="read", at="0xfffffff0", len=8)
    check("reset vector bytes ea5be000f030362f", mem["hex"] == "ea5be000f030362f", mem["hex"])
    check("bundle disassembles real-mode far jmp", "jmp far" in w["code"][0]["text"])
    st = m.ok("step")
    check("single step lands in BIOS", st["pc"] != "0xfff0")
    m.ok("breakpoint", action="set", at="0x7c00", kind="hw")
    m.ok("vm_control", action="continue")
    w = m.ok("vm_wait", timeout_ms=20000)
    check("hw breakpoint hit at 0x7c00", w["pc"] == "0x7c00" and w["state"] == "stopped", str(w.get("pc")))
    check("boot-sector code decoded", w["code"][0]["text"] == "xor ax,ax")
    m.ok("breakpoint", action="clear", at="0x7c00", kind="hw")
    m.ok("vm_control", action="continue")
    w = m.ok("vm_wait", timeout_ms=5000, serial_regex="HELLO")
    check("serial regex wait sees HELLO", w["matched"] and "HELLO" in w["matched"], str(w.get("matched")))
    m.ok("serial_write", text="x\\n", escapes=True)
    check("managed reset really resets the CPU", m.ok("vm_control", action="reset")["pc"] == "0xfff0")
    m.ok("vm_control", action="continue")
    w = m.ok("vm_wait", timeout_ms=20000)  # SeaBIOS issues one extra warm reset after a host reset; the freeze policy stops on it
    check("post-reset guest reset freezes, not hangs", w["state"] == "stopped" and "crash" in w, str(w.get("crash")))
    check("resume from frozen state is refused", m.call("vm_control", action="continue")[0])
    m.ok("vm_control", action="kill"); m.close()


def t2_crash_and_hang_triage():
    print("T2 triple fault / dead hang vs idle / pvpanic / snapshot-after-crash")
    m = Mcp(BIN, "--unsafe")
    boot(m, "triple"); m.ok("vm_control", action="continue")
    w = m.ok("vm_wait", timeout_ms=15000)
    check("triple fault classified", w.get("crash", {}).get("class") == "triple_fault", str(w.get("crash")))
    snap = m.call("snapshot", action="save", name="after-crash")
    check("snapshot works after the crash", not snap[0], str(snap[1])[:200])
    m.ok("vm_control", action="kill")
    boot(m, "dead"); m.ok("vm_control", action="continue"); time.sleep(1)
    check("cli;hlt = dead_hang", m.ok("vm_status", probe_hang=True)["hang_probe"]["verdict"]["class"] == "dead_hang")
    m.ok("vm_control", action="kill")
    boot(m, "idle"); m.ok("vm_control", action="continue"); time.sleep(1)
    check("sti;hlt = idle", m.ok("vm_status", probe_hang=True)["hang_probe"]["verdict"]["class"] == "idle")
    m.ok("vm_control", action="kill")
    boot(m, "panic", pvpanic=True); m.ok("vm_control", action="continue")
    w = m.ok("vm_wait", timeout_ms=10000)
    check("pvpanic -> guest_panic", w.get("crash", {}).get("class") == "guest_panic", str(w.get("crash")))
    m.ok("vm_control", action="kill"); m.close()


def t3_snapshot_rewind(replay):
    print("T3 snapshot / rewind" + (" + experimental replay" if replay else ""))
    m = Mcp(BIN, "--unsafe")
    boot(m, "idle"); m.ok("breakpoint", action="set", at="0x7c00", kind="hw"); m.ok("vm_control", action="continue")
    m.ok("vm_wait", timeout_ms=20000)
    m.ok("breakpoint", action="clear", at="0x7c00", kind="hw")
    m.ok("snapshot", action="save", name="boot")
    for _ in range(6):
        m.ok("step")
    moved = m.ok("regs", names=["rip"])["rip"]
    ctx = m.ok("snapshot", action="load", name="boot")
    check("snapshot-load rewinds pc to 0x7c00", ctx["pc"] == "0x7c00", f"after steps {moved}, after load {ctx['pc']}")
    check("registers coherent after load (no stale cache)", m.ok("regs", names=["rip"])["rip"] == "0x7c00")
    check("memory coherent after load", m.ok("mem", action="read", at="0x7c00", len=2)["hex"] == "31c0")
    m.ok("vm_control", action="kill"); m.close()
    if replay:
        t3_replay()


def t3_replay():
    m = Mcp(BIN, "--unsafe", "--experimental-replay")
    rr = os.path.join(TMP, "rr.bin")
    m.ok("vm_launch", machine="pc", mem_mb=64, drives=[{"file": img("idle"), "format": "raw"}], replay={"mode": "record", "file": rr})
    m.ok("vm_control", action="continue"); time.sleep(2)
    m.ok("vm_control", action="kill"); m.close()
    m = Mcp(BIN, "--unsafe", "--experimental-replay")
    err, out = m.call("vm_launch", machine="pc", mem_mb=64, drives=[{"file": img("idle"), "format": "raw"}], replay={"mode": "replay", "file": rr})
    check("replay launch", not err, str(out)[:200])
    if not err:
        m.ok("breakpoint", action="set", at="0x7c00", kind="hw"); m.ok("vm_control", action="continue")
        m.ok("vm_wait", timeout_ms=20000)
        fwd = [m.call("step") for _ in range(3)]
        check("forward step stable in replay mode", all(not e for e, _ in fwd), str(fwd[-1])[:200])
        back = m.call("step", mode="back")
        print("  INFO reverse step ->", str(back)[:160])
        m.ok("vm_control", action="kill")
    m.close()


def t4_arch_smp_flood():
    print("T4 aarch64 / riscv64 / smp / early serial / flood")
    m = Mcp(BIN)
    for arch, machine, pc in (("aarch64", "virt", "0x0"), ("riscv64", "virt", "0x1000")):
        err, out = m.call("vm_launch", arch=arch, machine=machine, cpu="cortex-a57" if arch == "aarch64" else None, mem_mb=128)
        check(f"{arch} launches", not err, str(out)[:200])
        if err:
            continue
        w = m.ok("vm_wait", timeout_ms=100)
        check(f"{arch} reset pc {pc}", w["pc"] == pc, str(w.get("pc")))
        check(f"{arch} disassembly via llvm-mc", bool(w.get("code")) and "text" in w["code"][0], str(w.get("code"))[:120])
        m.ok("vm_control", action="kill")
    m.ok("vm_launch", machine="pc", mem_mb=64, smp=4)
    check("-smp 4 lists 4 threads", m.ok("vm_status")["threads"] == [1, 2, 3, 4])
    m.ok("vm_control", action="kill")
    boot(m, "idle")  # early serial: output produced before we ever attach to the stream, under -S
    m.ok("vm_control", action="continue"); time.sleep(1.5)
    check("early serial captured", "HELLO" in m.ok("log_read", source="serial")["text"])
    flood_serial_and_qmp(m)
    m.ok("vm_control", action="kill"); m.close()


def flood_serial_and_qmp(m):
    m.ok("vm_control", action="pause")
    for _ in range(40):
        m.ok("serial_write", text="A" * 4000)
    t0 = time.perf_counter()
    st = m.ok("vm_status")
    check("QMP responsive during serial flood", st["qmp_status"] is not None and time.perf_counter() - t0 < 2)


def t5_resilience_and_bench():
    print("T5 attach-mode resilience + footprint/performance")
    gdb, qmp, ser = (os.path.join(TMP, n) for n in ("gdb.sock", "qmp.sock", "ser.sock"))
    q = subprocess.Popen(["qemu-system-x86_64", "-S", "-display", "none", "-nodefaults", "-machine", "pc", "-m", "64",
                          "-drive", f"file={img('idle')},format=raw,if=ide", "-gdb", f"unix:{gdb},server=on,wait=off",
                          "-qmp", f"unix:{qmp},server=on,wait=off", "-serial", f"unix:{ser},server=on,wait=off"],
                         stderr=subprocess.DEVNULL, start_new_session=True)
    for p in (gdb, qmp, ser):
        for _ in range(100):
            if os.path.exists(p):
                break
            time.sleep(0.05)
    m = Mcp(BIN, "--unsafe")
    st = m.ok("vm_attach", gdb=f"unix:{gdb}", qmp=f"unix:{qmp}", serial=f"unix:{ser}")
    check("attach ok", st["mode"] == "attached")
    w = m.ok("vm_wait", timeout_ms=100)
    check("attached: reset state visible", w["pc"] == "0xfff0")
    m.ok("breakpoint", action="set", at="0x7c00", kind="hw"); m.ok("vm_control", action="continue")
    check("attached: breakpoint hit", m.ok("vm_wait", timeout_ms=20000)["pc"] == "0x7c00")
    m.ok("breakpoint", action="clear", at="0x7c00", kind="hw")
    m.ok("snapshot", action="save", name="a")
    for _ in range(4):
        m.ok("step")
    ctx = m.ok("snapshot", action="load", name="a")
    check("stub consistent after snapshot-load (pc)", ctx["pc"] == "0x7c00", str(ctx.get("pc")))
    check("stub consistent after snapshot-load (mem)", m.ok("mem", action="read", at="0x7c00", len=2)["hex"] == "31c0")
    check("packet sync after load (6 more steps)", all(not m.call("step")[0] for _ in range(6)))
    ctx = m.ok("vm_control", action="reset")
    check("stub consistent after system_reset (pc)", ctx["pc"] == "0xfff0", str(ctx.get("pc")))
    check("stub consistent after system_reset (mem)", m.ok("mem", action="read", at="0xfffffff0", len=2)["hex"] == "ea5b")
    check("step after reset works", not m.call("step")[0])
    err, out = m.call("vm_control", action="kill")
    check("kill refused in attach mode", err and q.poll() is None)
    bench_latency(m)
    bundle = m.ok("step")
    size = len(json.dumps(bundle))
    print(f"  BENCH stop-context bundle: {size} bytes ~= {size // 4} tokens")
    check("detach ok and QEMU survives", not m.call("vm_control", action="detach")[0] and q.poll() is None)
    time.sleep(0.5)
    st = subprocess.run(["bash", "-c", f"cat /proc/{q.pid}/stat | cut -d' ' -f3"], capture_output=True, text=True).stdout.strip()
    check("guest left running after detach", st in ("R", "S"), st)
    idle_footprint(m)
    m.close()
    os.killpg(q.pid, signal.SIGKILL); q.wait()


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))] * 1000


def bench_latency(m):
    for _ in range(60):
        m.call("vm_status"); m.call("regs", names=["rip"]); m.call("mem", action="read", at="0x7c00", len=64)
        m.call("log_read", source="serial"); m.call("serial_write", text="")
    for tool, label in (("vm_status", "QMP (query-status+threads)"), ("regs", "RSP regs"), ("mem", "RSP mem read 64B"), ("log_read", "serial ring read"), ("serial_write", "serial write")):
        xs = m.lat[tool]
        print(f"  BENCH {label:30s} p50={statistics.median(xs) * 1000:6.2f} ms  p95={pct(xs, 0.95):6.2f} ms  (n={len(xs)})")


def idle_footprint(m):
    pid = m.p.pid
    time.sleep(3)
    t0 = sum(map(int, open(f"/proc/{pid}/stat").read().split()[13:15]))
    time.sleep(5)
    t1 = sum(map(int, open(f"/proc/{pid}/stat").read().split()[13:15]))
    rss = int([l for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS")][0].split()[1])
    print(f"  BENCH idle RSS={rss / 1024:.1f} MiB  idle CPU={(t1 - t0) / os.sysconf('SC_CLK_TCK') / 5 * 100:.2f}%  binary={os.path.getsize(BIN) / 1024:.0f} KiB (stripped release)")


def gates_cleanup():
    print("Gates: SIGKILL / SIGTERM cleanup, monitor policy")
    m = Mcp(BIN)
    boot(m, "idle"); m.ok("vm_control", action="continue")
    before = qemu_pids()
    check("qemu running", len(before) >= 1)
    m.p.send_signal(signal.SIGKILL); m.p.wait()
    time.sleep(1.5)
    check("SIGKILL of MCP kills QEMU (pdeathsig)", not qemu_pids(), str(qemu_pids()))
    m = Mcp(BIN)
    boot(m, "idle")
    m.p.send_signal(signal.SIGTERM); m.p.wait(10)
    time.sleep(0.5)
    check("SIGTERM kills QEMU", not qemu_pids())
    m = Mcp(BIN)
    boot(m, "idle")
    check("monitor: info allowed", not m.call("monitor", kind="hmp", command="info registers")[0])
    check("monitor: quit refused", m.call("monitor", kind="hmp", command="quit")[0])
    check("monitor: mutating refused without --unsafe", m.call("monitor", kind="hmp", command="system_reset")[0])
    check("monitor: shell-ish refused", m.call("monitor", kind="qmp", command="human-monitor-command", args={"command-line": "quit"})[0])
    check("mem write refused without --unsafe", m.call("mem", action="write", at="0x7c00", hex="90")[0])
    m.ok("vm_control", action="kill"); m.close()
    time.sleep(0.5)
    check("no leftover QEMU / sockets", not qemu_pids())


if __name__ == "__main__":
    which = sys.argv[2:] or ["t1", "t2", "t3", "t4", "t5", "gates"]
    runs = {"t1": t1_reset_to_bootsector, "t2": t2_crash_and_hang_triage, "t3": lambda: t3_snapshot_rewind(True),
            "t4": t4_arch_smp_flood, "t5": t5_resilience_and_bench, "gates": gates_cleanup}
    for name in which:
        runs[name]()
    print("\nRESULT:", "ALL PASS" if not FAILS else f"{len(FAILS)} FAILED: {FAILS}")
    sys.exit(1 if FAILS else 0)
