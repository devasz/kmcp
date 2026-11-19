"""Dogfood: debug a real external kernel (mit-pdos/xv6-riscv, built with clang+lld, DWARF) purely through MCP tool calls,
then prove the MCP catches an injected early-boot fault out-of-band.  Usage: dogfood_xv6.py <xv6 clone> [binary]"""
import os, re, shutil, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcpc import Mcp

XV6 = os.path.abspath(sys.argv[1])
BIN = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "target", "release", "kmcp")
MAKE = ["make", "TOOLPREFIX=", "CC=clang --target=riscv64-unknown-elf -Wno-error -fno-strict-aliasing", "LD=ld.lld", "OBJCOPY=llvm-objcopy", "OBJDUMP=llvm-objdump",
        "LDFLAGS=-z max-page-size=4096 --image-base=0 --no-rosegment -e start"]
STRIPPED = MAKE[:-1] + [MAKE[-1] + " -s"]  # user programs only: -ggdb DWARF pushes usertests past xv6's MAXFILE
RUN_ROOT = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "qmcp")
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        fails.append(name)


def launch(m, root, **kw):
    return m.ok("vm_launch", arch="riscv64", machine="virt", bios="none", kernel=f"{root}/kernel/kernel", elf=f"{root}/kernel/kernel", mem_mb=128, smp=1,
                drives=[{"file": f"{root}/fs.img", "format": "raw", "interface": "virtio-mmio"}], **kw)


def diff(a, b):
    return {k: (a[k], b[k]) for k in a if k in b and a[k] != b[k]}


def part_3a_3b(m):
    launch(m, XV6)
    w = m.ok("vm_wait", timeout_ms=200)
    check("3a frozen at riscv reset vector 0x1000", w["pc"] == "0x1000" and w["state"] == "stopped", str(w.get("pc")))
    check("3a reset code decodes (auipc/csrr mhartid)", "auipc" in str(w["code"]) and "mhartid" in str(w["code"]))
    d = m.ok("mem", action="disasm", at="0x1000", count=3)
    check("3a mem disasm", "auipc" in str(d))
    main = int(m.ok("symbols", action="lookup", arg="main")["addr"], 16)
    entry = int(m.ok("symbols", action="lookup", arg="_entry")["addr"], 16)
    near = m.ok("symbols", action="nearest", arg=hex(main + 4))["at"]
    check("3b symbols: _entry is the ELF entry 0x80000000", entry == 0x80000000, hex(entry))
    check("3b symbols: addr2line main+4 -> main.c:line", re.search(r"main\+0x4 \(.*main\.c:\d+\)", near) is not None, near)
    return w, main


def part_3c(m, reset, main):
    m.ok("breakpoint", action="set", at="main")
    m.ok("vm_control", action="continue")
    hit = m.ok("vm_wait", timeout_ms=20000)
    check("3c stopped at main", int(hit["pc"], 16) == main, hit.get("pc"))
    check("3c stop-context names symbol + file:line", re.search(r"main.*main\.c:\d+", str(hit.get("symbol"))) is not None, str(hit.get("symbol")))
    changed = diff(reset["regs"], hit["regs"])
    check("3c regs diff reset->main (pc/sp/mstatus moved)", {"pc", "sp"} <= set(changed), str(changed))
    print("INFO regs diff reset->main:", changed)
    # step_off_breakpoint: the breakpoint at main is still active at the current pc; continue must leave it, and
    # a breakpoint at kexec must fire twice (/init, then sh), proving it was reinserted after the step-off
    m.ok("breakpoint", action="set", at="kexec")
    m.ok("vm_control", action="continue")
    first = m.ok("vm_wait", timeout_ms=30000)
    check("3c continue from an active breakpoint makes forward progress", "kexec" in str(first.get("symbol")) and int(first["pc"], 16) != main, str(first.get("symbol")))
    m.ok("vm_control", action="continue")
    second = m.ok("vm_wait", timeout_ms=30000)
    check("3c breakpoint re-fires after step-off (reinserted, new a0 = next exec)", second["pc"] == first["pc"] and second["regs"]["a0"] != first["regs"]["a0"], f"{first['regs']['a0']} -> {second['regs']['a0']}")
    s = m.ok("step")
    check("3c single-step advances pc", s["pc"] != second["pc"], f"{second['pc']} -> {s['pc']}")
    for name in ("main", "kexec"):
        m.ok("breakpoint", action="clear", at=name)


def part_3d(m):
    m.ok("vm_control", action="continue")
    m.ok("vm_wait", timeout_ms=3000, serial_regex=r"\$ ")  # the shell may already be at its prompt after 3c
    ring = m.ok("log_read", source="serial", tail=3000)["text"]
    check("3d serial ring: xv6 reached the shell prompt", "init: starting sh" in ring and ring.rstrip().endswith("$"), ring[-120:])
    m.ok("serial_write", text="echo qmcp-says-hi", newline=True)
    out = m.ok("vm_wait", timeout_ms=10000, serial_regex=r"\nqmcp-says-hi\n")
    check("3d serial_write -> shell echoes", out.get("matched") is not None, str(out)[:200])
    m.ok("serial_write", text="ls", newline=True)
    time.sleep(1.5)
    ls = m.ok("log_read", source="serial", tail=3000)["text"]
    check("3d `ls` lists README and sh", "README" in ls and re.search(r"\bsh\b", ls) is not None, ls[-200:])


def part_3e(m):
    m.ok("vm_control", action="pause")
    ram = "0x87000000"  # free RAM well above the kernel image
    m.ok("mem", action="write", at=ram, hex="aaaaaaaa", phys=True)
    before = m.ok("regs")
    sv = m.call("snapshot", action="save", name="midboot")
    check("3e snapshot save (riscv virt + virtio)", not sv[0], str(sv[1])[:200])
    if sv[0]:
        return
    m.ok("mem", action="write", at=ram, hex="bbbbbbbb", phys=True)
    m.ok("regs", set={"name": "a0", "value": "0xdead"})  # an idle shell sits in wfi, so mutate state explicitly
    check("3e state mutated after save (cache not stale)", m.ok("regs") != before)
    ld = m.call("snapshot", action="load", name="midboot")
    check("3e snapshot load", not ld[0], str(ld[1])[:200])
    after = m.ok("regs")
    check("3e regs identical to pre-save after load (no stale regcache)", after == before, str(diff(before, after)))
    mem = m.ok("mem", action="read", at=ram, len=4, phys=True)
    check("3e RAM restored (aaaaaaaa)", "aaaaaaaa" in str(mem).lower(), str(mem))
    m.ok("vm_control", action="continue")
    m.ok("serial_write", text="echo after-restore", newline=True)
    ok = m.ok("vm_wait", timeout_ms=15000, serial_regex=r"\nafter-restore\n")
    check("3e guest alive after restore", ok.get("matched") is not None, str(ok)[:200])


def build(root):
    """Kernel keeps DWARF (symbols tool); fs.img is built with stripped user programs."""
    for cmd in (MAKE + ["kernel/kernel"], STRIPPED + ["fs.img"]):
        subprocess.run(cmd, cwd=root, check=True, capture_output=True)


def broken_tree():
    tmp = tempfile.mkdtemp(prefix="xv6-broken-")
    root = tmp + "/xv6"
    shutil.copytree(XV6, root, symlinks=True)
    src = open(root + "/kernel/main.c").read()
    inject = "  *(volatile int *)0x10 = 1; // INJECTED early-boot fault, before consoleinit\n"
    assert "main()\n{\n" in src
    open(root + "/kernel/main.c", "w").write(src.replace("main()\n{\n", "main()\n{\n" + inject, 1))
    line = open(root + "/kernel/main.c").read().splitlines().index(inject.rstrip("\n")) + 1
    build(root)
    return tmp, root, line


def part_bonus():
    tmp, root, line = broken_tree()
    m = Mcp(BIN, "--unsafe")
    try:
        launch(m, root)
        m.ok("vm_control", action="continue")
        w = m.ok("vm_wait", timeout_ms=4000)
        check("bonus: no console output ever (stall is silent)", not m.ok("log_read", source="serial", tail=500)["text"])
        check("bonus: vm_wait times out with VM still running (out-of-band stall)", w["state"] == "running" or w["stop"]["reason"] == "timeout", str(w["stop"]))
        m.ok("vm_control", action="pause")
        ctx = m.ok("vm_wait", timeout_ms=500)
        first = ctx.get("first_fault") or {}
        check("bonus: recent_faults shows the trap storm at pc 0 (stvec never set)", any(f["pc"] == 0 for f in ctx.get("recent_faults") or []), str(ctx.get("recent_faults"))[:200])
        check("bonus: first_fault is the root-cause store fault (tval 0x10)", first.get("name") == "fault_store" and "tval=0x0000000000000010" in first.get("detail", ""), str(first))
        where = m.ok("symbols", action="nearest", arg=hex(first["pc"]))["at"] if first.get("pc") else ""
        check(f"bonus: first_fault pc resolves to kernel/main.c:{line}", re.search(rf"main\.c:{line}\)", where) is not None, f"{first.get('pc')} -> {where}")
        print("INFO first_fault:", first, "| resolved:", where)
        print("INFO final pc:", ctx.get("pc"), ctx.get("symbol"))
    finally:
        m.call("vm_control", action="kill")
        m.close()
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    build(XV6)
    m = Mcp(BIN, "--unsafe")
    try:
        reset, main_addr = part_3a_3b(m)
        part_3c(m, reset, main_addr)
        part_3d(m)
        part_3e(m)
    finally:
        m.call("vm_control", action="kill")
        m.close()
    time.sleep(0.5)
    left = subprocess.run(["pgrep", "-x", "qemu-system-riscv64"], capture_output=True, text=True).stdout.split()
    stale = os.listdir(RUN_ROOT) if os.path.isdir(RUN_ROOT) else []
    check("3f clean teardown: no orphan qemu, no stale run dirs", not left and not stale, f"{left} {stale}")
    part_bonus()
    time.sleep(0.5)
    check("bonus teardown clean", not subprocess.run(["pgrep", "-x", "qemu-system-riscv64"], capture_output=True, text=True).stdout.split())
    print("RESULT:", "ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
    sys.exit(1 if fails else 0)


main()
