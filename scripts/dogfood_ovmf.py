"""Dogfood: boot the host's stock edk2-ovmf (pflash) frozen at reset and drive it through the MCP only.
Covers 4 GiB reset vector -> protected mode -> long mode, serial/debugcon, UEFI Shell via serial_write, snapshot."""
import os, re, shutil, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcpc import Mcp

BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "target", "release", "kmcp")
CODE, VARS = "/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        fails.append(name)


def num(v):
    return int(v, 16)


def poll_long_mode(m, budget_s):
    """continue/pause sampling (TCG is slow; breakpoints need addresses we do not know) until a 64-bit stop."""
    end, seen = time.time() + budget_s, set()
    while time.time() < end:
        m.ok("vm_control", action="continue")
        time.sleep(1.5)
        m.ok("vm_control", action="pause")
        ctx = m.ok("regs")
        bits = 64 if num(ctx.get("efer", "0x0")) & 0x400 else (32 if num(ctx["cr0"]) & 1 else 16)
        seen.add(bits)
        if bits == 64:
            return ctx, seen
    return None, seen


def main():
    tmp = tempfile.mkdtemp(prefix="ovmf-dogfood-")
    shutil.copy(VARS, tmp + "/vars.fd")  # never touch the system VARS
    m = Mcp(BIN, "--unsafe")
    try:
        m.ok("vm_launch", machine="q35", mem_mb=512, debugcon=True, drives=[
            {"file": CODE, "format": "raw", "interface": "pflash", "readonly": True},
            {"file": tmp + "/vars.fd", "format": "raw", "interface": "pflash"}])
        w = m.ok("vm_wait", timeout_ms=100)
        check("frozen at 4 GiB reset vector", w.get("linear_pc") == "0xfffffff0" and w.get("mode_bits") == 16, str(w.get("pc")))
        check("reset vector decodes", "mov eax,cr0" in str(w.get("code")), str(w.get("code"))[:120])
        r = m.ok("regs", names=["cr0", "cr4", "efer", "eflags"])
        check("reset CR0 is 0x60000010 (not 0)", r["cr0"] == "0x60000010", str(r))
        hmp = m.ok("monitor", kind="hmp", command="info registers")["output"]
        check("regs agree with HMP", re.search(r"CR0=60000010", hmp) is not None)

        modes = []
        for _ in range(80):  # real -> protected happens within a few dozen instructions
            s = m.ok("step")
            modes.append(s.get("mode_bits"))
            if s.get("mode_bits") == 32:
                break
        check("step reached protected mode", 32 in modes, str(modes[-5:]))
        r = m.ok("regs", names=["cr0"])
        check("PE bit set after transition", num(r["cr0"]) & 1 == 1, str(r))

        ctx, seen = poll_long_mode(m, 90)
        check("reached long mode (EFER.LMA)", ctx is not None, str(sorted(seen)))
        if ctx:
            check("long mode CR0.PG/CR4.PAE/EFER.LME", num(ctx["cr0"]) & 0x80000001 == 0x80000001 and num(ctx["cr4"]) & 0x20 and num(ctx["efer"]) & 0x100,
                  str({k: ctx[k] for k in ("cr0", "cr4", "efer")}))
            d = m.ok("mem", action="disasm", at=ctx["rip"], count=4)
            check("64-bit disasm at rip", bool(d.get("code") or d.get("insns") or d), str(d)[:150])
        print("INFO debugcon bytes (release OVMF is silent on port 0x402):", len(m.ok("log_read", source="debugcon", tail=2000).get("text", "")))

        m.ok("vm_control", action="continue")
        # vm_wait only matches output no earlier bundle reported, so check the ring first
        if "Press any key" not in m.ok("log_read", source="serial", tail=8000).get("text", ""):
            m.ok("vm_wait", timeout_ms=30000, serial_regex=r"Press any key to enter the Boot Manager")
        check("serial shows BdsDxe prompt", "Press any key" in m.ok("log_read", source="serial", tail=8000).get("text", ""))
        m.ok("serial_write", text=" ")  # any key opens the Boot Manager menu
        menu = m.ok("vm_wait", timeout_ms=30000, serial_regex=r"EFI Internal Shell")
        check("vm_wait serial_regex matched boot menu", menu.get("matched") is not None, str(menu)[:200])
        m.ok("serial_write", text="\\e[B\\r", escapes=True)  # Down -> "EFI Internal Shell", Enter
        sh = m.ok("vm_wait", timeout_ms=30000, serial_regex=r"Shell>")
        check("vm_wait serial_regex matched Shell>", sh.get("matched") is not None, str(sh)[:300])
        m.ok("serial_write", text="ver", newline=True)
        time.sleep(1.5)
        ser = m.ok("log_read", source="serial", tail=4000).get("text", "")
        check("UEFI shell answers `ver` over serial_write", re.search(r"UEFI v\d|EDK II|UEFI Interactive Shell", ser) is not None, ser[-300:])

        m.ok("vm_control", action="pause")
        ctx = m.ok("regs")
        check("no timer IRQ reported as fault", "vector 0x20" not in str(m.ok("vm_wait", timeout_ms=100).get("recent_faults")))
        sv = m.call("snapshot", action="save", name="uefi")
        check("snapshot save with pflash", not sv[0], str(sv[1])[:200])
        if not sv[0]:
            ld = m.call("snapshot", action="load", name="uefi")
            check("snapshot load with pflash", not ld[0], str(ld[1])[:200])
            check("regs readable after load", num(m.ok("regs", names=["cr0"])["cr0"]) & 1 == 1)
    finally:
        m.call("vm_control", action="kill")
        m.close()
        shutil.rmtree(tmp, ignore_errors=True)
    time.sleep(0.5)
    left = subprocess.run(["pgrep", "-x", "qemu-system-x86_64"], capture_output=True, text=True).stdout.split()
    check("no orphan qemu", not left, str(left))
    print("RESULT:", "ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
    sys.exit(1 if fails else 0)


main()
