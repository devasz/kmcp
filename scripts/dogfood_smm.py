"""Dogfood: catch the first SMI of stock SMM-capable OVMF (q35, TCG) from outside the guest, inspect SMRAM code,
step inside SMM and watch the CPU leave it.  Usage: dogfood_smm.py [binary]"""
import os, re, shutil, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcpc import Mcp

BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "target", "release", "kmcp")
CODE, VARS = "/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"
SMI_ENTRY = 0x38000  # default SMBASE 0x30000 + 0x8000: where the CPU lands on the first SMI, before firmware relocates SMBASE
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        fails.append(name)


def main():
    tmp = tempfile.mkdtemp(prefix="smm-dogfood-")
    shutil.copy(VARS, tmp + "/vars.fd")
    m = Mcp(BIN, "--unsafe")
    try:
        m.ok("vm_launch", machine="q35", smm=True, mem_mb=512, drives=[
            {"file": CODE, "format": "raw", "interface": "pflash", "readonly": True},
            {"file": tmp + "/vars.fd", "format": "raw", "interface": "pflash"}])
        w = m.ok("vm_wait", timeout_ms=100)
        check("outside SMM at the reset vector (no smm key)", "smm" not in w and w.get("linear_pc") == "0xfffffff0", str(w.get("pc")))
        m.ok("breakpoint", action="set", at=hex(SMI_ENTRY), kind="hw")
        m.ok("vm_control", action="continue")
        hit = m.ok("vm_wait", timeout_ms=90000)
        check("stopped at the SMI entry point", hit.get("linear_pc") == hex(SMI_ENTRY), str(hit.get("linear_pc")))
        check("stop context flags smm: true", hit.get("smm") is True, str(hit.get("smm")))
        check("SMRAM stub decodes (mov ebp / jmp ebp)", "jmp ebp" in str(hit.get("code")), str(hit.get("code"))[:160])
        raw = m.ok("mem", action="read", at=hex(SMI_ENTRY), len=4)
        check("SMRAM is readable while the CPU is in SMM", raw.get("hex", "").startswith("66bd"), str(raw))
        m.ok("breakpoint", action="clear", at=hex(SMI_ENTRY))
        stub = [m.ok("step") for _ in range(3)]  # mov ebp / sub ebp / jmp ebp
        check("still in SMM after stepping the relocation stub", all(s.get("smm") is True for s in stub), str([s.get("smm") for s in stub]))
        target = int(stub[-1]["linear_pc"], 16)
        want = 0x30000 + int(stub[1]["regs"]["rbp"], 16)  # SMBASE + the ip the stub just computed in ebp
        check("jmp ebp lands at SMBASE+ebp (32-bit ip not truncated to 16 bits)", target == want, f"{hex(target)} != {hex(want)}")
        check("SMI handler decodes to real code, not zero padding", "add [bx+si],al" not in str(stub[-1].get("code"))[:200], str(stub[-1].get("code"))[:160])
        print("INFO SMI relocation handler at", hex(target), "| code:", [i["text"] for i in stub[-1].get("code", [])][:3])
        m.ok("vm_control", action="continue")
        m.ok("vm_wait", timeout_ms=60000, serial_regex=r"Press any key to enter the Boot Manager")
        m.ok("vm_control", action="pause")
        after = m.ok("vm_wait", timeout_ms=500)
        check("guest left SMM and booted on (smm absent, BdsDxe reached)", after.get("smm") is not True)
    finally:
        m.call("vm_control", action="kill")
        m.close()
        shutil.rmtree(tmp, ignore_errors=True)
    time.sleep(0.5)
    left = subprocess.run(["pgrep", "-x", "qemu-system-x86_64"], capture_output=True, text=True).stdout.split()
    check("clean teardown: no orphan qemu", not left, str(left))
    print("RESULT:", "ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
    sys.exit(1 if fails else 0)


main()
