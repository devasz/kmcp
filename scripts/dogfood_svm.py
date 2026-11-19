"""Dogfood: debug an AMD SVM hypervisor (scripts/fixtures/svm.asm: VMRUN of a cpuid guest) out-of-band on TCG.
Break on VMRUN, read the VMCB, step into the nested guest, catch the #VMEXIT, then edit the VMCB live.  Usage: dogfood_svm.py [binary]"""
import os, re, shutil, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from mcpc import Mcp

BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "target", "release", "kmcp")
VMCB, ORG = 0x10000, 0x7c00
INTERCEPT_CPUID, EXIT_CODE, SVM_EXIT_CPUID = VMCB + 0x0c, VMCB + 0x70, 0x72
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        fails.append(name)


def assemble(tmp):
    """Boot sector plus the listing, from which the VMRUN address comes (the instruction after the `vmrun_site:` label)."""
    src = os.path.join(HERE, "fixtures", "svm.asm")
    subprocess.run(["nasm", "-f", "bin", src, "-o", tmp + "/svm.bin", "-l", tmp + "/svm.lst"], check=True)
    lst = open(tmp + "/svm.lst").read().splitlines()
    site = next(i for i, l in enumerate(lst) if "vmrun_site:" in l)
    off = int(re.search(r"\s([0-9A-F]{8})\s", lst[site + 1]).group(1), 16)
    return ORG + off  # address of VMRUN; the next instruction starts 3 bytes later


def launch(m, tmp):
    m.ok("vm_launch", cpu="max", mem_mb=64, drives=[{"file": tmp + "/svm.bin", "format": "raw", "interface": "floppy"}])


def phys_u32(m, addr):
    return int.from_bytes(bytes.fromhex(m.ok("mem", action="read", at=hex(addr), len=4, phys=True)["hex"]), "little")


def run_to(m, addr):
    m.ok("breakpoint", action="set", at=hex(addr), kind="hw")
    m.ok("vm_control", action="continue")
    stop = m.ok("vm_wait", timeout_ms=20000)
    m.ok("breakpoint", action="clear", at=hex(addr))
    return stop


def part_trace_vmrun_and_vmexit(m, tmp, vmrun):
    launch(m, tmp)
    at = run_to(m, vmrun)
    check("stopped on VMRUN in 32-bit protected mode", at["pc"] == hex(vmrun) and at["mode_bits"] == 32, str(at.get("pc")))
    check("VMRUN decodes and rax holds the VMCB address", "vmrun" in str(at.get("code")) and int(at["regs"]["rax"], 16) == VMCB, str(at["regs"].get("rax")))
    check("EFER.SVME is set in the host", int(at["regs"]["efer"], 16) & (1 << 12) != 0, str(at["regs"].get("efer")))
    check("VMCB readable from outside (CPUID intercept bit programmed)", phys_u32(m, INTERCEPT_CPUID) == 1 << 18)
    inside = m.ok("step")
    check("one step over VMRUN lands in the nested guest (rax cleared, cpuid next)",
          int(inside["regs"]["rax"], 16) == 0 and "cpuid" in str(inside.get("code")), str(inside.get("code"))[:120])
    back = run_to(m, vmrun + 3)
    check("#VMEXIT returns to the host after VMRUN", back["pc"] == hex(vmrun + 3) and int(back["regs"]["rax"], 16) == VMCB, str(back.get("pc")))
    check("VMCB exit_code is SVM_EXIT_CPUID (0x72)", phys_u32(m, EXIT_CODE) == SVM_EXIT_CPUID, hex(phys_u32(m, EXIT_CODE)))
    m.ok("vm_control", action="continue")
    out = m.ok("vm_wait", timeout_ms=5000, serial_regex=r"K")
    check("host reported the exit on COM1", out.get("matched") is not None, str(out)[:160])


def part_edit_vmcb_live(m, tmp, vmrun):
    launch(m, tmp)
    run_to(m, vmrun)
    m.ok("mem", action="write", at=hex(INTERCEPT_CPUID), hex="00000000", phys=True)  # drop the CPUID intercept before VMRUN
    m.ok("vm_control", action="continue")
    time.sleep(2)
    m.ok("vm_control", action="pause")
    ring = m.ok("log_read", source="serial", tail=100)["text"]
    check("without the intercept the guest runs cpuid natively: no #VMEXIT, host never reports", ring == "", repr(ring))
    check("VMCB exit_code stays 0 (guest never exited)", phys_u32(m, EXIT_CODE) == 0, hex(phys_u32(m, EXIT_CODE)))


def main():
    tmp = tempfile.mkdtemp(prefix="svm-dogfood-")
    vmrun = assemble(tmp)
    for part in (part_trace_vmrun_and_vmexit, part_edit_vmcb_live):
        m = Mcp(BIN, "--unsafe")
        try:
            part(m, tmp, vmrun)
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
