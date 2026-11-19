"""Regression: under accel=kvm the gdbstub re-reports a breakpoint at the resume pc, so `step` used to stay put.
Usage: dogfood_kvm_step.py [binary]  (needs /dev/kvm and nasm)"""
import os, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcpc import Mcp

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "target", "release", "kmcp")
ENTRY = "0x7c00"

with tempfile.TemporaryDirectory() as tmp:
    subprocess.run(["nasm", "-f", "bin", f"{HERE}/fixtures/idle.asm", "-o", f"{tmp}/idle.img"], check=True)
    m = Mcp(BIN, "--unsafe")
    try:
        m.ok("vm_launch", accel="kvm", machine="pc", mem_mb=64, drives=[{"file": f"{tmp}/idle.img", "format": "raw"}])
        m.ok("breakpoint", action="set", at=ENTRY, kind="hw")
        m.ok("vm_control", action="continue")
        hit = m.ok("vm_wait", timeout_ms=10000)
        pcs = [m.ok("step")["pc"] for _ in range(3)]
        ok = hit.get("linear_pc", hit["pc"]) == ENTRY and len(set(pcs)) == 3
        print(("PASS" if ok else "FAIL"), "step from a hw breakpoint under KVM advances", hit["pc"], pcs)
        sys.exit(0 if ok else 1)
    finally:
        m.call("vm_control", action="kill")
        m.close()
