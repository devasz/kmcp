# kmcp

Out-of-band QEMU + kernel debugging over MCP (stdio). Host-side only, **zero guest code**: it drives QEMU through QMP, the
gdbstub (RSP), the serial/debugcon chardevs and QEMU's own `-d` log, from CPU reset through panic.
Design rationale: [`docs/adr/0001-architecture.md`](docs/adr/0001-architecture.md).

## Build and register

```
cargo build --release        # ~3.4 MiB stripped binary
```

Claude Code: `claude mcp add kmcp -- /abs/path/target/release/kmcp`
Any client (`mcpServers` JSON): `{"kmcp": {"command": "/abs/path/target/release/kmcp", "args": []}}`
Needs `qemu-system-*` (11.x tested), `qemu-img` (snapshots) and optionally `llvm-mc` (aarch64/riscv64 disassembly).

| Flag | Effect |
|---|---|
| `--unsafe` | allow register/memory writes and mutating monitor commands |
| `--experimental-replay` | allow record/replay launches (TCG only; reverse stepping **unverified**, see below) |
| `--systemd` | also run QEMU in a transient `systemd-run --user --scope` (cgroup cleanup even after SIGKILL of the MCP) |

## Tools

`vm_launch` `vm_attach` `vm_status` `vm_control` (continue/pause/reset/powerdown/kill/detach) `vm_wait` `regs` `step`
`breakpoint` (sw/hw/watch) `mem` (read/write/disasm) `log_read` (serial/qemu/debugcon) `serial_write` `snapshot`
(save/load/delete/list) `symbols` (ELF/DWARF) `monitor` (read-only HMP/QMP allowlist). Up to 4 VMs via `vm_id`.
Every stop returns one bundle: regs, symbol, code at PC, new serial text, new QMP events and crash evidence.

## Behaviour worth knowing

- **Crash triage**: managed VMs run `-action reboot=shutdown,shutdown=pause,panic=pause` plus pvpanic and, under TCG,
  `-d int,cpu_reset,guest_errors`. A triple fault freezes the VM with `crash.class=triple_fault`; a dead `cli;hlt` is
  reported as `dead_hang` by `vm_status probe_hang`, an idle `sti;hlt` is not. Under KVM (opt-in) `-d int` does not exist, so
  fault triage is reduced; `vm_status` says so. The same applies to attached VMs you launched yourself.
- **Frozen state**: after a guest reset/shutdown QEMU stays in `shutdown`; resuming is refused with a message. Use
  `vm_control reset`. SeaBIOS issues one extra warm reset after a host reset, so expect to see that once.
- **Reset**: x86 gdbstub reports no segment bases; real-mode PCs are shown as `linear_pc` (`cs*16+ip`, reset = `0xfffffff0`).
- **Trap storms**: a fault before the guest installs a trap vector (`stvec=0`) re-faults forever and floods the 8 MiB `-d` ring.
  `vm_wait` therefore also returns `first_fault`, the first fault since the last resume, which survives the flood.
  RISC-V timer/external interrupts (`async=1`) and `*_ecall` are never reported as faults; x86 hardware IRQs likewise.
- **Breakpoints**: QEMU's stub re-reports a breakpoint at the resume PC, so `continue` single-steps off it first
  (breakpoint lifted, one IRQ-free step, reinserted), as gdb does.
- **Launch shapes** (`vm_launch`): `drives[].interface` is `virtio`, `ide`, `pflash` (OVMF code/vars, in order) or
  `virtio-mmio` (non-x86 `virt`: becomes `virtio-blk-device` on `virtio-mmio-bus.N`, modern virtio forced). `bios: "none"`
  boots a bare-metal `-kernel` with no firmware. `elf` loads DWARF; asm labels (`NOTYPE`, e.g. `_entry`) are symbols too.
- **Attach** (`vm_attach`): needs QEMU started with `-gdb`/`-qmp`/serial sockets. `detach` resumes nothing and never kills the
  external QEMU; `kill` is refused.
- **Safety**: argv arrays only (no shell), validated paths, per-op timeouts, bounded ring buffers. QEMU dies with the MCP:
  `PR_SET_PDEATHSIG` + process-group kill + stale-run-dir reaping at startup; SIGINT/SIGTERM tear everything down.
- **Replay/reverse**: `--experimental-replay` launches record/replay (`rrsnapshot=init` only with a qcow2 drive). Forward
  `step` is stable in replay mode; `step back` / `reverse_continue` did **not** produce a stop in testing (blkreplay drive
  wiring is not implemented). Treat it as unsupported until fixed.
- Deferred: guest-physical page-table walk (use `monitor gva2gpa`), memory dump to file, QGA/vsock, gdb-oracle proxy.

## Verify

```
cargo test                                   # 44 unit tests
python3 scripts/demo.py [binary] [t1..t5 gates]   # live E2E + benchmarks, needs nasm, qemu x86_64/aarch64/riscv64
python3 scripts/dogfood_ovmf.py [binary]          # stock edk2-ovmf: pflash, 4 GiB reset vector, real->long mode, UEFI shell
python3 scripts/dogfood_xv6.py <xv6-riscv clone> [binary]   # real kernel (clang+lld, no riscv GCC needed), + broken-boot proof
```
`demo.py` reproduces: T1 reset-vector → boot sector (breakpoint, step, serial regex), T2 triple fault / hang / pvpanic /
snapshot-after-crash, T3 snapshot rewind (+ replay), T4 aarch64/riscv64/SMP/early serial/flood, T5 attach-mode resilience across
`snapshot-load` and `system_reset` + footprint/latency benchmarks, and the cleanup gates (SIGKILL/SIGTERM leave no QEMU behind).

Measured (this host, TCG): 3.4 MiB stripped binary, idle RSS 8.5 MiB, 0 % idle CPU; p50/p95 QMP 0.51/0.58 ms, RSP regs 0.14/0.18 ms,
RSP 64 B read 0.18/0.21 ms, serial read/write ~0.14 ms; stop bundle 965 bytes (~241 tokens).

MIT licensed.
