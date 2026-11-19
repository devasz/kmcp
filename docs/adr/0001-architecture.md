# ADR-0001: QEMU Out-of-Band Debug MCP (Phase 1+2, no implementation)

Date: 2026-11-19. Host: QEMU 11.1.3, gdb 18.1 (multi-target build), Linux x86_64.

Evidence tags:
- **[V]** verified by experiment here.
- **[D]** documented in a primary doc or source.
- **[R]** recalled, not checked.
- **[S]** speculative.

"Corrected" marks a claim the adversarial verification refuted or refined.

## 0. Decision summary

1. Build one unified MCP in **Rust (rmcp 3.11 + tokio)**. Reuse no existing MCP server. Copy patterns only.
2. We **own the gdbstub socket** with a native async RSP client. QEMU's stub is single-client, all-stop, and pauses the guest on accept.
3. QMP is a separate native client. HMP goes through `human-monitor-command` for registers and mtree while the guest runs.
4. Always launch with `-S`. Attach every channel, then resume.
5. Crash capture uses `-action reboot=shutdown,shutdown=pause,panic=pause` plus `-d int,cpu_reset,guest_errors`.
6. gdb is an optional "symbol oracle" behind our own RSP proxy. It is not in v1 core.
7. Not researched at all: QGA and vsock. See section 5.9.

## 1. Ecosystem Audit Table

Dates are last commit, or last push where marked "p". Checked via gh and git on 2026-11-19.

| Repo | Stars | Last | License | Verdict | Why |
|---|---|---|---|---|---|
| r0gueSch0lar/QMP-MCP | 3 | 2026-08-14 | MIT | cherry-pick patterns | Best lifecycle design: spec to argv generator, command denylist, cursor event buffer, per-command timeouts, ADRs. No gdbstub. Single VM. Ringbuf drains destructively. |
| BeaCox/gdb-mcp | 13 | commit 2026-09-16, push 2026-11-06 | MIT | cherry-pick patterns | MI parser, response budgets, session caps, unsafe gate, fake_gdb fixture. About 100 userland-centric tools and no QEMU awareness. **No `mi-async`**, so interrupt is unreliable. |
| yshestakov/qemu_mcp | 1 | 2026-10-28 p | none | cherry-pick patterns | Closest design: QEMU `-S`, MI with mi-async, QMP, UART, bounded deques. Run-state machine with refuse-while-running. Allowlisted console. Board-specific, no SMP, **no license, so do not copy code**. |
| 0xmortuex/gdbstub-mcp | 1 | 2026-10-11 p | MIT | cherry-pick patterns | Raw RSP with target.xml-driven registers. `explain_fault` parses the `-d int` log. Plain `c`/`s`, no vCont/Hg, so it cannot select a vCPU. 6 commits. |
| 0xmortuex/qemu-mcp | 5 | 2026-11-18 | MIT | cherry-pick patterns | `wait_serial` marker semantics, serial reconnect. Ungated raw QMP and extra_args. AI-maintained daily churn (BACKLOG.md). |
| 0xmortuex/qemu-replay-mcp | 0 | 2026-10-29 p | MIT | cherry-pick patterns | Confirms the bs/bc workflow. Single CPU and `-kernel` only, per its README. |
| alicmerjem/qemu-mcp | 0 | 2026-09-13 | **PolyForm-NC** | reject (license) | Product shape closest to ours. x86 only. Bare `c`/`s`/`g`, no thread packets. Do not copy. |
| benburkert/qemu-gdb-mcp | 0 | 2026-05-14 | none | cherry-pick ideas only | MI-based with list_threads/select_thread (corrected: it does handle vCPUs). RISC-V CSR decode, satp walk, stepi_no_irq. Attach-only. |
| schuay/gdb-mcp | 3 | 2026-08-01 | MIT | cherry-pick | Tainted-session-after-timeout rule. |
| signal-slot/mcp-gdb | 161 | 2026-07-28 p | declares MIT in README and package.json, no LICENSE file | reject | Corrected: not "unlicensed". Monolithic index.ts, readline matching of MI, no tests. |
| Ipiano/gdb-mcp | 53 | 2026-03-11 | MIT | reject | pygdbmi, inactivity timeouts, ungated raw exec. |
| pansila/mcp_server_gdb | 68 | 2025-09-17 | MIT | reject (stale) | Userland only. |
| yywz1999/gdb-mcp-server | 85 | 2025-11-27 | MIT | reject | tmux scraping with injected markers. |
| smadi0x86/MDB-MCP | 74 | 2026-10-07 | GPL-3.0 | reject | License, pygdbmi. |
| nagy/qemu-mcp-server | 3 | 2026-10-26 | AGPL-3.0 | reject | One raw `execute_qmp`. |
| KashunCheng/dap_mcp | 41 | 2025-09-24 | AGPL-3.0 | reject | DAP adds a layer and gains nothing for kernels. |
| Kevin4562/QEMU-MCP | 3 | 2026-02-18 | ? | reject | Needs in-guest SSH and gdb. Violates zero guest code. |
| Abdalla-Eldoumani/qemu-mcp-server, onionbutties/qemu-mcp | 1, 0 | 2026-10-26, 2026-11-16 | MIT | reject | QMP/screen only. onionbutties was created 2026-11-13. |
| walac/drgn-mcp | 7 | 2026-09-28 | ? | defer | Dump-only. Exposes arbitrary Python via `eval_expression`. |
| modelcontextprotocol/rust-sdk (rmcp) | 4.1k | 2026-11-17 | check LICENSE (GitHub says NOASSERTION) | **reuse** | rmcp-v3.11.0. Reports 100% conformance on 2025-11-25 and 2026-07-28, and the only SDK with the tasks extension. |
| modelcontextprotocol/go-sdk | 5.4k | 2026-11-17 | ? | runner-up | v1.8.0. No tasks extension. |
| qemu.qmp (gitlab python-qemu-qmp) | 9 | 2026-11-18 | ? | reference only | Correct event/id demux. Python, 0.0.x. |
| arcnmx/qapi-rs | 67 | 2025-08-25 | ? | reject | Typed schema lags 11.x. Our raw client is about 60 lines. |
| cs01/pygdbmi | 260 | 2023-12-27 | MIT | reference | Dormant. Port the MI grammar if the oracle is needed. |
| go-delve/delve `gdbserial` | 24.9k | 2026-11-16 | ? | reference | Production RSP client. Not importable. |
| dmaivel/ntoseye | 237 | 2026-11-06 | ? | unread | Source not read. |
| QEMU `contrib/plugins` (drcov, traps, hotblocks) | n/a | tag v11.1.3 | GPL (QEMU) | optional, documented only | Built and ran [V]. TCG only. Results written at exit. |
| torvalds/linux `scripts/gdb`, `decode_stacktrace.sh` | n/a | live | GPL | reuse via gdb oracle, later | Do not reimplement. |
| google/syzkaller | 6.4k | 2026-11-19 | ? | pattern | Console-regex crash detection, symbolizer pool. |

Gap confirmed (K1 not refuted): no server combines QEMU lifecycle, gdb (MI or RSP), QMP and serial with bounded buffers and SMP. Caveats to K1:
- The GitHub sweep was rate-limited and is not exhaustive.
- GitLab, Codeberg and private repos were not checked.
- 0xmortuex/qemu-mcp plus gdbstub-mcp is an MIT two-server pair covering lifecycle, QMP, serial and RSP. It has no threads, and it is two servers.
- yshestakov has every ingredient except SMP.

Star count does not predict quality here. Three data points: signal-slot 161 stars is the weakest, BeaCox 13 is the best. This is an anecdote, not a statistic.

## 2. Workflow Comparison Matrix

| Axis | Option | Evidence | Verdict |
|---|---|---|---|
| Debug channel | **Direct RSP (own client)** | Stub quirks are small and fully mapped [V]. About 0.4 to 1 ms per stepi. MCP owns the socket lifecycle. | **Core.** Costs us symbols, DWARF and unwinding. |
| | gdb/MI subprocess | Needs `mi-async on`, otherwise `-exec-interrupt` is ignored [V]. The `*stopped` record can arrive late, only after another command [V, corrected]. Octal-escaped UTF-8 and emoji in records [V]. Gives DWARF, CFI, `lx-*` and reverse commands. | Oracle only, behind our proxy. |
| | Compose an existing GDB MCP | Stub is single-client and a second connection got no reply [V]. Attaching pauses the guest [V]. None is QEMU-aware. | Reject. |
| Latency (corrected) | RSP vs MI | The claimed 13.2 ms MI read and 85x gap are **wrong**. Remeasured under load: stepi raw 0.5 to 1 ms vs MI 2.6 ms (about 2.7x). 4 KiB read raw 0.4 to 0.9 ms vs MI 0.8 to 1.3 ms. | Latency is not the deciding factor. Socket ownership and state control are. |
| Topology | **Single unified MCP** | Shared state is needed: pause-on-connect, snapshot invalidating register caches, QMP stop vs T02 correlation, supervised teardown. | **Chosen.** |
| | Composable multi-MCP | Impossible with a single-client stub. QMP-MCP denylists `human-monitor-command` [V], so it cannot give registers. | Reject. |
| Snapshot | **QMP `snapshot-save/load/delete`** | Async jobs. Needs a qcow2 block node name for `vmstate` and `devices` [V]. Reply `{}` only means the job was created, so check `query-jobs[].error` and `job-dismiss`. 128 MB guest: 0.6 s save. 256 MB: 1.7 s save, 0.6 s load. Rewind confirmed [V]. Works while stopped. | **Default**, using an orphan qcow2 carrier we always attach. |
| | migrate-to-file | Diskless OK. 256 MB: 1.8 s save, 2.2 s load [V]. Restore needs a new QEMU process, so chardev and gdb connections are lost. | Fallback and portable checkpoint. |
| | `x-ignore-shared` + file RAM | 13 ms save and load [V]. Needs `ram.bin` copied or reflinked to be point-in-time. | Optional fast path [S for productization]. |
| | icount record/replay | See next row. | Experimental flag. |
| Reverse debugging | rr=record/replay + gdb reverse | Needs TCG, `-icount`, `rrsnapshot`, blkreplay chain and an orphan qcow2 [V]. `ReverseStep+;ReverseContinue+` appear **only in replay mode**, sitting between `qXfer:features:read+` and `vContSupported+` [V, corrected]. Record mode `bs`/`bc` gives E22 [V]. End of log kills QEMU [V]. The log is valid only after a clean quit [V]. gdb reverse-stepi, reverse-continue and reverse watch worked on x86 [V]. **Contested:** one lane saw forward `s` in replay hang for 20 s. Another lane's gdb session worked. KVM refuses `-icount` [V]. Cost is about 26 to 29% on a tight loop [V]. | Optional, TCG only, guarded. Forward-step stability is unproven. |
| Accel | KVM | Fast. Hardware breakpoints and watchpoints work on x86 [V]. The `-d` log is nearly empty: no `IN:`, no `int`, **no "Triple fault"** [V]. | Opt-in, no triage. |
| | **TCG** | Full `-d` logs, plugins, record/replay [V]. | **Default.** |
| | Dual-mode live handoff | KVM to TCG migration **fails** (`Unknown section 'kvmclock'`) under every config tried [V]. TCG to KVM works with `-cpu qemu64` [V] but is unsupported territory. | Refuted as live handoff. Accel is chosen at launch. A "re-run the same image under TCG" triage is only [S]. |
| Crash signal | `-no-reboot` alone | QEMU **exits** rc 0 right after the SHUTDOWN event [V]. No post-mortem possible. | Do not use alone. |
| | `-action reboot=shutdown,shutdown=pause` (or `-no-reboot -no-shutdown`) | Status `shutdown`, QEMU alive, registers at the fault (EIP=7c15) [V]. | **Chosen.** |
| | pvpanic | Needs a guest write to port 0x505 [V]. Default `panic=shutdown` quits QEMU. Early panics and kernels without the driver emit nothing [V]. | Passive extra only. Pair with serial regex on `Kernel panic`. Set `-action panic=pause`. |
| | Triple fault | **No QMP event** [V]. Only `SHUTDOWN{guest-reset}` or a RESET loop. Only the TCG `-d int` log shows `Triple fault` [V]. | Log parser (TCG). On KVM, only a weak heuristic. |
| Multi-arch | x86_64 / aarch64 / riscv64 | One gdb binary handles all three and QEMU picks the arch from the stub [V, K3]. Debian-style single-arch gdb needs a probe. target.xml: x86 lacks GDTR/IDTR/DRx/MSR. riscv64 virt has 204 CSRs. aarch64 sysregs vary by CPU (a57/a72 170, n1 187, max 249) [V, corrected]. | Same RSP core. Per-arch decoders. Register layout parsed from target.xml, never hardcoded. |

## 3. Optimal Workflow Verdict

**Hybrid, RSP-first.**
- Native RSP client owns the stub. Native QMP client owns the control socket.
- HMP via `human-monitor-command` fills the gaps. It runs while the guest runs, at about 1.5 to 2.2 ms [V], and covers `info registers`, mtree, tlb and lapic.
- Per-arch decoders run host-side.
- Optional gdb oracle, v1.1, attaches through an in-process RSP proxy on a second unix socket. The proxy drops `vKill` and `k`, and maps `D` to our own detach.
- The proxy is **untested** [S]. Do not promise it.

### Where the Reference Baseline is wrong or needs correction

| # | Baseline assumption | Reality (evidence) |
|---|---|---|
| 1 | QMP can read registers or memory | No such command exists in 11.1.3 (242 commands, no `query-registers`) [V]. Use gdbstub or HMP. `query-cpus-fast` and `info cpus` have no pc or halted state [V]. |
| 2 | `savevm` or snapshot works on any guest | Needs a qcow2 node name. A diskless guest fails. A writable non-qcow2 device (floppy) blocks it unless `readonly=on` [V]. It is an async job and success is reported in `query-jobs`. The `info snapshots` HMP output is misleading [V]. |
| 3 | `-no-reboot` captures crashes | It exits QEMU. Use `-action reboot=shutdown,shutdown=pause` [V]. |
| 4 | QMP event reveals a triple fault | No such event. Parse the TCG `-d int` log [V]. |
| 5 | pvpanic detects panics | The guest must write the port. The default action quits QEMU. Early panics are invisible [V]. |
| 6 | gdb `target remote unix:path` | **Fails** in gdb 18.1 ("Servname not supported"). Use a plain path [V, corrected]. Socket paths over 108 bytes are rejected at startup. 109 or more fails, 108 passes [V, corrected]. Run dir stays short. |
| 7 | gdb shows real-mode correctly | The stub always says `i386:x86-64`. `$rip` is IP only, so linear = cs*16+ip. `set arch i8086` fails either way [V]. Disassemble host-side and track breakpoints by linear address. |
| 8 | Attach, detach, reattach is harmless | Accept pauses the guest. A plain socket close leaves it paused. Real gdb detaches on exit. Bare `D` returns E22 once `multiprocess+` was ever negotiated in that QEMU process, so send `D;1`. QMP `cont` is always safe [V, corrected]. `vKill` and `k` **exit QEMU** [V]. |
| 9 | Any packet can be sent while running | Corrected: **every received byte** pauses the VM (`vm_stop`). Only 0x03 gets a stop reply. A stray packet silently desyncs the client [V, source]. During `c`, send only 0x03. |
| 10 | Stop replies identify cause and PC | Corrected: `T05thread:p01.01;` is identical for Z0, Z1 and step. `T02` is for 0x03 or QMP stop. Watchpoints add `watch:ADDR;` (bare hex). There is no PC, so read it after every stop. No swbreak/hwbreak is advertised [V]. |
| 11 | Reverse debugging is a gdb setting | See the matrix row above. Replay-only, TCG-only, end-of-log fatal [V]. |
| 12 | Early serial output is captured | A socket chardev with no client **drops** output. `-S` plus attach-then-`cont` fixes it [V]. A reader that stops draining a socket chardev (debugcon at 0xe9, tested) **blocks the whole QEMU main loop**, including QMP [V]. The mechanism is inferred. Always drain. |
| 13 | `-mon` | Deprecated in 11.1.3. Use `-qmp` or `-object monitor-qmp` [V]. |
| 14 | QMP events arrive from t=0 | No event queue. Events before connect are lost. Always `-S` [V]. |
| 15 | HMP errors are QMP errors | HMP errors come back as a **successful** `return` string. Pattern-match [V]. HMP `quit` kills QEMU. Denylist it. |
| 16 | `mux=on` for serial plus monitor | Readline escape noise lands in logs [V]. Use separate sockets. |
| 17 | stepi enters IRQ handlers | `qqemu.sstep` default `0x7`: NOIRQ and NOTIMER are set, so stepi does not enter IRQ handlers. Corrected syntax: `Qqemu.sstep=HEX` (documented form). The `:` form also works. The mask must be a subset of the accelerator's bits or you get E22. KVM supports ENABLE only [V, corrected]. |
| 18 | Physical memory reads | `Qqemu.PhyMemMode:1` is a **global** stub flag. Restore it with `:0` after each use or serialize. The reset-vector read is identical in both modes (paging off), so use a paged guest to test the switch. E14 means unmapped (page vs no region). |

## 4. Beyond-Optimal Suggestions

| # | Idea | Tag | Note |
|---|---|---|---|
| 1 | Register diffing between stops (cache `g`, return changed regs only) | mechanism [V], token saving [S] | Invalidate the cache on snapshot-load and reset. |
| 2 | Decoded fault summary. x86: #PF error bits, CR0/CR4/EFER, EFLAGS, vector names. aarch64: ESR EC/ISS, FAR, ELR. riscv: scause, stval, sstatus, satp. | regs present [V], decode tables [D] | ESR/FAR/scause readable via the stub with zero guest code [V]. IDT and GDT via HMP `info registers`. |
| 3 | ANSI/CSI strip plus "line repeated N times" dedupe on log reads | need [V], impl trivial | |
| 4 | Auto hang detection: `info registers` HLT/IF/EIP stability plus `/proc/<pid>/task/<tid>/stat` CPU% plus serial silence | [V] | HLT=1 and IF=0 is a dead hang. HLT=1 and IF=1 is idle. 97% CPU with no progress is a spin. Verified on 16-bit real-mode payloads only. Long-mode register parsing untested. |
| 5 | Auto triple-fault detection from the `-d int` FIFO | [V], TCG only | Anchors: `^check_exception`, `Triple fault`, last `CPU Reset` dump. Keep a bounded tail. |
| 6 | Auto snapshot on crash or on a pre-resume policy | `snapshot-save` on a stopped VM [V]. Policy [S] | Costs 0.6 to 2 s per 100 to 200 MB of non-zero RAM. |
| 7 | `memory-backend-file,share=on` zero-copy RAM view | [V] x86, TCG and KVM | RAM only. GPA to file offset map from `info mtree -f`. No cross-word atomicity. ROM, VGA and MMIO are not in the file. aarch64 and riscv untested. |
| 8 | Host-side page-table walks via PhyMemMode or `gva2gpa` | PhyMemMode [V], walker code [S] | |
| 9 | Early console channels: isa-debugcon (0xe9), semihosting (aarch64, riscv64), ringbuf, isa-debug-exit | [V] | These need the guest under test to emit. We inject nothing. debugcon is x86 only. |
| 10 | DWARF correlation in v1 via `object` + `gimli`: symtab, line table, frame-pointer backtrace | [D], size [V] by gdbstub-mcp precedent | Types, locals, CFI and inline frames need the gdb oracle. PC-range-aware symbolization before paging (kernel runs at physical addresses) [R]. |
| 11 | Stop-context bundle: one result per stop with PC, symbol, flags decode, reg delta, last serial lines | precedent [D] (delve consolidated 26 tools to 13) | |
| 12 | Linux `lx-*`, `decode_stacktrace.sh`, drgn on `dump-guest-memory` | [D] | Needs `-device vmcoreinfo` and guest config. Use `paging=false` on Linux: `paging=true` took 13.4 s vs 0.03 s [V]. |
| 13 | Opt-in TCG plugins (drcov, traps, hotblocks) | [V], TCG only | stoptrigger was not run. A custom discon-callback plugin is [S]. |
| 14 | Live toggling of `trace-event-set-state` as an audit trail | [V] for pic_* | |
| 15 | Stop-reason inference from our own breakpoint table (since T05 is ambiguous) | [D] from source | Track Z0/Z1/Z2-4 and the last command ourselves. |
| 16 | Syzkaller-style console regex classification (oops, panic, BUG, WARN) | [D] | |
| 17 | Execution-trace minimization for LLM context (CrashFixer idea) | [D] literature, for us [S] | |
| 18 | Dual-mode KVM to TCG | **refuted** as live handoff [V] | Re-run triage only [S]. |

## 5. Final Tech Stack Decision

### 5.1 Language and libraries

Rust. Evidence for the choice is in the SDK lane:
- Hello-world 1.4 MB, 2 to 4 ms cold start, 4 MB RSS.
- Go official SDK: 13 ms, 8 MB RSS.
- Bun and Node: about 250 ms and 77 MB. Bun has no `setpgid` or `pdeathsig`: plain `Bun.spawn` leaked even the direct child on SIGKILL [V].
- Python: 1.1 to 1.7 s startup.

The `regex` crate is linear time, which matters because regex patterns come from an LLM.

Cargo dependencies: `rmcp`, `tokio`, `serde`/`serde_json`, `schemars`, `regex`, `libc`. Feature `symbols`: `object` + `gimli`. x86 disassembly: `iced-x86` is recalled, **not researched** (see open question 3).

Cost: cold build about 3 minutes. rmcp is on a fast-moving 3.x major, so pin the version.

### 5.2 Transport

- stdio newline-delimited JSON-RPC. Never write non-MCP data to stdout.
- Negotiate both the 2025-11-25 `initialize` flow and the 2026-07-28 stateless flow with `server/discover`. rmcp does this.
- No Streamable HTTP in v1 (YAGNI).
- Tool timeout clamp: Codex defaults to a 60 s tool timeout, and Claude progress notifications do not extend timeouts. `vm_wait` clamps to 50 s and returns partial results with a cursor.

### 5.3 Tool schema sketch (12 tools; 8 are core)

| Tool | Key params | Returns |
|---|---|---|
| `vm_launch` | arch, machine, cpu, accel (default tcg), mem_mb, smp, kernel/initrd/append, bios, drives[], capture{serial_kb, debugcon, d_flags, ring sizes}, crash_policy, rr{record\|replay,file}, elf | vm id, run dir, stopped at reset |
| `vm_status` | events_after cursor | run state, last stop, crash class, buffer sizes and drop counters |
| `vm_control` | op: continue \| pause \| reset \| powerdown \| kill | state |
| `vm_wait` | for: stop \| serial_regex \| event \| hang \| crash, timeout_ms, cursor | matched context or timeout and cursor |
| `regs` | cpu, names, diff, decode | registers, decoded fault summary |
| `step` | mode: stepi \| count \| until_addr \| continue, noirq (default true) | stop-context bundle |
| `breakpoint` | op: add \| del \| list, kind: sw \| hw \| watch-w/r/a, addr or symbol | list |
| `mem` | op: read \| write \| disasm \| walk \| dump, space: virt \| phys \| linear, len | bytes (capped), dump as file plus resource_link |
| `log_read` | channel: serial \| debugcon \| qemu_log \| events, offset or tail, grep, max_bytes, strip_ansi, dedupe | text plus next offset plus dropped count |
| `snapshot` | op: save \| load \| delete \| list, name, method: auto \| qcow2 \| migrate | job result with the error string checked |
| `symbols` | op: load_elf \| lookup \| addr2line \| backtrace | |
| `monitor` | kind: qmp \| hmp, command | allowlist plus read-only default. Hard denylist from QMP-MCP: `human-monitor-command` quit, `migrate`, `object-add`, `getfd`/`add-fd`, `device_add`, etc. Gated by `--unsafe`. |

Rules:
- No raw argv. QEMU arguments are generated from a validated spec, with comma escaping.
- `mem write`, register writes and the raw monitor are off unless `--unsafe` is set.
- Keep tool descriptions under 4 KB total. Registration order is deterministic.

### 5.4 State machine and concurrency

- One actor per VM owns the RSP socket and a QMP socket. States: `Stopped | Running | Stepping | Poisoned | Exited`.
- While `Running`, the **only** byte ever written to the stub is 0x03. Live queries use QMP and HMP instead.
- Resume through RSP `vCont;c` while the stub is attached, so stop replies arrive. This is a design inference, not tested: QMP `cont` while the stub is attached leaves a pause hazard on any later stub write.
- A QMP `stop` while the stub is in `c` produces `T02`. Correlate it.
- Timeout on an RSP or MI command marks the session `Poisoned` (schuay's rule) and triggers reconnect. Poison on any unexpected packet.
- Never forward `vKill` or `k`. Always `-S` at launch.
- After `snapshot-load`, `reset` or `replay-seek`, invalidate the register and memory caches. Effect on a live stub connection is **untested**.
- vCPU = gdb thread (`qfThreadInfo`, `Hgp1.N`). SMP threads verified via gdb on `-smp 4` [V]. Raw `Hg` use is [D].

### 5.5 Process supervision

- QEMU is the **direct child** of the MCP, in its own process group.
- `PR_SET_PDEATHSIG=SIGKILL` in `pre_exec`, with a `getppid()` recheck to close the race.
- Spawn from a dedicated long-lived std thread, **never `spawn_blocking`**. Pdeathsig fires when the spawning thread exits, which reproduced in Rust [V].
- SIGTERM handler calls `killpg(SIGKILL)`. `kill_on_drop(true)` is not enough on a crash.
- Hard `kill -9` of the MCP kills the direct child but leaks grandchildren in every language [V]. QEMU stays the direct child. Helpers (virtiofsd, swtpm) get their own pdeathsig.
- Pidfile with start-time and cmdline. Reap stale QEMU on startup.
- Optional `systemd-run --user --scope` for guaranteed tree cleanup [D], untested here.
- Run dir `$XDG_RUNTIME_DIR/qmcp/<id>`, mode 0700, path under about 100 bytes. QMP, gdb, serial and debugcon sockets live there.
- Teardown always kills QEMU. It never leaves the guest paused.

### 5.6 Bounded-buffer design

- One always-draining reader task per channel (serial, debugcon, `-D` FIFO). It never blocks on its consumers.
- Each channel writes into a ring with absolute monotonic byte offsets, a line index, and `dropped_bytes`.
- Defaults: serial 4 MiB, qemu_log 8 MiB, events 1024 (cursor, FIFO evict).
- Reader death means silent log loss on the FIFO, so supervise the reader task.
- `-D` FIFO: open it **before** spawning QEMU, otherwise QEMU blocks in `open` and no QMP socket appears [V].
- Optional MCP-owned spill file, rotated. Not QEMU `logfile=`, which has no rotation.
- Not recommended:
  - QEMU `ringbuf`: `ringbuf-read` drains and overwrites silently with no loss counter [V].
  - `pty`: a reader that stops reading freezes the guest [V].
  - `-d exec`: 6 to 25 MB/s unbounded [V].
- Tool outputs: default 4 KiB, hard cap 32 KiB, truncation markers with a next cursor. Claude Code's `MAX_MCP_OUTPUT_TOKENS` default is 25,000.
- Serial: `wait_serial` marker semantics (from 0xmortuex/qemu-mcp). The regex runs on the `regex` crate with a size limit.

### 5.7 Directory and module layout

```
kmcp/
  Cargo.toml
  docs/adr/0001-architecture.md
  src/
    main.rs            # rmcp stdio server, tool router
    tools.rs           # 12 thin handlers
    vm/mod.rs          # actor, state machine
    vm/launch.rs       # spec -> argv, run dir
    vm/supervise.rs    # spawn thread, pdeathsig, killpg, stale reaping
    qmp.rs             # client, id/event demux, policy
    rsp.rs             # framing, ack, T-parse, vCont, Z/z, qXfer, qemu.* ext
    regs.rs            # target.xml parser, cache, diff
    decode/{x86,aarch64,riscv}.rs
    ring.rs            # bounded ring, ANSI strip, dedupe
    logs.rs            # chardev/FIFO readers, -d int parser
    snapshot.rs
    symbols.rs         # feature "symbols"
  tests/
    fixtures/*.asm     # nasm payloads
    mock_stub.rs       # fake RSP/QMP for unit tests
    e2e.rs             # real QEMU, skipped if absent
```

Each file stays at one concern and each function under about 30 lines.

### 5.8 Phase 4 test plan

The condensed brief does **not** define Tests 1 to 4. I mapped them by capability. Please confirm or correct (open question 10).

| Test (assumed) | Design path | Pass criteria |
|---|---|---|
| **T1** Debug from CPU reset, zero guest code | `vm_launch` (`-S`, gdbstub) then `regs` and `mem` at 0xfff0, then `step` and `breakpoint` | pc=0xfff0, cs=0xf000, and `mem` at linear 0xfffffff0 returns `ea5be000f030362f` [V]. Host-side 16-bit disasm gives `ljmp $0xf000,$0xe05b`. A breakpoint at linear 0x7c00 is hit. |
| **T2** Triple fault, hang, crash detection plus auto-capture | `-action ... pause`, `-d int` FIFO, hang classifier, `vm_wait for=crash\|hang` | Triple-fault payload (`lidt` null, `int3`) reports "triple fault" and the final registers. `cli;hlt` reports dead hang, `sti;hlt` reports idle. `snapshot save` works afterward. pvpanic payload gives GUEST_PANICKED. |
| **T3** Snapshot, rewind, optional reverse | `snapshot` with the orphan qcow2 carrier, then rr record/replay under the experimental flag | A counter rewinds after `load` [V]. Reverse-stepi works on x86 TCG. **Forward step in replay must be re-tested** (contested). |
| **T4** Multi-arch, SMP, early serial | Same code on `-M virt` aarch64 and riscv64, `-smp 4` thread listing, serial and semihosting early output | aarch64 and riscv64 stop at the reset PC (0x0 and 0x1000 [V]). `-smp 4` lists CPU#0 to #3. Early serial line captured with no loss under `-S`. Flood test: QMP stays responsive. |

Additional gates:
- Unit tests for the RSP framing, `O` vs `OK` disambiguation, and the `-d int` parser, using the mock stub.
- Fault-injection test: SIGKILL the MCP and confirm QEMU dies.
- Spawn-thread test (the `spawn_blocking` hazard).

### 5.9 Risks and unresearched

**Risks**
- rmcp major-version churn and an unconfirmed license (GitHub says NOASSERTION).
- Single-client stub: a gdb-oracle proxy is untested.
- Replay forward-step is contested.
- Many repos are AI-maintained with daily churn, so audit data goes stale quickly.

**Unresearched or untested** (nothing is claimed about these)
- **QGA and vsock handoff: nothing was researched or tested.** It also requires guest code, so it conflicts with the zero-guest goal.
- Long-mode `info registers` parsing. Real kernel images (Linux boot under a stub with hbreak at `start_kernel`, KASLR).
- aarch64 and riscv64 stepping, hardware breakpoints and latency. KVM on non-x86.
- Behavior of RSP cache after `snapshot-load` on a live stub.
- Slow-client backpressure on a socket serial chardev. Client-mode `reconnect-ms`.
- Watchdog devices other than `ib700`. `stoptrigger` plugin semantics.
- Record/replay with `-smp > 1`.
- Windows guests (`win-dmp` failed with no vmcoreinfo note).
- Idle-box latency numbers (all timings here are from a loaded 12-core host).
- Disassembly crate choice, and the licenses of several audited repos marked "?".

### 5.10 Approval questions

1. **Language.** Rust (recommended) or Go (official SDK, 13 ms start, no tasks extension)?
2. **v1 symbols scope.** Native `object`+`gimli` line table and frame-pointer backtrace only, with the gdb-oracle proxy in v1.1? Or gdb oracle in v1?
3. **x86 disassembly.** Add `iced-x86` (unresearched here), or shell out to `objdump -m i8086` (verified)? aarch64 and riscv64 disassembly would then go through the oracle.
4. **Default accelerator.** TCG default (full debug fidelity) with KVM opt-in and no triage on KVM. Approve?
5. **Reverse debugging.** Ship it behind an `experimental_replay` flag, given the contested forward-step result?
6. **QGA/vsock.** Defer it entirely (unresearched, needs guest code)?
7. **Raw QMP/HMP tool.** Keep it with the hard denylist, or remove it?
8. **Write operations.** Memory and register writes off by default behind `--unsafe`. Approve?
9. **Default `-d int,cpu_reset,guest_errors`.** Always on under TCG? Linux boot costs about 2.8 MB per 10 s [V].
10. **Tests 1 to 4.** Confirm or replace my assumed definitions in 5.8.
11. **Minimum QEMU version.** Floor at 11.x, or feature-detect via `query-qmp-schema` and support older?
12. **Hard-crash cleanup.** Use an optional `systemd-run --user --scope` wrapper?
13. **Instance count.** Single VM in v1, or an optional `vm` id with a cap of 4?
14. **Project license.** MIT or Apache-2.0? We copy patterns only, so no licensed code is incorporated.

## Appendix: other corrections applied

- **K1:** survives. Added the two caveats (pair of 0xmortuex servers, incomplete sweep).
- **K9:** ringbuf plus chardev `logfile` is an alternative for persistent copies (logfile untested).
- **K12/K13:** signal-slot is MIT-declared with no license file.
- **target.xml (x86):** `cs_base`, `ss_base`, `ds_base` and `es_base` are commented out in the XML. They are not exposed.
- **BeaCox dates:** last commit 2026-09-16 by `git log`, last push 2026-11-06 by gh api. Likely a non-commit push or dependabot. Treated as maintained either way.
- **Known unreproducible figure:** the 400 µs monitor round-trip over RSP was never validly measured (the retest got an empty qRcmd reply).
