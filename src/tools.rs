//! The MCP tool surface. Each tool is a thin wrapper: validate, call a `Vm` operation, return JSON.
//! Errors come back as `Err(String)` (rmcp maps that to `is_error=true`, so the agent can self-correct).

use crate::logs::{compile_regex, ReadOpts};
use crate::ops::{check_monitor, probe_hang, resolve_addr, unescape, MonitorKind, MAX_SERIAL_WRITE};
use crate::qmp::CALL_TIMEOUT;
use crate::rsp::hex_to_bytes;
use crate::snapshot;
use crate::symbols::Symbols;
use crate::vm::context::{core_register_names, stop_context};
use crate::vm::ctl::Go;
use crate::vm::launch::LaunchSpec;
use crate::vm::wait::{wait_any, SerialWatch};
use crate::vm::{AttachSpec, Mode, Registry, Vm};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::tool;
use rmcp::tool_router;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const STEP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_INLINE_BYTES: usize = 4096;
const DEFAULT_LOG_BYTES: usize = 8192;
const MAX_LOG_BYTES: usize = 65536;
const RESET_WAIT: Duration = Duration::from_secs(2);
const SERIAL_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

type Out = Result<String, String>;

#[derive(Clone, Copy, Default)]
pub struct Flags {
    pub unsafe_ops: bool,
    pub replay: bool,
}

#[derive(Clone)]
pub struct Qmcp {
    reg: Arc<Registry>,
    flags: Flags,
}

impl Qmcp {
    pub fn new(reg: Arc<Registry>, flags: Flags) -> Self {
        Self { reg, flags }
    }

    fn vm(&self, id: &Option<String>) -> Result<Arc<Vm>, String> {
        self.reg.resolve(id.as_deref())
    }

    fn require_unsafe(&self, what: &str) -> Result<(), String> {
        match self.flags.unsafe_ops {
            true => Ok(()),
            false => Err(format!("{what} modifies the guest; start the server with --unsafe to allow it")),
        }
    }

    async fn status_json(&self, vm: &Vm) -> Value {
        let running = vm.rsp.is_running();
        let qmp_status = match &vm.qmp {
            Some(q) => q.exec("query-status", json!({}), CALL_TIMEOUT).await.ok(),
            None => None,
        };
        let threads = if running { None } else { vm.list_threads().await.ok() };
        let managed_tcg = vm.mode == Mode::Managed && vm.tcg;
        json!({
            "vm_id": vm.id, "mode": format!("{:?}", vm.mode).to_lowercase(), "arch": vm.arch,
            "accel": if vm.mode == Mode::Attached { "unknown(attached)" } else if vm.tcg { "tcg" } else { "kvm" },
            "state": if running { "running" } else { "stopped" }, "qmp_status": qmp_status, "threads": threads,
            "breakpoints": vm.breakpoints().await,
            "capabilities": {
                "fault_triage": managed_tcg, "reverse_debug": self.flags.replay && managed_tcg,
                "writes": self.flags.unsafe_ops, "serial": vm.serial_tx.lock().await.is_some(), "qmp": vm.qmp.is_some(),
            },
            "note": if managed_tcg { "" } else { "fault triage (-d int log) is available only for VMs we launch under TCG; KVM/attached VMs still get stops, registers, serial and QMP events" },
        })
    }

    async fn control(&self, vm: &Arc<Vm>, action: ControlAction) -> Out {
        match action {
            ControlAction::Continue => vm.go(Go::Continue, None).await.map(|_| json!({"state": "running"}).to_string()),
            ControlAction::Pause => {
                let stop = if vm.rsp.is_running() { Some(vm.pause().await?) } else { None };
                Ok(stop_context(vm, stop.as_ref(), "pause").await.to_string())
            }
            ControlAction::Reset => {
                if vm.rsp.is_running() {
                    vm.pause().await?;
                }
                reset_machine(vm).await?;
                vm.invalidate_caches().await;
                Ok(stop_context(vm, None, "reset").await.to_string())
            }
            ControlAction::Powerdown => vm.qmp()?.exec("system_powerdown", json!({}), CALL_TIMEOUT).await.map(|_| json!({"requested": "powerdown"}).to_string()),
            ControlAction::Kill => self.end_session(vm, true).await,
            ControlAction::Detach => self.end_session(vm, false).await,
        }
    }

    /// `kill` ends a managed VM; `detach` releases an attached one. The other combination is refused:
    /// killing an external QEMU is never our call, and detaching a managed one would orphan it.
    async fn end_session(&self, vm: &Arc<Vm>, kill: bool) -> Out {
        match (vm.mode, kill) {
            (Mode::Attached, true) => return Err("attached QEMU is owned by you and is never killed here; use action=detach".into()),
            (Mode::Managed, false) => return Err("managed VM: use action=kill (detach would leave an orphan QEMU)".into()),
            _ => {}
        }
        if kill {
            vm.quit_gracefully().await;
        } else {
            if vm.rsp.is_running() {
                vm.pause().await?;
            }
            vm.detach_rsp().await?;
        }
        self.reg.remove(&vm.id);
        vm.teardown();
        Ok(json!({"ended": vm.id, "qemu_killed": kill}).to_string())
    }
}

#[derive(Deserialize, JsonSchema)]
pub struct VmRef {
    /// Optional when exactly one VM is active.
    pub vm_id: Option<String>,
    /// Sample the running guest and classify hang vs idle vs alive (briefly pauses it).
    #[serde(default)]
    pub probe_hang: bool,
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ControlAction {
    Continue,
    Pause,
    Reset,
    Powerdown,
    /// Managed VMs only: SIGKILL the QEMU process group and clean up.
    Kill,
    /// Attached VMs only: resume the guest, release the stub, leave QEMU running.
    Detach,
}

#[derive(Deserialize, JsonSchema)]
pub struct ControlParams {
    pub vm_id: Option<String>,
    pub action: ControlAction,
}

#[derive(Deserialize, JsonSchema)]
pub struct WaitParams {
    pub vm_id: Option<String>,
    /// Max wait, default 10000, clamped to 50000.
    pub timeout_ms: Option<u64>,
    /// Also return when serial output not yet reported in an earlier response matches this regex.
    pub serial_regex: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct RegWrite {
    pub name: String,
    /// Hex (0x..) or decimal.
    pub value: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct RegsParams {
    pub vm_id: Option<String>,
    /// Register names; default is the core set (pc, flags, segment/control regs, GPRs).
    pub names: Option<Vec<String>>,
    /// vCPU number (1-based); default is the thread that last stopped.
    pub thread: Option<u32>,
    /// Write one register (requires --unsafe).
    pub set: Option<RegWrite>,
}

#[derive(Deserialize, JsonSchema, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum StepMode {
    /// One instruction, interrupts and timers masked (QEMU default).
    #[default]
    Into,
    /// One instruction with interrupts/timers enabled.
    IntoIrq,
    /// Reverse step (replay mode only).
    Back,
    /// Reverse continue to the previous breakpoint (replay mode only).
    ReverseContinue,
}

#[derive(Deserialize, JsonSchema)]
pub struct StepParams {
    pub vm_id: Option<String>,
    pub mode: Option<StepMode>,
    pub thread: Option<u32>,
}

#[derive(Deserialize, JsonSchema, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum BpKind {
    Sw,
    #[default]
    Hw,
    WatchWrite,
    WatchRead,
    WatchAccess,
}

impl BpKind {
    fn code(self) -> char {
        match self {
            Self::Sw => '0',
            Self::Hw => '1',
            Self::WatchWrite => '2',
            Self::WatchRead => '3',
            Self::WatchAccess => '4',
        }
    }
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum SetClearList {
    Set,
    Clear,
    List,
}

#[derive(Deserialize, JsonSchema)]
pub struct BreakpointParams {
    pub vm_id: Option<String>,
    pub action: SetClearList,
    /// Address (0x..) or symbol[+off]. x86 real mode: LINEAR address (cs*16+ip).
    pub at: Option<String>,
    pub kind: Option<BpKind>,
    /// Watchpoint length in bytes (default 1).
    pub len: Option<u32>,
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum MemAction {
    Read,
    /// Requires --unsafe.
    Write,
    Disasm,
}

#[derive(Deserialize, JsonSchema)]
pub struct MemParams {
    pub vm_id: Option<String>,
    pub action: MemAction,
    /// Address (0x..) or symbol[+off]; virtual unless `phys`.
    pub at: String,
    /// Bytes to read (default 64, max 4096).
    pub len: Option<usize>,
    pub phys: Option<bool>,
    /// Hex bytes for write.
    pub hex: Option<String>,
    /// Instructions to decode for disasm (default 8).
    pub count: Option<usize>,
    /// Force 16/32/64-bit decoding for disasm (default: from CPU mode).
    pub bits: Option<u32>,
    pub thread: Option<u32>,
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    Serial,
    /// QEMU's own log (-d int/cpu_reset/guest_errors under TCG, plus stderr).
    Qemu,
    Debugcon,
}

#[derive(Deserialize, JsonSchema)]
pub struct LogParams {
    pub vm_id: Option<String>,
    pub source: LogSource,
    /// Byte offset cursor from a previous `next` (omit for the tail).
    pub from: Option<u64>,
    /// Last N bytes (when `from` is omitted; default 8192).
    pub tail: Option<usize>,
    pub max_bytes: Option<usize>,
    /// Regex line filter.
    pub grep: Option<String>,
    /// Strip ANSI escapes (default true).
    pub strip_ansi: Option<bool>,
    /// Collapse repeated identical lines (default true).
    pub dedupe: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SerialWriteParams {
    pub vm_id: Option<String>,
    /// Text to send. With `escapes`, `\n \r \t \e \\ \xNN` are interpreted (Ctrl-C is `\x03`).
    pub text: String,
    #[serde(default)]
    pub escapes: bool,
    /// Append a newline (CR LF is not added; plain \n).
    #[serde(default)]
    pub newline: bool,
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum SnapAction {
    Save,
    Load,
    Delete,
    List,
}

#[derive(Deserialize, JsonSchema)]
pub struct SnapshotParams {
    pub vm_id: Option<String>,
    pub action: SnapAction,
    /// Snapshot name (letters, digits, _.- ).
    pub name: Option<String>,
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum SymAction {
    Load,
    Lookup,
    Nearest,
}

#[derive(Deserialize, JsonSchema)]
pub struct SymbolParams {
    pub vm_id: Option<String>,
    pub action: SymAction,
    /// load: ELF path. lookup: symbol name. nearest: address.
    pub arg: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct MonitorParams {
    pub vm_id: Option<String>,
    pub kind: MonitorKind,
    /// HMP: a command line. QMP: the command name (arguments in `args`).
    pub command: String,
    pub args: Option<Value>,
}

#[tool_router(server_handler)]
impl Qmcp {
    #[tool(description = "Launch a managed QEMU (TCG default) paused at CPU reset, with QMP, gdbstub, serial and QEMU-log capture wired up. No raw argv: a validated spec only.")]
    async fn vm_launch(&self, Parameters(spec): Parameters<LaunchSpec>) -> Out {
        if spec.replay.is_some() && !self.flags.replay {
            return Err("record/replay needs the server flag --experimental-replay".into());
        }
        let vm = self.reg.launch(spec).await?;
        Ok(self.status_json(&vm).await.to_string())
    }

    #[tool(description = "Attach to an already-running QEMU through its gdbstub (and optional QMP/serial sockets). Detaching never kills it.")]
    async fn vm_attach(&self, Parameters(spec): Parameters<AttachSpec>) -> Out {
        let vm = self.reg.attach(spec).await?;
        Ok(self.status_json(&vm).await.to_string())
    }

    #[tool(description = "VM state, vCPU threads, breakpoints, capability flags (fault triage, reverse debug, writes). probe_hang=true classifies a running guest as alive / idle / dead_hang / spin.")]
    async fn vm_status(&self, Parameters(p): Parameters<VmRef>) -> Out {
        let vm = self.vm(&p.vm_id)?;
        let mut status = self.status_json(&vm).await;
        if p.probe_hang {
            status["hang_probe"] = probe_hang(&vm).await?;
        }
        Ok(status.to_string())
    }

    #[tool(description = "Run control: continue, pause (returns the stop context), reset, powerdown, kill (managed only), detach (attached only).")]
    async fn vm_control(&self, Parameters(p): Parameters<ControlParams>) -> Out {
        let vm = self.vm(&p.vm_id)?;
        self.control(&vm, p.action).await
    }

    #[tool(description = "Block (max 50s) until a breakpoint/stop, a serial regex match, or guest shutdown/panic. Returns a stop-context bundle: regs, symbol, disassembly at PC, new serial text, new QMP events, crash class, recent faults.")]
    async fn vm_wait(&self, Parameters(p): Parameters<WaitParams>) -> Out {
        let vm = self.vm(&p.vm_id)?;
        let watch = match &p.serial_regex {
            Some(r) => Some(SerialWatch { re: compile_regex(r)?, from: vm.bundle_cursor.lock().unwrap().0 }), // output no bundle has reported yet
            None => None,
        };
        let waited = wait_any(&vm, Duration::from_millis(p.timeout_ms.unwrap_or(10_000)), watch).await?;
        let why = match (&waited.terminal_event, &waited.serial_match, &waited.stop) {
            (Some(_), _, _) => "guest_event",
            (_, Some(_), _) => "serial_match",
            (_, _, Some(_)) => "stop",
            _ => "timeout",
        };
        let mut ctx = stop_context(&vm, waited.stop.as_ref(), why).await;
        ctx["matched"] = json!(waited.serial_match.map(|m| m.0));
        ctx["event"] = json!(waited.terminal_event);
        Ok(ctx.to_string())
    }

    #[tool(description = "Read registers (default: core set) of a stopped target; optionally write one (requires --unsafe).")]
    async fn regs(&self, Parameters(p): Parameters<RegsParams>) -> Out {
        let vm = self.vm(&p.vm_id)?;
        if let Some(w) = &p.set {
            self.require_unsafe("writing a register")?;
            let value = crate::ops::parse_number(&w.value).ok_or("value must be hex (0x..) or decimal")?;
            vm.write_register(&w.name, value as u128, p.thread).await?;
        }
        let names = p.names.unwrap_or_else(|| core_register_names(&vm));
        let regs = vm.read_registers(&names, p.thread).await?;
        Ok(json!(regs.iter().map(|(n, v)| (n.clone(), format!("{v:#x}"))).collect::<std::collections::BTreeMap<_, _>>()).to_string())
    }

    #[tool(description = "Single-step and return the stop context. Reverse modes need --experimental-replay and a replay VM.")]
    async fn step(&self, Parameters(p): Parameters<StepParams>) -> Out {
        let vm = self.vm(&p.vm_id)?;
        let go = match p.mode.unwrap_or_default() {
            StepMode::Into => Go::Step { irq: false },
            StepMode::IntoIrq => Go::Step { irq: true },
            StepMode::Back => Go::ReverseStep,
            StepMode::ReverseContinue => Go::ReverseContinue,
        };
        if matches!(go, Go::ReverseStep | Go::ReverseContinue) && !self.flags.replay {
            return Err("reverse execution needs --experimental-replay and a VM launched with replay".into());
        }
        vm.go(go, p.thread).await?;
        let stop = vm.wait_for_stop(STEP_TIMEOUT).await?;
        Ok(stop_context(&vm, stop.as_ref(), "step").await.to_string())
    }

    #[tool(description = "Set/clear/list breakpoints and watchpoints (sw, hw, watch_write/read/access). `at` accepts an address or a symbol.")]
    async fn breakpoint(&self, Parameters(p): Parameters<BreakpointParams>) -> Out {
        let vm = self.vm(&p.vm_id)?;
        if let SetClearList::List = p.action {
            return Ok(json!(vm.breakpoints().await).to_string());
        }
        let addr = resolve_addr(&vm, p.at.as_deref().ok_or("`at` is required")?)?;
        let (kind, len) = (p.kind.unwrap_or_default().code(), p.len.unwrap_or(1));
        match p.action {
            SetClearList::Set => vm.set_breakpoint(kind, addr, len).await?,
            _ => vm.clear_breakpoint(kind, addr, len).await?,
        }
        Ok(json!({"ok": true, "addr": format!("{addr:#x}"), "count": vm.breakpoints().await.len()}).to_string())
    }

    #[tool(description = "Guest memory: read (hex+ascii), disasm (x86 native, aarch64/riscv64 via llvm-mc), write (requires --unsafe). Virtual by default, phys=true for physical.")]
    async fn mem(&self, Parameters(p): Parameters<MemParams>) -> Out {
        let vm = self.vm(&p.vm_id)?;
        let addr = resolve_addr(&vm, &p.at)?;
        let phys = p.phys.unwrap_or(false);
        match p.action {
            MemAction::Write => self.mem_write(&vm, addr, &p, phys).await,
            MemAction::Read => mem_read(&vm, addr, p.len.unwrap_or(64), phys, p.thread).await,
            MemAction::Disasm => mem_disasm(&vm, addr, &p, phys).await,
        }
    }

    #[tool(description = "Read a bounded capture buffer (serial, QEMU log, debugcon) with a cursor (`next`), optional regex filter, ANSI stripping and duplicate collapsing. Cursor reads report `dropped` bytes if the ring overflowed.")]
    async fn log_read(&self, Parameters(p): Parameters<LogParams>) -> Out {
        let vm = self.vm(&p.vm_id)?;
        let channel = match p.source {
            LogSource::Serial => vm.serial.clone(),
            LogSource::Qemu => vm.qemu_log.clone(),
            LogSource::Debugcon => vm.debugcon.clone().ok_or("no debugcon capture (launch with debugcon=true, x86 only)")?,
        };
        let max_bytes = p.max_bytes.unwrap_or(DEFAULT_LOG_BYTES).min(MAX_LOG_BYTES);
        let grep = p.grep.as_deref().map(compile_regex).transpose()?;
        let tail = p.from.is_none().then_some(p.tail.unwrap_or(DEFAULT_LOG_BYTES));
        let opts = ReadOpts { from: p.from, tail, max_bytes, grep, strip_ansi: p.strip_ansi.unwrap_or(true), dedupe: p.dedupe.unwrap_or(true) };
        let t = channel.read(&opts);
        Ok(json!({"text": t.text, "from": t.from, "next": t.next, "dropped": t.dropped}).to_string())
    }

    #[tool(description = "Type into the guest serial console (max 4096 bytes; escapes optional; newline optional).")]
    async fn serial_write(&self, Parameters(p): Parameters<SerialWriteParams>) -> Out {
        let vm = self.vm(&p.vm_id)?;
        let mut bytes = if p.escapes { unescape(&p.text)? } else { p.text.into_bytes() };
        if p.newline {
            bytes.push(b'\n');
        }
        if bytes.len() > MAX_SERIAL_WRITE {
            return Err(format!("payload {} bytes exceeds the {MAX_SERIAL_WRITE}-byte limit", bytes.len()));
        }
        let mut tx = vm.serial_tx.lock().await;
        let w = tx.as_mut().ok_or("this VM has no writable serial channel")?;
        let sent = async { w.write_all(&bytes).await?; w.flush().await };
        tokio::time::timeout(SERIAL_WRITE_TIMEOUT, sent).await.map_err(|_| "serial write timed out")?.map_err(|e| format!("serial write: {e}"))?;
        Ok(json!({"sent": bytes.len()}).to_string())
    }

    #[tool(description = "Snapshots via QMP jobs (works for diskless guests): save, load (returns the stop context and invalidates caches), delete, list.")]
    async fn snapshot(&self, Parameters(p): Parameters<SnapshotParams>) -> Out {
        let vm = self.vm(&p.vm_id)?;
        let qmp = vm.qmp()?;
        let name = p.name.as_deref().ok_or("`name` is required");
        match p.action {
            SnapAction::List => return Ok(json!({"snapshots": snapshot::list(qmp).await?}).to_string()),
            SnapAction::Save => snapshot::save(qmp, &vm.dir, name?).await?,
            SnapAction::Delete => snapshot::delete(qmp, &vm.dir, name?).await?,
            SnapAction::Load => snapshot::load(qmp, &vm.dir, name?).await?,
        }
        vm.invalidate_caches().await;
        Ok(stop_context(&vm, None, "snapshot").await.to_string())
    }

    #[tool(description = "Symbols from an ELF (native ELF+DWARF): load a file, look a name up, or find the nearest symbol+line for an address.")]
    async fn symbols(&self, Parameters(p): Parameters<SymbolParams>) -> Out {
        let vm = self.vm(&p.vm_id)?;
        let reply = match p.action {
            SymAction::Load => {
                *vm.symbols.lock().unwrap() = Symbols::load(&p.arg)?;
                json!({"loaded": p.arg})
            }
            SymAction::Lookup => json!({"addr": vm.symbols.lock().unwrap().lookup(&p.arg).map(|a| format!("{a:#x}"))}),
            SymAction::Nearest => json!({"at": vm.symbols.lock().unwrap().describe(resolve_addr(&vm, &p.arg)?)}),
        };
        Ok(reply.to_string())
    }

    #[tool(description = "Raw HMP/QMP escape hatch. Read-only by default (HMP info/x/xp/gva2gpa/print, QMP query-*); mutating commands need --unsafe; host-escaping commands are always refused.")]
    async fn monitor(&self, Parameters(p): Parameters<MonitorParams>) -> Out {
        check_monitor(p.kind, &p.command, self.flags.unsafe_ops)?;
        let vm = self.vm(&p.vm_id)?;
        let qmp = vm.qmp()?;
        match p.kind {
            MonitorKind::Hmp => qmp.hmp(&p.command).await.map(|text| json!({"output": text}).to_string()),
            MonitorKind::Qmp => qmp.exec(&p.command, p.args.unwrap_or(json!({})), CALL_TIMEOUT).await.map(|v| v.to_string()),
        }
    }
}

impl Qmcp {
    async fn mem_write(&self, vm: &Vm, addr: u64, p: &MemParams, phys: bool) -> Out {
        self.require_unsafe("writing guest memory")?;
        let data = hex_to_bytes(p.hex.as_deref().ok_or("`hex` is required for write")?)?;
        vm.write_memory(addr, &data, phys).await?;
        Ok(json!({"written": data.len(), "addr": format!("{addr:#x}")}).to_string())
    }
}

/// Managed VMs run with `-action reboot=shutdown` (to freeze at a triple fault), under which a bare
/// `system_reset` only pauses; flip the action to `reset` until QEMU's RESET event confirms the reset ran.
async fn reset_machine(vm: &Vm) -> Result<(), String> {
    let qmp = vm.qmp()?;
    if vm.mode == Mode::Attached {
        return qmp.exec("system_reset", json!({}), CALL_TIMEOUT).await.map(|_| ());
    }
    let cursor = vm.events.log.lock().unwrap().head();
    qmp.exec("set-action", json!({"reboot": "reset"}), CALL_TIMEOUT).await?;
    let reset = qmp.exec("system_reset", json!({}), CALL_TIMEOUT).await;
    let deadline = std::time::Instant::now() + RESET_WAIT;
    while reset.is_ok() && std::time::Instant::now() < deadline && !reset_event_since(vm, cursor) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    qmp.exec("set-action", json!({"reboot": "shutdown"}), CALL_TIMEOUT).await?;
    reset.map(|_| ())
}

fn reset_event_since(vm: &Vm, cursor: u64) -> bool {
    let (events, _) = vm.events.log.lock().unwrap().after(cursor, usize::MAX);
    events.iter().any(|e| e["event"] == "RESET")
}

async fn mem_read(vm: &Vm, addr: u64, len: usize, phys: bool, thread: Option<u32>) -> Out {
    let (bytes, error) = vm.read_memory(addr, len.min(MAX_INLINE_BYTES), phys, thread).await?;
    let ascii: String = bytes.iter().map(|b| if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' }).collect();
    Ok(json!({"addr": format!("{addr:#x}"), "len": bytes.len(), "hex": crate::decode::hex(&bytes), "ascii": ascii, "error": error}).to_string())
}

async fn mem_disasm(vm: &Vm, addr: u64, p: &MemParams, phys: bool) -> Out {
    let count = p.count.unwrap_or(8).clamp(1, 64);
    let (code, error) = vm.read_memory(addr, count * 15, phys, p.thread).await?;
    let bits = match p.bits {
        Some(b) => b,
        None => vm.mode_bits().await?,
    };
    let insns = crate::decode::disasm(&vm.arch, bits, addr, &code, count).await;
    Ok(json!({"bits": bits, "insns": insns, "error": error}).to_string())
}
