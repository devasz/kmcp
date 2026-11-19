//! One `Vm` = one QEMU (launched and supervised by us, or an external one we attached to).
//! Teardown rule: a managed QEMU is always killed; an attached one is never touched, only detached.

pub mod context;
pub mod ctl;
pub mod launch;
pub mod supervise;
pub mod wait;

use crate::logs::{self, Channel};
use crate::net::{Endpoint, Writer};
use crate::qmp::{Events, Qmp};
use crate::regs::{fetch_regdefs, RegCache, RegDefs};
use crate::rsp::Rsp;
use crate::symbols::Symbols;
use crate::triage;
use crate::Res;
use launch::LaunchSpec;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

const QUIT_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
pub const MAX_VMS: usize = 4;
const CONNECT_WAIT: Duration = Duration::from_secs(5);
const QEMU_LOG_BYTES: usize = 8 << 20;
const DEBUGCON_BYTES: usize = 1 << 20;
const DEFAULT_SERIAL_KB: usize = 4096;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    Managed,
    Attached,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Breakpoint {
    pub kind: char, // '0' sw, '1' hw, '2' write, '3' read, '4' access
    pub addr: u64,
    pub len: u32,
}

/// State that must change together with RSP traffic, so it lives behind the per-VM op lock.
#[derive(Default)]
pub struct OpState {
    /// Thread the user wants register/memory ops on (vCPU number, 1-based).
    pub thread: Option<u32>,
    /// Thread currently selected in the stub (`Hg`); differs until the next op re-selects.
    pub selected: Option<u32>,
    /// Last `Qqemu.sstep` flags sent.
    pub sstep: Option<u32>,
    /// Last `Qqemu.PhyMemMode` value sent.
    pub phys: bool,
    pub breakpoints: Vec<Breakpoint>,
}

pub struct Vm {
    pub id: String,
    pub dir: PathBuf,
    pub arch: String,
    pub tcg: bool,
    pub mode: Mode,
    pub qmp: Option<Qmp>,
    pub events: Arc<Events>,
    pub rsp: Rsp,
    pub multiprocess: bool,
    pub regdefs: RegDefs,
    pub regcache: AsyncMutex<RegCache>,
    pub op: AsyncMutex<OpState>,
    pub serial: Arc<Channel>,
    pub serial_tx: AsyncMutex<Option<Writer>>,
    pub debugcon: Option<Arc<Channel>>,
    pub qemu_log: Arc<Channel>,
    /// First fault in the `-d int` log since the VM was last resumed (see `FirstFaultLatch`).
    pub first_fault: Arc<Mutex<Option<triage::Fault>>>,
    pub symbols: Mutex<Symbols>,
    /// (serial offset, event cursor) already reported in a stop-context bundle.
    pub bundle_cursor: Mutex<(u64, u64)>,
    child: Mutex<Option<Child>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    _fifo_keepalive: Option<tokio::net::unix::pipe::Sender>,
}

impl Vm {
    pub fn qmp(&self) -> Res<&Qmp> {
        self.qmp.as_ref().ok_or_else(|| "no QMP socket attached to this VM".to_string())
    }

    /// Ask QEMU to `quit` so it flushes state (record/replay log) before `teardown` SIGKILLs the group.
    pub async fn quit_gracefully(&self) {
        let Some(qmp) = &self.qmp else { return };
        if qmp.exec("quit", serde_json::json!({}), QUIT_WAIT).await.is_err() {
            return;
        }
        let deadline = std::time::Instant::now() + QUIT_WAIT;
        while std::time::Instant::now() < deadline && self.child.lock().unwrap().as_mut().is_some_and(|c| c.try_wait().ok().flatten().is_none()) {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    /// Stop our tasks, kill the process group (managed only: an attached VM has no child) and delete the run dir.
    pub fn teardown(&self) {
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
        if let Some(mut child) = self.child.lock().unwrap().take() {
            supervise::kill_group(&mut child);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }

}

impl Drop for Vm {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Kills the child if `open` fails half-way.
struct SpawnGuard(Option<Child>);

impl SpawnGuard {
    fn release(mut self) -> Child {
        self.0.take().expect("child present")
    }
}

impl Drop for SpawnGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            supervise::kill_group(&mut c);
        }
    }
}

#[derive(Default)]
pub struct Registry {
    vms: Mutex<BTreeMap<String, Arc<Vm>>>,
    counter: AtomicU32,
}

impl Registry {
    pub fn resolve(&self, id: Option<&str>) -> Res<Arc<Vm>> {
        let vms = self.vms.lock().unwrap();
        match (id, vms.len()) {
            (Some(id), _) => vms.get(id).cloned().ok_or_else(|| format!("no VM '{id}' (active: {:?})", vms.keys().collect::<Vec<_>>())),
            (None, 1) => Ok(vms.values().next().cloned().expect("one vm")),
            (None, 0) => Err("no active VM; call vm_launch or vm_attach".into()),
            (None, _) => Err(format!("several VMs active, pass vm_id (one of {:?})", vms.keys().collect::<Vec<_>>())),
        }
    }

    pub fn remove(&self, id: &str) -> Option<Arc<Vm>> {
        self.vms.lock().unwrap().remove(id)
    }

    pub fn shutdown_all(&self) {
        let all: Vec<_> = std::mem::take(&mut *self.vms.lock().unwrap()).into_values().collect();
        all.iter().for_each(|vm| vm.teardown());
        supervise::kill_all_groups();
    }

    fn next_id(&self) -> Res<String> {
        if self.vms.lock().unwrap().len() >= MAX_VMS {
            return Err(format!("at most {MAX_VMS} concurrent VMs"));
        }
        Ok(format!("{:x}-{}", std::process::id(), self.counter.fetch_add(1, Ordering::Relaxed) + 1))
    }

    fn insert(&self, vm: Vm) -> Arc<Vm> {
        let vm = Arc::new(vm);
        self.vms.lock().unwrap().insert(vm.id.clone(), vm.clone());
        vm
    }

    pub async fn launch(&self, spec: LaunchSpec) -> Res<Arc<Vm>> {
        let id = self.next_id()?;
        let dir = supervise::run_root()?.join(&id);
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        supervise::restrict(&dir)?;
        let vm = match open_managed(&id, &dir, &spec).await {
            Ok(vm) => vm,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        Ok(self.insert(vm))
    }

    pub async fn attach(&self, a: AttachSpec) -> Res<Arc<Vm>> {
        let id = self.next_id()?;
        // the run dir only holds the snapshot carrier image for attached VMs; nothing of the external QEMU lives there
        let dir = supervise::run_root()?.join(&id);
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        supervise::restrict(&dir)?;
        match open_attached(&id, dir.clone(), a).await {
            Ok(vm) => Ok(self.insert(vm)),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                Err(e)
            }
        }
    }
}

#[derive(serde::Deserialize, schemars::JsonSchema, Default)]
pub struct AttachSpec {
    /// gdbstub endpoint: tcp:host:port, unix:/path or /path.
    pub gdb: String,
    /// Optional QMP endpoint (needed for snapshots, reset, events, status).
    pub qmp: Option<String>,
    /// Optional serial chardev socket endpoint (QEMU `-serial unix:...,server`).
    pub serial: Option<String>,
    /// Architecture of the target (x86_64, aarch64, riscv64). Default x86_64.
    pub arch: Option<String>,
    pub elf: Option<String>,
}

async fn connect_rsp(ep: &Endpoint) -> Res<(Rsp, bool)> {
    let (r, w) = ep.connect(CONNECT_WAIT).await?;
    let mut rsp = Rsp::new(r, w);
    let supported = rsp.request_ok("qSupported:multiprocess+;swbreak+;hwbreak+;vContSupported+;xmlRegisters=i386").await?;
    rsp.packet_size = supported.split(';').find_map(|f| f.strip_prefix("PacketSize=")).and_then(|n| usize::from_str_radix(n, 16).ok()).unwrap_or(4096);
    Ok((rsp, supported.contains("multiprocess+")))
}

async fn open_managed(id: &str, dir: &std::path::Path, spec: &LaunchSpec) -> Res<Vm> {
    let plan = launch::build(spec, dir)?;
    let symbols = spec.elf.as_deref().map(Symbols::load).transpose()?.unwrap_or_default();
    let qemu_log = Channel::new(QEMU_LOG_BYTES);
    let first_fault = Arc::new(Mutex::new(None));
    let mut tasks = Vec::new();
    let fifo = match plan.tcg {
        true => {
            let (rx, keep) = logs::open_log_fifo(&dir.join("qemu.log"))?;
            let mut latch = triage::FirstFaultLatch::new(&plan.arch, first_fault.clone());
            tasks.push(logs::pump_with(rx, qemu_log.clone(), move |chunk| latch.feed(chunk)));
            Some(keep)
        }
        false => None,
    };
    let guard = SpawnGuard(Some(supervise::spawn_qemu(&plan.argv, &dir.join("qemu.stderr"))?));
    supervise::write_pidfile(dir, guard.0.as_ref().expect("child").id() as i32)?;
    let sockets = connect_all(dir, spec.debugcon, &mut tasks, spec.serial_kb).await.map_err(|e| with_stderr(e, dir))?;
    let mut vm = assemble(id, dir.to_path_buf(), &plan.arch, plan.tcg, Mode::Managed, sockets, (qemu_log, first_fault), symbols, tasks).await.map_err(|e| with_stderr(e, dir))?;
    vm.child = Mutex::new(Some(guard.release()));
    vm._fifo_keepalive = fifo;
    Ok(vm)
}

fn with_stderr(err: String, dir: &std::path::Path) -> String {
    let stderr = std::fs::read_to_string(dir.join("qemu.stderr")).unwrap_or_default();
    match stderr.trim().is_empty() {
        true => err,
        false => format!("{err}\nqemu stderr: {}", stderr.trim().chars().take(600).collect::<String>()),
    }
}

struct Sockets {
    qmp: Option<Qmp>,
    events: Arc<Events>,
    rsp: Rsp,
    multiprocess: bool,
    serial: Arc<Channel>,
    serial_tx: Option<Writer>,
    debugcon: Option<Arc<Channel>>,
}

async fn connect_all(dir: &std::path::Path, debugcon: bool, tasks: &mut Vec<JoinHandle<()>>, serial_kb: Option<usize>) -> Res<Sockets> {
    let events = Events::new();
    let qmp = Qmp::connect(&Endpoint::Unix(dir.join("qmp.sock").to_string_lossy().into()), CONNECT_WAIT, events.clone()).await?;
    let serial = Channel::new(serial_kb.unwrap_or(DEFAULT_SERIAL_KB).clamp(1, 65536) * 1024);
    let (sr, sw) = Endpoint::Unix(dir.join("serial.sock").to_string_lossy().into()).connect(CONNECT_WAIT).await?;
    tasks.push(logs::pump(sr, serial.clone()));
    let dbg = match debugcon {
        true => {
            let ch = Channel::new(DEBUGCON_BYTES);
            let (dr, _dw) = Endpoint::Unix(dir.join("debugcon.sock").to_string_lossy().into()).connect(CONNECT_WAIT).await?;
            tasks.push(logs::pump(dr, ch.clone()));
            Some(ch)
        }
        false => None,
    };
    let (rsp, multiprocess) = connect_rsp(&Endpoint::Unix(dir.join("gdb.sock").to_string_lossy().into())).await?;
    Ok(Sockets { qmp: Some(qmp), events, rsp, multiprocess, serial, serial_tx: Some(sw), debugcon: dbg })
}

#[allow(clippy::too_many_arguments)]
async fn assemble(id: &str, dir: PathBuf, arch: &str, tcg: bool, mode: Mode, s: Sockets, (qemu_log, first_fault): (Arc<Channel>, Arc<Mutex<Option<triage::Fault>>>), symbols: Symbols, tasks: Vec<JoinHandle<()>>) -> Res<Vm> {
    let regdefs = fetch_regdefs(&s.rsp).await?;
    s.rsp.request_ok("?").await?; // initial stop reply; also proves the stub is stopped
    Ok(Vm {
        id: id.into(),
        dir,
        arch: arch.into(),
        tcg,
        mode,
        qmp: s.qmp,
        events: s.events,
        rsp: s.rsp,
        multiprocess: s.multiprocess,
        regdefs,
        regcache: Default::default(),
        op: Default::default(),
        serial: s.serial,
        serial_tx: AsyncMutex::new(s.serial_tx),
        debugcon: s.debugcon,
        qemu_log,
        first_fault,
        symbols: Mutex::new(symbols),
        bundle_cursor: Mutex::new((0, 0)),
        child: Mutex::new(None),
        tasks: Mutex::new(tasks),
        _fifo_keepalive: None,
    })
}

async fn open_attached(id: &str, dir: PathBuf, a: AttachSpec) -> Res<Vm> {
    let events = Events::new();
    let qmp = match &a.qmp {
        Some(ep) => Some(Qmp::connect(&Endpoint::parse(ep)?, CONNECT_WAIT, events.clone()).await?),
        None => None,
    };
    let mut tasks = Vec::new();
    let serial = Channel::new(DEFAULT_SERIAL_KB * 1024);
    let serial_tx = match &a.serial {
        Some(ep) => {
            let (r, w) = Endpoint::parse(ep)?.connect(CONNECT_WAIT).await?;
            tasks.push(logs::pump(r, serial.clone()));
            Some(w)
        }
        None => None,
    };
    let (rsp, multiprocess) = connect_rsp(&Endpoint::parse(&a.gdb)?).await?;
    let sockets = Sockets { qmp, events, rsp, multiprocess, serial, serial_tx, debugcon: None };
    let symbols = a.elf.as_deref().map(Symbols::load).transpose()?.unwrap_or_default();
    let arch = a.arch.unwrap_or_else(|| "x86_64".into());
    let log = Channel::new(1);
    assemble(id, dir, &arch, false, Mode::Attached, sockets, (log, Default::default()), symbols, tasks).await
}
