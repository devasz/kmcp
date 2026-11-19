//! kmcp: out-of-band QEMU + kernel debugging MCP server (QMP + gdbstub RSP + serial; zero guest code).

mod decode;
mod logs;
mod net;
mod ops;
mod qmp;
mod regs;
mod ring;
mod rsp;
mod snapshot;
mod symbols;
mod tools;
mod triage;
mod vm;

use rmcp::{transport::stdio, ServiceExt};
use std::sync::Arc;
use tools::{Flags, Qmcp};

pub type Res<T> = Result<T, String>;

const USAGE: &str = "kmcp [--unsafe] [--experimental-replay] [--systemd]\n  --unsafe              allow guest memory/register writes and mutating monitor commands\n  --experimental-replay allow record/replay launches and reverse stepping (TCG only)\n  --systemd             run QEMU in a transient `systemd-run --user --scope` (extra cleanup if we are SIGKILLed)";

fn parse_flags() -> Result<(Flags, bool), String> {
    let (mut flags, mut systemd) = (Flags::default(), false);
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--unsafe" => flags.unsafe_ops = true,
            "--experimental-replay" => flags.replay = true,
            "--systemd" => systemd = true,
            _ => return Err(format!("unknown argument '{arg}'\n{USAGE}")),
        }
    }
    Ok((flags, systemd))
}

/// SIGTERM/SIGINT: kill every managed QEMU group, then exit.
fn exit_on_signals(reg: Arc<vm::Registry>) {
    use tokio::signal::unix::{signal, SignalKind};
    tokio::spawn(async move {
        let (Ok(mut term), Ok(mut int)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else { return };
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
        reg.shutdown_all();
        std::process::exit(0);
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (flags, systemd) = parse_flags()?;
    if systemd {
        vm::supervise::use_systemd_scope();
    }
    if let Ok(root) = vm::supervise::run_root() {
        let reaped = vm::supervise::reap_stale(&root);
        if reaped > 0 {
            eprintln!("kmcp: reaped {reaped} stale QEMU instance(s) from a previous crash");
        }
    }
    let reg = Arc::new(vm::Registry::default());
    exit_on_signals(reg.clone());
    let running = Qmcp::new(reg.clone(), flags).serve(stdio()).await?;
    running.waiting().await?;
    reg.shutdown_all(); // client closed stdin
    Ok(())
}
