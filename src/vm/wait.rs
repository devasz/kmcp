//! `vm_wait`: block (bounded) until the first of: a gdbstub stop, a serial regex match, or a
//! terminal QMP event (guest shutdown/panic) that the gdbstub never reports as a stop.

use super::Vm;
use crate::rsp::Stop;
use crate::Res;
use regex::Regex;
use serde_json::Value;
use std::time::{Duration, Instant};

pub const MAX_WAIT: Duration = Duration::from_secs(50);
const EVENT_STOP_GRACE: Duration = Duration::from_millis(300);

pub struct SerialWatch {
    pub re: Regex,
    pub from: u64,
}

#[derive(Default)]
pub struct Waited {
    pub stop: Option<Stop>,
    /// (matching line, offset just past the match)
    pub serial_match: Option<(String, u64)>,
    pub terminal_event: Option<Value>,
}

fn terminal_event_since(vm: &Vm, cursor: u64) -> Option<Value> {
    let (events, _) = vm.events.log.lock().unwrap().after(cursor, usize::MAX);
    events.into_iter().find(|e| matches!(e["event"].as_str(), Some("SHUTDOWN" | "GUEST_PANICKED")))
}

async fn serial_or_never(vm: &Vm, watch: Option<&SerialWatch>, timeout: Duration) -> Option<(String, u64)> {
    match watch {
        Some(w) => vm.serial.wait_regex(&w.re, w.from, timeout).await,
        None => std::future::pending().await,
    }
}

pub async fn wait_any(vm: &Vm, timeout: Duration, watch: Option<SerialWatch>) -> Res<Waited> {
    let cursor = vm.events.log.lock().unwrap().head();
    let deadline = Instant::now() + timeout.min(MAX_WAIT);
    loop {
        let notified = vm.events.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(e) = terminal_event_since(vm, cursor) {
            // the gdbstub reports the QMP-side pause as a stop a moment later; collect it so state/regs are accurate
            let stop = vm.wait_for_stop(EVENT_STOP_GRACE).await?;
            return Ok(Waited { stop, terminal_event: Some(e), ..Default::default() });
        }
        let left = deadline.saturating_duration_since(Instant::now());
        tokio::select! {
            stop = vm.wait_for_stop(left) => return Ok(Waited { stop: stop?, ..Default::default() }),
            hit = serial_or_never(vm, watch.as_ref(), left) => return Ok(Waited { serial_match: hit, ..Default::default() }),
            _ = &mut notified => {}
        }
    }
}
