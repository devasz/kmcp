//! QMP client: greeting + capabilities handshake, id-demuxed replies, events into a bounded log.
//! Every call has a timeout; a dead socket fails all pending calls immediately.

use crate::net::{Endpoint, Reader, Writer};
use crate::ring::EventLog;
use crate::Res;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{oneshot, Notify};

const EVENT_CAP: usize = 1024;
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Events {
    pub log: Mutex<EventLog>,
    pub notify: Notify,
}

impl Events {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { log: Mutex::new(EventLog::new(EVENT_CAP)), notify: Notify::new() })
    }
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>;

pub struct Qmp {
    writer: tokio::sync::Mutex<Writer>,
    pending: Pending,
    next_id: AtomicU64,
    alive: Arc<AtomicBool>,
}

impl Qmp {
    pub async fn connect(ep: &Endpoint, wait: Duration, events: Arc<Events>) -> Res<Self> {
        let (r, mut w) = ep.connect(wait).await?;
        let mut lines = BufReader::new(r);
        let greeting = read_json(&mut lines).await?;
        if greeting.get("QMP").is_none() {
            return Err(format!("not a QMP socket (greeting: {greeting})"));
        }
        send_json(&mut w, &json!({"execute": "qmp_capabilities"})).await?;
        loop {
            let msg = read_json(&mut lines).await?;
            if msg.get("return").is_some() {
                break;
            }
            if msg.get("error").is_some() {
                return Err(format!("qmp_capabilities failed: {msg}"));
            }
        }
        let pending: Pending = Arc::default();
        let alive = Arc::new(AtomicBool::new(true));
        tokio::spawn(read_loop(lines, pending.clone(), events.clone(), alive.clone()));
        Ok(Self { writer: w.into(), pending, next_id: AtomicU64::new(1), alive })
    }

    /// Run a QMP command; returns the `return` value or the QMP error description.
    pub async fn exec(&self, cmd: &str, args: Value, timeout: Duration) -> Res<Value> {
        if !self.alive.load(Ordering::Relaxed) {
            return Err(format!("{cmd}: QMP connection closed (QEMU exited?)"));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let sent = send_json(&mut *self.writer.lock().await, &json!({"execute": cmd, "arguments": args, "id": id})).await;
        let reply = match sent {
            Ok(()) => tokio::time::timeout(timeout, rx).await,
            Err(e) => return self.fail(id, e),
        };
        match reply {
            Ok(Ok(msg)) => reply_value(cmd, msg),
            Ok(Err(_)) => Err(format!("{cmd}: QMP connection closed")),
            Err(_) => self.fail(id, format!("{cmd}: timed out after {timeout:?}")),
        }
    }

    fn fail<T>(&self, id: u64, msg: String) -> Res<T> {
        self.pending.lock().unwrap().remove(&id);
        Err(msg)
    }

    /// HMP via QMP. HMP reports failures as a *successful* string, so the usual error prefixes are mapped to Err.
    pub async fn hmp(&self, line: &str) -> Res<String> {
        let out = self.exec("human-monitor-command", json!({"command-line": line}), CALL_TIMEOUT).await?;
        let text = out.as_str().unwrap_or_default().to_string();
        match text.starts_with("unknown command:") || text.starts_with("Error:") {
            true => Err(format!("hmp '{line}': {}", text.trim())),
            false => Ok(text),
        }
    }
}

fn reply_value(cmd: &str, msg: Value) -> Res<Value> {
    match msg.get("error") {
        Some(e) => Err(format!("{cmd}: {}", e["desc"].as_str().unwrap_or("unknown QMP error"))),
        None => Ok(msg["return"].clone()),
    }
}

async fn send_json(w: &mut Writer, v: &Value) -> Res<()> {
    let mut line = v.to_string();
    line.push('\n');
    w.write_all(line.as_bytes()).await.map_err(|e| format!("qmp write: {e}"))
}

async fn read_json(r: &mut BufReader<Reader>) -> Res<Value> {
    let mut line = String::new();
    match r.read_line(&mut line).await {
        Ok(0) => Err("QMP socket closed".into()),
        Ok(_) => serde_json::from_str(&line).map_err(|e| format!("bad QMP json: {e}")),
        Err(e) => Err(format!("qmp read: {e}")),
    }
}

async fn read_loop(mut r: BufReader<Reader>, pending: Pending, events: Arc<Events>, alive: Arc<AtomicBool>) {
    while let Ok(msg) = read_json(&mut r).await {
        if msg.get("event").is_some() {
            events.log.lock().unwrap().push(msg);
            events.notify.notify_waiters();
        } else if let Some(tx) = msg["id"].as_u64().and_then(|id| pending.lock().unwrap().remove(&id)) {
            let _ = tx.send(msg);
        }
    }
    alive.store(false, Ordering::Relaxed);
    pending.lock().unwrap().clear(); // drops senders: callers fail fast instead of timing out
    events.notify.notify_waiters();
}
