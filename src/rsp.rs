//! GDB Remote Serial Protocol client for QEMU's gdbstub.
//!
//! Stub rules this client enforces (all verified against QEMU 11.1.3, see ADR-0001 §3):
//! - every byte received pauses the VM, so while the target runs the *only* byte we send is 0x03;
//! - T05 is ambiguous, so callers read the PC after each stop;
//! - a reader task owns the stream and routes packets: stop replies (while running) update shared
//!   state, everything else is a reply to the single in-flight request.

use crate::net::{Reader, Writer};
use crate::Res;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq)]
pub struct Stop {
    pub kind: char,
    pub signal: u8,
    pub thread: Option<u32>,
    pub watch: Option<u64>,
    pub raw: String,
}

impl Stop {
    pub fn parse(p: &str) -> Option<Self> {
        let kind = p.chars().next().filter(|c| matches!(c, 'T' | 'S' | 'W' | 'X'))?;
        let signal = u8::from_str_radix(p.get(1..3)?, 16).ok()?;
        let fields = p.get(3..).unwrap_or("").split(';').filter_map(|f| f.split_once(':'));
        let (mut thread, mut watch) = (None, None);
        for (key, val) in fields {
            match key {
                "thread" => thread = parse_thread_id(val),
                "watch" | "rwatch" | "awatch" => watch = u64::from_str_radix(val, 16).ok(),
                _ => {}
            }
        }
        Some(Self { kind, signal, thread, watch, raw: p.to_string() })
    }

    pub fn exited(&self) -> bool {
        matches!(self.kind, 'W' | 'X')
    }
}

/// `p01.0a` / `0a` / `p1.a` -> 10
pub fn parse_thread_id(s: &str) -> Option<u32> {
    let tid = s.rsplit_once('.').map_or(s.trim_start_matches('p'), |(_, t)| t);
    u32::from_str_radix(tid, 16).ok()
}

#[derive(Default)]
struct Shared {
    running: AtomicBool,
    poisoned: AtomicBool,
    closed: AtomicBool,
    last_stop: Mutex<Option<Stop>>,
}

pub struct Rsp {
    writer: Arc<tokio::sync::Mutex<Writer>>,
    replies: tokio::sync::Mutex<mpsc::UnboundedReceiver<String>>,
    stops: watch::Sender<u64>,
    sh: Arc<Shared>,
    pub packet_size: usize,
}

impl Rsp {
    pub fn new(r: Reader, w: Writer) -> Self {
        let writer = Arc::new(tokio::sync::Mutex::new(w));
        let (tx, rx) = mpsc::unbounded_channel();
        let (stops, _) = watch::channel(0u64);
        let sh = Arc::new(Shared::default());
        tokio::spawn(read_loop(r, writer.clone(), tx, stops.clone(), sh.clone()));
        Self { writer, replies: rx.into(), stops, sh, packet_size: 4096 }
    }

    pub fn is_running(&self) -> bool {
        self.sh.running.load(Ordering::SeqCst)
    }

    pub fn is_usable(&self) -> bool {
        !self.sh.poisoned.load(Ordering::SeqCst) && !self.sh.closed.load(Ordering::SeqCst)
    }

    pub fn last_stop(&self) -> Option<Stop> {
        self.sh.last_stop.lock().unwrap().clone()
    }

    async fn write_raw(&self, bytes: &[u8]) -> Res<()> {
        self.writer.lock().await.write_all(bytes).await.map_err(|e| format!("rsp write: {e}"))
    }

    fn check_usable(&self) -> Res<()> {
        match (self.sh.closed.load(Ordering::SeqCst), self.sh.poisoned.load(Ordering::SeqCst)) {
            (true, _) => Err("gdbstub connection closed".into()),
            (_, true) => Err("gdbstub session poisoned by an earlier timeout/desync; reattach".into()),
            _ => Ok(()),
        }
    }

    /// One command, one reply. Only legal while the target is stopped.
    pub async fn request(&self, payload: &str, timeout: Duration) -> Res<String> {
        self.check_usable()?;
        if self.is_running() {
            return Err("target is running; pause it first (only 0x03 may be sent while running)".into());
        }
        let mut rx = self.replies.lock().await;
        while rx.try_recv().is_ok() {} // stale replies would desync the pairing
        self.write_raw(&frame(payload)).await?;
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, rx.recv()).await {
                Ok(Some(p)) if is_console_output(&p) => continue,
                Ok(Some(p)) => return Ok(p),
                Ok(None) => return Err("gdbstub connection closed".into()),
                Err(_) => {
                    self.sh.poisoned.store(true, Ordering::SeqCst);
                    return Err(format!("gdbstub did not answer '{}' within {timeout:?}; session poisoned", abbreviate(payload)));
                }
            }
        }
    }

    /// Like `request`, but an `Exx` reply becomes an error.
    pub async fn request_ok(&self, payload: &str) -> Res<String> {
        let reply = self.request(payload, REQUEST_TIMEOUT).await?;
        match is_error_reply(&reply) {
            true => Err(format!("stub rejected '{}': {reply}", abbreviate(payload))),
            false => Ok(reply),
        }
    }

    /// Start the target (e.g. `vCont;c`, `vCont;s:p1.1`). Returns immediately; use `wait_stop`.
    pub async fn resume(&self, payload: &str) -> Res<()> {
        self.check_usable()?;
        if self.is_running() {
            return Err("target already running".into());
        }
        *self.sh.last_stop.lock().unwrap() = None;
        self.sh.running.store(true, Ordering::SeqCst);
        let sent = self.write_raw(&frame(payload)).await;
        if sent.is_err() {
            self.sh.running.store(false, Ordering::SeqCst);
        }
        sent
    }

    /// Ask a running target to stop (Ctrl-C byte). No-op when already stopped.
    pub async fn interrupt(&self) -> Res<()> {
        match self.is_running() {
            true => self.write_raw(&[0x03]).await,
            false => Ok(()),
        }
    }

    /// Wait for the target to stop. `None` means it is still running at the deadline (not an error).
    pub async fn wait_stop(&self, timeout: Duration) -> Option<Stop> {
        let mut changed = self.stops.subscribe();
        let deadline = Instant::now() + timeout;
        while self.is_running() && !self.sh.closed.load(Ordering::SeqCst) {
            let left = deadline.saturating_duration_since(Instant::now());
            if tokio::time::timeout(left, changed.changed()).await.is_err() {
                return None;
            }
        }
        self.last_stop()
    }

    /// Interrupt and wait; used before operations that need a stopped target.
    pub async fn stop_now(&self) -> Res<Stop> {
        self.interrupt().await?;
        self.wait_stop(Duration::from_secs(3)).await.ok_or_else(|| "target did not stop after interrupt".to_string())
    }
}

fn is_error_reply(p: &str) -> bool {
    p.len() == 3 && p.starts_with('E') && p[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// `O<hex>` console output vs the plain `OK` reply.
fn is_console_output(p: &str) -> bool {
    p.len() > 1 && p.starts_with('O') && p != "OK" && p[1..].len() % 2 == 0 && p[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn abbreviate(s: &str) -> String {
    s.chars().take(40).collect()
}

/// `$payload#cs` with `$ # } *` escaped.
pub fn frame(payload: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(payload.len());
    for b in payload.bytes() {
        if matches!(b, b'$' | b'#' | b'}' | b'*') {
            body.extend([b'}', b ^ 0x20]);
        } else {
            body.push(b);
        }
    }
    let sum = body.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(b'$');
    out.extend(body);
    out.extend(format!("#{sum:02x}").bytes());
    out
}

/// Incremental packet parser: feed bytes, get unescaped payloads. Bad checksums yield `Err`.
#[derive(Default)]
pub struct Parser {
    buf: Vec<u8>,
    in_packet: bool,
    sum_chars: usize,
}

impl Parser {
    pub fn feed(&mut self, byte: u8) -> Option<Result<String, ()>> {
        if !self.in_packet {
            if byte == b'$' {
                (self.in_packet, self.sum_chars) = (true, 0);
                self.buf.clear();
            }
            return None;
        }
        if self.sum_chars > 0 || byte == b'#' {
            return self.feed_checksum(byte);
        }
        self.buf.push(byte);
        None
    }

    fn feed_checksum(&mut self, byte: u8) -> Option<Result<String, ()>> {
        self.sum_chars += 1;
        self.buf.push(byte);
        if self.sum_chars < 3 {
            return None;
        }
        self.in_packet = false;
        let n = self.buf.len();
        let (body, cs) = (&self.buf[..n - 3], &self.buf[n - 2..]);
        let want = std::str::from_utf8(cs).ok().and_then(|s| u8::from_str_radix(s, 16).ok());
        let got = body.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        Some(match want == Some(got) {
            true => Ok(unescape(body)),
            false => Err(()),
        })
    }
}

fn unescape(body: &[u8]) -> String {
    let mut out = Vec::with_capacity(body.len());
    let mut it = body.iter();
    while let Some(&b) = it.next() {
        match (b, b == b'}') {
            (_, true) => out.extend(it.next().map(|n| n ^ 0x20)),
            _ => out.push(b),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn read_loop(mut r: Reader, w: Arc<tokio::sync::Mutex<Writer>>, replies: mpsc::UnboundedSender<String>, stops: watch::Sender<u64>, sh: Arc<Shared>) {
    let mut parser = Parser::default();
    let mut chunk = [0u8; 4096];
    'outer: loop {
        let n = match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for &byte in &chunk[..n] {
            let Some(parsed) = parser.feed(byte) else { continue };
            let ack: &[u8] = if parsed.is_ok() { b"+" } else { b"-" };
            if w.lock().await.write_all(ack).await.is_err() {
                break 'outer;
            }
            match parsed {
                Ok(p) => route(p, &replies, &stops, &sh),
                Err(()) => sh.poisoned.store(true, Ordering::SeqCst),
            }
        }
    }
    sh.closed.store(true, Ordering::SeqCst);
    sh.running.store(false, Ordering::SeqCst);
    stops.send_modify(|v| *v += 1);
}

fn route(p: String, replies: &mpsc::UnboundedSender<String>, stops: &watch::Sender<u64>, sh: &Shared) {
    if sh.running.load(Ordering::SeqCst) {
        if let Some(stop) = Stop::parse(&p) {
            *sh.last_stop.lock().unwrap() = Some(stop);
            sh.running.store(false, Ordering::SeqCst);
            stops.send_modify(|v| *v += 1);
        }
        return; // console output (O...) while running carries nothing we need
    }
    let _ = replies.send(p);
}

pub fn hex_to_bytes(s: &str) -> Res<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex '{}'", abbreviate(s)));
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("bad hex '{}'", abbreviate(s)))).collect()
}

pub fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(bytes: &[u8]) -> Vec<Result<String, ()>> {
        let mut p = Parser::default();
        bytes.iter().filter_map(|b| p.feed(*b)).collect()
    }

    #[test]
    fn frame_roundtrip_with_escapes() {
        let framed = frame("a$b#c}d*e");
        assert_eq!(parse_all(&framed), vec![Ok("a$b#c}d*e".to_string())]);
    }

    #[test]
    fn parser_skips_acks_and_rejects_bad_checksum() {
        let mut bytes = b"++".to_vec();
        bytes.extend(frame("OK"));
        bytes.extend(b"$OK#00");
        assert_eq!(parse_all(&bytes), vec![Ok("OK".to_string()), Err(())]);
    }

    #[test]
    fn stop_parse_thread_and_watch() {
        let s = Stop::parse("T05thread:p01.02;watch:1000;").unwrap();
        assert_eq!((s.signal, s.thread, s.watch), (5, Some(2), Some(0x1000)));
        assert!(Stop::parse("W00").unwrap().exited());
        assert!(Stop::parse("OK").is_none());
    }

    #[test]
    fn console_output_vs_ok_and_errors() {
        assert!(!is_console_output("OK"));
        assert!(is_console_output("O6869"));
        assert!(is_error_reply("E22") && !is_error_reply("E2") && !is_error_reply("OK"));
    }
}
