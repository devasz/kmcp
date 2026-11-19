//! Always-draining channel readers (serial, debugcon, the `-d` FIFO) feeding bounded rings.
//! A reader never blocks on its consumers, so a flooding guest cannot stall QEMU's main loop.

use crate::ring::{dedupe_lines, strip_ansi, Ring};
use crate::Res;
use regex::{Regex, RegexBuilder};
use std::ffi::CString;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::unix::pipe;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub struct Channel {
    pub ring: Mutex<Ring>,
    pub notify: Notify,
}

pub struct Text {
    pub text: String,
    pub from: u64,
    pub next: u64,
    pub dropped: u64,
}

pub struct ReadOpts {
    pub from: Option<u64>,
    pub tail: Option<usize>,
    pub max_bytes: usize,
    pub grep: Option<Regex>,
    pub strip_ansi: bool,
    pub dedupe: bool,
}

impl Channel {
    pub fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self { ring: Mutex::new(Ring::new(cap)), notify: Notify::new() })
    }

    pub fn read(&self, o: &ReadOpts) -> Text {
        let ring = self.ring.lock().unwrap();
        let chunk = match (o.from, o.tail) {
            (Some(from), _) => ring.read(from, o.max_bytes),
            (None, tail) => ring.tail(tail.unwrap_or(o.max_bytes).min(o.max_bytes)),
        };
        let mut text = String::from_utf8_lossy(&chunk.bytes).into_owned();
        if o.strip_ansi {
            text = strip_ansi(&text);
        }
        if let Some(re) = &o.grep {
            text = text.lines().filter(|l| re.is_match(l)).collect::<Vec<_>>().join("\n");
        }
        if o.dedupe {
            text = dedupe_lines(&text);
        }
        Text { text, from: chunk.from, next: chunk.next, dropped: ring.dropped() }
    }

    /// Wait until `re` matches text at or after absolute offset `from`. Returns the matching
    /// line context and the offset just past the match.
    pub async fn wait_regex(&self, re: &Regex, from: u64, timeout: Duration) -> Option<(String, u64)> {
        let deadline = Instant::now() + timeout;
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable(); // register before checking: no lost wakeup
            if let Some(found) = self.find(re, from) {
                return Some(found);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if tokio::time::timeout(left, notified).await.is_err() {
                return None;
            }
        }
    }

    fn find(&self, re: &Regex, from: u64) -> Option<(String, u64)> {
        let ring = self.ring.lock().unwrap();
        let chunk = ring.read(from, usize::MAX);
        let text = strip_ansi(&String::from_utf8_lossy(&chunk.bytes));
        let m = re.find(&text)?;
        let line_start = text[..m.start()].rfind('\n').map_or(0, |i| i + 1);
        let line_end = text[m.end()..].find('\n').map_or(text.len(), |i| m.end() + i);
        Some((text[line_start..line_end].to_string(), chunk.from + m.end().min(chunk.bytes.len()) as u64))
    }
}

/// Spawn the drain task for one channel.
pub fn pump<R: AsyncRead + Unpin + Send + 'static>(r: R, ch: Arc<Channel>) -> JoinHandle<()> {
    pump_with(r, ch, |_| {})
}

/// `pump` that also shows every chunk to `on_chunk` (before waiters are woken).
pub fn pump_with<R: AsyncRead + Unpin + Send + 'static>(mut r: R, ch: Arc<Channel>, mut on_chunk: impl FnMut(&[u8]) + Send + 'static) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        while let Ok(n) = r.read(&mut buf).await {
            if n == 0 {
                break;
            }
            ch.ring.lock().unwrap().push(&buf[..n]);
            on_chunk(&buf[..n]);
            ch.notify.notify_waiters();
        }
        ch.notify.notify_waiters();
    })
}

/// Create the `-D` FIFO and open its read end *before* QEMU starts (QEMU blocks in open otherwise).
/// The returned `Sender` is a keep-alive write end so the reader never sees EOF before QEMU opens it.
pub fn open_log_fifo(path: &Path) -> Res<(pipe::Receiver, pipe::Sender)> {
    let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: valid NUL-terminated path.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
        return Err(format!("mkfifo {}: {}", path.display(), std::io::Error::last_os_error()));
    }
    let rx = pipe::OpenOptions::new().open_receiver(path).map_err(|e| format!("open fifo: {e}"))?;
    let keepalive = pipe::OpenOptions::new().open_sender(path).map_err(|e| format!("open fifo writer: {e}"))?;
    Ok((rx, keepalive))
}

pub fn compile_regex(pattern: &str) -> Res<Regex> {
    RegexBuilder::new(pattern).size_limit(1 << 20).build().map_err(|e| format!("bad regex: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ReadOpts {
        ReadOpts { from: Some(0), tail: None, max_bytes: 1024, grep: None, strip_ansi: true, dedupe: true }
    }

    #[tokio::test]
    async fn pump_fills_ring_and_wait_regex_sees_late_data() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let ch = Channel::new(1024);
        pump(rx, ch.clone());
        let re = compile_regex("login:").unwrap();
        let waiter = { let ch = ch.clone(); tokio::spawn(async move { ch.wait_regex(&re, 0, Duration::from_secs(2)).await }) };
        tokio::io::AsyncWriteExt::write_all(&mut tx, b"boot\nlogin: ").await.unwrap();
        let (line, next) = waiter.await.unwrap().expect("match");
        assert_eq!((line.as_str(), next), ("login: ", 11)); // offset is just past the match
        assert_eq!(ch.read(&opts()).text, "boot\nlogin: ");
    }

    #[tokio::test]
    async fn wait_regex_times_out_without_match() {
        let ch = Channel::new(16);
        assert!(ch.wait_regex(&compile_regex("x").unwrap(), 0, Duration::from_millis(30)).await.is_none());
    }

    #[test]
    fn regex_size_limit_rejects_pathological_patterns() {
        assert!(compile_regex("(((a{100}){100}){100}){100}").is_err());
    }
}
