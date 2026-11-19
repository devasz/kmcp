//! Bounded buffers: a byte ring with absolute offsets (flood-proof) and an event log,
//! plus the text cleaning applied on reads (ANSI strip, repeated-line dedupe).

use serde_json::Value;
use std::collections::VecDeque;

/// Byte ring. Offsets are absolute and monotonic, so a reader's cursor stays valid
/// (and loss is reported) even when the oldest bytes were overwritten.
pub struct Ring {
    buf: VecDeque<u8>,
    cap: usize,
    start: u64,
    dropped: u64,
}

pub struct Chunk {
    pub bytes: Vec<u8>,
    /// Absolute offset of the first returned byte (> requested offset means bytes were lost).
    pub from: u64,
    pub next: u64,
}

impl Ring {
    pub fn new(cap: usize) -> Self {
        Self { buf: VecDeque::new(), cap: cap.max(1), start: 0, dropped: 0 }
    }

    pub fn push(&mut self, data: &[u8]) {
        let skip = data.len().saturating_sub(self.cap);
        if skip > 0 {
            let lost = self.buf.len() + skip;
            self.buf.clear();
            self.start += lost as u64;
            self.dropped += lost as u64;
        }
        self.buf.extend(&data[skip..]);
        let over = self.buf.len().saturating_sub(self.cap);
        if over > 0 {
            self.buf.drain(..over);
            self.start += over as u64;
            self.dropped += over as u64;
        }
    }

    pub fn end(&self) -> u64 {
        self.start + self.buf.len() as u64
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buf.len()
    }

    /// Up to `max` bytes starting at absolute offset `from` (clamped to the oldest retained byte).
    pub fn read(&self, from: u64, max: usize) -> Chunk {
        let from = from.clamp(self.start, self.end());
        let skip = (from - self.start) as usize;
        let bytes: Vec<u8> = self.buf.iter().skip(skip).take(max).copied().collect();
        let next = from + bytes.len() as u64;
        Chunk { bytes, from, next }
    }

    /// The last `max` bytes.
    pub fn tail(&self, max: usize) -> Chunk {
        self.read(self.end().saturating_sub(max as u64), max)
    }
}

/// Bounded FIFO of QMP events with a monotonic cursor.
pub struct EventLog {
    q: VecDeque<(u64, Value)>,
    next: u64,
    cap: usize,
}

impl EventLog {
    pub fn new(cap: usize) -> Self {
        Self { q: VecDeque::new(), next: 0, cap: cap.max(1) }
    }

    pub fn push(&mut self, event: Value) {
        if self.q.len() == self.cap {
            self.q.pop_front();
        }
        self.q.push_back((self.next, event));
        self.next += 1;
    }

    pub fn head(&self) -> u64 {
        self.next
    }

    /// Events with seq >= `cursor`, at most `max`; returns the cursor to pass next time.
    pub fn after(&self, cursor: u64, max: usize) -> (Vec<Value>, u64) {
        let out: Vec<Value> = self
            .q
            .iter()
            .filter(|(seq, _)| *seq >= cursor)
            .take(max)
            .map(|(seq, ev)| {
                let mut ev = ev.clone();
                ev["seq"] = (*seq).into();
                ev
            })
            .collect();
        let next = out.last().map_or(cursor.max(self.q.front().map_or(0, |f| f.0)), |e| e["seq"].as_u64().unwrap_or(0) + 1);
        (out, next.min(self.next))
    }
}

/// Remove ANSI CSI/OSC/two-byte escapes and carriage returns.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\r' => {}
            '\x1b' => match it.next() {
                Some('[') => {
                    for n in it.by_ref() {
                        if ('\x40'..='\x7e').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(n) = it.next() {
                        if n == '\x07' || (n == '\x1b' && it.peek() == Some(&'\\')) {
                            if n == '\x1b' {
                                it.next();
                            }
                            break;
                        }
                    }
                }
                _ => {}
            },
            c => out.push(c),
        }
    }
    out
}

/// Collapse runs of identical consecutive lines into `line  [xN]`.
pub fn dedupe_lines(s: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut run = 0usize;
    let mut prev: Option<&str> = None;
    for line in s.split('\n') {
        if prev == Some(line) {
            run += 1;
            continue;
        }
        flush_run(&mut out, run);
        run = 0;
        out.push(line.to_string());
        prev = Some(line);
    }
    flush_run(&mut out, run);
    out.join("\n")
}

fn flush_run(out: &mut [String], run: usize) {
    if run > 0 {
        if let Some(last) = out.last_mut() {
            last.push_str(&format!("  [x{}]", run + 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_overwrites_oldest_and_counts_loss() {
        let mut r = Ring::new(8);
        r.push(b"0123456789");
        assert_eq!((r.end(), r.dropped(), r.len()), (10, 2, 8));
        let c = r.read(0, 100);
        assert_eq!((c.bytes.as_slice(), c.from, c.next), (&b"23456789"[..], 2, 10));
        r.push(&[b'x'; 100]);
        assert_eq!(r.len(), 8);
        assert_eq!(r.tail(3).bytes, b"xxx");
        assert_eq!(r.dropped() + r.len() as u64, r.end());
    }

    #[test]
    fn event_log_cursor_and_eviction() {
        let mut e = EventLog::new(2);
        for i in 0..3 {
            e.push(serde_json::json!({ "event": i }));
        }
        let (evs, next) = e.after(0, 10);
        assert_eq!((evs.len(), next), (2, 3));
        assert_eq!(evs[0]["seq"], 1);
        assert!(e.after(next, 10).0.is_empty());
    }

    #[test]
    fn ansi_and_dedupe() {
        assert_eq!(strip_ansi("a\x1b[31mred\x1b[0m\r\nb\x1b]0;t\x07c"), "ared\nbc");
        assert_eq!(dedupe_lines("a\nb\nb\nb\nc"), "a\nb  [x3]\nc");
    }
}
