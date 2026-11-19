//! Helpers behind the MCP tools: monitor policy, serial escapes, address parsing, hang probe.

use crate::triage::{classify_hang, parse_cpu_sample};
use crate::vm::ctl::Go;
use crate::vm::Vm;
use crate::Res;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

pub const MAX_SERIAL_WRITE: usize = 4096;
const PROBE_SAMPLES: usize = 3;
const PROBE_GAP: Duration = Duration::from_millis(150);

#[derive(Deserialize, JsonSchema, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum MonitorKind {
    Hmp,
    Qmp,
}

/// Always refused, even with --unsafe: they write host files, open host channels, kill QEMU or
/// bypass this very policy (`human-monitor-command`).
const DENY: &[&str] = &[
    "quit", "q", "exit", "migrate", "migrate-incoming", "migrate_set_parameter", "memsave", "pmemsave", "dump-guest-memory", "screendump", "drive_add", "drive_del", "object_add", "object-add", "object_del", "netdev_add", "netdev-add", "chardev-add", "chardev-change", "getfd", "closefd", "add-fd", "change", "eject", "loadvm", "savevm", "delvm", "logfile",
    "trace-file", "human-monitor-command", "xen-save-devices-state", "nbd-server-start", "gdbserver", "set_password", "expire_password", "blockdev-add", "blockdev-backup", "drive-backup", "drive-mirror", "snapshot-save", "snapshot-load", "snapshot-delete",
];
const HMP_READ_ONLY: &[&str] = &["info", "x", "xp", "gva2gpa", "print", "p", "qom-get", "qom-list", "help"];

/// Default policy: read-only (HMP allowlist / QMP `query-*`); `--unsafe` unlocks the rest minus DENY.
pub fn check_monitor(kind: MonitorKind, line: &str, unsafe_ops: bool) -> Res<()> {
    let verb = line.split_whitespace().next().ok_or("empty monitor command")?;
    if DENY.contains(&verb) {
        return Err(format!("'{verb}' is on the hard denylist (host-escaping or lifecycle command); use the dedicated tools"));
    }
    let read_only = match kind {
        MonitorKind::Hmp => HMP_READ_ONLY.contains(&verb),
        MonitorKind::Qmp => verb.starts_with("query-"),
    };
    match read_only || unsafe_ops {
        true => Ok(()),
        false => Err(format!("'{verb}' can change the VM; the monitor is read-only unless the server runs with --unsafe")),
    }
}

pub fn parse_number(s: &str) -> Option<u64> {
    let s = s.trim().replace('_', "");
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// `0x7c00`, `1234`, `symbol` or `symbol+0x10`.
pub fn resolve_addr(vm: &Vm, at: &str) -> Res<u64> {
    if let Some(n) = parse_number(at) {
        return Ok(n);
    }
    let (name, offset) = match at.split_once('+') {
        Some((n, o)) => (n, parse_number(o).ok_or_else(|| format!("bad offset in '{at}'"))?),
        None => (at, 0),
    };
    let found = vm.symbols.lock().unwrap().lookup(name);
    found.map(|a| a.wrapping_add(offset)).ok_or_else(|| format!("'{at}' is neither a number nor a known symbol (load an ELF with vm_launch.elf or the symbols tool)"))
}

fn escape_byte(it: &mut impl Iterator<Item = u8>) -> Res<u8> {
    match it.next() {
        Some(b'n') => Ok(b'\n'),
        Some(b'r') => Ok(b'\r'),
        Some(b't') => Ok(b'\t'),
        Some(b'e') => Ok(0x1b),
        Some(b'\\') => Ok(b'\\'),
        Some(b'x') => {
            let hex: Vec<u8> = it.take(2).collect();
            let digits = std::str::from_utf8(&hex).ok().filter(|h| h.len() == 2);
            digits.and_then(|h| u8::from_str_radix(h, 16).ok()).ok_or_else(|| "\\x needs two hex digits".to_string())
        }
        other => Err(format!("unknown escape \\{}", other.map_or("<end>".into(), |b| (b as char).to_string()))),
    }
}

/// Interpret `\n \r \t \e \\ \xNN` so an agent can send Enter, Ctrl-C (`\x03`) and friends.
pub fn unescape(s: &str) -> Res<Vec<u8>> {
    let mut bytes = s.bytes();
    let mut out = Vec::with_capacity(s.len());
    while let Some(b) = bytes.next() {
        out.push(if b == b'\\' { escape_byte(&mut bytes)? } else { b });
    }
    Ok(out)
}

/// Pause the running guest a few times, sample the CPU through HMP and classify the stall.
pub async fn probe_hang(vm: &Vm) -> Res<Value> {
    if !vm.rsp.is_running() {
        return Err("target is stopped; a hang probe samples a running guest".into());
    }
    let mut samples = Vec::new();
    for _ in 0..PROBE_SAMPLES {
        vm.pause().await?;
        let dump = vm.qmp()?.hmp("info registers").await;
        vm.go(Go::Continue, None).await?; // resume even if the dump failed
        samples.extend(parse_cpu_sample(&dump?));
        tokio::time::sleep(PROBE_GAP).await;
    }
    if samples.len() < 2 {
        return Err("could not parse CPU samples from `info registers` (x86-only parser)".into());
    }
    Ok(json!({"verdict": classify_hang(&samples), "samples": samples.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_policy_layers() {
        assert!(check_monitor(MonitorKind::Hmp, "info registers", false).is_ok());
        assert!(check_monitor(MonitorKind::Qmp, "query-status", false).is_ok());
        assert!(check_monitor(MonitorKind::Hmp, "system_reset", false).is_err());
        assert!(check_monitor(MonitorKind::Hmp, "system_reset", true).is_ok());
        for bad in ["quit", "pmemsave 0 10 /tmp/x", "human-monitor-command"] {
            assert!(check_monitor(MonitorKind::Hmp, bad, true).is_err(), "{bad}");
        }
        assert!(check_monitor(MonitorKind::Hmp, "  ", true).is_err());
    }

    #[test]
    fn numbers_and_escapes() {
        assert_eq!(parse_number("0x7c00"), Some(0x7c00));
        assert_eq!(parse_number("1_000"), Some(1000));
        assert_eq!(parse_number("start_kernel"), None);
        assert_eq!(unescape("ls\\n\\x03\\e\\\\").unwrap(), b"ls\n\x03\x1b\\");
        assert!(unescape("\\q").is_err());
        assert!(unescape("\\x4").is_err());
    }
}
