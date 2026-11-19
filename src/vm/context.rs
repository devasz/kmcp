//! The stop-context bundle: everything an agent needs after a stop in ONE response (regs, symbol,
//! code at PC, new serial output, new QMP events, crash evidence), so it never needs 5 follow-up calls.

use super::ctl::{linear_pc, x86_bits};
use super::Vm;
use crate::logs::ReadOpts;
use crate::rsp::Stop;
use crate::triage;
use serde_json::{json, Map, Value};

const SERIAL_BUNDLE_BYTES: usize = 1024;
const LOG_SCAN_BYTES: usize = 64 * 1024;
const CODE_BYTES: usize = 32;
const CODE_INSNS: usize = 5;

fn hex(v: u128) -> String {
    format!("{v:#x}")
}

pub fn core_register_names(vm: &Vm) -> Vec<String> {
    let wanted: &[&str] = match vm.arch.as_str() {
        "x86_64" => &["rip", "eflags", "cs", "ss", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "cr0", "cr2", "cr3", "cr4", "efer"],
        "aarch64" => &["pc", "sp", "cpsr", "x0", "x1", "x2", "x3", "x29", "x30"],
        _ => &["pc", "sp", "ra", "a0", "a1", "a2", "a3", "mstatus", "mcause", "mepc"],
    };
    wanted.iter().filter(|n| vm.regdefs.has(n)).map(|n| n.to_string()).collect()
}

fn stop_view(stop: Option<&Stop>, why: &str) -> Value {
    match stop {
        None => json!({"reason": why}),
        Some(s) if s.exited() => json!({"reason": "exited", "raw": s.raw}),
        Some(s) => json!({"reason": if s.watch.is_some() { "watchpoint" } else { why }, "signal": s.signal, "thread": s.thread, "watch_addr": s.watch}),
    }
}

async fn register_view(vm: &Vm, out: &mut Map<String, Value>) -> Option<(u32, u64)> {
    let regs = match vm.read_registers(&core_register_names(vm), None).await {
        Ok(r) => r,
        Err(e) => {
            out.insert("regs_error".into(), json!(e));
            return None;
        }
    };
    let pc = regs.iter().find(|(n, _)| n == vm.pc_name()).map(|(_, v)| *v as u64)?;
    let bits = if vm.arch == "x86_64" { x86_bits(&regs) } else { 64 };
    let linear = if vm.arch == "x86_64" { linear_pc(bits, &regs) } else { pc };
    out.insert("regs".into(), Value::Object(regs.iter().map(|(n, v)| (n.clone(), json!(hex(*v)))).collect()));
    out.insert("pc".into(), json!(hex(pc as u128)));
    out.insert("mode_bits".into(), json!(bits));
    if linear != pc {
        out.insert("linear_pc".into(), json!(hex(linear as u128)));
    }
    if vm.arch == "x86_64" && in_smm(vm).await {
        out.insert("smm".into(), json!(true)); // only present when true: SMRAM code is invisible to the OS
    }
    Some((bits, linear))
}

async fn in_smm(vm: &Vm) -> bool {
    match vm.qmp() {
        Ok(qmp) => qmp.hmp("info registers").await.is_ok_and(|dump| crate::triage::dump_in_smm(&dump)),
        Err(_) => false,
    }
}

async fn code_view(vm: &Vm, out: &mut Map<String, Value>, bits: u32, linear: u64) {
    if let Some(sym) = vm.symbols.lock().unwrap().describe(linear) {
        out.insert("symbol".into(), json!(sym));
    }
    // a read that crosses 4 GiB (the x86 reset vector sits 16 bytes below it) makes the stub refuse the whole chunk
    let len = if linear < 1 << 32 { ((1u64 << 32) - linear).min(CODE_BYTES as u64) as usize } else { CODE_BYTES };
    let Ok((code, _)) = vm.read_memory(linear, len, false, None).await else { return };
    let insns = crate::decode::disasm(&vm.arch, bits, linear, &code, CODE_INSNS).await;
    out.insert("code".into(), json!(insns));
}

fn console_view(vm: &Vm, out: &mut Map<String, Value>) {
    let mut cursor = vm.bundle_cursor.lock().unwrap();
    let opts = ReadOpts { from: Some(cursor.0), tail: None, max_bytes: SERIAL_BUNDLE_BYTES, grep: None, strip_ansi: true, dedupe: true };
    let text = vm.serial.read(&opts);
    cursor.0 = text.next;
    if !text.text.is_empty() {
        out.insert("serial_new".into(), json!(text.text));
    }
    let (events, next) = vm.events.log.lock().unwrap().after(cursor.1, 32);
    cursor.1 = next;
    if !events.is_empty() {
        out.insert("events_new".into(), json!(events));
    }
}

fn evidence_view(vm: &Vm, out: &mut Map<String, Value>) {
    let log = vm.qemu_log.read(&ReadOpts { from: None, tail: Some(LOG_SCAN_BYTES), max_bytes: LOG_SCAN_BYTES, grep: None, strip_ansi: false, dedupe: false });
    let (all_events, _) = vm.events.log.lock().unwrap().after(0, usize::MAX);
    if let Some(crash) = triage::classify_crash(&log.text, &all_events) {
        out.insert("crash".into(), json!(crash));
    }
    if let Some(first) = vm.first_fault.lock().unwrap().as_ref() {
        out.insert("first_fault".into(), json!(first)); // root cause: survives trap storms that flood the log tail
    }
    let faults = triage::parse_faults(&vm.arch, &log.text);
    if let Some(recent) = faults.get(faults.len().saturating_sub(3)..).filter(|f| !f.is_empty()) {
        out.insert("recent_faults".into(), json!(recent));
    }
}

pub async fn stop_context(vm: &Vm, stop: Option<&Stop>, why: &str) -> Value {
    let mut out = Map::new();
    out.insert("vm_id".into(), json!(vm.id));
    out.insert("state".into(), json!(if vm.rsp.is_running() { "running" } else { "stopped" }));
    out.insert("stop".into(), stop_view(stop, why));
    if !vm.rsp.is_running() && !stop.is_some_and(|s| s.exited()) {
        if let Some((bits, linear)) = register_view(vm, &mut out).await {
            code_view(vm, &mut out, bits, linear).await;
        }
    }
    console_view(vm, &mut out);
    evidence_view(vm, &mut out);
    Value::Object(out)
}
