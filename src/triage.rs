//! Crash and hang triage from host-visible evidence only: the `-d int` log (TCG), QMP events,
//! and HMP `info registers` samples. Pure functions so they are unit-testable without QEMU.

use regex::Regex;
use serde::Serialize;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Fault {
    pub name: String,
    pub pc: Option<u64>,
    pub detail: String,
}

const X86_VECTORS: [&str; 22] = [
    "#DE divide error", "#DB debug", "NMI", "#BP breakpoint", "#OF overflow", "#BR bound range", "#UD invalid opcode", "#NM device not available", "#DF double fault", "coprocessor overrun", "#TS invalid TSS", "#NP segment not present", "#SS stack fault", "#GP general protection", "#PF page fault", "reserved",
    "#MF x87 fp", "#AC alignment check", "#MC machine check", "#XM simd fp", "#VE virtualization", "#CP control protection",
];

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

fn hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

fn parse_x86(log: &str) -> Vec<Fault> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(&R, r"(?m)(Servicing hardware INT=0x[0-9a-f]+\n)?^\s*\d+: v=([0-9a-f]{2}) e=([0-9a-f]{4}) i=(\d) cpl=(\d) IP=([0-9a-f]{4}):([0-9a-f]+) pc=([0-9a-f]+)");
    r.captures_iter(log)
        .filter(|c| c.get(1).is_none() && &c[4] == "0") // a hardware IRQ line (timer, PIC...) or a software INT n is not a fault
        .map(|c| {
            let vector = hex(&c[2]).unwrap_or(0) as usize;
            let name = X86_VECTORS.get(vector).map_or(format!("vector {vector:#x}"), |n| n.to_string());
            Fault { name, pc: hex(&c[8]), detail: format!("v={} err={} cpl={} cs:ip={}:{}", &c[2], &c[3], &c[5], &c[6], &c[7]) }
        })
        .collect()
}

fn parse_aarch64(log: &str) -> Vec<Fault> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(&R, r"Taking exception (\d+) \[([^\]]+)\].*?(?:from EL(\d) to EL(\d))?\n(?:.*?with ESR (0x[0-9a-f]+/0x[0-9a-f]+))?");
    r.captures_iter(log).map(|c| Fault { name: c[2].to_string(), pc: None, detail: format!("exception {} esr={}", &c[1], c.get(5).map_or("?", |m| m.as_str())) }).collect()
}

fn parse_riscv(log: &str) -> Vec<Fault> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(&R, r"riscv_cpu_do_interrupt: hart:(\d+), async:(\d), cause:([0-9a-f]+), epc:(0x[0-9a-f]+), tval:(0x[0-9a-f]+), desc=(\w+)");
    // async=1 are interrupts (timer ticks), `*_ecall` are system calls: expected traps, not faults
    r.captures_iter(log).filter(|c| &c[2] == "0" && !c[6].ends_with("_ecall")).map(|c| Fault { name: c[6].to_string(), pc: hex(&c[4]), detail: format!("hart={} async={} tval={}", &c[1], &c[2], &c[5]) }).collect()
}

/// Latches the first fault seen since the slot was last emptied. A trap storm (e.g. a bad `stvec` re-faulting forever)
/// floods the log ring and evicts the root cause; this keeps it. Parsing stops once latched, so storms cost nothing.
pub struct FirstFaultLatch {
    arch: String,
    partial_line: String,
    pub slot: Arc<Mutex<Option<Fault>>>,
}

const MAX_PARTIAL_LINE: usize = 64 * 1024;

impl FirstFaultLatch {
    pub fn new(arch: &str, slot: Arc<Mutex<Option<Fault>>>) -> Self {
        Self { arch: arch.into(), partial_line: String::new(), slot }
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        if self.slot.lock().unwrap().is_some() {
            self.partial_line.clear();
            return;
        }
        self.partial_line.push_str(&String::from_utf8_lossy(chunk));
        let Some(end) = self.partial_line.rfind('\n') else {
            self.partial_line.truncate(MAX_PARTIAL_LINE);
            return;
        };
        let rest = self.partial_line.split_off(end + 1);
        let complete = std::mem::replace(&mut self.partial_line, rest);
        *self.slot.lock().unwrap() = parse_faults(&self.arch, &complete).into_iter().next();
    }
}

pub fn parse_faults(arch: &str, log: &str) -> Vec<Fault> {
    match arch {
        "x86_64" => parse_x86(log),
        "aarch64" => parse_aarch64(log),
        _ => parse_riscv(log),
    }
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct CrashClass {
    pub class: &'static str,
    pub detail: String,
}

/// Strongest evidence first: pvpanic event, `Triple fault` in the log, then QMP shutdown events.
pub fn classify_crash(log: &str, events: &[serde_json::Value]) -> Option<CrashClass> {
    let event = |name: &str| events.iter().rev().find(|e| e["event"] == name);
    if let Some(e) = event("GUEST_PANICKED") {
        return Some(CrashClass { class: "guest_panic", detail: e["data"].to_string() });
    }
    if log.to_ascii_lowercase().contains("triple fault") {
        return Some(CrashClass { class: "triple_fault", detail: "CPU reset by triple fault (from -d int log)".into() });
    }
    let shutdown = events.iter().rev().find(|e| e["event"] == "SHUTDOWN" && !e["data"]["reason"].as_str().is_some_and(|r| r.starts_with("host-")))?;
    let reason = shutdown["data"]["reason"].as_str().unwrap_or("unknown");
    let class = if reason == "guest-reset" { "guest_reset_or_triple_fault" } else { "shutdown" };
    Some(CrashClass { class, detail: format!("SHUTDOWN reason={reason}") })
}

#[derive(Debug, Clone, PartialEq)]
pub struct CpuSample {
    pub pc: u64,
    pub halted: Option<bool>,
    pub irq_enabled: Option<bool>,
}

/// One CPU's state from HMP `info registers`. x86 also yields HLT and EFLAGS.IF; others only the PC.
/// True when an x86 `info registers` dump says the CPU is executing in System Management Mode.
pub fn dump_in_smm(dump: &str) -> bool {
    dump.contains(" SMM=1")
}

pub fn parse_cpu_sample(dump: &str) -> Option<CpuSample> {
    static PC: OnceLock<Regex> = OnceLock::new();
    static HLT: OnceLock<Regex> = OnceLock::new();
    static EFL: OnceLock<Regex> = OnceLock::new();
    let pc = re(&PC, r"(?i)\b(?:RIP|EIP|PC)\s*[= ]\s*(?:0x)?([0-9a-f]{8,16})\b").captures(dump).and_then(|c| hex(&c[1]))?;
    let halted = re(&HLT, r"HLT=(\d)").captures(dump).map(|c| &c[1] == "1");
    let irq_enabled = re(&EFL, r"[RE]FL=([0-9a-f]+)").captures(dump).and_then(|c| hex(&c[1])).map(|f| f & 0x200 != 0);
    Some(CpuSample { pc, halted, irq_enabled })
}

#[derive(Serialize, Debug, PartialEq)]
pub struct HangVerdict {
    pub class: &'static str,
    pub detail: String,
}

/// Classify a series of samples taken while the VM runs.
pub fn classify_hang(samples: &[CpuSample]) -> HangVerdict {
    let first = samples.first();
    let stuck = first.is_some_and(|f| samples.iter().all(|s| s.pc == f.pc));
    let Some(f) = first.filter(|_| stuck && samples.len() > 1) else {
        return HangVerdict { class: "alive", detail: "program counter is changing".into() };
    };
    match (f.halted, f.irq_enabled) {
        (Some(true), Some(true)) => HangVerdict { class: "idle", detail: format!("halted at {:#x} with interrupts enabled (waiting for an interrupt)", f.pc) },
        (Some(true), _) => HangVerdict { class: "dead_hang", detail: format!("halted at {:#x} with interrupts masked (cli;hlt): nothing can wake it", f.pc) },
        _ => HangVerdict { class: "spin", detail: format!("not halted but stuck at {:#x} (tight loop)", f.pc) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn x86_int_log_yields_fault_names_and_skips_software_ints() {
        let log = "     0: v=0d e=0000 i=0 cpl=0 IP=0008:0000000000100000 pc=0000000000100000 SP=0010:0000000000007000 env->regs[R_EAX]=0\n     1: v=80 e=0000 i=1 cpl=3 IP=001b:00401000 pc=00401000 SP=0023:0 env->regs[R_EAX]=1\n     2: v=0e e=0002 i=0 cpl=0 IP=0008:0000000000100010 pc=0000000000100010 SP=0010:0 CR2=0000000000000000\n";
        let faults = parse_faults("x86_64", log);
        assert_eq!(faults.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), vec!["#GP general protection", "#PF page fault"]);
        assert_eq!(faults[0].pc, Some(0x100000));
    }

    #[test]
    fn x86_hardware_irqs_are_not_faults() {
        // regression (found booting OVMF): timer IRQs (and real-mode IRQ8-15, which alias #DF..) were reported as recent_faults
        let log = "Servicing hardware INT=0x20\n   401: v=20 e=0000 i=0 cpl=0 IP=0038:000000001eb32c51 pc=000000001eb32c51 SP=0030:1\n   402: v=0e e=0002 i=0 cpl=0 IP=0038:000000001eb32c60 pc=000000001eb32c60 SP=0030:1\nServicing hardware INT=0x08\n   403: v=08 e=0000 i=0 cpl=0 IP=f000:0000e05b pc=000fe05b SP=0000:6f00\n";
        let faults = parse_faults("x86_64", log);
        assert_eq!(faults.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), vec!["#PF page fault"]);
    }

    #[test]
    fn first_fault_survives_a_storm_and_split_chunks() {
        // regression (found with an injected early-boot fault in xv6): the log tail only showed the trap-vector re-fault loop
        let slot = Arc::new(Mutex::new(None));
        let mut latch = FirstFaultLatch::new("riscv64", slot.clone());
        let line = |cause: &str, epc: &str, desc: &str| format!("riscv_cpu_do_interrupt: hart:0, async:0, cause:{cause}, epc:{epc}, tval:0x0000000000000010, desc={desc}\n");
        let first = line("0000000000000007", "0x0000000080001160", "store_amo_access_fault");
        let (head, tail) = first.split_at(30);
        latch.feed(head.as_bytes());
        assert!(slot.lock().unwrap().is_none());
        latch.feed(format!("{tail}{}", line("0000000000000001", "0x0000000000000000", "fault_fetch")).as_bytes());
        latch.feed(line("0000000000000001", "0x0000000000000000", "fault_fetch").as_bytes());
        let got = slot.lock().unwrap().clone().unwrap();
        assert_eq!((got.name.as_str(), got.pc), ("store_amo_access_fault", Some(0x8000_1160)));
        slot.lock().unwrap().take();
        latch.feed(line("0000000000000002", "0x0000000080000004", "illegal_instruction").as_bytes());
        assert_eq!(slot.lock().unwrap().as_ref().unwrap().name, "illegal_instruction"); // re-arms after the slot is emptied
    }

    #[test]
    fn riscv_interrupts_and_ecalls_are_not_faults() {
        // regression (found booting xv6): every s_timer tick and user_ecall syscall was reported as a recent fault
        let line = |asy: u8, desc: &str| format!("riscv_cpu_do_interrupt: hart:0, async:{asy}, cause:0000000000000008, epc:0x0000000080001000, tval:0x0000000000000000, desc={desc}\n");
        let log = line(1, "s_timer") + &line(0, "user_ecall") + &line(0, "supervisor_ecall") + &line(0, "fault_store");
        let faults = parse_faults("riscv64", &log);
        assert_eq!(faults.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), vec!["fault_store"]);
    }

    #[test]
    fn riscv_and_aarch64_logs_parse() {
        let r = parse_faults("riscv64", "riscv_cpu_do_interrupt: hart:0, async:0, cause:0000000000000002, epc:0x0000000080000004, tval:0x0000000000000000, desc=illegal_instruction\n");
        assert_eq!((r[0].name.as_str(), r[0].pc), ("illegal_instruction", Some(0x80000004)));
        let a = parse_faults("aarch64", "Taking exception 4 [Data Abort] on CPU 0\n...from EL1 to EL1\n...with ESR 0x25/0x96000045\n");
        assert_eq!(a[0].name, "Data Abort");
    }

    #[test]
    fn crash_priority_panic_then_triple_fault_then_shutdown() {
        let panic = json!({"event": "GUEST_PANICKED", "data": {"action": "pause"}});
        let shut = json!({"event": "SHUTDOWN", "data": {"reason": "guest-reset"}});
        assert_eq!(classify_crash("Triple fault", &[panic]).unwrap().class, "guest_panic");
        assert_eq!(classify_crash("... Triple fault ...", &[shut.clone()]).unwrap().class, "triple_fault");
        assert_eq!(classify_crash("", &[shut]).unwrap().class, "guest_reset_or_triple_fault");
        assert!(classify_crash("", &[]).is_none());
    }

    #[test]
    fn hang_classes() {
        let s = |pc, halted, irq| CpuSample { pc, halted, irq_enabled: irq };
        assert_eq!(classify_hang(&[s(1, Some(true), Some(false)), s(1, Some(true), Some(false))]).class, "dead_hang");
        assert_eq!(classify_hang(&[s(1, Some(true), Some(true)), s(1, Some(true), Some(true))]).class, "idle");
        assert_eq!(classify_hang(&[s(1, Some(false), Some(true)), s(1, Some(false), Some(true))]).class, "spin");
        assert_eq!(classify_hang(&[s(1, None, None), s(2, None, None)]).class, "alive");
    }

    #[test]
    fn smm_flag_read_from_dump() {
        assert!(dump_in_smm("RIP=0 RFL=2 [-------] CPL=0 II=0 A20=1 SMM=1 HLT=0"));
        assert!(!dump_in_smm("RIP=0 RFL=2 [-------] CPL=0 II=0 A20=1 SMM=0 HLT=0"));
    }

    #[test]
    fn cpu_sample_from_hmp_dump() {
        let dump = "RAX=0 RBX=0\nRIP=00000000000000f1 RFL=00000202 [-------] CPL=0 II=0 A20=1 SMM=0 HLT=1\n";
        assert_eq!(parse_cpu_sample(dump), Some(CpuSample { pc: 0xf1, halted: Some(true), irq_enabled: Some(true) }));
    }
}
