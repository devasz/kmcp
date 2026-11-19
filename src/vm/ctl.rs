//! Debug operations on a `Vm`: every RSP read/write/run-control sequence lives here, serialized by
//! the per-VM `op` lock so cached registers and the stub's selected thread never go stale.

use super::{Breakpoint, OpState, Vm};
use crate::regs::{read_regs, write_reg};
use crate::rsp::{bytes_to_hex, hex_to_bytes, Stop, REQUEST_TIMEOUT};
use crate::Res;
use std::time::Duration;
use tokio::sync::MutexGuard;

const SSTEP_ENABLE: u32 = 1;
const SSTEP_NOIRQ: u32 = 2;
const SSTEP_NOTIMER: u32 = 4;
pub const MAX_MEM_READ: usize = 1 << 20;

#[derive(Clone, Copy)]
pub enum Go {
    Continue,
    Step { irq: bool },
    ReverseStep,
    ReverseContinue,
}

/// Address-bit width the guest is executing in, from control registers when the stub exposes them.
/// ponytail: no-cr0 fallback guesses from rip magnitude; wrong only for 32-bit code below 64 KiB.
pub fn x86_bits(regs: &[(String, u128)]) -> u32 {
    let get = |n: &str| regs.iter().find(|(k, _)| k == n).map(|(_, v)| *v);
    match (get("cr0"), get("efer"), get("rip")) {
        (Some(cr0), _, _) if cr0 & 1 == 0 => 16,
        (Some(_), Some(efer), _) if efer & (1 << 10) != 0 => 64,
        (Some(_), _, _) => 32,
        (None, _, Some(rip)) if rip > u32::MAX as u128 => 64,
        (None, _, Some(rip)) if rip > 0xffff => 32,
        _ => 16,
    }
}

/// Real mode needs linear = cs*16 + ip; the stub's breakpoint/memory addresses are linear.
/// ponytail: protected/long mode assumes flat segments (segment base 0); the stub exposes no
/// segment bases, so the CPU reset state (cs=f000 ip=fff0, base ffff0000) is special-cased.
pub fn linear_pc(bits: u32, regs: &[(String, u128)]) -> u64 {
    let get = |n: &str| regs.iter().find(|(k, _)| k == n).map_or(0, |(_, v)| *v as u64);
    match (bits, get("cs"), get("rip")) {
        (16, 0xf000, 0xfff0) => 0xffff_fff0,
        (16, cs, ip) => (cs << 4).wrapping_add(ip & 0xffff),
        (_, _, ip) => ip,
    }
}

/// Execution breakpoints (software/hardware) located exactly at `pc`.
fn breakpoints_at(all: &[Breakpoint], pc: u64) -> Vec<Breakpoint> {
    all.iter().filter(|b| matches!(b.kind, '0' | '1') && b.addr == pc).cloned().collect()
}

impl Vm {
    pub fn pc_name(&self) -> &'static str {
        if self.arch == "x86_64" { "rip" } else { "pc" }
    }

    /// Execution width for decoding at the current PC (x86 real/protected/long; 64 elsewhere).
    pub async fn mode_bits(&self) -> Res<u32> {
        if self.arch != "x86_64" {
            return Ok(64);
        }
        let names: Vec<String> = ["cr0", "efer", "rip"].into_iter().filter(|n| self.regdefs.has(n)).map(String::from).collect();
        Ok(x86_bits(&self.read_registers(&names, None).await?))
    }

    fn tid(&self, n: u32) -> String {
        if self.multiprocess { format!("p1.{n:x}") } else { format!("{n:x}") }
    }

    pub async fn invalidate_caches(&self) {
        self.regcache.lock().await.clear();
    }

    /// Lock for a stopped-target operation.
    pub async fn lock_stopped(&self) -> Res<MutexGuard<'_, OpState>> {
        let op = self.op.lock().await;
        match self.rsp.is_running() {
            true => Err("target is running; call vm_control pause (or vm_wait for a stop) first".into()),
            false => Ok(op),
        }
    }

    async fn select_thread(&self, op: &mut OpState, thread: Option<u32>) -> Res<()> {
        let want = thread.or(op.thread).unwrap_or(1);
        op.thread = Some(want);
        if op.selected == Some(want) {
            return Ok(());
        }
        self.rsp.request_ok(&format!("Hg{}", self.tid(want))).await?;
        op.selected = Some(want);
        self.invalidate_caches().await;
        Ok(())
    }

    pub async fn read_registers(&self, names: &[String], thread: Option<u32>) -> Res<Vec<(String, u128)>> {
        let mut op = self.lock_stopped().await?;
        self.select_thread(&mut op, thread).await?;
        let mut cache = self.regcache.lock().await;
        read_regs(&self.rsp, &self.regdefs, &mut cache, names).await
    }

    pub async fn write_register(&self, name: &str, value: u128, thread: Option<u32>) -> Res<()> {
        let mut op = self.lock_stopped().await?;
        self.select_thread(&mut op, thread).await?;
        write_reg(&self.rsp, &self.regdefs, name, value).await?;
        self.invalidate_caches().await;
        Ok(())
    }

    async fn set_phys(&self, op: &mut OpState, phys: bool) -> Res<()> {
        if op.phys != phys {
            self.rsp.request_ok(&format!("Qqemu.PhyMemMode:{}", phys as u8)).await?;
            op.phys = phys;
        }
        Ok(())
    }

    /// Read guest memory (virtual by default, physical when `phys`). Returns bytes read so far and
    /// the stub's error text if it stopped early (unmapped page).
    pub async fn read_memory(&self, addr: u64, len: usize, phys: bool, thread: Option<u32>) -> Res<(Vec<u8>, Option<String>)> {
        let mut op = self.lock_stopped().await?;
        self.select_thread(&mut op, thread).await?;
        self.set_phys(&mut op, phys).await?;
        let chunk = (self.rsp.packet_size / 2).saturating_sub(16).clamp(64, 4096);
        let mut out = Vec::with_capacity(len.min(MAX_MEM_READ));
        while out.len() < len.min(MAX_MEM_READ) {
            let n = chunk.min(len.min(MAX_MEM_READ) - out.len());
            let reply = self.rsp.request(&format!("m{:x},{n:x}", addr.wrapping_add(out.len() as u64)), REQUEST_TIMEOUT).await?;
            match hex_to_bytes(&reply) {
                Ok(bytes) if !bytes.is_empty() => out.extend(bytes),
                _ => {
                    let note = format!("stub error '{reply}' at {:#x}", addr.wrapping_add(out.len() as u64));
                    return Ok((out, Some(note)));
                }
            }
        }
        Ok((out, None))
    }

    pub async fn write_memory(&self, addr: u64, data: &[u8], phys: bool) -> Res<()> {
        let mut op = self.lock_stopped().await?;
        self.select_thread(&mut op, None).await?;
        self.set_phys(&mut op, phys).await?;
        let chunk = (self.rsp.packet_size / 2).saturating_sub(32).clamp(64, 2048);
        for (i, part) in data.chunks(chunk).enumerate() {
            let at = addr.wrapping_add((i * chunk) as u64);
            self.rsp.request_ok(&format!("M{at:x},{:x}:{}", part.len(), bytes_to_hex(part))).await?;
        }
        self.invalidate_caches().await;
        Ok(())
    }

    pub async fn set_breakpoint(&self, kind: char, addr: u64, len: u32) -> Res<()> {
        let mut op = self.lock_stopped().await?;
        self.rsp.request_ok(&format!("Z{kind},{addr:x},{len:x}")).await?;
        op.breakpoints.push(Breakpoint { kind, addr, len });
        Ok(())
    }

    pub async fn clear_breakpoint(&self, kind: char, addr: u64, len: u32) -> Res<()> {
        let mut op = self.lock_stopped().await?;
        self.rsp.request_ok(&format!("z{kind},{addr:x},{len:x}")).await?;
        op.breakpoints.retain(|b| !(b.kind == kind && b.addr == addr));
        Ok(())
    }

    pub async fn breakpoints(&self) -> Vec<Breakpoint> {
        self.op.lock().await.breakpoints.clone()
    }

    pub async fn list_threads(&self) -> Res<Vec<u32>> {
        let _op = self.lock_stopped().await?;
        let mut ids = Vec::new();
        let mut reply = self.rsp.request_ok("qfThreadInfo").await?;
        while let Some(list) = reply.strip_prefix('m') {
            ids.extend(list.split(',').filter_map(crate::rsp::parse_thread_id));
            reply = self.rsp.request_ok("qsThreadInfo").await?;
        }
        Ok(ids)
    }

    async fn apply_sstep(&self, op: &mut OpState, irq: bool) -> Res<()> {
        let flags = if irq { SSTEP_ENABLE } else { SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER };
        if op.sstep != Some(flags) {
            // ponytail: record/replay stubs answer E22 here; the step still works with their defaults, so the error is not fatal
            let _ = self.rsp.request_ok(&format!("Qqemu.sstep:{flags:x}")).await;
            op.sstep = Some(flags);
        }
        Ok(())
    }

    /// Linear PC of the selected thread, in the address space the stub's breakpoints use.
    async fn linear_pc_now(&self, thread: Option<u32>) -> Res<u64> {
        if self.arch != "x86_64" {
            return Ok(self.read_registers(&[self.pc_name().into()], thread).await?[0].1 as u64);
        }
        let bits = self.mode_bits().await?;
        Ok(linear_pc(bits, &self.read_registers(&["cs".into(), "rip".into()], thread).await?))
    }

    /// QEMU's stub re-reports a breakpoint sitting at the resume PC instead of executing it (gdb steps over it
    /// client-side), so a bare `continue` from a breakpoint never leaves it. Single-step it out with the breakpoint lifted.
    /// ponytail: a step that times out leaves the lifted breakpoint un-reinserted; the error says so.
    async fn step_off_breakpoint(&self, thread: Option<u32>) -> Res<()> {
        let at = self.linear_pc_now(thread).await?;
        let hit = breakpoints_at(&self.breakpoints().await, at);
        if hit.is_empty() {
            return Ok(());
        }
        let mut op = self.lock_stopped().await?;
        for b in &hit {
            self.rsp.request_ok(&format!("z{},{:x},{:x}", b.kind, b.addr, b.len)).await?;
        }
        self.apply_sstep(&mut op, false).await?;
        self.rsp.resume(&format!("vCont;s:{}", self.tid(thread.or(op.thread).unwrap_or(1)))).await?;
        if self.rsp.wait_stop(REQUEST_TIMEOUT).await.is_none() {
            return Err(format!("stepping off the breakpoint at {at:#x} timed out; breakpoint left lifted"));
        }
        for b in &hit {
            self.rsp.request_ok(&format!("Z{},{:x},{:x}", b.kind, b.addr, b.len)).await?;
        }
        self.invalidate_caches().await;
        Ok(())
    }

    /// Start (or step) the target; returns immediately. Use `wait_for_stop`.
    pub async fn go(&self, how: Go, thread: Option<u32>) -> Res<()> {
        if matches!(how, Go::Continue) {
            self.step_off_breakpoint(thread).await?;
        }
        let mut op = self.lock_stopped().await?;
        let payload = match how {
            Go::Continue => "vCont;c".to_string(),
            Go::Step { irq } => {
                self.apply_sstep(&mut op, irq).await?;
                format!("vCont;s:{}", self.tid(thread.or(op.thread).unwrap_or(1)))
            }
            Go::ReverseStep => "bs".into(),
            Go::ReverseContinue => "bc".into(),
        };
        self.ensure_not_frozen().await?;
        self.invalidate_caches().await;
        self.first_fault.lock().unwrap().take();
        self.rsp.resume(&payload).await
    }

    /// After a guest reset/shutdown the freeze policy leaves QEMU in `shutdown`, where resuming silently does nothing.
    async fn ensure_not_frozen(&self) -> Res<()> {
        let Ok(qmp) = self.qmp() else { return Ok(()) };
        let status = qmp.exec("query-status", serde_json::json!({}), crate::qmp::CALL_TIMEOUT).await?;
        match status["status"] == "shutdown" {
            true => Err("guest reset/shut down and is frozen by policy; run vm_control reset (SeaBIOS issues one extra reset after a host reset, so expect to continue once more)".into()),
            false => Ok(()),
        }
    }

    /// Wait up to `timeout` for a stop. `Ok(None)` = still running.
    pub async fn wait_for_stop(&self, timeout: Duration) -> Res<Option<Stop>> {
        let stop = self.rsp.wait_stop(timeout).await;
        if !self.rsp.is_usable() {
            return Err("gdbstub connection lost (QEMU exited or the session desynced)".into());
        }
        self.after_stop(stop.as_ref()).await;
        Ok(stop)
    }

    async fn after_stop(&self, stop: Option<&Stop>) {
        let Some(stop) = stop else { return };
        let mut op = self.op.lock().await;
        if let Some(t) = stop.thread {
            op.thread = Some(t);
            op.selected = Some(t); // a stop reply leaves that thread selected for `g`
        }
        self.invalidate_caches().await;
    }

    /// Pause a running target and return the stop.
    pub async fn pause(&self) -> Res<Stop> {
        let stop = self.rsp.stop_now().await?;
        self.after_stop(Some(&stop)).await;
        Ok(stop)
    }

    /// Resume the guest and release the stub: the only RSP exit that leaves the guest running.
    pub async fn detach_rsp(&self) -> Res<()> {
        let mut op = self.lock_stopped().await?;
        let ids: Vec<_> = op.breakpoints.drain(..).collect();
        for b in ids {
            let _ = self.rsp.request(&format!("z{},{:x},{:x}", b.kind, b.addr, b.len), REQUEST_TIMEOUT).await;
        }
        let cmd = if self.multiprocess { "D;1" } else { "D" };
        self.rsp.request_ok(cmd).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regs(items: &[(&str, u128)]) -> Vec<(String, u128)> {
        items.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn bitness_from_control_registers() {
        assert_eq!(x86_bits(&regs(&[("cr0", 0x60000010), ("rip", 0xfff0)])), 16);
        assert_eq!(x86_bits(&regs(&[("cr0", 0x11), ("efer", 0)])), 32);
        assert_eq!(x86_bits(&regs(&[("cr0", 0x80000011), ("efer", 0x500)])), 64);
        assert_eq!(x86_bits(&regs(&[("rip", 0xffff_ffff_8000_0000)])), 64);
        assert_eq!(x86_bits(&regs(&[("rip", 0x100000)])), 32);
        assert_eq!(x86_bits(&regs(&[("rip", 0xfff0)])), 16);
    }

    #[test]
    fn only_execution_breakpoints_at_the_pc_are_stepped_over() {
        // regression (found continuing xv6 from a `kexec` breakpoint): the stub re-hit it forever
        let bp = |kind, addr| Breakpoint { kind, addr, len: 4 };
        let all = [bp('0', 0x100), bp('1', 0x100), bp('2', 0x100), bp('0', 0x200)];
        let hit: Vec<_> = breakpoints_at(&all, 0x100).iter().map(|b| b.kind).collect();
        assert_eq!(hit, vec!['0', '1']);
        assert!(breakpoints_at(&all, 0x300).is_empty());
    }

    #[test]
    fn linear_pc_real_vs_flat() {
        let r = regs(&[("cs", 0xf000), ("rip", 0xfff0)]);
        assert_eq!(linear_pc(16, &r), 0xffff_fff0);
        assert_eq!(linear_pc(16, &regs(&[("cs", 0), ("rip", 0x7c00)])), 0x7c00);
        assert_eq!(linear_pc(32, &regs(&[("cs", 8), ("rip", 0x100000)])), 0x100000);
    }
}
