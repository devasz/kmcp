//! Host-side disassembly. x86 (16/32/64-bit) uses iced-x86; aarch64/riscv64 shell out to
//! `llvm-mc` (argv only, bytes on stdin) and degrade to raw `.word`/`.half` lines if it is missing.

use crate::Res;
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use serde::Serialize;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[derive(Serialize, Debug, PartialEq)]
pub struct Insn {
    pub addr: u64,
    pub bytes: String,
    pub text: String,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn x86(bits: u32, addr: u64, code: &[u8], max: usize) -> Vec<Insn> {
    let mut decoder = Decoder::with_ip(bits, code, addr, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut out = Vec::new();
    while decoder.can_decode() && out.len() < max {
        let start = decoder.position();
        let insn = decoder.decode();
        let mut text = String::new();
        formatter.format(&insn, &mut text);
        let text = if insn.is_invalid() { "(bad)".to_string() } else { text };
        out.push(Insn { addr: insn.ip(), bytes: hex(&code[start..decoder.position()]), text });
    }
    out
}

/// `llvm-mc --show-encoding` line -> (mnemonic text, encoded bytes).
fn parse_llvm_line(line: &str) -> Option<(String, Vec<u8>)> {
    let (text, enc) = line.split_once("encoding: [")?;
    let bytes = enc.trim_end_matches(']').split(',').map(|b| u8::from_str_radix(b.trim().trim_start_matches("0x"), 16).ok()).collect::<Option<Vec<u8>>>()?;
    let text = text.trim_end().trim_end_matches("//").trim_end_matches('#').trim().split_whitespace().collect::<Vec<_>>().join(" ");
    Some((text, bytes))
}

fn raw_words(arch: &str, addr: u64, code: &[u8], max: usize) -> Vec<Insn> {
    let step = if arch == "riscv64" { 2 } else { 4 };
    code.chunks(step).take(max).enumerate().map(|(i, c)| Insn { addr: addr + (i * step) as u64, bytes: hex(c), text: format!(".byte {}", c.iter().map(|b| format!("{b:#04x}")).collect::<Vec<_>>().join(",")) }).collect()
}

async fn run_llvm_mc(arch: &str, code: &[u8]) -> Res<String> {
    let (triple, attr) = if arch == "riscv64" { ("riscv64", "+c,+m,+a,+f,+d") } else { ("aarch64", "") };
    let mut child = tokio::process::Command::new("llvm-mc")
        .args(["--disassemble", "--show-encoding", &format!("-triple={triple}"), &format!("-mattr={attr}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("llvm-mc: {e}"))?;
    let input: String = code.iter().map(|b| format!("{b:#04x} ")).collect();
    child.stdin.take().ok_or("llvm-mc stdin")?.write_all(input.as_bytes()).await.map_err(|e| e.to_string())?;
    let out = tokio::time::timeout(Duration::from_secs(3), child.wait_with_output()).await.map_err(|_| "llvm-mc timed out".to_string())?.map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub async fn external(arch: &str, addr: u64, code: &[u8], max: usize) -> Vec<Insn> {
    let Ok(listing) = run_llvm_mc(arch, code).await else { return raw_words(arch, addr, code, max) };
    let mut at = addr;
    let mut out = Vec::new();
    for (text, bytes) in listing.lines().filter_map(parse_llvm_line).take(max) {
        out.push(Insn { addr: at, bytes: hex(&bytes), text });
        at += bytes.len() as u64;
    }
    match out.is_empty() {
        true => raw_words(arch, addr, code, max),
        false => out,
    }
}

pub async fn disasm(arch: &str, bits: u32, addr: u64, code: &[u8], max: usize) -> Vec<Insn> {
    match arch {
        "x86_64" => x86(bits, addr, code, max),
        _ => external(arch, addr, code, max).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_real_mode_cli_hlt() {
        let got = x86(16, 0x7c00, &[0xfa, 0xf4], 10);
        assert_eq!(got.iter().map(|i| (i.addr, i.text.as_str())).collect::<Vec<_>>(), vec![(0x7c00, "cli"), (0x7c01, "hlt")]);
    }

    #[test]
    fn x86_reset_vector_is_far_jump() {
        let got = x86(16, 0xfff0, &[0xea, 0x5b, 0xe0, 0x00, 0xf0], 1);
        assert!(got[0].text.starts_with("jmp") && got[0].text.contains("0E05B"), "{:?}", got[0]);
    }

    #[test]
    fn llvm_line_parses_both_comment_styles() {
        assert_eq!(parse_llvm_line("\tnop        // encoding: [0x1f,0x20,0x03,0xd5]"), Some(("nop".into(), vec![0x1f, 0x20, 0x03, 0xd5])));
        assert_eq!(parse_llvm_line("\tmv\ta0, a1   # encoding: [0x13,0x85,0x05,0x00]").unwrap().0, "mv a0, a1");
        assert_eq!(parse_llvm_line("   // =0x0"), None);
    }
}
