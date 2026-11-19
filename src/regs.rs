//! Register layout from the stub's `target.xml` (never hardcoded) and register read/write helpers.

use crate::rsp::{bytes_to_hex, hex_to_bytes, Rsp};
use crate::Res;
use regex::Regex;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct RegDef {
    pub name: String,
    pub bits: usize,
    pub regnum: usize,
}

#[derive(Default)]
pub struct RegDefs {
    pub regs: Vec<RegDef>,
}

fn attr(tag: &str, key: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"\b{key}="([^"]*)""#)).ok()?;
    re.captures(tag).map(|c| c[1].to_string())
}

pub fn xml_includes(xml: &str) -> Vec<String> {
    let re = Regex::new(r#"<xi:include[^>]*href="([^"]+)""#).unwrap();
    re.captures_iter(xml).map(|c| c[1].to_string()).collect()
}

/// Advertised by QEMU's x86-64 `target.xml` but absent from the stub's register numbering and `g` reply.
const PHANTOM: [&str; 3] = ["ss_base", "ds_base", "es_base"];

impl RegDefs {
    /// Parse the `<reg .../>` elements of one or more XML documents, in document order.
    pub fn from_xml(docs: &[String]) -> Self {
        let reg_tag = Regex::new(r"<reg\b[^>]*>").unwrap();
        let mut regs = Vec::new();
        let mut next = 0usize;
        for tag in docs.iter().flat_map(|d| reg_tag.find_iter(d)).map(|m| m.as_str()) {
            let (Some(name), Some(bits)) = (attr(tag, "name"), attr(tag, "bitsize")) else { continue };
            if PHANTOM.contains(&name.as_str()) {
                continue;
            }
            let regnum = attr(tag, "regnum").and_then(|n| n.parse().ok()).unwrap_or(next);
            next = regnum + 1;
            regs.push(RegDef { name, bits: bits.parse().unwrap_or(0), regnum });
        }
        regs.sort_by_key(|r| r.regnum);
        Self { regs }
    }

    pub fn find(&self, name: &str) -> Option<&RegDef> {
        self.regs.iter().find(|r| r.name.eq_ignore_ascii_case(name))
    }

    pub fn has(&self, name: &str) -> bool {
        self.find(name).is_some()
    }
}

/// Little-endian register bytes (hex) -> number. Registers wider than 128 bits are unsupported.
pub fn le_hex_to_u128(hex: &str) -> Option<u128> {
    let bytes = hex_to_bytes(hex).ok().filter(|b| b.len() <= 16)?;
    Some(bytes.iter().rev().fold(0u128, |acc, b| (acc << 8) | *b as u128))
}

pub fn u128_to_le_hex(value: u128, bits: usize) -> String {
    bytes_to_hex(&value.to_le_bytes()[..bits.div_ceil(8).min(16)])
}

/// Fetch `target.xml` and everything it includes.
pub async fn fetch_regdefs(rsp: &Rsp) -> Res<RegDefs> {
    let root = fetch_feature(rsp, "target.xml").await?;
    let mut docs = vec![root.clone()];
    for href in xml_includes(&root) {
        docs.push(fetch_feature(rsp, &href).await?);
    }
    let defs = RegDefs::from_xml(&docs);
    match defs.regs.is_empty() {
        true => Err("target.xml contained no registers".into()),
        false => Ok(defs),
    }
}

async fn fetch_feature(rsp: &Rsp, name: &str) -> Res<String> {
    let mut out = String::new();
    let step = (rsp.packet_size / 2).saturating_sub(16).max(256);
    loop {
        let reply = rsp.request_ok(&format!("qXfer:features:read:{name}:{:x},{step:x}", out.len())).await?;
        let (more, body) = reply.split_at(1);
        out.push_str(body);
        match more {
            "l" => return Ok(out),
            "m" => continue,
            _ => return Err(format!("bad qXfer reply for {name}: {}", &reply[..reply.len().min(20)])),
        }
    }
}

/// Registers covered by a `g` reply, walked in regnum order until the hex runs out.
pub fn parse_g_reply(defs: &RegDefs, hex: &str) -> Vec<(String, u128)> {
    let mut at = 0usize;
    let mut out = Vec::new();
    for reg in &defs.regs {
        let chars = reg.bits.div_ceil(8) * 2;
        let Some(chunk) = hex.get(at..at + chars) else { break };
        at += chars;
        if let Some(v) = le_hex_to_u128(chunk) {
            out.push((reg.name.clone(), v));
        }
    }
    out
}

pub type RegCache = HashMap<String, u128>;

/// Read registers, serving from `cache` and filling it (one `g` for the core set, `p` for the rest).
pub async fn read_regs(rsp: &Rsp, defs: &RegDefs, cache: &mut RegCache, names: &[String]) -> Res<Vec<(String, u128)>> {
    if cache.is_empty() {
        let g = rsp.request_ok("g").await?;
        cache.extend(parse_g_reply(defs, &g));
    }
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let def = defs.find(name).ok_or_else(|| format!("unknown register '{name}'"))?;
        let key = def.name.clone();
        if !cache.contains_key(&key) {
            let reply = rsp.request_ok(&format!("p{:x}", def.regnum)).await?;
            let value = le_hex_to_u128(&reply).ok_or_else(|| format!("register '{name}' is {} bits; too wide to display", def.bits))?;
            cache.insert(key.clone(), value);
        }
        out.push((key.clone(), cache[&key]));
    }
    Ok(out)
}

pub async fn write_reg(rsp: &Rsp, defs: &RegDefs, name: &str, value: u128) -> Res<()> {
    let def = defs.find(name).ok_or_else(|| format!("unknown register '{name}'"))?;
    rsp.request_ok(&format!("P{:x}={}", def.regnum, u128_to_le_hex(value, def.bits))).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<feature name="x"><reg name="rax" bitsize="64" type="int64" regnum="0"/>
        <reg name="rbx" bitsize="64" regnum="1"/><reg name="eflags" bitsize="32"/></feature>"#;

    #[test]
    fn parses_regs_with_and_without_regnum() {
        let d = RegDefs::from_xml(&[XML.to_string()]);
        let got: Vec<_> = d.regs.iter().map(|r| (r.name.as_str(), r.bits, r.regnum)).collect();
        assert_eq!(got, vec![("rax", 64, 0), ("rbx", 64, 1), ("eflags", 32, 2)]);
        assert!(d.has("RAX"));
    }

    #[test]
    fn g_reply_walks_layout_and_stops_at_end() {
        let d = RegDefs::from_xml(&[XML.to_string()]);
        let hex = "efcdab0000000000".to_string() + "0100000000000000" + "02000000";
        assert_eq!(parse_g_reply(&d, &hex), vec![("rax".into(), 0xabcdef), ("rbx".into(), 1), ("eflags".into(), 2)]);
        assert_eq!(parse_g_reply(&d, &hex[..20]).len(), 1);
    }

    #[test]
    fn phantom_base_registers_do_not_shift_numbering() {
        // regression (found booting OVMF): QEMU's x86-64 XML lists ss/ds/es_base before fs_base but the stub has no such
        // registers, so cr0/cr4/efer were read 3 slots off (cr0 showed 0 instead of 0x60000010)
        let xml = r#"<feature><reg name="gs" bitsize="32" regnum="23"/><reg name="ss_base" bitsize="64"/><reg name="ds_base" bitsize="64"/>
            <reg name="es_base" bitsize="64"/><reg name="fs_base" bitsize="64"/><reg name="cr0" bitsize="64"/></feature>"#;
        let d = RegDefs::from_xml(&[xml.to_string()]);
        let got: Vec<_> = d.regs.iter().map(|r| (r.name.as_str(), r.regnum)).collect();
        assert_eq!(got, vec![("gs", 23), ("fs_base", 24), ("cr0", 25)]);
    }

    #[test]
    fn le_hex_roundtrip() {
        assert_eq!(le_hex_to_u128("f0ff0000"), Some(0xfff0));
        assert_eq!(u128_to_le_hex(0xfff0, 32), "f0ff0000");
    }

    #[test]
    fn includes_found() {
        assert_eq!(xml_includes(r#"<xi:include href="a.xml"/><xi:include href="b.xml"/>"#), vec!["a.xml", "b.xml"]);
    }
}
