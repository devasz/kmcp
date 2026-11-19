//! Native symbol and line lookup (object + gimli): no gdb needed. Addresses are the ELF's
//! link-time addresses, so use it with kernels loaded at their linked address (no KASLR).

use crate::Res;
use gimli::{EndianSlice, RunTimeEndian};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use std::borrow::Cow;

const MAX_LINE_ROWS: usize = 4_000_000;

#[derive(Default)]
pub struct Symbols {
    /// (address, size, name), sorted by address.
    funcs: Vec<(u64, u64, String)>,
    /// (address, file, line), sorted by address.
    lines: Vec<(u64, String, u32)>,
}

impl Symbols {
    pub fn load(path: &str) -> Res<Self> {
        let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
        let file = object::File::parse(&*data).map_err(|e| format!("parse {path}: {e}"))?;
        let mut funcs: Vec<_> = file.symbols().filter(|s| is_addressable(s) && s.address() != 0).filter_map(|s| Some((s.address(), s.size(), s.name().ok()?.to_string()))).collect();
        funcs.sort();
        let lines = read_lines(&file).unwrap_or_default(); // missing/odd DWARF just means no line info
        Ok(Self { funcs, lines })
    }

    pub fn lookup(&self, name: &str) -> Option<u64> {
        self.funcs.iter().find(|(_, _, n)| n == name).map(|f| f.0)
    }

    /// `name+0xoff` for the symbol containing (or, for sizeless symbols, preceding) `addr`.
    pub fn nearest(&self, addr: u64) -> Option<String> {
        let i = self.funcs.partition_point(|f| f.0 <= addr).checked_sub(1)?;
        let (start, size, name) = &self.funcs[i];
        let off = addr - start;
        match *size == 0 || off < *size {
            true => Some(if off == 0 { name.clone() } else { format!("{name}+{off:#x}") }),
            false => None,
        }
    }

    pub fn line(&self, addr: u64) -> Option<String> {
        let i = self.lines.partition_point(|l| l.0 <= addr).checked_sub(1)?;
        let (_, file, line) = &self.lines[i];
        Some(format!("{file}:{line}"))
    }

    /// `name+off (file:line)` when known.
    pub fn describe(&self, addr: u64) -> Option<String> {
        let sym = self.nearest(addr)?;
        Some(match self.line(addr) {
            Some(l) => format!("{sym} ({l})"),
            None => sym,
        })
    }
}

/// Functions, data, and plain assembly labels (`NOTYPE`: xv6's `_entry`, `kernelvec`, most kernel entry stubs), minus
/// undefined symbols and toolchain markers (`$x`/`$d` mapping symbols, `.L` locals).
fn is_addressable<'a>(sym: &impl ObjectSymbol<'a>) -> bool {
    match sym.kind() {
        SymbolKind::Text | SymbolKind::Data => true,
        SymbolKind::Unknown => sym.section_index().is_some() && sym.name().is_ok_and(|n| !n.is_empty() && !n.starts_with(['$', '.'])),
        _ => false,
    }
}

fn read_lines(file: &object::File) -> Result<Vec<(u64, String, u32)>, gimli::Error> {
    let endian = if file.is_little_endian() { RunTimeEndian::Little } else { RunTimeEndian::Big };
    let load = |id: gimli::SectionId| -> Result<Cow<[u8]>, gimli::Error> { Ok(file.section_by_name(id.name()).and_then(|s| s.uncompressed_data().ok()).unwrap_or(Cow::Borrowed(&[][..]))) };
    let owned = gimli::DwarfSections::load(load)?;
    let dwarf = owned.borrow(|section| EndianSlice::new(section, endian));
    let mut rows_out = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let Some(program) = unit.line_program.clone() else { continue };
        let mut rows = program.rows();
        while let Some((lp, row)) = rows.next_row()? {
            if row.end_sequence() || rows_out.len() >= MAX_LINE_ROWS {
                continue;
            }
            let name = row.file(lp).and_then(|f| dwarf.attr_string(&unit, f.path_name()).ok()).map_or_else(|| "?".to_string(), |s| s.to_string_lossy().into_owned());
            rows_out.push((row.address(), name, row.line().map_or(0, |l| l.get() as u32)));
        }
    }
    rows_out.sort_by_key(|r| r.0);
    Ok(rows_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_respects_size_and_offset() {
        let s = Symbols { funcs: vec![(0x100, 0x10, "a".into()), (0x200, 0, "b".into())], lines: vec![(0x100, "x.c".into(), 7)] };
        assert_eq!(s.nearest(0x100).as_deref(), Some("a"));
        assert_eq!(s.nearest(0x108).as_deref(), Some("a+0x8"));
        assert_eq!(s.nearest(0x150), None);
        assert_eq!(s.nearest(0x300).as_deref(), Some("b+0x100"));
        assert_eq!(s.describe(0x104).as_deref(), Some("a+0x4 (x.c:7)"));
        assert_eq!(s.lookup("b"), Some(0x200));
    }

    #[test]
    fn plain_assembly_labels_are_symbols() {
        // regression (found loading xv6-riscv): `_entry` is a NOTYPE label and was silently dropped
        use object::write::{Object as Out, Symbol, SymbolSection};
        use object::{Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolScope};
        let mut obj = Out::new(BinaryFormat::Elf, Architecture::Riscv64, Endianness::Little);
        let text = obj.add_section(vec![], b".text".to_vec(), SectionKind::Text);
        obj.append_section_data(text, &[0; 16], 4);
        let mut label = |name: &str, value: u64| {
            obj.add_symbol(Symbol { name: name.into(), value, size: 0, kind: SymbolKind::Text, scope: SymbolScope::Dynamic, weak: false, section: SymbolSection::Section(text), flags: SymbolFlags::Elf { st_info: object::elf::SymbolInfo(0x10), st_other: object::elf::SymbolOther(0) } }); // GLOBAL NOTYPE
        };
        label("_entry", 0x10);
        label("$x", 0x14);
        let path = std::env::temp_dir().join(format!("qmcp-sym-{}.o", std::process::id()));
        std::fs::write(&path, obj.write().unwrap()).unwrap();
        let loaded = Symbols::load(path.to_str().unwrap());
        std::fs::remove_file(&path).ok();
        let s = loaded.unwrap();
        assert_eq!(s.lookup("_entry"), Some(0x10));
        assert_eq!(s.lookup("$x"), None);
    }

    #[test]
    fn loads_own_test_binary() {
        let exe = std::env::current_exe().unwrap();
        let s = Symbols::load(exe.to_str().unwrap()).unwrap();
        assert!(!s.funcs.is_empty());
    }
}
