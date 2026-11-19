//! Validated launch spec -> QEMU argv. There is no raw-argv escape hatch: every value is checked
//! against a whitelist or canonicalized, and `,` in paths is escaped for QEMU's option parser.

use crate::Res;
use schemars::JsonSchema;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize, JsonSchema, Default, Clone)]
pub struct Drive {
    /// Absolute path to the image.
    pub file: String,
    /// raw (default) or qcow2.
    pub format: Option<String>,
    /// ide, virtio, sd, scsi, floppy or none; omitted = QEMU default for the machine.
    pub interface: Option<String>,
    pub readonly: Option<bool>,
}

#[derive(Deserialize, JsonSchema, Default, Clone)]
pub struct Replay {
    /// record or replay (needs --experimental-replay and TCG).
    pub mode: String,
    pub file: String,
}

#[derive(Deserialize, JsonSchema, Default, Clone)]
pub struct LaunchSpec {
    /// x86_64 (default), aarch64 or riscv64. Non-x86 machines get modern virtio-mmio.
    pub arch: Option<String>,
    pub machine: Option<String>,
    pub cpu: Option<String>,
    /// tcg (default) or kvm. Under kvm the `-d int` fault triage is unavailable.
    pub accel: Option<String>,
    pub mem_mb: Option<u32>,
    pub smp: Option<u32>,
    pub kernel: Option<String>,
    pub initrd: Option<String>,
    pub append: Option<String>,
    /// Firmware file, or the keyword `none` (no firmware: bare-metal kernels such as xv6).
    pub bios: Option<String>,
    #[serde(default)]
    pub drives: Vec<Drive>,
    /// Add a pvpanic device so guest panics raise GUEST_PANICKED.
    #[serde(default)]
    pub pvpanic: bool,
    /// x86 only: enable SMM with SMRAM-protected pflash, which SMM-capable firmware (OVMF_CODE.secboot) needs to boot.
    #[serde(default)]
    pub smm: bool,
    /// x86 only: capture the 0x402 debug console (SeaBIOS/OVMF debug output).
    #[serde(default)]
    pub debugcon: bool,
    /// `-d` flags (TCG only). Default int,cpu_reset,guest_errors.
    pub d_flags: Option<String>,
    /// Serial ring size in KiB (default 4096).
    pub serial_kb: Option<usize>,
    pub replay: Option<Replay>,
    /// ELF with symbols/DWARF to load for the session.
    pub elf: Option<String>,
}

pub struct Launch {
    pub argv: Vec<String>,
    pub arch: String,
    pub tcg: bool,
}

pub const DEFAULT_D_FLAGS: &str = "int,cpu_reset,guest_errors";
const ARCHES: [&str; 3] = ["x86_64", "aarch64", "riscv64"];
const INTERFACES: [&str; 7] = ["ide", "virtio", "sd", "scsi", "floppy", "pflash", "none"];
/// Not a QEMU `if=` value: a `virtio-blk-device` on the n-th virtio-mmio transport (riscv/arm `virt`, where `if=virtio` means PCI).
const VIRTIO_MMIO: &str = "virtio-mmio";

fn ident(what: &str, v: &str) -> Res<String> {
    let ok = !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b));
    match ok {
        true => Ok(v.to_string()),
        false => Err(format!("invalid {what} '{v}' (letters, digits and _.+- only)")),
    }
}

fn one_of(what: &str, v: &str, allowed: &[&str]) -> Res<String> {
    match allowed.contains(&v) {
        true => Ok(v.to_string()),
        false => Err(format!("invalid {what} '{v}' (one of {})", allowed.join(", "))),
    }
}

/// Existing absolute path, canonicalized, with `,` doubled for QEMU option strings.
pub fn existing_path(what: &str, p: &str) -> Res<String> {
    if !p.starts_with('/') {
        return Err(format!("{what} must be an absolute path, got '{p}'"));
    }
    let real = std::fs::canonicalize(p).map_err(|e| format!("{what} '{p}': {e}"))?;
    Ok(real.to_string_lossy().replace(',', ",,"))
}

fn sock(dir: &Path, name: &str) -> Res<String> {
    let path = dir.join(name).to_string_lossy().into_owned();
    match path.len() < 100 {
        true => Ok(path),
        false => Err(format!("socket path too long ({} bytes, limit ~108): {path}", path.len())),
    }
}

fn socket_chardev(id: &str, path: &str) -> String {
    format!("socket,id={id},path={path},server=on,wait=off")
}

fn machine_args(spec: &LaunchSpec, arch: &str) -> Res<Vec<String>> {
    let accel = one_of("accel", spec.accel.as_deref().unwrap_or("tcg"), &["tcg", "kvm"])?;
    let default_machine = if arch == "x86_64" { "pc" } else { "virt" };
    let machine = ident("machine", spec.machine.as_deref().unwrap_or(default_machine))?;
    if spec.smm && arch != "x86_64" {
        return Err("smm is x86 only".into());
    }
    let machine = if spec.smm { format!("{machine},smm=on") } else { machine };
    let mut args = vec!["-machine".into(), machine, "-accel".into(), accel];
    if spec.smm {
        args.extend(["-global".into(), "driver=cfi.pflash01,property=secure,value=on".into()]);
    }
    let cpu = spec.cpu.as_deref().or(if arch == "aarch64" { Some("cortex-a57") } else { None });
    if let Some(cpu) = cpu {
        args.extend(["-cpu".into(), ident("cpu", cpu)?]);
    }
    if arch != "x86_64" {
        // modern (v2) virtio-mmio: legacy v1 is QEMU's default there and current guests (xv6, Linux, Zephyr) expect v2
        args.extend(["-global".into(), "virtio-mmio.force-legacy=false".into()]);
    }
    let (mem, smp) = (spec.mem_mb.unwrap_or(128).clamp(1, 16384), spec.smp.unwrap_or(1).clamp(1, 64));
    args.extend(["-m".into(), mem.to_string(), "-smp".into(), smp.to_string()]);
    Ok(args)
}

fn boot_args(spec: &LaunchSpec) -> Res<Vec<String>> {
    let mut args = Vec::new();
    for (flag, path) in [("-kernel", &spec.kernel), ("-initrd", &spec.initrd), ("-bios", &spec.bios)] {
        match path.as_deref() {
            Some("none") if flag == "-bios" => args.extend(["-bios".into(), "none".into()]), // QEMU keyword: no firmware (xv6, bare-metal riscv)
            Some(p) => args.extend([flag.to_string(), existing_path(flag, p)?]),
            None => {}
        }
    }
    if let Some(line) = &spec.append {
        args.extend(["-append".into(), line.clone()]); // its own argv element: no option parsing
    }
    Ok(args)
}

fn drive_args(d: &Drive, index: usize) -> Res<Vec<String>> {
    let mut opt = format!("file={},format={}", existing_path("drive file", &d.file)?, one_of("drive format", d.format.as_deref().unwrap_or("raw"), &["raw", "qcow2"])?);
    let mmio = d.interface.as_deref() == Some(VIRTIO_MMIO);
    match (&d.interface, mmio) {
        (_, true) => opt += &format!(",if=none,id=mmio{index}"),
        (Some(i), false) => opt += &format!(",if={}", one_of("drive interface", i, &INTERFACES)?),
        (None, false) => {}
    }
    if d.readonly == Some(true) {
        opt += ",readonly=on";
    }
    let mut args = vec!["-drive".into(), opt];
    if mmio {
        args.extend(["-device".into(), format!("virtio-blk-device,drive=mmio{index},bus=virtio-mmio-bus.{index}")]);
    }
    Ok(args)
}

fn replay_args(spec: &LaunchSpec) -> Res<Vec<String>> {
    let Some(r) = &spec.replay else { return Ok(vec![]) };
    let mode = one_of("replay mode", &r.mode, &["record", "replay"])?;
    let file = match mode.as_str() {
        "replay" => existing_path("replay file", &r.file)?,
        _ => new_output_path(&r.file)?,
    };
    let has_qcow2 = spec.drives.iter().any(|d| d.format.as_deref() == Some("qcow2"));
    let snapshot = if has_qcow2 { ",rrsnapshot=init" } else { "" };
    Ok(vec!["-icount".into(), format!("shift=auto,rr={mode},rrfile={file}{snapshot}")])
}

/// A not-yet-existing absolute output path inside an existing directory.
fn new_output_path(p: &str) -> Res<String> {
    let path = PathBuf::from(p);
    let parent = path.parent().filter(|d| path.is_absolute() && d.is_dir()).ok_or_else(|| format!("replay file '{p}' must be an absolute path in an existing directory"))?;
    Ok(parent.canonicalize().map_err(|e| e.to_string())?.join(path.file_name().ok_or("replay file has no name")?).to_string_lossy().replace(',', ",,"))
}

fn device_args(spec: &LaunchSpec, arch: &str, dir: &Path) -> Res<Vec<String>> {
    let mut args = vec!["-chardev".into(), socket_chardev("ser0", &sock(dir, "serial.sock")?), "-serial".into(), "chardev:ser0".into()];
    if spec.debugcon {
        match arch == "x86_64" {
            true => args.extend(["-chardev".into(), socket_chardev("dbg0", &sock(dir, "debugcon.sock")?), "-device".into(), "isa-debugcon,iobase=0x402,chardev=dbg0".into()]),
            false => return Err("debugcon is x86 only".into()),
        }
    }
    if spec.pvpanic {
        args.extend(["-device".into(), if arch == "x86_64" { "pvpanic" } else { "pvpanic-pci" }.into()]);
    }
    for (index, d) in spec.drives.iter().enumerate() {
        args.extend(drive_args(d, index)?);
    }
    Ok(args)
}

fn control_args(dir: &Path) -> Res<Vec<String>> {
    Ok(vec![
        "-S".into(),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        "none".into(),
        "-qmp".into(),
        format!("unix:{},server=on,wait=off", sock(dir, "qmp.sock")?),
        "-chardev".into(),
        socket_chardev("gdb0", &sock(dir, "gdb.sock")?),
        "-gdb".into(),
        "chardev:gdb0".into(),
        "-action".into(),
        "reboot=shutdown,shutdown=pause,panic=pause".into(),
    ])
}

fn log_args(spec: &LaunchSpec, dir: &Path, tcg: bool) -> Res<Vec<String>> {
    if !tcg {
        return Ok(vec![]);
    }
    let flags = ident_flags(spec.d_flags.as_deref().unwrap_or(DEFAULT_D_FLAGS))?;
    Ok(vec!["-D".into(), dir.join("qemu.log").to_string_lossy().into_owned(), "-d".into(), flags])
}

fn ident_flags(v: &str) -> Res<String> {
    let ok = !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_,".contains(&b));
    match ok {
        true => Ok(v.to_string()),
        false => Err(format!("invalid d_flags '{v}'")),
    }
}

/// Build the full argv for `spec`; sockets and the log FIFO live in `dir`.
pub fn build(spec: &LaunchSpec, dir: &Path) -> Res<Launch> {
    let arch = one_of("arch", spec.arch.as_deref().unwrap_or("x86_64"), &ARCHES)?;
    let tcg = spec.accel.as_deref().unwrap_or("tcg") == "tcg";
    if spec.replay.is_some() && !tcg {
        return Err("replay requires accel=tcg".into());
    }
    let mut argv = vec![format!("qemu-system-{arch}")];
    for part in [machine_args(spec, &arch)?, boot_args(spec)?, device_args(spec, &arch, dir)?, control_args(dir)?, log_args(spec, dir, tcg)?, replay_args(spec)?] {
        argv.extend(part);
    }
    Ok(Launch { argv, arch, tcg })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        PathBuf::from("/run/qmcp/t1")
    }

    #[test]
    fn defaults_are_paused_tcg_with_triage_flags() {
        let l = build(&LaunchSpec::default(), &dir()).unwrap();
        assert_eq!(l.argv[0], "qemu-system-x86_64");
        assert!(l.argv.windows(2).any(|w| w == ["-accel", "tcg"]));
        assert!(l.argv.contains(&"-S".to_string()));
        assert!(l.argv.windows(2).any(|w| w == ["-d", DEFAULT_D_FLAGS]));
    }

    #[test]
    fn rejects_injection_in_names_and_flags() {
        for bad in [LaunchSpec { machine: Some("pc,dumpdtb=/x".into()), ..Default::default() }, LaunchSpec { arch: Some("../evil".into()), ..Default::default() }, LaunchSpec { d_flags: Some("int -foo".into()), ..Default::default() }] {
            assert!(build(&bad, &dir()).is_err());
        }
    }

    #[test]
    fn kvm_drops_log_flags_and_comma_paths_are_escaped() {
        let kvm = LaunchSpec { accel: Some("kvm".into()), ..Default::default() };
        assert!(!build(&kvm, &dir()).unwrap().argv.contains(&"-d".to_string()));
        assert_eq!(existing_path("x", "/").unwrap(), "/");
        assert!(existing_path("x", "relative").is_err());
    }

    #[test]
    fn pflash_drives_are_accepted_in_order() {
        // regression (found booting OVMF): `pflash` was not an allowed drive interface
        let flash = |readonly| Drive { file: "/dev/null".into(), format: None, interface: Some("pflash".into()), readonly: Some(readonly) };
        let spec = LaunchSpec { drives: vec![flash(true), flash(false)], ..Default::default() };
        let argv = build(&spec, &dir()).unwrap().argv;
        let drives: Vec<_> = argv.iter().filter(|a| a.contains("if=pflash")).collect();
        assert_eq!(drives.len(), 2);
        assert!(drives[0].contains("readonly=on") && !drives[1].contains("readonly=on"));
    }

    #[test]
    fn smm_launch_enables_smm_with_secure_flash_on_x86_only() {
        let spec = LaunchSpec { machine: Some("q35".into()), smm: true, ..Default::default() };
        let argv = build(&spec, &dir()).unwrap().argv.join(" ");
        assert!(argv.contains("-machine q35,smm=on") && argv.contains("driver=cfi.pflash01,property=secure,value=on"), "{argv}");
        assert!(!build(&LaunchSpec::default(), &dir()).unwrap().argv.join(" ").contains("smm"));
        assert!(build(&LaunchSpec { arch: Some("riscv64".into()), smm: true, ..Default::default() }, &dir()).is_err());
    }

    #[test]
    fn riscv_bare_metal_launch_needs_no_firmware_and_modern_virtio() {
        // regression (found launching xv6-riscv): `bios: none` was treated as a file path
        let spec = LaunchSpec { arch: Some("riscv64".into()), bios: Some("none".into()), ..Default::default() };
        let argv = build(&spec, &dir()).unwrap().argv.join(" ");
        assert!(argv.contains("-bios none") && argv.contains("-global virtio-mmio.force-legacy=false"));
        assert!(!build(&LaunchSpec::default(), &dir()).unwrap().argv.join(" ").contains("force-legacy"));
    }

    #[test]
    fn virtio_mmio_drive_becomes_blk_device_on_the_first_bus() {
        // regression (found launching xv6-riscv): `if=virtio` is virtio-blk-PCI on `virt`, but xv6 probes virtio-mmio at 0x10001000
        let drive = Drive { file: "/dev/null".into(), format: None, interface: Some("virtio-mmio".into()), readonly: None };
        let spec = LaunchSpec { arch: Some("riscv64".into()), drives: vec![drive], ..Default::default() };
        let argv = build(&spec, &dir()).unwrap().argv.join(" ");
        assert!(argv.contains("file=/dev/null,format=raw,if=none,id=mmio0"), "{argv}");
        assert!(argv.contains("-device virtio-blk-device,drive=mmio0,bus=virtio-mmio-bus.0"), "{argv}");
    }

    #[test]
    fn long_socket_paths_are_refused() {
        let long = PathBuf::from(format!("/{}", "a".repeat(120)));
        assert!(build(&LaunchSpec::default(), &long).is_err());
    }
}
