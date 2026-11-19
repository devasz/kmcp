//! Process supervision. QEMU is our *direct* child in its own process group, so:
//! - `PR_SET_PDEATHSIG(SIGKILL)` kills it if we die (even by SIGKILL);
//! - pdeathsig fires when the *spawning thread* exits, so spawning happens on one long-lived
//!   std thread (never `spawn_blocking`, whose threads come and go);
//! - SIGTERM/SIGINT call `kill_all` (killpg); a pidfile lets the next start reap what a crash left.

use crate::Res;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

type SpawnJob = (Command, Sender<std::io::Result<Child>>);

static SPAWNER: OnceLock<Mutex<Sender<SpawnJob>>> = OnceLock::new();
static GROUPS: Mutex<Vec<i32>> = Mutex::new(Vec::new());
static SYSTEMD_SCOPE: AtomicBool = AtomicBool::new(false);

/// Opt-in: also run QEMU in a transient systemd user scope (cgroup cleanup if we are SIGKILLed).
pub fn use_systemd_scope() {
    SYSTEMD_SCOPE.store(true, Ordering::Relaxed);
}

fn command_for(argv: &[String]) -> Command {
    if !SYSTEMD_SCOPE.load(Ordering::Relaxed) {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        return cmd;
    }
    let mut cmd = Command::new("systemd-run");
    cmd.args(["--user", "--scope", "--quiet", "--"]).args(argv);
    cmd
}

fn spawner() -> &'static Mutex<Sender<SpawnJob>> {
    SPAWNER.get_or_init(|| {
        let (tx, rx) = channel::<SpawnJob>();
        std::thread::Builder::new()
            .name("qemu-spawner".into())
            .spawn(move || {
                for (mut cmd, reply) in rx {
                    let _ = reply.send(cmd.spawn());
                }
            })
            .expect("spawn supervisor thread");
        Mutex::new(tx)
    })
}

/// Spawn `argv` (no shell) as a pdeathsig-protected process-group leader.
pub fn spawn_qemu(argv: &[String], log_path: &Path) -> Res<Child> {
    let mut cmd = command_for(argv);
    cmd.stdin(Stdio::null()).stdout(Stdio::null());
    cmd.stderr(std::fs::File::create(log_path).map_err(|e| format!("create {}: {e}", log_path.display()))?);
    let parent = std::process::id() as i32;
    // SAFETY: only async-signal-safe libc calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            libc::setpgid(0, 0);
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
            if libc::getppid() != parent {
                libc::_exit(1); // parent died before pdeathsig was armed
            }
            Ok(())
        });
    }
    let (tx, rx) = channel();
    spawner().lock().unwrap().send((cmd, tx)).map_err(|_| "supervisor thread gone".to_string())?;
    let child = rx.recv().map_err(|_| "supervisor thread gone".to_string())?.map_err(|e| format!("spawn {}: {e}", argv[0]))?;
    GROUPS.lock().unwrap().push(child.id() as i32);
    Ok(child)
}

/// SIGKILL a managed process group and reap the leader. Idempotent.
pub fn kill_group(child: &mut Child) {
    let pgid = child.id() as i32;
    // SAFETY: plain syscall on a pgid we created.
    unsafe { libc::killpg(pgid, libc::SIGKILL) };
    let _ = child.wait();
    GROUPS.lock().unwrap().retain(|g| *g != pgid);
}

/// Signal-handler path: no `Child` handle needed.
pub fn kill_all_groups() {
    for pgid in GROUPS.lock().unwrap().drain(..) {
        // SAFETY: as above.
        unsafe { libc::killpg(pgid, libc::SIGKILL) };
    }
}

pub fn run_root() -> Res<PathBuf> {
    let base = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| format!("/tmp/qmcp-{}", unsafe { libc::getuid() }));
    let root = PathBuf::from(base).join("qmcp");
    std::fs::create_dir_all(&root).map_err(|e| format!("create {}: {e}", root.display()))?;
    restrict(&root)?;
    Ok(root)
}

pub fn restrict(dir: &Path) -> Res<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("chmod {}: {e}", dir.display()))
}

/// Field 22 of /proc/<pid>/stat (start time in ticks); the pid-reuse guard.
pub fn start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

fn pid_alive(pid: i32) -> bool {
    // SAFETY: signal 0 only probes.
    unsafe { libc::kill(pid, 0) == 0 }
}

pub fn write_pidfile(dir: &Path, qemu_pid: i32) -> Res<()> {
    let line = format!("{qemu_pid} {} {}\n", start_time(qemu_pid).unwrap_or(0), std::process::id());
    std::fs::write(dir.join("pidfile"), line).map_err(|e| format!("write pidfile: {e}"))
}

fn parse_pidfile(text: &str) -> Option<(i32, u64, i32)> {
    let mut f = text.split_whitespace();
    Some((f.next()?.parse().ok()?, f.next()?.parse().ok()?, f.next()?.parse().ok()?))
}

/// Kill QEMUs whose owning MCP died without cleaning up, and remove their run dirs.
/// Returns how many were reaped.
pub fn reap_stale(root: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else { return 0 };
    let mut reaped = 0;
    for dir in entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
        let Some((qemu, started, owner)) = std::fs::read_to_string(dir.join("pidfile")).ok().as_deref().and_then(parse_pidfile) else { continue };
        if pid_alive(owner) {
            continue;
        }
        if start_time(qemu) == Some(started) {
            // SAFETY: pid verified by start time; QEMU led its own group.
            unsafe { libc::killpg(qemu, libc::SIGKILL) };
            reaped += 1;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    reaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidfile_roundtrip() {
        assert_eq!(parse_pidfile("12 345 6\n"), Some((12, 345, 6)));
        assert_eq!(parse_pidfile("garbage"), None);
    }

    #[test]
    fn own_start_time_is_readable() {
        assert!(start_time(std::process::id() as i32).is_some());
    }
}
