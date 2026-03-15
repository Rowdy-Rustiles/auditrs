//! Functions for daemonizing `auditrs` and managing the PID file.
//!
//! This module encapsulates the low-level mechanics of running `auditrs` as a
//! background daemon process. It is responsible for:
//!
//! - **Process lifecycle**: forking into the background, wiring up
//!   stdout/stderr, and driving the main worker loop.
//! - **PID management**: creating, locating, reading, and cleaning up the PID
//!   file that identifies the running daemon.
//! - **Environment preparation**: ensuring that the legacy `auditd` service is
//!   disabled before `auditrs` starts.
//!
//! In the future, this behavior may be integrated with `systemd` or other
//! service managers, but for now it uses a traditional double-fork style
//! daemonization via the `daemonize` crate.

use anyhow::{Context, Result, anyhow};
use daemonize::{Daemonize, Outcome};
use std::fs::{self, File};
use std::path::PathBuf;
use std::process::Command;

use crate::daemon::PID_FILE_NAME;
use crate::daemon::worker::run_worker;

/// Starts the `auditrs` daemon as a background process.
///
/// This function:
///
/// - Verifies that the caller has root privileges.
/// - Prepares the environment by disabling the legacy `auditd` service.
/// - Forks into a background daemon using the `daemonize` crate.
/// - In the parent process, briefly waits and then checks that the PID file
///   exists to confirm successful startup.
/// - In the child process, runs the asynchronous worker loop and ensures the
///   PID file is cleaned up on exit via `FileGuard`.
pub fn start_daemon() -> Result<()> {
    is_root()?;
    prepare_auditrs().context("Could not stop auditd service with systemctl")?;
    let pid = pid_file_path();
    if let Some(parent) = pid.parent() {
        fs::create_dir_all(parent)
            .context(format!("Could not create parent folders for {parent:?}"))?;
    }
    let stdout = File::create("/tmp/daemon.out")?;
    let stderr = File::create("/tmp/daemon.err")?;

    let daemonize = Daemonize::new()
        .pid_file(&pid)
        .stdout(stdout)
        .stderr(stderr);

    // Use execute() instead of start() so we can report the result before the
    // parent process is killed.
    match daemonize.execute() {
        Outcome::Parent(Ok(_)) => {
            // We're in the parent process - daemon was forked successfully.
            // However, we'll see if it encountered any errors after launching.
            std::thread::sleep(std::time::Duration::from_millis(100));

            if pid.exists() {
                Ok(())
            } else {
                Err(anyhow::anyhow!(format!(
                    "Daemon failed to initialize. See /tmp/daemon.err for details."
                )))
            }
        }
        Outcome::Parent(Err(e)) => Err(anyhow::anyhow!("Failed to daemonize: {}", e)),

        Outcome::Child(res) => {
            // We're in the child process - we are daemon!
            // First, acquire the guard on the daemon's PID file so it gets deleted.
            let _guard = FileGuard::new(pid)?;

            match res {
                Ok(_) => {
                    let rt = tokio::runtime::Runtime::new()?;
                    rt.block_on(run_worker())?;
                    Ok(())
                }
                Err(e) => Err(anyhow::anyhow!("Failed to daemonize: {}", e)),
            }
        }
    }
}

/// Sends `SIGTERM` to the running daemon (used by `auditrs stop`).
///
/// This reads the PID from the daemon's PID file, validates it, and then
/// forwards a `SIGTERM` signal to request a graceful shutdown.
pub fn stop_daemon() -> Result<()> {
    is_root()?;
    let path = pid_file_path();
    let contents = fs::read_to_string(&path).context("No PID file found. Is AuditRS running?")?;
    let pid: i32 = contents
        .trim()
        .parse()
        .context(format!("invalid PID in {}", path.display()))?;
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Returns `true` if the PID file exists and the referenced process is alive.
///
/// This is used by higher-level control functions to determine whether an
/// `auditrs` daemon is currently active.
pub fn is_running() -> Result<bool> {
    Ok(fs::exists(pid_file_path())? && unsafe { libc::kill(read_pid()?, 0) == 0 })
}

/// Reads the PID from the daemon's PID file.
///
/// The PID file location is resolved via [`pid_file_path`], and the contents
/// are parsed as a signed 32-bit integer.
pub fn read_pid() -> Result<i32> {
    let path = pid_file_path();
    let contents = fs::read_to_string(&path).context("Could not read PID file")?;
    contents
        .trim()
        .parse::<i32>()
        .context(format!("Could not parse PID file contents: {contents}"))
}

/// Resolves the path to the daemon's PID file.
///
/// The resolution strategy is:
///
/// - If running as root (`geteuid() == 0`), use `/var/run/<PID_FILE_NAME>`.
/// - Otherwise, prefer `$XDG_RUNTIME_DIR/<PID_FILE_NAME>` if set.
/// - Next, fall back to `$HOME/.cache/auditrs/<PID_FILE_NAME>`.
/// - Finally, use `./<PID_FILE_NAME>` as a last resort.
pub fn pid_file_path() -> PathBuf {
    // Ideally this is the only block that runs.
    unsafe {
        if libc::geteuid() == 0 {
            return PathBuf::from("/var/run").join(PID_FILE_NAME);
        }
    }
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join(PID_FILE_NAME);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".cache")
            .join("auditrs")
            .join(PID_FILE_NAME);
    }
    PathBuf::from(".").join(PID_FILE_NAME)
}

/// Ensures that the current user is running with root privileges.
///
/// This is used as a guard before operations that must not be performed by
/// unprivileged users (such as starting or stopping the system daemon).
/// Non-root callers receive an error.
///
/// TODO: Ideally we check whether the user has write access to the configured
/// log directory instead of hard-requiring root.
fn is_root() -> Result<()> {
    unsafe {
        if libc::geteuid() == 0 {
            Ok(())
        } else {
            Err(anyhow!("User is not running with root privileges"))
        }
    }
}

/// Ensures that the legacy `auditd` service is no longer running.
///
/// This helper enables auditing via `auditctl -e 1` and then stops the
/// `auditd` service, preparing the system for `auditrs` to take over. It is
/// intentionally conservative and will error if the underlying shell command
/// fails.
///
/// TODO: This will fail if either `auditctl` or `auditd` are not installed on
/// the host system; we may want to detect and handle that case more gracefully.
fn prepare_auditrs() -> Result<()> {
    Command::new("sh")
        .arg("-c")
        .arg("auditctl -e 1 && service auditd stop")
        .output()
        .context("Command failed: `auditctl -e 1 && service auditd stop`")?;
    Ok(())
}

/// Guard object that owns the daemon's PID file and cleans it up on drop.
///
/// When an instance of `FileGuard` goes out of scope (typically when the
/// daemon exits), its `Drop` implementation removes the PID file so that
/// subsequent invocations do not see a stale daemon state.
struct FileGuard {
    path: PathBuf,
}

impl FileGuard {
    fn new(path: PathBuf) -> Result<Self, std::io::Error> {
        Ok(Self { path })
    }
}

impl Drop for FileGuard {
    fn drop(&mut self) {
        println!("Cleaning up PID file: {:?}", self.path);
        let _ = std::fs::remove_file(&self.path);
    }
}
