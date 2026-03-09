use super::worker::run_worker;
use anyhow::{Context, Result};
/// Functions for daemonizing auditrs and managing the PID file.
/// In the future, some work should be done to see if we can get this
/// working with systemctl or similar system services
use std::fs::{self, File};
use std::path::PathBuf;
use std::process::{Command, exit};

use crate::daemon::PID_FILE_NAME;

use daemonize::{Daemonize, Outcome};

/// Checks if the user has is running with root privileges.
/// Users without permissions will write to relative paths, we want to avoid this.
/// TODO: Ideally we check if the user has write access to the audit log directory.
fn is_root() -> Result<()> {
    unsafe {
        if libc::geteuid() == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("User is not running with root privileges"))
        }
    }
}

fn prepare_auditrs() -> Result<()> {
    Command::new("auditctl").arg("-e").arg("1").output()?;

    Command::new("service").arg("auditd").arg("stop").output()?;
    Ok(())
}

/// Creates a daemon process that runs in the background.
/// Both the parent (main) and child (daemon) will return up the call stack with a result.
/// The parent process will wait a moment and check if the daemon's PID file exists.
pub fn start_daemon() -> Result<(), anyhow::Error> {
    is_root()?;
    prepare_auditrs()?;
    let pid = pid_file_path();
    if let Some(parent) = pid.parent() {
        fs::create_dir_all(parent)?;
    }
    let stdout = File::create("/tmp/daemon.out")?;
    let stderr = File::create("/tmp/daemon.err")?;

    let daemonize = Daemonize::new()
        .pid_file(&pid)
        .stdout(stdout)
        .stderr(stderr);

    // Use execute() instead of start() so we can report the result before the parent process is killed.
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

/// Send SIGTERM to the daemon (used by `auditrs stop`).
pub fn stop_daemon() -> Result<()> {
    is_root()?;
    let path = pid_file_path();
    let contents = fs::read_to_string(&path).context("No PID file found. Is AuditRS running?")?;
    let pid: i32 = contents
        .trim()
        .parse()
        .with_context(|| format!("invalid PID in {}", path.display()))?;
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// True if the PID file exists and that process is still running.
pub fn is_running() -> bool {
    let path = pid_file_path();
    let Ok(contents) = fs::read_to_string(&path) else {
        return false;
    };
    let Ok(pid) = contents.trim().parse::<i32>() else {
        return false;
    };
    unsafe { libc::kill(pid, 0) == 0 }
}

fn pid_file_path() -> PathBuf {
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

// This is a file guard that will wrap the daemon's pid file.
// Once it falls out of scope (i.e., daemon exits), the Drop trait will make sure the pid file gets deleted.
struct FileGuard {
    file: std::fs::File,
    path: PathBuf,
}

impl FileGuard {
    fn new(path: PathBuf) -> Result<Self, std::io::Error> {
        let file = std::fs::File::open(&path)?;
        Ok(Self { file, path })
    }
}

impl Drop for FileGuard {
    fn drop(&mut self) {
        println!("Cleaning up PID file: {:?}", self.path);
        let _ = std::fs::remove_file(&self.path);
    }
}
