use anyhow::{Context, Result};
/// Functions for daemonizing auditrs and managing the PID file.
/// In the future, some work should be done to see if we can get this
/// working with systemctl or similar system services
use std::fs;
use std::path::PathBuf;

use crate::daemon::PID_FILE_NAME;

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

/// Daemonize the process using the daemonize crate. Call before starting the worker.
/// Returns Ok(()) in the daemon process; parent exits inside start().
pub fn start_daemon() -> Result<(), anyhow::Error> {
    let path = pid_file_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    println!("Daemonizing with PID file at {}", path.display());

    let daemonize = daemonize::Daemonize::new().pid_file(path);

    println!("Starting daemonization");

    match daemonize.start() {
        Ok(_) => {
            println!("Successfully daemonized");
            Ok(())
        }
        Err(e) => {
            println!("Failed to daemonize: {}", e);
            Err(anyhow::anyhow!("Failed to daemonize: {}", e))
        }
    }
}

/// Remove the PID file. Call on daemon shutdown.
pub fn remove_pid_file() {
    let _ = fs::remove_file(pid_file_path());
}

/// Send SIGTERM to the daemon and remove the PID file (used by `auditrs stop`).
pub fn stop_daemon() -> Result<()> {
    let path = pid_file_path();
    let contents = fs::read_to_string(&path).context("AuditRS is already stopped")?;
    let pid: i32 = contents
        .trim()
        .parse()
        .with_context(|| format!("invalid PID in {}", path.display()))?;
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    fs::remove_file(&path)?;
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
