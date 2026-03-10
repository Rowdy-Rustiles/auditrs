//! Top-level functions for controlling the state of the auditrs daemon.

use super::daemon::{is_running, read_pid, start_daemon, stop_daemon};
use anyhow::Result;
use colorized::*;
use std::fs;
use std::path::PathBuf;

/// Starts the auditrs daemon.
pub fn start_auditrs(reboot: bool) -> Result<()> {
    println!("Starting auditrs...");
    start_daemon()?;
    if !reboot {
        colorize_println("Auditrs started successfully", Colors::BrightGreenFg);
    }
    Ok(())
}

/// Stops the auditrs daemon.
pub fn stop_auditrs(reboot: bool) -> Result<()> {
    stop_daemon()?;
    if !reboot {
        colorize_println("Stopped auditRS daemon", Colors::BrightRedFg);
    }
    Ok(())
}

/// Reboot the auditrs daemon, this constitutes a full restart of the daemon.
/// The config is reloaded after the daemon is started up again. This is not
/// a dynamic reload of the config; for config reloads, use `reload_auditrs`.
pub fn reboot_auditrs() -> Result<()> {
    // If the daemon is not running, we don't need to reboot
    if !is_running()? {
        return Ok(());
    }
    colorize_println("Rebooting auditRS", Colors::BrightBlueFg);
    let _ = stop_auditrs(true)?;
    start_auditrs(true)?;
    colorize_println("Auditrs rebooted successfully", Colors::BrightGreenFg);
    Ok(())
}

pub fn status_auditrs() -> Result<()> {
    if is_running()? {
        colorize_println("Auditrs is running", Colors::BrightGreenFg);
    } else {
        colorize_println("Auditrs is not running", Colors::BrightRedFg);
    }
    Ok(())
}

/// Ask the running daemon to reload config (SIGHUP). This is a dynamic action
/// that will immediately apply new configuration to the auditrs daemon while it
/// is running.
pub fn reload_auditrs() -> Result<()> {
    if !is_running()? {
        return Ok(());
    }

    let pid = read_pid()?;
    if unsafe { libc::kill(pid, libc::SIGHUP) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
