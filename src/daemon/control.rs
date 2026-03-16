//! Top-level functions for controlling the lifecycle of the `auditrs` daemon.
//!
//! Exposes a small set of convenience functions that are used by
//! the CLI to start, stop, reboot, and reload the running daemon process. Each
//! function wraps lower-level primitives from `crate::daemon::daemon` and adds
//! user-friendly status output suitable for terminal use.

use anyhow::{Context, Result};
use colorized::{colorize_println, Colors};

use crate::daemon::daemon::{is_running, read_pid, start_daemon, stop_daemon};

/// Starts the `auditrs` daemon if it is not already running.
///
/// When invoked while a daemon instance is already active, this function
/// is a no-op and returns `Ok(())` after printing a short status message.
///
/// **Parameters:**
///
/// * `reboot`: Indicates whether this start is part of a reboot sequence. When
///   `true`, success messages intended for interactive users are suppressed so
///   that reboot flows remain quiet.
pub fn start_auditrs(reboot: bool) -> Result<()> {
    if is_running()? {
        colorize_println("Daemon is already running", Colors::BrightGreenFg);
        return Ok(());
    }
    println!("Starting auditrs...");
    start_daemon().context("Failed to start daemon")?;
    if !reboot {
        colorize_println("Auditrs started successfully", Colors::BrightGreenFg);
    }
    Ok(())
}

/// Stops the running `auditrs` daemon, if present.
///
/// If no daemon is currently running, this function simply prints a status
/// message and returns `Ok(())`.
///
/// **Parameters:**
///
/// * `reboot`: Indicates whether this stop is part of a reboot sequence. When
///   `true`, the usual "stopped" message is not printed.
pub fn stop_auditrs(reboot: bool) -> Result<()> {
    if !is_running()? {
        colorize_println("Daemon is already stopped", Colors::BrightRedFg);
        return Ok(());
    }
    stop_daemon()?;
    if !reboot {
        // We don't want to print this when we're in the middle of a reboot
        colorize_println("Stopped auditRS daemon", Colors::BrightRedFg);
    }
    Ok(())
}

/// Performs a full reboot of the `auditrs` daemon.
///
/// This is implemented as a stop followed by a fresh start of the daemon
/// process. Configuration is reloaded as part of the restart sequence.
/// For a dynamic, in-place configuration reload without a full restart,
/// prefer `reload_auditrs`.
/// 
/// TODO: Must test, not sure that this is working as expected.
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

/// Reports whether the `auditrs` daemon is currently running.
///
/// Prints a human-friendly message to standard output indicating the
/// daemon's status, and always returns `Ok(())` regardless of state.
pub fn status_auditrs() -> Result<()> {
    if is_running()? {
        colorize_println("Auditrs is running", Colors::BrightGreenFg);
    } else {
        colorize_println("Auditrs is not running", Colors::BrightRedFg);
    }
    Ok(())
}

/// Asks the running daemon to reload its configuration (SIGHUP).
///
/// This sends `SIGHUP` to the daemon process identified by the stored PID,
/// causing it to re-read configuration without a full restart. If the daemon
/// is not running, this function is a no-op and returns `Ok(())`.
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
