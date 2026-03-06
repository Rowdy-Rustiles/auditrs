use anyhow::Result;

use super::daemon::{is_running, start_daemon, stop_daemon};
use colorized::*;

pub fn start_auditrs(reboot: bool) -> Result<()> {
    println!("Starting auditrs...");
    start_daemon()?;
    if !reboot {
        colorize_println("Auditrs started successfully", Colors::BrightGreenFg);
    }
    Ok(())
}

pub fn stop_auditrs(reboot: bool) -> Result<()> {
    stop_daemon()?;
    if !reboot {
    colorize_println("Stopped auditRS daemon", Colors::BrightRedFg);
    }
    Ok(())
}

pub fn reboot_auditrs() -> Result<()> {
    // If the daemon is not running, we don't need to reboot
    if !is_running() {
        return Ok(());
    }
    colorize_println("Rebooting auditRS", Colors::BrightBlueFg);
    let _ = stop_auditrs(true)?;
    start_auditrs(true)?;
    colorize_println("Auditrs rebooted successfully", Colors::BrightGreenFg);
    Ok(())
}

pub fn status_auditrs() -> Result<()> {
    if is_running() {
        colorize_println("Auditrs is running", Colors::BrightGreenFg);
    } else {
        colorize_println("Auditrs is not running", Colors::BrightRedFg);
    }
    Ok(())
}
