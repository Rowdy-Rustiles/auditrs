use anyhow::Result;

use super::daemon::{is_running, start_daemon, stop_daemon};

pub fn start_auditrs() -> Result<()> {
    println!("Starting auditrs...");
    start_daemon()?;
    println!("Auditrs started successfully");
    Ok(())
}

pub fn stop_auditrs() -> Result<()> {
    stop_daemon()?;
    println!("Stopped auditRS daemon");
    Ok(())
}

pub fn reboot_auditrs() -> Result<()> {
    // If the daemon is not running, we don't need to reboot
    if !is_running() {
        return Ok(());
    }
    println!("Rebooting auditRS");
    let _ = stop_auditrs();
    start_auditrs()
}

pub fn status_auditrs() -> Result<()> {
    println!(
        "auditRS is {}",
        if is_running() {
            "running"
        } else {
            "not running"
        }
    );
    Ok(())
}
