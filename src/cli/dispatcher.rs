use anyhow::Result;
use clap::ArgMatches;

use crate::daemon::daemon::{is_running, start_daemon, stop_daemon};

/// Top-level entry point for handling CLI subcommands
pub fn dispatch(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("start", _)) => start_auditrs()?,
        Some(("stop", _)) => stop_auditrs()?,
        Some(("reboot", _)) => reboot_auditrs()?,
        Some(("status", _)) => status_auditrs()?,
        Some(("dump", sub_m)) => handle_dump(sub_m)?,
        Some(("search", sub_m)) => handle_search(sub_m)?,
        Some(("report", sub_m)) => handle_report(sub_m)?,
        Some(("config", sub_m)) => handle_config(sub_m)?,
        None => {
            unreachable!("cli implementation should prevent this");
        }
        _ => unreachable!("cli implementation should prevent this"),
    }

    Ok(())
}

fn start_auditrs() -> Result<()> {
    start_daemon()
}

fn stop_auditrs() -> Result<()> {
    stop_daemon()?;
    println!("Stopped auditRS daemon");
    Ok(())
}

fn reboot_auditrs() -> Result<()> {
    println!("Rebooting auditRS");
    let _ = stop_auditrs();
    start_auditrs()
}

fn status_auditrs() -> Result<()> {
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

fn handle_dump(_matches: &ArgMatches) -> Result<()> {
    println!("Dump, WIP");
    Ok(())
}

fn handle_search(_matches: &ArgMatches) -> Result<()> {
    println!("Search, WIP");
    Ok(())
}

fn handle_report(_matches: &ArgMatches) -> Result<()> {
    println!("Report, WIP");
    Ok(())
}

fn handle_config(_matches: &ArgMatches) -> Result<()> {
    println!("Config, WIP");
    Ok(())
}
