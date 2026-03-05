use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::config::{
    add_filter_interactive, get_config, get_filters, remove_filter, remove_filter_interactive,
    set_config, update_filter_interactive, GetConfigVariables, LogFormat, SetConfigVariables,
};
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

fn handle_config(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("get", get_m)) => {
            let key = match get_m.subcommand_name() {
                Some("directory") => Some(GetConfigVariables::OutputDirectory),
                Some("size") => Some(GetConfigVariables::LogSize),
                Some("format") => Some(GetConfigVariables::LogFormat),
                Some("filters") => Some(GetConfigVariables::LogFilters),
                _ => None,
            };
            get_config(key).map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("set", set_m)) => handle_config_set(set_m),
        Some(("filter", filter_m)) => handle_config_filter(filter_m),
        _ => Ok(()),
    }
}

fn handle_config_set(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("directory", m)) => {
            let value = m
                .get_one::<String>("value")
                .context("missing value")?
                .clone();
            set_config(SetConfigVariables::OutputDirectory { value })
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("size", m)) => {
            let value = m
                .get_one::<String>("value")
                .context("missing value")?
                .parse()
                .context("size must be a number")?;
            set_config(SetConfigVariables::LogSize { value })
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("format", m)) => {
            let s = m.get_one::<String>("value").context("missing value")?;
            let value = s
                .parse()
                .map_err(|e: String| anyhow::anyhow!("format must be legacy, simple, or json: {}", e))?;
            set_config(SetConfigVariables::LogFormat { value })
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        _ => Ok(()),
    }
}

/// TODO: should it be `auditrs filter` or `auditrs config filter`? im starting to lean towards the former
fn handle_config_filter(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("get", _)) => {
            get_filters()
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("add", _)) => {
            add_filter_interactive().map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("update", _)) => {
            update_filter_interactive().map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("remove", m)) => {
            match m.get_one::<String>("value") {
                Some(record_type) => remove_filter(record_type.clone()),
                None => remove_filter_interactive(),
            }
            .map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("import", _)) => {
            println!("Import filters, WIP");
            Ok(())
        }
        _ => Ok(()),
    }
}
