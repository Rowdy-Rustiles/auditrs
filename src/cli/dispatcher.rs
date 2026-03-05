use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::config::{
    add_filter_interactive, get_config, get_filters, import_filters, remove_filter_interactive,
    set_config, update_filter_interactive, GetConfigVariables, LogFormat, SetConfigVariables, State,
};
use crate::daemon::daemon::{is_running, start_daemon, stop_daemon};

/// Top-level entry point for handling CLI subcommands
pub fn dispatch(matches: &ArgMatches) -> Result<()> {
    let state = State::load_state()?;
    match matches.subcommand() {
        Some(("start", _)) => start_auditrs()?,
        Some(("stop", _)) => stop_auditrs()?,
        Some(("reboot", _)) => reboot_auditrs()?,
        Some(("status", _)) => status_auditrs()?,
        Some(("dump", sub_m)) => handle_dump(sub_m)?,
        Some(("search", sub_m)) => handle_search(sub_m)?,
        Some(("report", sub_m)) => handle_report(sub_m)?,
        Some(("config", sub_m)) => handle_config(sub_m)?,
        Some(("filter", sub_m)) => handle_filter(sub_m, &state)?,
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
                _ => None,
            };
            get_config(key).map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("set", set_m)) => handle_config_set(set_m),
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
            set_config(SetConfigVariables::LogSize { value }).map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("format", m)) => {
            set_config(SetConfigVariables::LogFormat)
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        _ => Ok(()),
    }
}

fn handle_filter(matches: &ArgMatches, state: &State) -> Result<()> {
    match matches.subcommand() {
        Some(("get", _sub_m)) => get_filters(state),
        Some(("add", _sub_m)) => add_filter_interactive(state),
        Some(("update", _sub_m)) => update_filter_interactive(state),
        Some(("remove", _sub_m)) => remove_filter_interactive(state),
        Some(("import", sub_m)) => {
            let file = sub_m
                .get_one::<String>("file")
                .context("missing file argument")?;
            import_filters(file)
        }
        _ => unreachable!("cli implementation should prevent this"),
    }
}
