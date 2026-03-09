use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::config::{
    GetConfigVariables, LogFormat, SetConfigVariables, State, add_filter_interactive, dump_filters,
    get_config, get_filters, import_filters, remove_filter_interactive, set_config,
    update_filter_interactive,
};
use crate::daemon::control::{
    reboot_auditrs, reload_auditrs, start_auditrs, status_auditrs, stop_auditrs,
};

/// Top-level entry point for handling CLI subcommands
pub fn dispatch(matches: &ArgMatches) -> Result<()> {
    let state = State::load_state()?;
    match matches.subcommand() {
        Some(("start", _)) => start_auditrs(false)?,
        Some(("stop", _)) => stop_auditrs(false)?,
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

/// Tools subcommands, to be moved to /tools when written

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
                Some("format") => Some(GetConfigVariables::LogFormat),
                Some("log-directory") => Some(GetConfigVariables::LogDirectory),
                Some("journal-directory") => Some(GetConfigVariables::JournalDirectory),
                Some("archive-directory") => Some(GetConfigVariables::ArchiveDirectory),
                Some("log-size") => Some(GetConfigVariables::LogSize),
                Some("journal-size") => Some(GetConfigVariables::JournalSize),
                Some("archive-size") => Some(GetConfigVariables::ArchiveSize),
                Some("archive-active") => Some(GetConfigVariables::ArchiveActive),
                _ => None,
            };
            get_config(key).map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("set", set_m)) => handle_config_set(set_m),
        _ => Ok(()),
    }
}

fn handle_config_set(matches: &ArgMatches) -> Result<()> {
    let result = match matches.subcommand() {
        Some(("format", _m)) => {
            set_config(SetConfigVariables::LogFormat).map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("log-directory", m)) => {
            let value = m
                .get_one::<String>("value")
                .context("missing value")?
                .clone();
            set_config(SetConfigVariables::LogDirectory { value })
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("journal-directory", m)) => {
            let value = m
                .get_one::<String>("value")
                .context("missing value")?
                .clone();
            set_config(SetConfigVariables::JournalDirectory { value })
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("archive-directory", m)) => {
            let value = m
                .get_one::<String>("value")
                .context("missing value")?
                .clone();
            set_config(SetConfigVariables::ArchiveDirectory { value })
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("log-size", _m)) => {
            set_config(SetConfigVariables::LogSize).map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("journal-size", _m)) => {
            set_config(SetConfigVariables::JournalSize).map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("archive-size", _m)) => {
            set_config(SetConfigVariables::ArchiveSize).map_err(|e| anyhow::anyhow!("{}", e))
        }
        Some(("archive-active", _m)) => {
            set_config(SetConfigVariables::ArchiveActive).map_err(|e| anyhow::anyhow!("{}", e))
        }
        _ => Ok(()),
    };

    // Reboot the daemon if the config was changed
    if result.is_ok() {
        reload_auditrs()?;
    }

    result
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
        Some(("dump", sub_m)) => {
            let file = sub_m
                .get_one::<String>("file")
                .context("missing file argument")?;
            dump_filters(file, state)
        }
        _ => unreachable!("cli implementation should prevent this"),
    }
}
