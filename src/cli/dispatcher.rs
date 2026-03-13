//! CLI dispatcher module for routing subcommands to their respective handlers.
//!
//! This module contains the top-level `dispatch` function that matches CLI
//! subcommands and delegates to handler functions.

use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::config::*;
use crate::daemon::control::{
    reboot_auditrs, reload_auditrs, start_auditrs, status_auditrs, stop_auditrs,
};
use crate::rules::*;
use crate::state::*;

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
        Some(("watch", sub_m)) => handle_watch(sub_m, &state)?,
        None => {
            unreachable!("cli implementation should prevent this");
        }
        _ => unreachable!("cli implementation should prevent this"),
    }

    Ok(())
}

/// Tools subcommands, to be moved to /tools when written

fn handle_dump(_matches: &ArgMatches) -> Result<()> {
    todo!()
}

fn handle_search(_matches: &ArgMatches) -> Result<()> {
    todo!()
}

fn handle_report(_matches: &ArgMatches) -> Result<()> {
    todo!()
}

fn handle_config(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("get", get_m)) => {
            let key = match get_m.subcommand_name() {
                Some("format") => Some(GetConfigVariables::LogFormat),
                Some("log-directory") => Some(GetConfigVariables::LogDirectory),
                Some("journal-directory") => Some(GetConfigVariables::JournalDirectory),
                Some("primary-directory") => Some(GetConfigVariables::PrimaryDirectory),
                Some("log-size") => Some(GetConfigVariables::LogSize),
                Some("journal-size") => Some(GetConfigVariables::JournalSize),
                Some("primary-size") => Some(GetConfigVariables::PrimarySize),
                _ => None,
            };
            get_config(key)
        }
        Some(("set", set_m)) => handle_config_set(set_m),
        _ => Ok(()),
    }
}

fn handle_config_set(matches: &ArgMatches) -> Result<()> {
    let result = match matches.subcommand() {
        Some(("format", _m)) => set_config(SetConfigVariables::LogFormat),
        Some(("log-directory", m)) => {
            let value = m
                .get_one::<String>("value")
                .context("missing value")?
                .clone();
            set_config(SetConfigVariables::LogDirectory { value })
        }
        Some(("journal-directory", m)) => {
            let value = m
                .get_one::<String>("value")
                .context("missing value")?
                .clone();
            set_config(SetConfigVariables::JournalDirectory { value })
        }
        Some(("primary-directory", m)) => {
            let value = m
                .get_one::<String>("value")
                .context("missing value")?
                .clone();
            set_config(SetConfigVariables::PrimaryDirectory { value })
        }
        Some(("log-size", _m)) => set_config(SetConfigVariables::LogSize),
        Some(("journal-size", _m)) => set_config(SetConfigVariables::JournalSize),
        Some(("primary-size", _m)) => set_config(SetConfigVariables::PrimarySize),
        _ => Ok(()),
    }
    .context("Could not set config");

    // Reboot the daemon if the config was changed
    if result.is_ok() {
        reload_auditrs()?;
    }

    result
}

fn handle_filter(matches: &ArgMatches, state: &State) -> Result<()> {
    match matches.subcommand() {
        Some(("get", _sub_m)) => get_filters(state),
        Some(("add", _sub_m)) => {
            let result = add_filter_interactive(state);
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
        }
        Some(("update", _sub_m)) => {
            let result = update_filter_interactive(state);
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
        }
        Some(("remove", _sub_m)) => {
            let result = remove_filter_interactive(state);
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
        }
        Some(("import", sub_m)) => {
            let file = sub_m
                .get_one::<String>("file")
                .context("missing file argument")?;
            let result = import_filters(file);
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
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

fn handle_watch(matches: &ArgMatches, state: &State) -> Result<()> {
    match matches.subcommand() {
        Some(("get", _sub_m)) => get_watches(state),
        Some(("add", _sub_m)) => {
            let result = add_watch_interactive();
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
        }
        Some(("update", _sub_m)) => {
            let result = update_watch_interactive(state);
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
        }
        Some(("remove", _sub_m)) => {
            let result = remove_watch_interactive(state);
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
        }
        Some(("import", sub_m)) => {
            let file = sub_m
                .get_one::<String>("file")
                .context("missing file argument")?;
            let result = import_watches(file);
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
        }
        Some(("dump", sub_m)) => {
            let file = sub_m
                .get_one::<String>("file")
                .context("missing file argument")?;
            dump_watches(file, state)
        }
        _ => unreachable!("cli implementation should prevent this"),
    }
}
