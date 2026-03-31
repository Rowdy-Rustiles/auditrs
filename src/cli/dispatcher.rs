//! CLI dispatcher module for routing subcommands to their respective handlers.
//!
//! This module contains the top-level `dispatch` function that matches CLI
//! subcommands and delegates to handler functions.

// TODO: There a couple of different function dispatch patterns (my bad) used
// within the dispatch/handle functions. We should aim to eventually unify these
// patterns into a consistent dispatch scheme.

use anyhow::{Context, Result};
use clap::ArgMatches;
use std::str::FromStr;

use crate::config::{GetConfigVariables, SetConfigVariables, get_config, set_config};
use crate::daemon::control::{
    reboot_auditrs,
    reload_auditrs,
    start_auditrs,
    status_auditrs,
    stop_auditrs,
};
use crate::rules::{
    add_filter,
    add_filter_interactive,
    add_watch,
    add_watch_interactive,
    dump_filters,
    dump_watches,
    get_filters,
    get_watches,
    import_filters,
    import_watches,
    remove_filter_by_record_type,
    remove_watch_by_key,
    remove_filter_interactive,
    remove_watch_interactive,
    update_filter,
    update_watch_by_key,
    update_filter_interactive,
    update_watch_interactive,
};
use crate::state::State;

/// Top-level entry point for handling CLI subcommands
///
/// **Parameters:**
///
/// * `matches`: CLI argument to match a handling function to
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

/// Dumps the contents of a selected auditrs log to a specified path.
///
/// **Parameters:**
///
/// * `matches`: CLI argument to match a handling function. Subcommands and
///   flags of the argument can be used for further options.
fn handle_dump(_matches: &ArgMatches) -> Result<()> {
    todo!()
}

/// Searches auditrs logs for a supplied term or pattern.
///
/// **Parameters:**
///
/// * `matches`: CLI argument to match a handling function. Subcommands and
///   flags of the argument can be used for further options
fn handle_search(_matches: &ArgMatches) -> Result<()> {
    todo!()
}

/// Generates a report on the audit logs with statistical analysis of their
/// contents
///
/// **Parameters:**
///
/// * `matches`: CLI argument to match a handling function. Subcommands and
///   flags of the argument can be used for further options
fn handle_report(_matches: &ArgMatches) -> Result<()> {
    todo!()
}

/// Dispatch of config handling commands. Config getters are directly addressed
/// in this function. Config setters are further propagated to the
/// `handle_config_set()` function.
///
/// **Parameters:**
///
/// * `matches`: CLI argument for getting/settings.
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

/// Prepares the proper function call to `set_config()` based on the supplied
/// CLI arguments.
///
/// **Parameters:**
///
/// * `matches`: CLI argument for the config option being set.
fn handle_config_set(matches: &ArgMatches) -> Result<()> {
    let result = match matches.subcommand() {
        Some(("format", m)) => {
            let value = m.get_one::<String>("value").cloned();
            set_config(SetConfigVariables::LogFormat { value })
        }
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

/// Dispatch of filter commands to their respective handler functions.
/// Dynamically reloads the auditrs daemon if necessary.
///
/// **Parameters:**
///
/// * `matches`: CLI argument to match a handling function. Subcommands and
///   flags of the argument can be used for further options
fn handle_filter(matches: &ArgMatches, state: &State) -> Result<()> {
    match matches.subcommand() {
        Some(("get", _sub_m)) => get_filters(state),
        Some(("add", sub_m)) => {
            let record_type = sub_m.get_one::<String>("record_type").cloned();
            let action = sub_m.get_one::<String>("action").cloned();

            let result = match (record_type, action) {
                (Some(rt), Some(a)) => add_filter(&rt, &a),
                (None, None) => add_filter_interactive(state),
                _ => Err(anyhow::anyhow!(
                    "non-interactive usage requires both --record-type and --action"
                )),
            };
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
        }
        Some(("update", sub_m)) => {
            let record_type = sub_m.get_one::<String>("record_type").cloned();
            let action = sub_m.get_one::<String>("action").cloned();

            let result = match (record_type, action) {
                (Some(rt), Some(a)) => update_filter(state, &rt, &a),
                (None, None) => update_filter_interactive(state),
                _ => Err(anyhow::anyhow!(
                    "non-interactive usage requires both --record-type and --action"
                )),
            };
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
        }
        Some(("remove", sub_m)) => {
            let value = sub_m.get_one::<String>("value").cloned();
            let result = match value {
                Some(record_type) => remove_filter_by_record_type(state, &record_type),
                None => remove_filter_interactive(state),
            };
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

/// Dispatch of watches commands to their respective handler functions.
/// Dynamically reloads the auditrs daemon if necessary.
///
/// **Parameters:**
///
/// * `matches`: CLI argument to match a handling function. Subcommands and
///   flags of the argument can be used for further options
fn handle_watch(matches: &ArgMatches, state: &State) -> Result<()> {
    match matches.subcommand() {
        Some(("get", _sub_m)) => get_watches(state),
        Some(("add", sub_m)) => {
            let path = sub_m.get_one::<String>("path").cloned();
            let actions = sub_m.get_many::<String>("action").map(|vals| {
                vals.map(|s| s.to_string()).collect::<Vec<String>>()
            });
            let recursive = sub_m.get_one::<bool>("recursive").copied().unwrap_or(false);

            let result = match (path, actions) {
                (Some(p), Some(a)) => {
                    let actions = a
                        .iter()
                        .map(|s| crate::rules::WatchAction::from_str(&s.to_lowercase())
                            .map_err(anyhow::Error::from))
                        .collect::<Result<Vec<_>>>()?;
                    add_watch(&p, actions, recursive)
                }
                (None, None) => add_watch_interactive(),
                _ => Err(anyhow::anyhow!(
                    "non-interactive usage requires PATH and at least one --action"
                )),
            };
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
        }
        Some(("update", sub_m)) => {
            let key = sub_m.get_one::<String>("key").cloned();
            let actions = sub_m.get_many::<String>("action").map(|vals| {
                vals.map(|s| s.to_string()).collect::<Vec<String>>()
            });
            let recursive = sub_m
                .get_one::<String>("recursive")
                .map(|s| s.eq_ignore_ascii_case("true"));

            let result = match (key, actions) {
                (Some(k), Some(a)) => {
                    let actions = a
                        .iter()
                        .map(|s| crate::rules::WatchAction::from_str(&s.to_lowercase())
                            .map_err(anyhow::Error::from))
                        .collect::<Result<Vec<_>>>()?;
                    update_watch_by_key(state, &k, actions, recursive)
                }
                (None, None) => update_watch_interactive(state),
                _ => Err(anyhow::anyhow!(
                    "non-interactive usage requires --key and at least one --action"
                )),
            };
            if result.is_ok() {
                reload_auditrs()?;
            }
            result
        }
        Some(("remove", sub_m)) => {
            let key = sub_m
                .get_one::<String>("key")
                .cloned()
                .or_else(|| sub_m.get_one::<String>("value").cloned());
            let result = match key {
                Some(k) => remove_watch_by_key(state, &k),
                None => remove_watch_interactive(state),
            };
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
