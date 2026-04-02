//! `auditrs` rewrite of the `aureport` utility.
//!
//! This module is intended to generate higher-level reports and summaries from
//! audit logs (e.g. per-user activity, rule hit counts, or anomaly snapshots),
//! complementing the lower-level `search` capabilities.

use std::path::PathBuf;

use anyhow::Result;
use clap::ArgMatches;

use crate::{
    config::LogFormat,
    state::State,
    utils::{read_from_json, read_from_legacy, read_from_simple},
};

pub fn generate_report(state: &State, matches: &ArgMatches) -> Result<()> {
    let primary_directory = PathBuf::from(&state.config.primary_directory);
    let events = match state.config.log_format {
        LogFormat::Legacy => read_from_legacy(state),
        LogFormat::Simple => read_from_simple(state),
        LogFormat::Json => read_from_json(&primary_directory),
    };

    println!("{:?}", events);
    Ok(())
}
