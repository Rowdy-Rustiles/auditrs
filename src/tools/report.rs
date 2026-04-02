//! `auditrs` rewrite of the `aureport` utility.
//!
//! This module is intended to generate higher-level reports and summaries from
//! audit logs (e.g. per-user activity, rule hit counts, or anomaly snapshots),
//! complementing the lower-level `search` capabilities.

use std::{fs::create_dir_all, path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::ArgMatches;

use crate::{
    config::LogFormat,
    core::{correlator::AuditEvent, writer::AuditLogWriter},
    state::State,
    utils::{read_from_json, read_from_legacy, read_from_simple},
};

/// Prints a debug dump of primary-log events for the configured log format.
pub fn generate_report(state: &State, matches: &ArgMatches) -> Result<()> {
    let primary_directory = PathBuf::from(&state.config.primary_directory);

    // We read the primary logs into a vector of `AuditEvent`s so that
    // they can be easily iterated over and aggregated for summary collections
    // and statistics.
    let events = match state.config.log_format {
        LogFormat::Legacy => read_from_legacy(&primary_directory),
        LogFormat::Simple => read_from_simple(&primary_directory),
        LogFormat::Json => read_from_json(&primary_directory),
    };

    // Extra conversion as a validation check, format value should be validated by
    // the CLI parser.
    let output_format = if let Some(output_format) = matches.get_one::<String>("format") {
        LogFormat::from_str(output_format)?
    } else {
        state.config.log_format
    };

    if let Some(output_path) = matches.get_one::<String>("output_path") {
        output_report(&events, PathBuf::from(output_path), output_format)?;
    }

    println!("{:?}", events);
    Ok(())
}

fn output_report(events: &[AuditEvent], mut output_path: PathBuf, format: LogFormat) -> Result<()> {
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            create_dir_all(parent)?;
        }
    }

    output_path.set_extension(format.get_extension());

    // might have overcomplicated the auditlogwriter for this as we are now coupling
    // it with functionality only used by reports (as of now). might want to change
    // this later?
    match format {
        LogFormat::Legacy => AuditLogWriter::write_events_legacy(&output_path, events)?,
        LogFormat::Simple => AuditLogWriter::write_events_simple(&output_path, events)?,
        LogFormat::Json => AuditLogWriter::write_events_json(&output_path, events)?,
    }
    Ok(())
}
