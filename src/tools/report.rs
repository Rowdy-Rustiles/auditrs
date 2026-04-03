//! `auditrs` rewrite of the `aureport` utility.
//!
//! This module is intended to generate higher-level reports and summaries from
//! audit logs (e.g. per-user activity, rule hit counts, or anomaly snapshots),
//! complementing the lower-level `search` capabilities.

use std::{
    collections::HashMap,
    fs::{OpenOptions, create_dir_all},
    io::{self, Write},
    path::PathBuf,
    str::FromStr,
    time::SystemTime,
};

use anyhow::Result;
use clap::ArgMatches;

use crate::{
    config::LogFormat,
    core::{correlator::AuditEvent, writer::AuditLogWriter},
    state::State,
    tools::SummaryDisposition,
    utils::{
        current_utc_string,
        parse_rfc3339_timestamp,
        read_from_json,
        read_from_legacy,
        read_from_simple,
        systemtime_to_utc_string,
    },
};

/// Prints a debug dump of primary-log events for the configured log format.
pub fn generate_report(state: &State, matches: &ArgMatches) -> Result<()> {
    let primary_directory = PathBuf::from(&state.config.primary_directory);

    // We read the primary logs into a vector of `AuditEvent`s so that
    // they can be easily iterated over and aggregated for summary collections
    // and statistics.
    let mut events = match state.config.log_format {
        LogFormat::Legacy => read_from_legacy(&primary_directory),
        LogFormat::Simple => read_from_simple(&primary_directory),
        LogFormat::Json => read_from_json(&primary_directory),
    };

    events = apply_time_window(&matches, events)?;
    let summary = build_summary_disposition(&matches, &events);

    // Extra conversion as a validation check, format value should be validated by
    // the CLI parser.
    let output_format = if let Some(output_format) = matches.get_one::<String>("format") {
        LogFormat::from_str(output_format)?
    } else {
        state.config.log_format
    };

    let no_save = matches.get_flag("no_save");

    if no_save {
        print_report(&events, output_format, &summary)?;
    } else if let Some(output_path) = matches.get_one::<String>("output_path") {
        output_report(&events, PathBuf::from(output_path), output_format, &summary)?;
    } else {
        output_report(
            &events,
            default_report_path(output_format),
            output_format,
            &summary,
        )?;
    }

    Ok(())
}

fn default_report_path(format: LogFormat) -> PathBuf {
    let ts = current_utc_string().replace(':', "-");
    PathBuf::from(format!(
        "./reports/report_{}.{}",
        ts,
        format.get_extension()
    ))
}

fn apply_time_window(matches: &ArgMatches, mut events: Vec<AuditEvent>) -> Result<Vec<AuditEvent>> {
    let since = if let Some(since) = matches.get_one::<String>("since") {
        parse_rfc3339_timestamp(since)
            .map_err(|e| anyhow::anyhow!("Invalid since timestamp: {}", e))?
    } else {
        SystemTime::UNIX_EPOCH
    };

    let until = if let Some(until) = matches.get_one::<String>("until") {
        parse_rfc3339_timestamp(until)
            .map_err(|e| anyhow::anyhow!("Invalid until timestamp: {}", e))?
    } else {
        SystemTime::now()
    };

    events.retain(|event| event.timestamp >= since && event.timestamp < until);
    Ok(events)
}

fn format_summary_text(
    event_count: usize,
    earliest: Option<SystemTime>,
    latest: Option<SystemTime>,
    record_type_counts: &HashMap<String, u32>,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push("summary:".to_string());
    lines.push(format!("  event_count: {event_count}"));
    lines.push(format!(
        "  earliest_event_timestamp: {}",
        earliest
            .map(systemtime_to_utc_string)
            .unwrap_or_else(|| "(none)".to_string())
    ));
    lines.push(format!(
        "  latest_event_timestamp: {}",
        latest
            .map(systemtime_to_utc_string)
            .unwrap_or_else(|| "(none)".to_string())
    ));
    lines.push("  record_type_counts:".to_string());

    let mut keys: Vec<&String> = record_type_counts.keys().collect();
    keys.sort();
    for k in keys {
        lines.push(format!("    {}: {}", k, record_type_counts[k]));
    }

    lines.join("\n") + "\n"
}

fn build_summary_disposition(matches: &ArgMatches, events: &[AuditEvent]) -> SummaryDisposition {
    let summary_type = matches
        .get_one::<String>("summary")
        .map(|s| s.as_str())
        .unwrap_or("combine");

    if summary_type == "exclude" {
        return SummaryDisposition::Exclude;
    }

    let mut record_type_counts = HashMap::<String, u32>::new();
    for event in events {
        for record in &event.records {
            *record_type_counts
                .entry(record.record_type.as_audit_str().to_string())
                .or_insert(0) += 1;
        }
    }

    let earliest = events.iter().map(|event| event.timestamp).min();
    let latest = events.iter().map(|event| event.timestamp).max();

    let text = format_summary_text(events.len(), earliest, latest, &record_type_counts);

    match summary_type {
        "separate" => SummaryDisposition::Separate(text),
        _ => SummaryDisposition::Combine(text),
    }
}

fn write_report_body<W: Write>(w: &mut W, events: &[AuditEvent], format: LogFormat) -> Result<()> {
    match format {
        LogFormat::Legacy => AuditLogWriter::write_events_legacy(w, events)?,
        LogFormat::Simple => AuditLogWriter::write_events_simple(w, events)?,
        LogFormat::Json => {
            let body = serde_json::to_string_pretty(events)?;
            write!(w, "{body}\n")?;
        }
    }
    Ok(())
}

fn print_report(
    events: &[AuditEvent],
    format: LogFormat,
    summary: &SummaryDisposition,
) -> Result<()> {
    let mut out = io::stdout().lock();
    match summary {
        SummaryDisposition::Exclude => {}
        SummaryDisposition::Combine(text) | SummaryDisposition::Separate(text) => {
            write!(out, "{text}\n")?;
        }
    }
    write_report_body(&mut out, events, format)?;
    Ok(())
}

fn output_report(
    events: &[AuditEvent],
    mut output_path: PathBuf,
    format: LogFormat,
    summary: &SummaryDisposition,
) -> Result<()> {
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            create_dir_all(parent)?;
        }
    }

    output_path.set_extension(format.get_extension());

    if let SummaryDisposition::Separate(text) = summary {
        let mut summary_path = output_path.clone();
        summary_path.set_extension("summary");
        let mut summary_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&summary_path)?;
        write!(summary_file, "{text}")?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .append(true)
        .truncate(false)
        .open(&output_path)?;

    if let SummaryDisposition::Combine(text) = summary {
        write!(file, "{text}\n")?;
    }

    write_report_body(&mut file, events, format)?;
    Ok(())
}
