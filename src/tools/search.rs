//! `auditrs` rewrite of the `ausearch` utility.
//!
//! Searches correlated audit events in the primary log directory with optional
//! filters (time range, field, event category, user, syscall outcome) and
//! prints matches as a table or JSON.

use std::borrow::Cow;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::Result;
use clap::ArgMatches;

use crate::config::LogFormat;
use crate::core::correlator::AuditEvent;
use crate::core::parser::ParsedAuditRecord;
use crate::core::parser::RecordType;
use crate::state::State;
use crate::utils::{
    parse_rfc3339_timestamp,
    read_from_json,
    read_from_legacy,
    read_from_simple,
    systemtime_to_utc_string,
};

/// Runs a search over primary audit logs using CLI filters and the query
/// expression.
///
/// **Parameters:**
///
/// * `state`: Loaded daemon state (paths and default log format).
/// * `matches`: Parsed `search` subcommand arguments.
pub fn search_events(state: &State, matches: &ArgMatches) -> Result<()> {
    let primary_directory = PathBuf::from(&state.config.primary_directory);

    let mut events = match state.config.log_format {
        LogFormat::Legacy => read_from_legacy(&primary_directory),
        LogFormat::Simple => read_from_simple(&primary_directory),
        LogFormat::Json => read_from_json(&primary_directory),
    };

    events = apply_time_window(matches, events)?;
    events.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.serial.cmp(&b.serial))
    });

    let query_arg = matches
        .get_one::<String>("query")
        .map(|s| s.as_str().trim())
        .filter(|s| !s.is_empty());

    let (field_name, field_value_from_flag) =
        parse_field_flag(matches.get_one::<String>("field").map(|s| s.as_str()));

    // `--field exe=/bin/ls` supplies both the field key and the search needle when
    // QUERY is omitted.
    let effective_query: Cow<'_, str> = match (query_arg, field_value_from_flag) {
        (Some(q), _) => Cow::Borrowed(q),
        (None, Some(v)) => Cow::Borrowed(v),
        (None, None) => Cow::Borrowed(""),
    };
    let type_filter = matches.get_one::<String>("type").map(|s| s.as_str());
    let user_filter = matches.get_one::<String>("user").map(|s| s.as_str());
    let result_filter = matches.get_one::<String>("result").map(|s| s.as_str());

    if let Some(u) = user_filter {
        validate_user_filter_arg(u)?;
    }

    let limit = match matches.get_one::<String>("limit") {
        Some(s) => {
            Some(
                s.parse::<usize>()
                    .map_err(|_| anyhow::anyhow!("Invalid --limit value: {:?}", s))?,
            )
        }
        None => None,
    };

    let output_format = matches
        .get_one::<String>("format")
        .map(|s| s.as_str())
        .unwrap_or("simple");

    let mut matched: Vec<AuditEvent> = Vec::new();
    for event in events {
        if let Some(ty) = type_filter
            && !event_matches_type(&event, ty)
        {
            continue;
        }
        if let Some(u) = user_filter
            && !event_matches_user(&event, u)
        {
            continue;
        }
        if let Some(r) = result_filter
            && !event_matches_result(&event, r)
        {
            continue;
        }
        if !event_matches_query(&event, effective_query.as_ref(), field_name) {
            continue;
        }
        matched.push(event);
        if let Some(max) = limit
            && matched.len() >= max
        {
            break;
        }
    }

    match output_format {
        "json" => print_json(&matched)?,
        "simple" => print_simple(&matched)?,
        other => anyhow::bail!("Unsupported output format: {:?}", other),
    }

    Ok(())
}

/// Splits `--field` into a key name and an optional `value` when written as
/// `name=value`. The audit field name is only ever the part before the first
/// `=`.
fn parse_field_flag(field: Option<&str>) -> (Option<&str>, Option<&str>) {
    let Some(raw) = field.map(str::trim).filter(|s| !s.is_empty()) else {
        return (None, None);
    };
    if let Some((k, v)) = raw.split_once('=') {
        let k = k.trim();
        let v = v.trim();
        if k.is_empty() {
            return (None, None);
        }
        return (Some(k), if v.is_empty() { None } else { Some(v) });
    }
    (Some(raw), None)
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

fn event_matches_type(event: &AuditEvent, ty: &str) -> bool {
    let t = ty.trim();
    if t.is_empty() {
        return true;
    }
    if record_type_category_matches(event, t) {
        return true;
    }
    event
        .records
        .iter()
        .any(|r| record_type_matches_cli_label(r, t))
}

/// Matches either the auditd-style name (`CONFIG_CHANGE`) or the same form used
/// in simple-log output (`ConfigChange` from `{:?}`).
fn record_type_matches_cli_label(record: &ParsedAuditRecord, t: &str) -> bool {
    record.record_type.as_audit_str().eq_ignore_ascii_case(t)
        || format!("{:?}", record.record_type).eq_ignore_ascii_case(t)
}

fn record_type_category_matches(event: &AuditEvent, cat: &str) -> bool {
    match cat.to_ascii_lowercase().as_str() {
        "exec" => {
            event.records.iter().any(|r| {
                matches!(
                    r.record_type,
                    RecordType::Syscall
                        | RecordType::Execve
                        | RecordType::BprmFcaps
                        | RecordType::Proctitle
                        | RecordType::Eoe
                        | RecordType::Capset
                )
            })
        }
        "file" => {
            event.records.iter().any(|r| {
                matches!(
                    r.record_type,
                    RecordType::Path
                        | RecordType::Cwd
                        | RecordType::Openat2
                        | RecordType::Mmap
                        | RecordType::Fanotify
                        | RecordType::FdPair
                )
            })
        }
        "auth" => {
            event.records.iter().any(|r| {
                matches!(
                    r.record_type,
                    RecordType::UserLogin
                        | RecordType::UserLogout
                        | RecordType::CredAcq
                        | RecordType::CredDisp
                        | RecordType::UserStart
                        | RecordType::UserEnd
                        | RecordType::GrpAuth
                        | RecordType::UserChauthtok
                        | RecordType::UserMgmt
                        | RecordType::AcctLock
                        | RecordType::AcctUnlock
                        | RecordType::Login
                )
            })
        }
        _ => false,
    }
}

const USER_FIELD_KEYS: &[&str] = &[
    "uid", "auid", "euid", "gid", "egid", "ouid", "fsuid", "loginuid", "suid", "ses",
];

fn is_user_identity_field(name: &str) -> bool {
    USER_FIELD_KEYS
        .iter()
        .any(|k| k.eq_ignore_ascii_case(name.trim()))
}

/// Rejects `--user key=value` when `key` is not an identity field (same set as
/// [`USER_FIELD_KEYS`]).
fn validate_user_filter_arg(raw: &str) -> Result<()> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(());
    }
    if let Some((k, _)) = raw.split_once('=') {
        let k = k.trim();
        if !k.is_empty() && !is_user_identity_field(k) {
            anyhow::bail!(
                "--user field must be one of: {}",
                USER_FIELD_KEYS.join(", ")
            );
        }
    }
    Ok(())
}

fn event_matches_user(event: &AuditEvent, user: &str) -> bool {
    let raw = user.trim();
    if raw.is_empty() {
        return true;
    }

    if let Some((k, v)) = raw.split_once('=') {
        let key = k.trim();
        let val = v.trim();
        if !key.is_empty() && is_user_identity_field(key) {
            if val.is_empty() {
                return event_has_field_key(event, key);
            }
            return user_key_value_matches(event, key, val);
        }
    }

    user_matches_any_identity_field(event, raw)
}

/// `key=value`: match substring in that field only (same rules as `--field`
/// key=value).
fn user_key_value_matches(event: &AuditEvent, key: &str, val: &str) -> bool {
    for record in &event.records {
        for (fk, fv) in &record.fields {
            if fk.eq_ignore_ascii_case(key) && (fv == val || fv.contains(val)) {
                return true;
            }
        }
    }
    false
}

/// Plain text: match if any identity field value equals or contains `needle`.
fn user_matches_any_identity_field(event: &AuditEvent, needle: &str) -> bool {
    for record in &event.records {
        for (fk, fv) in &record.fields {
            if USER_FIELD_KEYS
                .iter()
                .any(|uk| uk.eq_ignore_ascii_case(fk.as_str()))
                && (fv == needle || fv.contains(needle))
            {
                return true;
            }
        }
    }
    false
}

fn event_matches_result(event: &AuditEvent, want: &str) -> bool {
    for record in &event.records {
        if let Some(s) = record.fields.get("success") {
            let ok = match want {
                "success" => {
                    s.eq_ignore_ascii_case("yes") || s.eq_ignore_ascii_case("true") || *s == "1"
                }
                "failed" => {
                    s.eq_ignore_ascii_case("no") || s.eq_ignore_ascii_case("false") || *s == "0"
                }
                _ => return true,
            };
            if ok {
                return true;
            }
        }
    }
    false
}

fn event_matches_query(event: &AuditEvent, query: &str, restrict_field: Option<&str>) -> bool {
    let q = query.trim();
    if q.is_empty() {
        // `--field exe` with no query: only events that mention this field on some
        // record.
        return if let Some(f) = restrict_field {
            event_has_field_key(event, f)
        } else {
            true
        };
    }

    if let Some((k, v)) = q.split_once('=') {
        let key = k.trim();
        let val = v.trim();
        if !key.is_empty() {
            return key_value_matches(event, key, val, restrict_field);
        }
    }

    free_text_matches(event, q, restrict_field)
}

fn event_has_field_key(event: &AuditEvent, field: &str) -> bool {
    event
        .records
        .iter()
        .any(|r| r.fields.keys().any(|k| k.eq_ignore_ascii_case(field)))
}

fn key_value_matches(
    event: &AuditEvent,
    key: &str,
    val: &str,
    restrict_field: Option<&str>,
) -> bool {
    for record in &event.records {
        if let Some(f) = restrict_field
            && !key.eq_ignore_ascii_case(f)
        {
            continue;
        }
        for (fk, fv) in &record.fields {
            if fk.eq_ignore_ascii_case(key) && fv.contains(val) {
                return true;
            }
        }
    }
    false
}

fn free_text_matches(event: &AuditEvent, needle: &str, restrict_field: Option<&str>) -> bool {
    let needle_lower = needle.to_lowercase();
    for record in &event.records {
        if restrict_field.is_none() {
            let audit = record.record_type.as_audit_str();
            let rust = format!("{:?}", record.record_type);
            if audit.to_lowercase().contains(&needle_lower)
                || rust.to_lowercase().contains(&needle_lower)
            {
                return true;
            }
        }
        for (k, v) in &record.fields {
            if let Some(f) = restrict_field
                && !k.eq_ignore_ascii_case(f)
            {
                continue;
            }
            if v.to_lowercase().contains(&needle_lower) {
                return true;
            }
        }
    }
    false
}

fn print_simple(events: &[AuditEvent]) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "Found {} events \n", events.len())?;
    for event in events {
        write!(out, "{event}")?;
    }
    Ok(())
}

fn print_json(events: &[AuditEvent]) -> Result<()> {
    let mut out = io::stdout().lock();
    // Use the same record-type spelling as simple-format logs (`record_type:
    // ConfigChange` from `Debug`), not serde's SCREAMING_SNAKE_CASE or kernel
    // `as_audit_str()`.
    let payload: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "timestamp": systemtime_to_utc_string(e.timestamp),
                "serial": e.serial,
                "record_count": e.record_count,
                "records": e.records.iter().map(|r| {
                    serde_json::json!({
                        "record_type": format!("{:?}", r.record_type),
                        "timestamp": systemtime_to_utc_string(r.timestamp),
                        "serial": r.serial,
                        "fields": r.fields,
                    })
                }).collect::<Vec<_>>()
            })
        })
        .collect();
    let body = serde_json::to_string_pretty(&payload)?;
    writeln!(out, "Found {} events \n", events.len())?;
    writeln!(out, "{body}")?;
    Ok(())
}
