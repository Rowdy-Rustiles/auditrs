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

/// Loads primary logs, applies CLI filters and the query expression, and prints
/// matching events in simple or JSON format.
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

/// Parses the `--field` flag into a field name and optional value when the
/// argument uses `name=value` form; otherwise returns the whole string as the
/// field name.
///
/// **Parameters:**
///
/// * `field`: Raw `--field` value, or `None` if the flag was not passed.
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

/// Retains events whose timestamp falls in `[since, until)` from `--since` /
/// `--until` (RFC3339), defaulting to the full range when a bound is omitted.
///
/// **Parameters:**
///
/// * `matches`: Parsed `search` subcommand arguments.
/// * `events`: Events read from primary logs before filtering.
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

/// Returns whether the event satisfies `--type`: a category (`exec`, `file`,
/// `auth`), or any record whose type matches the given audit or Rust-style name.
///
/// **Parameters:**
///
/// * `event`: Event to test.
/// * `ty`: Value of `--type` (may be empty to match all).
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

/// Returns whether the CLI type string matches this record’s type (auditd-style
/// name such as `CONFIG_CHANGE`, or the Rust enum spelling such as `ConfigChange`).
///
/// **Parameters:**
///
/// * `record`: Parsed record whose `RecordType` is compared.
/// * `t`: Type filter string from the user.
fn record_type_matches_cli_label(record: &ParsedAuditRecord, t: &str) -> bool {
    record.record_type.as_audit_str().eq_ignore_ascii_case(t)
        || format!("{:?}", record.record_type).eq_ignore_ascii_case(t)
}

/// Returns whether `--type` names a built-in category and the event contains at
/// least one record in that category’s record-type set.
///
/// **Parameters:**
///
/// * `event`: Event to test.
/// * `cat`: Category name (`exec`, `file`, or `auth`; compared case-insensitively).
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

/// Audit field names used for `--user` filtering and `uid=…`-style user filters.
const USER_FIELD_KEYS: &[&str] = &[
    "uid", "auid", "euid", "gid", "egid", "ouid", "fsuid", "loginuid", "suid", "ses",
];

/// Returns whether `name` is one of the identity field keys (case-insensitive).
///
/// **Parameters:**
///
/// * `name`: Candidate field name, typically the left-hand side of `key=value`.
fn is_user_identity_field(name: &str) -> bool {
    USER_FIELD_KEYS
        .iter()
        .any(|k| k.eq_ignore_ascii_case(name.trim()))
}

/// Validates `--user` when it uses `key=value` form: the key must appear in
/// [`USER_FIELD_KEYS`].
///
/// **Parameters:**
///
/// * `raw`: Raw `--user` argument string.
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

/// Returns whether the event satisfies `--user`: plain text across identity
/// fields, or `key=value` / `key=` limited to [`USER_FIELD_KEYS`].
///
/// **Parameters:**
///
/// * `event`: Event to test.
/// * `user`: Raw `--user` argument (may include `uid=1000` form).
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

/// Returns whether any record has `key` matching `val` by equality or substring
/// (same idea as `key_value_matches` for `--field`, restricted to user keys).
///
/// **Parameters:**
///
/// * `event`: Event to test.
/// * `key`: Identity field name (e.g. `uid`).
/// * `val`: Needle matched against that field’s value.
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

/// Returns whether any [`USER_FIELD_KEYS`] value on the event equals or contains
/// `needle` (plain `--user` without `key=value`).
///
/// **Parameters:**
///
/// * `event`: Event to test.
/// * `needle`: Free-text user filter.
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

/// Returns whether the event satisfies `--result` by inspecting `success` on
/// records (typically SYSCALL).
///
/// **Parameters:**
///
/// * `event`: Event to test.
/// * `want`: Either `success` or `failed` from the CLI.
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

/// Returns whether the event matches the main search query: empty query with
/// optional `--field`-only semantics, `key=value`, or free text.
///
/// **Parameters:**
///
/// * `event`: Event to test.
/// * `query`: Effective query string (positional and/or `--field=…` value).
/// * `restrict_field`: Field name from `--field` when not using `field=value`, if any.
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

/// Returns whether any record in the event carries a field whose name matches
/// `field` (case-insensitive).
///
/// **Parameters:**
///
/// * `event`: Event to test.
/// * `field`: Audit field name.
fn event_has_field_key(event: &AuditEvent, field: &str) -> bool {
    event
        .records
        .iter()
        .any(|r| r.fields.keys().any(|k| k.eq_ignore_ascii_case(field)))
}

/// Returns whether `key=value` appears on the event, optionally requiring `key`
/// to match `--field` when only a field name was passed.
///
/// **Parameters:**
///
/// * `event`: Event to test.
/// * `key`: Left-hand side of the query’s `key=value` pair.
/// * `val`: Right-hand side substring matched in the field value.
/// * `restrict_field`: If set, `key` must match this field name.
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

/// Returns whether free-text `needle` appears in record types (when not
/// restricted) or in field values, optionally scoped to `--field`.
///
/// **Parameters:**
///
/// * `event`: Event to test.
/// * `needle`: Search string (case-insensitive for values and type names).
/// * `restrict_field`: If set, only this field’s values are searched.
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

/// Writes a short count line and each event using the simple (`Display`) format.
///
/// **Parameters:**
///
/// * `events`: Matched events to print to stdout.
fn print_simple(events: &[AuditEvent]) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "Found {} events \n", events.len())?;
    for event in events {
        write!(out, "{event}")?;
    }
    Ok(())
}

/// Writes a count line and a pretty-printed JSON array of events; record types
/// use the Rust enum spelling (`ConfigChange`) to align with simple logs.
///
/// **Parameters:**
///
/// * `events`: Matched events to serialize to stdout.
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
