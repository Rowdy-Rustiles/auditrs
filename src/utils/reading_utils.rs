use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use strum::IntoEnumIterator;

use crate::core::correlator::AuditEvent;
use crate::core::netlink::RawAuditRecord;
use crate::core::parser::{ParsedAuditRecord, RecordType};

/// Reads audit events from JSON files in the primary directory.
///
/// **Parameters:**
///
/// * `primary_directory`: The path to the primary directory.
pub fn read_from_json(primary_directory: &PathBuf) -> Vec<AuditEvent> {
    let files = fs::read_dir(primary_directory).unwrap();
    let mut events = Vec::new();
    for file in files {
        let file = file.unwrap();
        if file.path().extension().unwrap_or_default() != "json" {
            continue;
        }
        let content = fs::read_to_string(file.path()).unwrap();
        let event: Vec<AuditEvent> = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse JSON: {}", e))
            .unwrap();
        events.extend(event.into_iter());
    }
    events
}

/// Reads audit events from simple-format primary files (`.slog`).
///
/// Format matches [`std::fmt::Display`] on
/// [`AuditEvent`](crate::core::correlator::AuditEvent).
///
/// **Parameters:**
///
/// * `primary_directory`: The path to the primary directory.
pub fn read_from_simple(primary_directory: &PathBuf) -> Vec<AuditEvent> {
    let mut paths: Vec<_> = fs::read_dir(primary_directory)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "slog"))
        .collect();
    paths.sort();
    let mut events = Vec::new();
    for path in paths {
        let content = fs::read_to_string(&path).unwrap();
        match parse_simple_events(&content) {
            Ok(mut ev) => events.append(&mut ev),
            Err(e) => {
                eprintln!(
                    "warning: failed to parse simple log {}: {:?}",
                    path.display(),
                    e
                )
            }
        }
    }
    events
}

/// Reads audit events from legacy files in the primary directory.
///
/// Legacy lines are one record per line (`type=… msg=audit(…): …`). Grouping
/// from the live correlator is not stored, so records are reassembled into
/// [`AuditEvent`]s by matching `(timestamp, serial)` like the correlator does.
///
/// **Parameters:**
///
/// * `primary_directory`: The path to the primary directory.
pub fn read_from_legacy(primary_directory: &PathBuf) -> Vec<AuditEvent> {
    let mut all_records = Vec::new();
    let mut paths: Vec<_> = fs::read_dir(primary_directory)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "log"))
        .collect();
    paths.sort();
    for path in paths {
        let content = fs::read_to_string(&path).unwrap();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match parse_legacy_primary_line(line) {
                Ok(rec) => all_records.push(rec),
                Err(e) => eprintln!("warning: skip line in {}: {:?}", path.display(), e),
            }
        }
    }
    correlate_records(all_records)
}

/// Parses a legacy primary log line as written by the auditrs writer into a
/// [`ParsedAuditRecord`]: `type=RECORD_TYPE
/// msg=audit(<seconds>.<millis>:<serial>): key=value ...`
///
/// Strips the `type=` / `msg=` wrapper and delegates to
/// [`ParsedAuditRecord::try_from`] ([`RawAuditRecord`]), matching the netlink
/// path.
///
/// **Parameters:**
///
/// * `line`: The line to parse.
fn parse_legacy_primary_line(line: &str) -> anyhow::Result<ParsedAuditRecord> {
    let line = line.trim();
    if line.is_empty() {
        anyhow::bail!("empty line");
    }
    let rest = line
        .strip_prefix("type=")
        .ok_or_else(|| anyhow::anyhow!("legacy line missing leading type="))?;
    let (type_str, after_type) = rest
        .split_once(" msg=audit(")
        .ok_or_else(|| anyhow::anyhow!("legacy line missing msg=audit( after type"))?;
    let record_id = u16::from(
        RecordType::from_str(type_str.trim())
            .map_err(|_| anyhow::anyhow!("unknown record type string {:?}", type_str.trim()))?,
    );
    let data = format!("audit({}", after_type);
    ParsedAuditRecord::try_from(RawAuditRecord::new(record_id, data))
}

/// Groups flat [`ParsedAuditRecord`]s into [`AuditEvent`]s using `(timestamp,
/// serial)`. For use in reading and recorrelating already-written primary logs
/// in legacy format.
///
/// **Parameters:**
///
/// * `records`: The records to correlate.
fn correlate_records(records: Vec<ParsedAuditRecord>) -> Vec<AuditEvent> {
    let mut map: HashMap<(std::time::SystemTime, u16), Vec<ParsedAuditRecord>> = HashMap::new();
    for r in records {
        map.entry(r.identifier()).or_default().push(r);
    }
    let mut keys: Vec<_> = map.keys().cloned().collect();
    keys.sort_by(|a, b| {
        let ta = a.0.duration_since(UNIX_EPOCH).unwrap_or_default();
        let tb = b.0.duration_since(UNIX_EPOCH).unwrap_or_default();
        ta.cmp(&tb).then(a.1.cmp(&b.1))
    });
    keys.into_iter()
        .map(|id| {
            let records = map.remove(&id).expect("key must exist");
            let n = records.len() as u16;
            AuditEvent {
                timestamp: id.0,
                serial: id.1,
                record_count: n,
                records,
            }
        })
        .collect()
}

/// Parses a simple-format primary log file as written by the auditrs writer
/// into a [`Vec<AuditEvent>`]
///
/// **Parameters:**
///
/// * `content`: The content of the simple-format primary log file.
fn parse_simple_events(content: &str) -> anyhow::Result<Vec<AuditEvent>> {
    // Parse of hell
    let mut events = Vec::new();
    let mut cur: Option<(SystemTime, u16, u16, Vec<ParsedAuditRecord>)> = None;

    for line in content.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if let Some((ts, _, ser, recs)) = cur.take() {
                events.push(AuditEvent {
                    timestamp: ts,
                    serial: ser,
                    record_count: recs.len() as u16,
                    records: recs,
                });
            }
            let rest = line.trim().strip_prefix('[').context("header [")?;
            let (ts_str, rest) = rest
                .split_once("][Record Count: ")
                .context("][Record Count")?;
            let (rc_str, rest) = rest
                .split_once("] Audit Event Group ")
                .context("] Audit Event")?;
            let (ser_str, _) = rest.split_once(':').context("serial:")?;
            let expect: u16 = rc_str.trim().parse().context("record count")?;
            let ser: u16 = ser_str.trim().parse().context("serial")?;
            let ts: SystemTime = chrono::DateTime::parse_from_rfc3339(ts_str)
                .context("timestamp")?
                .with_timezone(&chrono::Utc)
                .into();
            cur = Some((ts, expect, ser, Vec::new()));
        } else if line.starts_with('\t') && line.contains("Record: ParsedAuditRecord") {
            let rec = parse_simple_record(line)?;
            let slot = cur.as_mut().context("record before header")?;
            slot.3.push(rec);
        }
    }

    if let Some((ts, expect, ser, recs)) = cur {
        let n = recs.len() as u16;
        if n != expect {
            eprintln!("warning: simple log got {n} records, header said {expect}");
        }
        events.push(AuditEvent {
            timestamp: ts,
            serial: ser,
            record_count: n,
            records: recs,
        });
    }

    Ok(events)
}

/// Parses a simple-format primary log record line as written by the auditrs
/// writer into a [`ParsedAuditRecord`]
///
/// **Parameters:**
///
/// * `line`: The line to parse.
fn parse_simple_record(line: &str) -> anyhow::Result<ParsedAuditRecord> {
    // Parse of hell, the sequel
    let inner = line
        .find("ParsedAuditRecord { ")
        .map(|i| &line[i + "ParsedAuditRecord { ".len()..])
        .context("ParsedAuditRecord")?
        .trim_end()
        .strip_suffix('}')
        .context("closing }}")?
        .trim_end();

    let (before_fields, tail) = inner.rsplit_once(", fields: ").context(", fields:")?;
    let (map_str, _) = brace_chunk(tail.trim_start())?;
    let fields: HashMap<String, String> = serde_json::from_str(map_str).context("fields")?;

    let (before_serial, ser_str) = before_fields
        .rsplit_once(", serial: ")
        .context(", serial:")?;
    let serial = ser_str.trim().parse().context("serial")?;

    let (rt_raw, ts_raw) = before_serial
        .split_once(", timestamp: ")
        .context(", timestamp:")?;
    let rt_name = rt_raw
        .strip_prefix("record_type: ")
        .context("record_type")?
        .trim();
    let record_type = RecordType::iter()
        .find(|rt| format!("{rt:?}") == rt_name)
        .with_context(|| format!("unknown record_type {rt_name:?}"))?;

    let ts_raw = ts_raw
        .trim_start()
        .strip_prefix("SystemTime")
        .context("SystemTime")?;
    let (brace, _) = brace_chunk(ts_raw.trim_start())?;
    let ts_inner = brace.trim().trim_matches(|c| c == '{' || c == '}');
    let mut tv_sec = None;
    let mut tv_nsec = None;
    for p in ts_inner.split(',') {
        let p = p.trim();
        if let Some(v) = p.strip_prefix("tv_sec:") {
            tv_sec = Some(v.trim().parse::<u64>()?);
        } else if let Some(v) = p.strip_prefix("tv_nsec:") {
            tv_nsec = Some(v.trim().parse::<u32>()?);
        }
    }

    Ok(ParsedAuditRecord {
        record_type,
        timestamp: UNIX_EPOCH + Duration::new(tv_sec.context("tv_sec")?, tv_nsec.unwrap_or(0)),
        serial,
        fields,
    })
}

/// Returns the first `{...}` in `s` and the rest after it.
///
/// **Parameters:**
///
/// * `s`: The string to parse.
fn brace_chunk(s: &str) -> anyhow::Result<(&str, &str)> {
    let s = s.trim_start();
    if !s.starts_with('{') {
        anyhow::bail!("expected {{");
    }
    let mut d = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '{' => d += 1,
            '}' => {
                d -= 1;
                if d == 0 {
                    return Ok((&s[..=i], &s[i + 1..]));
                }
            }
            _ => {}
        }
    }
    anyhow::bail!("unclosed {{");
}
