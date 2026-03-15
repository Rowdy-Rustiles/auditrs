//! General-purpose time and string utility helpers.
//!
//! This module provides small, reusable functions for working with
//! `SystemTime`, UTC timestamps, and simple string transformations.

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Convert an `<seconds>.<millis>` timestamp string into a `SystemTime`.
///
/// The input is expected to be in the same format used by the Linux audit
/// subsystem (e.g. `"1234567890.123"`). Only the first three fractional
/// digits are interpreted as milliseconds; any additional precision is
/// ignored.
///
/// **Parameters:**
///
/// * `secs_micros_str`: String of the form `<seconds>.<fraction>` representing
///   a UNIX timestamp in seconds plus fractional seconds.
pub fn timestamp_string_to_systemtime(secs_micros_str: &str) -> Result<SystemTime> {
    let (secs_str, micros_str) = secs_micros_str
        .split_once('.')
        .ok_or(anyhow::anyhow!("Invalid timestamp format"))?;

    let seconds: u64 = secs_str.parse()?;

    let millis: u64 = micros_str.get(0..3).unwrap_or(micros_str).parse()?;

    Ok(UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_millis(millis))
}

/// Render a `SystemTime` as an RFC3339-like UTC timestamp string.
///
/// The format used is `YYYY-MM-DDTHH:MM:SS.mmmZ`, always in UTC and with
/// millisecond precision.
///
/// **Parameters:**
///
/// * `systemtime`: Instant to convert into a human-readable UTC string.
pub fn systemtime_to_utc_string(systemtime: SystemTime) -> String {
    let dt: DateTime<Utc> = systemtime.into();
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Returns the current time as a UTC timestamp string.
///
/// The format matches [`systemtime_to_utc_string`]:
/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn current_utc_string() -> String {
    let dt: DateTime<Utc> = Utc::now();
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Convert a `SystemTime` into a `<seconds>.<millis>` timestamp string.
///
/// This is the inverse of [`timestamp_string_to_systemtime`] with
/// millisecond precision.
///
/// **Parameters:**
///
/// * `systime`: The `SystemTime` value to represent as an audit-style
///   timestamp.
pub fn systemtime_to_timestamp_string(systime: SystemTime) -> Result<String> {
    let duration = systime.duration_since(UNIX_EPOCH)?;
    Ok(format!(
        "{}.{:03}",
        duration.as_secs(),
        duration.subsec_millis()
    ))
}

/// Capitalize the first Unicode character in a string.
///
/// If the input is empty, returns an empty `String`. Otherwise, the first
/// character is converted to its uppercase variant and concatenated with the
/// remainder of the string unchanged.
///
/// **Parameters:**
///
/// * `s`: Input string slice whose first character should be capitalized.
pub fn capitalize_first_letter(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

/// Strip `/* ... */` block comments from raw file content (works across
/// multiple lines).
///
/// The function scans through the input, removing any well-formed `/* ... */`
/// comment sequences, and leaves all other text intact. Unterminated comment
/// blocks are dropped to the end of the input and emit a warning on stderr.
///
/// **Parameters:**
///
/// * `content`: Raw string content potentially containing C-style block
///   comments.
pub fn strip_block_comments(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c == '/' {
            chars.next();
            if chars.peek() == Some(&'*') {
                chars.next();
                let mut closed = false;
                while let Some(inner) = chars.next() {
                    if inner == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    eprintln!("warning: unterminated block comment (missing closing */)");
                }
            } else {
                result.push('/');
            }
        } else {
            result.push(c);
            chars.next();
        }
    }

    result
}
