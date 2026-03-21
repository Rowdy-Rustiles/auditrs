//! Implementation of the audit record parser.
//!
//! This module provides utilities for transforming raw netlink audit
//! messages into structured `ParsedAuditRecord` instances. It is a thin
//! wrapper around the Linux kernel audit message format, using `nom`
//! combinators to parse the fixed header and a small hand-rolled parser
//! for the trailing key–value section.

use nom::{
    Finish,
    IResult,
    Parser,
    bytes::complete::{tag, take_while1},
    character::complete::{char, space1},
};
use std::collections::HashMap;
use std::time::SystemTime;

use crate::core::netlink::RawAuditRecord;
use crate::core::parser::{ParsedAuditRecord, RecordData};
use crate::utils::timestamp_string_to_systemtime;

impl ParsedAuditRecord {
    /// Returns the `(timestamp, serial)` pair that uniquely identifies the
    /// audit event this record belongs to.
    ///
    /// The kernel emits several records (e.g. `SYSCALL`, `PATH`, `CWD`)
    /// that all share the same timestamp and serial number; callers can
    /// use this helper to group records belonging to the same logical
    /// event.
    pub fn identifier(&self) -> (SystemTime, u16) {
        (self.timestamp, self.serial)
    }
}

impl TryFrom<RawAuditRecord> for ParsedAuditRecord {
    type Error = anyhow::Error;
    /// Attempts to parse a `RawAuditRecord` into a high-level
    /// `ParsedAuditRecord`.
    ///
    /// The conversion understands the standard Linux audit header of
    /// the form:
    ///
    /// `audit(<seconds>.<millis>:<serial>): key1=val1 key2="val 2" ...`
    ///
    /// The header is parsed with `nom` and the remaining key–value
    /// payload is stored in the `fields` map.
    fn try_from(raw_record: RawAuditRecord) -> Result<Self, Self::Error> {
        parse_audit_message(&raw_record.data)
            .finish()
            .map(|(_, record_data)| {
                ParsedAuditRecord {
                    record_type: raw_record.record_id.into(),
                    timestamp: record_data.timestamp,
                    serial: record_data.serial.parse::<u16>().unwrap_or(0),
                    fields: record_data.fields,
                }
            })
            .map_err(|e| anyhow::anyhow!("Failed to parse audit message: {:?}", e))
    }
}

/// Parses a single audit message line into `RecordData`.
///
/// The expected format is the canonical Linux audit prefix followed by
/// a space and an opaque key–value payload:
///
/// `audit(<seconds>.<millis>:<serial>): key1=val1 key2="val 2" ...`
///
/// The timestamp is converted into a `SystemTime`, the serial is stored
/// as a string, and the remaining payload is parsed into key–value
/// pairs stored directly in the `fields` map.
fn parse_audit_message(input: &str) -> IResult<&str, RecordData> {
    // Basic parsers
    let audit_tag = tag("audit(");
    let timestamp_digits = take_while1(|c: char| c.is_ascii_digit());
    let timestamp_milis = take_while1(|c: char| c.is_ascii_digit());
    let timestamp = (timestamp_digits, char('.'), timestamp_milis);
    let serial_digits = take_while1(|c: char| c.is_ascii_digit());

    // Parse the header: 'audit(1234567890.123:456):'
    let (input, (_, timestamp_tuple, _, serial, _, _)) = (
        audit_tag,
        timestamp,
        char(':'),
        serial_digits,
        char(')'),
        char(':'),
    )
        .parse(input)?; // does not parse the trailing ' '.

    // Now parse the rest of the line as key-value pairs
    // Brute implementation: put everything into a single "kv" field.
    // There will only be one line in the payload, so we can just take until the end
    // of the line

    let (input, _) = space1(input)?; // consume the space after the header

    let (input, kvs) = nom::combinator::rest(input)?;
    let mut fields = HashMap::new();
    // Parse key–value pairs of the form:
    // key=value key2="val 2 with spaces"
    let mut chars = kvs.chars().peekable();
    while chars.peek().is_some() {
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' {
                chars.next();
                break;
            }
            key.push(c);
            chars.next();
        }

        let mut value = String::new();
        if let Some(&'"') = chars.peek() {
            chars.next();
            while let Some(c) = chars.next() {
                if c == '"' {
                    break;
                }
                value.push(c);
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ' ' {
                    break;
                }
                value.push(c);
                chars.next();
            }
        }

        if !key.is_empty() {
            fields.insert(key.trim().to_string(), value);
        }

        while let Some(&c) = chars.peek() {
            if !c.is_whitespace() {
                break;
            }
            chars.next();
        }
    }

    let timestamp =
        timestamp_string_to_systemtime(&format!("{}.{}", timestamp_tuple.0, timestamp_tuple.2))
            .unwrap();
    let serial = serial.to_string();

    let parsed_record = RecordData {
        timestamp,
        serial,
        fields,
    };
    Ok((input, parsed_record))
}

// tests
#[cfg(test)]
mod tests {
    use crate::core::parser::RecordType;

    use super::*;

    #[test]
    fn parse_audit_message_ok() {
        let input = "audit(1234567890.123:456): key1=value";
        let expected_timestamp = timestamp_string_to_systemtime("1234567890.123").unwrap();
        let expected_serial = "456".to_string();
        let expected = RecordData {
            timestamp: expected_timestamp,
            serial: expected_serial,
            fields: {
                let mut map = HashMap::new();
                map.insert("key1".to_string(), "value".to_string());
                map
            },
        };

        let result = parse_audit_message(input);
        assert!(result.is_ok(), "Parsing failed: {:?}", result);
        let (remaining, parsed) = result.unwrap();
        assert_eq!(remaining, "");
        assert_eq!(parsed.timestamp, expected.timestamp);
        assert_eq!(parsed.serial, expected.serial);
        assert_eq!(parsed.fields, expected.fields);
    }

    #[test]
    fn parsed_try_from_raw_audit_record() {
        let raw_record =
            RawAuditRecord::new(1000, "audit(1234567890.123:456): key1=value".to_string());
        let parsed_record = ParsedAuditRecord::try_from(raw_record).unwrap();
        assert_eq!(parsed_record.record_type, RecordType::GetStatus);
        assert_eq!(
            parsed_record.timestamp,
            timestamp_string_to_systemtime("1234567890.123").unwrap()
        );
        assert_eq!(parsed_record.serial, 456);
        assert_eq!(
            parsed_record.fields,
            HashMap::from([("key1".to_string(), "value".to_string())])
        );
    }

    #[test]
    fn identifier() {
        let parsed_record = ParsedAuditRecord {
            record_type: RecordType::GetStatus,
            timestamp: timestamp_string_to_systemtime("1234567890.123").unwrap(),
            serial: 456,
            fields: HashMap::from([("key1".to_string(), "value".to_string())]),
        };
        assert_eq!(
            parsed_record.identifier(),
            (parsed_record.timestamp, parsed_record.serial)
        );
    }

    #[test]
    fn parse_audit_message_quoted_value_with_spaces() {
        let input = r#"audit(1234567890.123:1): msg="hello world""#;
        let (_, parsed) = parse_audit_message(input).unwrap();
        assert_eq!(
            parsed.fields.get("msg").map(String::as_str),
            Some("hello world")
        );
    }

    #[test]
    fn parse_audit_message_multiple_key_value_pairs() {
        let input = "audit(1234567890.123:2): a=1 b=two c=three";
        let (_, parsed) = parse_audit_message(input).unwrap();
        assert_eq!(
            parsed.fields,
            HashMap::from([
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "two".to_string()),
                ("c".to_string(), "three".to_string()),
            ])
        );
    }

    #[test]
    fn parse_audit_message_skips_empty_key_before_equals() {
        // Leading `=foo` yields an empty key for the first pair and is skipped.
        let input = "audit(1234567890.123:3): =skipped key1=kept";
        let (_, parsed) = parse_audit_message(input).unwrap();
        assert_eq!(
            parsed.fields,
            HashMap::from([("key1".to_string(), "kept".to_string())])
        );
    }

    #[test]
    fn parse_audit_message_rejects_invalid_prefix() {
        assert!(parse_audit_message("not_audit(1.2:3): k=v").is_err());
    }

    #[test]
    fn parse_audit_message_requires_space_after_header() {
        assert!(parse_audit_message("audit(1234567890.123:4):k=v").is_err());
    }

    #[test]
    fn try_from_raw_rejects_unparseable_line() {
        let raw = RawAuditRecord::new(1300, "this is not an audit line".to_string());
        assert!(ParsedAuditRecord::try_from(raw).is_err());
    }

    #[test]
    fn try_from_serial_overflow_defaults_to_zero() {
        // Header serial is > u16::MAX - parse::<u16>() fails and unwrap_or(0) applies.
        let raw = RawAuditRecord::new(1300, "audit(1234567890.123:70000): key1=value".to_string());
        let parsed = ParsedAuditRecord::try_from(raw).unwrap();
        assert_eq!(parsed.serial, 0);
    }
}
