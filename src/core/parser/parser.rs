use nom::Finish;
use nom::{
    IResult,
    bytes::complete::{tag, take_while, take_while1},
    character::complete::{char, space1},
    sequence::tuple,
};
use std::collections::HashMap;
use std::time::SystemTime;

use crate::core::netlink::RawAuditRecord;
use crate::core::parser::{ParsedAuditRecord, RecordData};
use crate::utils::timestamp_string_to_systemtime;

impl ParsedAuditRecord {
    /// Returns (timestamp, serial) identifying the audit event this record
    /// belongs to.
    pub fn identifier(&self) -> (SystemTime, u16) {
        (self.timestamp, self.serial)
    }
}

impl TryFrom<RawAuditRecord> for ParsedAuditRecord {
    type Error = anyhow::Error;
    fn try_from(raw_record: RawAuditRecord) -> Result<Self, Self::Error> {
        let parse_result = parse_audit_message(&raw_record.data).finish();
        match parse_result {
            Ok((_, record_data)) => {
                let fields = parse_kv(record_data.fields.get("kv").unwrap_or(&String::new()));
                Ok(ParsedAuditRecord {
                    record_type: raw_record.record_id.into(),
                    timestamp: record_data.timestamp,
                    serial: record_data.serial.parse::<u16>().unwrap_or(0),
                    fields,
                })
            }
            Err(e) => Err(anyhow::anyhow!("Failed to parse audit message: {:?}", e)),
        }
    }
}

/// Parses the data payload of a RawAuditRecord into a hashmap of key-value
/// pairs.
fn parse_kv(input: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let mut chars = input.chars().peekable();

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

        fields.insert(key.trim().to_string(), value);

        while let Some(&c) = chars.peek() {
            if !c.is_whitespace() {
                break;
            }
            chars.next();
        }
    }

    fields
}

fn parse_audit_message(input: &str) -> IResult<&str, RecordData> {
    // Basic parsers
    let audit_tag = tag("audit(");
    let timestamp_digits = take_while1(|c: char| c.is_ascii_digit());
    let timestamp_milis = take_while1(|c: char| c.is_ascii_digit());
    let timestamp = (timestamp_digits, char('.'), timestamp_milis);
    let serial_digits = take_while1(|c: char| c.is_ascii_digit());

    // Parse the header: 'audit(1234567890.123:456):'
    let (input, (_, timestamp_tuple, _, serial, _, _)) = tuple((
        audit_tag,
        timestamp,
        char(':'),
        serial_digits,
        char(')'),
        char(':'),
    ))(input)?; // does not parse the trailing ' '.

    // Now parse the rest of the line as key-value pairs
    // Brute implementation: put everything into a single "kv" field.
    // There will only be one line in the payload, so we can just take until the end
    // of the line

    let (input, _) = space1(input)?; // consume the space after the header

    let (input, kvs) = take_while(|_| true)(input)?;
    let mut fields = HashMap::new();
    fields.insert("kv".to_string(), kvs.to_string());

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
mod test {
    use super::*;

    #[test]
    fn test_parse_audit_message() {
        let input = "audit(1234567890.123:456): key1=value";
        let expected_timestamp = timestamp_string_to_systemtime("1234567890.123").unwrap();
        let expected_serial = "456".to_string();
        let expected_kv = "key1=value".to_string();

        let expected_fields = {
            let mut map = HashMap::new();
            map.insert("kv".to_string(), expected_kv);
            map
        };

        let expected = RecordData {
            timestamp: expected_timestamp,
            serial: expected_serial,
            fields: expected_fields,
        };

        let result = parse_audit_message(input);
        assert!(result.is_ok(), "Parsing failed: {:?}", result);
        let (remaining, parsed) = result.unwrap();
        assert_eq!(remaining, "");
        assert_eq!(parsed.timestamp, expected.timestamp);
        assert_eq!(parsed.serial, expected.serial);
        assert_eq!(parsed.fields, expected.fields);
    }
}
