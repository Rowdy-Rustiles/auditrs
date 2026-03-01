use std::{collections::HashMap, time::SystemTime};
use crate::utils::timestamp_string_to_systemtime;

use nom::{
    bytes::complete::{tag, take_until, take_while1, take_while},
    character::complete::{char, digit1, alphanumeric1, space0, space1},
    combinator::{map, opt, recognize},
    multi::separated_list0,
    sequence::{delimited, preceded, separated_pair, tuple},
    IResult,
};

pub struct AuditMessageParser {}

impl AuditMessageParser {
    pub fn new() -> Self {
        AuditMessageParser {}
    }
}

#[derive(Debug)]
pub struct RecordData {
    pub timestamp: SystemTime,
    pub serial: String,
    pub fields: HashMap<String, String>,
}

pub fn parse_audit_message(input: &str) -> IResult<&str, RecordData> {
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
    // There will only be one line in the payload, so we can just take until the end of the line
    
    
    let (input, _) = space1(input)?; // consume the space after the header
    
    let (input, kvs) = take_while(|_| true)(input)?;
    let mut fields = HashMap::new();
    fields.insert("kv".to_string(), kvs.to_string());

    let timestamp = timestamp_string_to_systemtime(&format!("{}.{}", timestamp_tuple.0, timestamp_tuple.2)).unwrap();
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