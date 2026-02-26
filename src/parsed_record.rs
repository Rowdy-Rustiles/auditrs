use std::{any, collections::HashMap, iter::Map, os::linux::raw, time::SystemTime};


use nom::Finish;

use crate::{
    audit_types::RecordType, raw_record::RawAuditRecord, parser::parse_audit_message,

};

#[derive(Debug, Clone)]
pub struct ParsedAuditRecord {
    record_type: RecordType,
    timestamp: SystemTime,
    serial: u16,
    fields: HashMap<String, String>,
}

/// Impl block probably wont be needed for this, or it
/// will just have a thin wrapper around From<RawAuditRecord>.
/// I think splitting most of the logic between From<> and
/// some static functions is a good, simple approach
impl ParsedAuditRecord {
    /// This should ultimately be moved to another file
    pub fn to_legacy_log(&self) -> String {
        let field_data = self.fields.clone();
        let mut output = String::new();
        if (!self.fields.is_empty()) {
            output = format!(
                "type_id={} type={} msg={:?}",
                u16::from(self.record_type),
                self.record_type.as_audit_str(),
                field_data
            );
        } else {
            output = format!(
                "type_id={} type={}",
                u16::from(self.record_type),
                self.record_type.as_audit_str()
            );
        }
        output
    }
}

/// Converts a RawAuditRecord item into an enriched, typed ParsedAuditRecord
impl TryFrom<RawAuditRecord> for ParsedAuditRecord {
    // A little scuffy but it compiles!
    // Nom documentation encourages using the IResult type for parsing and doing the conversion in this TryFrom impl.
    // ...not sure if I agree.
    type Error = anyhow::Error;
    fn try_from(raw_record: RawAuditRecord) -> Result<Self, Self::Error> {
        let parse_result = parse_audit_message(&raw_record.data).finish();
        match parse_result {
            Ok((_, record_data)) => {
                // Need to move parse_kv() into the parser.
                let fields = parse_kv(&record_data.fields.get("kv").unwrap_or(&"".to_string()));
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

/// Parses the data payload of a RawAuditRecord into a hashmap of key-value pairs
fn parse_kv(input: &str) -> HashMap<String, String> {
    let mut fields = HashMap::<String, String>::new();
    let mut chars = input.chars().peekable();

    while chars.peek().is_some() {
        // Read key
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' {
                chars.next();
                break;
            }
            key.push(c);
            chars.next();
        }

        // Read value
        let mut value = String::new();
        if let Some(&'"') = chars.peek() {
            chars.next(); // consume opening quote
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

        // Skip whitespace
        while let Some(&c) = chars.peek() {
            if !c.is_whitespace() {
                break;
            }
            chars.next();
        }
    }

    fields
}
