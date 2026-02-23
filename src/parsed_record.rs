use std::{collections::HashMap, time::SystemTime};

use crate::{audit_types::RecordType, raw_record::RawAuditRecord, utils::timestamp_string_to_systemtime};

pub struct ParsedAuditRecord {
    record_type: RecordType,
    timestamp: SystemTime,
    serial: u16,
    fields: HashMap<String, String>
}

impl ParsedAuditRecord {
    pub fn to_log(&self) -> String {
        let field_data = self.data.clone();
        let mut output = String::new();
        if(!self.data.is_empty()) {
            output = format!("type_id={} type={} msg={}", u16::from(self.record_type), self.record_type.as_audit_str(), self.data);
        } else {
            output = format!("type_id={} type={}", u16::from(self.record_type), self.record_type.as_audit_str());
        }   
        output
    }
}

/// Converts a RawAuditRecord item into an enriched, typed ParsedAuditRecord
impl From<RawAuditRecord> for ParsedAuditRecord {
    fn from(raw_record: RawAuditRecord) -> Self {
        // First, we take the record_id directly form the raw record
        let record_type = RecordType::from(raw_record.record_id);

        // We then extract the timestamp from the following portion of the message payload:
        // msg=audit(1769633068.289:1322), corresponding to seconds.milliseconds:serial.
        // The timestamp is time since UNIX_EPOCH
        let timestamp_str = raw_record
            .data
            .split("audit(")
            .nth(1)
            .and_then(|s| s.split_once(':'))
            .map(|(ts, _)| ts);

        let timestamp: SystemTime = match timestamp_str {
            Some(ts_string) => {
                timestamp_string_to_systemtime(ts_string)?
            }
            None => {
                return Err("Error parsing record timestamp!".into());
            }
        };

        // After getting the timestamp, get the record's serial number
        let serial: u16 = {
            let serial_str = raw_record
                .data
                .split_once("audit(")
                .and_then(|(_, rest)| rest.split_once(')'))
                .and_then(|(inside, _)| inside.split_once(':'))
                .map(|(_, serial)| serial);

            match serial_str {
                Some(s) => match s.parse::<u16>() {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Invalid audit serial '{}': {}", s, e);
                        return;
                    }
                },
                None => {
                    eprintln!("Audit serial not found in record!");
                    return;
                }
            }
        };

        // These should be further qualified, but for now we return an empty hashmap
        let fields = HashMap::<String, String>::new();

        ParsedAuditRecord { record_type, timestamp, serial, fields }
    }
}