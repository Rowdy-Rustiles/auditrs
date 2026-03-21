//! `Display` and `Debug` formatting for `AuditEvent`.

use std::fmt;

use crate::core::correlator::AuditEvent;
use crate::utils::systemtime_to_utc_string;

impl fmt::Debug for AuditEvent {
    /// Format the event for debug output (timestamp, record count, and each
    /// record).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = String::new();
        output.push_str(&format!(
            "{:?} Record Count: {} records: {{\n",
            self.timestamp, self.record_count
        ));
        for record in self.records.iter() {
            output.push_str(&format!("\tRecord: {:?}\n", record));
        }
        output.push_str("}\n");
        write!(f, "{}", output)
    }
}

impl fmt::Display for AuditEvent {
    /// Format the event for user-facing output (UTC timestamp, record count,
    /// serial, and each record).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = String::new();
        output.push_str(&format!(
            "[{}][Record Count: {}] Audit Event Group {}:\n",
            systemtime_to_utc_string(self.timestamp),
            self.record_count,
            self.serial
        ));
        for record in self.records.iter() {
            output.push_str(&format!("\tRecord: {:?}\n", record));
        }
        write!(f, "{}", output)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core::parser::{ParsedAuditRecord, RecordType};
    use std::{collections::HashMap, time::SystemTime};

    fn create_test_event() -> AuditEvent {
        let timestamp = SystemTime::UNIX_EPOCH;
        AuditEvent {
            timestamp: timestamp,
            serial: 1,
            record_count: 1,
            records: vec![ParsedAuditRecord {
                timestamp: timestamp,
                serial: 1,
                record_type: RecordType::AddGroup,
                fields: HashMap::new(),
            }],
        }
    }

    #[test]
    fn test_debug_format() {
        let event = create_test_event();
        let expected = concat!(
            "SystemTime { tv_sec: 0, tv_nsec: 0 } Record Count: 1 records: {\n",
            "\tRecord: ParsedAuditRecord { record_type: AddGroup, timestamp: SystemTime { tv_sec: 0, tv_nsec: 0 }, serial: 1, fields: {} }\n",
            "}\n",
        );
        assert_eq!(format!("{event:?}"), expected);
    }

    #[test]
    fn test_display_format() {
        let event = create_test_event();
        let expected = concat!(
            "[1970-01-01T00:00:00.000Z][Record Count: 1] Audit Event Group 1:\n",
            "\tRecord: ParsedAuditRecord { record_type: AddGroup, timestamp: SystemTime { tv_sec: 0, tv_nsec: 0 }, serial: 1, fields: {} }\n",
        );
        assert_eq!(format!("{event}"), expected);
    }
}
