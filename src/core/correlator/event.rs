use std::fmt;

use crate::core::correlator::AuditEvent;
use crate::utils::systemtime_to_utc_string;


impl fmt::Debug for AuditEvent {
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
