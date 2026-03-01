use std::fmt;

use super::AuditEvent;

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
