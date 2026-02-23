/*
    Definition of an Audit Record. This corresponds to a single line in an audit log file,
    which may contain multiple fields. Original implementation uses key/value string pairs
    stored in a HashMap, but could be extended to a more strongly typed structure in the
    future.

    Relevant documentation:
    https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv

    For information on the mapping of netlink messages to auditrs log types, refer to:
    https://codebrowser.dev/linux/include/linux/audit.h.html#147

    need to look into the types presented here:
    https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files

    and additionally find more modern types
*/

use std::{collections::HashMap, time::SystemTime};
use crate::audit_types::RecordType;


#[derive(Debug, PartialEq)]
pub struct RawAuditRecord {
    pub record_type: RecordType,
    pub data: String,
}

impl RawAuditRecord {
    pub fn new(_type: RecordType, data: String) -> Self {
        RawAuditRecord {
            record_type: _type,
            data,
        }
    }

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

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn test_record_to_log() {
        let record_type = RecordType::from(1300); // Syscall
        let record = AuditRecord::new(record_type, "example data".to_string());
        assert_eq!(record.record_type.as_audit_str(), "SYSCALL");
        assert_eq!(record.to_log(), "type=SYSCALL msg=example data");

        // Round-trip u16 conversion
        let num: u16 = record_type.into();
        assert_eq!(num, 1300);
        assert_eq!(RecordType::from(num), record_type);
    }
}
