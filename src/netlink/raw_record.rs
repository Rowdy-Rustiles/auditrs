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

use crate::audit_types::RecordType;
use std::{collections::HashMap, time::SystemTime};

#[derive(Debug, PartialEq)]
pub struct RawAuditRecord {
    pub record_id: u16,
    pub data: String,
}

impl RawAuditRecord {
    pub fn new(id: u16, data: String) -> Self {
        RawAuditRecord {
            record_id: id,
            data,
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
}
