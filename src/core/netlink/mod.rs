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

mod netlink;
mod raw_record;

/// A raw audit record received from the kernel via netlink.
#[derive(Debug, PartialEq)]
pub struct RawAuditRecord {
    /// The record ID.
    pub record_id: u16,
    /// The data of the record.
    pub data: String,
}

/// A transport for receiving raw audit records from the kernel via netlink and
/// forwarding them to an intermediary MPSC channel for parsing.
pub struct NetlinkAuditTransport {
    pub(crate) receiver: tokio::sync::mpsc::Receiver<RawAuditRecord>,
}
