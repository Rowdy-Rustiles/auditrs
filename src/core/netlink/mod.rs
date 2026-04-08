//! Defines the netlink transport for receiving raw audit records from the
//! kernel.
//!
//! This module contains the `RawAuditRecord` struct, which is used to represent
//! a single raw audit record received from the kernel. It also contains the
//! `NetlinkAuditTransport` struct, which is used to transport the raw audit
//! records to the parser.
//!
//! The `RawAuditRecord` struct is used to represent a single raw audit record
//! received from the kernel. It contains the record ID and the data of the
//! record.
//!
//! The `NetlinkAuditTransport` struct is used to transport the raw audit
//! records to the parser.
//!
//! [`apply_audit_rule_message`] uses separate short-lived netlink sessions to
//! add or delete kernel rules (e.g. path watches), distinct from the event
//! listener.

mod netlink;
mod raw_record;
mod rule_session;

pub use rule_session::apply_audit_rule_message;

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
    receiver: tokio::sync::mpsc::Receiver<RawAuditRecord>,
}
