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
