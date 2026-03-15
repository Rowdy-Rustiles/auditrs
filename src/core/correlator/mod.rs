//! Combine multiple `ParsedAuditRecord`s into a single `AuditEvent`.
//!
//! See <https://man7.org/linux/man-pages/man5/auditd.conf.5.html>, Notes section.
//! The auditd system does not guarantee that the set of records that make up an
//! event will occur atomically; the stream may have interleaved records from
//! different events.

mod correlator;
mod event;

use std::collections::HashMap;
use std::time::{Instant, SystemTime};

use crate::core::parser::ParsedAuditRecord;

/// A single audit event: one or more records sharing the same (timestamp,
/// serial).
#[derive(Clone)]
pub struct AuditEvent {
    /// Event timestamp from the audit stream.
    pub timestamp: SystemTime,
    /// Serial number identifying this event in the stream.
    pub serial: u16,
    /// Number of records in this event.
    pub record_count: u16,
    /// The correlated records that make up this event.
    pub records: Vec<ParsedAuditRecord>,
}

/// Buffer that groups incoming audit records by (timestamp, serial) and flushes
/// them as `AuditEvent`s when an entry’s timeout elapses. Each time a record is
/// added to an entry, that entry’s timeout is reset.
pub struct Correlator {
    pub(crate) event_buffer: HashMap<(SystemTime, u16), (Vec<ParsedAuditRecord>, Instant)>,
}
