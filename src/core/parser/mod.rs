//! Parses raw audit records into their typed equivalents.
//!
//! Auditrs relies on the `audit` crate to initially structure the raw records
//! received from the kernel (see (audit crate documentation)[https://docs.rs/audit/latest/audit/]).
//! The `parser` module then converts these raw records into their typed
//! equivalents (with some additional identifier fields), using the `RecordType`
//! enum to represent the type of the record.
//!
//! Note that the parser does not perform any type enrichment; this is handled
//! by the `enricher` module.

pub mod audit_types;
pub mod parser;

pub use audit_types::RecordType;

/// Intermediate result of parsing an audit message; used by parser and
/// parsed_record. This should be phased out
#[derive(Debug)]
pub struct RecordData {
    /// The timestamp of the record.
    pub timestamp: std::time::SystemTime,
    /// The serial number of the record.
    pub serial: String,
    /// The key-value pairs of the record (stored as strings).
    pub fields: std::collections::HashMap<String, String>,
}

/// A parsed audit record.
#[derive(Debug, Clone)]
pub struct ParsedAuditRecord {
    /// The type of the record.
    pub(crate) record_type: RecordType,
    /// The timestamp of the record.
    pub(crate) timestamp: std::time::SystemTime,
    /// The serial number of the record.
    pub(crate) serial: u16,
    /// The key-value pairs of the record (stored as strings).
    pub(crate) fields: std::collections::HashMap<String, String>,
}
