pub mod audit_types;
pub mod parser;

pub use audit_types::RecordType;

/// Intermediate result of parsing an audit message; used by parser and parsed_record.
/// This should be phased out
#[derive(Debug)]
pub struct RecordData {
    pub timestamp: std::time::SystemTime,
    pub serial: String,
    pub fields: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ParsedAuditRecord {
    pub(crate) record_type: RecordType,
    pub(crate) timestamp: std::time::SystemTime,
    pub(crate) serial: u16,
    pub(crate) fields: std::collections::HashMap<String, String>,
}
