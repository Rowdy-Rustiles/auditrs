use std::time::SystemTime;
use crate::record::AuditRecord;

pub struct AuditEvent {
    // pub timestamp: SystemTime,
    // pub serial: u64,
    pub records: Vec<AuditRecord>,
}

impl AuditEvent {
    pub fn new_simple(record: AuditRecord) -> Self {
        Self {
            // timestamp: record.timestamp,
            // serial: record.serial,
            records: vec![record],
        }
    }
    
    // pub fn new_compound(records: Vec<AuditRecord>) -> Result<Self, ValidationError> {
    //     // Unsure if this validation should be done here... might be the correlators job?
    //     if records.is_empty() {
    //         return Err(ValidationError::EmptyRecords);
    //     }
        
    //     // Get reference values from first record
    //     let first = &records[0];
    //     // let expected_timestamp = first.timestamp;
    //     // let expected_serial = first.serial;
        
    //     // Validate all records have matching correlation fields
    //     for record in &records {
        
    //         if record.timestamp != expected_timestamp {
    //             return Err(ValidationError::TimestampMismatch {
    //                 expected: expected_timestamp,
    //                 found: record.timestamp,
    //             });
    //         }
            
    //         if record.serial != expected_serial {
    //             return Err(ValidationError::SerialMismatch {
    //                 expected: expected_serial,
    //                 found: record.serial,
    //             });
    //         }
    //     }
        
    //     Ok(AuditEvent {
    //         timestamp: expected_timestamp,
    //         serial: expected_serial,
    //         records,
    //     })
    // }

    pub fn is_simple(self) -> bool {
        assert!(!self.records.is_empty());
        self.records.len() == 1
    }

    pub fn is_compound(self) -> bool {
        self.records.len() > 1
    }
}

pub enum ValidationError {
    EmptyRecords,
    TimestampMismatch { expected: SystemTime, found: SystemTime },
    SerialMismatch { expected: u64, found: u64 },
}