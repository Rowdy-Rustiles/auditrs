use std::{collections::HashMap, time::SystemTime};

use crate::raw_record::RecordType;

pub struct ParsedAuditRecord {
    record_type: RecordType, //  is this the same RecordType?
    timestamp: SystemTime,
    serial: u64,
    fields: HashMap<String, String>
}