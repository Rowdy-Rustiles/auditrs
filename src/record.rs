pub struct AuditRecord {
    pub record_type: RecordType,
    pub data: String,
}

pub struct CorrelatedRecord {
    pub record_type: RecordType,
    pub data: String,
    pub correlated_event: Vec<AuditRecord>,
}

impl AuditRecord {
    pub fn new(record_type: RecordType, data: String) -> Self {
        AuditRecord { record_type, data }
    }
}
