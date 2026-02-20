use crate::event::AuditEvent;
use crate::record::AuditRecord;

pub struct AuditRecordCorrelator {}

impl AuditRecordCorrelator {
    pub fn new() -> Self {
        todo!()
    }
    fn correlate_records(record_buffer: Vec<AuditRecord>) -> Vec<AuditEvent> {
        let event_buffer;

        for record in record_buffer {}
    }
}
