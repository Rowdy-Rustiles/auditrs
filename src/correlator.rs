use crate::record::AuditRecord;
use crate::event::AuditEvent;

pub struct AuditRecordCorrelator { }

impl AuditRecordCorrelator {
    pub fn new() -> Self {
        todo!()
    }
    fn correlate_records(record_buffer: Vec<AuditRecord>) -> Vec<AuditEvent> {
        let event_buffer;

        for record in record_buffer
        {

        }
    }
}