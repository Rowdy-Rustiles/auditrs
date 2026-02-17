use crate::record::AuditRecord;
use crate::event::AuditEvent;

struct Correlator { }

impl Correlator {
    fn correlate_records(record_buffer: Vec<AuditRecord>) -> Vec<AuditEvent> {
        let event_buffer;

        for record in record_buffer
        {

        }
    }
}