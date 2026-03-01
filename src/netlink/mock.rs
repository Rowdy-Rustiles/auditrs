use super::*;
use tokio::sync::mpsc;

pub struct MockSocketReader;

impl AuditTransport for MockSocketReader {
    fn new() -> Self {
        todo!()
    }
    fn read_message(&self) -> Option<Vec<u8>> {
        todo!()
    }
    fn into_receiver(self) -> mpsc::Receiver<crate::raw_record::RawAuditRecord> {
        todo!()
    }
    async fn recv(&mut self) -> Option<crate::raw_record::RawAuditRecord> {
        todo!()
    }
}
