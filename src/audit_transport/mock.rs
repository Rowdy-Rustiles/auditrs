use super::*;

pub struct MockSocketReader;

impl AuditTransport for MockSocketReader {
    fn read_message(&self) -> Option<Vec<u8>> {
        todo!()
    }

    fn new() -> Self {
        todo!()
    }
}