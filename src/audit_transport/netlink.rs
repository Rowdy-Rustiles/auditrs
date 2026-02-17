use super::AuditTransport;
pub struct NetlinkAuditTransport {
    // evil evil evil evil
}



impl AuditTransport for NetlinkAuditTransport {
    fn read_message(&self) -> Option<Vec<u8>> {
        todo!()
    }

    fn new() -> Self {
        todo!()
    }
}