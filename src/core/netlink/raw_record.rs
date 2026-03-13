use crate::core::netlink::RawAuditRecord;


impl RawAuditRecord {
    pub fn new(id: u16, data: String) -> Self {
        RawAuditRecord {
            record_id: id,
            data,
        }
    }
}
