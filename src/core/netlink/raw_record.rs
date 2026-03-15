use crate::core::netlink::RawAuditRecord;

impl RawAuditRecord {
    /// Creates a new `RawAuditRecord` with the given record ID and data.
    ///
    /// **Parameters:**
    ///
    /// * `id`: The record ID.
    /// * `data`: The data of the record.
    pub fn new(id: u16, data: String) -> Self {
        RawAuditRecord {
            record_id: id,
            data,
        }
    }
}
