// Audit record parsing. Converts raw socket data into a parsed AuditRecord

use crate::record::*;

pub struct AuditMessageParser;

impl AuditMessageParser {
    pub fn new() -> Self {
        AuditMessageParser {}
    }
}