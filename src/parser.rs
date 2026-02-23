// Audit record parsing. Converts raw socket data into a parsed AuditRecord

use crate::parsed_record::*;
use crate::raw_record::*;

pub struct AuditMessageParser;

impl AuditMessageParser {
    pub fn new() -> Self {
        AuditMessageParser {}
    }
}
