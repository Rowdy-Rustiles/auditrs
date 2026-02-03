// Audit record parsing

use std::time::SystemTime;
use crate::record::*;



#[derive(Debug)]
pub enum ParseError {
    InvalidLine(String),
    Unknown,
}
pub struct RecordPreamble {
    pub record_type: RecordType,
    pub timestamp: SystemTime,
    pub serial: u64, 
}

/// Fields like SADDR={ saddr_fam=netlink nlnk-fam=16 nlnk-pid=0 } need whitespace removed to parse grouped values together.
/// Depending on how common this pattern is in these logs, we might want to make the parser robust enough to handle nested
/// key-value pairs.


fn parse_audit_record(line: &str) -> Result<AuditRecord, ParseError>{
    // Parse the common fields (type, timestamp, serial number)
    let (preamble, remainder) = parse_preamble(line)?;
    let data = parse_fields(remainder)?;

    Ok( AuditRecord {
        record_type: preamble.record_type,
        timestamp: preamble.timestamp,
        serial: preamble.serial,
        data
    })
}

fn parse_preamble(line: &str) -> Result<(RecordPreamble, &str), ParseError> {
    todo!()
}

fn parse_fields(line: &str) -> Result<RecordData, ParseError> {
    todo!()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_line() {
        let invalid_line = "type=SYSCALL msg=audit(1364481363.243:24287) arch=c000003e syscall"; // missing '=' in last part
        let result = read_to_fields(invalid_line);
        assert!(matches!(result, Err(ParseError::InvalidLine(_))));
    }


    #[test]
    fn test_empty_line() {
        // Empty lines should(?) be treated as invalid.
        let empty_line = "";
        let result = read_to_fields(empty_line);
        assert!(matches!(result, Err(ParseError::InvalidLine(_))));
    }
}
