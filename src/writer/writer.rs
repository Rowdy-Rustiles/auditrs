use super::{AuditLogWriter, DEFAULT_DIR, DEFAULT_LOG_SIZE, DEFAULT_OUTPUT_FORMAT, OutputFormat};
use crate::correlator::AuditEvent;
use crate::utils::*;
use anyhow::Result;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

impl AuditLogWriter {
    pub fn new() -> anyhow::Result<Self> {
        let log_dir = PathBuf::from(DEFAULT_DIR);
        create_dir_all(&log_dir)?;
        let log_file = log_dir.join("auditrs.log");
        let file_handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)?;
        Ok(Self {
            output_format: DEFAULT_OUTPUT_FORMAT,
            destination: log_dir,
            log_size: DEFAULT_LOG_SIZE,
            file_handle,
        })
    }

    pub fn write_event(&mut self, event: AuditEvent) -> Result<()> {
        match self.output_format {
            OutputFormat::Legacy => self.write_event_legacy(event),
            OutputFormat::Simple => self.write_event_simple(event),
            OutputFormat::Json => self.write_event_json(event),
        }
    }

    fn write_event_legacy(&mut self, event: AuditEvent) -> Result<()> {
        let mut prefix: String = String::new();
        let mut fields: String = String::new();
        for record in event.records {
            prefix.push_str(&format!(
                "type={} msg=audit({}:{}",
                record.record_type.as_audit_str(),
                systemtime_to_timestamp_string(event.timestamp)?,
                event.serial
            ));
            for field in record.fields {
                fields.push_str(&format!(" {}={}", field.0, field.1));
            }
        }
        let line = format!("{}{}", prefix, fields);

        writeln!(self.file_handle, "{}", line)?;
        self.file_handle.flush()?;
        Ok(())
    }

    fn write_event_simple(&mut self, event: AuditEvent) -> Result<()> {
        writeln!(self.file_handle, "{}", event)?;
        self.file_handle.flush()?;
        Ok(())
    }

    fn write_event_json(&mut self, event: AuditEvent) -> Result<()> {
        let res = serde_json::to_string(&event)?;
        writeln!(self.file_handle, "{}", res)?;
        self.file_handle.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::parser::ParsedAuditRecord;
    use crate::parser::RecordType;
    use std::collections::HashMap;
    use super::*;
    fn generate_test_event() -> AuditEvent {
        let sample_timestamp = timestamp_string_to_systemtime("1768231884.588").unwrap();
        let record_1 = ParsedAuditRecord {
            record_type: RecordType::Syscall,
            timestamp: sample_timestamp,
            serial: 1151,
            fields: ,
        }
        let record_2 = ParsedAuditRecord {
            record_type: RecordType::Cwd,
            timestamp: sample_timestamp,
            serial: 1151,
            fields: HashMap::from([("cwd", "/")]),
        }
        let record_3 = ParsedAuditRecord {
            record_type: RecordType::Path,
            timestamp: sample_timestamp,
            serial: 1151,
            fields: ,
        }
        let record_4 = ParsedAuditRecord {
            record_type: RecordType::Proctitle,
            timestamp: sample_timestamp,
            serial: 1151,
            fields: ,
        }

        let event = AuditEvent {
            timestamp: sample_timestamp,
            serial: 1151,
            record_count: 4,
            records: vec![record_1, record_2, record_3, record_4],
        }
    }
    #[test]
    fn test_write_legacy() {
        let event = generate_test_event();

    }

    #[test]
    fn test_write_simple() {

    }

    #[test]
    fn test_write_json() {

    }

}