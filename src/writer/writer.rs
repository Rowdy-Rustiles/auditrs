use super::{
    AuditLogWriter, DEFAULT_DIR, DEFAULT_LOG_SIZE, DEFAULT_OUTPUT_FORMAT, OutputFormat,
};
use anyhow::Result;
use crate::correlator::AuditEvent;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;
use crate::utils::*;

impl AuditLogWriter {
    pub fn new() -> Self {
        let log_dir = PathBuf::from(DEFAULT_DIR);
        create_dir_all(&log_dir).expect("failed to create log directory");
        let log_file = log_dir.join("auditrs.log");
        let file_handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .unwrap_or_else(|e| panic!("failed to open log file {}: {}", log_file.display(), e));
        Self {
            output_format: DEFAULT_OUTPUT_FORMAT,
            destination: log_dir,
            log_size: DEFAULT_LOG_SIZE,
            file_handle,
        }
    }

    pub fn write_event(&mut self, event: AuditEvent) -> Result<()> {
        match self.output_format {
            OutputFormat::Legacy => self.write_event_legacy(event),
            OutputFormat::Simple => self.write_event_simple(event),
            OutputFormat::Json => self.write_event_json(event),
        }
    }

    fn write_event_legacy(&mut self, event: AuditEvent) -> Result<()> {
        let prefix;
        let fields;
        for record in event.records {
            prefix = format!("type={} msg=audit({}:{}",
                             record.record_type.as_audit_str(),
                             systemtime_to_timestamp_string(event.timestamp),
                             event.serial);
            for field in record.fields {
                fields.push_str(format!(" {}={}", field.0, field.1));
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
        let timestamp = format!("\"timestamp\": \"{}\"", systemtime_to_utc_string(event.timestamp));
        let serial = format!("\"serial\": \"{}\"", event.serial);

        // writeln!(self.file_handle, );
        Ok(())
    }
}
