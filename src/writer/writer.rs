use super::{
    AuditLogWriter, DEFAULT_DIR, DEFAULT_LOG_SIZE, DEFAULT_OUTPUT_FORMAT, OutputFormat,
};
use anyhow::Result;
use crate::correlator::AuditEvent;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;

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

    fn write_event_legacy(&mut self, event: AuditEvent) -> Result<(), WriteError> {
        let prefix;
        let fields;
        for record in event.records {
            prefix = format!("type={:?} msg=audit({:?}.{:?}:", record.record_type, event.timestamp, event.serial);
            for field in record.fields {
                fields.push_str(format!(" {:?}={:?}", field.0, field.1));
            }
        }
        let line = format!("{}{}", prefix, fields);

        writeln!(self.file_handle, "{}", line).map_err(|_| WriteError::Unknown)?;
        self.file_handle.flush().map_err(|_| WriteError::Unknown)?;
        Ok(())
    }

    fn write_event_simple(&mut self, event: AuditEvent) -> Result<()> {
        writeln!(self.file_handle, "{}", event)?;
        self.file_handle.flush()?;
        Ok(())
    }

    fn write_event_json(&mut self, _event: AuditEvent) -> Result<()> {
        todo!()
    }
}
