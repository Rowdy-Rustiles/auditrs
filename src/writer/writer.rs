use super::{AuditLogWriter, DEFAULT_ACTIVE_DIR, DEFAULT_LOG_SIZE, DEFAULT_OUTPUT_FORMAT};
use crate::config::LogFormat;
use crate::config::State;
use crate::correlator::AuditEvent;
use crate::utils::*;
use anyhow::Result;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::os::unix::fs::DirEntryExt;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

impl AuditLogWriter {
    pub fn new() -> anyhow::Result<Self> {
        let state = State::load_state()?;
        let log_dir = PathBuf::from(state.config.output_directory);
        create_dir_all(&log_dir)?;
        let log_file = log_dir.join(format!(
            "auditrs.{}",
            state.config.log_format.get_extension()
        ));
        let file_handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)?;
        let mut writer = Self {
            output_format: state.config.log_format,
            destination: log_dir,
            log_size: state.config.log_size,
            file_handle,
        };
        // Immediately check if the log file is too large and create a new one if it is
        // This is needed in the case of a reboot caused by a config log size change
        writer.check_log_size()?;
        Ok(writer)
    }

    pub fn write_event(&mut self, event: AuditEvent) -> Result<()> {
        match self.output_format {
            LogFormat::Legacy => self.write_event_legacy(event)?,
            LogFormat::Simple => self.write_event_simple(event)?,
            LogFormat::Json => self.write_event_json(event)?,
        }
        self.check_log_size()
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
        todo!();
        let timestamp = format!(
            "\"timestamp\": \"{}\"",
            systemtime_to_utc_string(event.timestamp)
        );
        let serial = format!("\"serial\": \"{}\"", event.serial);

        let res = format!("");
        writeln!(self.file_handle,);
        Ok(())
    }

    fn active_log_path(&self) -> PathBuf {
        self.destination
            .join(format!("auditrs.{}", self.output_format.get_extension()))
    }

    /// Check log size for log rotation, needs to be rewritten with proper log rotation logic
    /// Overly complicated, needs to be rewritten and split
    fn check_log_size(&mut self) -> Result<()> {
        let active_log = self.active_log_path();
        let file_size = match std::fs::metadata(&active_log) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if file_size > self.log_size as u64 {
            let ext = &self.output_format.get_extension();
            let archive_counter = std::fs::read_dir(&self.destination)?
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some(ext))
                .count();
            let archived_log = self.destination.join(format!(
                "auditrs_{}_{}.{}",
                archive_counter,
                current_utc_string(),
                self.output_format.get_extension()
            ));
            std::fs::rename(&active_log, &archived_log)?;
            self.file_handle = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&active_log)?;
        }
        Ok(())
    }
}
