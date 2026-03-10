//! Writer module implementation.

use super::{AuditActive, AuditJournal, AuditLogWriter, AuditPrimary};
use crate::config::AuditConfig;
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

// TODO: this whole module needs to be closely looked over, a lot of IO is
// happening here and we want to make sure its not wasting resources.
impl AuditLogWriter {
    pub fn new() -> anyhow::Result<Self> {
        let state = State::load_state()?;
        let config = &state.config;

        let active_directory = PathBuf::from(&config.active_directory);
        let journal_directory = PathBuf::from(&config.journal_directory);
        let primary_directory = PathBuf::from(&config.primary_directory);

        // Ensure directories exist
        create_dir_all(&active_directory)?;
        create_dir_all(&journal_directory)?;
        create_dir_all(&primary_directory)?;

        // Open (or create) the active log file
        let active_path =
            active_directory.join(format!("auditrs.{}", config.log_format.get_extension()));
        let file_handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active_path)?;
        let active_size = std::fs::metadata(&active_path)
            .map(|m| m.len() as usize)
            .unwrap_or(0);

        let mut writer = Self {
            log_format: config.log_format,
            active_directory,
            journal_directory,
            primary_directory,
            log_size: config.log_size,
            journal_size: config.journal_size,
            primary_size: config.primary_size,
            active: AuditActive {
                file_handle,
                path: active_path,
                size: active_size,
            },
            journal: AuditJournal { paths: Vec::new() },
            primary: AuditPrimary { paths: Vec::new() },
        };
        // Immediately check if the log file is too large and create a new one if it is
        // This is needed in the case of a reboot caused by a config log size change
        writer.check_log_size()?;
        Ok(writer)
    }

    pub fn write_event(&mut self, event: AuditEvent) -> Result<()> {
        match self.log_format {
            LogFormat::Legacy => self.write_event_legacy(event)?,
            LogFormat::Simple => self.write_event_simple(event)?,
            LogFormat::Json => self.write_event_json(event)?,
        }
        // TODO: We should be checking to see if writing an event would exceed the log
        // size limit. if so, log rotation should be triggered then rather than
        // after the fact.
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

        writeln!(self.active.file_handle, "{}", line)?;
        self.active.file_handle.flush()?;
        Ok(())
    }

    fn write_event_simple(&mut self, event: AuditEvent) -> Result<()> {
        writeln!(self.active.file_handle, "{}", event)?;
        self.active.file_handle.flush()?;
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
        writeln!(self.active.file_handle, "{}", res)?;
        Ok(())
    }

    fn active_log_path(&self) -> PathBuf {
        self.active.path.clone()
    }

    /// Check log size for log rotation. If the active log exceeds `log_size`,
    /// rotate it into the journal and open a fresh active log file.
    fn check_log_size(&mut self) -> Result<()> {
        let active_log = self.active_log_path();
        let file_size = match std::fs::metadata(&active_log) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        self.active.size = file_size as usize;

        if file_size > self.log_size as u64 {
            self.rotate_active_into_journal()?;
            self.open_fresh_active_for_current_settings()?;
        }

        Ok(())
    }

    /// Rotate the current active log into the journal.
    pub fn rotate_active_into_journal(&mut self) -> Result<()> {
        let active_path = self.active.path.clone();
        let ext = self.log_format.get_extension();

        // New journal file name
        let journal_index = self.journal.paths.len();
        let journal_path = self.journal_directory.join(format!(
            "auditrs_journal_{}_{}.{}",
            journal_index,
            current_utc_string(),
            ext
        ));

        // Move active log into journal
        std::fs::rename(&active_path, &journal_path)?;

        // Track journal entry in memory
        self.journal.paths.push(journal_path);

        // Enforce journal size limit. For now, excess entries are deleted;
        // a future implementation may move them into primary storage.
        while self.journal.paths.len() > self.journal_size {
            let oldest = self.journal.paths.remove(0);
            let _ = std::fs::remove_file(oldest);
        }

        Ok(())
    }

    /// Open a fresh active log file using the writer's current
    /// directory and log format settings.
    fn open_fresh_active_for_current_settings(&mut self) -> Result<()> {
        let new_active_path = self
            .active_directory
            .join(format!("auditrs.{}", self.log_format.get_extension()));
        let new_active_handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&new_active_path)?;

        self.active.path = new_active_path;
        self.active.file_handle = new_active_handle;
        self.active.size = std::fs::metadata(&self.active.path)
            .map(|m| m.len() as usize)
            .unwrap_or(0);

        Ok(())
    }

    /// Reload writer settings from a new config
    ///
    /// If `log_format` or any directory changed, rotate the current active log
    /// into the journal so the old file stays coherent, then reopen a fresh
    /// active file using the new directory and extension.
    pub fn reload_config(&mut self, cfg: &AuditConfig) -> Result<()> {
        let old_format = self.log_format;
        let old_active_dir = self.active_directory.clone();
        let old_journal_dir = self.journal_directory.clone();
        let old_primary_dir = self.primary_directory.clone();

        let new_active_dir = PathBuf::from(&cfg.active_directory);
        let new_journal_dir = PathBuf::from(&cfg.journal_directory);
        let new_primary_dir = PathBuf::from(&cfg.primary_directory);
        let new_format = cfg.log_format;

        // Apply size and toggle changes
        self.log_size = cfg.log_size;
        self.journal_size = cfg.journal_size;
        self.primary_size = cfg.primary_size;

        // Ensure the (possibly new) directories exist
        create_dir_all(&new_active_dir)?;
        create_dir_all(&new_journal_dir)?;
        create_dir_all(&new_primary_dir)?;

        let format_changed = new_format != old_format;
        let active_dir_changed = new_active_dir != old_active_dir;
        let journal_dir_changed = new_journal_dir != old_journal_dir;
        let primary_dir_changed = new_primary_dir != old_primary_dir;

        if format_changed || active_dir_changed || journal_dir_changed || primary_dir_changed {
            let _ = self.rotate_active_into_journal();
        }

        // Apply new settings
        self.log_format = new_format;
        self.active_directory = new_active_dir;
        self.journal_directory = new_journal_dir;
        self.primary_directory = new_primary_dir;

        // Reopen active file at new location/extension using updated settings
        self.open_fresh_active_for_current_settings()
    }
}
