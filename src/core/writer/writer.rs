//! Writer module implementation.
//!
//! This module is responsible for persisting correlated `AuditEvent`s to
//! disk. It encapsulates the logic for:
//!
//! - **Active logs**: the currently open log file that receives new events.
//! - **Journal rotation**: moving full active logs into a bounded journal
//!   directory and pruning old entries.
//! - **Primary logs**: optional, long-lived logs that receive a subset of
//!   events (e.g. those matching configured watches).
//! - **Dynamic reconfiguration**: reacting to changes in `AuditConfig` and
//!   `Rules` so that directory paths, formats, and watch behavior can be
//!   updated at runtime without restarting the daemon.

use anyhow::Result;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;

use crate::config::{AuditConfig, LogFormat};
use crate::core::{
    correlator::AuditEvent,
    writer::{AuditActive, AuditJournal, AuditLogWriter, AuditPrimary},
};
use crate::state::{Rules, State};
use crate::utils::{current_utc_string, systemtime_to_timestamp_string};

// TODO: this whole module needs to be closely looked over, a lot of IO is
// happening here and we want to make sure its not wasting resources.
impl AuditLogWriter {
    /// Constructs a new `AuditLogWriter` using the current application state.
    ///
    /// This function:
    ///
    /// - Loads `State` from disk to obtain the initial `AuditConfig`.
    /// - Ensures that the configured active, journal, and primary directories
    ///   exist, creating them if necessary.
    /// - Opens (or creates) the active log file and initializes its size.
    /// - Immediately checks whether the active log already exceeds the
    ///   configured size limit and rotates it if needed.
    ///
    /// **Parameters:**
    ///
    /// This constructor takes an optional `State` parameter which can be passed
    /// in for unit testing but should be otherwise loaded from disk.
    pub fn new(state: Option<State>) -> anyhow::Result<Self> {
        let state = if let Some(state) = state {
            state
        } else {
            State::load_state()?
        };
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
            state: state,
        };
        // Immediately check if the log file is too large and create a new one if it is
        // This is needed in the case of a reboot caused by a config log size change
        writer.check_log_size()?;
        Ok(writer)
    }

    /// Writes a single correlated `AuditEvent` to the active log (and
    /// optionally to the primary log).
    ///
    /// The concrete output format is determined by `log_format`:
    ///
    /// - `LogFormat::Legacy`: legacy kernel-style log line.
    /// - `LogFormat::Simple`: human-readable summary via `Display` on
    ///   `AuditEvent`.
    /// - `LogFormat::Json`: JSON representation (not yet implemented).
    ///
    /// After writing, this function also enforces the active log size limit,
    /// rotating the file into the journal when necessary.
    ///
    /// **Parameters:**
    ///
    /// * `event`: The `AuditEvent` to be written.
    pub fn write_event(&mut self, event: AuditEvent) -> Result<()> {
        let write_primary = self.check_watch_events(&event);
        match self.log_format {
            LogFormat::Legacy => self.write_event_legacy(event, write_primary)?,
            LogFormat::Simple => self.write_event_simple(event, write_primary)?,
            LogFormat::Json => self.write_event_json(event, write_primary)?,
        }
        // TODO: We should be checking to see if writing an event would exceed the log
        // size limit. if so, log rotation should be triggered then rather than
        // after the fact.
        self.check_log_size()
    }

    /// Writes an `AuditEvent` using the legacy audit log format.
    ///
    /// The output takes the form:
    /// ```ignore
    /// type=... msg=audit(<timestamp>:<serial>): key1=val1 key2=val2 ...
    /// ```
    ///
    /// **Parameters:**
    ///
    /// * `event`: The correlated `AuditEvent` to render.
    /// * `write_primary`: When `true`, the same formatted line is also written
    ///   to the primary log in addition to the active log.
    fn write_event_legacy(&mut self, event: AuditEvent, write_primary: bool) -> Result<()> {
        let mut event_str: String = String::new();
        for record in event.records {
            let mut prefix: String = String::new();
            let mut fields: String = String::new();
            prefix.push_str(&format!(
                "type={} msg=audit({}:{}):",
                record.record_type.as_audit_str(),
                systemtime_to_timestamp_string(event.timestamp)?,
                event.serial
            ));
            for field in record.fields {
                fields.push_str(&format!(" {}={}", field.0, field.1));
            }
            event_str.push_str(&format!("{}{}\n", prefix, fields));
        }

        write!(self.active.file_handle, "{}", event_str)?;
        self.active.file_handle.flush()?;

        if write_primary {
            self.write_primary(event_str)?;
        }

        Ok(())
    }

    /// Writes an `AuditEvent` using the "simple" format.
    ///
    /// The output takes the form:
    /// ```ignore
    /// [UTC timestamp][Record Count: <number of records>][Audit Event Group <serial>]:
    ///     Record: <record type> <record data>
    ///     ...
    ///     Record: <record type> <record data>
    /// ```
    /// This format delegates to the `Display` implementation of `AuditEvent`,
    /// producing a concise, human-readable representation.
    ///
    /// **Parameters:**
    ///
    /// * `event`: The event to format and write.
    /// * `write_primary`: When `true`, also mirrors the simple-formatted event
    ///   into the primary log.
    fn write_event_simple(&mut self, event: AuditEvent, write_primary: bool) -> Result<()> {
        let event_str = format!("{}\n", event);
        write!(self.active.file_handle, "{}", event_str)?;
        self.active.file_handle.flush()?;

        if write_primary {
            self.write_primary(event_str)?;
        }

        Ok(())
    }

    /// Writes an `AuditEvent` as JSON.
    ///
    /// This is a placeholder for a future JSON log format implementation.
    ///
    /// **Parameters:**
    ///
    /// * `event`: The event to serialize as JSON.
    /// * `write_primary`: When `true`, the JSON representation will also be
    ///   written to the primary log.
    fn write_event_json(&mut self, _event: AuditEvent, _write_primary: bool) -> Result<()> {
        todo!();
        // let timestamp = format!(
        //     "\"timestamp\": \"{}\"",
        //     systemtime_to_utc_string(event.timestamp)
        // );
        // let serial = format!("\"serial\": \"{}\"", event.serial);

        // let res = format!("");
        // writeln!(self.active.file_handle, "{}", res)?;

        // if write_primary {
        //     self.write_primary(res)?;
        // }

        // Ok(())
    }
    /// Appends a single log line to the primary log.
    ///
    /// If no primary log file exists yet for the current configuration, this
    /// function will create one with a timestamped name and track it in the
    /// writer's `primary` state.
    ///
    /// **Parameters:**
    ///
    /// * `line`: Fully formatted log line to be appended to the primary log.
    fn write_primary(&mut self, line: String) -> Result<()> {
        // Get the latest primary log path, creating one if it doesn't exist yet.
        let path: PathBuf = if let Some(last) = self.primary.paths.last() {
            last.clone()
        } else {
            let new_path = self.primary_directory.join(format!(
                "auditrs_primary_{}.{}",
                current_utc_string(),
                self.log_format.get_extension()
            ));
            self.primary.paths.push(new_path.clone());
            new_path
        };

        let mut file_handle = OpenOptions::new().create(true).append(true).open(&path)?;
        write!(file_handle, "{}", line)?;
        file_handle.flush()?;
        Ok(())
    }

    /// Check if the audit event contains a record with a key identifier that
    /// matches a configured watch.
    ///
    /// This helper is used to decide whether an event should also be written
    /// to the primary log, based on watch keys defined in the current `Rules`.
    ///
    /// **Parameters:**
    ///
    /// * `event`: The `AuditEvent` being inspected for matching watch keys.
    fn check_watch_events(&self, event: &AuditEvent) -> bool {
        let watches = &self.state.rules.watches.0;

        // Return true if any record in this event has a `key` field that matches
        // the `key` of any configured watch.
        for record in &event.records {
            if let Some(record_key) = record.fields.get("key") {
                if watches.iter().any(|watch| &watch.key == record_key) {
                    return true;
                }
            }
        }

        false
    }

    /// Returns the filesystem path of the current active log file.
    fn active_log_path(&self) -> PathBuf {
        self.active.path.clone()
    }

    /// Check log size for log rotation.
    ///
    /// If the active log exceeds the configured `log_size`, this function
    /// rotates it into the journal and opens a fresh active log file.
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
    ///
    /// This moves the existing active log file into the journal directory,
    /// tracks it in memory, and enforces the maximum number of journal files
    /// by deleting the oldest when necessary.
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

    /// Reload writer settings from a new `AuditConfig`.
    ///
    /// If `log_format` or any directory changed, rotate the current active log
    /// into the journal so the old file stays coherent, then reopen a fresh
    /// active file using the new directory and extension.
    ///
    /// **Parameters:**
    ///
    /// * `cfg`: The new `AuditConfig` to reload from.
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

    /// Reload rules (filters + watches) used by the writer.
    ///
    /// Currently this primarily affects which events are written to the primary
    /// log, based on the configured watches.
    pub fn reload_rules(&mut self, rules: &Rules) {
        self.state.rules = rules.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::parser::{ParsedAuditRecord, RecordType},
        rules::{AuditWatch, Filters, WatchAction, Watches},
    };
    use serial_test::serial;
    use std::{collections::HashMap, path::Path, time::SystemTime};

    fn get_state() -> State {
        State {
            config: AuditConfig {
                active_directory: ("./tmp/auditrs/active").to_string(),
                journal_directory: "./tmp/auditrs/journal".to_string(),
                primary_directory: "./tmp/auditrs/primary".to_string(),
                log_size: 1024,
                journal_size: 10,
                log_format: LogFormat::Legacy,
                primary_size: 1024,
            },
            rules: Rules {
                filters: Filters(Vec::new()),
                watches: Watches(vec![AuditWatch {
                    key: "auditrs_watch_1234567890".to_string(),
                    path: PathBuf::from("./tmp/auditrs/primary/auditrs_watch_1234567890.log"),
                    actions: vec![WatchAction::Read, WatchAction::Write, WatchAction::Execute],
                    recursive: true,
                }]),
            },
        }
    }

    fn create_event(multiple_records: bool) -> AuditEvent {
        let timestamp = SystemTime::UNIX_EPOCH;

        AuditEvent {
            timestamp: timestamp,
            serial: 1,
            record_count: if multiple_records { 2 } else { 1 },
            records: if multiple_records {
                vec![
                    ParsedAuditRecord {
                        timestamp: timestamp,
                        serial: 1,
                        record_type: RecordType::AddGroup,
                        fields: HashMap::from([("key".to_string(), "value".to_string())]),
                    },
                    ParsedAuditRecord {
                        timestamp: timestamp,
                        serial: 1,
                        record_type: RecordType::DelGroup,
                        fields: HashMap::from([("key_2".to_string(), "value_2".to_string())]),
                    },
                ]
            } else {
                vec![ParsedAuditRecord {
                    timestamp: timestamp,
                    serial: 1,
                    record_type: RecordType::AddGroup,
                    fields: HashMap::from([("key".to_string(), "value".to_string())]),
                }]
            },
        }
    }

    fn create_event_with_watch_key() -> AuditEvent {
        let timestamp = SystemTime::UNIX_EPOCH;
        AuditEvent {
            timestamp: timestamp,
            serial: 1,
            record_count: 1,
            records: vec![ParsedAuditRecord {
                timestamp: timestamp,
                serial: 1,
                record_type: RecordType::AddGroup,
                fields: HashMap::from([(
                    "key".to_string(),
                    "auditrs_watch_1234567890".to_string(),
                )]),
            }],
        }
    }

    fn cleanup() {
        let _ = std::fs::remove_dir_all(Path::new("./tmp/auditrs"));
    }

    #[test]
    #[serial(writer)]
    fn writer_new() {
        let state = get_state();
        let writer = AuditLogWriter::new(Some(state)).unwrap();
        assert!(Path::new("./tmp/auditrs/active/auditrs.log").exists());
        assert!(Path::new("./tmp/auditrs/journal").is_dir());
        assert!(Path::new("./tmp/auditrs/primary").is_dir());
        assert!(Path::new("./tmp/auditrs/active").is_dir());
        assert_eq!(
            writer.active.path,
            PathBuf::from("./tmp/auditrs/active/auditrs.log")
        );
        assert_eq!(writer.journal.paths.len(), 0);
        assert_eq!(writer.primary.paths.len(), 0);
        assert_eq!(writer.log_size, 1024);
        assert_eq!(writer.journal_size, 10);
        assert_eq!(writer.primary_size, 1024);
        assert_eq!(writer.log_format, LogFormat::Legacy);
        cleanup();
    }

    #[test]
    #[serial(writer)]
    fn write_event_legacy() {
        let state = get_state();
        let mut writer = AuditLogWriter::new(Some(state)).unwrap();
        let event = create_event(false);
        writer.write_event(event).unwrap();
        assert!(Path::new("./tmp/auditrs/active/auditrs.log").exists());
        let contents =
            std::fs::read_to_string(Path::new("./tmp/auditrs/active/auditrs.log")).unwrap();
        assert_eq!(contents, "type=ADD_GROUP msg=audit(0.000:1): key=value\n");
        cleanup();
    }

    #[test]
    #[serial(writer)]
    /// Test an event with multiple records within it. Legacy formatting does
    /// not correlate records so those should be written as disjoint items.
    fn write_event_legacy_multiple_records() {
        let state = get_state();
        let mut writer = AuditLogWriter::new(Some(state)).unwrap();
        let event = create_event(true);
        writer.write_event(event).unwrap();
        assert!(Path::new("./tmp/auditrs/active/auditrs.log").exists());
        let contents =
            std::fs::read_to_string(Path::new("./tmp/auditrs/active/auditrs.log")).unwrap();
        assert_eq!(
            contents,
            "type=ADD_GROUP msg=audit(0.000:1): key=value\ntype=DEL_GROUP msg=audit(0.000:1): key_2=value_2\n"
        );
        cleanup();
    }

    #[test]
    #[serial(writer)]
    /// Test writing multiple events and records.
    fn write_event_legacy_multiple_events() {
        let state = get_state();
        let mut writer = AuditLogWriter::new(Some(state)).unwrap();
        let event = create_event(false);
        // Write multiple events to the active log
        for _ in 0..10 {
            writer.write_event(event.clone()).unwrap();
        }
        assert!(Path::new("./tmp/auditrs/active/auditrs.log").exists());
        let contents =
            std::fs::read_to_string(Path::new("./tmp/auditrs/active/auditrs.log")).unwrap();
        assert_eq!(
            contents,
            "type=ADD_GROUP msg=audit(0.000:1): key=value\n".repeat(10)
        );
        cleanup();
    }

    #[test]
    #[serial(writer)]
    fn write_event_legacy_mixed_items() {
        let state = get_state();
        let mut writer = AuditLogWriter::new(Some(state)).unwrap();
        let event = create_event(false);
        let event_2 = create_event(true);
        writer.write_event(event).unwrap();
        writer.write_event(event_2).unwrap();
        assert!(Path::new("./tmp/auditrs/active/auditrs.log").exists());
        let contents =
            std::fs::read_to_string(Path::new("./tmp/auditrs/active/auditrs.log")).unwrap();
        assert_eq!(
            contents,
            "type=ADD_GROUP msg=audit(0.000:1): key=value\ntype=ADD_GROUP msg=audit(0.000:1): key=value\ntype=DEL_GROUP msg=audit(0.000:1): key_2=value_2\n"
        );
        cleanup();
    }

    #[test]
    #[serial(writer)]
    fn write_event_simple() {
        let mut state = get_state();
        state.config.log_format = LogFormat::Simple;
        let mut writer = AuditLogWriter::new(Some(state)).unwrap();
        let event = create_event(false);
        writer.write_event(event).unwrap();
        assert!(Path::new("./tmp/auditrs/active/auditrs.slog").exists());
        let contents =
            std::fs::read_to_string(Path::new("./tmp/auditrs/active/auditrs.slog")).unwrap();
        assert_eq!(
            contents,
            "[1970-01-01T00:00:00.000Z][Record Count: 1] Audit Event Group 1:\n\tRecord: ParsedAuditRecord { record_type: AddGroup, timestamp: SystemTime { tv_sec: 0, tv_nsec: 0 }, serial: 1, fields: {\"key\": \"value\"} }\n\n"
        );
        cleanup();
    }

    #[test]
    #[serial(writer)]
    fn write_event_simple_multiple_records() {
        let mut state = get_state();
        state.config.log_format = LogFormat::Simple;
        let mut writer = AuditLogWriter::new(Some(state)).unwrap();
        let event = create_event(true);
        writer.write_event(event).unwrap();
        assert!(Path::new("./tmp/auditrs/active/auditrs.slog").exists());
        let contents =
            std::fs::read_to_string(Path::new("./tmp/auditrs/active/auditrs.slog")).unwrap();
        assert_eq!(
            contents,
            "[1970-01-01T00:00:00.000Z][Record Count: 2] Audit Event Group 1:\n\tRecord: ParsedAuditRecord { record_type: AddGroup, timestamp: SystemTime { tv_sec: 0, tv_nsec: 0 }, serial: 1, fields: {\"key\": \"value\"} }\n\tRecord: ParsedAuditRecord { record_type: DelGroup, timestamp: SystemTime { tv_sec: 0, tv_nsec: 0 }, serial: 1, fields: {\"key_2\": \"value_2\"} }\n\n"
        );
        cleanup();
    }

    #[test]
    #[serial(writer)]
    /// This test represents an impossible state, as the correlator should be
    /// grouping these events into a single event. However, for the purpose
    /// of testing multiple events, this is valid and represents the expected
    /// formatting of multiple disjoint events.
    fn write_event_simple_multiple_events() {
        let mut state = get_state();
        state.config.log_format = LogFormat::Simple;
        let mut writer = AuditLogWriter::new(Some(state)).unwrap();
        let event = create_event(false);
        for _ in 0..4 {
            writer.write_event(event.clone()).unwrap();
        }
        assert!(Path::new("./tmp/auditrs/active/auditrs.slog").exists());
        let contents =
            std::fs::read_to_string(Path::new("./tmp/auditrs/active/auditrs.slog")).unwrap();
        assert_eq!(contents, "[1970-01-01T00:00:00.000Z][Record Count: 1] Audit Event Group 1:\n\tRecord: ParsedAuditRecord { record_type: AddGroup, timestamp: SystemTime { tv_sec: 0, tv_nsec: 0 }, serial: 1, fields: {\"key\": \"value\"} }\n\n".repeat(4));
        cleanup();
    }

    #[test]
    #[serial(writer)]
    fn write_event_simple_mixed_items() {
        let mut state = get_state();
        state.config.log_format = LogFormat::Simple;
        let mut writer = AuditLogWriter::new(Some(state)).unwrap();
        let event = create_event(false);
        let event_2 = create_event(true);
        writer.write_event(event).unwrap();
        writer.write_event(event_2).unwrap();
        assert!(Path::new("./tmp/auditrs/active/auditrs.slog").exists());
        let contents =
            std::fs::read_to_string(Path::new("./tmp/auditrs/active/auditrs.slog")).unwrap();
        assert_eq!(
            contents,
            "[1970-01-01T00:00:00.000Z][Record Count: 1] Audit Event Group 1:\n\tRecord: ParsedAuditRecord { record_type: AddGroup, timestamp: SystemTime { tv_sec: 0, tv_nsec: 0 }, serial: 1, fields: {\"key\": \"value\"} }\n\n[1970-01-01T00:00:00.000Z][Record Count: 2] Audit Event Group 1:\n\tRecord: ParsedAuditRecord { record_type: AddGroup, timestamp: SystemTime { tv_sec: 0, tv_nsec: 0 }, serial: 1, fields: {\"key\": \"value\"} }\n\tRecord: ParsedAuditRecord { record_type: DelGroup, timestamp: SystemTime { tv_sec: 0, tv_nsec: 0 }, serial: 1, fields: {\"key_2\": \"value_2\"} }\n\n"
        );
        cleanup();
    }

    #[test]
    #[serial(writer)]
    fn write_legacy_to_primary() {
        let state = get_state();
        let mut writer = AuditLogWriter::new(Some(state)).unwrap();
        let event = create_event_with_watch_key();
        writer.write_event(event).unwrap();
        let primary_path = writer.primary.paths.last().unwrap();
        let contents = std::fs::read_to_string(primary_path).unwrap();
        assert_eq!(contents, "type=ADD_GROUP msg=audit(0.000:1): key=auditrs_watch_1234567890\n");
        cleanup();
    }
}
