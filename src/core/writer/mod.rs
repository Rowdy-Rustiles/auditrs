//! Writer module for auditrs, responsible for writing events to disk.

mod writer;

use crate::config::LogFormat;
use crate::state::*;
use std::fs::File;
use std::path::PathBuf;

const DEFAULT_ACTIVE_DIR: &str = "/var/log/auditrs/active";
const DEFAULT_JOURNAL_DIR: &str = "/var/log/auditrs/journal";
const DEFAULT_PRIMARY_DIR: &str = "/var/log/auditrs/primary";
const DEFAULT_LOG_FORMAT: LogFormat = LogFormat::Simple;
const DEFAULT_LOG_SIZE: usize = 6 * 1024 * 1024; // 6 MB

/// Main writer for audit logs, handles writing to the active log, journal, and
/// primary store. The audit log writer is responsible for managing log
/// rotations, enforcing log size limits, and handling long term log storage.
pub struct AuditLogWriter {
    /// The log format to use for the active log.
    log_format: LogFormat,
    /// The directory to write the active log to.
    active_directory: PathBuf,
    /// The directory to write the journal to.
    journal_directory: PathBuf,
    /// The directory to write the primary log to.
    primary_directory: PathBuf,
    /// The size of the active log in bytes.
    log_size: usize,
    /// The size of the journal in bytes.
    journal_size: usize,
    /// The size of the primary log in bytes.
    primary_size: usize,
    /// The active log.
    active: AuditActive,
    /// The journal.
    journal: AuditJournal,
    /// The primary log.
    primary: AuditPrimary,
    /// The state of the auditrs configuration.
    state: State,
}

/// Represents the active log immediately written to by the daemon.
/// Since writes are frequent, this struct contains a file handle for
/// efficient writing.
#[derive(Debug)]
pub struct AuditActive {
    file_handle: File,
    path: PathBuf,
    size: usize,
}

/// Represents audit journal, holding `journal_size` number of logs.
/// Journal entries are active logs have been flushed to the journal
/// either by reaching the `log_size` limit or because of a `log_format` change.
#[derive(Debug)]
pub struct AuditJournal {
    paths: Vec<PathBuf>,
}

/// Represents long-term primary storage, holding `primary_size` number of logs.
/// Primary entries are journals that have been flushed to primary storage.
/// In the future, a custom rotation policy for primary storage may be added.
#[derive(Debug)]
pub struct AuditPrimary {
    paths: Vec<PathBuf>,
}
