mod writer;

use crate::config::LogFormat;
use std::fs::File;
use std::path::PathBuf;

const DEFAULT_ACTIVE_DIR: &str = "/var/log/auditrs/active";
const DEFAULT_JOURNAL_DIR: &str = "/var/log/auditrs/journal";
const DEFAULT_ARCHIVE_DIR: &str = "/var/log/auditrs/archive";
const DEFAULT_LOG_FORMAT: LogFormat = LogFormat::Simple;
const DEFAULT_LOG_SIZE: usize = 6 * 1024 * 1024; // 6 MB

/// Main writer for audit logs, handles writing to the active log, journal, and
/// archive. The audit log writer is the responsible for the managing log
/// rotations, enforcing log size limits, and handling long term log storage.
pub struct AuditLogWriter {
    log_format: LogFormat,
    active_directory: PathBuf,
    journal_directory: PathBuf,
    archive_directory: PathBuf,
    log_size: usize,     // size of active log in bytes
    journal_size: usize, // number of logs to keep in journal
    archive_size: usize, // number of logs to keep in archive
    active: AuditActive,
    journal: AuditJournal,
    archive: AuditArchive,
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

#[derive(Debug)]
pub struct AuditArchive {
    paths: Vec<PathBuf>,
}
