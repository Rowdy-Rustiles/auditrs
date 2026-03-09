mod writer;

use crate::config::LogFormat;
use std::fs::File;
use std::path::PathBuf;

const DEFAULT_ACTIVE_DIR: &str = "/var/log/auditrs/active";
const DEFAULT_JOURNAL_DIR: &str = "/var/log/auditrs/journal";
const DEFAULT_ARCHIVE_DIR: &str = "/var/log/auditrs/archive";
const DEFAULT_OUTPUT_FORMAT: LogFormat = LogFormat::Simple;
const DEFAULT_LOG_SIZE: usize = 6 * 1024 * 1024; // 6 MB

pub struct AuditLogWriter {
    output_format: LogFormat,
    destination: PathBuf,
    log_size: usize,
    file_handle: File,
}
