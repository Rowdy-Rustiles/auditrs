/*

To be implemented/structured

*/

mod writer;

use std::fs::File;
use std::path::PathBuf;
// Will be moved to a centralized config

const DEFAULT_DIR: &str = "/home/ec2-user/auditrs/var/log/auditrs/";
// const DEFAULT_DIR: &str = "/var/log/auditrs/";
const DEFAULT_OUTPUT_FORMAT: OutputFormat = OutputFormat::Simple;
const DEFAULT_LOG_SIZE: usize = 6 * 1024 * 1024; // 6 MB

pub struct AuditLogWriter {
    output_format: OutputFormat,
    destination: PathBuf,
    log_size: usize,
    file_handle: File,
}

#[derive(Debug)]
pub enum WriteError {
    Unknown,
}

enum OutputFormat {
    Legacy,
    Simple,
    Json,
}
