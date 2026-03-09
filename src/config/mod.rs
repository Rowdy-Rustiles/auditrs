pub mod config;
pub mod filters;
pub mod input_utils;
pub mod state;

pub use config::{get_config, load_config, set_config};
pub use filters::{
    add_filter_interactive, dump_filters, get_filters, import_filters, load_filters,
    remove_filter_interactive, update_filter_interactive,
};
use serde::Deserialize;

pub const MINIMUM_LOG_SIZE: usize = 8096; // 8 KB
pub const MINIMUM_JOURNAL_SIZE: usize = 16; // 16 logs
pub const MINIMUM_ARCHIVE_SIZE: usize = 16; // 16 logs
pub const CONFIG_DIR: &str = "/etc/auditrs";
pub const CONFIG_FILE: &str = "/etc/auditrs/config.toml";
pub const FILTERS_FILE: &str = "/etc/auditrs/filters.toml";
pub const FILTER_FILE_EXTENSIONS: &[&str] = &["toml", "ars"];
pub const ACTIONS: &[&str] = &["allow", "block"];
pub const LOG_FORMATS: &[&str] = &["Legacy", "Simple", "Json"];
pub const DEFAULT_CONFIG: &str = r#"[meta]
version = "0.3.0"

[settings]
log_format = "legacy"
active_directory = "/var/log/auditrs/active"
archive_directory = "/var/log/auditrs/archive"
journal_directory = "/var/log/auditrs/journal"
log_size = 4194304
journal_size = 16
archive_size = 16
"#;

#[derive(Debug)]
pub struct State {
    pub(crate) config: AuditConfig,
    pub(crate) filters: Filters,
}

// Thin audit filters wrapper for printing extensibility
#[derive(Debug, Deserialize)]
pub(crate) struct Filters(Vec<AuditFilter>);

#[derive(Debug, Deserialize)]
pub struct AuditFilter {
    pub record_type: String,
    pub action: String,
}

#[derive(Debug, Deserialize)]
pub struct AuditConfig {
    #[serde(alias = "output_directory")]
    pub active_directory: String,
    pub log_size: usize,
    pub log_format: LogFormat,
    pub journal_directory: String,
    pub journal_size: usize,
    pub archive_directory: String,
    pub archive_size: usize,
}

#[derive(Debug, Deserialize)]
pub enum GetConfigVariables {
    LogDirectory,
    JournalDirectory,
    ArchiveDirectory,
    LogSize,
    JournalSize,
    ArchiveSize,
    LogFormat,
}

#[derive(Debug, Deserialize)]
pub enum SetConfigVariables {
    LogDirectory { value: String },
    JournalDirectory { value: String },
    ArchiveDirectory { value: String },
    LogSize,
    JournalSize,
    ArchiveSize,
    LogFormat,
}

// Unused, for reference
#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Legacy,
    Simple,
    Json,
}
