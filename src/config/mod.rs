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
pub const MINIMUM_JOURNAL_SIZE: usize = 8388608; // 8 MB
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
log_size = 65536
output_directory = "/var/log/auditrs"
journal_size = 8388608
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
    pub output_directory: String,
    pub log_size: usize,
    pub log_format: String,
    pub journal_size: usize,
}

#[derive(Debug, Deserialize)]
pub enum GetConfigVariables {
    OutputDirectory,
    LogSize,
    LogFormat,
    JournalSize,
}

#[derive(Debug, Deserialize)]
pub enum SetConfigVariables {
    OutputDirectory { value: String },
    LogSize,
    LogFormat,
    JournalSize,
}

// Unused, for reference
#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Legacy,
    Simple,
    Json,
}
