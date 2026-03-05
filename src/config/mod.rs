pub mod config;
pub mod filters;
pub mod input_utils;
pub mod state;

pub use config::{get_config, load_config, set_config};
pub use filters::{
    add_filter_interactive, get_filters, import_filters, load_filters, remove_filter_interactive,
    update_filter_interactive, dump_filters,
};
use serde::Deserialize;

pub const CONFIG_FILE: &str = "Config.toml";
pub const FILTERS_FILE: &str = "Filters.toml";
pub const FILTER_FILE_EXTENSIONS: &[&str] = &["toml", "ars"];
pub const ACTIONS: &[&str] = &["allow", "block"];
pub const LOG_FORMATS: &[&str] = &["Legacy", "Simple", "Json"];

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
}

#[derive(Debug, Deserialize)]
pub enum GetConfigVariables {
    OutputDirectory,
    LogSize,
    LogFormat,
}

#[derive(Debug, Deserialize)]
pub enum SetConfigVariables {
    OutputDirectory { value: String },
    LogSize { value: usize },
    LogFormat
}

// Unused, for reference
#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Legacy,
    Simple,
    Json,
}
