pub mod config;
pub mod input_utils;

use serde::Deserialize;
pub use config::*;

const CONFIG_FILE: &str = "Config.toml";

// Thin audit filters wrapper for printing extensibility
#[derive(Debug, Deserialize)]
struct Filters(Vec<AuditFilter>);

#[derive(Debug, Deserialize)]
pub enum GetConfigVariables {
    OutputDirectory,
    LogSize,
    LogFormat,
    LogFilters,
}

#[derive(Debug, Deserialize)]
pub enum SetConfigVariables {
    OutputDirectory { value: String },
    LogSize { value: usize },
    LogFormat { value: LogFormat },
    LogFilters {
        record_type: String,
        action: String,
    },
    RemoveFilter { record_type: String },
}

#[derive(Debug, Deserialize)]
pub struct AuditConfig {
    pub output_directory: String,
    pub log_size: usize,
    pub log_format: String,
    pub filters: Filters,
}

#[derive(Debug, Deserialize)]
pub struct AuditFilter {
    record_type: String,
    action: String,
}

#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Legacy,
    Simple,
    Json,
}