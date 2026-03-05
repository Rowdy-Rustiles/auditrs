pub mod config;
pub mod input_utils;

use serde::Deserialize;
pub use config::*;

const CONFIG_FILE: &str = "Config.toml";

// Thin audit filters wrapper for printing extensibility
#[derive(Debug, Deserialize)]
struct Filters(Vec<AuditFilter>);

impl Filters {
    /// Returns the list of record types currently defined in the config (for autocomplete).
    pub fn record_types(&self) -> Vec<String> {
        self.0.iter().map(|f| f.record_type.clone()).collect()
    }

    /// Returns the underlying filter list.
    pub fn as_slice(&self) -> &[AuditFilter] {
        &self.0
    }
}

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
    pub record_type: String,
    pub action: String,
}

#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Legacy,
    Simple,
    Json,
}