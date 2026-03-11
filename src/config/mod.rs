//! Top level configuration module for auditrs. Internally, the config module is
//! split into the core configuration, `config.rs`, and the rules configuration,
//! which jointly defines the set of filters and watches used by auditrs.
//! Changes to the core configuration effect structural aspects of the daemon,
//! such as log directories and file sizes. Configuring rules occurs in the
//! `filters.rs` and `watches.rs` modules, which are more outward-facing
//! intefaces that impact the write path of audit events.
//!
//! Adjustments to rules occurs via the `auditrs filter` and `auditrs watch`
//! commands, which are subsequently tied to logic in `config/filters/` and
//! `config/watches/` submodules, respectively. Adjustments to the core
//! configuration occurs via the `auditrs config` command, which is tied to
//! logic in the top-level files within `config/`.

pub mod auditctl;
pub mod config;
pub mod filters;
pub mod input_utils;
pub mod state;
pub mod watches;

pub use config::{get_config, load_config, set_config};
// TODO: a lot of the logic between filters and watches is the same, we might
// want to consider refactoring and consolidating some of their functions.
// For now, duplication is ok
pub use auditctl::{execute_auditctl_command, execute_watch_auditctl_command};
pub use filters::{
    AuditFilter, FilterAction, Filters, add_filter_interactive, dump_filters, get_filters,
    import_filters, load_filters, remove_filter_interactive, update_filter_interactive,
};
use serde::Deserialize;
pub use watches::{
    AuditWatch, WatchAction, Watches, add_watch_interactive, dump_watches, get_watches,
    import_watches, load_watches, remove_watch_interactive, update_watch_interactive,
};

/// The minimum log size for the auditrs daemon.
pub const MINIMUM_LOG_SIZE: usize = 1048576; // 1 MB
/// The minimum journal size for the auditrs daemon.
pub const MINIMUM_JOURNAL_SIZE: usize = 16; // 16 logs
/// The minimum primary size for the auditrs daemon.
pub const MINIMUM_PRIMARY_SIZE: usize = 8388608; // 8 MB
/// The configuration directory for the auditrs daemon.
pub const CONFIG_DIR: &str = "/etc/auditrs";
/// The configuration file for the auditrs daemon.
pub const CONFIG_FILE: &str = "/etc/auditrs/config.toml";
/// The rules file for the auditrs daemon.
pub const RULES_FILE: &str = "/etc/auditrs/rules.toml";
/// The file extensions that can be used for importing and dumping filters.
pub const FILTER_FILE_EXTENSIONS: &[&str] = &["toml", "ars"];
/// The actions available for filters and watches.
pub const FILTER_ACTIONS: &[&str] = &[
    "allow",
    "block",
    "sample",
    "redact",
    "route_secondary",
    "tag",
    "count_only",
    "alert",
];
/// The log formats for the auditrs output logs.
pub const LOG_FORMATS: &[&str] = &["Legacy", "Simple", "Json"];
/// The default configuration for the auditrs daemon.
pub const DEFAULT_CONFIG: &str = r#"[meta]
version = "0.3.0"

[settings]
log_format = "legacy"
active_directory = "/var/log/auditrs/active"
primary_directory = "/var/log/auditrs/primary"
journal_directory = "/var/log/auditrs/journal"
log_size = 4194304
journal_size = 16
primary_size = 67108864
"#;

/// An interface for exposing the current state of the auditrs configuration to
/// the configuration manipulation functions.
#[derive(Debug)]
pub struct State {
    /// The core configuration for the auditrs daemon.
    pub(crate) config: AuditConfig,
    /// The rules for the auditrs daemon.
    pub(crate) rules: Rules,
}

/// Audit rules are a collections of filters and watches that are applied to
/// audit events before they can be written to the primary log.
#[derive(Debug, Deserialize)]
pub struct Rules {
    /// The filters for the auditrs daemon.
    pub(crate) filters: Filters,
    /// The watches for the auditrs daemon.
    pub(crate) watches: Watches,
}

/// The core configuration of the auditrs daemon, which is used to define the
/// structural aspects of the daemon, such as log directories and file sizes.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    /// The log directory for the auditrs daemon.
    pub active_directory: String,
    /// The log size for the auditrs daemon.
    pub log_size: usize,
    /// The log format for the auditrs daemon.
    pub log_format: LogFormat,
    /// The journal directory for the auditrs daemon.
    pub journal_directory: String,
    /// The journal size for the auditrs daemon.
    pub journal_size: usize,
    /// The primary directory for the auditrs daemon.
    pub primary_directory: String,
    /// The primary size for the auditrs daemon.
    pub primary_size: usize,
}

/// An enum for the different configuration variables that can be retrieved.
#[derive(Debug, Deserialize)]
pub enum GetConfigVariables {
    /// Get the log directory for the auditrs daemon.
    LogDirectory,
    /// Get the journal directory for the auditrs daemon.
    JournalDirectory,
    /// Get the primary directory for the auditrs daemon.
    PrimaryDirectory,
    /// Get the log size for the auditrs daemon.
    LogSize,
    /// Get the journal size for the auditrs daemon.
    JournalSize,
    /// Get the primary size for the auditrs daemon.
    PrimarySize,
    /// Get the log format for the auditrs daemon.
    LogFormat,
}

/// An enum for the different configuration variables that can be set.
#[derive(Debug, Deserialize)]
pub enum SetConfigVariables {
    /// Set the log directory for the auditrs daemon.
    LogDirectory { value: String },
    /// Set the journal directory for the auditrs daemon.
    JournalDirectory { value: String },
    /// Set the primary directory for the auditrs daemon.
    PrimaryDirectory { value: String },
    /// Set the log size for the auditrs daemon.
    LogSize,
    /// Set the journal size for the auditrs daemon.
    JournalSize,
    /// Set the primary size for the auditrs daemon.
    PrimarySize,
    /// Set the log format for the auditrs daemon.
    LogFormat,
}

/// An enum for the different log formats that can be used by the auditrs
/// daemon.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// The legacy log format, copies auditd's formatting for backwards
    /// compatibility. Produces a `.log` log file.
    Legacy,
    /// The simple log format, intended for human readability. Produces a
    /// `.slog` log file.
    Simple,
    /// Formats audit events as JSON objects. Produces a `.json` log file.
    Json,
}
