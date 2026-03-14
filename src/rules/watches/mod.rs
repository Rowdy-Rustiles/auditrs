mod watches;

pub use watches::{
    add_watch_interactive,
    dump_watches,
    get_watches,
    import_watches,
    load_watches,
    remove_watch_interactive,
    update_watch_interactive,
};

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use std::path::PathBuf;

/// The set of actions that can be taken by filters.
#[derive(
    Debug,
    Clone,
    Copy,
    strum::EnumIter,
    strum::EnumString,
    strum::AsRefStr,
    strum::Display,
    Deserialize,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum WatchAction {
    /// Watch for reads to the specified path.
    Read,
    /// Watch for writes to the specified path.
    Write,
    /// Watch for executions on the specified path.
    Execute,
}

/// Watches are fine-grained, directory and file-based rules that specify which
/// system paths are to be monitored and logged into the primary log. These can
/// be combined with filters to create a rule set that is narrowed on system
/// paths and record types.
#[derive(Debug, Clone, Deserialize)]
pub struct Watches(pub(crate) Vec<AuditWatch>);

/// The internal auditrs representation of a single watch, which is a system
/// path coupled with the actions to be taken on it.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditWatch {
    pub path: PathBuf,
    pub actions: Vec<WatchAction>,
    pub recursive: bool,
    #[serde(default)]
    pub key: String,
    // pub duration: Option<Duration>,
    // pub from: Option<DateTime<Utc>>,
    // pub to: Option<DateTime<Utc>>,
}
