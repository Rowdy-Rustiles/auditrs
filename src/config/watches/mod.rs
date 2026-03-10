mod watches;

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use crate::config::FilterAction;

pub use watches::{add_watch_interactive, get_watches, load_watches};

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
    /// Report matching records to the primary log.
    Report,
    /// Do not write matching records to the primary log.
    Block,
}

/// Watches are fine-grained, directory and file-based rules that specify which
/// system paths are to be monitored and logged into the primary log. These can
/// be combined with filters to create a rule set that is narrowed on system
/// paths and record types.
#[derive(Debug, Deserialize)]
pub struct Watches(pub(crate) Vec<AuditWatch>);

/// The internal auditrs representation of a single watch, which is a system
/// path coupled with the action to be taken on it.
#[derive(Debug, Deserialize)]
pub struct AuditWatch {
    pub path: String,
    pub action: WatchAction,
    pub recursive: bool,
    // pub duration: Option<Duration>,
    // pub from: Option<DateTime<Utc>>,
    // pub to: Option<DateTime<Utc>>,
}
