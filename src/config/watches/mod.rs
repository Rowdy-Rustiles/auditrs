mod watches;

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

pub use watches::load_watches;

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
    pub action: String,
    pub recursive: bool,
    // pub duration: Option<Duration>,
    // pub from: Option<DateTime<Utc>>,
    // pub to: Option<DateTime<Utc>>,
}
