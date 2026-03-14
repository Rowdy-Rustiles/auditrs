//! Audit rule definitions for `auditrs`.
//!
//! The `rules` module owns the **filter and watch rule set** that determines
//! which audit records are written, transformed, or ignored:
//! - `filters` provides record-type based rules and interactive CLI flows for
//!   listing, adding, updating, removing, importing, and dumping filters.
//! - `watches` provides path-based rules backed by `auditctl`, together with
//!   import/export helpers and interactive management.
//! A `Rules` value combines both `Filters` and `Watches` and is used by the
//! daemon state to enforce the current rule set.

pub mod auditctl;
pub mod filters;
pub mod watches;

pub use auditctl::{execute_auditctl_command, execute_watch_auditctl_command};
pub use filters::*;
pub use watches::*;

use serde::Deserialize;

/// Audit rules are collections of filters and watches that are applied to
/// audit events before they can be written to the primary log.
#[derive(Debug, Clone, Deserialize)]
pub struct Rules {
    /// The filters for the auditrs daemon.
    pub(crate) filters: Filters,
    /// The watches for the auditrs daemon.
    pub(crate) watches: Watches,
}
