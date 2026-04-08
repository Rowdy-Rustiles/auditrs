//! Audit rule definitions, encompassing filters and watches (`rules.toml`).
//!
//! The `rules` module owns the **filter and watch rule set** that determines
//! which audit records are written, transformed, or ignored:
//! - `filters` provides record-type based rules and interactive CLI flows for
//!   listing, adding, updating, removing, importing, and dumping filters.
//! - `watches` provides path-based rules backed by kernel netlink watch rules,
//!   together with import/export helpers and interactive management.
//! A `Rules` value combines both `Filters` and `Watches` and is used by the
//! daemon state to enforce the current rule set.

pub mod filters;
pub mod kernel_watches;
pub mod watches;

pub use filters::*;
pub use kernel_watches::apply_watch_kernel_rule;
pub use watches::*;

use serde::Deserialize;

pub(crate) const AUDIT_RULES_FILE: &str = "/etc/audit/audit.rules";

/// Audit rules are collections of filters and watches that are applied to
/// audit events before they can be written to the primary log.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Rules {
    /// The filters for the auditrs daemon.
    pub(crate) filters: Filters,
    /// The watches for the auditrs daemon.
    pub(crate) watches: Watches,
}
