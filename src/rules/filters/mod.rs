//! System for filtering audit record outputs to the primary log.
//!
//! Implementation of the `filters` subcommand for manipulating the output to
//! the primary log. The functions defined here are exposed via the command
//! `auditrs filter` and provide standard CRUD operations as well as
//! import/export functionality. Filters are stored alongside watches
//! at `/etc/auditrs/rules.toml`.
//!
//! Unlike watches, filters do not interact with the kernel to control record
//! emission. Instead, filters are applied to audit events that fall under a
//! watch after they are written to the active and journal logs but before they
//! are written to a primary log. Therefore, it is possible that the an
//! audit event's uniquely identifying audit record(s) are absent from the
//! output to the primary log.

mod filters;

pub use filters::{
    add_filter_interactive,
    dump_filters,
    get_filters,
    import_filters,
    load_filters,
    remove_filter_interactive,
    update_filter_interactive,
};

use serde::Deserialize;

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
pub enum FilterAction {
    /// Write matching records to the primary log.
    Allow,
    /// Do not write matching records to the primary log.
    Block,
    /// Write only a sampled subset of matching records to the primary log.
    Sample,
    /// Write matching records but with sensitive fields redacted.
    Redact,
    /// Route matching records to a secondary destination instead of (or in
    /// addition to) the primary log.
    #[serde(rename = "route_secondary")]
    #[strum(serialize = "route_secondary")]
    RouteSecondary,
    /// Write matching records and tag them for downstream processing or
    /// analysis.
    Tag,
    /// Do not write individual records; track only aggregate counts/metrics for
    /// matches.
    #[serde(rename = "count_only")]
    #[strum(serialize = "count_only")]
    CountOnly,
    /// Write matching records and also trigger an alert or side-effect.
    Alert,
}

/// Filters are broad, record-type-based rules that specify which audit record
/// types are written to the primary log based on a user-defined action. These
/// are coarse-grained knobs for controlling the primary log's content.
#[derive(Debug, Clone, Deserialize)]
pub struct Filters(pub(crate) Vec<AuditFilter>);

/// The internal auditrs representation of a single filter, which is a record
/// type coupled with the action to be taken on it.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditFilter {
    /// The record type to filter.
    pub record_type: String,
    /// The action to take on the record type.
    pub action: FilterAction,
}
