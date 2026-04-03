//! Auxiliary CLI tools built on auditrs-generated logs.
//!
//! The `tools` module groups higher-level commands that operate on existing
//! audit logs and state rather than driving the live daemon directly:
//! - `dump`: utilities for exporting or transforming stored audit data.
//! - `search`: facilities for querying logs and rules.
//! - `report`: reporting and analysis helpers for generating human-readable
//!   summaries.

pub mod dump;
pub mod report;
pub mod search;

/// How summary text should be emitted relative to the main report file or
/// stdout.
enum SummaryDisposition {
    Exclude,
    Combine(String),
    Separate(String),
}
