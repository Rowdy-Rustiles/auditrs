//! Auxiliary CLI tools built on auditrs-generated logs.
//!
//! The `tools` module groups higher-level commands that operate on existing
//! audit logs and state rather than driving the live daemon directly:
//! - `dump`: utilities for exporting or transforming stored audit data.
//! - `search`: facilities for querying logs and rules.
//! - `report`: reporting and analysis helpers for generating human-readable
//!   summaries.

use std::collections::{BTreeSet, HashMap};

pub mod dump;
pub mod report;
pub mod search;

/// How summary text should be emitted relative to the main report file or
/// stdout.
#[derive(Debug, PartialEq)]
enum SummaryDisposition {
    /// Exclude the summary text from the report.
    Exclude,
    /// Combine the summary text with the report body.
    Combine(String),
    /// Separate the summary text from the report body (functions like `combine`
    /// when `--no-save` is specified).
    Separate(String),
}

/// Aggregates identity and path-like fields from audit records (SYSCALL, PATH,
/// CWD, etc.) for summmarization.
struct ForensicsAggregates {
    /// User IDs present in the events.
    uids: BTreeSet<String>,
    /// Audit user IDs present in the events.
    auids: BTreeSet<String>,
    /// Path interactions with the occurrence counts; organized by CWD.
    path_interactions: HashMap<String, HashMap<String, u32>>,
    /// SYSCALL `comm` values (short command names) with occurrence counts.
    command_counts: HashMap<String, u32>,
}
