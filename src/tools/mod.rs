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
enum SummaryDisposition {
    Exclude,
    Combine(String),
    Separate(String),
}

/// Aggregates identity and path-like fields from audit records (SYSCALL, PATH,
/// CWD, etc.).
struct ForensicsAggregates {
    uids: BTreeSet<String>,
    auids: BTreeSet<String>,
    /// Path interactions with the occurrence counts for each CWD.
    path_interactions: HashMap<String, HashMap<String, u32>>,
    /// SYSCALL `comm` values (short command names) with occurrence counts.
    command_counts: HashMap<String, u32>,
}
