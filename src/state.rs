//! Shared state aggregation for the `auditrs` daemon and CLI.
//!
//! This module defines the `State` type, which bundles together the current
//! core configuration and rule set:
//! - wraps `config` and `rules` loading into a single `load_state` entry point;
//! - exposes a convenient read-only snapshot used by CLI commands and the
//!   daemon worker to avoid redundant disk I/O;
//! - provides strongly-typed access to configuration and rules for higher
//!   layers without leaking internal persistence details.

// We re-export these so they can be used for typing when State is invoked
pub use crate::config::{AuditConfig, load_config};
pub use crate::rules::Rules;

use anyhow::{Context, Result};

use crate::rules::{load_filters, load_watches};

/// An interface for exposing the current state of the auditrs configuration to
/// the configuration manipulation functions.
#[derive(Debug)]
pub struct State {
    /// The core configuration for the auditrs daemon.
    pub(crate) config: AuditConfig,
    /// The rules for the auditrs daemon.
    pub(crate) rules: Rules,
}

/// The state contians all active settings related to the auditrs daemon.
/// Since all CLI commands are atomic, the state is loaded each time a command
/// is executed. However, in the case that there are command "sessions" or
/// similar multi-command operations, using the state loaded in memory can avoid
/// unnecessary file I/O. The state interface also generally provides a more
/// convenient interface for accessing the config state.
impl State {
    /// Loads the state of the auditrs daemon from the configuration and rules
    /// files.
    pub fn load_state() -> Result<State> {
        let config = load_config().context("Could not load config")?;
        let filters = load_filters().context("Could not load filters")?;
        let watches = load_watches().context("Could not load watches")?;
        let rules = Rules { filters, watches };
        Ok(State { config, rules })
    }
}
