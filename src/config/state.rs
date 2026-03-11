//! Module implementing the State struct. Specifically provides the state
//! loading function.

use crate::config::*;
use anyhow::Result;

/// The state contians all active settings related to the auditrs daemon.
/// Since all CLI commands are atomic, the state is loaded each time a command
/// is executed. However, in the case that there are command "sessions" or
/// similar multi-command operations, using the state loaded in memory can avoid
/// unnecessary file I/O. The state interface also generally provides a more
/// convenient interface for accessing the config state.
impl State {
    pub fn load_state() -> Result<State> {
        let config = load_config()?;
        let filters = load_filters()?;
        let watches = load_watches()?;
        let rules = Rules { filters, watches };
        Ok(State { config, rules })
    }
}
