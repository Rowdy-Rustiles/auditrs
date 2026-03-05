use crate::config::*;
use anyhow::Result;

impl State {
    pub fn load_state() -> Result<State> {
        let config = load_config()?;
        let filters = load_filters()?;
        Ok(State { config, filters })
    }
}
