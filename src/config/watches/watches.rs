use crate::config::{WatchAction, AuditWatch, RULES_FILE, Watches};
use anyhow::Result;
use std::path::Path;
use std::str::FromStr;
use toml;

impl Watches {
    /// Returns the list of watched paths currently defined.
    pub fn paths(&self) -> Vec<String> {
        self.0.iter().map(|w| w.path.clone()).collect()
    }

    /// Returns the underlying watch list.
    pub fn as_slice(&self) -> &[AuditWatch] {
        &self.0
    }

    /// Construct an empty set of watches.
    pub fn empty() -> Watches {
        Watches(Vec::new())
    }

    /// Load watches from the shared rules file (`rules.toml`), reading the
    /// top-level `[[watches]]` tables.
    pub fn load() -> Result<Watches> {
        let file_path = RULES_FILE;

        if !Path::new(file_path).exists() {
            // No rules file yet – treat as empty set of watches.
            return Ok(Watches::empty());
        }

        let content = std::fs::read_to_string(file_path)?;
        if content.trim().is_empty() {
            return Ok(Watches::empty());
        }

        let root: toml::Value = toml::from_str(&content)?;
        let watches_vec = root
            .get("watches")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_table())
                    .filter_map(|table| {
                        let path = table.get("path")?.as_str()?.to_string();
                        let action_str = table.get("action")?.as_str()?.to_string();
                        let action = WatchAction::from_str(&action_str.to_lowercase()).ok()?;
                        Some(AuditWatch {
                            path,
                            action,
                            // Default values for optional fields that may not be present in the
                            // rules file yet.
                            recursive: false,
                            // duration: None,
                            // from: None,
                            // to: None,
                        })
                    })
                    .collect()
            })
            .unwrap_or_else(Vec::new);

        Ok(Watches(watches_vec))
    }
}

/// Function used by the shared state loader.
pub fn load_watches() -> Result<Watches> {
    Watches::load()
}
