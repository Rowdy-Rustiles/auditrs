use crate::config::State;
use crate::config::input_utils::FilePathCompleter;
use crate::config::{AuditWatch, CONFIG_DIR, RULES_FILE, WatchAction, Watches};
use anyhow::{Context, Result, anyhow};
use inquire::Select;
use inquire::{Confirm, formatter::StringFormatter, validator::Validation};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use strum::IntoEnumIterator;
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

fn persist_watches(watches: &[AuditWatch]) -> Result<()> {
    let file_path = RULES_FILE;
    fs::create_dir_all(CONFIG_DIR)?;

    let array: Vec<toml::Value> = watches
        .iter()
        .map(|f| {
            let mut table = toml::map::Map::new();
            table.insert("path".into(), toml::Value::String(f.path.clone()));
            table.insert(
                "action".into(),
                toml::Value::String(f.action.as_ref().to_string()),
            );
            toml::Value::Table(table)
        })
        .collect();

    let mut root = toml::map::Map::new();
    root.insert("watches".into(), toml::Value::Array(array));

    std::fs::write(
        file_path,
        toml::to_string_pretty(&toml::Value::Table(root))?,
    )?;
    Ok(())
}

fn set_watch(watch: AuditWatch) -> Result<()> {
    let mut current = load_watches()?;
    // Replace or append.
    if let Some(existing) = current.0.iter_mut().find(|f| f.path == watch.path) {
        *existing = watch;
    } else {
        current.0.push(watch);
    }

    persist_watches(&current.0)
}

/// Add a single filter via interactive prompts.
pub fn add_watch_interactive(_state: &State) -> Result<()> {
    let watch_path = inquire::Text::new("Enter a record type to filter on:")
        .with_autocomplete(FilePathCompleter::default())
        .with_validator(|input: &str| {
            if Path::new(input).exists() {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "Please enter a valid path (use suggestions)".into(),
                ))
            }
        })
        .with_formatter(&|i| i.to_lowercase())
        .with_page_size(12)
        .prompt()
        .map_err(|e| anyhow!("{}", e))?
        .trim()
        .to_string()
        .to_lowercase();

    if watch_path.is_empty() {
        return Err(anyhow!("record type cannot be empty"));
    }

    let actions: Vec<String> = WatchAction::iter()
        .map(|a| a.as_ref().to_string())
        .collect();
    let action_str = Select::new("Select an action for this watch", actions)
        .prompt()
        .map_err(|e| anyhow!("{}", e))?;
    let action = WatchAction::from_str(&action_str.to_lowercase()).map_err(|e| anyhow!("{}", e))?;

    let recursive = Confirm::new("Watch recursively?")
        .with_default(true)
        .prompt()
        .map_err(|e| anyhow!("{}", e))?;

    let watch = AuditWatch {
        path: watch_path,
        action,
        recursive,
    };
    set_watch(watch)
}

/// Gets all watches from the watches file using the pre-loaded state.
pub fn get_watches(state: &State) -> Result<()> {
    let watches = state.rules.watches.as_slice();
    if watches.is_empty() {
        println!("No watches defined");
    } else {
        println!("Watches:");
        for watch in watches {
            let recursive_str = if watch.recursive { "Yes" } else { "No" };
            println!("    {}: \n\tAction: {} \n\tRecursive?: {}", watch.path, watch.action.as_ref(), recursive_str);
        }
    }
    Ok(())
}
