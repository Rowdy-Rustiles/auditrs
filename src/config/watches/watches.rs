//! Module defining auditrs's watch feature. This is a wrapper around the
//! auditctl command as well as the logic behind how auditrs stores and manages
//! watches.

use crate::config::input_utils::{FilePathCompleter, StringListAutoCompleter};
use crate::config::{
    AuditWatch, CONFIG_DIR, FILTER_FILE_EXTENSIONS, RULES_FILE, State, WatchAction, Watches,
    execute_watch_auditctl_command,
};
use crate::utils::{current_utc_string, strip_block_comments};
use anyhow::{Context, Result, anyhow};
use inquire::{Confirm, formatter::StringFormatter, validator::Validation};
use inquire::{MultiSelect, Select};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::BufRead;
use std::path::{Path, PathBuf, absolute};
use std::str::FromStr;
use strum::EnumString;
use strum::IntoEnumIterator;
use tokio::sync::watch;
use toml;

/// Implementation of the `Watches` struct. Defines the non-interactive
/// functionaity for referencing watches as state.
impl Watches {
    /// Returns the list of watched paths currently defined.
    pub fn paths(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|w| w.path.to_string_lossy().into_owned())
            .collect()
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

                        let actions: Vec<WatchAction> =
                            table.get("actions").and_then(|v| v.as_array()).map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str())
                                    .filter_map(|s| WatchAction::from_str(&s.to_lowercase()).ok())
                                    .collect::<Vec<_>>()
                            })?;

                        if actions.is_empty() {
                            return None;
                        }

                        let recursive = table.get("recursive").and_then(|v| v.as_bool())?;

                        let path_buf = PathBuf::from(&path);
                        let key = table
                            .get("key")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())?;

                        Some(AuditWatch {
                            path: path_buf,
                            actions,
                            recursive,
                            key,
                        })
                    })
                    .collect()
            })
            .ok_or_else(|| anyhow!("Failed to parse watches"))?;

        Ok(Watches(watches_vec))
    }
}

/// Function used by the shared state loader.
pub fn load_watches() -> Result<Watches> {
    Watches::load()
}

/// Generates a unique key for the watch rule. Used for identifying rules when
/// they are deleted.
///
/// **Parameters:**
///
/// * `path`: Filesystem path being watched.
/// * `actions`: List of `WatchAction`s associated with the watch.
/// * `recursive`: Whether the watch applies recursively to subdirectories.
fn generate_watch_key(path: &Path, actions: &[WatchAction], recursive: bool) -> String {
    let mut hasher = DefaultHasher::new();
    path.to_string_lossy().to_lowercase().hash(&mut hasher);
    for action in actions {
        action.as_ref().hash(&mut hasher);
    }
    recursive.hash(&mut hasher);
    let hash = hasher.finish();
    format!("auditrs_watch_{:016x}", hash)
}

/// Persist the watches to `/etc/auditrs/rules.toml`.
/// Accepts a slice of `AuditWatch`s.
///
/// **Parameters:**
///
/// * `watches`: A slice of `AuditWatch`s to persist. Referenced as `Watches` is
///   a unit struct around a vector of `AuditWatch`s.
fn persist_watches(watches: &[AuditWatch]) -> Result<()> {
    let file_path = RULES_FILE;
    // Create a default config folder at /etc/auditrs if it doesn't exist
    fs::create_dir_all(CONFIG_DIR)?;

    // Load existing rules file for the preservation of other sections
    let mut root_table = if Path::new(file_path).exists() {
        let existing = std::fs::read_to_string(file_path)?;
        match toml::from_str::<toml::Value>(&existing) {
            Ok(toml::Value::Table(table)) => table,
            _ => toml::map::Map::new(),
        }
    } else {
        toml::map::Map::new()
    };

    let array: Vec<toml::Value> = watches
        .iter()
        .map(|f| {
            let mut table = toml::map::Map::new();
            table.insert(
                "path".into(),
                toml::Value::String(f.path.to_string_lossy().into_owned()),
            );
            table.insert(
                "actions".into(),
                toml::Value::Array(
                    f.actions
                        .iter()
                        .map(|a| toml::Value::String(a.as_ref().to_string()))
                        .collect(),
                ),
            );
            table.insert("recursive".into(), toml::Value::Boolean(f.recursive));
            table.insert("key".into(), toml::Value::String(f.key.clone()));
            toml::Value::Table(table)
        })
        .collect();

    // Overwrite just the `watches` section while preserving others (e.g. `filters`)
    root_table.insert("watches".into(), toml::Value::Array(array));

    std::fs::write(
        file_path,
        toml::to_string_pretty(&toml::Value::Table(root_table))?,
    )?;
    Ok(())
}

/// Set a single watch in the watches file.
///
/// **Parameters:**
///
/// * `watch`: The `AuditWatch` to add or replace in the rules file.
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

/// Add a single watch via interactive prompts.
pub fn add_watch_interactive() -> Result<()> {
    let mut watch_path_str = inquire::Text::new("Enter a file or directory path to watch:")
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

    if watch_path_str.is_empty() {
        return Err(anyhow!("record type cannot be empty"));
    }

    let actions: Vec<String> = WatchAction::iter()
        .map(|a| a.as_ref().to_string())
        .collect();
    let action_str = MultiSelect::new("Select the actions to watch for", actions)
        .with_validator(|input: &[inquire::list_option::ListOption<&String>]| {
            if input.is_empty() {
                Ok(Validation::Invalid(
                    "Please select at least one action".into(),
                ))
            } else {
                Ok(Validation::Valid)
            }
        })
        .prompt()
        .map_err(|e| anyhow!("{}", e))?;
    let actions = action_str
        .iter()
        .map(|a| WatchAction::from_str(&a.to_lowercase()).map_err(|e| anyhow!("{}", e)))
        .collect::<Result<Vec<_>>>()?;

    // We only prompt for recursive if the path is a directory
    let mut recursive = false;
    if Path::new(&watch_path_str).is_dir() {
        recursive = Confirm::new("Watch recursively?")
            .with_default(true)
            .prompt()
            .map_err(|e| anyhow!("{}", e))?;
    }

    // Derive the absolute path
    let watch_path = absolute(watch_path_str)?;
    let key = generate_watch_key(&watch_path, &actions, recursive);

    let watch = AuditWatch {
        path: watch_path,
        actions,
        recursive,
        key,
    };
    // Create the watch in the Linux audit system
    execute_watch_auditctl_command(&watch, false)?;
    // Then persist the watch to the auditrs rules file
    set_watch(watch)
}

/// Gets all watches from the watches file using the pre-loaded state.
///
/// **Parameters:**
///
/// * `state`: Shared application `State` containing preloaded `Watches`.
pub fn get_watches(state: &State) -> Result<()> {
    let watches = state.rules.watches.as_slice();
    if watches.is_empty() {
        println!("No watches defined");
    } else {
        println!("Watches:");
        for watch in watches {
            let recursive_str = if watch.recursive { "Yes" } else { "No" };
            let actions_str = watch
                .actions
                .iter()
                .map(|a| a.as_ref())
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "    {}: \n\tActions: {} \n\tRecursive?: {}",
                watch.path.to_string_lossy().into_owned(),
                actions_str,
                recursive_str
            );
        }
    }
    Ok(())
}

/// Remove a watch from the rules file by its path.
///
/// **Parameters:**
///
/// * `path`: String representation of the watch path to remove.
fn remove_watch(path: &str) -> Result<()> {
    let mut current = load_watches()?;
    current
        .0
        .retain(|w| !w.path.to_string_lossy().eq_ignore_ascii_case(path));
    persist_watches(&current.0)
}

/// Remove a watch via interactive prompt with fuzzy autocomplete over existing
/// watches only.
///
/// **Parameters:**
///
/// * `state`: Shared application `State` used to obtain existing `Watches`.
pub fn remove_watch_interactive(state: &State) -> Result<()> {
    let existing = state.rules.watches.paths();
    if existing.is_empty() {
        return Err(anyhow!("No watches defined; nothing to remove."));
    }
    let completer = StringListAutoCompleter::new(existing.clone());
    let watch_path = inquire::Text::new("Select a watch path to remove:")
        .with_autocomplete(completer)
        .with_validator(move |input: &str| {
            let trimmed = input.trim().to_lowercase();
            if existing.iter().any(|s| s.eq_ignore_ascii_case(&trimmed)) {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "Please choose one of the existing watch paths (use suggestions).".into(),
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

    // This should always be Some because of the validator above
    let watch_to_remove = state
        .rules
        .watches
        .as_slice()
        .iter()
        .find(|w| w.path.to_string_lossy().eq_ignore_ascii_case(&watch_path));
    if let Some(watch) = watch_to_remove {
        execute_watch_auditctl_command(watch, true)?;
    } else {
        unreachable!("Validator should be preventing this state")
    }
    remove_watch(&watch_path)
}

/// Update an existing watch via interactive prompt; watch path chosen from
/// current watches only.
///
/// **Parameters:**
///
/// * `state`: Shared application `State` used to obtain and update `Watches`.
pub fn update_watch_interactive(state: &State) -> Result<()> {
    let existing = state.rules.watches.paths();
    if existing.is_empty() {
        return Err(anyhow!(
            "No watches defined; add a watch first or use 'watch add'."
        ));
    }
    let completer = StringListAutoCompleter::new(existing.clone());
    let watch_path = inquire::Text::new("Select a watch path to update:")
        .with_autocomplete(completer)
        .with_validator(move |input: &str| {
            let trimmed = input.trim().to_lowercase();
            if existing.iter().any(|s| s.eq_ignore_ascii_case(&trimmed)) {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "Please choose one of the existing watch paths (use suggestions).".into(),
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

    let actions: Vec<String> = WatchAction::iter()
        .map(|a| a.as_ref().to_string())
        .collect();
    let action_str = MultiSelect::new("Select new actions for this watch", actions)
        .prompt()
        .map_err(|e| anyhow!("{}", e))?;
    let actions = action_str
        .iter()
        .map(|a| WatchAction::from_str(&a.to_lowercase()).map_err(|e| anyhow!("{}", e)))
        .collect::<Result<Vec<_>>>()?;

    let recursive = Confirm::new("Watch recursively?")
        .with_default(true)
        .prompt()
        .map_err(|e| anyhow!("{}", e))?;

    let watch_actions = actions.clone();
    let path_buf = PathBuf::from(watch_path.clone());
    let key = generate_watch_key(&path_buf, &watch_actions, recursive);

    let watch = AuditWatch {
        path: path_buf,
        actions: watch_actions,
        recursive,
        key,
    };
    set_watch(watch)
}

/// Validate raw watch fields and construct an `AuditWatch`.
///
/// **Parameters:**
///
/// * `path`: Raw filesystem path string.
/// * `actions`: Parsed list of `WatchAction`s.
/// * `recursive`: Whether the watch should be recursive.
/// * `location`: Human-readable location string for error reporting.
fn validate_and_build_watch(
    path: &str,
    actions: Vec<WatchAction>,
    recursive: bool,
    location: &str,
) -> Result<AuditWatch> {
    let path = path.trim();

    if path.is_empty() {
        return Err(anyhow!("{}: path is empty", location));
    }
    if actions.is_empty() {
        return Err(anyhow!("{}: actions is empty", location));
    }

    let path_buf = PathBuf::from(path.to_lowercase());
    let key = generate_watch_key(&path_buf, &actions, recursive);

    Ok(AuditWatch {
        path: path_buf,
        actions,
        recursive,
        key,
    })
}

/// Import watches from a TOML rules file into `AuditWatch` values.
///
/// **Parameters:**
///
/// * `content`: Raw TOML file content.
/// * `path`: Filesystem path to the TOML file, used in diagnostics.
fn import_from_toml(content: &str, path: &Path) -> Result<Vec<AuditWatch>> {
    let cleaned = strip_block_comments(content);
    let root: toml::Value = toml::from_str(&cleaned)
        .with_context(|| format!("failed to parse '{}' as TOML", path.display()))?;

    let watches_array = root
        .get("watches")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow!(
                "'{}': missing [[watches]] array at top level",
                path.display()
            )
        })?;

    let mut watches = Vec::new();

    for (i, entry) in watches_array.iter().enumerate() {
        let location = format!("{}:watches[{}]", path.display(), i);
        let table = match entry.as_table() {
            Some(t) => t,
            None => {
                eprintln!("warning: {}: entry is not a table, skipping", location);
                continue;
            }
        };

        let watch_path = match table.get("path").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                eprintln!(
                    "warning: {}: missing or non-string 'path' field, skipping",
                    location
                );
                continue;
            }
        };

        let actions: Vec<WatchAction> = match table.get("actions").and_then(|v| v.as_array()) {
            Some(arr) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| WatchAction::from_str(&s.to_lowercase()).ok())
                .collect(),
            None => {
                eprintln!(
                    "warning: {}: missing 'actions' array field, skipping",
                    location
                );
                continue;
            }
        };

        if actions.is_empty() {
            eprintln!("warning: {}: empty actions list, skipping", location);
            continue;
        }

        let recursive = match table.get("recursive").and_then(|v| v.as_bool()) {
            Some(b) => b,
            None => {
                eprintln!(
                    "warning: {}: missing or non-boolean 'recursive' field, skipping",
                    location
                );
                continue;
            }
        };

        match validate_and_build_watch(watch_path, actions, recursive, &location) {
            Ok(w) => watches.push(w),
            Err(e) => eprintln!("warning: {}, skipping", e),
        }
    }

    Ok(watches)
}

/// Import watches from an external `.ars` file and convert them into
/// `AuditWatch` values (used internally by the `auditrs watch import <file>`
/// command).
///
/// **Parameters:**
///
/// * `content`: Raw `.ars` file content.
/// * `path`: Filesystem path to the `.ars` file, used in diagnostics.
fn import_from_ars(content: &str, path: &Path) -> Result<Vec<AuditWatch>> {
    let cleaned = strip_block_comments(content);
    let reader = std::io::BufReader::new(cleaned.as_bytes());
    let mut watches = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        let location = format!("{}:{}", path.display(), line_num + 1);

        let (watch_path, options) = match trimmed.split_once(':') {
            Some(pair) => pair,
            None => {
                eprintln!(
                    "warning: {}: invalid syntax '{}' (expected 'path: action'), skipping",
                    location, trimmed
                );
                continue;
            }
        };

        let (actions_raw, recursive) = match options.split_once(',') {
            Some(pair) => pair,
            None => {
                eprintln!(
                    "warning: {}: invalid syntax '{}' (expected 'action, recursive'), skipping",
                    location, trimmed
                );
                continue;
            }
        };

        let actions: Vec<WatchAction> = actions_raw
            .split('|')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| WatchAction::from_str(&s.to_lowercase()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| anyhow!("{}: invalid action list '{}'", location, actions_raw))?;

        match validate_and_build_watch(watch_path, actions, recursive.parse::<bool>()?, &location) {
            Ok(w) => watches.push(w),
            Err(e) => eprintln!("warning: {}, skipping", e),
        }
    }

    Ok(watches)
}

/// Import watches from an external file (`.toml` or `.ars` format) and persist
/// them into the main rules file.
///
/// **Parameters:**
///
/// * `file`: Path to the watch definition file to import.
pub fn import_watches(file: &str) -> Result<()> {
    let path = Path::new(file);
    if !path.exists() {
        return Err(anyhow!("file does not exist: {}", file));
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read '{}'", path.display()))?;

    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .ok_or_else(|| anyhow!("Failed to get file extension"))?;

    let watches = match extension {
        "toml" => import_from_toml(&content, path)?,
        "ars" => import_from_ars(&content, path)?,
        other => {
            return Err(anyhow!(
                "unsupported file extension '.{}' (expected .toml or .ars)",
                other
            ));
        }
    };

    if watches.is_empty() {
        println!("No watches found in '{}'", path.display());
        return Ok(());
    }

    let count = watches.len();
    for watch in watches {
        set_watch(watch)?;
    }

    println!(
        "Successfully imported {} watch(es) from '{}'",
        count,
        path.display()
    );
    Ok(())
}

/// Dump the currently configured watches into an external file in either TOML
/// or ARS format, preserving a generated header.
///
/// **Parameters:**
///
/// * `file`: Base path (with or without extension) to write the dump to.
/// * `state`: Shared application `State` containing the `Watches` to dump.
pub fn dump_watches(file: &str, state: &State) -> Result<()> {
    let watches = state.rules.watches.as_slice();
    if watches.is_empty() {
        return Err(anyhow!("No watches defined; nothing to dump."));
    }

    let watch_file_extension = Select::new(
        "Select a watch file format",
        FILTER_FILE_EXTENSIONS.to_vec(),
    )
    .prompt()
    .map_err(|e| anyhow!("{}", e))?
    .to_lowercase();

    // Replace any user-given extension with the selected extension from the
    // terminal
    let base = Path::new(file).with_extension("");
    let path = base.with_extension(&watch_file_extension);

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory '{}'", parent.display()))?;
        }
    }

    let mut header = String::from("/*\n\nGenerated by auditrs via CLI at ")
        + &current_utc_string()
        + "\n\n*/\n\n";
    let content = match watch_file_extension.as_str() {
        "toml" => to_toml_format(watches)?,
        "ars" => to_ars_format(watches)?,
        _ => return Err(anyhow!("Invalid watch file format")),
    };

    std::fs::write(&path, header.to_string() + &content)
        .with_context(|| format!("failed to write '{}'", path.display()))?;
    println!("Watches dumped to '{}'", path.display());
    Ok(())
}

/// Serialize the provided watches into TOML text containing a top-level
/// `[[watches]]` array.
///
/// **Parameters:**
///
/// * `watches`: Slice of `AuditWatch`s to serialize.
fn to_toml_format(watches: &[AuditWatch]) -> Result<String> {
    let mut table = toml::map::Map::new();
    table.insert(
        "watches".into(),
        toml::Value::Array(
            watches
                .iter()
                .map(|w| {
                    let mut watch_table = toml::map::Map::new();
                    watch_table.insert(
                        "path".into(),
                        toml::Value::String(w.path.to_string_lossy().into_owned()),
                    );
                    watch_table.insert(
                        "actions".into(),
                        toml::Value::Array(
                            w.actions
                                .iter()
                                .map(|a| toml::Value::String(a.as_ref().to_string()))
                                .collect(),
                        ),
                    );
                    watch_table.insert("recursive".into(), toml::Value::Boolean(w.recursive));
                    watch_table.insert("key".into(), toml::Value::String(w.key.clone()));
                    toml::Value::Table(watch_table)
                })
                .collect(),
        ),
    );
    Ok(toml::to_string_pretty(&toml::Value::Table(table))?)
}

/// Serialize the provided watches into the `.ars` line-based text format.
///
/// **Parameters:**
///
/// * `watches`: Slice of `AuditWatch`s to serialize.
fn to_ars_format(watches: &[AuditWatch]) -> Result<String> {
    let mut content = String::new();
    for watch in watches {
        let actions_str = watch
            .actions
            .iter()
            .map(|a| a.as_ref())
            .collect::<Vec<_>>()
            .join("|");
        content.push_str(&format!(
            "{}: {}, {}\n",
            watch.path.display(),
            actions_str,
            watch.recursive.to_string().to_lowercase()
        ));
    }
    Ok(content)
}
