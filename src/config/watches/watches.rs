use crate::config::input_utils::{FilePathCompleter, StringListAutoCompleter};
use crate::config::{
    AuditWatch, CONFIG_DIR, FILTER_FILE_EXTENSIONS, RULES_FILE, State, WatchAction, Watches,
};
use crate::utils::{current_utc_string, strip_block_comments};
use anyhow::{Context, Result, anyhow};
use inquire::Select;
use inquire::{Confirm, formatter::StringFormatter, validator::Validation};
use std::fs;
use std::io::BufRead;
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
            table.insert("path".into(), toml::Value::String(f.path.clone()));
            table.insert(
                "action".into(),
                toml::Value::String(f.action.as_ref().to_string()),
            );
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
            println!(
                "    {}: \n\tAction: {} \n\tRecursive?: {}",
                watch.path,
                watch.action.as_ref(),
                recursive_str
            );
        }
    }
    Ok(())
}

fn remove_watch(path: &str) -> Result<()> {
    let mut current = load_watches()?;
    current.0.retain(|w| !w.path.eq_ignore_ascii_case(path));
    persist_watches(&current.0)
}

/// Remove a watch via interactive prompt with fuzzy autocomplete over existing
/// watches only.
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

    remove_watch(&watch_path)
}

/// Update an existing watch via interactive prompt; watch path chosen from
/// current watches only.
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
    let action_str = Select::new("Select new action for this watch", actions)
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

fn validate_and_build_watch(path: &str, action: &str, recursive: bool, location: &str) -> Result<AuditWatch> {
    let path = path.trim();
    let action = action.trim();

    if path.is_empty() {
        return Err(anyhow!("{}: path is empty", location));
    }
    if action.is_empty() {
        return Err(anyhow!("{}: action is empty", location));
    }

    let parsed_action = WatchAction::from_str(&action.to_lowercase()).map_err(|_| {
        anyhow!(
            "{}: invalid action '{}' (expected one of: report, block)",
            location,
            action
        )
    })?;

    Ok(AuditWatch {
        path: path.to_lowercase(),
        action: parsed_action,
        recursive: recursive,
    })
}

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

        let action = match table.get("action").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                eprintln!(
                    "warning: {}: missing or non-string 'action' field, skipping",
                    location
                );
                continue;
            }
        };

        let recursive = match table.get("recursive").and_then(|v| v.as_bool()) {
            Some(b) => b,
            None => {
                eprintln!("warning: {}: missing or non-boolean 'recursive' field, skipping", location);
                continue;
            }
        };

        match validate_and_build_watch(watch_path, action, recursive, &location) {
            Ok(w) => watches.push(w),
            Err(e) => eprintln!("warning: {}, skipping", e),
        }
        };

    Ok(watches)
}

/// Import watches from an external and load them into rules.toml (used in
/// `auditrs watch import <file>` command)
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

        let (action, recursive) = match options.split_once(',') {
            Some(pair) => pair,
            None => {
                eprintln!("warning: {}: invalid syntax '{}' (expected 'action, recursive'), skipping", location, trimmed);
                continue;
            }
        };

        match validate_and_build_watch(watch_path, action, recursive.parse::<bool>()?, &location) {
            Ok(w) => watches.push(w),
            Err(e) => eprintln!("warning: {}, skipping", e),
        }
    }

    Ok(watches)
}

/// Import watches from an external file (.toml or .ars format).
pub fn import_watches(file: &str) -> Result<()> {
    let path = Path::new(file);
    if !path.exists() {
        return Err(anyhow!("file does not exist: {}", file));
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read '{}'", path.display()))?;

    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

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

    // Replace any user-given extension with the selected extension from the terminal
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

fn to_toml_format(watches: &[AuditWatch]) -> Result<String> {
    let mut table = toml::map::Map::new();
    table.insert(
        "watches".into(),
        toml::Value::Array(
            watches
                .iter()
                .map(|w| {
                    let mut watch_table = toml::map::Map::new();
                    watch_table.insert("path".into(), toml::Value::String(w.path.clone()));
                    watch_table.insert(
                        "action".into(),
                        toml::Value::String(w.action.as_ref().to_string()),
                    );
                    watch_table.insert("recursive".into(), toml::Value::Boolean(w.recursive));
                    toml::Value::Table(watch_table)
                })
                .collect(),
        ),
    );
    Ok(toml::to_string_pretty(&toml::Value::Table(table))?)
}

fn to_ars_format(watches: &[AuditWatch]) -> Result<String> {
    let mut content = String::new();
    for watch in watches {
        content.push_str(&format!(
            "{}: {}, {}\n",
            watch.path,
            watch.action.as_ref(),
            watch.recursive.to_string().to_lowercase()
        ));
    }
    Ok(content)
}
