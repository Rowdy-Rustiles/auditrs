//! Implementation of the `Filters` struct and associated functions.

use anyhow::{Context, Result, anyhow};
use inquire::Select;
use inquire::{formatter::StringFormatter, validator::Validation};
use std::fs;
use std::io::BufRead;
use std::path::Path;
use std::str::FromStr;
use strum::IntoEnumIterator;
use toml;

use crate::config::{CONFIG_DIR, FILTER_FILE_EXTENSIONS, RULES_FILE};
use crate::core::parser::audit_types::RecordType;
use crate::rules::{AuditFilter, FilterAction, Filters};
use crate::state::State;
use crate::utils::{
    RecordTypeAutoCompleter,
    StringListAutoCompleter,
    current_utc_string,
    strip_block_comments,
};

/// Implementation of the `Filters` struct. Defines the non-interactive
/// functionality for referencing filters as state.
impl Filters {
    /// Returns the list of record types currently defined in the filters (for
    /// autocomplete).
    pub fn record_types(&self) -> Vec<String> {
        self.0.iter().map(|f| f.record_type.clone()).collect()
    }

    /// Returns the underlying filter list.
    pub fn as_slice(&self) -> &[AuditFilter] {
        &self.0
    }

    /// Load filters from the dedicated rules file defined in the config
    /// (default: `/etc/auditrs/rules.toml`).
    pub fn load() -> Result<Filters> {
        let file_path = RULES_FILE;

        if !Path::new(file_path).exists() {
            // No filters file yet – treat as empty set of filters.
            eprintln!("Filters file not found at {RULES_FILE}, creating empty rules file");
            let filters = Filters(Vec::new());
            persist_filters(&filters.0)?;
            return Ok(filters);
        }

        let content = std::fs::read_to_string(file_path)?;
        if content.trim().is_empty() {
            return Ok(Filters(Vec::new()));
        }

        let root: toml::Value = toml::from_str(&content)?;
        let filters_vec = root
            .get("filters")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_table())
                    .filter_map(|table| {
                        let record_type = table.get("record_type")?.as_str()?.to_string();
                        let action_str = table.get("action")?.as_str()?.to_string();
                        let action = FilterAction::from_str(&action_str.to_lowercase()).ok()?;
                        Some(AuditFilter {
                            record_type,
                            action,
                        })
                    })
                    .collect()
            })
            .unwrap_or_else(Vec::new);

        Ok(Filters(filters_vec))
    }
}

/// Free function used by the shared state loader.
pub fn load_filters() -> Result<Filters> {
    Filters::load()
}

/// Persist the provided filters into the shared rules file (`rules.toml`),
/// while preserving other top-level sections such as `watches`.
///
/// **Parameters:**
///
/// * `filters`: Slice of `AuditFilter`s that should become the authoritative
///   `filters` section in the rules file.
fn persist_filters(filters: &[AuditFilter]) -> Result<()> {
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

    let array: Vec<toml::Value> = filters
        .iter()
        .map(|f| {
            let mut table = toml::map::Map::new();
            table.insert(
                "record_type".into(),
                toml::Value::String(f.record_type.clone()),
            );
            table.insert(
                "action".into(),
                toml::Value::String(f.action.as_ref().to_string()),
            );
            toml::Value::Table(table)
        })
        .collect();

    // Overwrite just the `filters` section while preserving others (e.g. `watches`)
    root_table.insert("filters".into(), toml::Value::Array(array));

    // Ensure a `watches` key exists so that a freshly created rules file
    // always has both top-level sections initialized.
    // should be raised elsewhere
    if !root_table.contains_key("watches") {
        root_table.insert("watches".into(), toml::Value::Array(Vec::new()));
    }

    std::fs::write(
        file_path,
        toml::to_string_pretty(&toml::Value::Table(root_table))?,
    )?;
    Ok(())
}

/// Insert or update a single filter in the rules file.
///
/// If a filter with the same `record_type` already exists, its `action` is
/// replaced; otherwise a new filter entry is appended.
///
/// **Parameters:**
///
/// * `filter`: The `AuditFilter` to upsert into the current filter set.
fn set_filter(filter: AuditFilter) -> Result<()> {
    let mut current = load_filters()?;
    // Replace or append.
    if let Some(existing) = current
        .0
        .iter_mut()
        .find(|f| f.record_type == filter.record_type)
    {
        *existing = filter;
    } else {
        current.0.push(filter);
    }

    persist_filters(&current.0)
}

/// Remove any filters whose `record_type` matches the provided record type
/// (case-insensitive) and persist the result.
///
/// **Parameters:**
///
/// * `record_type`: Record type identifier to remove filters for.
fn remove_filter(record_type: &str) -> Result<()> {
    let mut current = load_filters()?;
    current
        .0
        .retain(|f| !f.record_type.eq_ignore_ascii_case(record_type));
    persist_filters(&current.0)
}

/// Print all filters from the rules file using the pre-loaded shared state.
///
/// **Parameters:**
///
/// * `state`: Shared application `State` containing preloaded `Filters`.
pub fn get_filters(state: &State) -> Result<()> {
    let filters = state.rules.filters.as_slice();
    if filters.is_empty() {
        println!("No filters defined");
    } else {
        println!("Filters:");
        for filter in filters {
            println!("    {}: {}", filter.record_type, filter.action.as_ref());
        }
    }
    Ok(())
}

/// Add a single filter via interactive prompts.
///
/// The user is prompted for a valid audit record type and a filter action, and
/// the resulting `AuditFilter` is persisted into the rules file.
///
/// **Parameters:**
///
/// * `_state`: Currently unused, included for symmetry with other interactive
///   commands that may need shared state.
pub fn add_filter_interactive(_state: &State) -> Result<()> {
    let record_type = inquire::Text::new("Enter a record type to filter on:")
        .with_autocomplete(RecordTypeAutoCompleter::default())
        .with_validator(|input: &str| {
            let is_valid = RecordType::iter()
                .any(|rt: RecordType| rt.as_audit_str().eq_ignore_ascii_case(input.trim()));

            if is_valid {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "Please enter a valid record type (use suggestions)".into(),
                ))
            }
        })
        .with_formatter(&|i| i.to_lowercase())
        .with_page_size(12)
        .prompt()?
        .trim()
        .to_string()
        .to_lowercase();

    if record_type.is_empty() {
        return Err(anyhow!("record type cannot be empty"));
    }

    let actions: Vec<String> = FilterAction::iter()
        .map(|a| a.as_ref().to_string())
        .collect();
    let action_str = Select::new("Select an action for this record type", actions).prompt()?;
    let action = FilterAction::from_str(&action_str.to_lowercase())?;

    let filter = AuditFilter {
        record_type,
        action,
    };
    set_filter(filter)
}

/// Remove a filter via interactive prompt with fuzzy autocomplete over existing
/// filters only.
///
/// The user selects a `record_type` from currently configured filters and the
/// corresponding filter entry is removed from the rules file.
///
/// **Parameters:**
///
/// * `state`: Shared application `State` used to obtain existing `Filters`.
pub fn remove_filter_interactive(state: &State) -> Result<()> {
    let existing = state.rules.filters.record_types();
    if existing.is_empty() {
        return Err(anyhow!("No filters defined; nothing to remove."));
    }
    let completer = StringListAutoCompleter::new(existing.clone());
    let record_type = inquire::Text::new("Select a record type to remove:")
        .with_autocomplete(completer)
        .with_validator(move |input: &str| {
            let trimmed = input.trim().to_lowercase();
            if existing.iter().any(|s| s.eq_ignore_ascii_case(&trimmed)) {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "Please choose one of the existing filter record types (use suggestions)."
                        .into(),
                ))
            }
        })
        .with_formatter(&|i| i.to_lowercase())
        .with_page_size(12)
        .prompt()?
        .trim()
        .to_string()
        .to_lowercase();

    remove_filter(&record_type)
}

/// Update an existing filter's action via interactive prompt; record type
/// chosen from current filters only.
///
/// The user selects an existing `record_type` and a new action; the matching
/// filter is then updated in the rules file.
///
/// **Parameters:**
///
/// * `state`: Shared application `State` used to obtain and update `Filters`.
pub fn update_filter_interactive(state: &State) -> Result<()> {
    let existing = state.rules.filters.record_types();
    if existing.is_empty() {
        return Err(anyhow!(
            "No filters defined; add a filter first or use 'filter add'."
        ));
    }
    let completer = StringListAutoCompleter::new(existing.clone());
    let record_type = inquire::Text::new("Select a record type to update:")
        .with_autocomplete(completer)
        .with_validator(move |input: &str| {
            let trimmed = input.trim().to_lowercase();
            if existing.iter().any(|s| s.eq_ignore_ascii_case(&trimmed)) {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "Please choose one of the existing filter record types (use suggestions)."
                        .into(),
                ))
            }
        })
        .with_formatter(&|i| i.to_lowercase())
        .with_page_size(12)
        .prompt()?
        .trim()
        .to_string()
        .to_lowercase();

    let actions: Vec<String> = FilterAction::iter()
        .map(|a| a.as_ref().to_string())
        .collect();
    let action_str = Select::new("Select new action for this record type", actions).prompt()?;
    let action = FilterAction::from_str(&action_str.to_lowercase())?;

    let filter = AuditFilter {
        record_type,
        action,
    };
    set_filter(filter)
}

/// Validate raw filter fields and construct an `AuditFilter`.
///
/// **Parameters:**
///
/// * `record_type`: Raw record type string; validated against known
///   `RecordType` variants.
/// * `action`: Raw filter action string; validated as a `FilterAction`.
/// * `location`: Human-readable identifier (file name, line, or index) used in
///   error messages for diagnostics.
fn validate_and_build_filter(
    record_type: &str,
    action: &str,
    location: &str,
) -> Result<AuditFilter> {
    let record_type = record_type.trim();
    let action = action.trim();

    if record_type.is_empty() {
        return Err(anyhow!("{}: record_type is empty", location));
    }
    if action.is_empty() {
        return Err(anyhow!("{}: action is empty", location));
    }

    let parsed_rt = RecordType::from_str(&record_type.to_uppercase()).map_err(|_| {
        anyhow!(
            "{}: unknown record type '{}' (see valid types with `auditrs filter add`)",
            location,
            record_type
        )
    })?;

    let parsed_action = FilterAction::from_str(&action.to_lowercase()).map_err(|_| {
        anyhow!(
            "{}: invalid action '{}' (expected one of: allow, block)",
            location,
            action
        )
    })?;

    Ok(AuditFilter {
        record_type: parsed_rt.as_audit_str().to_lowercase(),
        action: parsed_action,
    })
}

/// Import filters from a TOML rules file into `AuditFilter` values.
///
/// **Parameters:**
///
/// * `content`: Raw TOML file content.
/// * `path`: Filesystem path to the TOML file, used in diagnostics.
fn import_from_toml(content: &str, path: &Path) -> Result<Vec<AuditFilter>> {
    let cleaned = strip_block_comments(content);
    let root: toml::Value = toml::from_str(&cleaned)
        .with_context(|| format!("failed to parse '{}' as TOML", path.display()))?;

    let filters_array = root
        .get("filters")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow!(
                "'{}': missing [[filters]] array at top level",
                path.display()
            )
        })?;

    let mut filters = Vec::new();

    for (i, entry) in filters_array.iter().enumerate() {
        let location = format!("{}:filters[{}]", path.display(), i);
        let table = match entry.as_table() {
            Some(t) => t,
            None => {
                eprintln!("warning: {}: entry is not a table, skipping", location);
                continue;
            }
        };

        let record_type = match table.get("record_type").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                eprintln!(
                    "warning: {}: missing or non-string 'record_type' field, skipping",
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

        match validate_and_build_filter(record_type, action, &location) {
            Ok(f) => filters.push(f),
            Err(e) => eprintln!("warning: {}, skipping", e),
        }
    }

    Ok(filters)
}

/// Import filters from an external `.ars` file and convert them into
/// `AuditFilter` values (used internally by the `auditrs filter import <file>`
/// command).
///
/// **Parameters:**
///
/// * `content`: Raw `.ars` file content.
/// * `path`: Filesystem path to the `.ars` file, used in diagnostics.
fn import_from_ars(content: &str, path: &Path) -> Result<Vec<AuditFilter>> {
    let cleaned = strip_block_comments(content);
    let reader = std::io::BufReader::new(cleaned.as_bytes());
    let mut filters = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        let location = format!("{}:{}", path.display(), line_num + 1);

        let (record_type, action) = match trimmed.split_once(':') {
            Some(pair) => pair,
            None => {
                eprintln!(
                    "warning: {}: invalid syntax '{}' (expected 'record_type: action'), skipping",
                    location, trimmed
                );
                continue;
            }
        };

        match validate_and_build_filter(record_type, action, &location) {
            Ok(f) => filters.push(f),
            Err(e) => eprintln!("warning: {}, skipping", e),
        }
    }

    Ok(filters)
}

/// Import filters from an external file (`.toml` or `.ars` format) and persist
/// them into the main rules file.
///
/// **Parameters:**
///
/// * `file`: Path to the filter definition file to import.
pub fn import_filters(file: &str) -> Result<()> {
    let path = Path::new(file);
    if !path.exists() {
        return Err(anyhow!("file does not exist: {}", file));
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read '{}'", path.display()))?;

    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    let filters = match extension {
        "toml" => import_from_toml(&content, path)?,
        "ars" => import_from_ars(&content, path)?,
        other => {
            return Err(anyhow!(
                "unsupported file extension '.{}' (expected .toml or .ars)",
                other
            ));
        }
    };

    if filters.is_empty() {
        println!("No filters found in '{}'", path.display());
        return Ok(());
    }

    let count = filters.len();
    for filter in filters {
        set_filter(filter)?;
    }

    println!(
        "Successfully imported {} filter(s) from '{}'",
        count,
        path.display()
    );
    Ok(())
}

/// Dump the currently configured filters into an external file in either TOML
/// or ARS format, preserving a generated header.
///
/// **Parameters:**
///
/// * `file`: Base path (with or without extension) to write the dump to.
/// * `state`: Shared application `State` containing the `Filters` to dump.
pub fn dump_filters(file: &str, state: &State) -> Result<()> {
    let filters = state.rules.filters.as_slice();
    if filters.is_empty() {
        return Err(anyhow!("No filters defined; nothing to dump."));
    }

    let filter_file_extension = Select::new(
        "Select a filter file format",
        FILTER_FILE_EXTENSIONS.to_vec(),
    )
    .prompt()?
    .to_lowercase();

    // Replace any user-given extension with the selected extension from the
    // terminal
    let base = Path::new(file).with_extension("");
    let path = base.with_extension(&filter_file_extension);

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory '{}'", parent.display()))?;
        }
    }

    let mut header = String::from("/*\n\nGenerated by auditrs via CLI at ")
        + &current_utc_string()
        + "\n\n*/\n\n";
    let content = match filter_file_extension.as_str() {
        "toml" => to_toml_format(filters)?,
        "ars" => to_ars_format(filters)?,
        _ => return Err(anyhow!("Invalid filter file format")),
    };

    std::fs::write(&path, header.to_string() + &content)
        .with_context(|| format!("failed to write '{}'", path.display()))?;
    println!("Filters dumped to '{}'", path.display());
    Ok(())
}

/// Serialize the provided filters into TOML text containing a top-level
/// `[[filters]]` array.
///
/// **Parameters:**
///
/// * `filters`: Slice of `AuditFilter`s to serialize.
fn to_toml_format(filters: &[AuditFilter]) -> Result<String> {
    let mut table = toml::map::Map::new();
    table.insert(
        "filters".into(),
        toml::Value::Array(
            filters
                .iter()
                .map(|f| {
                    let mut filter_table = toml::map::Map::new();
                    filter_table.insert(
                        "record_type".into(),
                        toml::Value::String(f.record_type.clone()),
                    );
                    filter_table.insert(
                        "action".into(),
                        toml::Value::String(f.action.as_ref().to_string()),
                    );
                    toml::Value::Table(filter_table)
                })
                .collect(),
        ),
    );
    Ok(toml::to_string_pretty(&toml::Value::Table(table))?)
}

/// Serialize the provided filters into the `.ars` line-based text format.
///
/// **Parameters:**
///
/// * `filters`: Slice of `AuditFilter`s to serialize.
fn to_ars_format(filters: &[AuditFilter]) -> Result<String> {
    let mut content = String::new();
    for filter in filters {
        content.push_str(&format!(
            "{}: {}\n",
            filter.record_type,
            filter.action.as_ref()
        ));
    }
    Ok(content)
}
