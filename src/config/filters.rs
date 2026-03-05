use crate::config::input_utils::{RecordTypeAutoCompleter, StringListAutoCompleter};
use crate::config::{AuditFilter, Filters, FILTERS_FILE, State};
use crate::parser::audit_types::RecordType;
use anyhow::{anyhow, Result};
use inquire::Select;
use inquire::{formatter::StringFormatter, validator::Validation};
use std::path::Path;
use strum::IntoEnumIterator;
use toml;

impl Filters {
    /// Returns the list of record types currently defined in the filters (for autocomplete).
    pub fn record_types(&self) -> Vec<String> {
        self.0.iter().map(|f| f.record_type.clone()).collect()
    }

    /// Returns the underlying filter list.
    pub fn as_slice(&self) -> &[AuditFilter] {
        &self.0
    }

    /// Load filters from the dedicated filters file.
    pub fn load() -> Result<Filters> {
        let file_path = FILTERS_FILE;

        if !Path::new(file_path).exists() {
            // No filters file yet – treat as empty set of filters.
            return Ok(Filters(Vec::new()));
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
                        let action = table.get("action")?.as_str()?.to_string();
                        Some(AuditFilter { record_type, action })
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

fn persist_filters(filters: &[AuditFilter]) -> Result<()> {
    let file_path = FILTERS_FILE;

    let array: Vec<toml::Value> = filters
        .iter()
        .map(|f| {
            let mut table = toml::map::Map::new();
            table.insert("record_type".into(), toml::Value::String(f.record_type.clone()));
            table.insert("action".into(), toml::Value::String(f.action.clone()));
            toml::Value::Table(table)
        })
        .collect();

    let mut root = toml::map::Map::new();
    root.insert("filters".into(), toml::Value::Array(array));

    std::fs::write(file_path, toml::to_string_pretty(&toml::Value::Table(root))?)?;
    Ok(())
}

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

fn remove_filter(record_type: &str) -> Result<()> {
    let mut current = load_filters()?;
    current
        .0
        .retain(|f| !f.record_type.eq_ignore_ascii_case(record_type));
    persist_filters(&current.0)
}

/// Gets all filters from the filters file using the pre-loaded state.
pub fn get_filters(state: &State) -> Result<()> {
    let filters = state.filters.as_slice();
    if filters.is_empty() {
        println!("No filters defined");
    } else {
        println!("Filters:");
        for filter in filters {
            println!("    {}: {}", filter.record_type, filter.action);
        }
    }
    Ok(())
}

/// Add a single filter via interactive prompts.
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
        .prompt()
        .map_err(|e| anyhow!("{}", e))?
        .trim()
        .to_string()
        .to_lowercase();

    if record_type.is_empty() {
        return Err(anyhow!("record type cannot be empty"));
    }

    let filter_actions: Vec<&str> = vec!["allow", "block"];
    let action = Select::new("Select an action for this record type", filter_actions)
        .prompt()
        .map_err(|e| anyhow!("{}", e))?
        .to_lowercase();

    let filter = AuditFilter { record_type, action };
    set_filter(filter)
}

/// Remove a filter via interactive prompt with fuzzy autocomplete over existing filters only.
pub fn remove_filter_interactive(state: &State) -> Result<()> {
    let existing = state.filters.record_types();
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
        .prompt()
        .map_err(|e| anyhow!("{}", e))?
        .trim()
        .to_string()
        .to_lowercase();

    remove_filter(&record_type)
}

/// Update an existing filter's action via interactive prompt; record type chosen from current filters only.
pub fn update_filter_interactive(state: &State) -> Result<()> {
    let existing = state.filters.record_types();
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
        .prompt()
        .map_err(|e| anyhow!("{}", e))?
        .trim()
        .to_string()
        .to_lowercase();

    let filter_actions: Vec<&str> = vec!["allow", "block"];
    let action = Select::new("Select new action for this record type", filter_actions)
        .prompt()
        .map_err(|e| anyhow!("{}", e))?
        .to_lowercase();

    let filter = AuditFilter { record_type, action };
    set_filter(filter)
}