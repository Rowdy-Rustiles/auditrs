use config::Config;
use inquire::Select;
use serde::Deserialize;
use crate::config::{CONFIG_FILE, AuditConfig, SetConfigVariables, GetConfigVariables, LogFormat};
use crate::config::input_utils::{RecordTypeAutoCompleter, StringListAutoCompleter};
use crate::parser::audit_types::RecordType;
use inquire::{validator::Validation, formatter::StringFormatter};
use strum::IntoEnumIterator;
use anyhow::{anyhow, Result};

impl std::str::FromStr for LogFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "legacy" => Ok(LogFormat::Legacy),
            "simple" => Ok(LogFormat::Simple),
            "json" => Ok(LogFormat::Json),
            _ => Err(format!("unknown format: {}", s)),
        }
    }
}

/// TODO: initialize default config file if one doesn't exist
/// also, store the config in memory, should be small enough to not cause performance concerns,
/// therefore, we can avoid the IO costs of reading the config file on every operation
pub fn load_config() -> Result<AuditConfig> {
    let config = Config::builder()
        .add_source(config::File::new("Config", config::FileFormat::Toml))
        .build()
        .map_err(|e| anyhow!("{}", e))?;

    // The TOML file has a top-level `[settings]` table; we map that into `AuditConfig`.
    let settings = config.get::<AuditConfig>("settings").map_err(|e| anyhow!("{}", e))?;
    Ok(settings)
}

pub fn set_config(key: SetConfigVariables) -> Result<()> {
    let content = std::fs::read_to_string(CONFIG_FILE)?;
    let mut root: toml::Table = toml::from_str(&content)?;

    let settings = root
        .get_mut("settings")
        .and_then(|v| v.as_table_mut())
        .ok_or_else(|| anyhow!("missing [settings] section"))?;

    match key {
        SetConfigVariables::OutputDirectory { value } => {
            settings.insert("output_directory".into(), toml::Value::String(value));
        }
        SetConfigVariables::LogSize { value } => {
            settings.insert("log_size".into(), toml::Value::Integer(value as i64));
        }
        SetConfigVariables::LogFormat { value } => {
            let s = match value {
                LogFormat::Legacy => "legacy",
                LogFormat::Simple => "simple",
                LogFormat::Json => "json",
            };
            settings.insert("log_format".into(), toml::Value::String(s.to_string()));
        }
        SetConfigVariables::LogFilters {
            record_type,
            action,
        } => {
            let mut filter_table = toml::map::Map::new();
            // I literally have no idea how action is always inserted above record type in the config file.
            // switching these two lines around doesnt do anything
            // it is what it is
            filter_table.insert("record_type".into(), toml::Value::String(record_type.clone()));
            filter_table.insert("action".into(), toml::Value::String(action.clone()));

            if let Some(filters_value) = settings.get_mut("filters") {
                if let Some(filters_array) = filters_value.as_array_mut() {
                    if let Some(existing) = filters_array.iter_mut().find(|v| {
                        v.as_table()
                            .and_then(|t| t.get("record_type"))
                            .and_then(|v| v.as_str())
                            .map(|s| s == record_type)
                            .unwrap_or(false)
                    }) {
                        if let Some(table) = existing.as_table_mut() {
                            table.insert("record_type".into(), toml::Value::String(record_type));
                            table.insert("action".into(), toml::Value::String(action));
                        }
                    } else {
                        filters_array.push(toml::Value::Table(filter_table));
                    }
                } else {
                    return Err(anyhow!("settings.filters is not an array"));
                }
            } else {
                settings.insert(
                    "filters".into(),
                    toml::Value::Array(vec![toml::Value::Table(filter_table)]),
                );
            }
            println!("Filter successfully set");
        }
        SetConfigVariables::RemoveFilter { record_type } => {
            if let Some(filters_value) = settings.get_mut("filters") {
                if let Some(filters_array) = filters_value.as_array_mut() {
                    filters_array.retain(|v| {
                        v.as_table()
                            .and_then(|t| t.get("record_type"))
                            .and_then(|v| v.as_str())
                            .map(|s| s != record_type)
                            .unwrap_or(true)
                    });
                }
            }
            println!("Filter successfully removed");
        }
    }

    std::fs::write(CONFIG_FILE, toml::to_string_pretty(&root)?)?;
    Ok(())
}

/// Print config values (used by `config get`).
pub fn get_config(key: Option<GetConfigVariables>) -> Result<()> {
    let config = load_config()?;
    match key {
        Some(GetConfigVariables::OutputDirectory) => {
            println!("output_directory: {}", config.output_directory);
        }
        Some(GetConfigVariables::LogSize) => println!("log_size: {}", config.log_size),
        Some(GetConfigVariables::LogFormat) => println!("log_format: {}", config.log_format),
        Some(GetConfigVariables::LogFilters) => println!("filters: {:?}", config.filters),
        None => println!("{:?}", config),
    }
    Ok(())
}


/// TODO: if this file gets too longer, we'll split the config files into multiple files by CLI subcommand

/// Gets all filters from the config file
pub fn get_filters() -> Result<()> {
    let config = load_config()?;
    let filters = config.filters.as_slice();
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

/// Add a single filter via interactive prompts 
pub fn add_filter_interactive() -> Result<()> {
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
        .prompt()
        .map_err(|e| anyhow::anyhow!("{}", e))?
        .trim()
        .to_string()
        .to_lowercase();
    if record_type.is_empty() {
        return Err(anyhow!("record type cannot be empty"));
    }

    let filter_actions: Vec<&str> = vec!["Allow", "Block"];
    let action = Select::new("Select an action for this record type", filter_actions)
        .prompt()
        .map_err(|e| anyhow::anyhow!("{}", e))?
        .to_lowercase();

    set_config(SetConfigVariables::LogFilters {
        record_type,
        action,
    })
}

/// Remove a filter by record type (direct; use for CLI when value is provided).
pub fn remove_filter(record_type: String) -> Result<()> {
    set_config(SetConfigVariables::RemoveFilter { record_type })
}

/// Remove a filter via interactive prompt with fuzzy autocomplete over existing filters only.
pub fn remove_filter_interactive() -> Result<()> {
    let config = load_config()?;
    let existing = config.filters.record_types();
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
                    "Please choose one of the existing filter record types (use suggestions).".into(),
                ))
            }
        })
        .with_formatter(&|i| i.to_lowercase())
        .prompt()
        .map_err(|e| anyhow::anyhow!("{}", e))?
        .trim()
        .to_string()
        .to_lowercase();
    set_config(SetConfigVariables::RemoveFilter { record_type })
}

/// Update an existing filter's action via interactive prompt; record type chosen from current config only.
pub fn update_filter_interactive() -> Result<()> {
    let config = load_config()?;
    let existing = config.filters.record_types();
    if existing.is_empty() {
        return Err(anyhow!("No filters defined; add a filter first or use 'filter add'."));
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
                    "Please choose one of the existing filter record types (use suggestions).".into(),
                ))
            }
        })
        .with_formatter(&|i| i.to_lowercase())
        .prompt()
        .map_err(|e| anyhow::anyhow!("{}", e))?
        .trim()
        .to_string()
        .to_lowercase();
    let filter_actions: Vec<&str> = vec!["Allow", "Block"];
    let action = Select::new("Select new action for this record type", filter_actions)
        .prompt()
        .map_err(|e| anyhow::anyhow!("{}", e))?
        .to_lowercase();
    set_config(SetConfigVariables::LogFilters {
        record_type,
        action,
    })
}