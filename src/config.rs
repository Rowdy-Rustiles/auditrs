use serde::Deserialize;
use config::{Config};
use std::io::{self, Write};

// Thin audit filters wrapper for printing extensibility
#[derive(Debug, Deserialize)]
struct Filters(Vec<AuditFilter>);

#[derive(Debug, Deserialize)]
pub enum GetConfigVariables {
    OutputDirectory,
    LogSize,
    LogFormat,
    LogFilters,
}


#[derive(Debug, Deserialize)]
pub enum SetConfigVariables {
    OutputDirectory {
        value: String,
    },
    LogSize {
        value: usize,
    },
    LogFormat {
        value: LogFormat,
    },
    /// Raw filter expression or YAML snippet for now
        LogFilters 
}

#[derive(Debug, Deserialize)]
pub struct AuditConfig {
    pub output_directory: String,
    pub log_size: usize,
    pub log_format: String,
    pub filters: Filters,
}

#[derive(Debug, Deserialize)]
pub struct AuditFilter {
    record_type: String,
    action: Action,
}

#[derive(Copy, Clone, Debug, Deserialize)]
enum LogFormat {
    Legacy,
    Simple,
    Json,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum Action {
    Allow,
    Block,
}

pub fn load_config() -> Result<AuditConfig, Box<dyn std::error::Error>> {
    let config = Config::builder()
        .add_source(config::File::new("Config", config::FileFormat::Toml))
        .build()?;

    // The TOML file has a top-level `[settings]` table; we map that into `AuditConfig`.
    let settings = config.get::<AuditConfig>("settings")?;
    Ok(settings)
}

pub fn set_config(key: SetConfigVariables) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "config.toml";
    let content = std::fs::read_to_string(file_path)?;
    let mut root: toml::Table = toml::from_str(&content)?;

    let settings = root
        .get_mut("settings")
        .and_then(|v| v.as_table_mut())
        .ok_or("missing [settings] section")?;

    println!("settings: {:?}", settings);

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
        SetConfigVariables::LogFilters => {
            print!("Enter a record type to filter on: ");
            io::stdout().flush()?;
            let mut record_type = String::new();
            io::stdin().read_line(&mut record_type)?;
            let record_type = record_type.trim();

            print!("Enter an action for the filter {{ allow | block }}: ");
            io::stdout().flush()?;
            let mut action = String::new();
            io::stdin().read_line(&mut action)?;
            let action = action.trim();

            // Build new filter table
            let mut filter_table = toml::map::Map::new();
            filter_table.insert("action".into(), toml::Value::String(action.to_string()));
            filter_table.insert("record_type".into(), toml::Value::String(record_type.to_string()));

            if let Some(filters_value) = settings.get_mut("filters") {
                if let Some(filters_array) = filters_value.as_array_mut() {
                    // Find existing filter for this record_type
                    if let Some(existing) = filters_array.iter_mut().find(|v| {
                        v.as_table()
                            .and_then(|t| t.get("record_type"))
                            .and_then(|v| v.as_str())
                            .map(|s| s == record_type)
                            .unwrap_or(false)
                    }) {
                        // Update existing
                        if let Some(table) = existing.as_table_mut() {
                            table.insert(
                                "action".into(),
                                toml::Value::String(action.to_string()),
                            );
                            table.insert(
                                "record_type".into(),
                                toml::Value::String(record_type.to_string()),
                            );
                        }
                    } else {
                        // Insert new filter
                        filters_array.push(toml::Value::Table(filter_table));
                    }
                } else {
                    return Err("settings.filters is not an array".into()); 
                }
            } else {
                // Create new filters array
                settings.insert(
                    "filters".into(),
                    toml::Value::Array(vec![toml::Value::Table(filter_table)]),
                );
            }
        }
    }

    std::fs::write(file_path, toml::to_string_pretty(&root)?)?;
    Ok(())
}

pub fn get_config(key: Option<GetConfigVariables>) -> Result<(), anyhow::Error> {
    let config = load_config().map_err(|e| anyhow::anyhow!("{}", e))?;
    match key {
        Some(GetConfigVariables::OutputDirectory) => {
            println!("OutputDirectory: {:?}", config.output_directory)
        }
        Some(GetConfigVariables::LogSize) => println!("LogSize: {:?}", config.log_size),
        Some(GetConfigVariables::LogFormat) => println!("LogFormat: {:?}", config.log_format),
        Some(GetConfigVariables::LogFilters) => println!("LogFilters: {:?}", config.filters),
        None => println!("{:?}", config),
    }
    Ok(())
}
