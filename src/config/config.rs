use crate::config::{AuditConfig, CONFIG_FILE, GetConfigVariables, LogFormat, SetConfigVariables};
use std::{fs::{OpenOptions}, io::{Write}};
use std::path::Path;
use anyhow::{Result, anyhow};
use config::Config;
use inquire::Select;

const DEFAULT_CONFIG: &str = r#"[meta]
version = "0.3.0"

[settings]
log_format = "legacy"
log_size = 65536
output_directory = "/var/log/auditrs"
"#;

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
impl AuditConfig {
    pub fn load_config() -> Result<AuditConfig> {
        if !Path::new(CONFIG_FILE).exists() {
            eprintln!("Config file not found, creating default file");
            let mut config_file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(CONFIG_FILE)?;
            write!(config_file, "{}", DEFAULT_CONFIG)?;
        }

        let config = Config::builder()
            .add_source(config::File::new("Config", config::FileFormat::Toml))
            .build()
            .map_err(|e| anyhow!("{}", e))?;

        // The TOML file has a top-level `[settings]` table; we map that into `AuditConfig`.
        let settings = config
            .get::<AuditConfig>("settings")
            .map_err(|e| anyhow!("{}", e))?;
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
            SetConfigVariables::LogFormat { } => {
                let log_formats: Vec<&str> = vec!["Legacy", "Simple", "Json"];
                let log_format = Select::new("Select a log format", log_formats)
                .prompt()
                .map_err(|e| anyhow!("{}", e))?
                .to_lowercase();
            
                settings.insert("log_format".into(), toml::Value::String(log_format.to_string().to_lowercase()));
            }
        }
        let write_result = std::fs::write(CONFIG_FILE, toml::to_string_pretty(&root)?);
        if write_result.is_err() {
            return Err(anyhow!("Failed to save config to {}", CONFIG_FILE));
        } else {
        println!("Config successfully saved to {}", CONFIG_FILE);
        }
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
            None => println!("{:?}", config),
        }
        Ok(())
    }
}

/// Convenience free functions re-exported from the `config` module.
pub fn load_config() -> Result<AuditConfig> {
    AuditConfig::load_config()
}

pub fn set_config(key: SetConfigVariables) -> Result<()> {
    AuditConfig::set_config(key)
}

pub fn get_config(key: Option<GetConfigVariables>) -> Result<()> {
    AuditConfig::get_config(key)
}
