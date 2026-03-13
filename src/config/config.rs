use anyhow::{Context, Result, anyhow};
use config::Config;
use inquire::{Confirm, Select, Text, validator::Validation};
use std::path::Path;
use std::{fs, fs::OpenOptions, io::Write};

use crate::config::{
    AuditConfig, CONFIG_DIR, CONFIG_FILE, DEFAULT_CONFIG, GetConfigVariables, LOG_FORMATS,
    LogFormat, MINIMUM_JOURNAL_SIZE, MINIMUM_LOG_SIZE, MINIMUM_PRIMARY_SIZE, SetConfigVariables,
};
use crate::utils::capitalize_first_letter;


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

impl AuditConfig {
    // TODO: it would be nice if we could automatically resolve missing config key
    // errors
    /// Load the auditrs configuration from the config file.
    pub fn load_config() -> Result<AuditConfig> {
        if !Path::new(CONFIG_FILE).exists() {
            eprintln!("Config file not found at {CONFIG_FILE}, creating default");
            fs::create_dir_all(CONFIG_DIR)
                .context(format!("Could not create folders for: {CONFIG_DIR}"))?;
            let mut config_file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(CONFIG_FILE)
                .context(format!("Could not create config file at {CONFIG_FILE}"))?;
            write!(config_file, "{}", DEFAULT_CONFIG)
                .context(format!("Could not write to config file at {CONFIG_FILE}"))?;
        }

        let config = Config::builder()
            .add_source(config::File::new(
                CONFIG_FILE.trim_end_matches(".toml"),
                config::FileFormat::Toml,
            ))
            .build()?;

        // The TOML file has a top-level `[settings]` table; we map that into
        // `AuditConfig`.
        let settings = config.get::<AuditConfig>("settings")?;
        Ok(settings)
    }

    /// TODO: decide if we want to use inquire for input or directly handle CLI
    /// arguments For the set directory command, we can use the CLI
    /// arguments directly since most terminals have autocompletions for
    /// paths. But for the set size and format commands, we use inquire,
    /// would we want unify this?
    pub fn set_config(key: SetConfigVariables) -> Result<()> {
        // Config is loaded for the help messages, it could probably be removed later
        let config = load_config()?;
        let content = std::fs::read_to_string(CONFIG_FILE)?;
        let mut root: toml::Table = toml::from_str(&content)?;

        let settings = root
            .get_mut("settings")
            .and_then(|v| v.as_table_mut())
            .ok_or(anyhow!("missing [settings] section"))?;

        match key {
            SetConfigVariables::LogDirectory { value } => {
                settings.insert("active_directory".into(), toml::Value::String(value));
            }
            SetConfigVariables::JournalDirectory { value } => {
                settings.insert("journal_directory".into(), toml::Value::String(value));
            }
            SetConfigVariables::PrimaryDirectory { value } => {
                settings.insert("primary_directory".into(), toml::Value::String(value));
            }
            SetConfigVariables::LogSize => {
                let current_size = config.log_size;
                let log_size = Text::new("Enter a new log size (in bytes):")
                    .with_help_message(&format!("Current log size: {} bytes", current_size))
                    .with_validator(|input: &str| {
                        // Enforce minimum log size (8 KB)
                        match input.parse::<usize>() {
                            Err(e) => Ok(Validation::Invalid(format!("{}", e).into())),
                            Ok(size) if size < MINIMUM_LOG_SIZE => Ok(Validation::Invalid(
                                format!("Log size must be at least {} bytes", MINIMUM_LOG_SIZE)
                                    .into(),
                            )),
                            Ok(_) => Ok(Validation::Valid),
                        }
                    })
                    .prompt()?
                    .parse::<usize>()?;
                settings.insert("log_size".into(), toml::Value::Integer(log_size as i64));
            }
            SetConfigVariables::JournalSize => {
                let current_size = config.journal_size;
                let journal_size = Text::new("Enter a new journal size (in logs):")
                    .with_help_message(&format!("Current journal size: {} logs", current_size))
                    .with_validator(|input: &str| match input.parse::<usize>() {
                        Err(e) => Ok(Validation::Invalid(format!("{}", e).into())),
                        Ok(size) if size < MINIMUM_JOURNAL_SIZE => Ok(Validation::Invalid(
                            format!(
                                "Journal size must be at least {} logs",
                                MINIMUM_JOURNAL_SIZE
                            )
                            .into(),
                        )),
                        Ok(_) => Ok(Validation::Valid),
                    })
                    .prompt()?
                    .parse::<usize>()?;
                settings.insert(
                    "journal_size".into(),
                    toml::Value::Integer(journal_size as i64),
                );
            }
            SetConfigVariables::PrimarySize => {
                let current_size = config.primary_size;
                let primary_size = Text::new("Enter a new primary size (in bytes):")
                    .with_help_message(&format!("Current primary size: {} bytes", current_size))
                    .with_validator(|input: &str| match input.parse::<usize>() {
                        Err(e) => Ok(Validation::Invalid(format!("{}", e).into())),
                        Ok(size) if size < MINIMUM_PRIMARY_SIZE => Ok(Validation::Invalid(
                            format!(
                                "Primary size must be at least {} bytes",
                                MINIMUM_PRIMARY_SIZE
                            )
                            .into(),
                        )),
                        Ok(_) => Ok(Validation::Valid),
                    })
                    .prompt()?
                    .parse::<usize>()?;
                settings.insert(
                    "primary_size".into(),
                    toml::Value::Integer(primary_size as i64),
                );
            }
            SetConfigVariables::LogFormat {} => {
                let current_fmt = capitalize_first_letter(&config.log_format.to_string());
                let log_format = Select::new("Select a log format", LOG_FORMATS.to_vec())
                    .with_help_message(&format!(
                        "Current log format: {}]\n[{}",
                        current_fmt,
                        Select::<&str>::DEFAULT_HELP_MESSAGE.unwrap()
                    ))
                    .prompt()?
                    .to_lowercase();

                settings.insert(
                    "log_format".into(),
                    toml::Value::String(log_format.to_string().to_lowercase()),
                );
            }
        }
        let write_result = std::fs::write(CONFIG_FILE, toml::to_string_pretty(&root)?);

        write_result
            .with_context(|| format!("Failed to save config to {}", CONFIG_FILE))
            .inspect(|_| println!("Config successfully saved to {}", CONFIG_FILE))
    }

    /// Print config values (used by `config get`).
    pub fn get_config(key: Option<GetConfigVariables>) -> Result<()> {
        let config = load_config()?;
        match key {
            Some(GetConfigVariables::LogDirectory) => println!("{}", config.active_directory),
            Some(GetConfigVariables::JournalDirectory) => println!("{}", config.journal_directory),
            Some(GetConfigVariables::PrimaryDirectory) => println!("{}", config.primary_directory),
            Some(GetConfigVariables::LogSize) => println!("{} bytes", config.log_size),
            Some(GetConfigVariables::JournalSize) => println!("{} logs", config.journal_size),
            Some(GetConfigVariables::PrimarySize) => println!("{} bytes", config.primary_size),
            Some(GetConfigVariables::LogFormat) => println!(
                "{}",
                capitalize_first_letter(&config.log_format.to_string())
            ),
            None => println!("{}", config.to_string()),
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

impl LogFormat {
    pub fn to_string(&self) -> String {
        match self {
            LogFormat::Legacy => "legacy".to_string(),
            LogFormat::Simple => "simple".to_string(),
            LogFormat::Json => "json".to_string(),
        }
    }

    /// Get the extension for the log file based on the log format
    /// Each log format has a unique extension for easier identification and
    /// parsing.
    pub fn get_extension(&self) -> String {
        match self {
            LogFormat::Legacy => "log".to_string(),
            LogFormat::Simple => "slog".to_string(), // i like this
            LogFormat::Json => "json".to_string(),
        }
    }
}

impl AuditConfig {
    pub fn to_string(&self) -> String {
        format!(
            "Log format: {}\nLog directory: {}\nJournal directory: {}\nPrimary directory: {}\nLog size: {} bytes\nJournal size: {} logs\nPrimary size: {} bytes",
            capitalize_first_letter(&self.log_format.to_string()),
            self.active_directory,
            self.journal_directory,
            self.primary_directory,
            self.log_size,
            self.journal_size,
            self.primary_size,
        )
    }
}
