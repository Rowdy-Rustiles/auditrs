use anyhow::Result;
use chrono::{DateTime, Utc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn timestamp_string_to_systemtime(secs_micros_str: &str) -> Result<SystemTime> {
    let (secs_str, micros_str) = secs_micros_str
        .split_once('.')
        .ok_or(anyhow::anyhow!("Invalid timestamp format"))?;

    let seconds: u64 = secs_str.parse()?;

    let millis: u64 = micros_str.get(0..3).unwrap_or(micros_str).parse()?;

    Ok(UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_millis(millis))
}

pub fn systemtime_to_utc_string(systemtime: SystemTime) -> String {
    let dt: DateTime<Utc> = systemtime.into();
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn current_utc_string() -> String {
    let dt: DateTime<Utc> = Utc::now();
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn systemtime_to_timestamp_string(systime: SystemTime) -> Result<String> {
    let duration = systime.duration_since(UNIX_EPOCH)?;
    Ok(format!(
        "{}.{:03}",
        duration.as_secs(),
        duration.subsec_millis()
    ))
}

pub fn capitalize_first_letter(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}