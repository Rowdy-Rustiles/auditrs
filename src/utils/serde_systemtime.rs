//! Serde helpers for [`std::time::SystemTime`] as RFC3339 UTC strings with
//! millisecond precision, matching [`super::systemtime_to_utc_string`].

use serde::{Deserialize, Deserializer, Serializer};
use std::time::SystemTime;

use super::systemtime_to_utc_string;

/// Serializes `SystemTime` using the same format as the JSON log writer.
pub fn serialize<S>(t: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&systemtime_to_utc_string(*t))
}

/// Deserializes RFC3339 UTC strings (i.e. from primary JSON logs) into
/// `SystemTime`.
pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let dt = chrono::DateTime::parse_from_rfc3339(s.trim()).map_err(serde::de::Error::custom)?;
    Ok(SystemTime::from(dt))
}
