use std::time::{SystemTime, UNIX_EPOCH, Duration};

pub fn timestamp_string_to_systemtime(
    secs_micros_str: &str,
) -> Result<SystemTime, Box<dyn std::error::Error>> {

    let (secs_str, micros_str) =
        secs_micros_str.split_once('.')
        .ok_or("Invalid timestamp format")?;

    let seconds: u64 = secs_str.parse()?;

    let millis: u64 = micros_str
        .get(0..3)
        .unwrap_or(micros_str)
        .parse()?;

    Ok(UNIX_EPOCH
        + Duration::from_secs(seconds)
        + Duration::from_millis(millis))
}