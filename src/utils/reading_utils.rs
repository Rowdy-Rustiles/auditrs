use std::{fs, path::PathBuf};

use crate::core::correlator::AuditEvent;

/// Reads audit events from JSON files in the primary directory.
/// 
/// **Parameters:**
/// 
/// * `primary_directory`: The path to the primary directory.
pub fn read_from_json(primary_directory: &PathBuf) -> Vec<AuditEvent> {
    let files = fs::read_dir(primary_directory).unwrap();
    let mut events = Vec::new();
    for file in files {
        let file = file.unwrap();
        if file.path().extension().unwrap_or_default() != "json" {
            continue;
        }
        let content = fs::read_to_string(file.path()).unwrap();
        let event: Vec<AuditEvent> = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse JSON: {}", e))
            .unwrap();
        events.extend(event.into_iter());
    }
    events
}

/// Reads audit events from simple files in the primary directory.
/// 
/// **Parameters:**
/// 
/// * `primary_directory`: The path to the primary directory.
pub fn read_from_simple(primary_directory: &PathBuf) -> Vec<AuditEvent> {
    todo!()
}

/// Reads audit events from legacy files in the primary directory.
/// 
/// **Parameters:**
/// 
/// * `primary_directory`: The path to the primary directory.
pub fn read_from_legacy(primary_directory: &PathBuf) -> Vec<AuditEvent> {
    todo!()
}
