//! Module defining functions that execute the auditctl commands that auditrs
//! wraps.
//!
//! This module is the single place where we construct and invoke `auditctl`
//! commands, so higher-level config code can stay focused on concepts
//! like watches & filters.

use anyhow::Result;
use std::process::Command;

use crate::config::{AuditWatch, WatchAction};

/// Execute a raw `auditctl` command string.
///
/// The provided `command` should NOT include the leading `auditctl` binary
/// name, only its arguments (e.g. `"-a always,exit -F path=/tmp/foo -F
/// perm=rw"`).
pub fn execute_auditctl_command(command: &str) -> Result<()> {
    Command::new("sh")
        .arg("-c")
        .arg(format!("auditctl {}", command))
        .output()?;
    Ok(())
}

/// Given an `AuditWatch`` and whether we are deleting or adding, return the
/// appropriate `auditctl` command.
fn watch_to_auditctl_format(watch: &AuditWatch, delete: bool) -> String {
    let mut perms = String::new();
    for action in &watch.actions {
        match action {
            WatchAction::Read => perms.push('r'),
            WatchAction::Write => perms.push('w'),
            WatchAction::Execute => perms.push('x'),
        }
    }

    // Using the auditctl cli tool, the dir argument automatically enables recursive
    // watching, the path argument does not allow recursive watching.
    let recursive_str = if watch.recursive { "dir=" } else { "path=" };
    let add_or_delete_str = if delete { "-d" } else { "-a" };
    format!(
        "{} always,exit -F {}{} -F perm={} -k {}",
        add_or_delete_str,
        recursive_str,
        watch.path.to_string_lossy(),
        perms,
        watch.key
    )
}

/// Build and execute the appropriate `auditctl` command for a single
/// `AuditWatch`.
pub fn execute_watch_auditctl_command(watch: &AuditWatch, delete: bool) -> Result<()> {
    if !delete {
        let command = watch_to_auditctl_format(watch, false);
        return execute_auditctl_command(&command);
    }

    let delete_cmd = watch_to_auditctl_format(watch, true);
    println!("Deleting watch: {}", delete_cmd);
    execute_auditctl_command(&delete_cmd)
}
