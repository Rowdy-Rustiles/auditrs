//! Module defining functions that execute the auditctl commands that auditrs
//! wraps. For features like watches, it is not enough to look for commands
//! affecting given paths, we need to tell Linux Audit Subsystem to send us
//! events related to actions taken on those paths.
//!
//! This module is the single place where we construct and invoke `auditctl`
//! commands, so higher-level config code can stay focused on concepts
//! like watches & filters.

use anyhow::Result;
use std::process::Command;

use crate::config::{AuditWatch, WatchAction};

// TODO: to persist the auditctl rules between reboots, we need to add them to
// /etc/audit/audit.rules, this should be done at the same time as the watches
// are added to /etc/auditrs/rules.toml and auditctl.

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
    let mut recursive_str = String::new();
    let mut path_str = String::from(watch.path.to_string_lossy());
    if watch.recursive {
        recursive_str = "dir=".to_string();
        if !path_str.ends_with('/') {
            path_str.push('/');
        }
    } else {
        recursive_str = "path=".to_string();
        if path_str.ends_with('/') {
            path_str.pop();
        }
    }
    let add_or_delete_str = if delete { "-d" } else { "-a" };
    format!(
        "{} always,exit -F {}{} -F perm={} -k {}",
        add_or_delete_str, recursive_str, path_str, perms, watch.key
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
