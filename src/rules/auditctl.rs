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
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
};

use crate::rules::{AUDIT_RULES_FILE, AuditWatch, WatchAction};

// TODO: to persist the auditctl rules between reboots, we need to add them to
// /etc/audit/audit.rules, this should be done at the same time as the watches
// are added to /etc/auditrs/rules.toml and auditctl.

/// Execute a raw `auditctl` command string.
///
/// The provided `command` should NOT include the leading `auditctl` binary
/// name, only its arguments (e.g. `"-a always,exit -F path=/tmp/foo -F
/// perm=rw"`).
fn execute_auditctl_command(command: &str) -> Result<()> {
    Command::new("sh")
        .arg("-c")
        .arg(format!("auditctl {}", command))
        .output()?;

    persist_audit_rule(command)?;
    Ok(())
}

/// Check the default audit rules file for the presence of the auditrs signature
/// at the top: `# auditrs` If it is not present, we clear the file and add the
/// signature.
///
/// TODO: This is a workaround avoiding that we should ultimately be loading the
/// audit rules from `/etc/auditrs/rules.toml` on system startup. Eventually,
/// when the custom auditctl implementation is underway, we should seek to
/// replace rewrite this function.
fn prepare_audit_rules_file() -> Result<()> {
    // Open the rules file for both reading and writing so we can inspect and,
    // if necessary, rewrite its contents.
    let mut rules_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(AUDIT_RULES_FILE)?;

    let mut reader = BufReader::new(&rules_file);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line != "# auditrs\n" {
        rules_file.seek(SeekFrom::Start(0))?;
        rules_file.set_len(0)?;
        rules_file.write_all(b"# auditrs\n")?;
        rules_file.flush()?;
    }
    Ok(())
}

/// Persist a single audit rule to the audit rules file at
/// `/etc/audit/audit.rules`.
///
/// **Parameters:**
///
/// * `rule`: The audit rule to persist.
fn persist_audit_rule(rule: &str) -> Result<()> {
    // This is a lot of unnecessary IO
    prepare_audit_rules_file()?;

    let mut rules_file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(AUDIT_RULES_FILE)?;

    rules_file.write_all(format!("{}\n", rule).as_bytes())?;
    rules_file.flush()?;
    Ok(())
}

/// Given an `AuditWatch`` and whether we are deleting or adding, return the
/// appropriate `auditctl` command.
///
/// **Parameters:**
///
/// * `watch`: The `AuditWatch` to convert to an `auditctl` command.
/// * `delete`: Whether we are deleting or adding the watch.
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
///
/// **Parameters:**
///
/// * `watch`: The `AuditWatch` to execute the `auditctl` command for.
/// * `delete`: Whether we are deleting or adding the watch.
pub fn execute_watch_auditctl_command(watch: &AuditWatch, delete: bool) -> Result<()> {
    if !delete {
        let command = watch_to_auditctl_format(watch, false);
        return execute_auditctl_command(&command);
    }

    let delete_cmd = watch_to_auditctl_format(watch, true);
    println!("Deleting watch: {}", delete_cmd);
    execute_auditctl_command(&delete_cmd)
}
