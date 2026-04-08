//! Apply path watches to the Linux audit subsystem via netlink (`add_rule` /
//! `del_rule`), and optionally persist auditctl-compatible lines to
//! `/etc/audit/audit.rules` for distro tooling (see persistence policy in
//! module docs).

use anyhow::Result;
use audit::packet::{
    RuleAction,
    RuleField,
    RuleFieldFlags,
    RuleFlags,
    RuleMessage,
    RuleSyscalls,
    constants::{AUDIT_PERM_EXEC, AUDIT_PERM_READ, AUDIT_PERM_WRITE},
};
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
};

use crate::core::netlink::apply_audit_rule_message;
use crate::rules::{AUDIT_RULES_FILE, AuditWatch, WatchAction};

/// Build a [`RuleMessage`] matching the prior `auditctl` watch shape:
/// always,exit with path/dir, perm, and key.
pub fn audit_watch_to_rule_message(watch: &AuditWatch) -> RuleMessage {
    let mut perm: u32 = 0;
    for action in &watch.actions {
        match action {
            WatchAction::Read => perm |= AUDIT_PERM_READ,
            WatchAction::Write => perm |= AUDIT_PERM_WRITE,
            WatchAction::Execute => perm |= AUDIT_PERM_EXEC,
        }
    }

    let mut path_str = String::from(watch.path.to_string_lossy());
    let path_field = if watch.recursive {
        if !path_str.ends_with('/') {
            path_str.push('/');
        }
        RuleField::Dir(path_str)
    } else {
        if path_str.ends_with('/') {
            path_str.pop();
        }
        RuleField::Watch(path_str)
    };

    let mut rule = RuleMessage::default();
    rule.flags = RuleFlags::FilterExit;
    rule.action = RuleAction::Always;
    rule.fields = vec![
        (path_field, RuleFieldFlags::Equal),
        (RuleField::Perm(perm), RuleFieldFlags::Equal),
        (
            RuleField::Filterkey(watch.key.clone()),
            RuleFieldFlags::Equal,
        ),
    ];
    rule.syscalls = RuleSyscalls::new_maxed();
    rule
}

/// Human-readable audit rule line for `/etc/audit/audit.rules` (auditctl
/// argument form, without the `auditctl` binary name). Kept stable for minimal
/// persistence diff.
fn watch_to_audit_rules_file_line(watch: &AuditWatch, delete: bool) -> String {
    let mut perms = String::new();
    for action in &watch.actions {
        match action {
            WatchAction::Read => perms.push('r'),
            WatchAction::Write => perms.push('w'),
            WatchAction::Execute => perms.push('x'),
        }
    }

    let recursive_str;
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

fn prepare_audit_rules_file() -> Result<()> {
    let mut rules_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
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

fn persist_audit_rule_line(line: &str) -> Result<()> {
    prepare_audit_rules_file()?;

    let mut rules_file = OpenOptions::new().append(true).open(AUDIT_RULES_FILE)?;

    rules_file.write_all(format!("{line}\n").as_bytes())?;
    rules_file.flush()?;
    Ok(())
}

/// Add or remove a single watch in the kernel and append a matching line to
/// `/etc/audit/audit.rules` (policy: keep file in sync for external loaders).
pub fn apply_watch_kernel_rule(watch: &AuditWatch, delete: bool) -> Result<()> {
    let rule = audit_watch_to_rule_message(watch);
    apply_audit_rule_message(rule, delete)?;

    let line = watch_to_audit_rules_file_line(watch, delete);
    if delete {
        println!("Deleting watch: {}", line);
    }
    persist_audit_rule_line(&line)?;
    Ok(())
}
