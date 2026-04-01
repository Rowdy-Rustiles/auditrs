//! Enricher module implementation.
//!
//! Augments parsed audit records with derived fields before they are
//! written or displayed. Enrichment runs per record within an [`AuditEvent`]
//! and includes:
//!
//! - **Proctitle**: decode hex `proctitle` into human-readable text.
//! - **Syscall**: map numeric `syscall` IDs to names for the **host**
//!   architecture (the binary’s target), using the `syscalls` crate.
//! - **Mode**: interpret octal `mode` into file type and permission strings.

#[cfg(target_arch = "arm")]
use syscalls::arm;
#[cfg(target_arch = "riscv32")]
use syscalls::riscv32;
#[cfg(target_arch = "riscv64")]
use syscalls::riscv64;
#[cfg(target_arch = "x86")]
use syscalls::x86;
#[cfg(target_arch = "x86_64")]
use syscalls::x86_64;

use crate::core::{correlator::AuditEvent, parser::ParsedAuditRecord};

/// Runs all registered record enrichers on each record in the event.
///
/// Enrichers are applied in the order defined by the `RECORD_ENRICHERS` table.
///
/// **Parameters:**
///
/// * `event`: The correlated `AuditEvent` whose records will be enriched in
///   place.
pub fn enrich_event(mut event: AuditEvent) -> AuditEvent {
    for record in event.records.iter_mut() {
        enrich_record(record);
    }
    event
}

/// Ordered list of record-level enricher functions.
///
/// Add new enrichers here to participate in the pipeline; each function may
/// insert keys into `record.fields` when its source fields are present.
const RECORD_ENRICHERS: &[fn(&mut ParsedAuditRecord)] =
    &[enrich_proctitle, enrich_syscall, enrich_mode];

/// Applies every enricher in [`RECORD_ENRICHERS`] to a single record.
///
/// **Parameters:**
///
/// * `record`: The `ParsedAuditRecord` to enrich in place.
fn enrich_record(record: &mut ParsedAuditRecord) {
    for enricher in RECORD_ENRICHERS {
        enricher(record);
    }
}

/// Decodes the hex-encoded `proctitle` field into `proctitle_plaintext`.
///
/// Null bytes in the decoded payload are replaced with spaces; trailing
/// whitespace is trimmed.
///
/// **Parameters:**
///
/// * `record`: The record that may contain a `proctitle` field.
fn enrich_proctitle(record: &mut ParsedAuditRecord) {
    if let Some(value) = record.fields.get("proctitle") {
        if let Ok(bytes) = hex::decode(&*value) {
            record.fields.insert(
                "proctitle_plaintext".to_owned(),
                String::from_utf8_lossy(&bytes)
                    .replace('\u{0000}', " ")
                    .trim_end()
                    .to_owned(),
            );
        }
    }
}

/// Maps the numeric `syscall` field to `syscall_name` for the host
/// architecture.
///
/// The lookup uses the `syscalls` crate’s per-architecture syscall tables; the
/// meaningful mapping is for the architecture this binary was built for (not
/// necessarily the machine that produced the audit stream, if those differ).
///
/// **Parameters:**
///
/// * `record`: The record that may contain a `syscall` field.
fn enrich_syscall(record: &mut ParsedAuditRecord) {
    if let Some(value) = record.fields.get("syscall") {
        let syscall_id = value.parse::<u32>().unwrap();

        #[cfg(target_arch = "x86_64")]
        let syscall_name = x86_64::Sysno::from(syscall_id).name();
        #[cfg(target_arch = "x86")]
        let syscall_name = x86::Sysno::from(syscall_id).name();
        #[cfg(target_arch = "riscv64")]
        let syscall_name = riscv64::Sysno::from(syscall_id).name();
        #[cfg(target_arch = "riscv32")]
        let syscall_name = riscv32::Sysno::from(syscall_id).name();
        #[cfg(target_arch = "arm")]
        let syscall_name = arm::Sysno::from(syscall_id).name();

        record
            .fields
            .insert("syscall_name".to_owned(), syscall_name.to_owned());
    }
}

/// Parses octal `mode` and adds `file_type` and `file_permissions`.
///
/// `file_permissions` uses the conventional nine-character `rwxrwxrwx` form,
/// with setuid/setgid/sticky reflected as `s`/`S`/`t`/`T` on the execute slots.
///
/// **Parameters:**
///
/// * `record`: The record that may contain a `mode` field (octal string, e.g.
///   `"040755"`).
fn enrich_mode(record: &mut ParsedAuditRecord) {
    if let Some(value) = record.fields.get("mode") {
        let mode = parse_audit_mode_octal(value).unwrap();
        let file_type = file_type_string(mode);
        let rwx = rwx_string(mode);
        record
            .fields
            .insert("file_type".to_owned(), file_type.to_owned());
        record.fields.insert("file_permissions".to_owned(), rwx);
    }
}

/// Parses a Linux-style mode string as an unsigned octal value.
///
/// Accepts optional `0o` prefix and surrounding whitespace.
///
/// **Parameters:**
///
/// * `s`: Raw mode text from the audit record.
fn parse_audit_mode_octal(s: &str) -> Option<u32> {
    let s = s.trim();
    let s = s.strip_prefix("0o").unwrap_or(s);
    u32::from_str_radix(s, 8).ok()
}

/// Returns a short file-type label from the mode’s S_IFMT bits.
///
/// **Parameters:**
///
/// * `mode`: Full st_mode value (including type and permission bits).
fn file_type_string(mode: u32) -> &'static str {
    match mode & 0o170000 {
        0o040000 => "dir",
        0o100000 => "file",
        0o120000 => "symlink",
        0o060000 => "block",
        0o020000 => "char",
        0o010000 => "fifo",
        0o140000 => "socket",
        _ => "unknown",
    }
}

/// Builds the nine-character permission string from the permission bits.
///
/// **Parameters:**
///
/// * `mode`: Full st_mode value; only the permission and setuid/setgid/sticky
///   bits are used.
fn rwx_string(mode: u32) -> String {
    let mut out = ['-'; 9];

    // user
    if mode & 0o0400 != 0 {
        out[0] = 'r';
    }
    if mode & 0o0200 != 0 {
        out[1] = 'w';
    }
    if mode & 0o0100 != 0 {
        out[2] = 'x';
    }

    // group
    if mode & 0o0040 != 0 {
        out[3] = 'r';
    }
    if mode & 0o0020 != 0 {
        out[4] = 'w';
    }
    if mode & 0o0010 != 0 {
        out[5] = 'x';
    }

    // other
    if mode & 0o0004 != 0 {
        out[6] = 'r';
    }
    if mode & 0o0002 != 0 {
        out[7] = 'w';
    }
    if mode & 0o0001 != 0 {
        out[8] = 'x';
    }

    // setuid/setgid/sticky adjust execute chars
    if mode & 0o4000 != 0 {
        out[2] = if out[2] == 'x' { 's' } else { 'S' };
    }
    if mode & 0o2000 != 0 {
        out[5] = if out[5] == 'x' { 's' } else { 'S' };
    }
    if mode & 0o1000 != 0 {
        out[8] = if out[8] == 'x' { 't' } else { 'T' };
    }

    out.into_iter().collect()
}
