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

pub fn enrich_event(mut event: AuditEvent) -> AuditEvent {
    for record in event.records.iter_mut() {
        enrich_record(record);
    }
    event
}

fn enrich_record(record: &mut ParsedAuditRecord) {
    enrich_proctitle(record);
    enrich_syscall(record)
}

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

fn enrich_syscall(record: &mut ParsedAuditRecord) {
    if let Some(value) = record.fields.get("syscall") {
        let syscall_id = value.parse::<u32>().unwrap();

        // Dynamic syscall table lookup for a few common architectures
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
