use super::{AuditLogWriter, DEFAULT_DIR, DEFAULT_LOG_SIZE, DEFAULT_OUTPUT_FORMAT, OutputFormat};
use crate::correlator::AuditEvent;
use crate::utils::*;
use anyhow::Result;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::process::Output;
use std::time::UNIX_EPOCH;

impl AuditLogWriter {
    pub fn new() -> anyhow::Result<Self> {
        let log_dir = PathBuf::from(DEFAULT_DIR);
        create_dir_all(&log_dir)?;
        let log_file = log_dir.join("auditrs.log");
        let file_handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)?;
        Ok(Self {
            output_format: DEFAULT_OUTPUT_FORMAT,
            destination: log_dir,
            log_size: DEFAULT_LOG_SIZE,
            file_handle,
        })
    }

    pub fn write_event(&mut self, event: AuditEvent) -> Result<()> {
        match self.output_format {
            OutputFormat::Legacy => self.write_event_legacy(event),
            OutputFormat::Simple => self.write_event_simple(event),
            OutputFormat::Json => self.write_event_json(event),
        }
    }

    fn write_event_legacy(&mut self, event: AuditEvent) -> Result<()> {
        let mut prefix: String = String::new();
        let mut fields: String = String::new();
        for record in event.records {
            prefix.push_str(&format!(
                "type={} msg=audit({}:{}",
                record.record_type.as_audit_str(),
                systemtime_to_timestamp_string(event.timestamp)?,
                event.serial
            ));
            for field in record.fields {
                fields.push_str(&format!(" {}={}", field.0, field.1));
            }
        }
        let line = format!("{}{}", prefix, fields);

        writeln!(self.file_handle, "{}", line)?;
        self.file_handle.flush()?;
        Ok(())
    }

    fn write_event_simple(&mut self, event: AuditEvent) -> Result<()> {
        writeln!(self.file_handle, "{}", event)?;
        self.file_handle.flush()?;
        Ok(())
    }

    fn write_event_json(&mut self, event: AuditEvent) -> Result<()> {
        let res = serde_json::to_string(&event)?;
        writeln!(self.file_handle, "{}", res)?;
        self.file_handle.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::parser::ParsedAuditRecord;
    use crate::parser::RecordType;
    use std::collections::HashMap;
    use super::*;
    fn generate_test_event() -> AuditEvent {
        let sample_timestamp = timestamp_string_to_systemtime("1768231884.588").unwrap();
        let record_1 = ParsedAuditRecord {
            record_type: RecordType::Syscall,
            timestamp: sample_timestamp,
            serial: 1151,
            fields: HashMap::from([
                                      ("arch".into(), "c000003e".into()),
                                      ("syscall".into(), "257".into()),
                                      ("success".into(), "yes".into()),
                                      ("exit".into(), "6".into()),
                                      ("a0".into(), "ffffff9c".into()),
                                      ("a1".into(), "7ff64c375eae".into()),
                                      ("a2".into(), "80000".into()),
                                      ("a3".into(), "0".into()),
                                      ("items".into(), "1".into()),
                                      ("ppid".into(), "977".into()),
                                      ("pid".into(), "3280".into()),
                                      ("auid".into(), "4294967295".into()),
                                      ("uid".into(), "998".into()),
                                      ("gid".into(), "996".into()),
                                      ("euid".into(), "998".into()),
                                      ("suid".into(), "998".into()),
                                      ("fsuid".into(), "998".into()),
                                      ("egid".into(), "996".into()),
                                      ("sgid".into(), "996".into()),
                                      ("fsgid".into(), "996".into()),
                                      ("tty".into(), "(none)".into()),
                                      ("ses".into(), "4294967295".into()),
                                      ("comm".into(), "pkla-check-auth".into()),
                                      ("exe".into(), "/usr/bin/pkla-check-authorization".into()),
                                      ("key".into(), "beck_passwd".into()),
                                      ("ARCH".into(), "x86_64".into()),
                                      ("SYSCALL".into(), "openat".into()),
                                      ("AUID".into(), "unset".into()),
                                      ("UID".into(), "polkitd".into()),
                                      ("GID".into(), "polkitd".into()),
                                      ("EUID".into(), "polkitd".into()),
                                      ("SUID".into(), "polkitd".into()),
                                      ("FSUID".into(), "polkitd".into()),
                                      ("EGID".into(), "polkitd".into()),
                                      ("SGID".into(), "polkitd".into()),
                                      ("FSGID".into(), "polkitd".into())
                                      ]),
        };
        let record_2 = ParsedAuditRecord {
            record_type: RecordType::Cwd,
            timestamp: sample_timestamp,
            serial: 1151,
            fields: HashMap::from([("cwd".into(), "/".into())]),
        };
        let record_3 = ParsedAuditRecord {
            record_type: RecordType::Path,
            timestamp: sample_timestamp,
            serial: 1151,
            fields: HashMap::from([
                ("item".into(), "0".into()),
                ("name".into(), "/etc/passwd".into()),
                ("inode".into(), "137618356".into()),
                ("dev".into(), "fd:00".into()),
                ("mode".into(), "0100644".into()),
                ("ouid".into(), "0".into()),
                ("ogid".into(), "0".into()),
                ("rdev".into(), "00:00".into()),
                ("nametype".into(), "NORMAL".into()),
                ("cap_fp".into(), "0".into()),
                ("cap_fi".into(), "0".into()),
                ("cap_fe".into(), "0".into()),
                ("cap_fver".into(), "0".into()),
                ("cap_frootid".into(), "0".into()),
                ("OUID".into(), "root".into()),
                ("OGID".into(), "root".into()),
            ]),
        };
        let record_4 = ParsedAuditRecord {
            record_type: RecordType::Proctitle,
            timestamp: sample_timestamp,
            serial: 1151,
            fields: HashMap::from(["proctitle".into(), "2F7573722F62696E2F706B6C612D636865636B2D617574686F72697A6174696F6E007573657200747275650074727565006F72672E667265656465736B746F702E4E6574776F726B4D616E616765722E776966692E7363616E".into()]),
        };

        let event = AuditEvent {
            timestamp: sample_timestamp,
            serial: 1151,
            record_count: 4,
            records: vec![record_1, record_2, record_3, record_4],
        };

        event
    }
    #[test]
    fn test_write_event() {
        let event = generate_test_event();
        let mut writer = AuditLogWriter::new().unwrap();
        writer.write_event(event).unwrap();
    }
}