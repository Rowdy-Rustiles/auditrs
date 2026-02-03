/*
    Definition of an Audit Record. This corresponds to a single line in an audit log file,
    which may contain multiple fields. Original implementation uses key/value string pairs
    stored in a HashMap, but could be extended to a more strongly typed structure in the
    future.

    Relevant documentation:
    https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv

    Very curious how feasible it is to have a fully typed Record struct, given the wide variety of
    fields that can appear in an audit log line. An incremental approach would be putting everything
    in a HashMap for now, then gradually converting known fields to typed members of the Record struct.
*/

use std::{collections::HashMap, time::SystemTime};

use strum_macros::EnumString;

#[derive(Debug, PartialEq)]
pub struct AuditRecord {
    // Essential values, all records will have this
    pub record_type: RecordType,
    pub timestamp: SystemTime,
    pub serial: u64, 
    // Fields that are unique to each recordtype.
    pub data: RecordData,
}

pub type RecordData = HashMap<String, String>;


#[derive(EnumString, PartialEq, Debug)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordType {
    NetfilterCfg,
    Syscall,
    UserStart,
    CryptoKeyUser,
    CredRefr,
    SystemShutdown,
    CredAcq,
    SystemRunlevel,
    ServiceStop,
    AnomAbend,
    UserCmd,
    Path,
    DaemonStart,
    Proctitle,
    ServiceStart,
    ConfigChange,
    Cwd,
    UserEnd,
    UserAuth,
    DaemonEnd,
    Sockaddr,
    SystemBoot,
    Login,
    UserAcct,
    CredDisp,
    Unknown(String)
    // ... there are loads more.
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_string_to_enum() {
        assert_eq!(RecordType::from_str("SYSCALL").unwrap(), RecordType::Syscall);
        assert_eq!(RecordType::from_str("NETFILTER_CFG").unwrap(), RecordType::NetfilterCfg);
        assert_eq!(RecordType::from_str("CRED_DISP").unwrap(), RecordType::CredDisp);
        assert_eq!(RecordType::from_str("CRYPTO_KEY_USER").unwrap(), RecordType::CryptoKeyUser);
    }
}