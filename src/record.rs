/*
    Definition of an Audit Record. This corresponds to a single line in an audit log file,
    which may contain multiple fields. Original implementation uses key/value string pairs
    stored in a HashMap, but could be extended to a more strongly typed structure in the
    future.

    Relevant documentation:
    https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv

    For information on the mapping of netlink messages to auditrs log types, refer to:
    https://codebrowser.dev/linux/include/linux/audit.h.html#147
*/

use std::{collections::HashMap, time::SystemTime};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    Control(ControlMessage),
    User(UserMessage),
    Daemon(DaemonMessage),
    Kernel(KernelRecord),
    Selinux(SelinuxRecord),
    Anomaly(AnomalyRecord),
    Integrity(IntegrityRecord),
    LegacyKernel,
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlMessage {
    GetStatus,          // 1000
    SetStatus,          // 1001
    List,               // 1002 (deprecated)
    Add,                // 1003 (deprecated)
    Del,                // 1004 (deprecated)
    User,               // 1005 (deprecated)
    Login,              // 1006
    WatchInsert,        // 1007
    WatchRemove,        // 1008
    WatchList,          // 1009
    SignalInfo,         // 1010
    AddRule,            // 1011
    DelRule,            // 1012
    ListRules,          // 1013
    Trim,               // 1014
    MakeEquiv,          // 1015
    TtyGet,             // 1016
    TtySet,             // 1017
    SetFeature,         // 1018
    GetFeature,         // 1019
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserMessage {
    FirstUserMsg,   // 1100
    UserAvc,        // 1107
    UserTty,        // 1124
    LastUserMsg,    // 1199
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonMessage {
    Start,      // 1200
    End,        // 1201
    Abort,      // 1202
    Config,     // 1203
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelRecord {
    Syscall,           // 1300
    Path,              // 1302
    Ipc,               // 1303
    Socketcall,        // 1304
    ConfigChange,      // 1305
    Sockaddr,          // 1306
    Cwd,               // 1307
    Execve,            // 1309
    IpcSetPerm,        // 1311
    MqOpen,            // 1312
    MqSendRecv,        // 1313
    MqNotify,          // 1314
    MqGetSetAttr,      // 1315
    KernelOther,       // 1316
    FdPair,            // 1317
    ObjPid,            // 1318
    Tty,               // 1319
    Eoe,               // 1320
    BprmFcaps,         // 1321
    Capset,            // 1322
    Mmap,              // 1323
    NetfilterPkt,      // 1324
    NetfilterCfg,      // 1325
    Seccomp,           // 1326
    Proctitle,         // 1327
    FeatureChange,     // 1328
    Replace,           // 1329
    KernModule,        // 1330
    Fanotify,          // 1331
    TimeInjOffset,     // 1332
    TimeAdjNtpVal,     // 1333
    Bpf,               // 1334
    EventListener,     // 1335
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelinuxRecord {
    Avc,                   // 1400
    SelinuxErr,            // 1401
    AvcPath,               // 1402
    MacPolicyLoad,         // 1403
    MacStatus,             // 1404
    MacConfigChange,       // 1405
    MacUnlblAllow,         // 1406
    MacCipsoV4Add,         // 1407
    MacCipsoV4Del,         // 1408
    MacMapAdd,             // 1409
    MacMapDel,             // 1410
    MacIpsecEvent,         // 1415
    MacUnlblStcAdd,        // 1416
    MacUnlblStcDel,        // 1417
    MacCalipsoAdd,         // 1418
    MacCalipsoDel,         // 1419
    MacTaskContexts,       // 1420
    MacObjContexts,        // 1421
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyRecord {
    Promiscuous,    // 1700
    Abend,          // 1701
    Link,           // 1702
    Creat,          // 1703
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityRecord {
    Data,           // 1800
    Metadata,       // 1801
    Status,         // 1802
    Hash,           // 1803
    Pcr,            // 1804
    Rule,           // 1805
    EvmXattr,       // 1806
    PolicyRule,     // 1807
}


impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        match value {

            // Control (1000–1099)
            1000 => RecordType::Control(ControlMessage::GetStatus),
            1001 => RecordType::Control(ControlMessage::SetStatus),
            1002 => RecordType::Control(ControlMessage::List),
            1003 => RecordType::Control(ControlMessage::Add),
            1004 => RecordType::Control(ControlMessage::Del),
            1005 => RecordType::Control(ControlMessage::User),
            1006 => RecordType::Control(ControlMessage::Login),
            1007 => RecordType::Control(ControlMessage::WatchInsert),
            1008 => RecordType::Control(ControlMessage::WatchRemove),
            1009 => RecordType::Control(ControlMessage::WatchList),
            1010 => RecordType::Control(ControlMessage::SignalInfo),
            1011 => RecordType::Control(ControlMessage::AddRule),
            1012 => RecordType::Control(ControlMessage::DelRule),
            1013 => RecordType::Control(ControlMessage::ListRules),
            1014 => RecordType::Control(ControlMessage::Trim),
            1015 => RecordType::Control(ControlMessage::MakeEquiv),
            1016 => RecordType::Control(ControlMessage::TtyGet),
            1017 => RecordType::Control(ControlMessage::TtySet),
            1018 => RecordType::Control(ControlMessage::SetFeature),
            1019 => RecordType::Control(ControlMessage::GetFeature),

            // User (1100–1199)
            1100 => RecordType::User(UserMessage::FirstUserMsg),
            1107 => RecordType::User(UserMessage::UserAvc),
            1124 => RecordType::User(UserMessage::UserTty),
            1199 => RecordType::User(UserMessage::LastUserMsg),

            // Daemon (1200–1299)
            1200 => RecordType::Daemon(DaemonMessage::Start),
            1201 => RecordType::Daemon(DaemonMessage::End),
            1202 => RecordType::Daemon(DaemonMessage::Abort),
            1203 => RecordType::Daemon(DaemonMessage::Config),

            // Kernel 1300–1335
            1300 => RecordType::Kernel(KernelRecord::Syscall),
            1302 => RecordType::Kernel(KernelRecord::Path),
            1303 => RecordType::Kernel(KernelRecord::Ipc),
            1304 => RecordType::Kernel(KernelRecord::Socketcall),
            1305 => RecordType::Kernel(KernelRecord::ConfigChange),
            1306 => RecordType::Kernel(KernelRecord::Sockaddr),
            1307 => RecordType::Kernel(KernelRecord::Cwd),
            1309 => RecordType::Kernel(KernelRecord::Execve),
            1311 => RecordType::Kernel(KernelRecord::IpcSetPerm),
            1312 => RecordType::Kernel(KernelRecord::MqOpen),
            1313 => RecordType::Kernel(KernelRecord::MqSendRecv),
            1314 => RecordType::Kernel(KernelRecord::MqNotify),
            1315 => RecordType::Kernel(KernelRecord::MqGetSetAttr),
            1316 => RecordType::Kernel(KernelRecord::KernelOther),
            1317 => RecordType::Kernel(KernelRecord::FdPair),
            1318 => RecordType::Kernel(KernelRecord::ObjPid),
            1319 => RecordType::Kernel(KernelRecord::Tty),
            1320 => RecordType::Kernel(KernelRecord::Eoe),
            1321 => RecordType::Kernel(KernelRecord::BprmFcaps),
            1322 => RecordType::Kernel(KernelRecord::Capset),
            1323 => RecordType::Kernel(KernelRecord::Mmap),
            1324 => RecordType::Kernel(KernelRecord::NetfilterPkt),
            1325 => RecordType::Kernel(KernelRecord::NetfilterCfg),
            1326 => RecordType::Kernel(KernelRecord::Seccomp),
            1327 => RecordType::Kernel(KernelRecord::Proctitle),
            1328 => RecordType::Kernel(KernelRecord::FeatureChange),
            1329 => RecordType::Kernel(KernelRecord::Replace),
            1330 => RecordType::Kernel(KernelRecord::KernModule),
            1331 => RecordType::Kernel(KernelRecord::Fanotify),
            1332 => RecordType::Kernel(KernelRecord::TimeInjOffset),
            1333 => RecordType::Kernel(KernelRecord::TimeAdjNtpVal),
            1334 => RecordType::Kernel(KernelRecord::Bpf),
            1335 => RecordType::Kernel(KernelRecord::EventListener),

            // SELinux
            1400 => RecordType::Selinux(SelinuxRecord::Avc),

            // Anomaly
            1701 => RecordType::Anomaly(AnomalyRecord::Abend),

            // Integrity
            1800 => RecordType::Integrity(IntegrityRecord::Data),

            // Legacy
            2000 => RecordType::LegacyKernel,

            other => RecordType::Unknown(other),
        }
    }
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::*;

}