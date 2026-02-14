/*
    Definition of an Audit Record. This corresponds to a single line in an audit log file,
    which may contain multiple fields. Original implementation uses key/value string pairs
    stored in a HashMap, but could be extended to a more strongly typed structure in the
    future.

    Relevant documentation:
    https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv

    For information on the mapping of netlink messages to auditrs log types, refer to:
    https://codebrowser.dev/linux/include/linux/audit.h.html#147

    need to look into the types presented here:
    https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files

    and additionally find more modern types
*/

use std::{collections::HashMap, time::SystemTime};

#[derive(Debug, PartialEq)]
pub struct AuditRecord {
    pub record_type: RecordType,
    pub data: String,
}

impl AuditRecord {
    pub fn new(_type: RecordType, data: String) -> Self {
        AuditRecord {
            record_type: _type,
            data,
        }
    }

    pub fn to_log(&self) -> String {
        format!("type={} msg={}", self.record_type.as_audit_str(), self.data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    /* =========================
     * Control (1000–1019)
     * ========================= */
    GetStatus,
    SetStatus,
    List,
    Add,
    Del,
    User,
    Login,
    WatchInsert,
    WatchRemove,
    WatchList,
    SignalInfo,
    AddRule,
    DelRule,
    ListRules,
    Trim,
    MakeEquiv,
    TtyGet,
    TtySet,
    SetFeature,
    GetFeature,

    /* =========================
     * User (1100–1199 subset)
     * ========================= */
    FirstUserMsg,
    UserAvc,
    UserTty,
    LastUserMsg,

    /* =========================
     * Daemon (1200–1203)
     * ========================= */
    DaemonStart,
    DaemonEnd,
    DaemonAbort,
    DaemonConfig,

    /* =========================
     * Kernel (1300–1335)
     * ========================= */
    Syscall,
    Path,
    Ipc,
    Socketcall,
    ConfigChange,
    Sockaddr,
    Cwd,
    Execve,
    IpcSetPerm,
    MqOpen,
    MqSendRecv,
    MqNotify,
    MqGetSetAttr,
    KernelOther,
    FdPair,
    ObjPid,
    Tty,
    Eoe,
    BprmFcaps,
    Capset,
    Mmap,
    NetfilterPkt,
    NetfilterCfg,
    Seccomp,
    Proctitle,
    FeatureChange,
    Replace,
    KernModule,
    Fanotify,
    TimeInjOffset,
    TimeAdjNtpVal,
    Bpf,
    EventListener,

    /* =========================
     * SELinux (1400+ subset)
     * ========================= */
    Avc,
    SelinuxErr,
    AvcPath,
    MacPolicyLoad,
    MacStatus,
    MacConfigChange,
    MacUnlblAllow,
    MacCipsoV4Add,
    MacCipsoV4Del,
    MacMapAdd,
    MacMapDel,
    MacIpsecEvent,
    MacUnlblStcAdd,
    MacUnlblStcDel,
    MacCalipsoAdd,
    MacCalipsoDel,
    MacTaskContexts,
    MacObjContexts,

    /* =========================
     * Anomaly (1700–1703)
     * ========================= */
    AnomalyPromiscuous,
    AnomalyAbend,
    AnomalyLink,
    AnomalyCreat,

    /* =========================
     * Integrity (1800–1807)
     * ========================= */
    IntegrityData,
    IntegrityMetadata,
    IntegrityStatus,
    IntegrityHash,
    IntegrityPcr,
    IntegrityRule,
    IntegrityEvmXattr,
    IntegrityPolicyRule,

    /* =========================
     * Legacy
     * ========================= */
    CryptoKeyUser,

    /* =========================
     * Fallback
     * ========================= */
    Unknown(u16),
}

impl RecordType {
    pub fn as_audit_str(&self) -> &'static str {
        match self {
            // Control
            Self::GetStatus => "GET_STATUS",
            Self::SetStatus => "SET_STATUS",
            Self::List => "LIST",
            Self::Add => "ADD",
            Self::Del => "DEL",
            Self::User => "USER",
            Self::Login => "LOGIN",
            Self::WatchInsert => "WATCH_INSERT",
            Self::WatchRemove => "WATCH_REMOVE",
            Self::WatchList => "WATCH_LIST",
            Self::SignalInfo => "SIGNAL_INFO",
            Self::AddRule => "ADD_RULE",
            Self::DelRule => "DEL_RULE",
            Self::ListRules => "LIST_RULES",
            Self::Trim => "TRIM",
            Self::MakeEquiv => "MAKE_EQUIV",
            Self::TtyGet => "TTY_GET",
            Self::TtySet => "TTY_SET",
            Self::SetFeature => "SET_FEATURE",
            Self::GetFeature => "GET_FEATURE",

            // User
            Self::FirstUserMsg => "USER_FIRST_MSG",
            Self::UserAvc => "USER_AVC",
            Self::UserTty => "USER_TTY",
            Self::LastUserMsg => "USER_LAST_MSG",

            // Daemon
            Self::DaemonStart => "DAEMON_START",
            Self::DaemonEnd => "DAEMON_END",
            Self::DaemonAbort => "DAEMON_ABORT",
            Self::DaemonConfig => "DAEMON_CONFIG",

            // Kernel
            Self::Syscall => "SYSCALL",
            Self::Path => "PATH",
            Self::Ipc => "IPC",
            Self::Socketcall => "SOCKETCALL",
            Self::ConfigChange => "CONFIG_CHANGE",
            Self::Sockaddr => "SOCKADDR",
            Self::Cwd => "CWD",
            Self::Execve => "EXECVE",
            Self::IpcSetPerm => "IPC_SET_PERM",
            Self::MqOpen => "MQ_OPEN",
            Self::MqSendRecv => "MQ_SEND_RECV",
            Self::MqNotify => "MQ_NOTIFY",
            Self::MqGetSetAttr => "MQ_GETSETATTR",
            Self::KernelOther => "KERNEL_OTHER",
            Self::FdPair => "FD_PAIR",
            Self::ObjPid => "OBJ_PID",
            Self::Tty => "TTY",
            Self::Eoe => "EOE",
            Self::BprmFcaps => "BPRM_FCAPS",
            Self::Capset => "CAPSET",
            Self::Mmap => "MMAP",
            Self::NetfilterPkt => "NETFILTER_PKT",
            Self::NetfilterCfg => "NETFILTER_CFG",
            Self::Seccomp => "SECCOMP",
            Self::Proctitle => "PROCTITLE",
            Self::FeatureChange => "FEATURE_CHANGE",
            Self::Replace => "REPLACE",
            Self::KernModule => "KERN_MODULE",
            Self::Fanotify => "FANOTIFY",
            Self::TimeInjOffset => "TIME_INJ_OFFSET",
            Self::TimeAdjNtpVal => "TIME_ADJ_NTP_VAL",
            Self::Bpf => "BPF",
            Self::EventListener => "EVENT_LISTENER",

            // SELinux
            Self::Avc => "AVC",
            Self::SelinuxErr => "SELINUX_ERR",
            Self::AvcPath => "AVC_PATH",
            Self::MacPolicyLoad => "MAC_POLICY_LOAD",
            Self::MacStatus => "MAC_STATUS",
            Self::MacConfigChange => "MAC_CONFIG_CHANGE",
            Self::MacUnlblAllow => "MAC_UNLBL_ALLOW",
            Self::MacCipsoV4Add => "MAC_CIPSO_V4_ADD",
            Self::MacCipsoV4Del => "MAC_CIPSO_V4_DEL",
            Self::MacMapAdd => "MAC_MAP_ADD",
            Self::MacMapDel => "MAC_MAP_DEL",
            Self::MacIpsecEvent => "MAC_IPSEC_EVENT",
            Self::MacUnlblStcAdd => "MAC_UNLBL_STC_ADD",
            Self::MacUnlblStcDel => "MAC_UNLBL_STC_DEL",
            Self::MacCalipsoAdd => "MAC_CALIPSO_ADD",
            Self::MacCalipsoDel => "MAC_CALIPSO_DEL",
            Self::MacTaskContexts => "MAC_TASK_CONTEXTS",
            Self::MacObjContexts => "MAC_OBJ_CONTEXTS",

            // Anomaly
            Self::AnomalyPromiscuous => "ANOM_PROMISCUOUS",
            Self::AnomalyAbend => "ANOM_ABEND",
            Self::AnomalyLink => "ANOM_LINK",
            Self::AnomalyCreat => "ANOM_CREAT",

            // Integrity
            Self::IntegrityData => "INTEGRITY_DATA",
            Self::IntegrityMetadata => "INTEGRITY_METADATA",
            Self::IntegrityStatus => "INTEGRITY_STATUS",
            Self::IntegrityHash => "INTEGRITY_HASH",
            Self::IntegrityPcr => "INTEGRITY_PCR",
            Self::IntegrityRule => "INTEGRITY_RULE",
            Self::IntegrityEvmXattr => "INTEGRITY_EVM_XATTR",
            Self::IntegrityPolicyRule => "INTEGRITY_POLICY_RULE",

            // Legacy
            Self::CryptoKeyUser => "CRYPTO_KEY_USER",

            // Fallback
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        use RecordType::*;

        match value {
            // Control
            1000 => GetStatus,
            1001 => SetStatus,
            1002 => List,
            1003 => Add,
            1004 => Del,
            1005 => User,
            1006 => Login,
            1007 => WatchInsert,
            1008 => WatchRemove,
            1009 => WatchList,
            1010 => SignalInfo,
            1011 => AddRule,
            1012 => DelRule,
            1013 => ListRules,
            1014 => Trim,
            1015 => MakeEquiv,
            1016 => TtyGet,
            1017 => TtySet,
            1018 => SetFeature,
            1019 => GetFeature,

            // User
            1100 => FirstUserMsg,
            1107 => UserAvc,
            1124 => UserTty,
            1199 => LastUserMsg,

            // Daemon
            1200 => DaemonStart,
            1201 => DaemonEnd,
            1202 => DaemonAbort,
            1203 => DaemonConfig,

            // Kernel
            1300 => Syscall,
            1302 => Path,
            1303 => Ipc,
            1304 => Socketcall,
            1305 => ConfigChange,
            1306 => Sockaddr,
            1307 => Cwd,
            1309 => Execve,
            1311 => IpcSetPerm,
            1312 => MqOpen,
            1313 => MqSendRecv,
            1314 => MqNotify,
            1315 => MqGetSetAttr,
            1316 => KernelOther,
            1317 => FdPair,
            1318 => ObjPid,
            1319 => Tty,
            1320 => Eoe,
            1321 => BprmFcaps,
            1322 => Capset,
            1323 => Mmap,
            1324 => NetfilterPkt,
            1325 => NetfilterCfg,
            1326 => Seccomp,
            1327 => Proctitle,
            1328 => FeatureChange,
            1329 => Replace,
            1330 => KernModule,
            1331 => Fanotify,
            1332 => TimeInjOffset,
            1333 => TimeAdjNtpVal,
            1334 => Bpf,
            1335 => EventListener,

            // SELinux
            1400 => Avc,
            1401 => SelinuxErr,
            1402 => AvcPath,
            1403 => MacPolicyLoad,
            1404 => MacStatus,
            1405 => MacConfigChange,
            1406 => MacUnlblAllow,
            1407 => MacCipsoV4Add,
            1408 => MacCipsoV4Del,
            1409 => MacMapAdd,
            1410 => MacMapDel,
            1415 => MacIpsecEvent,
            1416 => MacUnlblStcAdd,
            1417 => MacUnlblStcDel,
            1418 => MacCalipsoAdd,
            1419 => MacCalipsoDel,
            1420 => MacTaskContexts,
            1421 => MacObjContexts,

            // Anomaly
            1700 => AnomalyPromiscuous,
            1701 => AnomalyAbend,
            1702 => AnomalyLink,
            1703 => AnomalyCreat,

            // Integrity
            1800 => IntegrityData,
            1801 => IntegrityMetadata,
            1802 => IntegrityStatus,
            1803 => IntegrityHash,
            1804 => IntegrityPcr,
            1805 => IntegrityRule,
            1806 => IntegrityEvmXattr,
            1807 => IntegrityPolicyRule,

            // Legacy
            2000 => CryptoKeyUser,

            other => Unknown(other),
        }
    }
}

impl From<RecordType> for u16 {
    fn from(value: RecordType) -> Self {
        use RecordType::*;

        match value {
            GetStatus => 1000,
            SetStatus => 1001,
            List => 1002,
            Add => 1003,
            Del => 1004,
            User => 1005,
            Login => 1006,
            WatchInsert => 1007,
            WatchRemove => 1008,
            WatchList => 1009,
            SignalInfo => 1010,
            AddRule => 1011,
            DelRule => 1012,
            ListRules => 1013,
            Trim => 1014,
            MakeEquiv => 1015,
            TtyGet => 1016,
            TtySet => 1017,
            SetFeature => 1018,
            GetFeature => 1019,

            FirstUserMsg => 1100,
            UserAvc => 1107,
            UserTty => 1124,
            LastUserMsg => 1199,

            DaemonStart => 1200,
            DaemonEnd => 1201,
            DaemonAbort => 1202,
            DaemonConfig => 1203,

            Syscall => 1300,
            Path => 1302,
            Ipc => 1303,
            Socketcall => 1304,
            ConfigChange => 1305,
            Sockaddr => 1306,
            Cwd => 1307,
            Execve => 1309,
            IpcSetPerm => 1311,
            MqOpen => 1312,
            MqSendRecv => 1313,
            MqNotify => 1314,
            MqGetSetAttr => 1315,
            KernelOther => 1316,
            FdPair => 1317,
            ObjPid => 1318,
            Tty => 1319,
            Eoe => 1320,
            BprmFcaps => 1321,
            Capset => 1322,
            Mmap => 1323,
            NetfilterPkt => 1324,
            NetfilterCfg => 1325,
            Seccomp => 1326,
            Proctitle => 1327,
            FeatureChange => 1328,
            Replace => 1329,
            KernModule => 1330,
            Fanotify => 1331,
            TimeInjOffset => 1332,
            TimeAdjNtpVal => 1333,
            Bpf => 1334,
            EventListener => 1335,

            Avc => 1400,
            SelinuxErr => 1401,
            AvcPath => 1402,
            MacPolicyLoad => 1403,
            MacStatus => 1404,
            MacConfigChange => 1405,
            MacUnlblAllow => 1406,
            MacCipsoV4Add => 1407,
            MacCipsoV4Del => 1408,
            MacMapAdd => 1409,
            MacMapDel => 1410,
            MacIpsecEvent => 1415,
            MacUnlblStcAdd => 1416,
            MacUnlblStcDel => 1417,
            MacCalipsoAdd => 1418,
            MacCalipsoDel => 1419,
            MacTaskContexts => 1420,
            MacObjContexts => 1421,

            AnomalyPromiscuous => 1700,
            AnomalyAbend => 1701,
            AnomalyLink => 1702,
            AnomalyCreat => 1703,

            IntegrityData => 1800,
            IntegrityMetadata => 1801,
            IntegrityStatus => 1802,
            IntegrityHash => 1803,
            IntegrityPcr => 1804,
            IntegrityRule => 1805,
            IntegrityEvmXattr => 1806,
            IntegrityPolicyRule => 1807,

            CryptoKeyUser => 2000,

            Unknown(v) => v,
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn test_record_to_log() {
        let record_type = RecordType::from(1300); // Syscall
        let record = AuditRecord::new(record_type, "example data".to_string());
        assert_eq!(record.record_type.as_audit_str(), "SYSCALL");
        assert_eq!(record.to_log(), "type=SYSCALL msg=example data");

        // Round-trip u16 conversion
        let num: u16 = record_type.into();
        assert_eq!(num, 1300);
        assert_eq!(RecordType::from(num), record_type);
    }
}
