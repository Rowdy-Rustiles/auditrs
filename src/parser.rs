// Audit record parsing

// General flow for parsing an audit record:
// 1. Open file (e.g., /var/log/audit/audit.log).
// 2. Read lines from the file.
// 3. For each line, parse fields into key-value pairs.
// 4. Convert key-value pairs into structured data types.

// Assumptions:
// - Each audit record is a single line in the log file.
// - Audit records can be uniquely identified by the list of key-value pairs.

// Questions:
// - There's some level of bundling to records... multiple events in one record? Should this parser even consider that?


/*
    Example lines from audit.log:
    type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 success=no exit=-13 a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=1 ppid=2686 pid=3538 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="cat" exe="/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="sshd_config"
    type=CWD msg=audit(1364481363.243:24287):  cwd="/home/shadowman"
    type=PATH msg=audit(1364481363.243:24287): item=0 name="/etc/ssh/sshd_config" inode=409248 dev=fd:00 mode=0100600 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:etc_t:s0  objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0
    type=PROCTITLE msg=audit(1364481363.243:24287) : proctitle=636174002F6574632F7373682F737368645F636F6E666967
    
    For now, let's just grab all the key=value pairs.
    */
    
    
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, PartialEq)]
pub struct Record {
    fields: HashMap<String, String>, // identical to RecordFields for now. this would be a fully type qualified struct in a more complete implementation.
}

struct RecordFields {
        fields: HashMap<String, String>,
}


#[derive(Debug)]
pub enum ParseError {
    FileNotFound,
    FailedToReadLine,
    InvalidLine(String),
}

fn read_to_fields(line: &str) -> Result<RecordFields, ParseError> {
    let mut fields = HashMap::new();
    
    for part in line.split_whitespace() {
        if let Some(eq_pos) = part.find('=') {
            let key = &part[..eq_pos];
            let value = &part[eq_pos + 1..];
            fields.insert(key.to_string(), value.to_string());
        } else {
            if part == ":"  {
                continue;
            }
            return Err(ParseError::InvalidLine(line.to_string()));
        }
    }
    
    Ok(RecordFields { fields })
}

fn parse_to_record(record_fields: RecordFields) -> Result<Record, ParseError> {
    Ok(Record { fields: record_fields.fields })
}

pub fn parse_log_file(filepath: String) -> Result<Vec<Record>, ParseError> {
    let file = File::open(filepath).map_err(|_| ParseError::FileNotFound)?;
    let reader = BufReader::new(file);
    
    reader
        .lines()
        .map(|line| read_to_fields(&line.map_err(|_| ParseError::FailedToReadLine)?)) // convert each line into a RecordFields
        .map(|fields| parse_to_record(fields?)) // convert each RecordFields into a Record
        .collect()
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    fn record_from_kv(pairs: Vec<(&str, &str)>) -> Record {
        let mut fields = HashMap::new();
        for (k, v) in pairs {
            fields.insert(k.to_string(), v.to_string());
        }
        Record { fields }
    }    
    #[test]
    fn test_parse_log_file() {
        let test_log = "type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 success=no exit=-13 a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=1 ppid=2686 pid=3538 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm=\"cat\" exe=\"/bin/cat\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=\"sshd_config\"\n\
                        type=CWD msg=audit(1364481363.243:24287):  cwd=\"/home/shadowman\"\n\
                        type=PATH msg=audit(1364481363.243:24287): item=0 name=\"/etc/ssh/sshd_config\" inode=409248 dev=fd:00 mode=0100600 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:etc_t:s0  objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0\n\
                        type=PROCTITLE msg=audit(1364481363.243:24287) : proctitle=636174002F6574632F7373682F737368645F636F6E666967";
        
        let temp_file_path = "test_audit.log";
        std::fs::write(temp_file_path, test_log).unwrap();
        
        let records = parse_log_file(temp_file_path.to_string()).unwrap();
        assert_eq!(records, vec![
            record_from_kv(vec![
                ("type", "SYSCALL"),
                ("msg", "audit(1364481363.243:24287):"),
                ("arch", "c000003e"),
                ("syscall", "2"),
                ("success", "no"),
                ("exit", "-13"),
                ("a0", "7fffd19c5592"),
                ("a1", "0"),
                ("a2", "7fffd19c4b50"),
                ("a3", "a"),
                ("items", "1"),
                ("ppid", "2686"),
                ("pid", "3538"),
                ("auid", "1000"),
                ("uid", "1000"),
                ("gid", "1000"),
                ("euid", "1000"),
                ("suid", "1000"),
                ("fsuid", "1000"),
                ("egid", "1000"),
                ("sgid", "1000"),
                ("fsgid", "1000"),
                ("tty", "pts0"),
                ("ses", "1"),
                ("comm", "\"cat\""),
                ("exe", "\"/bin/cat\""),
                ("subj", "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"),
                ("key", "\"sshd_config\""),
            ]),
            record_from_kv(vec![
                ("type", "CWD"),
                ("msg", "audit(1364481363.243:24287):"),
                ("cwd", "\"/home/shadowman\""),
            ]),
            record_from_kv(vec![
                ("type", "PATH"),
                ("msg", "audit(1364481363.243:24287):"),
                ("item", "0"),
                ("name", "\"/etc/ssh/sshd_config\""),
                ("inode", "409248"),
                ("dev", "fd:00"),
                ("mode", "0100600"),
                ("ouid", "0"),
                ("ogid", "0"),
                ("rdev", "00:00"),
                ("obj", "system_u:object_r:etc_t:s0"),
                ("objtype", "NORMAL"),
                ("cap_fp", "none"),
                ("cap_fi", "none"),
                ("cap_fe", "0"),
                ("cap_fver", "0"),
            ]),
            record_from_kv(vec![
                ("type", "PROCTITLE"),
                ("msg", "audit(1364481363.243:24287)"),
                ("proctitle", "636174002F6574632F7373682F737368645F636F6E666967"),
            
            ])
        ]);
        
        std::fs::remove_file(temp_file_path).unwrap();
    }
}