//! Basic tests that ensure test-source.log (a sample of binary audit data captured from the kernel) is valid.

use netlink_packet_audit::AuditMessage;
use netlink_packet_core::NetlinkMessage;
use std::io::BufRead;
use std::path::Path;

const TEST_SOURCE_LOG: &str = "tests/test-source.log";

/*

TEST HELPER FUNCTIONS
We may benefit from creating a common helper function file for the tests.

*/


/// Deserializes test-source.log into a list of netlink audit messages.
/// Returns an error if the an error occurs at any point in the process.
pub fn deserialize_source_log(
    path: &Path,
) -> Result<Vec<NetlinkMessage<AuditMessage>>, String> {
    let file = std::io::BufReader::new(
        std::fs::File::open(path).map_err(|e| format!("open {}: {}", path.display(), e))?,
    );
    let mut messages = Vec::new();
    for (i, line) in file.lines().enumerate() {
        let line = line.map_err(|e| format!("read line: {}", e))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let bytes = hex_decode(line).map_err(|e| format!("line {}: {}", i + 1, e))?;
        let msg = NetlinkMessage::<AuditMessage>::deserialize(&bytes)
            .map_err(|e| format!("line {} deserialize: {}", i + 1, e))?;
        messages.push(msg);
    }
    Ok(messages)
}

/// Formats a single netlink audit message into a readable string.
pub fn message_to_readable(msg: &NetlinkMessage<AuditMessage>) -> String {
    format!(
        "  type={:?} length={} flags={:?} seq={}\n  payload={:?}",
        msg.header.message_type,
        msg.header.length,
        msg.header.flags,
        msg.header.sequence_number,
        msg.payload
    )
}

/// Deserializes the source log and returns each message in a readable format.
/// For the test that use these, run `cargo test --test test_source_log -- --nocapture` to see the output.
pub fn source_log_to_readable(path: &Path) -> Result<Vec<String>, String> {
    let messages = deserialize_source_log(path)?;
    Ok(messages
        .iter()
        .enumerate()
        .map(|(i, msg)| format!("Message {}:\n{}", i + 1, message_to_readable(msg)))
        .collect())
}

/// Decode a hex string into bytes, returns error if any char is not valid.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| format!("invalid hex at position {}: {}", i, e))?;
        out.push(b);
    }
    Ok(out)
}

#[test]
fn test_source_log_file_exists() {
    let path = Path::new(TEST_SOURCE_LOG);
    assert!(
        path.exists(),
        "{} should exist (run the capture binary first to generate it)",
        path.display()
    );
}

#[test]
fn test_source_log_has_content() {
    let path = Path::new(TEST_SOURCE_LOG);
    let file = std::io::BufReader::new(
        std::fs::File::open(&path).expect("test-source.log should be readable"),
    );
    let lines: Vec<String> = file.lines().filter_map(Result::ok).collect();
    assert!(
        !lines.is_empty(),
        "test-source.log should contain at least one line"
    );
}

#[test]
fn test_source_log_lines_are_valid_hex() {
    let path = Path::new(TEST_SOURCE_LOG);
    let file = std::io::BufReader::new(
        std::fs::File::open(&path).expect("test-source.log should be readable"),
    );
    for (i, line) in file.lines().enumerate() {
        let line = line.expect("read line");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let decoded = hex_decode(line).expect(&format!("line {} should be valid hex", i + 1));
        assert!(
            !decoded.is_empty(),
            "line {} decoded to non-empty bytes",
            i + 1
        );
    }
}

#[test]
fn test_source_log_lines_are_interpretable_as_netlink_audit_messages() {
    let path = Path::new(TEST_SOURCE_LOG);
    let file = std::io::BufReader::new(
        std::fs::File::open(&path).expect("test-source.log should be readable"),
    );
    let mut deserialized_count = 0u32;
    for (i, line) in file.lines().enumerate() {
        let line = line.expect("read line");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let bytes = hex_decode(&line).expect("valid hex");
        match NetlinkMessage::<AuditMessage>::deserialize(&bytes) {
            Ok(_msg) => deserialized_count += 1,
            Err(e) => panic!(
                "line {} failed to deserialize as NetlinkMessage<AuditMessage>: {}",
                i + 1,
                e
            ),
        }
    }
    assert!(
        deserialized_count > 0,
        "at least one line should deserialize as a netlink audit message"
    );
}

#[test]
fn test_print_reconstructed_messages() {
    let path = Path::new(TEST_SOURCE_LOG);
    let readable = source_log_to_readable(&path).expect("deserialize source log to readable form");
    println!("--- Reconstructed messages from {} ---", path.display());
    for s in &readable {
        println!("{}\n", s);
    }
    println!("--- End ({} messages) ---", readable.len());
    assert!(!readable.is_empty(), "should have at least one message to print");
}

#[test]
fn test_deserialize_source_log_helper() {
    let path = Path::new(TEST_SOURCE_LOG);
    if !path.exists() {
        return;
    }
    let messages = deserialize_source_log(&path).expect("deserialize_source_log should succeed");
    assert!(!messages.is_empty(), "helper should return at least one message");
    for (i, msg) in messages.iter().enumerate() {
        assert!(msg.header.length >= 16, "message {} has valid netlink header length", i + 1);
        let readable = message_to_readable(msg);
        assert!(readable.contains("type="), "readable form for message {} includes type", i + 1);
        assert!(readable.contains("payload="), "readable form for message {} includes payload", i + 1);
    }
}

#[test]
fn test_source_log_to_readable_helper() {
    let path = Path::new(TEST_SOURCE_LOG);
    if !path.exists() {
        return;
    }
    let readable = source_log_to_readable(&path).expect("source_log_to_readable should succeed");
    assert_eq!(
        readable.len(),
        deserialize_source_log(&path).unwrap().len(),
        "readable count should match deserialized message count"
    );
    for (i, block) in readable.iter().enumerate() {
        assert!(
            block.starts_with(&format!("Message {}:", i + 1)),
            "readable block {} should start with 'Message N:'",
            i + 1
        );
        assert!(
            block.contains("payload="),
            "readable block {} should contain payload",
            i + 1
        );
    }
}
