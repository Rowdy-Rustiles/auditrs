//! Integration tests for the auditrs daemon.
//!
//! Mark any test requiring daemon file management with the `daemonization`
//! serial group attribute (to ensure tests don't run in parallel and interfere
//! with each other). Tests requiring sudo privileges should additionally be
//! marked with the `ignore` attribute so they are not run alongside the
//! non-privileged/unit tests. Most tests in this file require sudo privileges,

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    process::Command,
};

use anyhow::Result;
use serial_test::serial;

const AUDITRS_DEBUG_EXEC: &str = "./target/debug/auditrs";
const AUDITRS_CONFIG_DIR: &str = "/etc/auditrs";
const AUDITRS_RULES_FILE: &str = "/etc/auditrs/rules.toml";
const AUDITRS_ACTIVE_LOG_DIR: &str = "/var/log/auditrs/active";
const AUDITRS_JOURNAL_LOG_DIR: &str = "/var/log/auditrs/journal";
const AUDITRS_PRIMARY_LOG_DIR: &str = "/var/log/auditrs/primary";
const AUDITRS_PID_FILE: &str = "/var/run/auditrs.pid";
const AUDITRS_STDOUT_FILE: &str = "/tmp/daemon.out";
const AUDITRS_STDERR_FILE: &str = "/tmp/daemon.err";

fn cleanup() -> Result<()> {
    Command::new(AUDITRS_DEBUG_EXEC)
        .arg("stop")
        .output()
        .expect("Failed to stop auditrs");
    let _ = std::fs::remove_file(Path::new(AUDITRS_PID_FILE));
    let _ = std::fs::remove_file(Path::new(AUDITRS_STDOUT_FILE));
    let _ = std::fs::remove_file(Path::new(AUDITRS_STDERR_FILE));
    let _ = std::fs::remove_dir_all(Path::new(AUDITRS_ACTIVE_LOG_DIR));
    let _ = std::fs::remove_dir_all(Path::new(AUDITRS_JOURNAL_LOG_DIR));
    let _ = std::fs::remove_dir_all(Path::new(AUDITRS_PRIMARY_LOG_DIR));
    let _ = std::fs::remove_file(Path::new(AUDITRS_CONFIG_DIR));
    let _ = std::fs::remove_file(Path::new(AUDITRS_RULES_FILE));
    Ok(())
}

#[test]
#[ignore]
#[serial(daemonization)]
fn test_start_daemon_control_init() {
    Command::new(AUDITRS_DEBUG_EXEC)
        .arg("start")
        .output()
        .expect("Failed to start auditrs");

    // Check for daemon pid file
    let pid_file = Path::new(AUDITRS_PID_FILE);
    assert!(pid_file.exists());

    // Checkout for stdout and stderr files
    let stdout_file = Path::new(AUDITRS_STDOUT_FILE);
    let stderr_file = Path::new(AUDITRS_STDERR_FILE);
    assert!(stdout_file.exists());
    assert!(stderr_file.exists());

    cleanup().expect("Failed to cleanup");
}

#[test]
#[ignore]
#[serial(daemonization)]
fn test_start_daemon_audit_init() {
    Command::new(AUDITRS_DEBUG_EXEC)
        .arg("start")
        .output()
        .expect("Failed to start auditrs");

    // Check for log files
    let active_directory = Path::new(AUDITRS_ACTIVE_LOG_DIR);
    let journal_directory = Path::new(AUDITRS_JOURNAL_LOG_DIR);
    let primary_directory = Path::new(AUDITRS_PRIMARY_LOG_DIR);
    assert!(active_directory.exists());
    assert!(journal_directory.exists());
    assert!(primary_directory.exists());

    // Check for configuration and rules files
    let config_file = Path::new(AUDITRS_CONFIG_DIR);
    let rules_file = Path::new(AUDITRS_RULES_FILE);
    assert!(config_file.exists());
    assert!(rules_file.exists());

    cleanup().expect("Failed to cleanup");
}

#[test]
#[ignore]
#[serial(daemonization)]
fn test_stop_daemon() {
    let start = Command::new(AUDITRS_DEBUG_EXEC)
        .arg("start")
        .output()
        .expect("Failed to execute auditrs start");
    assert!(
        start.status.success(),
        "auditrs start failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&start.stdout),
        String::from_utf8_lossy(&start.stderr)
    );

    // Read pid
    let pid_file = Path::new(AUDITRS_PID_FILE);
    let pid_file_reader = BufReader::new(File::open(pid_file).expect("Failed to open pid file"));
    let pid = pid_file_reader
        .lines()
        .next()
        .expect("Could not read pid from pid file")
        .expect("Could not parse pid from pid file");

    let stop = Command::new(AUDITRS_DEBUG_EXEC)
        .arg("stop")
        .output()
        .expect("Failed to execute auditrs stop");
    assert!(
        stop.status.success(),
        "Auditrs stop failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&stop.stdout),
        String::from_utf8_lossy(&stop.stderr)
    );

    // Allow time for SIGTERM to be processed by daemon
    let mut stopped = false;
    for _ in 0..50 {
        let status = Command::new("kill")
            .arg("-0")
            .arg(&pid)
            .status()
            .expect("Failed to check daemon pid with kill -0");

        if !status.success() {
            stopped = true;
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    assert!(
        stopped,
        "daemon with pid {} did not stop within timeout",
        pid
    );

    cleanup().expect("Failed to cleanup");
}

#[test]
#[ignore]
#[serial(daemonization)]
fn test_daemon_running() {
    Command::new(AUDITRS_DEBUG_EXEC)
        .arg("start")
        .output()
        .expect("Failed to start auditrs");

    // Read the pid from the pid file
    let pid_file = Path::new(AUDITRS_PID_FILE);
    let pid_file_reader = BufReader::new(File::open(pid_file).expect("Failed to open pid file"));
    let pid = pid_file_reader
        .lines()
        .next()
        .expect("Could not read pid from pid file")
        .expect("Could not parse pid from pid file");

    // Check the command status of process with pid `pid` using `kill -0 <pid>`
    // This should return an exit status of 0 if the process is running
    let status = Command::new("kill")
        .arg("-0")
        .arg(pid)
        .status()
        .expect("Daemonized process is not running");

    assert!(status.code().unwrap() == 0);
    cleanup().expect("Failed to cleanup");
}

#[test]
#[ignore]
#[serial(daemonization)]
fn test_daemon_running_status() {
    Command::new(AUDITRS_DEBUG_EXEC)
        .arg("start")
        .output()
        .expect("Failed to start auditrs");

    let stdout = Command::new(AUDITRS_DEBUG_EXEC)
        .arg("status")
        .output()
        .expect("Failed to start auditrs")
        .stdout;

    let stdout_str = String::from_utf8_lossy(&stdout);
    assert!(stdout_str.contains("Auditrs is running"));

    cleanup().expect("Failed to cleanup");
}

#[test]
#[ignore]
#[serial(daemonization)]
fn test_daemon_not_running_status() {
    let stdout = Command::new(AUDITRS_DEBUG_EXEC)
        .arg("status")
        .output()
        .expect("Failed to get auditrs status")
        .stdout;

    let stdout_str = String::from_utf8_lossy(&stdout);
    assert!(stdout_str.contains("Auditrs is not running"));

    cleanup().expect("Failed to cleanup");
}
