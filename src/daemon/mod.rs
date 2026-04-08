//! Daemon lifecycle and orchestration.
//!
//! This module wires the long-running audit daemon together:
//! - `control` exposes CLI-facing operations for starting, stopping, reloading,
//!   and querying the status of the daemon.
//! - `daemon` manages process-level concerns such as daemonization and PID file
//!   management.
//! - `worker` runs the asynchronous processing pipeline, listens for signals
//!   (e.g. SIGHUP), and coordinates config/rules reloads.
//! - `auditd_preflight` checks that legacy `auditd` is not running before
//!   startup.
//! The `PID_FILE_NAME` constant defines the canonical PID file used by control
//! commands and system integration.

mod auditd_preflight;
pub mod control;
pub mod daemon;
pub mod worker;
pub(crate) const PID_FILE_NAME: &str = "auditrs.pid";
