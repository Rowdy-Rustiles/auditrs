//! # Introduction
//!
//! AuditRS is aimed at being a modern, efficient, and flexible replacement for
//! the userspace components of the Linux audit system (auditd, ausearch, etc.).
//! These tools allow users to monitor and analyze system activity in real-time,
//! particularly for security and compliance purposes. AuditRS is written
//! entirely in Rust to provide strong safety guarantees and high performance.
//! The core functionality of AuditRS includes:
//!
//! - Reading audit logs from the kernel via netlink sockets.
//! - Parsing raw audit record lines into structured data.
//! - Correlating related records into events.
//! - Applying user-defined filters to determine which events should be logged.
//! - Writing the resulting events to log files in a structured format.
//! - Providing a configuration system for managing audit rules, filters, and
//!   other settings.
//! - Seamless log rotation and management of log files.
//!
//! # Goals
//! - **Performance**: Process audit records with minimal latency and resource
//!   usage.
//! - **Safety** : Leverage Rust's safety guarantees to minimize bugs and
//!   security vulnerabilities.
//! - **Modernization**: Provide a more user-friendly output format and
//!   configuration system, enriching the logs with additional context where
//!   possible.
//! - **Compatibility**: Maintain compatibility with existing audit rules,
//!   formats, and tools where possible, while also allowing for modern
//!   improvements.

#![warn(missing_docs, unused_attributes)]
pub mod cli;
pub mod config;
pub mod core;
pub mod daemon;
pub mod rules;
pub mod state;
pub mod tools;
pub mod utils;
