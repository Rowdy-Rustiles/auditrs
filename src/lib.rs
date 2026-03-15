//! # Introduction
//! 
//! AuditRS is aimed at being a modern, efficient, and flexible replacement for the userspace components of the Linux audit system (auditd, ausearch, etc.). These tools allow users to monitor and analyze system activity in real-time, particularly for security and compliance purposes. AuditRS is written entirely in Rust to provide strong safety guarantees and high performance. The core functionality of AuditRS includes:
//! 
//! - Reading audit logs from the kernel via netlink sockets.
//! - Parsing raw audit record lines into structured data.
//! - Correlating related records into events.
//! - Applying user-defined filters to determine which events should be logged.
//! - Writing the resulting events to log files in a structured format.
//! - Providing a configuration system for managing audit rules, filters, and other settings.
//! - Seamless log rotation and management of log files.
//! 
//! # Goals
//! - **Performance**: Process audit records with minimal latency and resource usage.
//! - **Safety** : Leverage Rust's safety guarantees to minimize bugs and security vulnerabilities.
//! - **Modernization**: Provide a more user-friendly output format and configuration system, enriching the logs with additional context where possible.
//! - **Compatibility**: Maintain compatibility with existing audit rules, formats, and tools where possible, while also allowing for modern improvements.
//! 
//! # Terms and Definitions
//! - **Audit Record**: A structured representation of an audit event, containing fields such as timestamp, event type, user ID, etc.
//! - **Audit Event**: A single occurrence of an action or operation that is logged by the audit system.
//!   - **Simple Event** - An event that is fully contained within a single audit record.
//!   - **Compound Event** - An event that spans multiple audit records. Correlated via serial and timestamp.
//! - **Audit Rules**: Configurations applied to the kernel to specify what events are emitted.
//!   - These are loaded from a rules file at startup. Since it talks to the kernel, we should keep the legacy format.
//!   - The legacy format is quite opaque, so writing our own wrapper around it is a stretch goal.
//! - **Audit Filters**: User-defined criteria to determine which audit records should be logged or discarded. Applying in user-space allows for more complex logic and richer context than what the kernel can provide.
//! - **Configurations**: Any setting that is not a filter or rule, such as log file paths, log rotation policies, etc.

#![warn(missing_docs, unused_attributes, unused_imports, unused_variables)]
pub mod cli;
pub mod config;
pub mod core;
pub mod daemon;
pub mod rules;
pub mod state;
pub mod tools;
pub mod utils;
