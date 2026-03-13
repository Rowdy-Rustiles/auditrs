//! Core processing pipeline for `auditrs`.
//!
//! The `core` module contains the main building blocks of the event pipeline:
//! - `netlink`: low-level integration with the Linux audit subsystem and
//!   translation of raw kernel records into internal types.
//! - `parser`: parsing of raw records into structured events and shared
//!   `audit_types` definitions.
//! - `correlator`: higher-level aggregation and correlation of related events
//!   into richer `AuditEvent`s.
//! - `enricher`: optional enrichment stages that augment events with extra
//!   context.
//! - `writer`: generic writer interfaces used by the daemon to persist data.

pub mod correlator;
pub mod enricher;
pub mod netlink;
pub mod parser;
pub mod writer;
