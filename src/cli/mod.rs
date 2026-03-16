//! Top-level CLI module.
//!
//! This module defines the command-line interface surface of the daemon:
//! - `cli` contains the clap-based command hierarchy and argument parsing.
//! - `dispatcher` routes parsed CLI matches to the appropriate handlers in
//!   other subsystems (configuration, rules, daemon control, and tools).

pub mod cli;
pub mod dispatcher;

pub use cli::build_cli;
pub use dispatcher::dispatch;
