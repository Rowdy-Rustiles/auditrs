//! Shared utilities for the codebase.
//!
//! This module collects small, reusable helpers that are shared across
//! subsystems:
//! - `input_utils` contains CLI-oriented utilities such as autocompleters and
//!   validators used by interactive commands.
//! - `utils` provides general-purpose helpers (time formatting, string
//!   manipulation, filesystem helpers, etc.).
//! - `reading_utils` supports higher-level tools that need to scan or process
//!   existing audit logs.
//! Keeping these utilities centralized avoids duplication between the CLI,
//! daemon, and tools modules.

mod input_utils;
mod reading_utils;
mod utils;

pub use input_utils::*;
pub use utils::*;
