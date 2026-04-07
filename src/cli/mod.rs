//! Top-level CLI module.
//!
//! This module defines the command-line interface surface of the daemon:
//! - `cli` contains the clap-based command hierarchy and argument parsing.
//! - `dispatcher` routes parsed CLI matches to the appropriate handlers in
//!   other subsystems (configuration, rules, daemon control, and tools).
//!
//! # CLI overview
//!
//! The root command is `auditrs`. A subcommand is required; running `auditrs`
//! alone shows help. Top-level subcommands are registered in this order:
//! `start`, `stop`, `reboot`, `status`, `filter`, `watch`, `search`, `report`,
//! `config`.
//!
//! ## Daemon control
//!
//! | Command | Description |
//! |---------|-------------|
//! | `start` | Start the auditrs daemon and event pipeline. |
//! | `stop` | Stop the running auditrs daemon. |
//! | `reboot` | Restart the daemon. |
//! | `status` | Show whether the daemon is running. |
//!
//! ## `search` — query events
//!
//! Search primary audit logs. An event matches when it satisfies the query (if
//! any) and every filter that was passed.
//!
//! **Positional:** `QUERY` (optional when `--field FIELD=VALUE` supplies the
//! search term) — free text, or `key=value` to match a specific field.
//!
//! **Flags:**
//!
//! - `--since` / `--until` — RFC3339 time window (inclusive start, exclusive end).
//! - `--type` — shorthand category (`exec`, `file`, `auth`) or a specific record
//!   type name (see the record-types link under `filter`).
//! - `--user` — identity fields (`uid`, `auid`, …); use `uid=1000` style to
//!   target one field.
//! - `--result` — `success` or `failed` (syscall `success=` field).
//! - `--field` — field name, or `FIELD=VALUE` when `QUERY` is omitted.
//! - `--format simple|json` — output (default: `simple`).
//! - `--limit N` — maximum number of matching events to print.
//!
//! ## `report` — aggregate summaries
//!
//! Summarize audit events over an optional time window. Events are sorted
//! earliest-to-latest before writing or printing.
//!
//! **Flags:**
//!
//! - `--since` / `--until` — RFC3339 time window.
//! - `--format legacy|simple|json` — report body format (default: the daemon’s
//!   configured log format when omitted).
//! - `--summary combine|separate|exclude` — how to emit summary text (default:
//!   `combine`).
//! - `--no-save` — print to stdout instead of writing a file.
//! - `--summary-only` — print only the summary (cannot be used with
//!   `--summary=exclude`).
//! - `-o` / `--output PATH` — output file path.
//! - With no `-o`/`--output` and without `--no-save`, writes
//!   `./reports/report_<timestamp>.<ext>`.
//!
//! ## `config` — read and update settings
//!
//! Nested under `config get` and `config set`. Subcommands require a further
//! keyword (e.g. `config get log-directory`).
//!
//! **`config get` (read-only):** `format`, `log-directory`,
//! `journal-directory`, `primary-directory`, `log-size`, `journal-size`,
//! `primary-size`.
//!
//! **`config set` (updates; may reboot the daemon if configuration changes):**
//! same keys as `get`. For `set log-directory`, `set journal-directory`, and
//! `set primary-directory`, a required `VALUE` positional argument supplies the
//! new path. Other `set` subcommands are defined in the CLI without additional
//! parsed arguments in code (behavior may be interactive or extended
//! elsewhere).
//!
//! ## `filter` — manage log filter rules
//!
//! Reference for record types used in filters:
//! <https://github.com/Rowdy-Rustiles/docs/blob/main/Reference/Record%20Types.md>
//!
//! **Subcommands:**
//!
//! - `get` — show current filters.
//! - `add` — add a filter rule (see record types link above).
//! - `remove` — remove a filter rule; optional `VALUE` (record type), or omit
//!   for an interactive choice among existing filters.
//! - `update` — update an existing filter rule.
//! - `import FILE` — import filters from a file (`.ars`, `.toml`, `.rules`).
//! - `dump FILE` — dump filters to a file (`.ars`, `.toml`; omit file extension
//!   as documented in `--help`).
//!
//! ## `watch` — manage log watch rules
//!
//! **Subcommands:** `get`, `add`, `remove`, `update`, `import FILE`, `dump
//! FILE`. Optional `VALUE` on `remove` is the path to remove; omit for
//! interactive selection. Import supports `.ars`, `.toml`, `.rules`; dump
//! supports `.ars`, `.toml` (see `--help` for file arguments). The CLI’s
//! extended help for watches is not yet fully specified (`TO IMPLEMENT`
//! placeholders in code).

pub mod cli;
pub mod dispatcher;

pub use cli::build_cli;
pub use dispatcher::dispatch;
