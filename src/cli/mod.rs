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
//! alone shows help. The tool inspects and manages audit events, the daemon,
//! filters, watches, and configuration.
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
//! ## `dump` — stream or write events
//!
//! Dump matching audit events to stdout or an optional file. Supports time
//! range, type, user, result, format, streaming, and a limit.
//!
//! **Positional:** optional `FILE` — output path; if omitted, writes to stdout.
//!
//! **Flags:**
//!
//! - `--since TIME` — events at or after this time (e.g. `2026-03-04T10:00`,
//!   `-1h`).
//! - `--until TIME` — events strictly before this time.
//! - `--type EVENT_TYPE` — filter by event type (e.g. exec, file, auth).
//! - `--user USER` — filter by effective user name or ID.
//! - `--result success|failed` — filter by outcome.
//! - `--format legacy|simple|json` — output format (default: simple).
//! - `--follow` — stream events as they arrive (similar to `tail -f`).
//! - `--limit N` — maximum number of events to output.
//!
//! ## `search` — query events
//!
//! Search audit events with a required query and optional filters.
//!
//! **Positional:** `QUERY` (required) — free-text or key-value search
//! expression.
//!
//! **Flags:** `--since`, `--until`, `--type`, `--user`, and `--result` behave
//! like `dump`. Additionally:
//!
//! - `--field FIELD` — restrict search to a field (e.g. exe, path, syscall).
//! - `--format table|json` — human-readable table or JSON.
//! - `--limit N` — cap the number of matching events printed.
//!
//! ## `report` — aggregate summaries
//!
//! Summarize audit events over an optional time window with grouping and caps.
//!
//! **Flags:**
//!
//! - `--since TIME` / `--until TIME` — report time window.
//! - `--by user|result|syscall|exe|type` — aggregation dimension.
//! - `--failed` — only include failed events.
//! - `--top N` — show only the top *N* buckets per aggregation.
//! - `--format table|json` — report output format.
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
