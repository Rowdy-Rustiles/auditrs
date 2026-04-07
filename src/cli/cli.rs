//! # auditrs CLI Module
//!
//! This module defines the command-line interface for the auditrs audit event
//! management tool. It provides a comprehensive set of subcommands for
//! inspecting, managing, and configuring audit events and the auditrs daemon.

use clap::{Arg, ArgAction, Command as ClapCommand};

/// Builds the top-level command-line interface for the `auditrs` binary.
///
/// This function defines the root command and registers all supported
/// subcommands for daemon control, event inspection, reporting, and
/// configuration management.
pub fn build_cli() -> ClapCommand {
    ClapCommand::new("auditrs")
        .about("Inspect and manage audit events and configuration")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(ClapCommand::new("start").about("Start the auditrs daemon and event pipeline"))
        .subcommand(ClapCommand::new("stop").about("Stop the running auditrs daemon"))
        .subcommand(ClapCommand::new("reboot").about("Restart the auditrs daemon (stop + start)"))
        .subcommand(ClapCommand::new("status").about("Show whether the daemon is running"))
        .subcommand(build_filter())
        .subcommand(build_watch())
        .subcommand(build_search())
        .subcommand(build_report())
        .subcommand(build_config())
}


/// Builds the `search` subcommand.
///
/// The `search` command queries audit events using a free-text or key-value
/// expression and supports additional filters such as time range, field,
/// event type, user, result, and output format.
fn build_search() -> ClapCommand {
    ClapCommand::new("search")
        .about("Search audit events")
        .long_about("Returns any events that match the search query and/or its options")
        .arg(
            Arg::new("query")
                .value_name("QUERY")
                .required(false)
                .help("Free-text or key-value search expression"),
        )
        .arg(
            Arg::new("since")
                .long("since")
                .value_name("TIME")
                .help("Only include events at or after this time")
                .long_help(
                    "Start time of the window for the report (inclusive).\n
Input should be formatted as a RFC3339 timestamp, see the following resources for more information:
<https://time.now/tool/rfc-3339-converter/>, <https://datatracker.ietf.org/doc/html/rfc3339>.
YYYY-MM-DDTHH:MM:SS[.mmm]Z

Examples:
- 2026-03-04T10:00:00Z
- 2026-03-04T10:00:00.000Z
                ",
                ),
        )
        .arg(
            Arg::new("until")
                .long("until")
                .value_name("TIME")
                .help("Only include events strictly before this time")
                .long_help(
                    "End time of the window for the report (exclusive).\n
Input should be formatted as a RFC3339 timestamp, see the following resources for more information:
<https://time.now/tool/rfc-3339-converter/>, <https://datatracker.ietf.org/doc/html/rfc3339>.
YYYY-MM-DDTHH:MM:SS[.mmm]Z

Examples:
- 2026-03-04T10:00:00Z
- 2026-03-04T10:00:00.000Z
                ",
                ),
        )
        .arg(
            Arg::new("field")
                .long("field")
                .value_name("FIELD=VALUE")
                .help(
                    "Restrict the search to a field (e.g. exe). Use field=value to set the search \
                     term when QUERY is omitted (e.g. --field exe=/usr/bin/ls)",
                )
                .long_help(
                    "Restrict the search to a field (e.g. exe). Use field=value to set the search \
                     term when QUERY is omitted (e.g. --field exe=/usr/bin/ls). \n
Possible fields to query by include, but are not limited to the fields found here:
<https://access.redhat.com/articles/4409591?extIdCarryOver=true&sc_cid=RHCTG0180000382536#audit-event-fields-1>."
                ),
        )
        .arg(
            Arg::new("type")
                .long("type")
                .value_name("EVENT_TYPE")
                .help("Filter by event type")
                .long_help(
                    "Filter by event type \n
A few blanket types covering multiple record types are available: <exec, file, auth>.
More specific event types can be found here 
<https://github.com/Rowdy-Rustiles/docs/blob/main/Reference/Record%20Types.md>.
"

                ),
        )
        .arg(
            Arg::new("user")
                .long("user")
                .value_name("USER_KEY=VALUE")
                .help(
                    "Filter by user ID/name across uid/auid/euid/… fields, or restrict with \
                     uid=1000, auid=…, etc.",
                )
                .long_help(
                    "Filter by user ID/name across uid/auid/euid/… fields, or restrict with \
                     uid=1000, auid=…, etc. \n
Possible keys: <uid, auid, euid, gid, egid, ouid, fsuid, loginuid, suid, ses>. "
                ),
        )
        .arg(
            Arg::new("result")
                .long("result")
                .value_name("RESULT")
                .value_parser(["success", "failed"])
                .help("Filter by outcome"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .value_parser(["simple", "json"])
                .help("Output as a human-readable table or JSON"),
        )
        .arg(
            Arg::new("limit")
                .long("limit")
                .value_name("N")
                .help("Maximum number of matching events to print"),
        )
}

/// Builds the `report` subcommand.
///
/// The `report` command generates aggregate summaries over audit events
/// within an optional time window and supports grouping, failed-only
/// filtering, and multiple output formats.
fn build_report() -> ClapCommand {
    ClapCommand::new("report")
        .about("Generate summary reports over audit events")
        .arg(
            Arg::new("since")
                .long("since")
                .value_name("TIME")
                .help("Start of the time window for the report (inclusive)")
                .long_help(
                    "Start time of the window for the report (inclusive).\n
Input should be formatted as a RFC3339 timestamp, see the following resources for more information:
<https://time.now/tool/rfc-3339-converter/>, <https://datatracker.ietf.org/doc/html/rfc3339>.
YYYY-MM-DDTHH:MM:SS[.mmm]Z

Examples:
- 2026-03-04T10:00:00Z
- 2026-03-04T10:00:00.000Z
                ",
                ),
        )
        .arg(
            Arg::new("until")
                .long("until")
                .value_name("TIME")
                .help("End of the time window for the report (exclusive)")
                .long_help(
                    "End time of the window for the report (exclusive).\n
Input should be formatted as a RFC3339 timestamp, see the following resources for more information:
<https://time.now/tool/rfc-3339-converter/>, <https://datatracker.ietf.org/doc/html/rfc3339>.
YYYY-MM-DDTHH:MM:SS[.mmm]Z

Examples:
- 2026-03-04T10:00:00Z
- 2026-03-04T10:00:00.000Z
                ",
                ),
        )
        .arg(
            Arg::new("summary")
                .long("summary")
                .value_name("TYPE")
                .value_parser(["combine", "separate", "exclude"])
                .help("Generate a summary report"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .value_parser(["legacy", "simple", "json"])
                .help("Report output format"),
        )
        .arg(
            Arg::new("no_save")
                .long("no-save")
                .action(ArgAction::SetTrue)
                .help("Do not save the report; print it to stdout (summary at top for combine/separate)"),
        )
        .arg(
            Arg::new("summary_only")
                .long("summary-only")
                .action(ArgAction::SetTrue)
                .help("Only print the summary; do not print the report body"),
        )
        .arg(
            Arg::new("output_path")
                .short('o')
                .long("output")
                .value_name("PATH")
                .help("Path to write the report to"),
        )
}

/// Builds the `config` subcommand.
///
/// The `config` command provides nested subcommands for reading and updating
/// daemon configuration values such as directories, size limits, and log
/// format.
fn build_config() -> ClapCommand {
    ClapCommand::new("config")
        .about("Inspect and update audit configuration")
        .subcommand(
            ClapCommand::new("get")
                .about("Read config values")
                .subcommand(ClapCommand::new("format").about("Get the current output format"))
                .subcommand(
                    ClapCommand::new("log-directory").about("Get the current log directory"),
                )
                .subcommand(
                    ClapCommand::new("journal-directory")
                        .about("Get the current journal directory"),
                )
                .subcommand(
                    ClapCommand::new("primary-directory")
                        .about("Get the current primary directory"),
                )
                .subcommand(ClapCommand::new("log-size").about("Get the current log size limit"))
                .subcommand(
                    ClapCommand::new("journal-size").about("Get the current journal size limit"),
                )
                .subcommand(
                    ClapCommand::new("primary-size").about("Get the current primary size limit"),
                ),
        )
        .subcommand(
            ClapCommand::new("set")
                .about("Update config values, will reboot the daemon if the config was changed")
                .subcommand(
                    ClapCommand::new("format")
                        .about("Set the output format")
                        .arg(
                            Arg::new("value")
                                .value_name("FORMAT")
                                .required(false)
                                .value_parser(["legacy", "simple", "json"])
                                .help("New log format; omit for interactive selection"),
                        ),
                )
                .subcommand(
                    ClapCommand::new("log-directory")
                        .about("Set the log directory")
                        .arg(
                            Arg::new("value")
                                .value_name("VALUE")
                                .required(true)
                                .help("New log directory path"),
                        ),
                )
                .subcommand(
                    ClapCommand::new("journal-directory")
                        .about("Set the journal directory")
                        .arg(
                            Arg::new("value")
                                .value_name("VALUE")
                                .required(true)
                                .help("New journal directory path"),
                        ),
                )
                .subcommand(
                    ClapCommand::new("primary-directory")
                        .about("Set the primary directory")
                        .arg(
                            Arg::new("value")
                                .value_name("VALUE")
                                .required(true)
                                .help("New primary directory path"),
                        ),
                )
                .subcommand(ClapCommand::new("log-size").about("Set the log size limit"))
                .subcommand(ClapCommand::new("journal-size").about("Set the journal size limit"))
                .subcommand(ClapCommand::new("primary-size").about("Set the primary size limit"))
                .arg_required_else_help(true),
        )
        .arg_required_else_help(true)
}

/// Builds the `filter` subcommand.
///
/// The `filter` command provides operations for viewing, adding, removing,
/// updating, importing, and dumping audit filter rules.
fn build_filter() -> ClapCommand {
    ClapCommand::new("filter")
        .about("Commands for managing log filters")
        .long_about("Commands for managing log filters\nDocumentation about the record types that can be used in filters can be\nfound at: https://github.com/Rowdy-Rustiles/docs/blob/main/Reference/Record%20Types.md")
        .subcommand(
            ClapCommand::new("get").about("Show current filters"),
        )
        .subcommand(
            ClapCommand::new("add")
                .about("Add a filter rule")
                .long_about(
                    "Add a filter rule for a record type defined in:\nhttps://github.com/Rowdy-Rustiles/docs/blob/main/Reference/Record%20Types.md",
                )
                .arg(
                    Arg::new("record_type")
                        .long("record-type")
                        .value_name("RECORD_TYPE")
                        .required(false)
                        .help("Record type to add; omit for interactive prompt"),
                )
                .arg(
                    Arg::new("action")
                        .long("action")
                        .value_name("ACTION")
                        .required(false)
                        .help("Filter action (allow, block, sample, redact, route_secondary, tag, count_only, alert)"),
                ),
        )
        .subcommand(
            ClapCommand::new("remove")
                .about("Remove a filter rule")
                .arg(Arg::new("value").value_name("VALUE").required(false).help(
                    "Record type to remove; omit for interactive choice from existing filters",
                )),
        )
        .subcommand(
            ClapCommand::new("update")
                .about("Update a filter rule")
                .long_about("Update an existing filter rule")
                .arg(
                    Arg::new("record_type")
                        .long("record-type")
                        .value_name("RECORD_TYPE")
                        .required(false)
                        .help("Record type to update; omit for interactive prompt"),
                )
                .arg(
                    Arg::new("action")
                        .long("action")
                        .value_name("ACTION")
                        .required(false)
                        .help("New filter action; omit for interactive prompt"),
                ),
        )
        .subcommand(
            ClapCommand::new("import")
                .about("Import filters from a file (supports .ars, .toml)")
                .arg(Arg::new("file").value_name("FILE").required(true).help(
                    "File to import filters from (.ars, .toml, .rules)",
                )),
        )
        .subcommand(
            ClapCommand::new("dump")
                .about("Dump filters to a file (supports .ars, .toml)")
                .arg(Arg::new("file").value_name("FILE").required(true).help(
                    "File to dump filters to (omit file extension)"
                )),
        )
        .arg_required_else_help(true)
}

/// Builds the `watch` subcommand.
///
/// The `watch` command provides operations for viewing, adding, removing,
/// updating, importing, and dumping audit watch rules.
fn build_watch() -> ClapCommand {
    ClapCommand::new("watch")
        .about("Commands for managing log watches")
        .long_about("Commands for managing log watches\nDocumentation about watches can be\nfound at: TO IMPLEMENT")
        .subcommand(
            ClapCommand::new("get").about("Show current watches"),
        )
        .subcommand(
            ClapCommand::new("add")
                .about("Add a watch rule")
                .long_about("Add a watch rule for as specified in:\nTO IMPLEMENT")
                .arg(
                    Arg::new("path")
                        .value_name("PATH")
                        .required(false)
                        .help("Path to watch; omit for interactive prompt"),
                )
                .arg(
                    Arg::new("action")
                        .long("action")
                        .value_name("ACTION")
                        .required(false)
                        .action(ArgAction::Append)
                        .help("Watch action (read, write, execute). Repeatable. Omit for interactive prompt"),
                )
                .arg(
                    Arg::new("recursive")
                        .long("recursive")
                        .action(ArgAction::SetTrue)
                        .help("Watch directories recursively (non-interactive only)"),
                ),
        )
        .subcommand(
            ClapCommand::new("remove")
                .about("Remove a watch rule")
                .arg(
                    Arg::new("key")
                        .long("key")
                        .value_name("KEY")
                        .required(false)
                        .help("Key of the watch to remove; omit for interactive prompt"),
                )
                .arg(Arg::new("value").value_name("VALUE").required(false).help(
                    "Key to remove; omit for interactive choice from existing watches",
                )),
        )
        .subcommand(
            ClapCommand::new("update")
                .about("Update a watch rule")
                .long_about("Update an existing watch rule")
                .arg(
                    Arg::new("key")
                        .long("key")
                        .value_name("KEY")
                        .required(false)
                        .help("Key of the watch to update; omit for interactive prompt"),
                )
                .arg(
                    Arg::new("action")
                        .long("action")
                        .value_name("ACTION")
                        .required(false)
                        .action(ArgAction::Append)
                        .help("New watch actions (read, write, execute). Repeatable. Omit for interactive prompt"),
                )
                .arg(
                    Arg::new("recursive")
                        .long("recursive")
                        .value_name("true|false")
                        .required(false)
                        .value_parser(["true", "false"])
                        .help("Set recursive mode (non-interactive only)"),
                ),
        )
        .subcommand(
            ClapCommand::new("import")
                .about("Import watches from a file (supports .ars, .toml)")
                .arg(Arg::new("file").value_name("FILE").required(true).help(
                    "File to import filters from (.ars, .toml, .rules)",
                )),
        )
        .subcommand(
            ClapCommand::new("dump")
                .about("Dump watches to a file (supports .ars, .toml)")
                .arg(Arg::new("file").value_name("FILE").required(true).help(
                    "File to dump filters to (omit file extension)"
                )),
        )
        .arg_required_else_help(true)
}

/// Tests for command-line parsing behavior in the CLI module.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_search_query() {
        let cmd = build_cli();
        let matches = cmd
            .clone()
            .try_get_matches_from(["auditrs", "search", "uid=1000"])
            .expect("arguments should parse");

        let ("search", sub_m) = matches.subcommand().expect("expected search subcommand") else {
            unreachable!();
        };

        assert_eq!(sub_m.get_one::<String>("query").unwrap(), "uid=1000");
    }

    #[test]
    fn parses_config_get_log_directory() {
        let cmd = build_cli();
        let matches = cmd
            .clone()
            .try_get_matches_from(["auditrs", "config", "get", "log-directory"])
            .expect("arguments should parse");

        let ("config", cfg_m) = matches.subcommand().expect("expected config subcommand") else {
            unreachable!();
        };

        let ("get", get_m) = cfg_m.subcommand().expect("expected get subcommand") else {
            unreachable!();
        };

        assert_eq!(get_m.subcommand_name(), Some("log-directory"));
    }
}
