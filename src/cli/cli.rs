use clap::{Arg, ArgAction, Command as ClapCommand};

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
        .subcommand(build_dump())
        .subcommand(build_search())
        .subcommand(build_report())
        .subcommand(build_config())
}

fn build_dump() -> ClapCommand {
    ClapCommand::new("dump")
        .about("Dump audit events to a file or stdout")
        .arg(
            Arg::new("since")
                .long("since")
                .value_name("TIME")
                .help("Only include events at or after this time (e.g. 2026-03-04T10:00, -1h)"),
        )
        .arg(
            Arg::new("until")
                .long("until")
                .value_name("TIME")
                .help("Only include events strictly before this time"),
        )
        .arg(
            Arg::new("type")
                .long("type")
                .value_name("EVENT_TYPE")
                .help("Filter by event type (e.g. exec, file, auth)"),
        )
        .arg(
            Arg::new("user")
                .long("user")
                .value_name("USER")
                .help("Filter by effective user name or ID"),
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
                .value_parser(["legacy", "simple", "json"])
                .help("Output format (default: simple)"),
        )
        .arg(
            Arg::new("follow")
                .long("follow")
                .action(ArgAction::SetTrue)
                .help("Stream events as they arrive (like tail -f)"),
        )
        .arg(
            Arg::new("limit")
                .long("limit")
                .value_name("N")
                .help("Maximum number of events to output"),
        )
        .arg(
            Arg::new("file")
                .value_name("FILE")
                .help("Optional output file path; if omitted, writes to stdout"),
        )
}

fn build_search() -> ClapCommand {
    ClapCommand::new("search")
        .about("Search audit events")
        .arg(
            Arg::new("query")
                .value_name("QUERY")
                .required(true)
                .help("Free-text or key-value search expression"),
        )
        .arg(
            Arg::new("since")
                .long("since")
                .value_name("TIME")
                .help("Only include events at or after this time"),
        )
        .arg(
            Arg::new("until")
                .long("until")
                .value_name("TIME")
                .help("Only include events strictly before this time"),
        )
        .arg(
            Arg::new("field")
                .long("field")
                .value_name("FIELD")
                .help("Restrict the search to a specific field (e.g. exe, path, syscall)"),
        )
        .arg(
            Arg::new("type")
                .long("type")
                .value_name("EVENT_TYPE")
                .help("Filter by event type"),
        )
        .arg(
            Arg::new("user")
                .long("user")
                .value_name("USER")
                .help("Filter by user"),
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
                .value_parser(["table", "json"])
                .help("Output as a human-readable table or JSON"),
        )
        .arg(
            Arg::new("limit")
                .long("limit")
                .value_name("N")
                .help("Maximum number of matching events to print"),
        )
}

fn build_report() -> ClapCommand {
    ClapCommand::new("report")
        .about("Generate summary reports over audit events")
        .arg(
            Arg::new("since")
                .long("since")
                .value_name("TIME")
                .help("Start of the time window for the report"),
        )
        .arg(
            Arg::new("until")
                .long("until")
                .value_name("TIME")
                .help("End of the time window for the report"),
        )
        .arg(
            Arg::new("by")
                .long("by")
                .value_name("DIMENSION")
                .value_parser(["user", "result", "syscall", "exe", "type"])
                .help("Aggregation dimension"),
        )
        .arg(
            Arg::new("failed")
                .long("failed")
                .action(ArgAction::SetTrue)
                .help("Only include failed events"),
        )
        .arg(
            Arg::new("top")
                .long("top")
                .value_name("N")
                .help("Only show the top-N buckets per aggregation"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .value_parser(["table", "json"])
                .help("Report output format"),
        )
}

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
                .subcommand(ClapCommand::new("format").about("Set the output format"))
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

fn build_filter() -> ClapCommand {
    ClapCommand::new("filter")
        .about("Commands for managing log filters")
        .long_about("Commands for managing log filters\nDocumentation about the record types that can be used in filters can be\nfound at: https://github.com/Rowdy-Rustiles/docs/blob/main/Reference/Record%20Types.md")
        .subcommand(
            ClapCommand::new("get").about("Show current filters").arg(
                Arg::new("value")
                    .value_name("VALUE")
                    .required(false)
                    .help("Optional single value to filter by"),
            ),
        )
        .subcommand(ClapCommand::new("add")
        .about("Add a filter rule")
        .long_about("Add a filter rule for a record type defined in:\nhttps://github.com/Rowdy-Rustiles/docs/blob/main/Reference/Record%20Types.md"))
        .subcommand(
            ClapCommand::new("remove")
                .about("Remove a filter rule")
                .arg(Arg::new("value").value_name("VALUE").required(false).help(
                    "Record type to remove; omit for interactive choice from existing filters",
                )),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dump_with_basic_options() {
        let cmd = build_cli();
        let matches = cmd
            .clone()
            .try_get_matches_from([
                "auditrs",
                "dump",
                "--since",
                "2026-03-04T10:00",
                "--limit",
                "10",
            ])
            .expect("arguments should parse");

        let ("dump", sub_m) = matches.subcommand().expect("expected dump subcommand") else {
            unreachable!();
        };

        assert_eq!(
            sub_m.get_one::<String>("since").unwrap(),
            "2026-03-04T10:00"
        );
        assert_eq!(sub_m.get_one::<String>("limit").unwrap(), "10");
    }

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
