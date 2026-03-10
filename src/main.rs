#![allow(warnings)]
use anyhow::Result;

use auditrs::cli::{cli::build_cli, dispatcher};

fn main() -> Result<()> {
    if std::env::consts::OS != "linux" {
        println!("auditRS is only supported on Linux");
        return Ok(());
    }

    let mut cmd = build_cli();
    let matches = cmd.clone().get_matches();

    dispatcher::dispatch(&matches)
}
