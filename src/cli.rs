use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "auditrs")]
#[command(version = "0.3.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Start,
    Stop,
    Dump,
    Status,
    Config,
}
