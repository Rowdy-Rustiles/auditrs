#![allow(warnings)]
use clap::Parser;
use std::sync::Arc;
use std::time::Duration; // todo - when to use std::sync vs tokio::sync ?? tokio docs say something about access across threads
use tokio::signal;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;

use auditrs::cli::{Cli, Commands};
use auditrs::{
    correlator::{AuditEvent, Correlator},
    daemon,
    netlink::{NetlinkAuditTransport, RawAuditRecord},
    parser::ParsedAuditRecord,
    writer::AuditLogWriter,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::consts::OS != "linux" {
        println!("auditRS is only supported on Linux");
        return Ok(());
    }

    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Start => {
            println!("Starting auditRS");
            daemon::start_daemon()?;
            // Runtime must be created after fork?? maybe?
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            rt.block_on(run_worker())
        }
        Commands::Stop => stop_auditrs(),
        Commands::Dump => dump_auditrs(),
        Commands::Status => status_auditrs(),
        Commands::Config => config_auditrs(),
    };

    if let Err(e) = result {
        return Err(e);
    }

    Ok(())
}

async fn run_worker() -> Result<(), Box<dyn std::error::Error>> {
    let writer = AuditLogWriter::new();
    let transport = NetlinkAuditTransport::new();
    let raw_audit_rx = transport.into_receiver();
    let correlator = Correlator::new();

    let (parsed_audit_tx, parsed_audit_rx) = mpsc::channel(1000);
    let (correlated_event_tx, correlated_event_rx) = mpsc::channel(1000);

    let parser_task = spawn_parser_task(raw_audit_rx, parsed_audit_tx);
    let correlator_task = spawn_correlator_task(correlator, parsed_audit_rx, correlated_event_tx);
    let writer_task = spawn_writer_task(writer, correlated_event_rx);

    // Await a shutdown signal (either via auditrs stop or ctrl+c)
    let mut sigterm = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    tokio::select! {
        _ = signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }

    parser_task.abort();
    correlator_task.abort();
    writer_task.abort();
    let _ = tokio::join!(parser_task, correlator_task, writer_task);

    daemon::remove_pid_file();

    Ok(())
}

fn stop_auditrs() -> Result<(), Box<dyn std::error::Error>> {
    {
        daemon::stop_daemon()?;
        println!("Stopped auditRS daemon");
    }
    Ok(())
}

fn dump_auditrs() -> Result<(), Box<dyn std::error::Error>> {
    println!("Dump, WIP");
    Ok(())
}

fn status_auditrs() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "auditRS is {}",
        if daemon::is_running() {
            "running"
        } else {
            "not running"
        }
    );
    Ok(())
}

fn config_auditrs() -> Result<(), Box<dyn std::error::Error>> {
    println!("Config, WIP");
    Ok(())
}

fn spawn_parser_task(
    mut receiver: mpsc::Receiver<RawAuditRecord>,
    sender: mpsc::Sender<ParsedAuditRecord>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(raw_record) = receiver.recv().await {
            let parsed_record = ParsedAuditRecord::try_from(raw_record).unwrap();
            println!("Parsed record: {:?}", parsed_record);
            sender.send(parsed_record).await.unwrap();
        }
    })
}

fn spawn_correlator_task(
    mut correlator: Correlator,
    mut receiver: mpsc::Receiver<ParsedAuditRecord>,
    sender: mpsc::Sender<AuditEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            /// Two async branches are run, the first to succeed will be executed.
            /// The second branch is executed periodically, every 500ms.
            tokio::select! {
                Some(record) = receiver.recv() => {
                    correlator.push(record);
                }
                _ = sleep(Duration::from_millis(500)) => {
                    for event in correlator.flush_expired() {
                        sender.send(event).await.unwrap();
                    }
                }
            }
        }
    })
}

fn spawn_writer_task(
    mut writer: AuditLogWriter,
    mut receiver: mpsc::Receiver<AuditEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = receiver.recv().await {
            if let Err(e) = writer.write_event(event) {
                eprintln!("Failed to write audit event: {:?}", e);
            }
        }
    })
}
