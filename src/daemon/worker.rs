use anyhow::Result;
use std::time::Duration;
use tokio::signal;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;

use crate::config::{AuditConfig, load_config};
use crate::correlator::{AuditEvent, Correlator};
use crate::daemon::daemon;
use crate::netlink::{NetlinkAuditTransport, RawAuditRecord};
use crate::parser::ParsedAuditRecord;
use crate::writer::AuditLogWriter;

/// Launches the auditrs daemons' component threads
pub async fn run_worker() -> Result<()> {
    // We watch to see if the config file changes, if so, we
    // send the new config into the config transmitter channel to
    // propagate to the necessary components.
    let config = load_config()?;
    let (config_tx, config_rx) = watch::channel(config);

    let writer = AuditLogWriter::new()?;
    let transport = NetlinkAuditTransport::new();
    let raw_audit_rx = transport.into_receiver();
    let correlator = Correlator::new();

    let (parsed_audit_tx, parsed_audit_rx) = mpsc::channel(1000);
    let (correlated_event_tx, correlated_event_rx) = mpsc::channel(1000);

    let parser_task = spawn_parser_task(raw_audit_rx, parsed_audit_tx);
    let correlator_task = spawn_correlator_task(correlator, parsed_audit_rx, correlated_event_tx);
    let writer_task = spawn_writer_task(writer, correlated_event_rx, config_rx);

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => {
                match load_config() {
                    Ok(cfg) => { let _ = config_tx.send(cfg); }
                    Err(e) => eprintln!("SIGHUP: failed to reload config: {:?}", e),
                }
            }
        }
    }

    parser_task.abort();
    correlator_task.abort();
    writer_task.abort();
    let _ = tokio::join!(parser_task, correlator_task, writer_task);
    Ok(())
}

fn spawn_parser_task(
    mut receiver: mpsc::Receiver<RawAuditRecord>,
    sender: mpsc::Sender<ParsedAuditRecord>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(raw_record) = receiver.recv().await {
            match ParsedAuditRecord::try_from(raw_record) {
                Ok(parsed_record) => {
                    println!("Parsed record: {:?}", parsed_record);
                    sender
                        .send(parsed_record)
                        .await
                        .unwrap_or_else(|e| eprintln!("Failed to send parsed record: {:?}", e));
                }
                Err(e) => {
                    eprintln!("Failed to parse raw audit record: {:?}", e);
                    continue;
                }
            };
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
    mut config_rx: watch::Receiver<AuditConfig>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                maybe_event = receiver.recv() => {
                    let Some(event) = maybe_event else { break; };
                    if let Err(e) = writer.write_event(event) {
                        eprintln!("Failed to write audit event: {:?}", e);
                    }
                }
                Ok(()) = config_rx.changed() => {
                    let cfg = config_rx.borrow_and_update().clone();
                    if let Err(e) = writer.reload_config(&cfg) {
                        eprintln!("Failed to apply config reload: {:?}", e);
                    }
                }
            }
        }
    })
}
