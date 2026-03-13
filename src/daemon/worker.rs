use anyhow::Result;
use std::time::Duration;
use tokio::signal;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;

use crate::core::{
    correlator::{AuditEvent, Correlator},
    netlink::{NetlinkAuditTransport, RawAuditRecord},
    parser::ParsedAuditRecord,
    writer::AuditLogWriter,
};
use crate::daemon::daemon;
use crate::state::{AuditConfig, Rules, State};


/// Launches the auditrs daemons' component threads
pub async fn run_worker() -> Result<()> {
    // We watch to see if the config and rules files change; on reload, we
    // send the new values into watch channels to propagate to the necessary
    // components (currently the writer).
    let state = State::load_state()?;

    let (config_tx, config_rx) = watch::channel(state.config);
    let (rules_tx, rules_rx) = watch::channel(state.rules);

    let writer = AuditLogWriter::new()?;
    let transport = NetlinkAuditTransport::new();
    let raw_audit_rx = transport.into_receiver();
    let correlator = Correlator::new();

    let (parsed_audit_tx, parsed_audit_rx) = mpsc::channel(1000);
    let (correlated_event_tx, correlated_event_rx) = mpsc::channel(1000);

    let parser_task = spawn_parser_task(raw_audit_rx, parsed_audit_tx);
    let correlator_task = spawn_correlator_task(correlator, parsed_audit_rx, correlated_event_tx);
    let writer_task = spawn_writer_task(writer, correlated_event_rx, config_rx, rules_rx);

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => {
                match State::load_state() {
                    Ok(state) => {
                        let _ = config_tx.send(state.config);
                        let _ = rules_tx.send(state.rules);
                    }
                    Err(e) => {
                        eprintln!("SIGHUP: failed to reload state: {:?}", e);
                    }
                };
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
    mut rules_rx: watch::Receiver<Rules>,
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
                Ok(()) = rules_rx.changed() => {
                    let rules = rules_rx.borrow_and_update().clone();
                    writer.reload_rules(&rules);
                }
            }
        }
    })
}
