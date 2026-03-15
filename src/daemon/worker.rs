//! Asynchronous worker loop and background tasks for the `auditrs` daemon.
//!
//! This module wires together the core components of the daemon:
//! the netlink transport, parser, correlator, and writer. It is
//! responsible for:
//!
//! - **Launching tasks** that receive raw audit records, parse them into
//!   structured records, correlate them into higher-level events, and persist
//!   them to disk.
//! - **Managing configuration and rules reloads** in response to `SIGHUP`,
//!   propagating new values to interested components via `watch` channels.
//! - **Handling shutdown signals** (`SIGTERM`, Ctrl‑C) and orchestrating a
//!   graceful stop of background tasks.

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
use crate::state::{AuditConfig, Rules, State};

/// Launches the daemon's asynchronous worker tasks and drives signal handling.
///
/// The worker performs the following high-level steps:
///
/// - Loads initial `State` (configuration and rules) and exposes them on
///   `watch` channels so that downstream components can react to updates.
/// - Constructs the core pipeline components: `AuditLogWriter`,
///   `NetlinkAuditTransport`, and `Correlator`.
/// - Spawns three cooperative tasks:
///   - a **parser task** that consumes `RawAuditRecord`s and produces
///     `ParsedAuditRecord`s,
///   - a **correlator task** that groups related records into `AuditEvent`s,
///   - a **writer task** that persists events and reacts to config/rules
///     changes.
/// - Waits for termination signals (`SIGTERM`, `SIGHUP`, Ctrl‑C); on `SIGHUP`
///   it reloads state and publishes new config/rules; on termination signals it
///   aborts the background tasks and returns.
///
/// **Parameters:**
///
/// This function does not take any parameters; it is intended to be the
/// top-level entry point for the daemon's asynchronous runtime.
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

/// Spawns the background task responsible for parsing raw audit records.
///
/// This task:
///
/// - Receives `RawAuditRecord`s from the netlink transport.
/// - Converts each record into a `ParsedAuditRecord` via
///   `ParsedAuditRecord::try_from`.
/// - Emits successfully parsed records on the provided `mpsc` channel for
///   downstream correlation.
/// - Logs parse errors but continues processing subsequent records.
///
/// **Parameters:**
///
/// * `receiver`: `mpsc::Receiver<RawAuditRecord>` from which raw records are
///   pulled.
/// * `sender`: `mpsc::Sender<ParsedAuditRecord>` used to forward successfully
///   parsed records to the correlator stage.
///
/// The returned `JoinHandle` can be used to manage or cancel the task.
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

/// Spawns the correlator task that groups parsed records into audit events.
///
/// The correlator task:
///
/// - Listens for incoming `ParsedAuditRecord`s and pushes them into a
///   `Correlator` instance.
/// - Periodically (every 500ms) flushes expired or complete events from the
///   correlator and forwards them on an `mpsc` channel to the writer.
///
/// This design ensures that events are written out in a timely fashion even if
/// no new records are currently arriving.
///
/// **Parameters:**
///
/// * `correlator`: The `Correlator` instance responsible for grouping related
///   audit records into higher-level `AuditEvent`s.
/// * `receiver`: `mpsc::Receiver<ParsedAuditRecord>` that supplies parsed
///   records to be correlated.
/// * `sender`: `mpsc::Sender<AuditEvent>` used to publish completed or expired
///   events to the writer stage.
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

/// Spawns the writer task that persists correlated events and reacts to
/// runtime configuration changes.
///
/// The writer task:
///
/// - Consumes `AuditEvent`s from an `mpsc` channel and writes them to the
///   configured log outputs.
/// - Listens for changes on the `config_rx` and `rules_rx` `watch` channels,
///   applying updated configuration and rules to the `AuditLogWriter` as they
///   arrive (typically triggered by `SIGHUP`).
///
/// The task runs until the event channel is closed, after which it exits
/// cleanly.
///
/// **Parameters:**
///
/// * `writer`: The `AuditLogWriter` instance responsible for persisting
///   `AuditEvent`s and applying configuration updates.
/// * `receiver`: `mpsc::Receiver<AuditEvent>` from which correlated events are
///   consumed.
/// * `config_rx`: `watch::Receiver<AuditConfig>` that delivers live
///   configuration updates.
/// * `rules_rx`: `watch::Receiver<Rules>` that delivers live rule changes used
///   by the writer.
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
