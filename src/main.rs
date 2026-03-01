#![allow(warnings)]
use std::sync::Arc;
use std::time::Duration; // todo - when to use std::sync vs tokio::sync ?? tokio docs say something about access across threads
use tokio::signal;
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;


use auditrs::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting auditRS");

    // Initialize components.
    // Todo - wrapping these components in Arc Mutexes might be overkill. Can ownership be moved to their respective tasks?
    let transport = NetlinkAuditTransport::new();
    let raw_audit_rx = transport.into_receiver();
    let parser = Arc::new(Mutex::new(AuditMessageParser::new()));
    let correlator = Arc::new(Mutex::new(Correlator::new()));
    // let writer = Arc::new(Mutex::new(AuditLogWriter::new()));
    // let rule_manager = Arc::new(Mutex::new(RuleManager::new()));

    // Create message channels to link components input/output.
    let (parsed_audit_tx, parsed_audit_rx) = mpsc::channel(1000);
    let (correlated_event_tx, correlated_event_rx) = mpsc::channel(1000);
    // General form for these pipes is:
    // let (output_tx, input_rx) = mpsc::channel(buffer_size);

    // Start a task that uses each component, with channels hooked up.
    let parser_task = spawn_parser_task(parser, raw_audit_rx, parsed_audit_tx);
    let correlator_task = spawn_correlator_task(correlator, parsed_audit_rx, correlated_event_tx);
    let temp_output_task = tokio::spawn(async move {
        let mut rx = correlated_event_rx;
        while rx.recv().await.is_some() {
            // Events already printed by correlator; drain to prevent channel backpressure
        }
    });

    println!("auditRS started successfully");
    // Only job at this point is maintaining the threads and cancelling them if need be.
    // Potentially, we could add logic for detecting config changes and applying them here.

    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            println!("Received SIGINT, shutting down");
        }
    }
    // Graceful shutdown
    println!("Shutting down auditRS");
    parser_task.abort();
    correlator_task.abort();
    temp_output_task.abort();

    // Optionally wait for them to finish aborting
    let _ = tokio::join!(parser_task, correlator_task, temp_output_task);

    Ok(())
}

fn spawn_parser_task(
    parser: Arc<Mutex<AuditMessageParser>>,
    mut receiver: mpsc::Receiver<RawAuditRecord>,
    sender: mpsc::Sender<ParsedAuditRecord>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let parser_clone = Arc::clone(&parser);
        loop {
            let raw_record = receiver.recv().await;
            if let Some(raw_record) = raw_record {
                let parser = parser_clone.lock().await;
                let parsed_record = ParsedAuditRecord::try_from(raw_record).unwrap();
                println!("Parsed record: {:?}", parsed_record);
                sender.send(parsed_record).await.unwrap();
            }
        }
    })
}

fn spawn_correlator_task(
    correlator: Arc<Mutex<Correlator>>,
    mut receiver: mpsc::Receiver<ParsedAuditRecord>,
    sender: mpsc::Sender<AuditEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            /// Two async branches are run, the first to succeed will be executed.
            /// The second branch is executed periodically, every 500ms.
            tokio::select! {
                Some(record) = receiver.recv() => {
                    correlator.lock().await.push(record);
                }
                _ = sleep(Duration::from_millis(500)) => {
                    let mut corr = correlator.lock().await;
                    for event in corr.flush_expired() {
                        println!("Correlated event: {:?}", event);
                        sender.send(event).await.unwrap();
                    }
                }
            }
        }
    })
}

fn spawn_writer_task(
    writer: Arc<Mutex<AuditLogWriter>>,
    mut receiver: mpsc::Receiver<AuditEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            println!("writng the disk :p");
            sleep(Duration::from_millis(100)).await;
            /* e.g.,
            let event = receiver.recv().await
            write_event_to_disk(event);
            */
        }
    })
}
