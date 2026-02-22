use std::sync::Arc;
use std::time::Duration; // todo - when to use std::sync vs tokio::sync ?? tokio docs say something about access across threads
use tokio::sync::{mpsc, Mutex};
use tokio::signal;
use tokio::time::sleep;

use auditrs::{
    event::*,
    raw_record::*,
    writer::*,
    parser::*,
    correlator::*,
    audit_transport::*,
    parsed_record::*,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    println!("Starting auditRS");
    
    // Initialize components.
    // Todo - wrapping these components in Arc Mutexes might be overkill. Can ownership be moved to their respective tasks?
    let transport   = Arc::new(Mutex::new(  NetlinkAuditTransport::new())   );
    let parser      = Arc::new(Mutex::new(  AuditMessageParser::new())      );
    let correlator  = Arc::new(Mutex::new(  AuditRecordCorrelator::new())   );
    let writer      = Arc::new(Mutex::new(  AuditLogWriter::new())          );
    // let rule_manager = Arc::new(Mutex::new(RuleManager::new()));
    
    // Create message channels to link components input/output.
    let (raw_audit_tx, raw_audit_rx)                = mpsc::channel(1000);
    let (parsed_audit_tx, parsed_audit_rx)          = mpsc::channel(1000);
    let (correlated_event_tx, correlated_event_rx)  = mpsc::channel(1000);
    // General form for these pipes is:
    // let (output_tx, input_rx) = mpsc::channel(buffer_size);
    
    // Start a task that uses each component, with channels hooked up.
    let transport_task  = spawn_transport_task(transport, raw_audit_tx);
    let parser_task     = spawn_parser_task(parser, raw_audit_rx, parsed_audit_tx);
    let correlator_task = spawn_correlator_task(correlator, parsed_audit_rx, correlated_event_tx);
    let writer_task     = spawn_writer_task(writer, correlated_event_rx);
    
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
    transport_task.abort();
    parser_task.abort();
    correlator_task.abort();
    writer_task.abort();
    
    // Optionally wait for them to finish aborting
    let _ = tokio::join!(transport_task, parser_task, correlator_task, writer_task);
    
    Ok(())
}

fn spawn_transport_task(
    transport: Arc<Mutex<NetlinkAuditTransport>>, 
    sender: mpsc::Sender<RawAuditRecord>
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Driver code for the transport goes here. Start it up, listen to messages.
        loop {
            println!("I'm reading/writing to the netlink socket! Yippee.");
            sleep(Duration::from_millis(100)).await;
            // Suppose you got a message, ala:
            // let msg = transport.recv().await
            // You'd then send that to the parser, or whatever component held the other end of the channel.
            // sender.send(msg);
        }
    })
}

fn spawn_parser_task(
    parser: Arc<Mutex<AuditMessageParser>>,
    mut receiver: mpsc::Receiver<RawAuditRecord>,
    sender: mpsc::Sender<ParsedAuditRecord>
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            println!("Parssssing ~~~");
            sleep(Duration::from_millis(100)).await;
        }
    })
}

fn spawn_correlator_task(
    correlator: Arc<Mutex<AuditRecordCorrelator>>,
    mut receiver: mpsc::Receiver<ParsedAuditRecord>,
    sender: mpsc::Sender<AuditEvent>
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            println!("Correlation!!! woah :o");
            sleep(Duration::from_millis(100)).await;
        }
    })
}

fn spawn_writer_task(
    writer: Arc<Mutex<AuditLogWriter>>,
    mut receiver: mpsc::Receiver<AuditEvent>
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
