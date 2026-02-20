
use super::AuditTransport;
use crate::event::{RawAuditEvent, RawEventType};
use audit::packet::AuditMessage;
use futures::stream::StreamExt;
use netlink_packet_core::NetlinkPayload;
use tokio::sync::mpsc;

pub struct NetlinkAuditTransport {
    receiver: mpsc::Receiver<RawAuditEvent>,
}

impl AuditTransport for NetlinkAuditTransport {
    fn read_message(&self) -> Option<Vec<u8>> {
        // Deferred to the spawned task
        None
    }

    fn new() -> Self {
        let (tx, rx) = mpsc::channel(1000);

        // Spawn the netlink listener task
        tokio::spawn(async move {
            if let Err(e) = netlink_listener_task(tx).await {
                eprintln!("Netlink listener error: {}", e);
            }
        });

        NetlinkAuditTransport { receiver: rx }
    }
}

impl NetlinkAuditTransport {
    /// Async method to receive the next RawAuditEvent
    pub async fn recv(&mut self) -> Option<RawAuditEvent> {
        self.receiver.recv().await
    }
}

async fn netlink_listener_task(
    sender: mpsc::Sender<RawAuditEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create netlink socket connection
    let (connection, mut handle, mut messages) =
        audit::new_connection().map_err(|e| format!("Connection failed: {}", e))?;

    // Spawn connection task
    tokio::spawn(connection);

    // Enable audit events
    handle
        .enable_events()
        .await
        .map_err(|e| format!("Failed to enable events: {}", e))?;

    println!("Netlink audit transport listening for kernel events");

    // Process events from the Linux kernel audit subsystem
    while let Some((msg, _addr)) = messages.next().await {
        if let NetlinkPayload::InnerMessage(inner) = &msg.payload {
            if let AuditMessage::Event(event) = inner {
                let (_, kvs) = event;
                let data = kvs.to_string();

                // Convert message type to RawEventType
                let record_type = RawEventType::from(msg.header.message_type);

                // Create RawAuditEvent
                let raw_event = RawAuditEvent::new(record_type, data);

                // Send event through channel
                if sender.send(raw_event).await.is_err() {
                    break; // Channel closed
                }
            }
        }
    }
    Ok(())
}
