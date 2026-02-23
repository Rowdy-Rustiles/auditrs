use super::AuditTransport;
use crate::raw_record::RawAuditRecord;
use audit::packet::AuditMessage;
use futures::stream::StreamExt;
use netlink_packet_core::NetlinkPayload;
use tokio::sync::mpsc;

pub struct NetlinkAuditTransport {
    receiver: mpsc::Receiver<RawAuditRecord>,
}

impl AuditTransport for NetlinkAuditTransport {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel(1000);
        tokio::spawn(async move {
            if let Err(e) = netlink_listener_task(sender).await {
                eprintln!("Netlink listener error: {}", e);
            }
        });
        Self { receiver }
    }
    fn read_message(&self) -> Option<Vec<u8>> {
        None
    }
    fn into_receiver(self) -> mpsc::Receiver<RawAuditRecord> {
        self.receiver
    }
    async fn recv(&mut self) -> Option<RawAuditRecord> {
        self.receiver.recv().await
    }
}

impl Default for NetlinkAuditTransport {
    fn default() -> Self {
        <Self as AuditTransport>::new()
    }
}

async fn netlink_listener_task(
    sender: mpsc::Sender<RawAuditRecord>,
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

                // Create RawAuditRecord
                let record_id = msg.header.message_type;
                let raw_record = RawAuditRecord::new(record_id, data);

                // Send event through channel
                if sender.send(raw_record).await.is_err() {
                    break; // Channel closed    
                }
            }
        }
    }
    Ok(())
}
