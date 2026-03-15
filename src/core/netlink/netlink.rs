use anyhow::{Context, Result};
use audit::packet::AuditMessage;
use futures::stream::StreamExt;
use netlink_packet_core::NetlinkPayload;
use tokio::sync::mpsc;

use crate::core::netlink::{NetlinkAuditTransport, RawAuditRecord};

impl NetlinkAuditTransport {
    /// Creates a new `NetlinkAuditTransport` and spawns a task to listen for
    /// audit events.
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(1000);
        tokio::spawn(async move {
            if let Err(e) = netlink_listener_task(sender).await {
                eprintln!("Netlink listener error: {}", e);
            }
        });
        Self { receiver }
    }
    /// Converts the `NetlinkAuditTransport` into a receiver for the raw audit
    /// records.
    pub fn into_receiver(self) -> mpsc::Receiver<RawAuditRecord> {
        self.receiver
    }

    /// Receives a raw audit record from the kernel via netlink.
    async fn recv(&mut self) -> Option<RawAuditRecord> {
        self.receiver.recv().await
    }
}

/// Async listener that listens for audit messages emitted by the kernel via the
/// netlink socket and forwards them into the a MPSC channel via the `sender`
/// parameter. Used in the constructor of `NetlinkAuditTransport`.
///
/// **Parameters:**
///
/// * `sender`: The MPSC channel to forward the raw audit records to.
async fn netlink_listener_task(sender: mpsc::Sender<RawAuditRecord>) -> Result<()> {
    // Create netlink socket connection
    let (connection, mut handle, mut messages) =
        audit::new_connection().context(("Netlink socket connection failed."))?;

    // Spawn connection task
    tokio::spawn(connection);

    // Enable audit events
    handle
        .enable_events()
        .await
        .context("Failed to enable events.")?;

    println!("Netlink audit transport listening for kernel events");

    // Process events from the Linux kernel audit subsystem
    while let Some((msg, _addr)) = messages.next().await {
        if let NetlinkPayload::InnerMessage(inner) = &msg.payload {
            let data = match inner {
                AuditMessage::Event((_, kvs)) => kvs.to_string(),
                AuditMessage::Other((_, data)) => data.clone(),
                _ => continue,
            };

            let record_id = msg.header.message_type;
            let raw_record = RawAuditRecord::new(record_id, data);

            if sender.send(raw_record).await.is_err() {
                break; // Channel closed
            }
        }
    }
    Ok(())
}
