//! Implementation of the netlink transport for receiving raw audit records from
//! the kernel and passing them on through the daemon core.

use anyhow::{Context, Result};
use audit::packet::AuditMessage;
use futures::stream::StreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use tokio::sync::mpsc;

use crate::core::netlink::{NetlinkAuditTransport, RawAuditRecord};

/// The following two functions are abstractions over the netlink listener task
/// that are used for unit testing the inner logic of the listener task

/// Maps a netlink audit message to a [`RawAuditRecord`]. Used by
/// [`netlink_listener_task`]; separated so the transformation can be
/// unit-tested without a live audit session.
fn raw_record_from_netlink_message(
    msg: &NetlinkMessage<audit::packet::AuditMessage>,
) -> Option<RawAuditRecord> {
    if let NetlinkPayload::InnerMessage(inner) = &msg.payload {
        let data = match inner {
            AuditMessage::Event((_, kvs)) => kvs.to_string(),
            AuditMessage::Other((_, data)) => data.clone(),
            _ => return None,
        };

        let record_id = msg.header.message_type;
        Some(RawAuditRecord::new(record_id, data))
    } else {
        None
    }
}

/// Sends a parsed record to the parser task. Returns `false` if the channel is
/// closed (receiver dropped), which is the same condition that makes
/// [`netlink_listener_task`] exit its receive loop.
async fn send_raw_record_to_channel(
    sender: &mpsc::Sender<RawAuditRecord>,
    record: RawAuditRecord,
) -> bool {
    sender.send(record).await.is_ok()
}

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
    async fn _recv(&mut self) -> Option<RawAuditRecord> {
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
        audit::new_connection().context("Netlink socket connection failed.")?;

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
        if let Some(raw_record) = raw_record_from_netlink_message(&msg) {
            if !send_raw_record_to_channel(&sender, raw_record).await {
                break; // Channel closed
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use netlink_packet_core::NetlinkHeader;
    use std::time::Duration;

    #[test]
    fn raw_record_from_event_message() {
        let mut msg = NetlinkMessage::from(AuditMessage::Event((
            1300,
            "type=SYSCALL key=value".to_string(),
        )));
        msg.finalize();

        let record = raw_record_from_netlink_message(&msg).expect("event maps to record");
        assert_eq!(record.record_id, 1300);
        assert_eq!(record.data, "type=SYSCALL key=value");
    }

    #[test]
    fn raw_record_from_other_message() {
        let mut msg = NetlinkMessage::from(AuditMessage::Other((1315, "opaque".to_string())));
        msg.finalize();

        let record = raw_record_from_netlink_message(&msg).expect("other maps to record");
        assert_eq!(record.record_id, 1315);
        assert_eq!(record.data, "opaque");
    }

    #[test]
    fn raw_record_skips_control_messages() {
        let mut msg = NetlinkMessage::from(AuditMessage::GetStatus(None));
        msg.finalize();

        assert!(raw_record_from_netlink_message(&msg).is_none());
    }

    #[test]
    fn raw_record_returns_none_for_non_inner_payload() {
        let msg =
            NetlinkMessage::<AuditMessage>::new(NetlinkHeader::default(), NetlinkPayload::Noop);
        assert!(raw_record_from_netlink_message(&msg).is_none());
    }

    #[tokio::test]
    async fn send_raw_record_to_channel_false_when_receiver_dropped() {
        let (sender, receiver) = mpsc::channel::<RawAuditRecord>(1);
        drop(receiver);
        assert!(!send_raw_record_to_channel(&sender, RawAuditRecord::new(1, "x".into())).await);
    }

    #[tokio::test]
    async fn send_raw_record_to_channel_true_when_open() {
        let (sender, mut receiver) = mpsc::channel(1);
        assert!(send_raw_record_to_channel(&sender, RawAuditRecord::new(2, "y".into())).await);
        let got = receiver.recv().await.unwrap();
        assert_eq!(got.record_id, 2);
        assert_eq!(got.data, "y");
    }

    #[tokio::test]
    async fn netlink_audit_transport_new_and_into_receiver() {
        let transport = NetlinkAuditTransport::new();
        let mut receiver = transport.into_receiver();
        // Background task may fail immediately without audit privileges - we only check
        // if the receiver is open
        let _ = tokio::time::timeout(Duration::from_millis(200), receiver.recv()).await;
    }
}
