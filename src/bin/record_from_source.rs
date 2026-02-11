use futures::stream::StreamExt;
use netlink_packet_audit::AuditMessage;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::signal;
use auditrs::record::{AuditRecord, RecordType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create timestamped filename
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let filename = format!("audit_capture_{}.bin", timestamp);

    println!("Capturing audit messages to: {}", filename);

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .truncate(true)
        .open(&filename)?;

    let (connection, mut handle, mut messages) =
        audit::new_connection().map_err(|e| format!("Connection failed: {}", e))?;

    tokio::spawn(connection);

    println!("Enabling audit events...");
    handle
        .enable_events()
        .await
        .map_err(|e| format!("Failed to enable events: {}", e))?;

    println!("Listening for audit messages... Press Ctrl+C to stop");

    let mut message_count = 0;

    // Capture phase with signal handling
    tokio::select! {
        _ = signal::ctrl_c() => {
            println!("\nCtrl+C received, stopping capture...");
        }
        _ = async {
            while let Some((msg, _addr)) = messages.next().await {
                // Serialize the netlink message to buffer
                let mut buffer = vec![0u8; msg.buffer_len()];
                msg.serialize(&mut buffer);

                // Write length prefix (4 bytes) + message data
                file.write_all(&(buffer.len() as u32).to_le_bytes())?;
                file.write_all(&buffer)?;
                file.flush()?;

                message_count += 1;
                if message_count % 10 == 0 {
                    println!("Captured {} messages", message_count);
                }
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        } => {}
    }

    println!(
        "Capture stopped. {} messages saved to {}",
        message_count, filename
    );

    // Verification phase - read back and print first few
    println!("\n--- Deserializing first few messages for verification ---");

    // Seek back to beginning of file
    file.seek(SeekFrom::Start(0))?;

    for i in 0..message_count {
        // Read length prefix
        let mut length_buf = [0u8; 4];
        file.read_exact(&mut length_buf)?;
        let length = u32::from_le_bytes(length_buf) as usize;

        // Read message data
        let mut msg_buf = vec![0u8; length];
        file.read_exact(&mut msg_buf)?;

        // Deserialize back to NetlinkMessage
        match netlink_packet_core::NetlinkMessage::<AuditMessage>::deserialize(&msg_buf) {
            Ok(reconstructed_msg) => {
                println!("\nMessage {}: Successfully reconstructed", i + 1);
                println!("Type: {:?}", reconstructed_msg.header.message_type);
                println!("Length: {}", reconstructed_msg.header.length);

                // build a test record
                let record = AuditRecord { record_type: RecordType::from(reconstructed_msg.header.message_type), 
                timestamp: std::time::SystemTime::now(),
                serial: 1,
                data: std::collections::HashMap::<String, String>::new()
                };

                println!("Record object: {:?}", record);
            }
            Err(e) => {
                println!("Message {}: Deserialization failed: {}", i + 1, e);
            }
        }
    }

    println!("\nVerification complete!");
    Ok(())
}
