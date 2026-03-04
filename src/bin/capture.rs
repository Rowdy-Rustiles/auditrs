/*
This is a simple binary that captures audit messages and logs them to files in various stages of processing.
The output settings can be configured in the OutputSettings struct, which controls what gets logged and where.
*/
use anyhow::{Context, Result};
use audit::new_connection;
use audit::packet::AuditMessage;
use futures::stream::StreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use auditrs::netlink::RawAuditRecord;
use auditrs::parser::ParsedAuditRecord;

#[derive(Clone)]
struct OutputSettings {
    netlink_message_path: Option<String>,
    netlink_payload_path: Option<String>,
    audit_message_path: Option<String>,
    raw_audit_record_path: Option<String>,
    parsed_audit_record_path: Option<String>,
    conglomerate_path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let current_time = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();

    // Ensure output directory exists
    fs::create_dir_all("output").context("Failed to create output directory")?;

    // Change this to control what gets logged to a file.
    let output_settings = OutputSettings {
        netlink_message_path: Some(format!("output/netlink_message_{}.log", current_time)),
        netlink_payload_path: Some(format!("output/netlink_payload_{}.log", current_time)),
        audit_message_path: Some(format!("output/audit_message_{}.log", current_time)),
        raw_audit_record_path: Some(format!("output/raw_audit_record_{}.log", current_time)),
        parsed_audit_record_path: Some(format!("output/parsed_audit_record_{}.log", current_time)),
        conglomerate_path: Some(format!("output/conglomerate_{}.log", current_time)),
    };

    let (connection, mut handle, mut messages) =
        new_connection().context("Failed to establish audit socket connection.")?;

    tokio::spawn(connection);
    handle
        .enable_events()
        .await
        .context("Failed to enable audit events")?;

    env_logger::init();
    while let Some((msg, _)) = messages.next().await {
        println!("Received message: {:?}\n", msg);
        if let Err(e) = handle_message(msg, &output_settings) {
            eprintln!("Error handling message: {}", e);
        }
    }
    Ok(())
}

fn handle_message(
    msg: NetlinkMessage<AuditMessage>,
    output_settings: &OutputSettings,
) -> Result<()> {
    // NetlinkMessage
    append_to_file(
        output_settings.netlink_message_path.clone(),
        &format!("{:?}\n", msg),
    )?;
    append_to_file(
        output_settings.conglomerate_path.clone(),
        &format!("NetlinkMessage: {:?}\n", msg),
    )?;

    // NetlinkPayload
    append_to_file(
        output_settings.netlink_payload_path.clone(),
        &format!("{:?}\n", msg.payload),
    )?;
    append_to_file(
        output_settings.conglomerate_path.clone(),
        &format!("NetlinkPayload: {:?}\n", msg.payload),
    )?;

    // AuditMessage
    if let NetlinkPayload::InnerMessage(audit_msg) = &msg.payload {
        append_to_file(
            output_settings.audit_message_path.clone(),
            &format!("{:?}\n", audit_msg),
        )?;
        append_to_file(
            output_settings.conglomerate_path.clone(),
            &format!("AuditMessage: {:?}\n", audit_msg),
        )?;
    }

    // RawAuditRecord
    if let NetlinkPayload::InnerMessage(AuditMessage::Event(raw_audit)) = &msg.payload {
        append_to_file(
            output_settings.raw_audit_record_path.clone(),
            &format!("{:?}\n", raw_audit),
        )?;
        append_to_file(
            output_settings.conglomerate_path.clone(),
            &format!("RawAuditRecord: {:?}\n", raw_audit),
        )?;
    }

    // ParsedAuditRecord
    if let NetlinkPayload::InnerMessage(inner) = &msg.payload {
        // We want to match for both Event and Other enum variants to avoid ignoring potentially useful data.
        let data = match inner {
            AuditMessage::Event((_, kvs)) => kvs.to_string(),
            AuditMessage::Other((_, data)) => data.clone(),
            _ => {
                return Err(anyhow::anyhow!(format!(
                    "Invalid AuditMessage variant: {:?}",
                    inner
                )));
            }
        };

        let record_id = msg.header.message_type;
        let raw_record = RawAuditRecord::new(record_id, data);
        let parsed_record =
            ParsedAuditRecord::try_from(raw_record).context("Failed to parse RawAuditRecord")?;
        append_to_file(
            output_settings.parsed_audit_record_path.clone(),
            &format!("{:?}\n", parsed_record),
        )?;
        append_to_file(
            output_settings.conglomerate_path.clone(),
            &format!("ParsedAuditRecord: {:?}\n", parsed_record),
        )?;
    }

    // Place a delimeter after each message for readability in the conglomerate log
    append_to_file(
        output_settings.conglomerate_path.clone(),
        "-----------------------------\n",
    )?;

    Ok(())
}

// Append content to a file, creating the file if it doesn't exist.
// Takes in an option just to make calling code cleaner - if the path is None, it does nothing.
fn append_to_file(path: Option<String>, content: &str) -> Result<()> {
    if let Some(path) = path {
        ensure_parent_dir(&path)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("Failed to open file {} for appending", path))?;

        file.write(content.as_bytes())
            .with_context(|| format!("Failed to append to {}", path))?;
    }
    Ok(())
}

// Ensure the parent directory of a file exists
fn ensure_parent_dir(file_path: &str) -> Result<()> {
    if let Some(parent) = Path::new(file_path).parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }
    Ok(())
}
