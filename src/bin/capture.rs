/*
This is a simple binary that captures audit messages and logs them to files in various stages of processing. 
The output settings can be configured in the OutputSettings struct, which controls what gets logged and where.
*/

use audit::new_connection;
use auditrs::parsed_record::ParsedAuditRecord;
use auditrs::raw_record::RawAuditRecord;
use futures::stream::StreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use audit::packet::{AuditMessage};


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
async fn main() -> Result<(), String> {

    let current_time = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();

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
        new_connection().map_err(|e| format!("{e}"))?;

    tokio::spawn(connection);
    handle.enable_events().await.map_err(|e| format!("{e}"))?;

    env_logger::init();
    while let Some((msg, _)) = messages.next().await {
        handle_message(msg, output_settings.clone());
    }
    Ok(())
}

fn handle_message(msg: NetlinkMessage<AuditMessage>, output_settings: OutputSettings) {

    if let Some(path) = output_settings.netlink_message_path {
        std::fs::write(path, format!("{:?}", msg)).unwrap();
        std::fs::write(
            output_settings.conglomerate_path.clone().unwrap(),
            format!("NetlinkMessage: {:?}\n", msg),
        ).unwrap();
    }
    if let Some(path) = output_settings.netlink_payload_path {
        std::fs::write(path, format!("{:?}", msg.payload.clone())).unwrap();
        std::fs::write(
            output_settings.conglomerate_path.clone().unwrap(),
            format!("NetlinkPayload: {:?}\n", msg.payload.clone()),
        ).unwrap();
    }
    if let Some(path) = output_settings.audit_message_path
        && let NetlinkPayload::InnerMessage(audit_msg) = &msg.payload {
            std::fs::write(path, format!("{:?}", audit_msg.clone())).unwrap();
            std::fs::write(
                output_settings.conglomerate_path.clone().unwrap(),
                format!("AuditMessage: {:?}\n", audit_msg.clone()),
            ).unwrap();
        }
    if let Some(path) = output_settings.raw_audit_record_path
        && let &NetlinkPayload::InnerMessage(AuditMessage::Event(ref raw_audit)) = &msg.payload {
            std::fs::write(path, format!("{:?}", raw_audit)).unwrap();
            std::fs::write(
                output_settings.conglomerate_path.clone().unwrap(),
                format!("RawAuditRecord: {:?}\n", raw_audit),
            ).unwrap();
        }
    if let Some(path) = output_settings.parsed_audit_record_path 
        && let NetlinkPayload::InnerMessage(AuditMessage::Event(raw_audit)) = msg.payload {
            // this is stupid. we should make a from impl or tryfrom impl. or maybe combine the type?
            // raw_audit_record is the same as AuditMessage::Event. both are eq. to (u16, String).
            let raw_audit = RawAuditRecord {
                record_id: raw_audit.0,
                data: raw_audit.1,
            };
            match ParsedAuditRecord::try_from(raw_audit) {
                Ok(parsed_record) => {
                    std::fs::write(path, format!("{:?}", parsed_record)).unwrap();
                    std::fs::write(
                        output_settings.conglomerate_path.clone().unwrap(),
                        format!("ParsedAuditRecord: {:?}\n", parsed_record),
                    ).unwrap();
                },
                Err(e) => eprintln!("Failed to parse audit message: {:?}", e),
            }
    }
}