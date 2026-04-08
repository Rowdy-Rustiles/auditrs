//! Short-lived netlink sessions to add or delete kernel audit rules.
//!
//! Each call opens a new [`audit::new_connection`], spawns the connection
//! driver, and runs [`audit::Handle::add_rule`] or [`audit::Handle::del_rule`].
//! This is intentionally separate from
//! [`super::netlink::netlink_listener_task`], which owns the long-lived
//! connection for receiving audit events.

use anyhow::{Context, Result};
use audit::packet::RuleMessage;

/// Apply a single [`RuleMessage`] to the kernel (`add_rule` or `del_rule`)
/// using a one-shot netlink session.
pub fn apply_audit_rule_message(rule: RuleMessage, delete: bool) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("failed to create Tokio runtime")?;
    rt.block_on(async move {
        let (connection, mut handle, _messages) =
            audit::new_connection().context("audit netlink new_connection")?;
        tokio::spawn(connection);
        if delete {
            handle
                .del_rule(rule)
                .await
                .map_err(|e| anyhow::anyhow!("audit del_rule: {}", e))
        } else {
            handle
                .add_rule(rule)
                .await
                .map_err(|e| anyhow::anyhow!("audit add_rule: {}", e))
        }
    })
}
