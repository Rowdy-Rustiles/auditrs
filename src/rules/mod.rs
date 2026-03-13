pub mod filters;
pub mod watches;

pub use filters::*;
use serde::Deserialize;
pub use watches::*;

/// Audit rules are collections of filters and watches that are applied to
/// audit events before they can be written to the primary log.
#[derive(Debug, Clone, Deserialize)]
pub struct Rules {
    /// The filters for the auditrs daemon.
    pub(crate) filters: Filters,
    /// The watches for the auditrs daemon.
    pub(crate) watches: Watches,
}
