use serde::Deserialize;

mod filters;

pub use filters::{
    add_filter_interactive, dump_filters, get_filters, import_filters, load_filters,
    remove_filter_interactive, update_filter_interactive,
};

/// Filters are broad, record-type-based rules that specify which audit record
/// types are written to the primary log based on a user-defined action. These
/// are coarse-grained knobs for controlling the primary log's content.
#[derive(Debug, Deserialize)]
pub struct Filters(pub(crate) Vec<AuditFilter>);

/// The internal auditrs representation of a single filter, which is a record
/// type coupled with the action to be taken on it.
#[derive(Debug, Deserialize)]
pub struct AuditFilter {
    pub record_type: String,
    pub action: String,
}
