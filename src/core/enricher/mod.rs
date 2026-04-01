//! Enricher module for auditrs, responsible for augmenting parsed audit records
//! with derived fields (decoded proctitle, syscall names, file type and
//! permissions).

mod enricher;

pub use enricher::enrich_event;
