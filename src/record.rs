/*
    Definition of an Audit Record. This corresponds to a single line in an audit log file,
    which may contain multiple fields. Original implementation uses key/value string pairs
    stored in a HashMap, but could be extended to a more strongly typed structure in the
    future.

    Relevant documentation:
    https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv

    Very curious how feasible it is to have a fully typed Record struct, given the wide variety of
    fields that can appear in an audit log line. An incremental approach would be putting everything
    in a HashMap for now, then gradually converting known fields to typed members of the Record struct.
*/

use std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub struct Record {
    fields: HashMap<String, String>, // identical to RecordFields for now.
}

pub struct RecordFields {
    pub fields: HashMap<String, String>,
}

// This is a good starting point for typed records. Just read the 'TYPE' field and kaboom.
pub enum RecordType {
    Syscall,
    Cwd,
    Path,
    Proctitle,
    // ... there are loads more.
}

// TODO: Consider auto-generating types from the field dictionary.
// Could use serde, strum, or similar crates for automatic string-to-typed conversion.
// Alternative: Large match statement to convert string type names to RecordType enum variants.
// Evaluate if the complexity is justified for this use case.

impl Record {
    pub fn new(fields: HashMap<String, String>) -> Self {
        Record { fields }
    }
}

