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
    fields: HashMap<String, String>, // identical to RecordFields for now. this would be a fully type qualified struct in a more complete implementation.
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

// Wonder if there's a way to auto-generate these from the field dictionary?
// Also curious if there's a way to autoconvert the string values into typed members of the struct. I think I've seen crates like that.
//   The alternative is to have basically a huge match statement like:
//      match type_name {
//          "SYSCALL" => RecordType::Syscall,
//          "CWD" => RecordType::Cwd,
//          ...
//          _ => panic!("Unknown record type"),
//      }

// Might be more complexity than it's worth.

impl Record {
    pub fn new(fields: HashMap<String, String>) -> Self {
        Record { fields }
    }
}

