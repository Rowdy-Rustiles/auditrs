use std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub struct Record {
    fields: HashMap<String, String>,
}

pub struct RecordFields {
    pub fields: HashMap<String, String>, // identical to RecordFields for now. this would be a fully type qualified struct in a more complete implementation.
}

pub enum RecordType {
    Syscall,
    Cwd,
    Path,
    Proctitle,
    // ... there are loads more.
}

impl Record {
    pub fn new(fields: HashMap<String, String>) -> Self {
        Record { fields }
    }
}

