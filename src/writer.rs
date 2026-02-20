use crate::event::AuditEvent;

pub struct AuditLogWriter {
    output_format: OutputFormat,
    destination: String,
}

enum WriteError {
    Unknown,
}

enum OutputFormat {
    Legacy,
    JSON,
}

impl AuditLogWriter {
    pub fn new() -> Self {
        todo!()
    }

    pub fn write_event(self, event: AuditEvent) -> Result<(), WriteError> {
        // Returns Ok(()) if nothing went wrong.
        match self.output_format {
            OutputFormat::Legacy => self.write_event_legacy(event),
            OutputFormat::JSON => self.write_event_json(event),
        }
    }

    pub fn write_event_legacy(self, event: AuditEvent) -> Result<(), WriteError> {
        todo!()
    }

    pub fn write_event_json(self, event: AuditEvent) -> Result<(), WriteError> {
        todo!()
    }
}
