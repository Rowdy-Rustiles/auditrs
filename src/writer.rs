struct Writer {
    output_format: OutputFormat,
    destination: FilePath,
}

enum WriteError {
    Unknown,
}

enum OutputFormat {
    Legacy,
    JSON,
}

impl Writer {
    pub fn write_event(event: AuditEvent) -> Result<_, WriteError> {
        todo!()
    }
}