// Interface for getting a message from an audit socket.
// We create this interface so we can simplify use of the socket reader,
// as well as allowing us to implement a mock socket reader for testing.

use crate::raw_record::RawAuditRecord;
use tokio::sync::mpsc;

pub trait AuditTransport {
    fn new() -> Self;
    fn read_message(&self) -> Option<Vec<u8>>;

    /// Consume the transport and return the receiver for wiring into the pipeline.
    fn into_receiver(self) -> mpsc::Receiver<RawAuditRecord>;

    /// Async receive the next raw audit record (for use when holding the transport).
    async fn recv(&mut self) -> Option<RawAuditRecord>;
}
