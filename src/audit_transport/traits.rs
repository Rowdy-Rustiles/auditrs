// Interface for getting a message from an audit socket.
// We create this interface so we can simplify use of the socket reader,
// as well as allowing us to implement a mock socket reader for testing.

pub trait AuditTransport {
    fn new() -> Self;
    fn read_message(&self) -> Option<Vec<u8>>;
}
