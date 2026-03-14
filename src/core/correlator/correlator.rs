use std::collections::{HashMap, hash_map::Entry};
use std::time::{Duration, Instant, SystemTime};

use crate::core::correlator::Correlator;
use crate::core::parser::ParsedAuditRecord;

const TIMEOUT: Duration = Duration::from_secs(3);
type Identifier = (SystemTime, u16);

impl Correlator {
    pub fn new() -> Self {
        Self {
            event_buffer: HashMap::new(),
        }
    }

    /// Add a record to the buffer. If an entry for this event exists, append
    /// the record and reset the timeout. Otherwise create a new buffer
    /// entry.
    pub fn push(&mut self, record: ParsedAuditRecord) {
        let id = record.identifier();
        let now = Instant::now();

        match self.event_buffer.entry(id) {
            Entry::Occupied(mut o) => {
                let (records, last_activity) = o.get_mut();
                records.push(record);
                *last_activity = now;
            }
            Entry::Vacant(v) => {
                v.insert((vec![record], now));
            }
        }
    }

    /// Remove and return all buffer entries whose timeout has elapsed.
    /// Call this periodically (e.g. from a timer task) to flush completed
    /// events.
    pub fn flush_expired(&mut self) -> Vec<super::AuditEvent> {
        let now = Instant::now();
        let expired: Vec<Identifier> = self
            .event_buffer
            .iter()
            .filter(|(_, (_, last_activity))| now.duration_since(*last_activity) >= TIMEOUT)
            .map(|(id, _)| *id)
            .collect();

        expired
            .into_iter()
            .filter_map(|id| {
                self.event_buffer
                    .remove(&id)
                    .map(|(records, _)| (id, records))
            })
            .map(|(id, records)| {
                super::AuditEvent {
                    timestamp: id.0,
                    serial: id.1,
                    record_count: records.len() as u16,
                    records,
                }
            })
            .collect()
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}
