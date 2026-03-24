//! Implementation of the `Correlator` buffer: push records by (timestamp,
//! serial) and flush expired entries as `AuditEvent`s.

use std::collections::{HashMap, hash_map::Entry};
use std::time::{Duration, Instant, SystemTime};

use crate::core::correlator::{AuditEvent, Correlator};
use crate::core::parser::ParsedAuditRecord;

/// Duration after the last record in a buffer entry before that entry is
/// considered expired.
const TIMEOUT: Duration = Duration::from_secs(3);

/// Key for a buffer entry: (event timestamp, serial).
type Identifier = (SystemTime, u16);

impl Correlator {
    /// Construct an empty correlator buffer.
    pub fn new() -> Self {
        Self {
            event_buffer: HashMap::new(),
        }
    }

    /// Add a record to the buffer. If an entry for this event exists, append
    /// the record and reset the timeout; otherwise create a new buffer
    /// entry.
    ///
    /// **Parameters:**
    ///
    /// * `record`: The parsed audit record to correlate (grouped by its
    ///   identifier).
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

    /// Remove and return all buffer entries whose timeout has elapsed. Call
    /// this periodically (e.g. from a timer task) to flush completed
    /// events.
    pub fn flush_expired(&mut self) -> Vec<AuditEvent> {
        let now = Instant::now();
        // Collect identifiers of entries that have been idle for at least TIMEOUT.
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
                AuditEvent {
                    timestamp: id.0,
                    serial: id.1,
                    record_count: records.len() as u16,
                    records,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_record() -> ParsedAuditRecord {
        let time = SystemTime::now();
        ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::AddGroup,
            timestamp: time,
            serial: 1,
        }
    }

    /// If `grouped` is true, the two records will have the same serial number
    /// and be grouped into the same event.
    fn create_audit_records_for_event(grouped: bool) -> (ParsedAuditRecord, ParsedAuditRecord) {
        let time = SystemTime::now();
        let record = ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::AddGroup,
            timestamp: time,
            serial: 1,
        };
        let record_2 = ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::Add,
            timestamp: time,
            serial: if grouped { 1 } else { 2 },
        };
        (record, record_2)
    }

    #[test]
    /// Ensure that the push function properly adds a new event to the buffer.
    fn push_new_event() {
        let mut correlator = Correlator::new();
        let record = create_record();

        correlator.push(record);

        assert!(correlator.event_buffer.len() == 1);
    }

    #[test]
    /// Check that correlated records are grouped into the same event in the
    /// event buffer.
    fn push_correlated_records() {
        let mut correlator = Correlator::new();
        let (record, record_2) = create_audit_records_for_event(true);

        correlator.push(record.clone());
        correlator.push(record_2.clone());

        assert!(correlator.event_buffer.len() == 1);
        // Check that the two records are stored under the same identifier
        assert!(
            correlator.event_buffer.get(&record.identifier()).unwrap()
                == correlator.event_buffer.get(&record_2.identifier()).unwrap()
        );
    }

    #[test]
    /// Check that uncorrelated records are not grouped into the same event in
    /// the event buffer.
    fn push_uncorrelated_records() {
        let mut correlator = Correlator::new();
        let (record, record_2) = create_audit_records_for_event(false);

        correlator.push(record.clone());
        correlator.push(record_2.clone());

        assert!(correlator.event_buffer.len() == 2);
        // Check that the two records are stored under separate identifiers
        assert!(
            correlator.event_buffer.get(&record.identifier()).unwrap()
                != correlator.event_buffer.get(&record_2.identifier()).unwrap()
        );
    }

    #[test]
    #[ignore] // Doesn't necessarily need to be ignored, but takes up some time
    // Flush the event buffer and check the flushed events
    fn flush_to_event() {
        let mut correlator = Correlator::new();
        let (record, record_2) = create_audit_records_for_event(true);
        correlator.push(record.clone());
        correlator.push(record_2.clone());

        // Sleep for 3.5 seconds to ensure the timeout has elapsed
        std::thread::sleep(std::time::Duration::from_millis(3500));
        let events = correlator.flush_expired();

        println!("{:?}", events);
        assert!(events.len() == 1);
        assert!(events[0].records[0] == record);
        assert!(events[0].records[1] == record_2);
    }

    #[test]
    /// Check that the event buffer is not flushed if the timeout has not
    /// elapsed.
    fn insufficient_time_to_flush_event() {
        let mut correlator = Correlator::new();
        let (record, record_2) = create_audit_records_for_event(true);
        correlator.push(record);
        correlator.push(record_2);

        std::thread::sleep(std::time::Duration::from_millis(300));
        let events = correlator.flush_expired();

        println!("{:?}", events);
        assert!(events.is_empty());
    }
}
