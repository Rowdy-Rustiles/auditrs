//! Implementation of the `Correlator` buffer: push records by (timestamp,
//! serial) and flush expired entries as `AuditEvent`s.

use std::collections::{HashMap, hash_map::Entry};
use std::time::{Duration, Instant, SystemTime};

use crate::core::correlator::{Correlator, AuditEvent};
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

impl Default for Correlator {
    /// Return an empty correlator (same as `Correlator::new()`).
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn push_new_event() {
        let mut correlator = Correlator::new();
        let time = SystemTime::now();
        let record = ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::AddGroup,
            timestamp: time,
            serial: 1
        };

        correlator.push(record);

        assert!(correlator.event_buffer.len() == 1);
    }

    #[test]
    fn push_correlated_records() {
        let mut correlator = Correlator::new();
        let time = SystemTime::now();
        let record = ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::AddGroup,
            timestamp: time,
            serial: 1
        };

        let record_2 = ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::Add,
            timestamp: time,
            serial: 1
        };

        correlator.push(record);
        correlator.push(record_2);

        assert!(correlator.event_buffer.len() == 1);
    }

     #[test]
    fn push_uncorrelated_records() {
        let mut correlator = Correlator::new();
        let time = SystemTime::now();
        let record = ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::AddGroup,
            timestamp: time,
            serial: 1
        };

        let record_2 = ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::Add,
            timestamp: time,
            // Note the differing serial number, this will lead to a different identifier from the previous correlated records test
            serial: 2     
        };

        correlator.push(record);
        correlator.push(record_2);

        assert!(correlator.event_buffer.len() == 2);
    }

    #[test]
    fn test_flush_to_event() {
        let mut correlator = Correlator::new();
        let time = SystemTime::now();
        let record = ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::AddGroup,
            timestamp: time,
            serial: 1
        };

        let record_2 = ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::Add,
            timestamp: time,
            serial: 1
        };

        correlator.push(record);
        correlator.push(record_2);

        //
        std::thread::sleep(std::time::Duration::from_millis(3500));
        let events = correlator.flush_expired();

        println!("{:?}", events);
        assert!(events.len() == 1);
    }

        #[test]
    fn test_insufficient_time_to_flush_event() {
        let mut correlator = Correlator::new();
        let time = SystemTime::now();
        let record = ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::AddGroup,
            timestamp: time,
            serial: 1
        };

        let record_2 = ParsedAuditRecord {
            fields: HashMap::<String, String>::new(),
            record_type: crate::core::parser::RecordType::Add,
            timestamp: time,
            serial: 1
        };

        correlator.push(record);
        correlator.push(record_2);

        //
        std::thread::sleep(std::time::Duration::from_millis(300));
        let events = correlator.flush_expired();

        println!("{:?}", events);
        assert!(events.len() == 0);
    }
}