/* Combine multiple ParsedAuditRecords into a singular AuditEvent

  https://man7.org/linux/man-pages/man5/auditd.conf.5.html
  ^ Refer to Notes section:

  Auditd events are made up of one or more records. The auditd
      system cannot guarantee that the set of records that make up an
      event will occur atomically, that is the stream will have
      interleaved records of different events, IE

             event0_record0
             event1_record0
             event2_record0
             event1_record3
             event2_record1
             event1_record4
             event3_record0

      The auditd system does not guarantee that the records that make up
      an event will appear in order. Thus, when processing event
      streams, we need to maintain a list of events with their own list
      of records hence List of List (LOL) event processing.

      When processing an event stream we define the end of an event via

             record type = AUDIT_EOE (audit end of event type record),
             or
             record type = AUDIT_PROCTITLE (we note the AUDIT_PROCTITLE
             is always the last record), or
             record type = AUDIT_KERNEL (kernel events are one record
             events), or
             record type < AUDIT_FIRST_EVENT (only single record events
             appear before this type), or
             record type >= AUDIT_FIRST_ANOM_MSG (only single record
             events appear after this type), or
             record type >= AUDIT_MAC_UNLBL_ALLOW && record type <=
             AUDIT_MAC_CALIPSO_DEL (these are also one record events),
             or
             for the stream being processed, the time of the event is
             over end_of_event_timeout seconds old.
*/

use crate::parsed_record::ParsedAuditRecord;
use std::{
    collections::hash_map::Entry,
    collections::HashMap,
    time::{Duration, Instant, SystemTime},
    fmt
};

const TIMEOUT: Duration = Duration::from_secs(3);

type Identifier = (SystemTime, u16);

#[derive(Clone)]
pub struct AuditEvent {
    pub timestamp: SystemTime,
    pub serial: u16,
    pub record_count: u16,
    pub records: Vec<ParsedAuditRecord>,
}

/// A struct that serves as a buffer for correlating the audit records within it into
/// audit events. Records are grouped by (timestamp, serial). Each buffer entry's
/// timeout is reset to TIMEOUT whenever a new record is added. When an entry's
/// timeout elapses, it is flushed as an AuditEvent.
pub struct Correlator {
    event_buffer: HashMap<Identifier, (Vec<ParsedAuditRecord>, Instant)>,
}

impl Correlator {
    pub fn new() -> Self {
        Self {
            event_buffer: HashMap::new(),
        }
    }

    /// Add a record to the buffer. If an entry for this event exists, append the
    /// record and reset the timeout. Otherwise create a new buffer entry.
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
    /// Call this periodically (e.g. from a timer task) to flush completed events.
    pub fn flush_expired(&mut self) -> Vec<AuditEvent> {
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
            .map(|(id, records)| AuditEvent {
                timestamp: id.0,
                serial: id.1,
                record_count: records.len() as u16,
                records,
            })
            .collect()
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = String::new();
        output.push_str(&format!("{:?} Record Count: {} records: {{\n", self.timestamp, self.record_count));
        for record in self.records.iter() {
            output.push_str(&format!("\tRecord: {:?}\n", record));
        }
        output.push_str("}\n");
        write!(f, "{}", output)
    }
}