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

mod correlator;
mod event;

use crate::parser::ParsedAuditRecord;
use std::collections::HashMap;
use std::time::{Instant, SystemTime};

#[derive(Clone)]
pub struct AuditEvent {
    pub timestamp: SystemTime,
    pub serial: u16,
    pub record_count: u16,
    pub records: Vec<ParsedAuditRecord>,
}

/// A struct that serves as a buffer for correlating the audit records within it
/// into audit events. Records are grouped by (timestamp, serial). Each buffer
/// entry's timeout is reset to TIMEOUT whenever a new record is added. When an
/// entry's timeout elapses, it is flushed as an AuditEvent.
pub struct Correlator {
    pub(crate) event_buffer: HashMap<(SystemTime, u16), (Vec<ParsedAuditRecord>, Instant)>,
}
