//! Event-log position carried by a single-scheduler continuation.
//!
//! A continuation names the log's sealed segments and carries only the open
//! tail, never a sealed entry (RFC-0020 CCOMP-33):
//!
//! ```text
//! EventLogWire {
//!   prefix, appended_segment, bytes, events,   // the chain position (offset)
//!   base_events,                               // first sequence covered
//!   segments: [EventLogSegmentRef, ...],       // dense from base_events
//!   tail: [SchedulerEventLogEntry, ...],       // dense to events, <= 8 MiB
//!   last_append_entries,                       // entries of the latest append
//! }
//! ```
//!
//! The latest append's per-append binary segment is recomputed from the
//! entries on restore and must derive the offset's appended segment, which
//! binds the carried entries to the chain position. Restore folds the
//! condition prefix from the segments in order, holding one segment at a
//! time. The prefix itself still retains its complete history until the
//! bounded fold of RFC-0020 section 15.4 replaces it.

use serde::{Deserialize, Serialize};

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EventLogWire {
    pub(super) prefix: ContentHash,
    pub(super) appended_segment: Option<ContentHash>,
    pub(super) bytes: u64,
    pub(super) events: u64,
    pub(super) base_events: u64,
    pub(super) segments: Vec<EventLogSegmentRef>,
    pub(super) tail: Vec<SchedulerEventLogEntry>,
    pub(super) last_append_entries: u64,
}

impl From<&EventLog> for EventLogWire {
    fn from(log: &EventLog) -> Self {
        Self {
            prefix: log.offset.prefix,
            appended_segment: log.offset.appended_segment,
            bytes: log.offset.bytes,
            events: log.offset.events,
            base_events: log.condition_base_events,
            segments: log.sealed.to_vec(),
            tail: log.tail.to_vec(),
            last_append_entries: log.last_append_entries,
        }
    }
}

impl EventLogWire {
    pub(super) fn offset(&self) -> EventLogOffset {
        EventLogOffset {
            prefix: self.prefix,
            appended_segment: self.appended_segment,
            bytes: self.bytes,
            events: self.events,
        }
    }

    /// Checks the position's structure and returns the tail's encoded size.
    ///
    /// Segment contents are authenticated only when a reader decodes them.
    pub(super) fn validate(&self) -> Result<u64, SingleSchedulerCheckpointError> {
        let invalid = SingleSchedulerCheckpointError::EventLog;
        let tail_start = validate_segment_refs(&self.segments, self.base_events).ok_or(invalid)?;
        for (offset, entry) in (0_u64..).zip(&self.tail) {
            if Some(entry.sequence()) != tail_start.checked_add(offset) {
                return Err(invalid);
            }
        }
        let tail_len = u64::try_from(self.tail.len()).map_err(|_| invalid)?;
        if tail_start.checked_add(tail_len) != Some(self.events) {
            return Err(invalid);
        }

        // The log seals before an entry would overflow its tail, so any
        // append leaves a nonempty tail, and an empty tail means no append
        // happened after the base.
        let appended = self.events != self.base_events;
        let latest_append_fits = (1..=self.events - self.base_events)
            .contains(&self.last_append_entries)
            && self.appended_segment.is_some()
            && !self.tail.is_empty();
        let nothing_appended =
            self.segments.is_empty() && self.tail.is_empty() && self.last_append_entries == 0;
        if (appended && !latest_append_fits) || (!appended && !nothing_appended) {
            return Err(invalid);
        }

        let tail_bytes = entry_encodings(&self.tail)
            .map_err(|_| invalid)?
            .into_iter()
            .try_fold(0_u64, u64::checked_add)
            .ok_or(invalid)?;
        if tail_bytes > EVENT_LOG_SEAL_TARGET_BYTES as u64 {
            return Err(invalid);
        }
        Ok(tail_bytes)
    }

    /// Visits every entry in order, reading one sealed segment at a time.
    pub(super) fn try_for_each_entry<E: From<SingleSchedulerCheckpointError>>(
        &self,
        reader: &(impl EventLogSegmentReader + ?Sized),
        mut visit: impl FnMut(SchedulerEventLogEntry) -> Result<(), E>,
    ) -> Result<(), E> {
        for segment in &self.segments {
            for entry in read_sealed_segment(reader, segment)? {
                visit(entry)?;
            }
        }
        for entry in &self.tail {
            visit(entry.clone())?;
        }
        Ok(())
    }
}

fn read_sealed_segment(
    reader: &(impl EventLogSegmentReader + ?Sized),
    segment: &EventLogSegmentRef,
) -> Result<Vec<SchedulerEventLogEntry>, SingleSchedulerCheckpointError> {
    let bytes = reader
        .read_event_log_segment(segment)
        .map_err(|_| SingleSchedulerCheckpointError::EventLog)?;
    segment
        .decode(&bytes)
        .map_err(|_| SingleSchedulerCheckpointError::EventLog)
}

/// Restores `log` to the position `wire` carries.
///
/// The sealed segments are read from `log`'s own segment store, which the
/// caller populates before restore. The latest append is authenticated
/// against the offset and its per-append segment is stored again, so the
/// destination store holds every object the restored offset names.
pub(super) fn restore_event_log(
    log: &mut EventLog,
    wire: &EventLogWire,
) -> Result<(), SingleSchedulerCheckpointError> {
    let tail_bytes = wire.validate()?;
    let offset = wire.offset();
    let latest_append_start = wire.events - wire.last_append_entries;

    let mut condition_prefix =
        ConditionEventLogPrefix::genesis().with_base_sequence(wire.base_events);
    let mut batcher = ConditionBatcher::default();
    let mut latest_append = Vec::new();
    let mut fold = |entry: SchedulerEventLogEntry| {
        if entry.sequence() >= latest_append_start {
            latest_append.push(entry.clone());
        }
        match batcher.push(entry) {
            Some(batch) => condition_prefix
                .append_scheduler_entries(batch)
                .map_err(|_| SingleSchedulerCheckpointError::EventLog),
            None => Ok(()),
        }
    };
    wire.try_for_each_entry(log.segment_store.store.as_ref(), &mut fold)?;
    let remainder = batcher.finish();
    if !remainder.is_empty() {
        condition_prefix
            .append_scheduler_entries(remainder)
            .map_err(|_| SingleSchedulerCheckpointError::EventLog)?;
    }

    if wire.last_append_entries != 0 {
        let appended = scheduler_event_log_segment_bytes(wire.prefix, &latest_append);
        if Some(ContentHash::from_bytes(&appended)) != wire.appended_segment {
            return Err(SingleSchedulerCheckpointError::EventLog);
        }
        log.segment_store
            .put_segment(&appended)
            .map_err(|_| SingleSchedulerCheckpointError::EventLog)?;
    }

    log.prefix = scheduler_event_log_prefix_for_resume(offset);
    log.sealed = crate::History::from(wire.segments.clone());
    log.tail = crate::History::from(wire.tail.clone());
    log.tail_bytes = tail_bytes;
    log.last_append_entries = wire.last_append_entries;
    log.offset = offset;
    log.bytes = offset.bytes;
    log.events = offset.events;
    log.condition_base_events = wire.base_events;
    log.condition_prefix = condition_prefix.with_event_log_offset(offset);
    Ok(())
}

/// Pull reader over a continuation's event-log entries.
///
/// Returned by [`SingleSchedulerCheckpoint::event_log_entries`]. The reader
/// decodes one sealed segment when its first entry is requested and
/// authenticates it against its reference first, then yields the open tail.
/// After yielding an error it yields nothing more.
pub struct CheckpointEventLogEntries<'a, R: ?Sized> {
    reader: &'a R,
    segments: std::slice::Iter<'a, EventLogSegmentRef>,
    current: std::vec::IntoIter<SchedulerEventLogEntry>,
    tail: std::slice::Iter<'a, SchedulerEventLogEntry>,
    failed: bool,
}

impl<'a, R: EventLogSegmentReader + ?Sized> CheckpointEventLogEntries<'a, R> {
    pub(super) fn new(wire: &'a EventLogWire, reader: &'a R) -> Self {
        Self {
            reader,
            segments: wire.segments.iter(),
            current: Vec::new().into_iter(),
            tail: wire.tail.iter(),
            failed: false,
        }
    }
}

impl<R: EventLogSegmentReader + ?Sized> Iterator for CheckpointEventLogEntries<'_, R> {
    type Item = Result<SchedulerEventLogEntry, SingleSchedulerCheckpointError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        loop {
            if let Some(entry) = self.current.next() {
                return Some(Ok(entry));
            }
            let Some(segment) = self.segments.next() else {
                return self.tail.next().cloned().map(Ok);
            };
            match read_sealed_segment(self.reader, segment) {
                Ok(entries) => self.current = entries.into_iter(),
                Err(error) => {
                    self.failed = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

impl<R: ?Sized> fmt::Debug for CheckpointEventLogEntries<'_, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointEventLogEntries")
            .field("remaining_segments", &self.segments.len())
            .field("remaining_tail", &self.tail.len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "event_log_continuation_tests.rs"]
mod tests;
