//! Sealed-segment storage for the session's event-log histories.
//!
//! The session keeps two views of the scheduler event log: the subscriber hub
//! ([`SessionEventLog`]) and the debug history the actor uses for breakpoints
//! and time travel. Neither holds the run in memory. Each seals its entries
//! with the scheduler's own rule (RFC-0020 section 15.2, CCOMP-33) into
//! decodable segments stored by BLAKE3 identity, and keeps only the entries
//! since the last seal resident:
//!
//! ```text
//! index:  [ref 0, counts before] [ref 1, counts before] ...   // one row per segment
//! tail:   entries since the last seal                         // resident
//! ```
//!
//! Seal points depend only on the entries, so a session log that starts at
//! the scheduler's genesis seals byte-identical segments into the same store
//! as the scheduler and adds no new objects. The index keeps cumulative class
//! counts so a summary needs at most one segment decode. Readers authenticate
//! every segment against its reference and hold one segment at a time.

use std::sync::Arc;

use crucible_engine::attempt_log::{MAX_ATTEMPT_LOG_ENTRY_BYTES, encode_segment, encoded_entry_len};
use crucible_engine::{EVENT_LOG_SEAL_TARGET_BYTES, EventLogSegmentRef};

use super::*;

/// Failure to store or read a sealed session event-log segment.
///
/// The session fails closed: an entry that cannot be sealed or a segment that
/// cannot be read back stops the operation instead of skipping history.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("session event-log segment {operation} failed: {reason}")]
pub struct SessionEventLogStoreError {
    operation: &'static str,
    reason: String,
}

impl SessionEventLogStoreError {
    fn new(operation: &'static str, reason: impl Into<String>) -> Self {
        Self {
            operation,
            reason: reason.into(),
        }
    }
}

/// Entry counts by class over a run of dense entries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ClassCounts {
    pub(super) causal: u64,
    pub(super) observational: u64,
}

impl ClassCounts {
    fn observe(&mut self, entry: &SchedulerEventLogEntry) {
        match entry.class() {
            SchedulerEventLogClass::Causal => self.causal = self.causal.saturating_add(1),
            SchedulerEventLogClass::Observational => {
                self.observational = self.observational.saturating_add(1);
            }
        }
    }

    fn over<'a>(entries: impl IntoIterator<Item = &'a SchedulerEventLogEntry>) -> Self {
        let mut counts = Self::default();
        for entry in entries {
            counts.observe(entry);
        }
        counts
    }

    fn plus(self, other: Self) -> Self {
        Self {
            causal: self.causal.saturating_add(other.causal),
            observational: self.observational.saturating_add(other.observational),
        }
    }

    pub(super) const fn total(self) -> u64 {
        self.causal.saturating_add(self.observational)
    }
}

/// One sealed segment with cumulative class counts around it.
#[derive(Clone, Copy, Debug)]
struct SealedSegment {
    reference: EventLogSegmentRef,
    // Counts of every retained entry before this segment.
    counts_before: ClassCounts,
    // Counts of every retained entry through this segment's last entry.
    counts_after: ClassCounts,
}

impl SealedSegment {
    fn end(&self) -> u64 {
        self.reference
            .first_sequence
            .saturating_add(self.reference.entry_count)
    }
}

/// Dense entries read from one segment or from the resident tail.
#[derive(Clone, Debug)]
pub(super) struct LogChunk {
    /// Sequence of the first entry in `entries`.
    pub(super) first_sequence: u64,
    /// Entries in sequence order.
    pub(super) entries: Arc<Vec<SchedulerEventLogEntry>>,
}

impl LogChunk {
    /// Returns the sequence after this chunk's last entry.
    pub(super) fn end(&self) -> u64 {
        self.first_sequence
            .saturating_add(usize_to_u64(self.entries.len()))
    }

    /// Returns the entry at `sequence`, when this chunk holds it.
    pub(super) fn get(&self, sequence: u64) -> Option<&SchedulerEventLogEntry> {
        let offset = sequence.checked_sub(self.first_sequence)?;
        self.entries.get(usize::try_from(offset).ok()?)
    }
}

/// Dense event-log entries sealed into stored segments plus a resident tail.
pub(super) struct SegmentedEntryLog {
    store: Arc<dyn DagStore>,
    // Sequence of the first retained entry; `None` while the log is empty.
    base: Option<u64>,
    sealed: Vec<SealedSegment>,
    tail: Vec<SchedulerEventLogEntry>,
    tail_bytes: u64,
    totals: ClassCounts,
    // Encoded tail size that triggers a seal; the scheduler's target outside
    // tests, so equal entries seal into equal segments.
    seal_target: u64,
}

impl fmt::Debug for SegmentedEntryLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SegmentedEntryLog")
            .field("base", &self.base)
            .field("sealed", &self.sealed.len())
            .field("tail", &self.tail.len())
            .field("tail_bytes", &self.tail_bytes)
            .finish_non_exhaustive()
    }
}

impl SegmentedEntryLog {
    /// Builds an empty log that seals into `store`.
    pub(super) fn new(store: Arc<dyn DagStore>) -> Self {
        Self {
            store,
            base: None,
            sealed: Vec::new(),
            tail: Vec::new(),
            tail_bytes: 0,
            totals: ClassCounts::default(),
            seal_target: usize_to_u64(EVENT_LOG_SEAL_TARGET_BYTES),
        }
    }

    /// Builds an empty log with a smaller seal target, so tests can cross
    /// segment boundaries with few entries.
    #[cfg(test)]
    pub(super) fn with_seal_target(store: Arc<dyn DagStore>, seal_target: u64) -> Self {
        Self {
            seal_target,
            ..Self::new(store)
        }
    }

    /// Returns the number of retained entries.
    pub(super) const fn len(&self) -> u64 {
        self.totals.total()
    }

    /// Returns whether no entry is retained.
    pub(super) const fn is_empty(&self) -> bool {
        self.base.is_none()
    }

    /// Returns the sequence of the first retained entry, when any.
    pub(super) const fn base(&self) -> Option<u64> {
        self.base
    }

    /// Returns the sequence after the last entry, or zero when empty.
    pub(super) fn end(&self) -> u64 {
        self.base
            .map_or(0, |base| base.saturating_add(self.totals.total()))
    }

    /// Returns the last retained entry's sequence, when any.
    pub(super) fn last_sequence(&self) -> Option<u64> {
        self.end().checked_sub(1).filter(|_| self.base.is_some())
    }

    /// Appends dense entries, sealing the tail before it would exceed the
    /// shared seal target.
    ///
    /// The first entry of an empty log fixes its base sequence.
    pub(super) fn append(
        &mut self,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<(), SessionEventLogStoreError> {
        for entry in entries {
            if let Some(base) = self.base
                && entry.sequence() != base.saturating_add(self.totals.total())
            {
                return Err(SessionEventLogStoreError::new(
                    "append",
                    format!(
                        "entry {} is not dense after sequence {}",
                        entry.sequence(),
                        self.end()
                    ),
                ));
            }
            let bytes = encoded_entry_len(entry)
                .map_err(|error| SessionEventLogStoreError::new("append", error.to_string()))?;
            if bytes > MAX_ATTEMPT_LOG_ENTRY_BYTES {
                return Err(SessionEventLogStoreError::new(
                    "append",
                    format!(
                        "entry {} encodes to {bytes} bytes, above the \
                         {MAX_ATTEMPT_LOG_ENTRY_BYTES}-byte entry bound",
                        entry.sequence()
                    ),
                ));
            }
            let bytes = usize_to_u64(bytes);
            // The scheduler's rule: seal a nonempty tail before an entry
            // would carry it past the target, and for no other reason.
            if !self.tail.is_empty() && self.tail_bytes.saturating_add(bytes) > self.seal_target {
                self.seal_tail()?;
            }

            self.base.get_or_insert(entry.sequence());
            self.tail.push(entry.clone());
            self.tail_bytes = self.tail_bytes.saturating_add(bytes);
            self.totals.observe(entry);
        }
        Ok(())
    }

    /// Drops every entry at or after sequence `len`.
    ///
    /// A cut inside a sealed segment decodes that one segment and keeps its
    /// leading entries as the new resident tail.
    pub(super) fn truncate(&mut self, len: u64) -> Result<(), SessionEventLogStoreError> {
        let Some(base) = self.base else {
            return Ok(());
        };
        if len >= self.end() {
            return Ok(());
        }
        if len <= base {
            self.base = None;
            self.sealed.clear();
            self.tail.clear();
            self.tail_bytes = 0;
            self.totals = ClassCounts::default();
            return Ok(());
        }

        let tail_first = self.tail_first_sequence();
        if len >= tail_first {
            let keep = usize::try_from(len - tail_first).unwrap_or(usize::MAX);
            self.tail.truncate(keep);
        } else {
            let index = self.sealed.partition_point(|segment| segment.end() <= len);
            let Some(segment) = self.sealed.get(index).copied() else {
                return Err(SessionEventLogStoreError::new(
                    "truncate",
                    format!("no sealed segment covers sequence {len}"),
                ));
            };
            let mut entries = self.read_segment(&segment.reference)?;
            let keep =
                usize::try_from(len - segment.reference.first_sequence).unwrap_or(usize::MAX);
            entries.truncate(keep);
            self.sealed.truncate(index);
            self.tail = entries;
        }
        self.recount_tail()
    }

    /// Returns class counts over every entry before sequence `through`, and
    /// the last such entry's sequence.
    pub(super) fn counts_through(
        &self,
        through: u64,
    ) -> Result<(ClassCounts, Option<u64>), SessionEventLogStoreError> {
        let Some(base) = self.base else {
            return Ok((ClassCounts::default(), None));
        };
        if through >= self.end() {
            return Ok((self.totals, self.last_sequence()));
        }
        if through <= base {
            return Ok((ClassCounts::default(), None));
        }

        let tail_first = self.tail_first_sequence();
        let counts = if through >= tail_first {
            let keep = usize::try_from(through - tail_first).unwrap_or(usize::MAX);
            self.counts_before_tail()
                .plus(ClassCounts::over(self.tail.iter().take(keep)))
        } else {
            let index = self
                .sealed
                .partition_point(|segment| segment.end() <= through);
            let segment = self.sealed.get(index).copied().ok_or_else(|| {
                SessionEventLogStoreError::new(
                    "count",
                    format!("no sealed segment covers sequence {through}"),
                )
            })?;
            let entries = self.read_segment(&segment.reference)?;
            let keep =
                usize::try_from(through - segment.reference.first_sequence).unwrap_or(usize::MAX);
            segment
                .counts_before
                .plus(ClassCounts::over(entries.iter().take(keep)))
        };
        Ok((counts, Some(through - 1)))
    }

    /// Returns entries starting at sequence `from`.
    ///
    /// Inside the resident tail at most `limit` entries are copied. Inside a
    /// sealed segment the whole decoded segment from its first entry is
    /// returned, so a reader can cache it while it walks the segment.
    /// Returns `None` when `from` is at or after the end.
    pub(super) fn chunk_from(
        &self,
        from: u64,
        limit: usize,
    ) -> Result<Option<LogChunk>, SessionEventLogStoreError> {
        let Some(base) = self.base else {
            return Ok(None);
        };
        let from = from.max(base);
        if from >= self.end() {
            return Ok(None);
        }

        let tail_first = self.tail_first_sequence();
        if from >= tail_first {
            let skip = usize::try_from(from - tail_first).unwrap_or(usize::MAX);
            let entries = self
                .tail
                .iter()
                .skip(skip)
                .take(limit)
                .cloned()
                .collect::<Vec<_>>();
            return Ok(Some(LogChunk {
                first_sequence: from,
                entries: Arc::new(entries),
            }));
        }
        let index = self.sealed.partition_point(|segment| segment.end() <= from);
        let segment = self.sealed.get(index).copied().ok_or_else(|| {
            SessionEventLogStoreError::new("read", format!("no sealed segment covers {from}"))
        })?;
        Ok(Some(LogChunk {
            first_sequence: segment.reference.first_sequence,
            entries: Arc::new(self.read_segment(&segment.reference)?),
        }))
    }

    /// Collects every entry before sequence `through`, one segment at a time.
    ///
    /// Only operator-initiated debugger commands, whose engine API takes a
    /// complete slice, and test inspection use this.
    pub(super) fn collect_through(
        &self,
        through: u64,
    ) -> Result<Vec<SchedulerEventLogEntry>, SessionEventLogStoreError> {
        let mut entries = Vec::new();
        for segment in &self.sealed {
            if segment.reference.first_sequence >= through {
                return Ok(entries);
            }
            let decoded = self.read_segment(&segment.reference)?;
            entries.extend(
                decoded
                    .into_iter()
                    .take_while(|entry| entry.sequence() < through),
            );
        }
        entries.extend(
            self.tail
                .iter()
                .take_while(|entry| entry.sequence() < through)
                .cloned(),
        );
        Ok(entries)
    }

    fn tail_first_sequence(&self) -> u64 {
        self.sealed
            .last()
            .map_or_else(|| self.base.unwrap_or_default(), SealedSegment::end)
    }

    // Counts of every entry before the resident tail.
    fn counts_before_tail(&self) -> ClassCounts {
        self.sealed
            .last()
            .map_or_else(ClassCounts::default, |last| last.counts_after)
    }

    fn seal_tail(&mut self) -> Result<(), SessionEventLogStoreError> {
        let Some(first) = self.tail.first() else {
            return Ok(());
        };
        let first_sequence = first.sequence();
        let bytes = encode_segment(first_sequence, &self.tail)
            .map_err(|error| SessionEventLogStoreError::new("seal", error.to_string()))?;
        let expected = ContentHash::from_bytes(&bytes);
        let stored = self
            .store
            .put(&bytes)
            .map_err(|error| SessionEventLogStoreError::new("seal", error.to_string()))?;
        if stored != expected {
            return Err(SessionEventLogStoreError::new(
                "seal",
                format!(
                    "store returned {}, expected {}",
                    stored.to_hex(),
                    expected.to_hex()
                ),
            ));
        }

        let counts_before = self.counts_before_tail();
        self.sealed.push(SealedSegment {
            reference: EventLogSegmentRef {
                object: stored,
                first_sequence,
                entry_count: usize_to_u64(self.tail.len()),
                encoded_bytes: usize_to_u64(bytes.len()),
            },
            counts_before,
            counts_after: counts_before.plus(ClassCounts::over(&self.tail)),
        });
        self.tail.clear();
        self.tail_bytes = 0;
        Ok(())
    }

    // Rederives the tail's byte charge and the totals after a truncation.
    fn recount_tail(&mut self) -> Result<(), SessionEventLogStoreError> {
        let mut tail_bytes = 0_u64;
        for entry in &self.tail {
            let bytes = encoded_entry_len(entry)
                .map_err(|error| SessionEventLogStoreError::new("truncate", error.to_string()))?;
            tail_bytes = tail_bytes.saturating_add(usize_to_u64(bytes));
        }
        self.tail_bytes = tail_bytes;
        self.totals = self
            .counts_before_tail()
            .plus(ClassCounts::over(&self.tail));
        Ok(())
    }

    fn read_segment(
        &self,
        reference: &EventLogSegmentRef,
    ) -> Result<Vec<SchedulerEventLogEntry>, SessionEventLogStoreError> {
        let bytes = self
            .store
            .get(&reference.object)
            .map_err(|error| SessionEventLogStoreError::new("read", error.to_string()))?;
        reference
            .decode(&bytes)
            .map_err(|error| SessionEventLogStoreError::new("read", error.to_string()))
    }
}

#[cfg(test)]
#[path = "segmented_log_tests.rs"]
mod tests;
