//! Segmented attempt event log: sealed, chained segments plus an open tail.
//!
//! An attempt's scheduler event log grows with every quantum, so the executor
//! never holds it whole. Entries accumulate in an open tail; before the tail's
//! encoding would exceed [`ATTEMPT_LOG_SEGMENT_TARGET_BYTES`], or when the
//! caller seals at a checkpoint or the attempt stop, the tail is encoded as one
//! segment, written to an [`AttemptLogSegmentStore`], and dropped from memory.
//! Only a small [`AttemptLogSegmentRef`] per sealed segment stays resident.
//!
//! The segment, chain, and manifest formats live in [`crucible_engine::attempt_log`],
//! so the engine can read a log its failure evidence references; this module
//! owns the running writer and the executor's segment stores (RFC-0020
//! section 15.2).

use crucible_engine::{ContentHash, SchedulerEventLogEntry};
use crucible_store::content_store::{ContentId, ObjectKind};

mod store;

pub(crate) use store::{
    AttemptLogDirectory, AttemptLogNamespace, AttemptLogSegmentStore, AttemptLogStore,
    read_content_file, write_content_file,
};
pub use store::{AttemptLogSegmentSource, AttemptLogSegmentSources, MemorySegmentStore};

pub use crucible_engine::attempt_log::{
    ATTEMPT_LOG_SEGMENT_SCHEMA, ATTEMPT_LOG_SEGMENT_TARGET_BYTES, AttemptEventLogError,
    AttemptLogEntries, AttemptLogManifest, AttemptLogSegmentRef, MAX_ATTEMPT_LOG_ENTRY_BYTES,
    MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS, MAX_ATTEMPT_LOG_SEGMENT_BYTES, decode_segment,
};
pub(crate) use crucible_engine::attempt_log::{
    empty_chain, encode_segment, encoded_entry_len, extend_chain, read_segment,
};

/// An attempt log retained as sealed segments plus an open tail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttemptEventLog<S> {
    store: S,
    maximum_bytes: u64,
    sealed: Vec<AttemptLogSegmentRef>,
    chain: ContentHash,
    sealed_bytes: u64,
    tail: Vec<SchedulerEventLogEntry>,
    tail_bytes: usize,
    first_sequence: u64,
    next_sequence: u64,
}

impl<S: AttemptLogSegmentStore> AttemptEventLog<S> {
    /// Starts an empty log whose first entry will carry `first_sequence`.
    pub(crate) fn new(store: S, maximum_bytes: u64, first_sequence: u64) -> Self {
        Self {
            store,
            maximum_bytes,
            sealed: Vec::new(),
            chain: empty_chain(),
            sealed_bytes: 0,
            tail: Vec::new(),
            tail_bytes: 0,
            first_sequence,
            next_sequence: first_sequence,
        }
    }

    /// Appends dense entries, sealing the tail whenever it reaches its target.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] for a non-dense entry, an entry beyond
    /// [`MAX_ATTEMPT_LOG_ENTRY_BYTES`], an append beyond the storage limit, or
    /// a segment that cannot be encoded or stored. A refused append leaves
    /// every previously appended entry retained.
    pub(crate) fn append(
        &mut self,
        entries: impl IntoIterator<Item = SchedulerEventLogEntry>,
    ) -> Result<(), AttemptEventLogError> {
        for entry in entries {
            let bytes = self.admit(&entry, self.next_sequence, self.total_bytes())?;
            self.push_admitted(entry, bytes)?;
        }
        Ok(())
    }

    /// Appends every entry of `entries`, or none of them.
    ///
    /// All entries are checked for density, size, and the storage limit
    /// before the first is retained, so a refusal leaves the log unchanged.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::append`]. A segment-store failure
    /// while sealing can still leave a prefix of `entries` retained.
    pub(crate) fn append_all(
        &mut self,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<(), AttemptEventLogError> {
        let mut sizes = Vec::with_capacity(entries.len());
        let mut retained = self.total_bytes();
        for (offset, entry) in entries.iter().enumerate() {
            let sequence = self.next_sequence.saturating_add(offset as u64);
            let bytes = self.admit(entry, sequence, retained)?;
            retained = retained.saturating_add(bytes as u64);
            sizes.push(bytes);
        }

        for (entry, bytes) in entries.iter().zip(sizes) {
            self.push_admitted(entry.clone(), bytes)?;
        }
        Ok(())
    }

    /// Checks one entry against the next sequence and the storage limit.
    fn admit(
        &self,
        entry: &SchedulerEventLogEntry,
        expected: u64,
        retained: u64,
    ) -> Result<usize, AttemptEventLogError> {
        if entry.sequence() != expected {
            return Err(AttemptEventLogError::NonDense {
                expected,
                actual: entry.sequence(),
            });
        }
        let bytes = encoded_entry_len(entry)?;
        if bytes > MAX_ATTEMPT_LOG_ENTRY_BYTES {
            return Err(AttemptEventLogError::EntryTooLarge {
                sequence: entry.sequence(),
                bytes,
            });
        }
        let required = retained.saturating_add(bytes as u64);
        if required > self.maximum_bytes {
            return Err(AttemptEventLogError::StorageLimit {
                required,
                limit: self.maximum_bytes,
            });
        }
        Ok(bytes)
    }

    /// Retains an admitted entry, sealing the tail first when it is full.
    fn push_admitted(
        &mut self,
        entry: SchedulerEventLogEntry,
        bytes: usize,
    ) -> Result<(), AttemptEventLogError> {
        if !self.tail.is_empty()
            && self.tail_bytes.saturating_add(bytes) > ATTEMPT_LOG_SEGMENT_TARGET_BYTES
        {
            self.seal()?;
        }

        self.tail.push(entry);
        self.tail_bytes += bytes;
        self.next_sequence += 1;
        Ok(())
    }

    /// Seals the open tail, if any, into one stored segment.
    ///
    /// Callers seal at checkpoint offsets and at the attempt stop so that seal
    /// points depend only on the entry sequence and those offsets.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when the log already holds
    /// [`MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS`] segments, or the segment cannot be
    /// encoded, exceeds [`MAX_ATTEMPT_LOG_SEGMENT_BYTES`], or cannot be stored.
    /// The tail is retained on error.
    pub(crate) fn seal(&mut self) -> Result<(), AttemptEventLogError> {
        let Some(first) = self.tail.first() else {
            return Ok(());
        };
        if self.sealed.len() >= MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS {
            return Err(AttemptEventLogError::SegmentLimit {
                limit: MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS,
            });
        }
        let first_sequence = first.sequence();
        let bytes = encode_segment(first_sequence, &self.tail)?;
        let id = ContentId::for_bytes(ObjectKind::Trace, ATTEMPT_LOG_SEGMENT_SCHEMA, &bytes);
        self.store
            .put(id, &bytes)
            .map_err(|source| AttemptEventLogError::Store { source })?;

        let segment = AttemptLogSegmentRef {
            id,
            first_sequence,
            entry_count: self.tail.len() as u64,
            encoded_bytes: bytes.len() as u64,
        };
        self.chain = extend_chain(self.chain, &segment);
        self.sealed_bytes += segment.encoded_bytes;
        self.sealed.push(segment);
        self.tail.clear();
        self.tail_bytes = 0;
        Ok(())
    }

    /// Returns the operational storage bound applied to appends.
    pub(crate) const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    /// Replaces the operational storage bound applied to later appends.
    pub(crate) fn set_maximum_bytes(&mut self, maximum_bytes: u64) {
        self.maximum_bytes = maximum_bytes;
    }

    /// Returns the references of every sealed segment, in order.
    pub(crate) fn sealed_segments(&self) -> &[AttemptLogSegmentRef] {
        &self.sealed
    }

    /// Returns the chain hash after the last sealed segment.
    pub(crate) const fn chain(&self) -> ContentHash {
        self.chain
    }

    /// Returns the entries not yet sealed.
    pub(crate) fn tail(&self) -> &[SchedulerEventLogEntry] {
        &self.tail
    }

    /// Returns the number of entries appended so far.
    pub(crate) const fn len(&self) -> u64 {
        self.next_sequence - self.first_sequence
    }

    /// Returns whether no entry has been appended.
    pub(crate) const fn is_empty(&self) -> bool {
        self.next_sequence == self.first_sequence
    }

    /// Returns the sequence the next appended entry must carry.
    pub(crate) const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Returns the encoded bytes of sealed segments plus the open tail.
    pub(crate) fn total_bytes(&self) -> u64 {
        self.sealed_bytes.saturating_add(self.tail_bytes as u64)
    }

    /// Visits every entry in sequence order, reading sealed segments back.
    ///
    /// Only one sealed segment is decoded at a time, so memory stays bounded
    /// by one segment plus the tail.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when a sealed segment is missing or
    /// fails authentication, or the first error `visit` returns.
    pub(crate) fn try_for_each_entry<E>(
        &self,
        mut visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), E>,
    ) -> Result<(), AttemptEventLogVisitError<E>> {
        for segment in &self.sealed {
            for entry in &read_segment(&self.store, segment)? {
                visit(entry).map_err(AttemptEventLogVisitError::Visit)?;
            }
        }
        for entry in &self.tail {
            visit(entry).map_err(AttemptEventLogVisitError::Visit)?;
        }
        Ok(())
    }

    /// Visits entries from sequence `start` onward, in order.
    ///
    /// Sealed segments that end before `start` are not read.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when a needed segment is missing or
    /// fails authentication, or the first error `visit` returns.
    pub(crate) fn try_for_each_entry_from<E>(
        &self,
        start: u64,
        mut visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), E>,
    ) -> Result<(), AttemptEventLogVisitError<E>> {
        for segment in &self.sealed {
            if segment.first_sequence.saturating_add(segment.entry_count) <= start {
                continue;
            }
            for entry in &read_segment(&self.store, segment)? {
                if entry.sequence() >= start {
                    visit(entry).map_err(AttemptEventLogVisitError::Visit)?;
                }
            }
        }
        for entry in self.tail.iter().filter(|entry| entry.sequence() >= start) {
            visit(entry).map_err(AttemptEventLogVisitError::Visit)?;
        }
        Ok(())
    }

    /// Returns the sequence of the log's first entry.
    pub(crate) const fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    /// Seals the tail and returns the manifest of the complete log.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when the tail cannot be sealed or the
    /// log has more segments than one manifest may reference.
    pub(crate) fn seal_manifest(&mut self) -> Result<AttemptLogManifest, AttemptEventLogError> {
        self.seal()?;
        AttemptLogManifest::new(self.sealed.clone())
    }

    /// Moves every sealed segment into `store` and keeps writing there.
    ///
    /// Each segment is authenticated against its reference as it is copied.
    /// On error the log keeps its current store, and `store` may hold copies
    /// of some segments.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when a sealed segment cannot be read
    /// back, fails authentication, or cannot be written to `store`.
    pub(crate) fn replace_store(&mut self, mut store: S) -> Result<(), AttemptEventLogError> {
        for segment in &self.sealed {
            let bytes = self
                .store
                .segment(segment.id)
                .map_err(|source| AttemptEventLogError::Store { source })?;
            decode_segment(segment, &bytes)?;
            store
                .put(segment.id, &bytes)
                .map_err(|source| AttemptEventLogError::Store { source })?;
        }
        self.store = store;
        Ok(())
    }

    /// Borrows the segment store, for publication of sealed segments.
    pub(crate) const fn store(&self) -> &S {
        &self.store
    }

    /// Releases the segment store, which holds every sealed segment.
    ///
    /// Entries still in the open tail are dropped; seal first to keep them.
    pub(crate) fn into_store(self) -> S {
        self.store
    }
}

/// Failure while visiting a segmented log's entries.
#[derive(Debug, thiserror::Error)]
pub enum AttemptEventLogVisitError<E> {
    /// A sealed segment could not be read back.
    #[error(transparent)]
    Log(#[from] AttemptEventLogError),
    /// The visitor refused an entry.
    #[error("attempt event log visitor failed")]
    Visit(E),
}

#[cfg(test)]
#[path = "attempt_event_log_tests.rs"]
mod tests;
