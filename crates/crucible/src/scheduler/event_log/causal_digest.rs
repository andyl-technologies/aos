//! Streaming identity of an event log's canonical causal projection.
//!
//! [`event_log_causal_projection`] retains every renumbered causal entry so
//! determinism gates can locate a first difference. Proofs that only bind the
//! projection's identity need its hash, encoded length, and entry count, which
//! [`EventLogCausalDigest`] computes one entry at a time without retaining the
//! log. The digest hashes exactly the bytes the projection would encode.

use super::*;

/// Identity of a causal projection: content hash, encoded size, and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventLogCausalSummary {
    /// Hash of the projection's canonical segment bytes.
    pub content_hash: ContentHash,
    /// Length of the projection's canonical segment bytes.
    pub canonical_bytes: usize,
    /// Number of causal entries in the projection.
    pub entries: usize,
}

impl EventLogCausalProjection {
    /// Returns the projection's identity without its retained entries.
    #[must_use]
    pub fn summary(&self) -> EventLogCausalSummary {
        EventLogCausalSummary {
            content_hash: self.content_hash,
            canonical_bytes: self.canonical_bytes.len(),
            entries: self.entries.len(),
        }
    }
}

/// Incremental form of [`event_log_causal_projection`]'s identity.
///
/// The canonical encoding carries the causal entry count before the entries,
/// so the caller supplies that count first, typically from a counting pass
/// with [`is_causal_event_log_entry`] over the same log. Non-causal entries
/// are ignored, so the digest consumes the unfiltered log.
///
/// # Examples
///
/// ```no_run
/// use crucible::{EventLogCausalDigest, SchedulerEventLogEntry, is_causal_event_log_entry};
///
/// fn summarize(log: &[SchedulerEventLogEntry]) -> Option<crucible::EventLogCausalSummary> {
///     let causal = log.iter().filter(|entry| is_causal_event_log_entry(entry)).count();
///     let mut digest = EventLogCausalDigest::new(causal as u64);
///     log.iter().for_each(|entry| digest.observe(entry));
///     digest.finish()
/// }
/// ```
#[derive(Debug)]
pub struct EventLogCausalDigest {
    hasher: blake3::Hasher,
    expected: u64,
    observed: u64,
    canonical_bytes: usize,
    scratch: Vec<u8>,
}

impl EventLogCausalDigest {
    /// Starts a digest for a projection of `causal_entries` entries.
    #[must_use]
    pub fn new(causal_entries: u64) -> Self {
        let mut header = Vec::new();
        encode_scheduler_event_log_segment_header(
            &mut header,
            scheduler_event_log_empty_prefix(),
            causal_entries,
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(&header);
        Self {
            hasher,
            expected: causal_entries,
            observed: 0,
            canonical_bytes: header.len(),
            scratch: Vec::new(),
        }
    }

    /// Adds one entry of the unfiltered log; non-causal entries are skipped.
    pub fn observe(&mut self, entry: &SchedulerEventLogEntry) {
        if !is_causal_event_log_entry(entry) {
            return;
        }
        let renumbered = causal_projection_entry(self.observed, entry);
        self.observed = self.observed.saturating_add(1);
        self.scratch.clear();
        SchedulerEventLogSegmentEntryMaterial::from_entry(&renumbered)
            .encode_into(&mut self.scratch);
        self.hasher.update(&self.scratch);
        self.canonical_bytes = self.canonical_bytes.saturating_add(self.scratch.len());
    }

    /// Returns the projection identity, or `None` when the observed causal
    /// entries differ from the count supplied to [`Self::new`].
    #[must_use]
    pub fn finish(self) -> Option<EventLogCausalSummary> {
        (self.observed == self.expected).then(|| EventLogCausalSummary {
            content_hash: ContentHash {
                bytes: *self.hasher.finalize().as_bytes(),
            },
            canonical_bytes: self.canonical_bytes,
            entries: usize::try_from(self.observed).unwrap_or(usize::MAX),
        })
    }
}

/// Returns whether `entry` belongs to the causal projection.
#[must_use]
pub fn is_causal_event_log_entry(entry: &SchedulerEventLogEntry) -> bool {
    entry.class == SchedulerEventLogClass::Causal
}

/// Renumbers one causal entry to its position in the projection.
pub(super) fn causal_projection_entry(
    causal_index: u64,
    entry: &SchedulerEventLogEntry,
) -> SchedulerEventLogEntry {
    scheduler_event_log_entry_with_material(
        causal_index,
        entry.at.clone(),
        entry.source.clone(),
        entry.level,
        SchedulerEventLogClass::Causal,
        entry.event_payload.clone(),
        entry.payload.clone(),
    )
}
