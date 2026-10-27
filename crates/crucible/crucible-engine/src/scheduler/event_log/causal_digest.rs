//! Streaming identity and comparison of an event log's causal projection.
//!
//! [`event_log_causal_projection`] retains every renumbered causal entry so
//! determinism gates can locate a first difference. Proofs that only bind the
//! projection's identity need its hash, encoded length, and entry count, which
//! [`EventLogCausalDigest`] computes one entry at a time without retaining the
//! log. The digest hashes exactly the bytes the projection would encode.
//!
//! [`first_event_log_causal_mismatch`] locates the same first difference as
//! [`compare_event_log_determinism`] while reading both logs as streams, so a
//! caller whose logs are stored as segments never holds either log whole.

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
/// use crucible_engine::{EventLogCausalDigest, SchedulerEventLogEntry, is_causal_event_log_entry};
///
/// fn summarize(log: &[SchedulerEventLogEntry]) -> Option<crucible_engine::EventLogCausalSummary> {
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
pub(crate) fn causal_projection_entry(
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

/// Locates the first causal-projection difference between two streamed logs.
///
/// Both inputs yield the unfiltered log in sequence order. Observational
/// entries are skipped and causal entries are renumbered independently on
/// each side, exactly as [`compare_event_log_determinism`] does, so the result
/// equals that comparison's [`EventLogDeterminismComparison::mismatch`]. Only
/// the current entry of each side is held; the comparison stops at the first
/// difference without reading further.
///
/// # Errors
///
/// Returns the first error either stream yields before a difference is found.
///
/// # Examples
///
/// ```no_run
/// use crucible_engine::{SchedulerEventLogEntry, first_event_log_causal_mismatch};
///
/// fn diverges(expected: &[SchedulerEventLogEntry], reproduced: &[SchedulerEventLogEntry]) -> bool {
///     let ok = |entry: &SchedulerEventLogEntry| Ok::<_, std::convert::Infallible>(entry.clone());
///     first_event_log_causal_mismatch(
///         expected.iter().map(ok),
///         reproduced.iter().map(ok),
///     )
///     .is_ok_and(|mismatch| mismatch.is_some())
/// }
/// ```
pub fn first_event_log_causal_mismatch<E>(
    expected: impl IntoIterator<Item = Result<SchedulerEventLogEntry, E>>,
    reproduced: impl IntoIterator<Item = Result<SchedulerEventLogEntry, E>>,
) -> Result<Option<EventLogDeterminismMismatch>, E> {
    let mut expected = CausalCursor::new(expected.into_iter());
    let mut reproduced = CausalCursor::new(reproduced.into_iter());

    for causal_index in 0_usize.. {
        let expected_entry = expected.next_causal()?;
        let reproduced_entry = reproduced.next_causal()?;
        let entries_match = match (&expected_entry, &reproduced_entry) {
            (Some(expected), Some(reproduced)) => expected.entry == reproduced.entry,
            (None, None) => return Ok(None),
            (Some(_), None) | (None, Some(_)) => false,
        };
        if !entries_match {
            return Ok(Some(EventLogDeterminismMismatch {
                causal_index,
                expected_raw_index: expected_entry.as_ref().map(|entry| entry.raw_index),
                reproduced_raw_index: reproduced_entry.as_ref().map(|entry| entry.raw_index),
                expected_location: expected_entry
                    .as_ref()
                    .map(event_log_causal_divergence_point),
                reproduced_location: reproduced_entry
                    .as_ref()
                    .map(event_log_causal_divergence_point),
                expected_entry: expected_entry.map(|entry| entry.entry),
                reproduced_entry: reproduced_entry.map(|entry| entry.entry),
            }));
        }
    }
    Ok(None)
}

/// One side of a streamed causal comparison.
///
/// Tracks the raw position of the next unfiltered entry and the number of
/// causal entries already yielded, which is the next renumbered index.
struct CausalCursor<I> {
    entries: I,
    raw_index: usize,
    causal_index: u64,
}

impl<I, E> CausalCursor<I>
where
    I: Iterator<Item = Result<SchedulerEventLogEntry, E>>,
{
    const fn new(entries: I) -> Self {
        Self {
            entries,
            raw_index: 0,
            causal_index: 0,
        }
    }

    /// Returns the next causal entry, renumbered, or `None` at the end.
    fn next_causal(&mut self) -> Result<Option<EventLogCausalProjectionEntry>, E> {
        for entry in self.entries.by_ref() {
            let entry = entry?;
            let raw_index = self.raw_index;
            self.raw_index = self.raw_index.saturating_add(1);
            if !is_causal_event_log_entry(&entry) {
                continue;
            }

            let renumbered = causal_projection_entry(self.causal_index, &entry);
            self.causal_index = self.causal_index.saturating_add(1);
            return Ok(Some(EventLogCausalProjectionEntry {
                raw_index,
                entry: renumbered,
            }));
        }
        Ok(None)
    }
}
