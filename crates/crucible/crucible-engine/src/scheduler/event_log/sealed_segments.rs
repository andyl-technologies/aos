//! Decodable sealed segments of the scheduler's unified event log.
//!
//! Every append still produces one binary event-log segment (format v6) that
//! is stored by its BLAKE3 identity and chained into the log's prefix hash
//! (RFC-0010 OBS-17 to OBS-20). Those segments hold canonical entry material,
//! not decodable entries, so a scheduler continuation could not rebuild its
//! condition prefix from them and formerly embedded every entry instead.
//!
//! The log therefore also seals its entries into decodable segments, using
//! the attempt segment encoding of RFC-0020 section 15.2, and keeps only the
//! entries since the last seal resident (RFC-0020 CCOMP-33):
//!
//! ```text
//! sealed: [segment 0] [segment 1] ...   // stored, named by reference
//! tail:   entries since the last seal   // resident, carried by a continuation
//! ```
//!
//! The log seals the tail before an entry would make the tail's encoding
//! exceed [`EVENT_LOG_SEAL_TARGET_BYTES`], and for no other reason. Seal points
//! are therefore a pure function of the entry sequence: a log restored from a
//! continuation seals exactly where the uninterrupted log would, and equal
//! entries seal into byte-identical segments wherever they are retained. An
//! entry whose encoding exceeds [`MAX_ATTEMPT_LOG_ENTRY_BYTES`] fails its
//! append closed.
//!
//! A sealed segment is stored under the BLAKE3 content hash of its bytes in
//! the log's segment store, beside the per-append binary segments, and is
//! referenced by an [`EventLogSegmentRef`]. Readers authenticate each segment
//! against its reference before decoding it and hold one segment at a time.

use std::io;

use crucible_store::content_store::{ContentId, ObjectKind};
use serde::{Deserialize, Serialize};

use super::*;
use crate::attempt_log::{
    ATTEMPT_LOG_SEGMENT_SCHEMA, ATTEMPT_LOG_SEGMENT_TARGET_BYTES, AttemptEventLogError,
    AttemptLogSegmentRef, MAX_ATTEMPT_LOG_ENTRY_BYTES, MAX_ATTEMPT_LOG_SEGMENT_BYTES,
    decode_segment, encode_segment, encoded_entry_len,
};

/// Encoded tail size before which the scheduler event log seals its tail.
///
/// This is the shared RFC-0020 section 15 sealing target, so a sealed
/// scheduler segment never exceeds [`MAX_ATTEMPT_LOG_SEGMENT_BYTES`].
pub const EVENT_LOG_SEAL_TARGET_BYTES: usize = ATTEMPT_LOG_SEGMENT_TARGET_BYTES;

/// Reference to one sealed segment of the scheduler's unified event log.
///
/// The referenced bytes are an attempt-log segment (RFC-0020 section 15.2)
/// covering the dense entries `first_sequence..first_sequence + entry_count`.
/// The reference names them by the BLAKE3 content hash used by the log's
/// segment store rather than by a campaign content identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventLogSegmentRef {
    /// BLAKE3 content hash of the encoded segment in the segment store.
    pub object: ContentHash,
    /// Sequence of the segment's first entry.
    pub first_sequence: u64,
    /// Number of entries in the segment; never zero.
    pub entry_count: u64,
    /// Encoded segment size in bytes.
    pub encoded_bytes: u64,
}

impl EventLogSegmentRef {
    /// Returns the dense sequence just after this segment's last entry.
    ///
    /// Returns `None` when the end is not representable, which a validated
    /// reference never produces.
    #[must_use]
    pub const fn end_sequence(&self) -> Option<u64> {
        self.first_sequence.checked_add(self.entry_count)
    }

    /// Authenticates `bytes` against this reference and decodes their entries.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError::InvalidSegment`] when the bytes exceed
    /// the segment bound, have another length or content hash, are not the
    /// canonical attempt-segment encoding, or carry entries that are not dense
    /// from [`Self::first_sequence`] or whose content hashes do not verify.
    pub fn decode(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<SchedulerEventLogEntry>, AttemptEventLogError> {
        let attempt = AttemptLogSegmentRef {
            id: ContentId::for_bytes(ObjectKind::Trace, ATTEMPT_LOG_SEGMENT_SCHEMA, bytes),
            first_sequence: self.first_sequence,
            entry_count: self.entry_count,
            encoded_bytes: self.encoded_bytes,
        };
        if ContentHash::from_bytes(bytes) != self.object {
            return Err(AttemptEventLogError::InvalidSegment {
                segment: attempt.id,
                reason: String::from("bytes do not derive the referenced content hash"),
            });
        }
        decode_segment(&attempt, bytes)
    }
}

/// Source of sealed scheduler event-log segments, read one at a time.
///
/// Every [`DagStore`] is a reader. Carriers whose segments live elsewhere,
/// such as a repository-authenticated exact checkpoint, implement it over
/// their own object opener.
pub trait EventLogSegmentReader {
    /// Returns the stored bytes of `segment`.
    ///
    /// Implementations need not authenticate the bytes: every caller checks
    /// them with [`EventLogSegmentRef::decode`] before use.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the segment is absent or cannot be read.
    fn read_event_log_segment(&self, segment: &EventLogSegmentRef) -> io::Result<Vec<u8>>;
}

impl<S: DagStore + ?Sized> EventLogSegmentReader for S {
    fn read_event_log_segment(&self, segment: &EventLogSegmentRef) -> io::Result<Vec<u8>> {
        self.get(&segment.object).map_err(io::Error::other)
    }
}

/// Returns the summed entry encodings of one append, checking each entry.
///
/// # Errors
///
/// Returns [`SchedulerError::BoundaryViolation`] when an entry cannot be
/// encoded or its encoding exceeds [`MAX_ATTEMPT_LOG_ENTRY_BYTES`].
pub(in crate::scheduler) fn entry_encodings(
    entries: &[SchedulerEventLogEntry],
) -> Result<Vec<u64>, SchedulerError> {
    entries
        .iter()
        .map(|entry| {
            let bytes =
                encoded_entry_len(entry).map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "event-log entry {} cannot be encoded for sealing: {error}",
                        entry.sequence()
                    ),
                })?;
            if bytes > MAX_ATTEMPT_LOG_ENTRY_BYTES {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "event-log entry {} encodes to {bytes} bytes, above the \
                         {MAX_ATTEMPT_LOG_ENTRY_BYTES}-byte entry bound",
                        entry.sequence()
                    ),
                });
            }
            u64::try_from(bytes).map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("event-log entry encoding length exceeds u64"),
            })
        })
        .collect()
}

/// Returns whether appending an entry of `entry_bytes` must first seal a
/// nonempty tail of `tail_bytes`.
pub(super) fn seals_before(tail_bytes: u64, tail_is_empty: bool, entry_bytes: u64) -> bool {
    !tail_is_empty && tail_bytes.saturating_add(entry_bytes) > EVENT_LOG_SEAL_TARGET_BYTES as u64
}

/// Encodes `entries` as one sealed segment and stores it in `store`.
///
/// # Errors
///
/// Returns [`SchedulerError::BoundaryViolation`] when the entries are empty,
/// cannot be encoded within [`MAX_ATTEMPT_LOG_SEGMENT_BYTES`], or `store`
/// rejects the bytes or returns another identity.
pub(super) fn seal_segment(
    store: &EventLogSegmentStore,
    entries: &[SchedulerEventLogEntry],
) -> Result<EventLogSegmentRef, SchedulerError> {
    let Some(first) = entries.first() else {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("event-log seal has no entries"),
        });
    };
    let bytes = encode_segment(first.sequence(), entries).map_err(|error| {
        SchedulerError::BoundaryViolation {
            message: format!("event-log tail cannot be sealed: {error}"),
        }
    })?;
    let object = store.put_sealed_segment(&bytes)?;
    let count = |value: usize| {
        u64::try_from(value).map_err(|_| SchedulerError::BoundaryViolation {
            message: String::from("sealed event-log segment size exceeds u64"),
        })
    };
    Ok(EventLogSegmentRef {
        object,
        first_sequence: first.sequence(),
        entry_count: count(entries.len())?,
        encoded_bytes: count(bytes.len())?,
    })
}

/// Checks that `segments` are nonempty, bounded, and dense from `base`.
///
/// Returns the sequence after the last segment.
pub(in crate::scheduler) fn validate_segment_refs(
    segments: &[EventLogSegmentRef],
    base: u64,
) -> Option<u64> {
    segments.iter().try_fold(base, |next, segment| {
        (segment.first_sequence == next
            && segment.entry_count != 0
            && segment.encoded_bytes <= MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64)
            .then(|| segment.end_sequence())
            .flatten()
    })
}

/// Splits a dense entry stream into condition-prefix batches.
///
/// A condition prefix accepts a batch only when no entry in it is later than
/// the batch's final entry, and a later batch must not end before the
/// previous one. Every live append satisfies both, so its final entry is a
/// running maximum of entry time. Cutting after each running maximum
/// therefore yields valid batches at most one append long, and folding them
/// produces the same prefix as folding the whole log at once, whatever the
/// segment boundaries.
#[derive(Debug, Default)]
pub(in crate::scheduler) struct ConditionBatcher {
    latest: Option<VirtualTime>,
    pending: Vec<SchedulerEventLogEntry>,
}

impl ConditionBatcher {
    /// Accepts the next entry and returns a completed batch, if any.
    pub(in crate::scheduler) fn push(
        &mut self,
        entry: SchedulerEventLogEntry,
    ) -> Option<Vec<SchedulerEventLogEntry>> {
        let at = entry.at();
        self.pending.push(entry);
        if self.latest.is_none_or(|latest| at >= latest) {
            self.latest = Some(at);
            return Some(std::mem::take(&mut self.pending));
        }
        None
    }

    /// Returns the entries after the last running maximum.
    ///
    /// A complete log ends at a running maximum, so this is empty for every
    /// valid log; a nonempty remainder is still returned so the condition
    /// prefix reports its own refusal.
    pub(in crate::scheduler) fn finish(self) -> Vec<SchedulerEventLogEntry> {
        self.pending
    }
}

#[cfg(test)]
#[path = "sealed_segments_tests.rs"]
mod tests;
