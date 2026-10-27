//! Segment codec of the segmented attempt event log.
//!
//! An attempt's scheduler event log grows with every quantum, so it is never
//! held whole. A writer seals the log into content-addressed segments, before
//! an append would make the open segment's encoding exceed
//! [`ATTEMPT_LOG_SEGMENT_TARGET_BYTES`] and at the caller's checkpoint and
//! stop offsets. Only a small [`AttemptLogSegmentRef`] per sealed segment
//! stays resident, and an [`AttemptLogManifest`] names a complete log.
//!
//! Each segment is the canonical CBOR encoding of:
//!
//! ```text
//! {
//!   schema: 1,
//!   first_sequence: u64,          // sequence of entries[0]
//!   entries: [SchedulerEventLogEntry, ...]   // dense, ascending
//! }
//! ```
//!
//! and is addressed as a trace leaf. Segments form a chain:
//!
//! ```text
//! chain_0 = H(domain, "empty")
//! chain_i = H(domain, chain_(i-1) | segment_i id | first sequence | entries | bytes)
//! ```
//!
//! The final chain hash plus the entry count identifies the complete log, and
//! authenticating segments `1..i` authenticates the dense prefix they cover
//! without decoding any later segment (RFC-0020 section 15.2). Carriers that
//! name a log without holding it encode its manifest:
//!
//! ```text
//! "crucible.attempt-log-manifest.v1\0"
//! u64 entry count, 32-byte chain, u64 segment count,
//! per segment: 32-byte digest, u64 first sequence, u64 entries, u64 bytes
//! ```
//!
//! All manifest integers are little-endian. This module owns the formats;
//! the daemon owns the writer that seals a running attempt into its storage.

use std::io::{self, Write};
use std::ops::Range;

use crucible_store::content_store::{ContentId, ObjectKind};
use serde::{Deserialize, Serialize};

use crate::segment_store::{SegmentSink, SegmentSource};
use crate::{ContentHash, SchedulerEventLogEntry};

/// Trace payload schema of an encoded attempt-log segment.
pub const ATTEMPT_LOG_SEGMENT_SCHEMA: u32 = 1;

/// Encoded size before which the open tail is sealed.
///
/// Every segmented log shares the RFC-0020 section 15 sealing rule.
pub const ATTEMPT_LOG_SEGMENT_TARGET_BYTES: usize =
    crucible_store::segment_store::SEGMENT_TARGET_BYTES;

/// Largest encoded segment any writer produces or reader accepts.
pub const MAX_ATTEMPT_LOG_SEGMENT_BYTES: usize = crucible_store::segment_store::MAX_SEGMENT_BYTES;

/// Largest single encoded entry; anything larger fails the attempt closed.
pub const MAX_ATTEMPT_LOG_ENTRY_BYTES: usize = ATTEMPT_LOG_SEGMENT_TARGET_BYTES;

/// Largest number of segments one manifest may reference.
///
/// A manifest and its segments are published as the evidence children of one
/// measurement set, whose evidence set holds at most 4,096 objects.
pub const MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS: usize =
    crucible_store::segment_store::MAX_MANIFEST_SEGMENTS;

/// Largest encoded manifest; a full manifest encodes to well under it.
pub const MAX_ATTEMPT_LOG_MANIFEST_BYTES: usize = 1024 * 1024;

/// Domain separating attempt-log chain hashes from other content.
const ATTEMPT_LOG_CHAIN_DOMAIN: &str = "crucible.attempt.event-log.chain.v1";

const MANIFEST_MAGIC: &[u8] = b"crucible.attempt-log-manifest.v1\0";

/// Encoded size of one manifest segment reference.
const MANIFEST_SEGMENT_BYTES: usize = 32 + 3 * 8;

/// Failures while retaining, sealing, or reading an attempt log.
#[derive(Debug, thiserror::Error)]
pub enum AttemptEventLogError {
    /// Appended entries do not continue the log's dense sequence.
    #[error("attempt event log expected sequence {expected}, got {actual}")]
    NonDense {
        /// Next sequence the log accepts.
        expected: u64,
        /// Sequence that was supplied.
        actual: u64,
    },
    /// One entry's encoding exceeds [`MAX_ATTEMPT_LOG_ENTRY_BYTES`].
    #[error("attempt event log entry {sequence} encodes to {bytes} bytes")]
    EntryTooLarge {
        /// Sequence of the oversized entry.
        sequence: u64,
        /// Its encoded size.
        bytes: usize,
    },
    /// The attempt exceeded its operational event-log storage limit.
    #[error("attempt event log needs {required} bytes, above its {limit}-byte limit")]
    StorageLimit {
        /// Total encoded bytes the append would require.
        required: u64,
        /// Configured `maximum_event_log_bytes`.
        limit: u64,
    },
    /// Encoding an entry or segment failed.
    #[error("attempt event log encoding failed: {reason}")]
    Encoding {
        /// Encoder diagnostic.
        reason: String,
    },
    /// A stored segment failed authentication or decoding.
    #[error("attempt event log segment {segment} is invalid: {reason}")]
    InvalidSegment {
        /// Content identity of the rejected segment.
        segment: ContentId,
        /// Validation failure.
        reason: String,
    },
    /// A manifest's segment references are not a dense, bounded chain.
    #[error("attempt event log manifest is invalid: {reason}")]
    InvalidManifest {
        /// Validation failure.
        reason: String,
    },
    /// Sealing another segment would exceed what one manifest may reference.
    ///
    /// Checked at every seal, so a long attempt fails when it reaches the
    /// bound rather than at its stop.
    #[error("attempt event log already holds {limit} sealed segments")]
    SegmentLimit {
        /// [`MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS`].
        limit: usize,
    },
    /// The segment store could not write or read a segment.
    #[error("attempt event log segment store failed: {source}")]
    Store {
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },
}

/// Reference to one sealed segment, retained in place of its entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttemptLogSegmentRef {
    /// Trace content identity of the encoded segment.
    pub id: ContentId,
    /// Sequence of the segment's first entry.
    pub first_sequence: u64,
    /// Number of entries in the segment.
    pub entry_count: u64,
    /// Encoded segment size.
    pub encoded_bytes: u64,
}

/// The ordered segment references identifying one complete attempt log.
///
/// A manifest is valid only when its segments are non-empty, dense from
/// sequence zero, within the segment size bound, and its chain hash is the
/// chain over exactly those references. Construction and decoding both check
/// this, so holding a manifest proves its structure; reading entries through
/// [`Self::try_for_each_entry_in`] additionally authenticates each segment's
/// bytes against its reference.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AttemptLogManifest {
    segments: Vec<AttemptLogSegmentRef>,
    entry_count: u64,
    chain: ContentHash,
}

impl AttemptLogManifest {
    /// Builds a manifest over ordered segment references.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError::InvalidManifest`] when a segment is
    /// empty, oversized, or does not continue the dense sequence from zero, or
    /// when there are more than [`MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS`].
    pub fn new(segments: Vec<AttemptLogSegmentRef>) -> Result<Self, AttemptEventLogError> {
        let invalid = |reason: String| AttemptEventLogError::InvalidManifest { reason };
        if segments.len() > MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS {
            return Err(invalid(format!("{} segments", segments.len())));
        }

        let mut entry_count = 0_u64;
        let mut chain = empty_chain();
        for segment in &segments {
            if segment.entry_count == 0
                || segment.encoded_bytes > MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64
                || segment.id.kind() != ObjectKind::Trace
                || segment.id.schema_version() != ATTEMPT_LOG_SEGMENT_SCHEMA
            {
                return Err(invalid(format!("segment {} is malformed", segment.id)));
            }
            if segment.first_sequence != entry_count {
                return Err(invalid(format!(
                    "segment {} starts at {}, expected {entry_count}",
                    segment.id, segment.first_sequence
                )));
            }
            entry_count = entry_count
                .checked_add(segment.entry_count)
                .ok_or_else(|| invalid(String::from("entry count overflows")))?;
            chain = extend_chain(chain, segment);
        }
        Ok(Self {
            segments,
            entry_count,
            chain,
        })
    }

    /// Rebuilds a decoded manifest and checks its recorded totals.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::new`], or
    /// [`AttemptEventLogError::InvalidManifest`] when the recorded entry
    /// count or chain differs from the one the segments derive.
    pub fn from_parts(
        segments: Vec<AttemptLogSegmentRef>,
        entry_count: u64,
        chain: ContentHash,
    ) -> Result<Self, AttemptEventLogError> {
        let manifest = Self::new(segments)?;
        if manifest.entry_count != entry_count || manifest.chain != chain {
            return Err(AttemptEventLogError::InvalidManifest {
                reason: String::from("recorded totals do not match the segments"),
            });
        }
        Ok(manifest)
    }

    /// Returns the segment references in log order.
    #[must_use]
    pub fn segments(&self) -> &[AttemptLogSegmentRef] {
        &self.segments
    }

    /// Returns the number of entries the log holds.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Returns the chain hash after the last segment.
    #[must_use]
    pub const fn chain(&self) -> ContentHash {
        self.chain
    }

    /// Returns the canonical manifest encoding described in the module docs.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            MANIFEST_MAGIC.len() + 48 + self.segments.len() * MANIFEST_SEGMENT_BYTES,
        );
        bytes.extend_from_slice(MANIFEST_MAGIC);
        bytes.extend_from_slice(&self.entry_count.to_le_bytes());
        bytes.extend_from_slice(&self.chain.bytes);
        bytes.extend_from_slice(&(self.segments.len() as u64).to_le_bytes());
        for segment in &self.segments {
            bytes.extend_from_slice(&segment.id.digest());
            bytes.extend_from_slice(&segment.first_sequence.to_le_bytes());
            bytes.extend_from_slice(&segment.entry_count.to_le_bytes());
            bytes.extend_from_slice(&segment.encoded_bytes.to_le_bytes());
        }
        bytes
    }

    /// Decodes and validates a canonical manifest encoding.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError::InvalidManifest`] for oversized,
    /// truncated, or trailing bytes, a segment count beyond
    /// [`MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS`], or totals that the references
    /// do not derive.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AttemptEventLogError> {
        let invalid = |reason: &str| AttemptEventLogError::InvalidManifest {
            reason: reason.to_owned(),
        };
        if bytes.len() > MAX_ATTEMPT_LOG_MANIFEST_BYTES {
            return Err(invalid("manifest exceeds its encoded size limit"));
        }
        let body = bytes
            .strip_prefix(MANIFEST_MAGIC)
            .ok_or_else(|| invalid("manifest magic is invalid"))?;
        let (header, references) = body
            .split_at_checked(48)
            .ok_or_else(|| invalid("manifest is truncated"))?;
        let entry_count = read_u64(&header[..8]);
        let mut chain = [0_u8; 32];
        chain.copy_from_slice(&header[8..40]);
        let count = usize::try_from(read_u64(&header[40..48]))
            .ok()
            .filter(|count| *count <= MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS)
            .ok_or_else(|| invalid("manifest segment count exceeds its limit"))?;
        if references.len() != count * MANIFEST_SEGMENT_BYTES {
            return Err(invalid("manifest length does not match its segment count"));
        }

        let (references, _) = references.as_chunks::<MANIFEST_SEGMENT_BYTES>();
        let segments = references
            .iter()
            .map(|reference| {
                let mut digest = [0_u8; 32];
                digest.copy_from_slice(&reference[..32]);
                AttemptLogSegmentRef {
                    id: ContentId::from_parts(
                        ObjectKind::Trace,
                        ATTEMPT_LOG_SEGMENT_SCHEMA,
                        digest,
                    ),
                    first_sequence: read_u64(&reference[32..40]),
                    entry_count: read_u64(&reference[40..48]),
                    encoded_bytes: read_u64(&reference[48..56]),
                }
            })
            .collect();
        Self::from_parts(segments, entry_count, ContentHash { bytes: chain })
    }

    /// Visits the entries whose sequences fall in `range`, in order.
    ///
    /// Segments wholly outside `range` are not read. Each segment read is
    /// authenticated against its reference before any of its entries is
    /// visited, so a visitor never sees unauthenticated content.
    ///
    /// # Errors
    ///
    /// Returns an error converted from [`AttemptEventLogError`] when a segment
    /// is missing or fails authentication, or the first error `visit` returns.
    pub fn try_for_each_entry_in<E: From<AttemptEventLogError>>(
        &self,
        source: &dyn SegmentSource,
        range: Range<u64>,
        mut visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), E>,
    ) -> Result<(), E> {
        for segment in &self.segments {
            let segment_end = segment.first_sequence + segment.entry_count;
            if segment_end <= range.start {
                continue;
            }
            if segment.first_sequence >= range.end {
                break;
            }
            for entry in read_segment(source, segment)? {
                if range.contains(&entry.sequence()) {
                    visit(&entry)?;
                }
            }
        }
        Ok(())
    }

    /// Visits every entry in order; see [`Self::try_for_each_entry_in`].
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_for_each_entry_in`].
    pub fn try_for_each_entry<E: From<AttemptEventLogError>>(
        &self,
        source: &dyn SegmentSource,
        visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), E>,
    ) -> Result<(), E> {
        self.try_for_each_entry_in(source, 0..self.entry_count, visit)
    }

    /// Returns a pull reader over every entry, in order.
    ///
    /// The reader decodes one segment when its first entry is requested and
    /// authenticates it against its reference first, so it holds at most one
    /// segment's entries. After yielding an error it yields nothing more.
    #[must_use]
    pub fn entries<'a>(&'a self, source: &'a dyn SegmentSource) -> AttemptLogEntries<'a> {
        AttemptLogEntries {
            source,
            segments: self.segments.iter(),
            current: Vec::new().into_iter(),
            failed: false,
        }
    }
}

/// Seals `entries` into segments in `sink` by size alone and returns their
/// manifest.
///
/// This is the writer for a log that is complete before it is stored, so it
/// seals only where the open segment would exceed its target. Entries must be
/// dense from sequence zero.
///
/// # Errors
///
/// Returns [`AttemptEventLogError`] for a non-dense or oversized entry, a log
/// that needs more than [`MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS`] segments, or a
/// segment `sink` cannot store.
pub fn seal_attempt_log<'a>(
    entries: impl IntoIterator<Item = &'a SchedulerEventLogEntry>,
    sink: &dyn SegmentSink,
) -> Result<AttemptLogManifest, AttemptEventLogError> {
    let mut segments = Vec::new();
    let mut open: Vec<SchedulerEventLogEntry> = Vec::new();
    let mut open_bytes = 0_usize;

    for (next_sequence, entry) in (0_u64..).zip(entries) {
        if entry.sequence() != next_sequence {
            return Err(AttemptEventLogError::NonDense {
                expected: next_sequence,
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
        if !open.is_empty() && open_bytes.saturating_add(bytes) > ATTEMPT_LOG_SEGMENT_TARGET_BYTES {
            seal_open(&mut open, &mut segments, sink)?;
            open_bytes = 0;
        }
        open.push(entry.clone());
        open_bytes += bytes;
    }
    seal_open(&mut open, &mut segments, sink)?;

    AttemptLogManifest::new(segments)
}

/// Seals the open entries, if any, into one segment stored in `sink`.
fn seal_open(
    open: &mut Vec<SchedulerEventLogEntry>,
    segments: &mut Vec<AttemptLogSegmentRef>,
    sink: &dyn SegmentSink,
) -> Result<(), AttemptEventLogError> {
    let Some(first) = open.first() else {
        return Ok(());
    };
    if segments.len() >= MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS {
        return Err(AttemptEventLogError::SegmentLimit {
            limit: MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS,
        });
    }

    let first_sequence = first.sequence();
    let bytes = encode_segment(first_sequence, open)?;
    let id = ContentId::for_bytes(ObjectKind::Trace, ATTEMPT_LOG_SEGMENT_SCHEMA, &bytes);
    sink.put_segment(id, &bytes)
        .map_err(|source| AttemptEventLogError::Store { source })?;

    segments.push(AttemptLogSegmentRef {
        id,
        first_sequence,
        entry_count: open.len() as u64,
        encoded_bytes: bytes.len() as u64,
    });
    open.clear();
    Ok(())
}

/// Pull reader over a manifest's entries; see [`AttemptLogManifest::entries`].
pub struct AttemptLogEntries<'a> {
    source: &'a dyn SegmentSource,
    segments: std::slice::Iter<'a, AttemptLogSegmentRef>,
    current: std::vec::IntoIter<SchedulerEventLogEntry>,
    failed: bool,
}

impl Iterator for AttemptLogEntries<'_> {
    type Item = Result<SchedulerEventLogEntry, AttemptEventLogError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        loop {
            if let Some(entry) = self.current.next() {
                return Some(Ok(entry));
            }
            let segment = self.segments.next()?;
            match read_segment(self.source, segment) {
                Ok(entries) => self.current = entries.into_iter(),
                Err(error) => {
                    self.failed = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

/// Reads one segment from `source` and authenticates it.
///
/// # Errors
///
/// Returns [`AttemptEventLogError::Store`] when `source` cannot supply the
/// segment, or the errors of [`decode_segment`].
pub fn read_segment(
    source: &(impl SegmentSource + ?Sized),
    segment: &AttemptLogSegmentRef,
) -> Result<Vec<SchedulerEventLogEntry>, AttemptEventLogError> {
    let bytes = source
        .segment(segment.id)
        .map_err(|source| AttemptEventLogError::Store { source })?;
    decode_segment(segment, &bytes)
}

/// Decodes and authenticates one stored segment against its reference.
///
/// # Errors
///
/// Returns [`AttemptEventLogError::InvalidSegment`] when the bytes exceed the
/// format bound, do not derive the referenced identity, are not canonical
/// CBOR of the segment schema, or carry entries that are not dense from the
/// referenced first sequence or whose content hashes do not verify.
pub fn decode_segment(
    segment: &AttemptLogSegmentRef,
    bytes: &[u8],
) -> Result<Vec<SchedulerEventLogEntry>, AttemptEventLogError> {
    let invalid = |reason: String| AttemptEventLogError::InvalidSegment {
        segment: segment.id,
        reason,
    };
    if bytes.len() > MAX_ATTEMPT_LOG_SEGMENT_BYTES || bytes.len() as u64 != segment.encoded_bytes {
        return Err(invalid(format!("unexpected length {}", bytes.len())));
    }
    if ContentId::for_bytes(ObjectKind::Trace, ATTEMPT_LOG_SEGMENT_SCHEMA, bytes) != segment.id {
        return Err(invalid(String::from(
            "bytes do not derive the segment identity",
        )));
    }

    let wire: SegmentWire =
        ciborium::de::from_reader(bytes).map_err(|error| invalid(format!("decode: {error}")))?;
    if wire.schema != ATTEMPT_LOG_SEGMENT_SCHEMA
        || wire.first_sequence != segment.first_sequence
        || wire.entries.len() as u64 != segment.entry_count
        || wire.entries.is_empty()
    {
        return Err(invalid(String::from("header does not match its reference")));
    }
    for (offset, entry) in wire.entries.iter().enumerate() {
        if entry.sequence() != segment.first_sequence + offset as u64 {
            return Err(invalid(format!("entry {} is not dense", entry.sequence())));
        }
        if !entry.has_valid_content_hash() {
            return Err(invalid(format!(
                "entry {} hash does not verify",
                entry.sequence()
            )));
        }
    }
    if encode_segment(wire.first_sequence, &wire.entries)? != bytes {
        return Err(invalid(String::from("encoding is not canonical")));
    }
    Ok(wire.entries)
}

/// Returns the chain hash of an empty log.
#[must_use]
pub fn empty_chain() -> ContentHash {
    ContentHash::from_canonical_material_bytes(ATTEMPT_LOG_CHAIN_DOMAIN, b"empty")
}

/// Extends `chain` by one sealed segment.
#[must_use]
pub fn extend_chain(chain: ContentHash, segment: &AttemptLogSegmentRef) -> ContentHash {
    let segment_id = segment.id.encode();
    let mut material = Vec::with_capacity(32 + segment_id.len() + 24);
    material.extend_from_slice(&chain.bytes);
    material.extend_from_slice(segment_id.as_bytes());
    material.extend_from_slice(&segment.first_sequence.to_le_bytes());
    material.extend_from_slice(&segment.entry_count.to_le_bytes());
    material.extend_from_slice(&segment.encoded_bytes.to_le_bytes());
    ContentHash::from_canonical_material_bytes(ATTEMPT_LOG_CHAIN_DOMAIN, &material)
}

#[derive(Serialize)]
struct SegmentWireRef<'a> {
    schema: u32,
    first_sequence: u64,
    entries: &'a [SchedulerEventLogEntry],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentWire {
    schema: u32,
    first_sequence: u64,
    entries: Vec<SchedulerEventLogEntry>,
}

/// Encodes one segment of dense entries starting at `first_sequence`.
///
/// # Errors
///
/// Returns [`AttemptEventLogError::Encoding`] when an entry cannot be encoded
/// or the segment exceeds [`MAX_ATTEMPT_LOG_SEGMENT_BYTES`].
pub fn encode_segment(
    first_sequence: u64,
    entries: &[SchedulerEventLogEntry],
) -> Result<Vec<u8>, AttemptEventLogError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(
        &SegmentWireRef {
            schema: ATTEMPT_LOG_SEGMENT_SCHEMA,
            first_sequence,
            entries,
        },
        &mut bytes,
    )
    .map_err(|error| AttemptEventLogError::Encoding {
        reason: error.to_string(),
    })?;
    if bytes.len() > MAX_ATTEMPT_LOG_SEGMENT_BYTES {
        return Err(AttemptEventLogError::Encoding {
            reason: format!("segment encodes to {} bytes", bytes.len()),
        });
    }
    Ok(bytes)
}

/// Counts an entry's CBOR encoding without retaining the bytes.
///
/// # Errors
///
/// Returns [`AttemptEventLogError::Encoding`] when the entry cannot be encoded.
pub fn encoded_entry_len(entry: &SchedulerEventLogEntry) -> Result<usize, AttemptEventLogError> {
    let mut counter = ByteCounter(0);
    ciborium::ser::into_writer(entry, &mut counter).map_err(|error| {
        AttemptEventLogError::Encoding {
            reason: error.to_string(),
        }
    })?;
    Ok(counter.0)
}

struct ByteCounter(usize);

impl Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut word = [0_u8; 8];
    word.copy_from_slice(bytes);
    u64::from_le_bytes(word)
}

#[cfg(test)]
#[path = "attempt_log_tests.rs"]
mod tests;
