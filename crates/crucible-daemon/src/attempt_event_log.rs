//! Segmented attempt event log: sealed, chained segments plus an open tail.
//!
//! An attempt's scheduler event log grows with every quantum, so the executor
//! never holds it whole. Entries accumulate in an open tail; before the tail's
//! encoding would exceed [`ATTEMPT_LOG_SEGMENT_TARGET_BYTES`], or when the
//! caller seals at a checkpoint or the attempt stop, the tail is encoded as one
//! segment, written to an [`AttemptLogSegmentStore`], and dropped from memory.
//! Only a small [`AttemptLogSegmentRef`] per sealed segment stays resident.
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
//! and is addressed as an executor trace leaf. Segments form a chain:
//!
//! ```text
//! chain_0 = H(domain, "empty")
//! chain_i = H(domain, chain_(i-1) | segment_i id | first sequence | entries | bytes)
//! ```
//!
//! The final chain hash plus the entry count identifies the complete log, and
//! authenticating segments `1..i` authenticates the dense prefix they cover
//! without decoding any later segment (RFC-0020 section 15.2).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::ops::Range;
use std::path::PathBuf;

use crucible::{ContentHash, SchedulerEventLogEntry};
use crucible_cas::content_store::{ContentId, ObjectKind};
use serde::{Deserialize, Serialize};

/// Trace payload schema of an encoded attempt-log segment.
pub const ATTEMPT_LOG_SEGMENT_SCHEMA: u32 = 1;

/// Encoded size before which the open tail is sealed.
pub const ATTEMPT_LOG_SEGMENT_TARGET_BYTES: usize = 8 * 1024 * 1024;

/// Largest encoded segment any writer produces or reader accepts.
pub const MAX_ATTEMPT_LOG_SEGMENT_BYTES: usize = 16 * 1024 * 1024;

/// Largest single encoded entry; anything larger fails the attempt closed.
pub const MAX_ATTEMPT_LOG_ENTRY_BYTES: usize = ATTEMPT_LOG_SEGMENT_TARGET_BYTES;

/// Domain separating attempt-log chain hashes from other content.
const ATTEMPT_LOG_CHAIN_DOMAIN: &str = "crucible.attempt.event-log.chain.v1";

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
    /// The segment store could not write or read a segment.
    #[error("attempt event log segment store failed: {source}")]
    Store {
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },
}

/// Reference to one sealed segment, retained in place of its entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// Read access to sealed segments, addressed by content identity.
///
/// Readers authenticate every segment they receive against its reference, so
/// a source only needs to return the bytes it holds under an identity.
pub trait AttemptLogSegmentSource {
    /// Reads one encoded segment.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the segment is absent, unreadable, or larger
    /// than [`MAX_ATTEMPT_LOG_SEGMENT_BYTES`].
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>>;
}

/// Writable storage for the segments an attempt seals.
pub(crate) trait AttemptLogSegmentStore: AttemptLogSegmentSource {
    /// Stores one encoded segment under its identity.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the segment cannot be durably written.
    fn put(&mut self, id: ContentId, bytes: &[u8]) -> io::Result<()>;
}

/// Segment store backed by one attempt-owned directory.
///
/// Each segment is written to a temporary name, synchronized, and renamed to
/// its identity, so a partially written segment is never visible.
#[derive(Debug)]
pub(crate) struct DirectorySegmentStore {
    directory: PathBuf,
}

impl DirectorySegmentStore {
    /// Uses `directory`, which the attempt owns and removes with its storage.
    pub(crate) fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn path(&self, id: ContentId) -> PathBuf {
        let name = id
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        self.directory.join(format!("{name}.segment"))
    }
}

impl AttemptLogSegmentStore for DirectorySegmentStore {
    fn put(&mut self, id: ContentId, bytes: &[u8]) -> io::Result<()> {
        let path = self.path(id);
        let staging = path.with_extension("segment.partial");
        let mut file = fs::File::create(&staging)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&staging, &path)
    }
}

impl AttemptLogSegmentSource for DirectorySegmentStore {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        let path = self.path(id);
        let length = fs::metadata(&path)?.len();
        if length > MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "attempt log segment exceeds its format bound",
            ));
        }
        fs::read(path)
    }
}

/// In-memory segment store for bounded in-process callers and tests.
///
/// Segments are keyed by the identity their bytes derive, so a store never
/// holds bytes under a foreign identity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemorySegmentStore {
    segments: BTreeMap<ContentId, Vec<u8>>,
}

impl MemorySegmentStore {
    /// Stores encoded segment bytes under the identity they derive.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError::InvalidSegment`] when the bytes exceed
    /// [`MAX_ATTEMPT_LOG_SEGMENT_BYTES`].
    pub fn insert(&mut self, bytes: Vec<u8>) -> Result<ContentId, AttemptEventLogError> {
        let id = ContentId::for_bytes(ObjectKind::Trace, ATTEMPT_LOG_SEGMENT_SCHEMA, &bytes);
        if bytes.len() > MAX_ATTEMPT_LOG_SEGMENT_BYTES {
            return Err(AttemptEventLogError::InvalidSegment {
                segment: id,
                reason: format!("unexpected length {}", bytes.len()),
            });
        }
        self.segments.insert(id, bytes);
        Ok(id)
    }

    /// Copies one referenced segment from `source` into this store.
    ///
    /// The segment is authenticated against its reference before it is kept.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when the segment is absent from
    /// `source` or fails authentication.
    pub fn copy_from(
        &mut self,
        source: &dyn AttemptLogSegmentSource,
        segment: &AttemptLogSegmentRef,
    ) -> Result<(), AttemptEventLogError> {
        if self.segments.contains_key(&segment.id) {
            return Ok(());
        }
        let bytes = source
            .segment(segment.id)
            .map_err(|source| AttemptEventLogError::Store { source })?;
        decode_segment(segment, &bytes)?;
        self.segments.insert(segment.id, bytes);
        Ok(())
    }

    /// Moves every segment of `other` into this store.
    pub fn extend(&mut self, other: Self) {
        self.segments.extend(other.segments);
    }

    /// Keeps only the segments whose identities `keep` accepts.
    pub fn retain(&mut self, mut keep: impl FnMut(ContentId) -> bool) {
        self.segments.retain(|id, _| keep(*id));
    }

    /// Returns whether a segment with `id` is stored.
    #[must_use]
    pub fn contains(&self, id: ContentId) -> bool {
        self.segments.contains_key(&id)
    }

    /// Returns the stored identities in ascending order.
    pub fn ids(&self) -> impl Iterator<Item = ContentId> + '_ {
        self.segments.keys().copied()
    }

    /// Returns the stored segments in identity order.
    pub fn iter(&self) -> impl Iterator<Item = (ContentId, &[u8])> {
        self.segments
            .iter()
            .map(|(id, bytes)| (*id, bytes.as_slice()))
    }

    /// Returns the number of stored segments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Returns whether no segment is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns the total encoded bytes of every stored segment.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.segments
            .values()
            .map(|bytes| bytes.len() as u64)
            .fold(0, u64::saturating_add)
    }

    /// Encodes `entries` as one sealed log and returns its manifest.
    ///
    /// The log is sealed at the ordinary target size, so the manifest matches
    /// what an executor retaining the same entries would publish.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when the entries are not dense from
    /// sequence zero or cannot be encoded.
    pub fn sealed_log(
        &mut self,
        entries: impl IntoIterator<Item = SchedulerEventLogEntry>,
    ) -> Result<AttemptLogManifest, AttemptEventLogError> {
        let mut log = AttemptEventLog::new(std::mem::take(self), u64::MAX, 0);
        let manifest = log.append(entries).and_then(|()| log.seal_manifest());
        // Segments sealed before a failure stay stored; they are unreferenced.
        *self = log.store;
        manifest
    }
}

impl AttemptLogSegmentStore for MemorySegmentStore {
    fn put(&mut self, id: ContentId, bytes: &[u8]) -> io::Result<()> {
        self.segments.insert(id, bytes.to_vec());
        Ok(())
    }
}

impl AttemptLogSegmentSource for MemorySegmentStore {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        self.segments
            .get(&id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "attempt log segment absent"))
    }
}

/// An attempt log retained as sealed segments plus an open tail.
#[derive(Clone, Debug)]
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
            if entry.sequence() != self.next_sequence {
                return Err(AttemptEventLogError::NonDense {
                    expected: self.next_sequence,
                    actual: entry.sequence(),
                });
            }
            let bytes = encoded_entry_len(&entry)?;
            if bytes > MAX_ATTEMPT_LOG_ENTRY_BYTES {
                return Err(AttemptEventLogError::EntryTooLarge {
                    sequence: entry.sequence(),
                    bytes,
                });
            }
            let required = self.total_bytes().saturating_add(bytes as u64);
            if required > self.maximum_bytes {
                return Err(AttemptEventLogError::StorageLimit {
                    required,
                    limit: self.maximum_bytes,
                });
            }
            if !self.tail.is_empty()
                && self.tail_bytes.saturating_add(bytes) > ATTEMPT_LOG_SEGMENT_TARGET_BYTES
            {
                self.seal()?;
            }

            self.tail.push(entry);
            self.tail_bytes += bytes;
            self.next_sequence += 1;
        }
        Ok(())
    }

    /// Seals the open tail, if any, into one stored segment.
    ///
    /// Callers seal at checkpoint offsets and at the attempt stop so that seal
    /// points depend only on the entry sequence and those offsets.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when the segment cannot be encoded,
    /// exceeds [`MAX_ATTEMPT_LOG_SEGMENT_BYTES`], or cannot be stored. The
    /// tail is retained on error.
    pub(crate) fn seal(&mut self) -> Result<(), AttemptEventLogError> {
        let Some(first) = self.tail.first() else {
            return Ok(());
        };
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

/// Largest number of segments one manifest may reference.
///
/// A manifest and its segments are published as the evidence children of one
/// measurement set, whose evidence set holds at most 4,096 objects.
pub const MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS: usize = 4_095;

/// The ordered segment references identifying one complete attempt log.
///
/// A manifest is valid only when its segments are non-empty, dense from
/// sequence zero, within the segment size bound, and its chain hash is the
/// chain over exactly those references. Construction and decoding both check
/// this, so holding a manifest proves its structure; reading entries through
/// [`Self::try_for_each_entry_in`] additionally authenticates each segment's
/// bytes against its reference.
#[derive(Clone, Debug, PartialEq, Eq)]
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
        source: &dyn AttemptLogSegmentSource,
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
        source: &dyn AttemptLogSegmentSource,
        visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), E>,
    ) -> Result<(), E> {
        self.try_for_each_entry_in(source, 0..self.entry_count, visit)
    }
}

/// Reads one segment from `source` and authenticates it.
fn read_segment(
    source: &(impl AttemptLogSegmentSource + ?Sized),
    segment: &AttemptLogSegmentRef,
) -> Result<Vec<SchedulerEventLogEntry>, AttemptEventLogError> {
    let bytes = source
        .segment(segment.id)
        .map_err(|source| AttemptEventLogError::Store { source })?;
    decode_segment(segment, &bytes)
}

/// Failure while visiting a segmented log's entries.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AttemptEventLogVisitError<E> {
    /// A sealed segment could not be read back.
    #[error(transparent)]
    Log(#[from] AttemptEventLogError),
    /// The visitor refused an entry.
    #[error("attempt event log visitor failed")]
    Visit(E),
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
pub(crate) fn empty_chain() -> ContentHash {
    ContentHash::from_canonical_material_bytes(ATTEMPT_LOG_CHAIN_DOMAIN, b"empty")
}

/// Extends `chain` by one sealed segment.
pub(crate) fn extend_chain(chain: ContentHash, segment: &AttemptLogSegmentRef) -> ContentHash {
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

fn encode_segment(
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
fn encoded_entry_len(entry: &SchedulerEventLogEntry) -> Result<usize, AttemptEventLogError> {
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

#[cfg(test)]
#[path = "attempt_event_log_tests.rs"]
mod tests;
