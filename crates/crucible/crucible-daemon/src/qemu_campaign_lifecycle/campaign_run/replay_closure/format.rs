//! Canonical root, frame, and bundle encodings of a version 2 replay closure.
//!
//! A closure is a small root plus an ordered list of frames. The root names
//! every frame by length and digest, so it authenticates the whole closure
//! by itself, and every frame is a separate object of at most
//! [`MAX_REPLAY_CLOSURE_FRAME_BYTES`]. No carrier or store has to hold the
//! closure as one value:
//!
//! ```text
//! root:
//!   magic         8 bytes, "CCRC\0\0\0\x02"
//!   entry_count   u64 little-endian
//!   record_count  u64 little-endian
//!   frame_count   u32 little-endian
//!   frames        frame_count repetitions of:
//!     kind        u8: 1 = selection entries, 2 = choice records
//!     item_count  u32 little-endian, 1..=4,096
//!     length      u32 little-endian encoded frame bytes
//!     digest      32 bytes: the frame's observation schema 1 content digest
//!
//! frame:
//!   magic         8 bytes, "CCRF\0\0\0\x02"
//!   kind          u8, as in the root
//!   item_count    u32 little-endian, equal to the root's count
//!   items         item_count repetitions of one of:
//!     entry:      selection identity digest (32 bytes), then the domain,
//!                 declaration, and opportunity record ordinals (u64 each)
//!     record:     record kind u8 (1 = domain, 2 = declaration,
//!                 3 = opportunity), u32 little-endian length, canonical bytes
//!
//! bundle (one-buffer carriers only):
//!   magic         8 bytes, "CCRB\0\0\0\x02"
//!   object_count  u32 little-endian, 1 + the root's frame_count
//!   objects       object_count repetitions of a u32 little-endian length
//!                 and the bytes of the root, then of each frame in order
//! ```
//!
//! Entries follow the covered schedule selection decisions in order, one per
//! decision. Records are numbered by first reference: each entry references
//! its domain, then its declaration, then its opportunity, and a record not
//! referenced before takes the next ordinal. Records are packed greedily
//! into record frames in ordinal order. An entry frame holds 4,096 entries,
//! except the last; before it is written the open record frame is closed, so
//! every record lives in a record frame before the first entry frame that
//! references it. `ClosureBuilder` is the one encoder, and decoders prove
//! canonical form by re-encoding.

use std::ops::Range;
use std::sync::Arc;

use crucible_store::content_store::{ContentId, ObjectKind};

use super::GuardedCampaignReplayClosureError;

/// Largest encoded frame, the ordinary component-message bound.
pub(crate) const MAX_REPLAY_CLOSURE_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// Most frames one closure may hold.
///
/// The bound keeps a root, and an exact-checkpoint root that names every
/// frame as a child, within one content envelope. It admits 67 million
/// selection entries, more than a configuration artifact's payload ceiling
/// can name.
pub(crate) const MAX_REPLAY_CLOSURE_FRAMES: usize = 32_768;

/// Largest encoded root.
pub(crate) const MAX_REPLAY_CLOSURE_ROOT_BYTES: usize =
    ROOT_HEADER_BYTES + MAX_REPLAY_CLOSURE_FRAMES * ROOT_FRAME_BYTES;

/// Object kind of root and frame content identities.
pub(crate) const REPLAY_CLOSURE_OBJECT_KIND: ObjectKind = ObjectKind::Observation;

/// Schema version of root and frame content identities.
///
/// The format version lives in each object's magic; the identity schema
/// stays the raw-protocol observation schema that exact-checkpoint closure
/// walkers accept for opaque root children.
pub(crate) const REPLAY_CLOSURE_OBJECT_SCHEMA_VERSION: u32 = 1;

/// Most items one frame may hold.
pub(super) const MAX_FRAME_ITEMS: usize = 4_096;
pub(super) const FRAME_HEADER_BYTES: usize = 8 + 1 + 4;
pub(super) const ENTRY_BYTES: usize = 32 + 3 * 8;
pub(super) const RECORD_HEADER_BYTES: usize = 1 + 4;

const ROOT_MAGIC: &[u8; 8] = b"CCRC\0\0\0\x02";
const FRAME_MAGIC: &[u8; 8] = b"CCRF\0\0\0\x02";
const BUNDLE_MAGIC: &[u8; 8] = b"CCRB\0\0\0\x02";
const ROOT_HEADER_BYTES: usize = 8 + 8 + 8 + 4;
const ROOT_FRAME_BYTES: usize = 1 + 4 + 4 + 32;

/// Returns the content identity of one encoded root or frame.
pub(crate) fn closure_object_id(bytes: &[u8]) -> ContentId {
    ContentId::for_bytes(
        REPLAY_CLOSURE_OBJECT_KIND,
        REPLAY_CLOSURE_OBJECT_SCHEMA_VERSION,
        bytes,
    )
}

/// What one frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FrameKind {
    Entries,
    Records,
}

impl FrameKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Entries => 1,
            Self::Records => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, GuardedCampaignReplayClosureError> {
        match tag {
            1 => Ok(Self::Entries),
            2 => Ok(Self::Records),
            _ => Err(invalid("replay closure frame kind is unknown")),
        }
    }
}

/// The kind of one choice record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum RecordKind {
    Domain,
    Declaration,
    Opportunity,
}

impl RecordKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Domain => 1,
            Self::Declaration => 2,
            Self::Opportunity => 3,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, GuardedCampaignReplayClosureError> {
        match tag {
            1 => Ok(Self::Domain),
            2 => Ok(Self::Declaration),
            3 => Ok(Self::Opportunity),
            _ => Err(invalid("replay closure record kind is unknown")),
        }
    }
}

/// One selection decision and the ordinals of the records it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    /// Digest of the selection's content identity.
    pub(super) selection: [u8; 32],
    pub(super) domain: u64,
    pub(super) declaration: u64,
    pub(super) opportunity: u64,
}

/// One frame's place in the closure, as the root declares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FrameSummary {
    pub(super) kind: FrameKind,
    pub(super) count: u32,
    pub(super) length: u32,
    pub(super) digest: [u8; 32],
    /// Ordinal of the first entry or record the frame holds.
    pub(super) first: u64,
}

impl FrameSummary {
    /// Returns the frame's content identity.
    pub(super) const fn id(&self) -> ContentId {
        ContentId::from_parts(
            REPLAY_CLOSURE_OBJECT_KIND,
            REPLAY_CLOSURE_OBJECT_SCHEMA_VERSION,
            self.digest,
        )
    }

    /// Returns the ordinal after the frame's last item.
    pub(super) const fn end(&self) -> u64 {
        // The root decoder proved that every frame's range fits in u64.
        self.first + self.count as u64
    }
}

/// A decoded root: counts, the frame table, and per-kind frame indexes.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ClosureRoot {
    pub(super) entry_count: u64,
    pub(super) record_count: u64,
    pub(super) frames: Vec<FrameSummary>,
    pub(super) bytes: Arc<[u8]>,
    entry_frames: Vec<usize>,
    record_frames: Vec<usize>,
}

impl ClosureRoot {
    /// Returns the root of the closure that covers no selection.
    pub(super) fn empty() -> Self {
        let mut bytes = Vec::with_capacity(ROOT_HEADER_BYTES);
        bytes.extend_from_slice(ROOT_MAGIC);
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        Self {
            entry_count: 0,
            record_count: 0,
            frames: Vec::new(),
            bytes: bytes.into(),
            entry_frames: Vec::new(),
            record_frames: Vec::new(),
        }
    }

    /// Encodes the root of frames already encoded in canonical order.
    pub(super) fn encode(
        frames: &[(FrameKind, u32, u32, [u8; 32])],
    ) -> Result<Self, GuardedCampaignReplayClosureError> {
        if frames.len() > MAX_REPLAY_CLOSURE_FRAMES {
            return Err(invalid("replay closure exceeds its frame bound"));
        }
        let count_items = |kind| {
            frames
                .iter()
                .filter(|frame| frame.0 == kind)
                .map(|frame| u64::from(frame.1))
                .sum::<u64>()
        };

        let mut bytes = Vec::with_capacity(ROOT_HEADER_BYTES + frames.len() * ROOT_FRAME_BYTES);
        bytes.extend_from_slice(ROOT_MAGIC);
        bytes.extend_from_slice(&count_items(FrameKind::Entries).to_le_bytes());
        bytes.extend_from_slice(&count_items(FrameKind::Records).to_le_bytes());
        bytes.extend_from_slice(&to_u32(frames.len())?.to_le_bytes());
        for (kind, count, length, digest) in frames {
            bytes.push(kind.tag());
            bytes.extend_from_slice(&count.to_le_bytes());
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(digest);
        }
        Self::decode(bytes.into())
    }

    /// Decodes and checks one root.
    ///
    /// Beyond its framing, a root must keep every entry frame but the last
    /// full and end with an entry frame, because records exist only for the
    /// entries after them.
    pub(super) fn decode(bytes: Arc<[u8]>) -> Result<Self, GuardedCampaignReplayClosureError> {
        if bytes.len() > MAX_REPLAY_CLOSURE_ROOT_BYTES {
            return Err(invalid("replay closure root exceeds its byte bound"));
        }
        let mut reader = Reader::new(&bytes);
        reader.magic(ROOT_MAGIC, "replay closure root has an invalid header")?;
        let entry_count = reader.u64()?;
        let record_count = reader.u64()?;
        let frame_count = reader.u32()? as usize;
        if frame_count > MAX_REPLAY_CLOSURE_FRAMES {
            return Err(invalid("replay closure exceeds its frame bound"));
        }

        let mut frames = Vec::with_capacity(frame_count);
        let mut entry_frames = Vec::new();
        let mut record_frames = Vec::new();
        let mut next_entry = 0_u64;
        let mut next_record = 0_u64;
        let mut partial_entry_frame = false;
        for index in 0..frame_count {
            let kind = FrameKind::from_tag(reader.u8()?)?;
            let count = reader.u32()?;
            let length = reader.u32()?;
            let mut digest = [0_u8; 32];
            digest.copy_from_slice(reader.take(32)?);
            if count == 0 || count as usize > MAX_FRAME_ITEMS {
                return Err(invalid("replay closure frame item count is out of range"));
            }
            if length as usize > MAX_REPLAY_CLOSURE_FRAME_BYTES {
                return Err(invalid("replay closure frame exceeds its byte bound"));
            }
            if partial_entry_frame {
                return Err(invalid("replay closure entry frame is not full"));
            }

            let (next, indexes) = match kind {
                FrameKind::Entries => {
                    partial_entry_frame = count as usize != MAX_FRAME_ITEMS;
                    (&mut next_entry, &mut entry_frames)
                }
                FrameKind::Records => (&mut next_record, &mut record_frames),
            };
            let first = *next;
            *next = first
                .checked_add(u64::from(count))
                .ok_or_else(|| invalid("replay closure item count overflowed"))?;
            indexes.push(index);
            frames.push(FrameSummary {
                kind,
                count,
                length,
                digest,
                first,
            });
        }
        reader.finish()?;

        if frames
            .last()
            .is_some_and(|frame| frame.kind != FrameKind::Entries)
        {
            return Err(invalid("replay closure ends with unreferenced records"));
        }
        if next_entry != entry_count || next_record != record_count {
            return Err(invalid("replay closure root counts differ from its frames"));
        }

        Ok(Self {
            entry_count,
            record_count,
            frames,
            bytes,
            entry_frames,
            record_frames,
        })
    }

    /// Returns the index of the frame holding entry `ordinal`.
    pub(super) fn entry_frame(&self, ordinal: u64) -> Option<usize> {
        self.frame_holding(&self.entry_frames, ordinal)
    }

    /// Returns the index of the frame holding record `ordinal`.
    pub(super) fn record_frame(&self, ordinal: u64) -> Option<usize> {
        self.frame_holding(&self.record_frames, ordinal)
    }

    fn frame_holding(&self, indexes: &[usize], ordinal: u64) -> Option<usize> {
        // Frames of one kind hold consecutive ordinals in frame order.
        let after = indexes.partition_point(|index| self.frames[*index].first <= ordinal);
        let index = *indexes.get(after.checked_sub(1)?)?;
        (ordinal < self.frames[index].end()).then_some(index)
    }
}

fn to_u32(value: usize) -> Result<u32, GuardedCampaignReplayClosureError> {
    u32::try_from(value).map_err(|_| invalid("replay closure length cannot be represented"))
}

/// Encodes one entry frame.
pub(super) fn encode_entry_frame(entries: &[Entry]) -> Vec<u8> {
    let mut bytes = frame_header(
        FrameKind::Entries,
        entries.len(),
        entries.len() * ENTRY_BYTES,
    );
    for entry in entries {
        bytes.extend_from_slice(&entry.selection);
        bytes.extend_from_slice(&entry.domain.to_le_bytes());
        bytes.extend_from_slice(&entry.declaration.to_le_bytes());
        bytes.extend_from_slice(&entry.opportunity.to_le_bytes());
    }
    bytes
}

/// Starts a frame of `count` items whose `body` bytes follow the header.
pub(super) fn frame_header(kind: FrameKind, count: usize, body: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FRAME_HEADER_BYTES + body);
    bytes.extend_from_slice(FRAME_MAGIC);
    bytes.push(kind.tag());
    // Builders close a frame at MAX_FRAME_ITEMS items.
    bytes.extend_from_slice(&(count as u32).to_le_bytes());
    bytes
}

/// Rewrites the item count of a record frame built incrementally.
pub(super) fn set_frame_count(frame: &mut [u8], count: usize) {
    // Builders close a frame at MAX_FRAME_ITEMS items.
    frame[9..FRAME_HEADER_BYTES].copy_from_slice(&(count as u32).to_le_bytes());
}

/// Appends one record item to a record frame.
pub(super) fn append_record(frame: &mut Vec<u8>, kind: RecordKind, record: &[u8]) {
    frame.push(kind.tag());
    // Builders admit only records that fit one frame.
    frame.extend_from_slice(&(record.len() as u32).to_le_bytes());
    frame.extend_from_slice(record);
}

/// Decodes the entries of one entry frame the root declared.
pub(super) fn decode_entry_frame(
    bytes: &[u8],
    summary: &FrameSummary,
) -> Result<Vec<Entry>, GuardedCampaignReplayClosureError> {
    let mut reader = frame_reader(bytes, summary, FrameKind::Entries)?;
    let mut entries = Vec::with_capacity(summary.count as usize);
    for _ in 0..summary.count {
        let mut selection = [0_u8; 32];
        selection.copy_from_slice(reader.take(32)?);
        entries.push(Entry {
            selection,
            domain: reader.u64()?,
            declaration: reader.u64()?,
            opportunity: reader.u64()?,
        });
    }
    reader.finish()?;
    Ok(entries)
}

/// Locates the records of one record frame the root declared.
///
/// Returns each record's kind and byte range within `bytes`.
pub(super) fn decode_record_frame(
    bytes: &[u8],
    summary: &FrameSummary,
) -> Result<Vec<(RecordKind, Range<usize>)>, GuardedCampaignReplayClosureError> {
    let mut reader = frame_reader(bytes, summary, FrameKind::Records)?;
    let mut records = Vec::with_capacity(summary.count as usize);
    for _ in 0..summary.count {
        let kind = RecordKind::from_tag(reader.u8()?)?;
        let length = reader.u32()? as usize;
        let start = reader.cursor;
        reader.take(length)?;
        records.push((kind, start..reader.cursor));
    }
    reader.finish()?;
    Ok(records)
}

fn frame_reader<'a>(
    bytes: &'a [u8],
    summary: &FrameSummary,
    expected: FrameKind,
) -> Result<Reader<'a>, GuardedCampaignReplayClosureError> {
    let mut reader = Reader::new(bytes);
    reader.magic(FRAME_MAGIC, "replay closure frame has an invalid header")?;
    let kind = FrameKind::from_tag(reader.u8()?)?;
    let count = reader.u32()?;
    if kind != expected || kind != summary.kind || count != summary.count {
        return Err(invalid("replay closure frame differs from its root entry"));
    }
    Ok(reader)
}

/// Encodes a root and its frames as one buffer.
pub(super) fn encode_bundle(
    root: &[u8],
    frames: &[Arc<[u8]>],
) -> Result<Vec<u8>, GuardedCampaignReplayClosureError> {
    let objects = to_u32(frames.len().saturating_add(1))?;
    let length = std::iter::once(root.len())
        .chain(frames.iter().map(|frame| frame.len()))
        .try_fold(BUNDLE_MAGIC.len() + 4, |total: usize, object| {
            total.checked_add(4)?.checked_add(object)
        })
        .ok_or_else(|| invalid("replay closure bundle size overflowed"))?;

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(GuardedCampaignReplayClosureError::Allocation)?;
    bytes.extend_from_slice(BUNDLE_MAGIC);
    bytes.extend_from_slice(&objects.to_le_bytes());
    for object in std::iter::once(root).chain(frames.iter().map(|frame| &frame[..])) {
        bytes.extend_from_slice(&to_u32(object.len())?.to_le_bytes());
        bytes.extend_from_slice(object);
    }
    Ok(bytes)
}

/// A bundle's root bytes and frame bytes, in order.
pub(super) type BundleParts = (Arc<[u8]>, Vec<Arc<[u8]>>);

/// Splits one buffer into the root and frames it carries.
///
/// Only the bundle framing and per-object bounds are checked here; the
/// caller authenticates each frame against the decoded root.
pub(super) fn decode_bundle(
    bytes: &[u8],
) -> Result<BundleParts, GuardedCampaignReplayClosureError> {
    let mut reader = Reader::new(bytes);
    reader.magic(BUNDLE_MAGIC, "replay closure bundle has an invalid header")?;
    let objects = reader.u32()? as usize;
    if objects == 0 || objects > MAX_REPLAY_CLOSURE_FRAMES + 1 {
        return Err(invalid(
            "replay closure bundle object count is out of range",
        ));
    }

    let root_length = reader.u32()? as usize;
    if root_length > MAX_REPLAY_CLOSURE_ROOT_BYTES {
        return Err(invalid("replay closure root exceeds its byte bound"));
    }
    let root = Arc::from(reader.take(root_length)?);
    let mut frames = Vec::with_capacity(objects - 1);
    for _ in 1..objects {
        let length = reader.u32()? as usize;
        if length > MAX_REPLAY_CLOSURE_FRAME_BYTES {
            return Err(invalid("replay closure frame exceeds its byte bound"));
        }
        frames.push(Arc::from(reader.take(length)?));
    }
    reader.finish()?;
    Ok((root, frames))
}

/// Bounds-checked little-endian reader over one encoded object.
struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn magic(
        &mut self,
        expected: &[u8; 8],
        reason: &'static str,
    ) -> Result<(), GuardedCampaignReplayClosureError> {
        if self.bytes.get(..expected.len()) != Some(expected.as_slice()) {
            return Err(invalid(reason));
        }
        self.cursor = expected.len();
        Ok(())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], GuardedCampaignReplayClosureError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or_else(|| invalid("replay closure offset overflowed"))?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| invalid("replay closure object is truncated"))?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, GuardedCampaignReplayClosureError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, GuardedCampaignReplayClosureError> {
        let mut value = [0_u8; 4];
        value.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(value))
    }

    fn u64(&mut self) -> Result<u64, GuardedCampaignReplayClosureError> {
        let mut value = [0_u8; 8];
        value.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(value))
    }

    fn finish(self) -> Result<(), GuardedCampaignReplayClosureError> {
        if self.cursor != self.bytes.len() {
            return Err(invalid("replay closure object has trailing bytes"));
        }
        Ok(())
    }
}

pub(super) const fn invalid(reason: &'static str) -> GuardedCampaignReplayClosureError {
    GuardedCampaignReplayClosureError::Invalid { reason }
}
