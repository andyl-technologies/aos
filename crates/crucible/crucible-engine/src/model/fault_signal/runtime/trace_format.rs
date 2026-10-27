//! Segment, manifest, and chain formats of the segmented resolved-effect trace.
//!
//! A resolved-effect trace holds one work item per evaluated scheduler
//! boundary or fault opportunity, so it grows with the attempt. It is retained
//! the way RFC-0020 section 15 retains the attempt event log: as sealed,
//! content-addressed segments named by one small manifest.
//!
//! ```text
//! segment   ContentId(trace, schema 1), at most 16 MiB:
//!   canonical CBOR { schema: 1, first_item: u64,
//!                    work_items: [ResolvedReplayWorkItem, ...] }   // dense, nonempty
//!
//! manifest  ContentId(trace, schema 4), at most 1 MiB:
//!   "crucible.resolved-effect-trace.v4\0" ++ canonical CBOR {
//!     mode, work_items: u64, records: u64, chain: ContentHash,
//!     segments: [{ id, first_item, item_count, records, encoded_bytes }, ...] }
//!
//! chain_0 = H("crucible.fault.resolved-effect-trace.chain.v1", "empty")
//! chain_i = H(domain, chain_(i-1) | segment id | first item | item count
//!                     | record count | encoded bytes)
//! ```
//!
//! A segment carries no replay mode, so one sealed segment serves a recomputed
//! and a locked replay of the same execution. The chain hash after the last
//! segment together with the item count identifies the complete item sequence,
//! and authenticating segments `1..i` authenticates the dense prefix they cover
//! without decoding any later segment.

use std::io::{self, Write};

use crucible_store::content_store::{ContentId, ObjectKind};
use serde::{Deserialize, Serialize};

use super::*;
use crate::segment_store::{MAX_MANIFEST_SEGMENTS, MAX_SEGMENT_BYTES, SEGMENT_TARGET_BYTES};

/// Trace-object schema of one encoded resolved-effect trace segment.
pub const RESOLVED_EFFECT_TRACE_SEGMENT_SCHEMA: u32 = 1;

/// Trace-object schema of a resolved-effect trace manifest.
pub const RESOLVED_EFFECT_TRACE_MANIFEST_SCHEMA: u32 = 4;

/// Largest encoded work item; a larger item fails its execution closed.
pub const MAX_RESOLVED_EFFECT_TRACE_ITEM_BYTES: usize = SEGMENT_TARGET_BYTES;

/// Largest encoded manifest any writer produces or reader accepts.
///
/// A manifest at [`MAX_MANIFEST_SEGMENTS`] segments encodes to well under this
/// bound, so the bound only refuses hostile input before it is decoded.
pub const MAX_RESOLVED_EFFECT_TRACE_MANIFEST_BYTES: usize = 1024 * 1024;

/// Owned bytes one decoded segment may allocate.
///
/// Decoding a segment can expand its at most 16 MiB of CBOR into larger Rust
/// values; this bound refuses an expansion beyond four times the wire size.
const MAX_DECODED_SEGMENT_BYTES: u64 = 4 * MAX_SEGMENT_BYTES as u64;

const MANIFEST_MAGIC: &[u8] = b"crucible.resolved-effect-trace.v4\0";
const CHAIN_DOMAIN: &str = "crucible.fault.resolved-effect-trace.chain.v1";

/// Reference to one sealed trace segment, retained in place of its items.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "SegmentRefWire", try_from = "SegmentRefWire")]
pub struct ResolvedEffectTraceSegmentRef {
    /// Trace content identity of the encoded segment.
    pub id: ContentId,
    /// Zero-based trace index of the segment's first work item.
    pub first_item: u64,
    /// Number of work items in the segment.
    pub item_count: u64,
    /// Number of resolved-effect records across the segment's work items.
    pub records: u64,
    /// Encoded segment size.
    pub encoded_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentRefWire {
    id: String,
    first_item: u64,
    item_count: u64,
    records: u64,
    encoded_bytes: u64,
}

impl From<ResolvedEffectTraceSegmentRef> for SegmentRefWire {
    fn from(segment: ResolvedEffectTraceSegmentRef) -> Self {
        Self {
            id: segment.id.encode(),
            first_item: segment.first_item,
            item_count: segment.item_count,
            records: segment.records,
            encoded_bytes: segment.encoded_bytes,
        }
    }
}

impl TryFrom<SegmentRefWire> for ResolvedEffectTraceSegmentRef {
    type Error = String;

    fn try_from(wire: SegmentRefWire) -> Result<Self, Self::Error> {
        let id = ContentId::parse(&wire.id)
            .map_err(|error| format!("trace segment identity is invalid: {error}"))?;
        if id.kind() != ObjectKind::Trace
            || id.schema_version() != RESOLVED_EFFECT_TRACE_SEGMENT_SCHEMA
        {
            return Err(String::from("trace segment identity has the wrong schema"));
        }
        Ok(Self {
            id,
            first_item: wire.first_item,
            item_count: wire.item_count,
            records: wire.records,
            encoded_bytes: wire.encoded_bytes,
        })
    }
}

impl ResolvedEffectTraceSegmentRef {
    /// Returns the trace index one past the segment's last work item.
    #[must_use]
    pub const fn end_item(&self) -> u64 {
        self.first_item.saturating_add(self.item_count)
    }
}

/// The ordered segment references identifying one complete trace.
///
/// A manifest is valid only when its segments are nonempty, dense from item
/// zero, within the segment size bound, and its totals and chain hash derive
/// from exactly those references. Construction and decoding both check this,
/// so holding a manifest proves its structure; reading items additionally
/// authenticates each segment's bytes against its reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "ManifestWire", try_from = "ManifestWire")]
pub struct ResolvedEffectTraceManifest {
    mode: FaultReplayMode,
    work_items: u64,
    records: u64,
    chain: ContentHash,
    segments: Vec<ResolvedEffectTraceSegmentRef>,
}

#[derive(Serialize)]
struct ManifestWireRef<'a> {
    mode: FaultReplayMode,
    work_items: u64,
    records: u64,
    chain: ContentHash,
    segments: &'a [ResolvedEffectTraceSegmentRef],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestWire {
    mode: FaultReplayMode,
    work_items: u64,
    records: u64,
    chain: ContentHash,
    #[serde(deserialize_with = "super::super::fallible_decode::deserialize_vec")]
    segments: Vec<ResolvedEffectTraceSegmentRef>,
}

impl From<ResolvedEffectTraceManifest> for ManifestWire {
    fn from(manifest: ResolvedEffectTraceManifest) -> Self {
        Self {
            mode: manifest.mode,
            work_items: manifest.work_items,
            records: manifest.records,
            chain: manifest.chain,
            segments: manifest.segments,
        }
    }
}

impl TryFrom<ManifestWire> for ResolvedEffectTraceManifest {
    type Error = FaultRuntimeError;

    fn try_from(wire: ManifestWire) -> Result<Self, Self::Error> {
        if wire.segments.len() > MAX_MANIFEST_SEGMENTS {
            return Err(invalid_manifest(format!(
                "{} segments",
                wire.segments.len()
            )));
        }
        let manifest = Self::new(wire.mode, wire.segments)?;
        if manifest.work_items != wire.work_items
            || manifest.records != wire.records
            || manifest.chain != wire.chain
        {
            return Err(invalid_manifest(String::from(
                "recorded totals do not match the segments",
            )));
        }
        Ok(manifest)
    }
}

impl ResolvedEffectTraceManifest {
    /// Builds a manifest over ordered segment references.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::InvalidReplayTrace`] for an unusable
    /// outcome-alignment mode, or [`FaultRuntimeError::InvalidTraceSegment`]
    /// when a segment is empty, oversized, of the wrong schema, or does not
    /// continue the dense item sequence, or when there are more than
    /// [`MAX_MANIFEST_SEGMENTS`] segments.
    pub fn new(
        mode: FaultReplayMode,
        segments: Vec<ResolvedEffectTraceSegmentRef>,
    ) -> Result<Self, FaultRuntimeError> {
        require_usable_mode(mode)?;
        if segments.len() > MAX_MANIFEST_SEGMENTS {
            return Err(invalid_manifest(format!("{} segments", segments.len())));
        }

        let mut work_items = 0_u64;
        let mut records = 0_u64;
        let mut chain = empty_chain();
        for segment in &segments {
            if segment.item_count == 0
                || segment.encoded_bytes == 0
                || segment.encoded_bytes > MAX_SEGMENT_BYTES as u64
                || segment.id.kind() != ObjectKind::Trace
                || segment.id.schema_version() != RESOLVED_EFFECT_TRACE_SEGMENT_SCHEMA
            {
                return Err(invalid_manifest(format!(
                    "segment {} is malformed",
                    segment.id
                )));
            }
            if segment.first_item != work_items {
                return Err(invalid_manifest(format!(
                    "segment {} starts at item {}, expected {work_items}",
                    segment.id, segment.first_item
                )));
            }
            work_items = work_items
                .checked_add(segment.item_count)
                .ok_or(FaultRuntimeError::CountOverflow("thin_replay_events"))?;
            records = records
                .checked_add(segment.records)
                .ok_or(FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
            chain = extend_chain(chain, segment);
        }
        Ok(Self {
            mode,
            work_items,
            records,
            chain,
            segments,
        })
    }

    /// Returns the manifest of a trace with no work items.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::InvalidReplayTrace`] for an unusable
    /// outcome-alignment mode.
    pub fn empty(mode: FaultReplayMode) -> Result<Self, FaultRuntimeError> {
        Self::new(mode, Vec::new())
    }

    /// Returns the same segments under another replay mode.
    ///
    /// Segments carry no mode, so a recomputed and a locked trace of one
    /// execution share every segment. Item-level mode constraints are checked
    /// whenever a reader decodes a segment.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::InvalidReplayTrace`] for an unusable
    /// outcome-alignment mode.
    pub fn with_mode(&self, mode: FaultReplayMode) -> Result<Self, FaultRuntimeError> {
        require_usable_mode(mode)?;
        Ok(Self {
            mode,
            ..self.clone()
        })
    }

    /// Returns the replay mode encoded in the reproduction artifact.
    #[must_use]
    pub const fn mode(&self) -> FaultReplayMode {
        self.mode
    }

    /// Returns the number of work items the trace holds.
    #[must_use]
    pub const fn work_items(&self) -> u64 {
        self.work_items
    }

    /// Returns the number of resolved-effect records across every work item.
    #[must_use]
    pub const fn records(&self) -> u64 {
        self.records
    }

    /// Returns the chain hash after the last segment.
    #[must_use]
    pub const fn chain(&self) -> ContentHash {
        self.chain
    }

    /// Returns the segment references in trace order.
    #[must_use]
    pub fn segments(&self) -> &[ResolvedEffectTraceSegmentRef] {
        &self.segments
    }

    /// Requires the trace to fit the scenario's replay counters.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::ResourceLimit`] when the work-item or
    /// record total exceeds `thin_replay_events` or `resolved_effect_records`.
    pub fn admit(&self, resource_limits: FaultResourceLimits) -> Result<(), FaultRuntimeError> {
        resource_limits
            .reserve("thin_replay_events", 0, self.work_items)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        resource_limits
            .reserve("resolved_effect_records", 0, self.records)
            .map_err(FaultRuntimeError::ResourceLimit)
    }

    /// Encodes the manifest leaf.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError::CheckpointEncoding`] when serialization
    /// fails or the leaf exceeds its format bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FaultRuntimeError> {
        let mut bytes = MANIFEST_MAGIC.to_vec();
        ciborium::ser::into_writer(
            &ManifestWireRef {
                mode: self.mode,
                work_items: self.work_items,
                records: self.records,
                chain: self.chain,
                segments: &self.segments,
            },
            &mut bytes,
        )
        .map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
        if bytes.len() > MAX_RESOLVED_EFFECT_TRACE_MANIFEST_BYTES {
            return Err(FaultRuntimeError::CheckpointEncoding);
        }
        Ok(bytes)
    }

    /// Decodes and validates one manifest leaf.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when the leaf exceeds its bound, lacks
    /// the version prefix, is not canonical, or its recorded totals or chain
    /// differ from the ones its segments derive.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, FaultRuntimeError> {
        if bytes.len() > MAX_RESOLVED_EFFECT_TRACE_MANIFEST_BYTES {
            return Err(invalid_manifest(format!("{} bytes", bytes.len())));
        }
        let payload = bytes
            .strip_prefix(MANIFEST_MAGIC)
            .ok_or(FaultRuntimeError::VersionOrIdentityMismatch)?;
        let wire: ManifestWire = ciborium::de::from_reader(payload)
            .map_err(|error| invalid_manifest(format!("decode: {error}")))?;
        let manifest = Self::try_from(wire)?;
        if manifest.canonical_bytes()? != bytes {
            return Err(invalid_manifest(String::from("encoding is not canonical")));
        }
        Ok(manifest)
    }

    /// Returns the trace-object identity of the manifest leaf.
    ///
    /// # Errors
    ///
    /// Returns the encoding failures of [`Self::canonical_bytes`].
    pub fn content_id(&self) -> Result<ContentId, FaultRuntimeError> {
        Ok(ContentId::for_bytes(
            ObjectKind::Trace,
            RESOLVED_EFFECT_TRACE_MANIFEST_SCHEMA,
            &self.canonical_bytes()?,
        ))
    }

    /// Returns the segment identities in trace order.
    pub fn segment_ids(&self) -> impl Iterator<Item = ContentId> + '_ {
        self.segments.iter().map(|segment| segment.id)
    }
}

/// Returns the trace content identity of one encoded segment.
///
/// Carriers that store segments by another key, such as an exact checkpoint
/// closure, recompute the identity a trace position names from the bytes.
#[must_use]
pub fn resolved_effect_trace_segment_id(bytes: &[u8]) -> ContentId {
    ContentId::for_bytes(
        ObjectKind::Trace,
        RESOLVED_EFFECT_TRACE_SEGMENT_SCHEMA,
        bytes,
    )
}

/// Decodes and authenticates one stored segment against its reference.
///
/// # Errors
///
/// Returns [`FaultRuntimeError::InvalidTraceSegment`] when the bytes exceed
/// the format bound, do not derive the referenced identity, are not canonical
/// CBOR of the segment schema, carry items that disagree with the reference,
/// or carry an invalid work item.
pub fn decode_resolved_effect_trace_segment(
    segment: &ResolvedEffectTraceSegmentRef,
    bytes: &[u8],
) -> Result<Vec<ResolvedReplayWorkItem>, FaultRuntimeError> {
    let invalid = |reason: String| FaultRuntimeError::InvalidTraceSegment {
        segment: segment.id.encode(),
        reason,
    };
    if bytes.len() > MAX_SEGMENT_BYTES || bytes.len() as u64 != segment.encoded_bytes {
        return Err(invalid(format!("unexpected length {}", bytes.len())));
    }
    if !segment.id.authenticates(bytes) {
        return Err(invalid(String::from(
            "bytes do not derive the segment identity",
        )));
    }

    let wire = decode_segment_wire(bytes).map_err(|error| invalid(format!("decode: {error}")))?;
    if wire.schema != RESOLVED_EFFECT_TRACE_SEGMENT_SCHEMA
        || wire.first_item != segment.first_item
        || wire.work_items.len() as u64 != segment.item_count
        || wire.work_items.is_empty()
    {
        return Err(invalid(String::from("header does not match its reference")));
    }
    let mut records = 0_u64;
    for item in &wire.work_items {
        item.validate()
            .map_err(|error| invalid(format!("work item: {error}")))?;
        records = records.saturating_add(item.records.len() as u64);
    }
    if records != segment.records {
        return Err(invalid(String::from("record count does not match")));
    }
    if encode_segment(wire.first_item, &wire.work_items)? != bytes {
        return Err(invalid(String::from("encoding is not canonical")));
    }
    Ok(wire.work_items)
}

/// Requires one decoded work item to satisfy its trace's replay mode.
pub(super) fn require_mode_item(
    mode: FaultReplayMode,
    item: &ResolvedReplayWorkItem,
) -> Result<(), FaultRuntimeError> {
    if matches!(mode, FaultReplayMode::OutcomeOnlyNetwork(_))
        && (item.network_frame_key.is_none()
            || item
                .records
                .iter()
                .any(|record| record.effect.descriptor().adapter != FaultAdapter::Network))
    {
        return Err(FaultRuntimeError::InvalidReplayTrace);
    }
    Ok(())
}

fn require_usable_mode(mode: FaultReplayMode) -> Result<(), FaultRuntimeError> {
    if matches!(
        mode,
        FaultReplayMode::OutcomeOnlyNetwork(NetworkOutcomeAlignment::OrderedTimeBucket {
            width_nanos: 0
        })
    ) {
        return Err(FaultRuntimeError::InvalidReplayTrace);
    }
    Ok(())
}

fn invalid_manifest(reason: String) -> FaultRuntimeError {
    FaultRuntimeError::InvalidTraceSegment {
        segment: String::from("manifest"),
        reason,
    }
}

/// Returns the chain hash of an empty trace.
pub(super) fn empty_chain() -> ContentHash {
    ContentHash::from_canonical_material_bytes(CHAIN_DOMAIN, b"empty")
}

/// Extends `chain` by one sealed segment.
pub(super) fn extend_chain(
    chain: ContentHash,
    segment: &ResolvedEffectTraceSegmentRef,
) -> ContentHash {
    let segment_id = segment.id.encode();
    let mut material = Vec::with_capacity(32 + segment_id.len() + 32);
    material.extend_from_slice(&chain.bytes);
    material.extend_from_slice(segment_id.as_bytes());
    material.extend_from_slice(&segment.first_item.to_le_bytes());
    material.extend_from_slice(&segment.item_count.to_le_bytes());
    material.extend_from_slice(&segment.records.to_le_bytes());
    material.extend_from_slice(&segment.encoded_bytes.to_le_bytes());
    ContentHash::from_canonical_material_bytes(CHAIN_DOMAIN, &material)
}

#[derive(Serialize)]
struct SegmentWireRef<'a> {
    schema: u32,
    first_item: u64,
    work_items: &'a [ResolvedReplayWorkItem],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentWire {
    schema: u32,
    first_item: u64,
    #[serde(deserialize_with = "super::super::fallible_decode::deserialize_vec")]
    work_items: Vec<ResolvedReplayWorkItem>,
}

/// Encodes one segment from its first item index and dense items.
pub(super) fn encode_segment(
    first_item: u64,
    work_items: &[ResolvedReplayWorkItem],
) -> Result<Vec<u8>, FaultRuntimeError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(
        &SegmentWireRef {
            schema: RESOLVED_EFFECT_TRACE_SEGMENT_SCHEMA,
            first_item,
            work_items,
        },
        &mut bytes,
    )
    .map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
    if bytes.len() > MAX_SEGMENT_BYTES {
        return Err(FaultRuntimeError::CheckpointEncoding);
    }
    Ok(bytes)
}

fn decode_segment_wire(bytes: &[u8]) -> Result<SegmentWire, FaultRuntimeError> {
    let mut limits = FaultResourceLimits::compiled_maximum();
    limits.fat_checkpoint_bytes = MAX_DECODED_SEGMENT_BYTES;
    let scratch_bytes = super::trace_codec::scratch_bytes(bytes)?;
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(scratch_bytes)
        .map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
    scratch.resize(scratch_bytes, 0);
    let _budget = super::super::fallible_decode::DecodeBudgetGuard::enter(limits);
    ciborium::de::from_reader_with_buffer(bytes, &mut scratch)
        .map_err(super::trace_codec::map_decode_error)
}

/// Counts one work item's CBOR encoding without retaining the bytes.
pub(super) fn encoded_item_len(item: &ResolvedReplayWorkItem) -> Result<usize, FaultRuntimeError> {
    let mut counter = ByteCounter(0);
    ciborium::ser::into_writer(item, &mut counter)
        .map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
    Ok(counter.0)
}

/// Write sink that only counts the bytes a serializer produces.
pub(super) struct ByteCounter(pub(super) usize);

impl Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
