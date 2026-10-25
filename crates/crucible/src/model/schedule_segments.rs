//! Segmented storage and transport of a schedule's decisions.
//!
//! A live scheduler appends decisions for every quantum that delivers events,
//! draws network or device randomness, or preempts a vCPU, so a schedule grows
//! with virtual time exactly as the attempt event log does. It is therefore
//! stored the way RFC-0020 section 15 stores that log: as sealed,
//! content-addressed segments named by one small manifest.
//!
//! ```text
//! segment   ContentId(trace, schema 2):
//!   "crucible.schedule-segment.v2\0"
//!   u64 first-decision, u64 decision-count, decision{decision-count}
//!                                         // dense, nonempty, addressed decision codec
//!
//! manifest  at most 1 MiB:
//!   "crucible.schedule-manifest.v1\0"
//!   hash schedule-content-hash, u64 decision-count, hash chain,
//!   u64 segment-count,
//!   { digest segment, u64 first-decision, u64 decision-count, u64 encoded-bytes }*
//!
//! schedule v6 (self-contained transport):
//!   "crucible.schedule.v6\0" blob manifest, blob segment{segment-count}
//!
//! chain_0 = H("crucible.schedule.segment-chain.v1", "empty")
//! chain_i = H(domain, chain_(i-1) | segment digest | first decision
//!                     | decision count | encoded bytes)
//! ```
//!
//! A writer seals before an append would make the open segment's encoding
//! exceed [`SEGMENT_TARGET_BYTES`] and never for any other reason, so the
//! segment boundaries are a pure function of the decision sequence. No segment
//! exceeds [`MAX_SEGMENT_BYTES`], so one decision encodes to at most that bound
//! less the segment header. A schedule that cannot be segmented, because one
//! decision exceeds that bound or the schedule needs more than
//! [`MAX_MANIFEST_SEGMENTS`] segments, fails every fallible writer, and its
//! infallible transport encoding is refused by every reader.
//!
//! Boundaries never enter schedule identity: [`Schedule::content_hash`] is
//! computed over the decisions, and the manifest records it so a reader
//! authenticates the reassembled schedule. Readers decode one segment at a
//! time, so the generic per-collection decoder bound applies to one segment
//! and never limits schedule length.

use crucible_cas::content_store::{ContentId, ObjectKind};

use super::*;
use crate::segment_store::{
    MAX_MANIFEST_SEGMENTS, MAX_SEGMENT_BYTES, SEGMENT_TARGET_BYTES, SegmentSink, SegmentSource,
};

/// Trace-object schema of one encoded schedule segment.
pub const SCHEDULE_SEGMENT_SCHEMA: u32 = 2;

/// Largest encoded schedule manifest any writer produces or reader accepts.
///
/// A manifest at [`MAX_MANIFEST_SEGMENTS`] segments encodes to well under this
/// bound, so the bound only refuses hostile input before it is decoded.
pub const MAX_SCHEDULE_MANIFEST_BYTES: usize = 1024 * 1024;

pub(super) const SCHEDULE_BINARY_MAGIC_V6: &[u8] = b"crucible.schedule.v6\0";
const SEGMENT_MAGIC: &[u8] = b"crucible.schedule-segment.v2\0";
const MANIFEST_MAGIC: &[u8] = b"crucible.schedule-manifest.v1\0";
const CHAIN_DOMAIN: &str = "crucible.schedule.segment-chain.v1";

/// Encoded size of a segment header: magic, first decision, decision count.
const SEGMENT_HEADER_BYTES: usize = SEGMENT_MAGIC.len() + 16;

/// Reference to one sealed schedule segment, retained in place of its decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScheduleSegmentRef {
    /// Trace content identity of the encoded segment.
    pub id: ContentId,
    /// Zero-based schedule index of the segment's first decision.
    pub first_decision: u64,
    /// Number of decisions in the segment.
    pub decision_count: u64,
    /// Encoded segment size.
    pub encoded_bytes: u64,
}

impl ScheduleSegmentRef {
    /// Returns the schedule index one past the segment's last decision.
    #[must_use]
    pub const fn end_decision(&self) -> u64 {
        self.first_decision.saturating_add(self.decision_count)
    }
}

/// The ordered segment references identifying one complete schedule.
///
/// A manifest is valid only when its segments are nonempty, dense from
/// decision zero, within their size bounds, and its decision count and chain
/// derive from exactly those references. Construction and decoding both check
/// this; reading decisions additionally authenticates every segment's bytes
/// against its reference and the reassembled schedule against the recorded
/// schedule content hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScheduleManifest {
    schedule: ContentHash,
    decision_count: u64,
    chain: ContentHash,
    segments: Vec<ScheduleSegmentRef>,
}

impl ScheduleManifest {
    /// Builds a manifest over ordered segment references.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when a segment is empty,
    /// oversized, of another object kind, or does not continue the dense
    /// sequence from zero, or when there are more than
    /// [`MAX_MANIFEST_SEGMENTS`] segments.
    pub fn new(
        schedule: ContentHash,
        segments: Vec<ScheduleSegmentRef>,
    ) -> Result<Self, EngineError> {
        if segments.len() > MAX_MANIFEST_SEGMENTS {
            return Err(scenario_serialization_error(format!(
                "schedule manifest names {} segments, above the {MAX_MANIFEST_SEGMENTS}-segment limit",
                segments.len()
            )));
        }

        let mut decision_count = 0_u64;
        let mut chain = empty_chain();
        for segment in &segments {
            validate_segment_ref(segment)?;
            if segment.first_decision != decision_count {
                return Err(scenario_serialization_error(format!(
                    "schedule segment starts at decision {}, expected {decision_count}",
                    segment.first_decision
                )));
            }
            decision_count = decision_count
                .checked_add(segment.decision_count)
                .ok_or_else(|| scenario_serialization_error("schedule decision count overflows"))?;
            chain = extend_chain(chain, segment);
        }
        Ok(Self {
            schedule,
            decision_count,
            chain,
            segments,
        })
    }

    /// Returns the content hash of the schedule this manifest names.
    #[must_use]
    pub const fn schedule_hash(&self) -> ContentHash {
        self.schedule
    }

    /// Returns the number of decisions the schedule holds.
    #[must_use]
    pub const fn decision_count(&self) -> u64 {
        self.decision_count
    }

    /// Returns the chain hash after the last segment.
    #[must_use]
    pub const fn chain(&self) -> ContentHash {
        self.chain
    }

    /// Returns the segment references in schedule order.
    #[must_use]
    pub fn segments(&self) -> &[ScheduleSegmentRef] {
        &self.segments
    }

    /// Returns the total encoded bytes of every referenced segment.
    #[must_use]
    pub fn segment_bytes(&self) -> u64 {
        self.segments
            .iter()
            .map(|segment| segment.encoded_bytes)
            .fold(0, u64::saturating_add)
    }

    /// Serializes this manifest as canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(MANIFEST_MAGIC);
        writer.write_hash(self.schedule);
        writer.write_u64(self.decision_count);
        writer.write_hash(self.chain);
        writer.write_count(self.segments.len());
        for segment in &self.segments {
            writer.bytes.extend_from_slice(&segment.id.digest());
            writer.write_u64(segment.first_decision);
            writer.write_u64(segment.decision_count);
            writer.write_u64(segment.encoded_bytes);
        }
        writer.finish()
    }

    /// Parses and validates canonical manifest bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for oversized,
    /// malformed, or noncanonical bytes, for references that do not form a
    /// valid manifest, or when the recorded decision count or chain differs
    /// from the one the references derive.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EngineError> {
        if bytes.len() > MAX_SCHEDULE_MANIFEST_BYTES {
            return Err(scenario_serialization_error(
                "schedule manifest exceeds its encoded size limit",
            ));
        }
        let mut reader = ScenarioBinaryReader::new(bytes, MANIFEST_MAGIC)?;
        let schedule = reader.read_hash()?;
        let decision_count = reader.read_u64()?;
        let chain = reader.read_hash()?;
        let count = reader.read_collection_count("schedule-manifest.segment")?;
        if count > MAX_MANIFEST_SEGMENTS {
            return Err(scenario_serialization_error(
                "schedule manifest segment count exceeds its limit",
            ));
        }
        let mut segments = Vec::with_capacity(count);
        for _ in 0..count {
            let digest = reader.read_hash()?.bytes;
            segments.push(ScheduleSegmentRef {
                id: ContentId::from_parts(ObjectKind::Trace, SCHEDULE_SEGMENT_SCHEMA, digest),
                first_decision: reader.read_u64()?,
                decision_count: reader.read_u64()?,
                encoded_bytes: reader.read_u64()?,
            });
        }
        reader.finish()?;

        let manifest = Self::new(schedule, segments)?;
        if manifest.decision_count != decision_count || manifest.chain != chain {
            return Err(scenario_serialization_error(
                "schedule manifest totals do not match its segments",
            ));
        }
        Ok(manifest)
    }

    /// Visits every decision in order, reading one segment at a time.
    ///
    /// Each segment is authenticated against its reference before any of its
    /// decisions is visited. The visit does not check the schedule content
    /// hash; [`Self::read_schedule`] does.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when a segment is
    /// missing or fails authentication or decoding, or the first error
    /// `visit` returns.
    pub fn try_for_each_decision(
        &self,
        source: &dyn SegmentSource,
        mut visit: impl FnMut(Decision) -> Result<(), EngineError>,
    ) -> Result<(), EngineError> {
        for segment in &self.segments {
            let bytes = source.segment(segment.id).map_err(|error| {
                scenario_serialization_error(format!(
                    "schedule segment {} is unavailable: {error}",
                    segment.id
                ))
            })?;
            for decision in decode_segment(segment, &bytes)? {
                visit(decision)?;
            }
        }
        Ok(())
    }

    /// Reassembles the schedule from `source` and authenticates its identity.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_for_each_decision`], or
    /// [`EngineError::ScenarioSerialization`] when the reassembled schedule
    /// does not derive the recorded content hash.
    pub fn read_schedule(&self, source: &dyn SegmentSource) -> Result<Schedule, EngineError> {
        let mut schedule = Schedule::empty();
        self.try_for_each_decision(source, |decision| {
            schedule.push(decision);
            Ok(())
        })?;
        validate_serialized_id("schedule", self.schedule, schedule.content_hash())?;
        Ok(schedule)
    }
}

impl Schedule {
    /// Encodes this schedule's segments in order and returns their manifest.
    ///
    /// Segments are encoded one at a time, so the encoder holds at most one
    /// open segment besides the schedule itself.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when the schedule needs
    /// more than [`MAX_MANIFEST_SEGMENTS`] segments, or the first error
    /// `visit` returns.
    pub fn try_for_each_segment(
        &self,
        mut visit: impl FnMut(&ScheduleSegmentRef, &[u8]) -> Result<(), EngineError>,
    ) -> Result<ScheduleManifest, EngineError> {
        let mut segments = Vec::new();
        let mut open = OpenSegment::new(0);
        let mut scratch = ScenarioBinaryWriter::new(&[]);

        for decision in self.decision_history() {
            scratch.bytes.clear();
            write_decision_binary(decision, &mut scratch);
            if !open.is_empty()
                && open.encoded_len().saturating_add(scratch.bytes.len()) > SEGMENT_TARGET_BYTES
            {
                let next = open.end_decision();
                let sealed = std::mem::replace(&mut open, OpenSegment::new(next));
                seal(sealed, &mut segments, &mut visit)?;
            }
            open.push(&scratch.bytes);
        }
        if !open.is_empty() {
            seal(open, &mut segments, &mut visit)?;
        }

        ScheduleManifest::new(self.content_hash(), segments)
    }

    /// Stores this schedule's segments in `sink` and returns their manifest.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when a segment cannot
    /// be stored, or the errors of [`Self::try_for_each_segment`].
    pub fn write_segments(&self, sink: &dyn SegmentSink) -> Result<ScheduleManifest, EngineError> {
        self.try_for_each_segment(|segment, bytes| {
            sink.put_segment(segment.id, bytes).map_err(|error| {
                scenario_serialization_error(format!(
                    "schedule segment {} cannot be stored: {error}",
                    segment.id
                ))
            })
        })
    }
}

/// Segment source that encodes schedule segments on demand from resident
/// schedules.
///
/// A holder of the schedules themselves, such as a prepared finding before
/// its journal stages any segment, can serve their segments without keeping
/// a second, encoded copy. Each read encodes only the requested segment's
/// decisions; the manifests are derived once at construction.
#[derive(Clone, Debug, Default)]
pub struct ResidentScheduleSegments {
    schedules: Vec<(Schedule, ScheduleManifest)>,
}

impl ResidentScheduleSegments {
    /// Serves the segments of every schedule in `schedules`.
    ///
    /// Schedules share their storage with the caller's copies, so holding
    /// them costs only their manifests.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when a schedule cannot
    /// be segmented within one manifest's bounds.
    pub fn new<'a>(schedules: impl IntoIterator<Item = &'a Schedule>) -> Result<Self, EngineError> {
        let schedules = schedules
            .into_iter()
            .map(|schedule| {
                let manifest = schedule.try_for_each_segment(|_, _| Ok(()))?;
                Ok((schedule.clone(), manifest))
            })
            .collect::<Result<_, EngineError>>()?;
        Ok(Self { schedules })
    }
}

impl SegmentSource for ResidentScheduleSegments {
    fn segment(&self, id: ContentId) -> std::io::Result<Vec<u8>> {
        let found = self.schedules.iter().find_map(|(schedule, manifest)| {
            manifest
                .segments()
                .iter()
                .find(|segment| segment.id == id)
                .map(|segment| (schedule, segment))
        });
        let Some((schedule, segment)) = found else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "schedule segment absent",
            ));
        };
        schedule
            .encode_segment(segment)
            .map_err(|error| std::io::Error::other(error.to_string()))
    }
}

impl Schedule {
    /// Encodes the one segment `segment` names, reading only its decisions.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when the reference lies
    /// beyond this schedule or its decisions do not encode to the referenced
    /// segment.
    pub fn encode_segment(&self, segment: &ScheduleSegmentRef) -> Result<Vec<u8>, EngineError> {
        let start = usize::try_from(segment.first_decision).unwrap_or(usize::MAX);
        let end = usize::try_from(segment.end_decision()).unwrap_or(usize::MAX);
        if end > self.len() || start >= end {
            return Err(scenario_serialization_error(format!(
                "schedule segment {} lies beyond the schedule",
                segment.id
            )));
        }

        let mut writer = ScenarioBinaryWriter::new(SEGMENT_MAGIC);
        writer.write_u64(segment.first_decision);
        writer.write_u64(segment.decision_count);
        for decision in self.decision_history().range(start..end) {
            write_decision_binary(decision, &mut writer);
        }
        let bytes = writer.finish();

        if bytes.len() as u64 != segment.encoded_bytes || !segment.id.authenticates(&bytes) {
            return Err(scenario_serialization_error(format!(
                "schedule decisions do not encode to segment {}",
                segment.id
            )));
        }
        Ok(bytes)
    }
}

/// Encodes `schedule` as the self-contained version 5 transport form.
pub(super) fn schedule_v6_bytes(schedule: &Schedule) -> Vec<u8> {
    let mut encoded = Vec::new();
    let manifest = schedule.try_for_each_segment(|_, bytes| {
        encoded.push(bytes.to_vec());
        Ok(())
    });

    let mut writer = ScenarioBinaryWriter::new(SCHEDULE_BINARY_MAGIC_V6);
    match manifest {
        Ok(manifest) => {
            writer.write_binary_blob(&manifest.to_bytes());
            for segment in &encoded {
                writer.write_binary_blob(segment);
            }
        }
        // A schedule beyond the segment bounds has no valid manifest. The
        // transport stays infallible by writing an empty manifest blob, which
        // every reader refuses before decoding a decision.
        Err(_) => writer.write_binary_blob(&[]),
    }
    writer.finish()
}

/// Feeds `schedule`'s version 5 transport, as a length-prefixed blob, into
/// `hasher` without materializing it.
///
/// The bytes hashed are exactly those [`schedule_v6_bytes`] wraps in a blob.
/// The manifest precedes the segments it names, so the segments are encoded
/// twice: once to derive the manifest and once to hash their bytes.
pub(super) fn hash_schedule_v6_blob(schedule: &Schedule, hasher: &mut blake3::Hasher) {
    let Ok(manifest) = schedule.try_for_each_segment(|_, _| Ok(())) else {
        // The unsegmentable transport is the magic and an empty manifest blob.
        let len = SCHEDULE_BINARY_MAGIC_V6.len() + 8;
        hasher.update(&(len as u64).to_le_bytes());
        hasher.update(SCHEDULE_BINARY_MAGIC_V6);
        hasher.update(&0_u64.to_le_bytes());
        return;
    };

    let manifest_bytes = manifest.to_bytes();
    let len = manifest.segments().iter().fold(
        SCHEDULE_BINARY_MAGIC_V6.len() as u64 + 8 + manifest_bytes.len() as u64,
        |len, segment| len.saturating_add(8).saturating_add(segment.encoded_bytes),
    );
    hasher.update(&len.to_le_bytes());
    hasher.update(SCHEDULE_BINARY_MAGIC_V6);
    hasher.update(&(manifest_bytes.len() as u64).to_le_bytes());
    hasher.update(&manifest_bytes);

    // Sealing is a pure function of the decisions, so this pass reproduces the
    // segments the first pass accepted and its visitor never fails.
    let _same_manifest = schedule.try_for_each_segment(|_, bytes| {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        Ok(())
    });
}

/// Decodes the self-contained version 5 transport form.
pub(super) fn schedule_from_v5_bytes(bytes: &[u8]) -> Result<Schedule, EngineError> {
    let mut reader = ScenarioBinaryReader::new(bytes, SCHEDULE_BINARY_MAGIC_V6)?;
    let manifest = ScheduleManifest::from_bytes(
        reader.read_binary_blob_bounded("schedule manifest", MAX_SCHEDULE_MANIFEST_BYTES)?,
    )?;

    let mut schedule = Schedule::empty();
    for segment in manifest.segments() {
        let bytes = reader.read_binary_blob_bounded("schedule segment", MAX_SEGMENT_BYTES)?;
        for decision in decode_segment(segment, bytes)? {
            schedule.push(decision);
        }
    }
    reader.finish()?;
    validate_serialized_id(
        "schedule",
        manifest.schedule_hash(),
        schedule.content_hash(),
    )?;
    Ok(schedule)
}

/// Decisions accumulated for the next segment, already encoded.
struct OpenSegment {
    first_decision: u64,
    decision_count: u64,
    body: Vec<u8>,
}

impl OpenSegment {
    const fn new(first_decision: u64) -> Self {
        Self {
            first_decision,
            decision_count: 0,
            body: Vec::new(),
        }
    }

    const fn is_empty(&self) -> bool {
        self.decision_count == 0
    }

    fn encoded_len(&self) -> usize {
        SEGMENT_HEADER_BYTES.saturating_add(self.body.len())
    }

    const fn end_decision(&self) -> u64 {
        self.first_decision.saturating_add(self.decision_count)
    }

    fn push(&mut self, decision: &[u8]) {
        self.body.extend_from_slice(decision);
        self.decision_count = self.decision_count.saturating_add(1);
    }
}

/// Encodes one open segment, visits it, and records its reference.
fn seal(
    open: OpenSegment,
    segments: &mut Vec<ScheduleSegmentRef>,
    visit: &mut impl FnMut(&ScheduleSegmentRef, &[u8]) -> Result<(), EngineError>,
) -> Result<(), EngineError> {
    if segments.len() >= MAX_MANIFEST_SEGMENTS {
        return Err(scenario_serialization_error(format!(
            "schedule needs more than {MAX_MANIFEST_SEGMENTS} segments"
        )));
    }
    if open.encoded_len() > MAX_SEGMENT_BYTES {
        return Err(scenario_serialization_error(format!(
            "schedule decision {} encodes beyond the {MAX_SEGMENT_BYTES}-byte segment bound",
            open.first_decision
        )));
    }
    let mut writer = ScenarioBinaryWriter::new(SEGMENT_MAGIC);
    writer.write_u64(open.first_decision);
    writer.write_u64(open.decision_count);
    writer.bytes.extend_from_slice(&open.body);
    let bytes = writer.finish();

    let segment = ScheduleSegmentRef {
        id: ContentId::for_bytes(ObjectKind::Trace, SCHEDULE_SEGMENT_SCHEMA, &bytes),
        first_decision: open.first_decision,
        decision_count: open.decision_count,
        encoded_bytes: bytes.len() as u64,
    };
    visit(&segment, &bytes)?;
    segments.push(segment);
    Ok(())
}

fn validate_segment_ref(segment: &ScheduleSegmentRef) -> Result<(), EngineError> {
    if segment.decision_count == 0
        || segment.encoded_bytes > MAX_SEGMENT_BYTES as u64
        || segment.id.kind() != ObjectKind::Trace
        || segment.id.schema_version() != SCHEDULE_SEGMENT_SCHEMA
    {
        return Err(scenario_serialization_error(format!(
            "schedule segment {} is malformed",
            segment.id
        )));
    }
    Ok(())
}

/// Decodes and authenticates one stored segment against its reference.
fn decode_segment(
    segment: &ScheduleSegmentRef,
    bytes: &[u8],
) -> Result<Vec<Decision>, EngineError> {
    if bytes.len() as u64 != segment.encoded_bytes || !segment.id.authenticates(bytes) {
        return Err(scenario_serialization_error(format!(
            "schedule segment {} bytes do not derive its reference",
            segment.id
        )));
    }

    let mut reader = ScenarioBinaryReader::new(bytes, SEGMENT_MAGIC)?;
    let first_decision = reader.read_u64()?;
    let decision_count = reader.read_count()?;
    if first_decision != segment.first_decision || decision_count as u64 != segment.decision_count {
        return Err(scenario_serialization_error(format!(
            "schedule segment {} header does not match its reference",
            segment.id
        )));
    }
    // Every decision encodes at least one byte; bound the reservation by the
    // input that remains before allocating.
    let remaining = bytes.len().saturating_sub(reader.offset);
    let mut decisions = Vec::with_capacity(decision_count.min(remaining));
    for _ in 0..decision_count {
        decisions.push(read_decision_binary(&mut reader)?);
    }
    reader.finish()?;
    Ok(decisions)
}

fn empty_chain() -> ContentHash {
    ContentHash::from_canonical_material_bytes(CHAIN_DOMAIN, b"empty")
}

fn extend_chain(chain: ContentHash, segment: &ScheduleSegmentRef) -> ContentHash {
    let mut material = Vec::with_capacity(32 + 32 + 24);
    material.extend_from_slice(&chain.bytes);
    material.extend_from_slice(&segment.id.digest());
    material.extend_from_slice(&segment.first_decision.to_le_bytes());
    material.extend_from_slice(&segment.decision_count.to_le_bytes());
    material.extend_from_slice(&segment.encoded_bytes.to_le_bytes());
    ContentHash::from_canonical_material_bytes(CHAIN_DOMAIN, &material)
}

#[cfg(test)]
#[path = "schedule_segments_tests.rs"]
mod tests;
