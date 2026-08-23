//! Canonical normalized signal-trace manifests and chunks.
//!
//! Raw capture formats are importer inputs only. Runtime evaluation consumes
//! this bounded, seekable, content-addressed representation with explicit time
//! mapping, quality, provenance, missing-data behavior, and byte encoding.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use super::*;

/// Canonical trace codec semantic version.
pub const TRACE_CODEC_VERSION: u16 = 1;
/// Exact maximum entries in one channel chunk.
pub const TRACE_ENTRIES_PER_CHUNK: usize = 4_096;
/// Hard maximum channels in one artifact.
pub const HARD_TRACE_CHANNELS_PER_ARTIFACT: usize = 16_384;
/// Hard maximum bytes in one trace value payload.
pub const HARD_TRACE_VALUE_BYTES: usize = 67_108_864;
/// Compiled maximum chunk references across one trace manifest.
pub const HARD_TRACE_CHUNKS_TOTAL: usize = 16_777_216;
/// Binary manifest magic.
const MANIFEST_MAGIC: &[u8; 8] = b"CRTRMAN1";
/// Binary chunk magic.
const CHUNK_MAGIC: &[u8; 8] = b"CRTRCHK1";

/// Exact source timestamp basis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TraceTimeBasis {
    /// Source values are nanoseconds.
    Nanoseconds,
    /// Source values are integer device ticks.
    DeviceTicks,
    /// Entries are ordered by producer sequence.
    Sequence,
}

/// Exact affine mapping from one source interval to virtual nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TraceTimeSegment {
    /// Inclusive first source coordinate.
    pub source_start: u64,
    /// Exclusive end, or no end for the final segment.
    pub source_end: Option<u64>,
    /// Source epoch subtracted before scaling.
    pub source_epoch: u64,
    /// Virtual epoch added after scaling.
    pub virtual_epoch_nanos: u64,
    /// Positive scale numerator.
    pub numerator: PositiveU64,
    /// Positive scale denominator.
    pub denominator: PositiveU64,
    /// Exact division rounding.
    pub rounding: SignalRounding,
}

impl TraceTimeSegment {
    /// Maps one in-segment coordinate with checked integer arithmetic.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] when the coordinate is outside the segment or
    /// before its epoch, arithmetic overflows, or exact rounding is impossible.
    pub fn map(self, source: u64) -> Result<u64, TraceError> {
        if source < self.source_start
            || self.source_end.is_some_and(|end| source >= end)
            || source < self.source_epoch
        {
            return Err(TraceError::CoordinateOutsideMapping { source });
        }
        let delta = u128::from(source - self.source_epoch);
        let product = delta
            .checked_mul(u128::from(self.numerator.get()))
            .ok_or(TraceError::TimeOverflow)?;
        let divisor = u128::from(self.denominator.get());
        let quotient = product / divisor;
        let remainder = product % divisor;
        let rounded = round_unsigned(quotient, remainder, divisor, self.rounding)?;
        let mapped = u128::from(self.virtual_epoch_nanos)
            .checked_add(rounded)
            .ok_or(TraceError::TimeOverflow)?;
        u64::try_from(mapped).map_err(|_| TraceError::TimeOverflow)
    }
}

fn round_unsigned(
    quotient: u128,
    remainder: u128,
    divisor: u128,
    rounding: SignalRounding,
) -> Result<u128, TraceError> {
    let increment = match rounding {
        SignalRounding::Floor | SignalRounding::TowardZero => false,
        SignalRounding::Ceiling | SignalRounding::AwayFromZero => remainder != 0,
        SignalRounding::NearestTiesToEven => {
            let doubled = remainder.checked_mul(2).ok_or(TraceError::TimeOverflow)?;
            doubled > divisor || (doubled == divisor && quotient % 2 == 1)
        }
    };
    quotient
        .checked_add(u128::from(increment))
        .ok_or(TraceError::TimeOverflow)
}

/// Piecewise exact source-to-virtual time mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedTraceTimeMapping {
    segments: Vec<TraceTimeSegment>,
}

impl NormalizedTraceTimeMapping {
    /// Validates strictly adjacent, non-overlapping segments.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] for no segments, overlap, gaps, invalid ends, or
    /// a non-final open segment.
    pub fn new(segments: Vec<TraceTimeSegment>) -> Result<Self, TraceError> {
        if segments.is_empty() {
            return Err(TraceError::InvalidTimeMapping);
        }
        for (index, segment) in segments.iter().enumerate() {
            if segment
                .source_end
                .is_some_and(|end| end <= segment.source_start)
                || (index + 1 < segments.len() && segment.source_end.is_none())
                || segments
                    .get(index + 1)
                    .is_some_and(|next| segment.source_end != Some(next.source_start))
            {
                return Err(TraceError::InvalidTimeMapping);
            }
        }
        Ok(Self { segments })
    }

    /// Returns validated segments in source order.
    #[must_use]
    pub fn segments(&self) -> &[TraceTimeSegment] {
        &self.segments
    }

    /// Maps a source coordinate by binary-searching the segment index.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] when no segment contains the coordinate or exact
    /// mapping arithmetic fails.
    pub fn map(&self, source: u64) -> Result<u64, TraceError> {
        let index = self
            .segments
            .partition_point(|segment| segment.source_start <= source)
            .checked_sub(1)
            .ok_or(TraceError::CoordinateOutsideMapping { source })?;
        self.segments[index].map(source)
    }
}

/// Optional local Cartesian coordinate-frame metadata.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TraceCoordinateFrame {
    /// Stable frame identity.
    pub id: FaultObjectId,
    /// Original reference-system metadata digest.
    pub source_reference: ContentHash,
    /// Integer source-origin coordinates in millimetres.
    pub origin_mm: [i64; 3],
    /// Axis-convention identity.
    pub axis_convention: FaultObjectId,
}

/// Deterministic privacy transform applied before publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpatialRedaction {
    /// Translation in millimetres.
    pub translation_mm: [i64; 3],
    /// Quarter turns around the positive Z axis.
    pub quarter_turns: u8,
    /// Positive quantization cell size.
    pub quantization_mm: PositiveU64,
}

impl SpatialRedaction {
    /// Applies rotation, translation, and nearest-lower cell quantization.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::SpatialOverflow`] when checked arithmetic fails or
    /// the quarter-turn value is outside `0..=3`.
    pub fn apply(self, point: [i64; 3]) -> Result<[i64; 3], TraceError> {
        let [x, y, z] = point;
        let rotated = match self.quarter_turns {
            0 => [x, y, z],
            1 => [y.checked_neg().ok_or(TraceError::SpatialOverflow)?, x, z],
            2 => [
                x.checked_neg().ok_or(TraceError::SpatialOverflow)?,
                y.checked_neg().ok_or(TraceError::SpatialOverflow)?,
                z,
            ],
            3 => [y, x.checked_neg().ok_or(TraceError::SpatialOverflow)?, z],
            _ => return Err(TraceError::SpatialOverflow),
        };
        let quantum =
            i64::try_from(self.quantization_mm.get()).map_err(|_| TraceError::SpatialOverflow)?;
        let mut result = [0; 3];
        for index in 0..3 {
            let translated = rotated[index]
                .checked_add(self.translation_mm[index])
                .ok_or(TraceError::SpatialOverflow)?;
            result[index] = translated
                .div_euclid(quantum)
                .checked_mul(quantum)
                .ok_or(TraceError::SpatialOverflow)?;
        }
        Ok(result)
    }
}

/// Raw-capture provenance retained by a normalized manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceProvenance {
    /// Raw content digest when retained or independently available.
    pub raw_content: Option<ContentHash>,
    /// Explicit reason raw bytes were not retained.
    pub raw_omission_reason: Option<FaultObjectId>,
    /// Importer identity.
    pub importer: FaultObjectId,
    /// Exact importer semantic version.
    pub importer_version: u16,
    /// Canonical importer-options digest.
    pub options: ContentHash,
    /// Stable source-device alias.
    pub source_alias: FaultObjectId,
    /// Privacy/redaction-policy digest.
    pub privacy_policy: ContentHash,
}

impl TraceProvenance {
    fn validate(&self) -> Result<(), TraceError> {
        if self.raw_content.is_some() == self.raw_omission_reason.is_some() {
            return Err(TraceError::InvalidProvenance);
        }
        Ok(())
    }
}

/// One immutable reference to a canonical trace chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TraceChunkReference {
    /// First included virtual coordinate.
    pub first_coordinate: u64,
    /// Last included virtual coordinate.
    pub last_coordinate: u64,
    /// Positive entry count no greater than 4,096.
    pub entry_count: u16,
    /// Chunk content address.
    pub content: ContentHash,
}

/// One normalized channel and its seek index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceChannel {
    /// Stable channel identity.
    pub id: SignalId,
    /// Typed/unit-bearing value shape.
    pub shape: SignalShape,
    /// Whether equal-coordinate event sequences are accepted.
    pub event_channel: bool,
    /// Ordered chunk references.
    pub chunks: Vec<TraceChunkReference>,
}

impl TraceChannel {
    fn validate(&self) -> Result<(), TraceError> {
        if self.chunks.is_empty() {
            return Err(TraceError::EmptyChannel);
        }
        for (index, chunk) in self.chunks.iter().enumerate() {
            let count = usize::from(chunk.entry_count);
            if count == 0
                || count > TRACE_ENTRIES_PER_CHUNK
                || (index + 1 < self.chunks.len() && count != TRACE_ENTRIES_PER_CHUNK)
                || chunk.first_coordinate > chunk.last_coordinate
                || self.chunks.get(index + 1).is_some_and(|next| {
                    if self.event_channel {
                        chunk.last_coordinate > next.first_coordinate
                    } else {
                        chunk.last_coordinate >= next.first_coordinate
                    }
                })
            {
                return Err(TraceError::InvalidChunkIndex);
            }
        }
        Ok(())
    }

    /// Finds the chunk at or immediately before `coordinate` in logarithmic
    /// index time.
    #[must_use]
    pub fn seek(&self, coordinate: u64) -> Option<&TraceChunkReference> {
        if self.event_channel {
            let index = self
                .chunks
                .partition_point(|chunk| chunk.last_coordinate < coordinate);
            return self.chunks.get(index);
        }
        let index = self
            .chunks
            .partition_point(|chunk| chunk.first_coordinate <= coordinate)
            .checked_sub(1)?;
        self.chunks.get(index)
    }
}

/// Canonical normalized trace manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalTraceManifest {
    /// Exact codec version.
    pub semantic_version: u16,
    /// Source coordinate basis.
    pub time_basis: TraceTimeBasis,
    /// Exact piecewise source-time mapping.
    pub time_mapping: NormalizedTraceTimeMapping,
    /// Optional coordinate frame.
    pub coordinate_frame: Option<TraceCoordinateFrame>,
    /// Optional identity-bearing redaction transform.
    pub redaction: Option<SpatialRedaction>,
    /// Channels in canonical ID order.
    pub channels: Vec<TraceChannel>,
    /// Raw-capture and importer provenance.
    pub provenance: TraceProvenance,
    /// Canonical binary content identity.
    pub content: ContentHash,
}

impl SignalTraceManifest {
    /// Validates, sorts, encodes, and content-addresses a manifest.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] for an unsupported version, malformed provenance,
    /// duplicate/empty/oversized channels, or invalid chunk index.
    // crucible-lint: allow rust-allow -- trace construction validates each independent provenance, mapping, redaction, and channel field.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        semantic_version: u16,
        time_basis: TraceTimeBasis,
        time_mapping: NormalizedTraceTimeMapping,
        coordinate_frame: Option<TraceCoordinateFrame>,
        redaction: Option<SpatialRedaction>,
        mut channels: Vec<TraceChannel>,
        provenance: TraceProvenance,
    ) -> Result<Self, TraceError> {
        if semantic_version != TRACE_CODEC_VERSION {
            return Err(TraceError::VersionMismatch {
                expected: TRACE_CODEC_VERSION,
                actual: semantic_version,
            });
        }
        provenance.validate()?;
        if channels.is_empty() || channels.len() > HARD_TRACE_CHANNELS_PER_ARTIFACT {
            return Err(TraceError::ChannelLimit);
        }
        channels.sort_by(|left, right| left.id.cmp(&right.id));
        if channels.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(TraceError::DuplicateChannel);
        }
        for channel in &channels {
            channel.validate()?;
        }
        validate_chunk_total(&channels, HARD_TRACE_CHUNKS_TOTAL)?;
        let mut value = Self {
            semantic_version,
            time_basis,
            time_mapping,
            coordinate_frame,
            redaction,
            channels,
            provenance,
            content: ContentHash::default(),
        };
        value.content = ContentHash::from_bytes(&value.encode());
        Ok(value)
    }

    /// Encodes the manifest using the canonical big-endian v1 format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(MANIFEST_MAGIC);
        put_u16(&mut output, self.semantic_version);
        output.push(match self.time_basis {
            TraceTimeBasis::Nanoseconds => 0,
            TraceTimeBasis::DeviceTicks => 1,
            TraceTimeBasis::Sequence => 2,
        });
        put_u32(&mut output, usize_to_u32(self.time_mapping.segments.len()));
        for segment in &self.time_mapping.segments {
            put_u64(&mut output, segment.source_start);
            put_optional_u64(&mut output, segment.source_end);
            put_u64(&mut output, segment.source_epoch);
            put_u64(&mut output, segment.virtual_epoch_nanos);
            put_u64(&mut output, segment.numerator.get());
            put_u64(&mut output, segment.denominator.get());
            output.push(rounding_tag(segment.rounding));
        }
        put_coordinate_frame(&mut output, self.coordinate_frame.as_ref());
        put_redaction(&mut output, self.redaction);
        put_u32(&mut output, usize_to_u32(self.channels.len()));
        for channel in &self.channels {
            put_text(&mut output, channel.id.as_str());
            put_shape(&mut output, &channel.shape);
            output.push(u8::from(channel.event_channel));
            put_u32(&mut output, usize_to_u32(channel.chunks.len()));
            for chunk in &channel.chunks {
                put_u64(&mut output, chunk.first_coordinate);
                put_u64(&mut output, chunk.last_coordinate);
                put_u16(&mut output, chunk.entry_count);
                output.extend_from_slice(&chunk.content.bytes);
            }
        }
        put_optional_hash(&mut output, self.provenance.raw_content);
        put_optional_id(&mut output, self.provenance.raw_omission_reason.as_ref());
        put_text(&mut output, self.provenance.importer.as_str());
        put_u16(&mut output, self.provenance.importer_version);
        output.extend_from_slice(&self.provenance.options.bytes);
        put_text(&mut output, self.provenance.source_alias.as_str());
        output.extend_from_slice(&self.provenance.privacy_policy.bytes);
        output
    }

    /// Decodes and revalidates one exact canonical manifest.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] for malformed, noncanonical, unsupported, or
    /// trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TraceError> {
        Self::decode_with_chunk_limit(bytes, HARD_TRACE_CHUNKS_TOTAL)
    }

    /// Decodes a manifest under one scenario-owned total chunk limit.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] for malformed, noncanonical, unsupported, or
    /// trailing bytes, or when all channel indexes together exceed `limit`.
    pub fn decode_with_chunk_limit(bytes: &[u8], limit: usize) -> Result<Self, TraceError> {
        let mut reader = Reader::new(bytes);
        reader.expect_magic(MANIFEST_MAGIC)?;
        let semantic_version = reader.u16()?;
        let time_basis = match reader.byte()? {
            0 => TraceTimeBasis::Nanoseconds,
            1 => TraceTimeBasis::DeviceTicks,
            2 => TraceTimeBasis::Sequence,
            _ => return Err(TraceError::MalformedCodec),
        };
        let segment_count = reader.count(HARD_TRACE_CHANNELS_PER_ARTIFACT)?;
        let mut segments = Vec::with_capacity(segment_count);
        for _ in 0..segment_count {
            segments.push(TraceTimeSegment {
                source_start: reader.u64()?,
                source_end: reader.optional_u64()?,
                source_epoch: reader.u64()?,
                virtual_epoch_nanos: reader.u64()?,
                numerator: PositiveU64::new("trace_time_numerator", reader.u64()?)
                    .map_err(TraceError::Contract)?,
                denominator: PositiveU64::new("trace_time_denominator", reader.u64()?)
                    .map_err(TraceError::Contract)?,
                rounding: decode_rounding(reader.byte()?)?,
            });
        }
        let time_mapping = NormalizedTraceTimeMapping::new(segments)?;
        let coordinate_frame = reader.coordinate_frame()?;
        let redaction = reader.redaction()?;
        let channel_count = reader.count(HARD_TRACE_CHANNELS_PER_ARTIFACT)?;
        let mut channels = Vec::with_capacity(channel_count);
        let mut total_chunks = 0_usize;
        for _ in 0..channel_count {
            let id = SignalId::parse(reader.text()?).map_err(TraceError::Signal)?;
            let shape = reader.shape()?;
            let event_channel = reader.boolean()?;
            let chunk_count = reader.count(limit.saturating_sub(total_chunks))?;
            total_chunks = total_chunks
                .checked_add(chunk_count)
                .ok_or(TraceError::MalformedCodec)?;
            let mut chunks = Vec::with_capacity(chunk_count);
            for _ in 0..chunk_count {
                chunks.push(TraceChunkReference {
                    first_coordinate: reader.u64()?,
                    last_coordinate: reader.u64()?,
                    entry_count: reader.u16()?,
                    content: reader.hash()?,
                });
            }
            channels.push(TraceChannel {
                id,
                shape,
                event_channel,
                chunks,
            });
        }
        let provenance = TraceProvenance {
            raw_content: reader.optional_hash()?,
            raw_omission_reason: reader.optional_id()?,
            importer: reader.id()?,
            importer_version: reader.u16()?,
            options: reader.hash()?,
            source_alias: reader.id()?,
            privacy_policy: reader.hash()?,
        };
        reader.finish()?;
        let decoded = Self::new(
            semantic_version,
            time_basis,
            time_mapping,
            coordinate_frame,
            redaction,
            channels,
            provenance,
        )?;
        if decoded.encode() != bytes {
            return Err(TraceError::NonCanonicalCodec);
        }
        Ok(decoded)
    }

    /// Returns the explicit normalized and raw provenance dependency closure.
    #[must_use]
    pub fn dependencies(&self) -> BTreeSet<ContentHash> {
        let mut dependencies = self
            .channels
            .iter()
            .flat_map(|channel| channel.chunks.iter().map(|chunk| chunk.content))
            .collect::<BTreeSet<_>>();
        if let Some(raw) = self.provenance.raw_content {
            dependencies.insert(raw);
        }
        dependencies
    }
}

fn validate_chunk_total(channels: &[TraceChannel], limit: usize) -> Result<(), TraceError> {
    let chunk_total = channels.iter().try_fold(0_usize, |total, channel| {
        total.checked_add(channel.chunks.len())
    });
    if chunk_total.is_none_or(|total| total > limit) {
        Err(TraceError::ChunkTotalLimit)
    } else {
        Ok(())
    }
}

/// Validity associated with one normalized entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TraceValidity {
    /// Value is admitted for ordinary interpolation.
    Valid,
    /// Value is retained but outside the accepted quality range.
    InvalidQuality,
    /// Source explicitly reported a missing value.
    Missing,
    /// Source discontinuity begins at this entry.
    Discontinuity,
}

/// One canonical normalized channel entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEntry {
    /// Mapped virtual coordinate.
    pub coordinate: u64,
    /// Stable event sequence, required only for event channels.
    pub event_sequence: Option<u64>,
    /// Typed normalized value.
    pub value: SignalValue,
    /// Explicit validity state.
    pub validity: TraceValidity,
}

/// One independently content-addressed channel chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalTraceChunk {
    /// Exact codec version.
    pub semantic_version: u16,
    /// Owning channel identity.
    pub channel: SignalId,
    /// Whether equal-coordinate event sequences are legal.
    pub event_channel: bool,
    /// Ordered entries.
    pub entries: Vec<TraceEntry>,
    /// Canonical binary content identity.
    pub content: ContentHash,
}

impl SignalTraceChunk {
    /// Validates, encodes, and content-addresses one nonempty channel chunk.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] for an unsupported version, invalid entry count,
    /// malformed value, or noncanonical coordinate/event ordering.
    pub fn new(
        semantic_version: u16,
        channel: SignalId,
        event_channel: bool,
        entries: Vec<TraceEntry>,
    ) -> Result<Self, TraceError> {
        if semantic_version != TRACE_CODEC_VERSION {
            return Err(TraceError::VersionMismatch {
                expected: TRACE_CODEC_VERSION,
                actual: semantic_version,
            });
        }
        if entries.is_empty() || entries.len() > TRACE_ENTRIES_PER_CHUNK {
            return Err(TraceError::ChunkEntryLimit);
        }
        for (index, entry) in entries.iter().enumerate() {
            if entry.value.value_type().is_none() || !value_payloads_bounded(&entry.value) {
                return Err(TraceError::InvalidValue);
            }
            if event_channel != entry.event_sequence.is_some() {
                return Err(TraceError::InvalidEventSequence);
            }
            if entries.get(index + 1).is_some_and(|next| {
                if event_channel {
                    (entry.coordinate, entry.event_sequence)
                        >= (next.coordinate, next.event_sequence)
                } else {
                    entry.coordinate >= next.coordinate
                }
            }) {
                return Err(TraceError::InvalidEntryOrder);
            }
        }
        let mut value = Self {
            semantic_version,
            channel,
            event_channel,
            entries,
            content: ContentHash::default(),
        };
        value.content = ContentHash::from_bytes(&value.encode());
        Ok(value)
    }

    /// Returns the exact manifest reference for this chunk.
    #[must_use]
    pub fn reference(&self) -> TraceChunkReference {
        TraceChunkReference {
            first_coordinate: self.entries[0].coordinate,
            last_coordinate: self.entries[self.entries.len() - 1].coordinate,
            entry_count: u16::try_from(self.entries.len()).unwrap_or(u16::MAX),
            content: self.content,
        }
    }

    /// Encodes the chunk using the canonical big-endian v1 format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(CHUNK_MAGIC);
        put_u16(&mut output, self.semantic_version);
        put_text(&mut output, self.channel.as_str());
        output.push(u8::from(self.event_channel));
        put_u16(
            &mut output,
            u16::try_from(self.entries.len()).unwrap_or(u16::MAX),
        );
        let mut prior = 0;
        for entry in &self.entries {
            put_u64(&mut output, entry.coordinate - prior);
            prior = entry.coordinate;
            put_optional_u64(&mut output, entry.event_sequence);
            output.push(match entry.validity {
                TraceValidity::Valid => 0,
                TraceValidity::InvalidQuality => 1,
                TraceValidity::Missing => 2,
                TraceValidity::Discontinuity => 3,
            });
            put_value(&mut output, &entry.value);
        }
        output
    }

    /// Decodes and revalidates one exact canonical chunk.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] for malformed, noncanonical, unsupported, or
    /// trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TraceError> {
        let mut reader = Reader::new(bytes);
        reader.expect_magic(CHUNK_MAGIC)?;
        let version = reader.u16()?;
        let channel = SignalId::parse(reader.text()?).map_err(TraceError::Signal)?;
        let event_channel = reader.boolean()?;
        let count = usize::from(reader.u16()?);
        if count == 0 || count > TRACE_ENTRIES_PER_CHUNK {
            return Err(TraceError::ChunkEntryLimit);
        }
        let mut entries = Vec::with_capacity(count);
        let mut coordinate = 0_u64;
        for _ in 0..count {
            coordinate = coordinate
                .checked_add(reader.u64()?)
                .ok_or(TraceError::TimeOverflow)?;
            let event_sequence = reader.optional_u64()?;
            let validity = match reader.byte()? {
                0 => TraceValidity::Valid,
                1 => TraceValidity::InvalidQuality,
                2 => TraceValidity::Missing,
                3 => TraceValidity::Discontinuity,
                _ => return Err(TraceError::MalformedCodec),
            };
            entries.push(TraceEntry {
                coordinate,
                event_sequence,
                value: reader.value()?,
                validity,
            });
        }
        reader.finish()?;
        let decoded = Self::new(version, channel, event_channel, entries)?;
        if decoded.encode() != bytes {
            return Err(TraceError::NonCanonicalCodec);
        }
        Ok(decoded)
    }
}

fn value_payloads_bounded(value: &SignalValue) -> bool {
    match value {
        SignalValue::Event { payload, .. } | SignalValue::Bytes(payload) => {
            payload.len() <= HARD_TRACE_VALUE_BYTES && u32::try_from(payload.len()).is_ok()
        }
        SignalValue::Vector2(values) | SignalValue::Vector3(values) => {
            values.iter().all(value_payloads_bounded)
        }
        _ => true,
    }
}

fn usize_to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_i64(output: &mut Vec<u8>, value: i64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_text(output: &mut Vec<u8>, value: &str) {
    put_u32(output, usize_to_u32(value.len()));
    output.extend_from_slice(value.as_bytes());
}

fn put_optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    output.push(u8::from(value.is_some()));
    if let Some(value) = value {
        put_u64(output, value);
    }
}

fn put_optional_hash(output: &mut Vec<u8>, value: Option<ContentHash>) {
    output.push(u8::from(value.is_some()));
    if let Some(value) = value {
        output.extend_from_slice(&value.bytes);
    }
}

fn put_optional_id(output: &mut Vec<u8>, value: Option<&FaultObjectId>) {
    output.push(u8::from(value.is_some()));
    if let Some(value) = value {
        put_text(output, value.as_str());
    }
}

fn rounding_tag(value: SignalRounding) -> u8 {
    match value {
        SignalRounding::Floor => 0,
        SignalRounding::Ceiling => 1,
        SignalRounding::TowardZero => 2,
        SignalRounding::AwayFromZero => 3,
        SignalRounding::NearestTiesToEven => 4,
    }
}

fn decode_rounding(value: u8) -> Result<SignalRounding, TraceError> {
    match value {
        0 => Ok(SignalRounding::Floor),
        1 => Ok(SignalRounding::Ceiling),
        2 => Ok(SignalRounding::TowardZero),
        3 => Ok(SignalRounding::AwayFromZero),
        4 => Ok(SignalRounding::NearestTiesToEven),
        _ => Err(TraceError::MalformedCodec),
    }
}

fn put_coordinate_frame(output: &mut Vec<u8>, frame: Option<&TraceCoordinateFrame>) {
    output.push(u8::from(frame.is_some()));
    if let Some(frame) = frame {
        put_text(output, frame.id.as_str());
        output.extend_from_slice(&frame.source_reference.bytes);
        for coordinate in frame.origin_mm {
            put_i64(output, coordinate);
        }
        put_text(output, frame.axis_convention.as_str());
    }
}

fn put_redaction(output: &mut Vec<u8>, redaction: Option<SpatialRedaction>) {
    output.push(u8::from(redaction.is_some()));
    if let Some(redaction) = redaction {
        for coordinate in redaction.translation_mm {
            put_i64(output, coordinate);
        }
        output.push(redaction.quarter_turns);
        put_u64(output, redaction.quantization_mm.get());
    }
}

fn put_shape(output: &mut Vec<u8>, shape: &SignalShape) {
    put_value_type(output, &shape.value_type);
    output.push(unit_tag(shape.unit));
    output.push(shape.scale_decimal_exponent.to_be_bytes()[0]);
}

pub(super) fn encode_signal_shape(shape: &SignalShape) -> Result<Vec<u8>, TraceError> {
    shape.validate().map_err(TraceError::Signal)?;
    let mut output = Vec::new();
    put_shape(&mut output, shape);
    Ok(output)
}

pub(super) fn decode_signal_shape(bytes: &[u8]) -> Result<SignalShape, TraceError> {
    let mut reader = Reader::new(bytes);
    let shape = reader.shape()?;
    reader.finish()?;
    if encode_signal_shape(&shape)? != bytes {
        return Err(TraceError::NonCanonicalCodec);
    }
    Ok(shape)
}

fn put_value_type(output: &mut Vec<u8>, value: &SignalValueType) {
    match value {
        SignalValueType::Bool => output.push(0),
        SignalValueType::I64 => output.push(1),
        SignalValueType::U64 => output.push(2),
        SignalValueType::Ratio => output.push(3),
        SignalValueType::DurationNanos => output.push(4),
        SignalValueType::RatePerSecond => output.push(5),
        SignalValueType::ProbabilityMillionths => output.push(6),
        SignalValueType::Enum(schema) => {
            output.push(7);
            put_text(output, schema.as_str());
        }
        SignalValueType::Event(schema) => {
            output.push(8);
            put_text(output, schema.as_str());
        }
        SignalValueType::Vector2(element) => {
            output.push(9);
            put_value_type(output, &element.value_type());
        }
        SignalValueType::Vector3(element) => {
            output.push(10);
            put_value_type(output, &element.value_type());
        }
        SignalValueType::Bytes => output.push(11),
    }
}

fn unit_tag(unit: SignalUnit) -> u8 {
    match unit {
        SignalUnit::Dimensionless => 0,
        SignalUnit::VirtualNanoseconds => 1,
        SignalUnit::Millimetres => 2,
        SignalUnit::MillimetresPerSecond => 3,
        SignalUnit::Millidegrees => 4,
        SignalUnit::Millicelsius => 5,
        SignalUnit::Microvolts => 6,
        SignalUnit::Microamps => 7,
        SignalUnit::Microwatts => 8,
        SignalUnit::Femtowatts => 9,
        SignalUnit::Microjoules => 10,
        SignalUnit::Millidecibels => 11,
        SignalUnit::MillidecibelMilliwatts => 12,
        SignalUnit::Kilohertz => 13,
        SignalUnit::BitsPerSecond => 14,
        SignalUnit::BytesPerSecond => 15,
        SignalUnit::OperationsPerSecond => 16,
        SignalUnit::PartsPerMillion => 17,
        SignalUnit::ProbabilityMillionths => 18,
        SignalUnit::MicrometresPerSecondSquared => 19,
        SignalUnit::MicrometresPerHour => 20,
        SignalUnit::SquareMillimetres => 21,
    }
}

fn put_value(output: &mut Vec<u8>, value: &SignalValue) {
    match value {
        SignalValue::Bool(value) => output.extend_from_slice(&[0, u8::from(*value)]),
        SignalValue::I64(value) => {
            output.push(1);
            put_i64(output, *value);
        }
        SignalValue::U64(value) => {
            output.push(2);
            put_u64(output, *value);
        }
        SignalValue::Ratio(value) => {
            output.push(3);
            put_i64(output, value.numerator());
            put_u64(output, value.denominator());
        }
        SignalValue::DurationNanos(value) => {
            output.push(4);
            put_u64(output, *value);
        }
        SignalValue::RatePerSecond(value) => {
            output.push(5);
            put_u64(output, *value);
        }
        SignalValue::ProbabilityMillionths(value) => {
            output.push(6);
            put_u32(output, *value);
        }
        SignalValue::Enum { schema, variant } => {
            output.push(7);
            put_text(output, schema.as_str());
            put_text(output, variant.as_str());
        }
        SignalValue::Event { schema, payload } => {
            output.push(8);
            put_text(output, schema.as_str());
            put_bytes(output, payload);
        }
        SignalValue::Vector2(values) => {
            output.push(9);
            for value in values {
                put_value(output, value);
            }
        }
        SignalValue::Vector3(values) => {
            output.push(10);
            for value in values {
                put_value(output, value);
            }
        }
        SignalValue::Bytes(bytes) => {
            output.push(11);
            put_bytes(output, bytes);
        }
    }
}

pub(super) fn encode_signal_value(value: &SignalValue) -> Result<Vec<u8>, TraceError> {
    if value.value_type().is_none() || !value_payloads_bounded(value) {
        return Err(TraceError::InvalidValue);
    }
    let mut output = Vec::new();
    put_value(&mut output, value);
    Ok(output)
}

pub(super) fn decode_signal_value(bytes: &[u8]) -> Result<SignalValue, TraceError> {
    let mut reader = Reader::new(bytes);
    let value = reader.value()?;
    reader.finish()?;
    if encode_signal_value(&value)? != bytes {
        return Err(TraceError::NonCanonicalCodec);
    }
    Ok(value)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(output, usize_to_u32(bytes.len()));
    output.extend_from_slice(bytes);
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TraceError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(TraceError::MalformedCodec)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(TraceError::MalformedCodec)?;
        self.cursor = end;
        Ok(value)
    }

    fn expect_magic(&mut self, magic: &[u8]) -> Result<(), TraceError> {
        if self.take(magic.len())? != magic {
            return Err(TraceError::MalformedCodec);
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), TraceError> {
        if self.cursor != self.bytes.len() {
            return Err(TraceError::TrailingBytes);
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, TraceError> {
        Ok(self.take(1)?[0])
    }

    fn boolean(&mut self) -> Result<bool, TraceError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(TraceError::MalformedCodec),
        }
    }

    fn u16(&mut self) -> Result<u16, TraceError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| TraceError::MalformedCodec)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, TraceError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| TraceError::MalformedCodec)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, TraceError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| TraceError::MalformedCodec)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn i64(&mut self) -> Result<i64, TraceError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| TraceError::MalformedCodec)?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, TraceError> {
        let value = usize::try_from(self.u32()?).map_err(|_| TraceError::MalformedCodec)?;
        if value > maximum {
            return Err(TraceError::MalformedCodec);
        }
        Ok(value)
    }

    fn text(&mut self) -> Result<String, TraceError> {
        let length = self.count(HARD_TRACE_VALUE_BYTES)?;
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| TraceError::MalformedCodec)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, TraceError> {
        let length = self.count(HARD_TRACE_VALUE_BYTES)?;
        Ok(self.take(length)?.to_vec())
    }

    fn hash(&mut self) -> Result<ContentHash, TraceError> {
        let bytes: [u8; 32] = self
            .take(32)?
            .try_into()
            .map_err(|_| TraceError::MalformedCodec)?;
        Ok(ContentHash { bytes })
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, TraceError> {
        if self.boolean()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }

    fn optional_hash(&mut self) -> Result<Option<ContentHash>, TraceError> {
        if self.boolean()? {
            Ok(Some(self.hash()?))
        } else {
            Ok(None)
        }
    }

    fn id(&mut self) -> Result<FaultObjectId, TraceError> {
        FaultObjectId::parse(self.text()?).map_err(TraceError::Contract)
    }

    fn optional_id(&mut self) -> Result<Option<FaultObjectId>, TraceError> {
        if self.boolean()? {
            Ok(Some(self.id()?))
        } else {
            Ok(None)
        }
    }

    fn coordinate_frame(&mut self) -> Result<Option<TraceCoordinateFrame>, TraceError> {
        if !self.boolean()? {
            return Ok(None);
        }
        Ok(Some(TraceCoordinateFrame {
            id: self.id()?,
            source_reference: self.hash()?,
            origin_mm: [self.i64()?, self.i64()?, self.i64()?],
            axis_convention: self.id()?,
        }))
    }

    fn redaction(&mut self) -> Result<Option<SpatialRedaction>, TraceError> {
        if !self.boolean()? {
            return Ok(None);
        }
        Ok(Some(SpatialRedaction {
            translation_mm: [self.i64()?, self.i64()?, self.i64()?],
            quarter_turns: self.byte()?,
            quantization_mm: PositiveU64::new("quantization_mm", self.u64()?)
                .map_err(TraceError::Contract)?,
        }))
    }

    fn shape(&mut self) -> Result<SignalShape, TraceError> {
        let value_type = self.value_type(0)?;
        let unit = decode_unit(self.byte()?)?;
        let scale = i8::from_be_bytes([self.byte()?]);
        SignalShape::new(value_type, unit, scale).map_err(TraceError::Signal)
    }

    fn value_type(&mut self, depth: u8) -> Result<SignalValueType, TraceError> {
        if depth > 2 {
            return Err(TraceError::MalformedCodec);
        }
        match self.byte()? {
            0 => Ok(SignalValueType::Bool),
            1 => Ok(SignalValueType::I64),
            2 => Ok(SignalValueType::U64),
            3 => Ok(SignalValueType::Ratio),
            4 => Ok(SignalValueType::DurationNanos),
            5 => Ok(SignalValueType::RatePerSecond),
            6 => Ok(SignalValueType::ProbabilityMillionths),
            7 => Ok(SignalValueType::Enum(
                SignalId::parse(self.text()?).map_err(TraceError::Signal)?,
            )),
            8 => Ok(SignalValueType::Event(
                SignalId::parse(self.text()?).map_err(TraceError::Signal)?,
            )),
            9 => Ok(SignalValueType::Vector2(
                self.value_type(depth + 1)?
                    .try_into()
                    .map_err(|_| TraceError::MalformedCodec)?,
            )),
            10 => Ok(SignalValueType::Vector3(
                self.value_type(depth + 1)?
                    .try_into()
                    .map_err(|_| TraceError::MalformedCodec)?,
            )),
            11 => Ok(SignalValueType::Bytes),
            _ => Err(TraceError::MalformedCodec),
        }
    }

    fn value(&mut self) -> Result<SignalValue, TraceError> {
        let value = match self.byte()? {
            0 => SignalValue::Bool(self.boolean()?),
            1 => SignalValue::I64(self.i64()?),
            2 => SignalValue::U64(self.u64()?),
            3 => SignalValue::Ratio(
                ExactRatio::new(self.i64()?, self.u64()?).map_err(TraceError::Signal)?,
            ),
            4 => SignalValue::DurationNanos(self.u64()?),
            5 => SignalValue::RatePerSecond(self.u64()?),
            6 => SignalValue::ProbabilityMillionths(self.u32()?),
            7 => SignalValue::Enum {
                schema: SignalId::parse(self.text()?).map_err(TraceError::Signal)?,
                variant: SignalId::parse(self.text()?).map_err(TraceError::Signal)?,
            },
            8 => SignalValue::Event {
                schema: SignalId::parse(self.text()?).map_err(TraceError::Signal)?,
                payload: self.bytes()?,
            },
            9 => SignalValue::Vector2(vec![self.value()?, self.value()?]),
            10 => SignalValue::Vector3(vec![self.value()?, self.value()?, self.value()?]),
            11 => SignalValue::Bytes(self.bytes()?),
            _ => return Err(TraceError::MalformedCodec),
        };
        if value.value_type().is_none() {
            return Err(TraceError::InvalidValue);
        }
        Ok(value)
    }
}

fn decode_unit(value: u8) -> Result<SignalUnit, TraceError> {
    let units = [
        SignalUnit::Dimensionless,
        SignalUnit::VirtualNanoseconds,
        SignalUnit::Millimetres,
        SignalUnit::MillimetresPerSecond,
        SignalUnit::Millidegrees,
        SignalUnit::Millicelsius,
        SignalUnit::Microvolts,
        SignalUnit::Microamps,
        SignalUnit::Microwatts,
        SignalUnit::Femtowatts,
        SignalUnit::Microjoules,
        SignalUnit::Millidecibels,
        SignalUnit::MillidecibelMilliwatts,
        SignalUnit::Kilohertz,
        SignalUnit::BitsPerSecond,
        SignalUnit::BytesPerSecond,
        SignalUnit::OperationsPerSecond,
        SignalUnit::PartsPerMillion,
        SignalUnit::ProbabilityMillionths,
        SignalUnit::MicrometresPerSecondSquared,
        SignalUnit::MicrometresPerHour,
        SignalUnit::SquareMillimetres,
    ];
    units
        .get(usize::from(value))
        .copied()
        .ok_or(TraceError::MalformedCodec)
}

/// Canonical trace construction, codec, or alignment failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceError {
    /// Trace codec semantic version differs.
    VersionMismatch {
        /// Implemented version.
        expected: u16,
        /// Encoded version.
        actual: u16,
    },
    /// Piecewise time mapping is malformed.
    InvalidTimeMapping,
    /// Source coordinate has no exact mapping.
    CoordinateOutsideMapping {
        /// Rejected coordinate.
        source: u64,
    },
    /// Time arithmetic overflowed.
    TimeOverflow,
    /// Spatial transform overflowed or has an invalid rotation.
    SpatialOverflow,
    /// Raw provenance and omission reason are inconsistent.
    InvalidProvenance,
    /// Channel list is empty or oversized.
    ChannelLimit,
    /// Channel ID appears more than once.
    DuplicateChannel,
    /// Channel contains no chunks.
    EmptyChannel,
    /// Chunk index violates ordering or fixed-boundary rules.
    InvalidChunkIndex,
    /// Chunk entry count is empty or oversized.
    ChunkEntryLimit,
    /// Aggregate chunk references exceed the compiled manifest ceiling.
    ChunkTotalLimit,
    /// Event sequence presence contradicts the channel kind.
    InvalidEventSequence,
    /// Entry coordinates or event sequences are not strictly ordered.
    InvalidEntryOrder,
    /// Trace value is structurally invalid.
    InvalidValue,
    /// Binary input is truncated or contains an unknown tag.
    MalformedCodec,
    /// Binary input has bytes after the canonical object.
    TrailingBytes,
    /// Decoded bytes do not reproduce the original encoding.
    NonCanonicalCodec,
    /// A nested signal contract failed.
    Signal(SignalProgramError),
    /// A nested fault contract failed.
    Contract(FaultContractError),
}

impl fmt::Display for TraceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid normalized trace: {self:?}")
    }
}

impl Error for TraceError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal_id(value: &str) -> SignalId {
        match SignalId::parse(value) {
            Ok(id) => id,
            Err(error) => panic!("test ID must be valid: {error}"),
        }
    }

    #[test]
    fn chunk_codec_is_canonical_and_rejects_trailing_bytes() {
        let chunk = match SignalTraceChunk::new(
            TRACE_CODEC_VERSION,
            signal_id("latency"),
            false,
            vec![
                TraceEntry {
                    coordinate: 10,
                    event_sequence: None,
                    value: SignalValue::DurationNanos(5),
                    validity: TraceValidity::Valid,
                },
                TraceEntry {
                    coordinate: 20,
                    event_sequence: None,
                    value: SignalValue::DurationNanos(7),
                    validity: TraceValidity::InvalidQuality,
                },
            ],
        ) {
            Ok(value) => value,
            Err(error) => panic!("test chunk must be valid: {error}"),
        };
        let encoded = chunk.encode();
        assert_eq!(SignalTraceChunk::decode(&encoded), Ok(chunk));
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            SignalTraceChunk::decode(&trailing),
            Err(TraceError::TrailingBytes)
        );
    }

    #[test]
    fn exact_time_mapping_rounds_ties_to_even() {
        let one = match PositiveU64::new("one", 1) {
            Ok(value) => value,
            Err(error) => panic!("one must be valid: {error}"),
        };
        let two = match PositiveU64::new("two", 2) {
            Ok(value) => value,
            Err(error) => panic!("two must be valid: {error}"),
        };
        let segment = TraceTimeSegment {
            source_start: 0,
            source_end: None,
            source_epoch: 0,
            virtual_epoch_nanos: 0,
            numerator: one,
            denominator: two,
            rounding: SignalRounding::NearestTiesToEven,
        };
        assert_eq!(segment.map(1), Ok(0));
        assert_eq!(segment.map(3), Ok(2));
    }

    #[test]
    fn event_seek_returns_first_chunk_that_can_hold_a_shared_coordinate() {
        let channel = TraceChannel {
            id: signal_id("events"),
            shape: match SignalShape::new(
                SignalValueType::Event(signal_id("event")),
                SignalUnit::Dimensionless,
                0,
            ) {
                Ok(value) => value,
                Err(error) => panic!("test shape must be valid: {error}"),
            },
            event_channel: true,
            chunks: vec![
                TraceChunkReference {
                    first_coordinate: 1,
                    last_coordinate: 10,
                    entry_count: 2,
                    content: ContentHash::from_bytes(b"first"),
                },
                TraceChunkReference {
                    first_coordinate: 10,
                    last_coordinate: 20,
                    entry_count: 2,
                    content: ContentHash::from_bytes(b"second"),
                },
            ],
        };
        assert_eq!(
            channel.seek(10).map(|chunk| chunk.content),
            Some(ContentHash::from_bytes(b"first"))
        );
    }

    #[test]
    fn manifest_construction_enforces_the_aggregate_chunk_ceiling() {
        let channel = TraceChannel {
            id: signal_id("samples"),
            shape: SignalShape::new(
                SignalValueType::DurationNanos,
                SignalUnit::VirtualNanoseconds,
                0,
            )
            .unwrap_or_else(|error| panic!("test shape: {error}")),
            event_channel: false,
            chunks: vec![TraceChunkReference {
                first_coordinate: 1,
                last_coordinate: 1,
                entry_count: 1,
                content: ContentHash::from_bytes(b"chunk"),
            }],
        };
        assert_eq!(
            validate_chunk_total(&[channel], 0),
            Err(TraceError::ChunkTotalLimit)
        );
    }

    #[test]
    fn spatial_redaction_rejects_quantization_overflow() {
        let quantum = match PositiveU64::new("quantization", 3) {
            Ok(value) => value,
            Err(error) => panic!("test quantization must be valid: {error}"),
        };
        let redaction = SpatialRedaction {
            translation_mm: [0; 3],
            quarter_turns: 0,
            quantization_mm: quantum,
        };
        assert_eq!(
            redaction.apply([i64::MIN + 1, 0, 0]),
            Err(TraceError::SpatialOverflow)
        );
    }
}
