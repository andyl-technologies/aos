//! Deterministic execution of validated signal programs.
//!
//! Evaluation is driven only by an explicit coordinate, scenario seed,
//! consumer identity, immutable normalized artifacts, and a recorded telemetry
//! snapshot. The evaluator never reads host time, ambient randomness, files, or
//! live device state. Mutable operator state and retained history are bounded
//! and can be encoded into a checkpoint without hidden process state.

use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt;

use super::*;
use crate::model::{DagStore, DagStoreError};

/// Hard maximum event payload accepted by the evaluator.
pub const HARD_SIGNAL_EVENT_BYTES: usize = HARD_TRACE_VALUE_BYTES;
/// Hard maximum retained history entries across one evaluator.
pub const HARD_SIGNAL_HISTORY_ENTRIES: usize = 4_194_304;
/// Hard maximum bytes in one evaluator checkpoint.
pub const HARD_SIGNAL_EVALUATOR_CHECKPOINT_BYTES: usize = 268_435_456;
/// Maximum serialized bytes retained for one signal node.
pub const HARD_SIGNAL_NODE_RUNTIME_BYTES: usize = 16_777_216;
/// Hard maximum delayed telemetry fields or pending emitted events.
pub const HARD_SIGNAL_BOUNDARY_ITEMS: usize = 262_144;
const EVALUATOR_CHECKPOINT_MAGIC: &[u8; 8] = b"CREVAL01";

/// Immutable canonical evaluator checkpoint bytes and content identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalEvaluatorCheckpoint {
    bytes: Vec<u8>,
    content: ContentHash,
}

impl SignalEvaluatorCheckpoint {
    /// Decodes and fully validates portable checkpoint bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignalEvaluationError`] when bytes are malformed,
    /// noncanonical, oversized, incomplete, or violate the supplied program's
    /// state and history contracts.
    pub fn decode(
        bytes: Vec<u8>,
        program: &SignalProgram,
        artifacts: &dyn SignalArtifactProvider,
    ) -> Result<Self, SignalEvaluationError> {
        let checkpoint = Self {
            content: ContentHash::from_bytes(&bytes),
            bytes,
        };
        let _ = SignalEvaluator::restore(program, artifacts, &checkpoint)?;
        Ok(checkpoint)
    }

    /// Returns the exact portable checkpoint bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the checkpoint content address.
    #[must_use]
    pub const fn content(&self) -> ContentHash {
        self.content
    }

    /// Validates the outer codec, evaluator version, content identity, and
    /// signal-program identity without restoring artifacts.
    ///
    /// # Errors
    ///
    /// Returns [`SignalEvaluationError`] when any outer checkpoint contract
    /// differs or the checkpoint exceeds the hard byte ceiling.
    pub fn validate_for_program(
        &self,
        program: &SignalProgram,
    ) -> Result<(), SignalEvaluationError> {
        if self.bytes.len() > HARD_SIGNAL_EVALUATOR_CHECKPOINT_BYTES
            || ContentHash::from_bytes(&self.bytes) != self.content
        {
            return Err(SignalEvaluationError::CheckpointContentMismatch);
        }
        let mut reader = EvaluatorReader::new(&self.bytes);
        if reader.take(EVALUATOR_CHECKPOINT_MAGIC.len())? != EVALUATOR_CHECKPOINT_MAGIC
            || reader.u16()? != SIGNAL_EVALUATOR_VERSION
            || reader.hash()? != program.id()
        {
            return Err(SignalEvaluationError::CheckpointIdentityMismatch);
        }
        Ok(())
    }
}

/// A value produced by one node at one explicit coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvaluatedSignal {
    /// The node produced a typed value or event.
    Value(SignalValue),
    /// The node's explicit boundary or missing-data policy selected inactivity.
    Inactive,
}

impl EvaluatedSignal {
    pub(super) fn value(&self) -> Result<&SignalValue, SignalEvaluationError> {
        match self {
            Self::Value(value) => Ok(value),
            Self::Inactive => Err(SignalEvaluationError::InactiveInput),
        }
    }
}

/// Stable identity supplied for counter-keyed stochastic choices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalChoiceContext {
    /// Scenario-wide deterministic seed.
    pub scenario_seed: ContentHash,
    /// Binding, state node, or other stable consumer identity.
    pub consumer: FaultObjectId,
    /// Stable opportunity identity when evaluating an opportunity-keyed source.
    pub opportunity: Option<FaultOpportunity>,
    /// Monotone transition identity when evaluating a transition-keyed source.
    pub transition_sequence: Option<u64>,
}

/// One immutable evaluation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalEvaluationRequest {
    /// Requested output node.
    pub output: SignalId,
    /// Exact coordinate in the output node's domain.
    pub coordinate: SignalCoordinate,
    /// Stable sequence among events at the same domain coordinate.
    pub same_coordinate_sequence: u64,
    /// Stochastic identity tuple.
    pub choice: SignalChoiceContext,
}

/// Typed lookup key for one-boundary-delayed telemetry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignalTelemetryKey {
    /// Producing adapter.
    pub adapter: SignalId,
    /// Concrete adapter target.
    pub target: SignalId,
    /// Registered telemetry field.
    pub field: SignalId,
}

/// Recorded values visible at the start of a deterministic boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignalBoundarySnapshot {
    /// Canonically ordered delayed telemetry values.
    pub telemetry: BTreeMap<SignalTelemetryKey, SignalValue>,
}

/// One side-band event emitted by a stateful node transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatefulSignalEvent {
    /// Emitting node.
    pub node: SignalId,
    /// Declared event variant.
    pub variant: SignalId,
    /// Exact transition coordinate.
    pub coordinate: SignalCoordinate,
    /// Stable transition order at the coordinate.
    pub same_coordinate_sequence: u64,
}

/// Backend for immutable normalized source artifacts.
///
/// Implementations must validate content addresses and canonical codecs before
/// returning a value. The evaluator supplies the full closed source schema, so
/// implementations cannot reinterpret an unknown source kind.
pub trait SignalArtifactProvider: Send + Sync {
    /// Loads and validates one normalized integer inverse-CDF table.
    ///
    /// # Errors
    ///
    /// Returns [`SignalEvaluationError`] when the content is absent, corrupt,
    /// or not a canonical inverse-CDF table.
    fn inverse_cdf_table(
        &self,
        content: &ContentHash,
    ) -> Result<InverseCdfTable, SignalEvaluationError>;

    /// Evaluates one trace, spatial, or calibrated transmitter source.
    ///
    /// # Errors
    ///
    /// Returns [`SignalEvaluationError`] when the artifact is absent, corrupt,
    /// incompatible with the source declaration, or has no value under the
    /// declaration's explicit boundary policy.
    fn evaluate_artifact_source(
        &self,
        node: &SignalNode,
        source: &SignalSourceSpecification,
        coordinate: &SignalCoordinate,
        same_coordinate_sequence: u64,
        choice: &SignalChoiceContext,
        inputs: &[EvaluatedSignal],
    ) -> Result<EvaluatedSignal, SignalEvaluationError>;
}

/// Production artifact provider backed by Crucible's content-addressed store.
pub struct DagSignalArtifactProvider<'a> {
    store: &'a dyn DagStore,
}

impl<'a> DagSignalArtifactProvider<'a> {
    /// Wraps a content-addressed artifact store.
    #[must_use]
    pub const fn new(store: &'a dyn DagStore) -> Self {
        Self { store }
    }

    fn get(&self, content: &ContentHash) -> Result<Vec<u8>, SignalEvaluationError> {
        let bytes = self
            .store
            .get(content)
            .map_err(SignalEvaluationError::Store)?;
        if ContentHash::from_bytes(&bytes) != *content {
            return Err(SignalEvaluationError::ArtifactContentMismatch(*content));
        }
        Ok(bytes)
    }
}

impl SignalArtifactProvider for DagSignalArtifactProvider<'_> {
    fn inverse_cdf_table(
        &self,
        content: &ContentHash,
    ) -> Result<InverseCdfTable, SignalEvaluationError> {
        InverseCdfTable::decode(&self.get(content)?).map_err(SignalEvaluationError::Sampler)
    }

    fn evaluate_artifact_source(
        &self,
        node: &SignalNode,
        source: &SignalSourceSpecification,
        coordinate: &SignalCoordinate,
        same_coordinate_sequence: u64,
        choice: &SignalChoiceContext,
        inputs: &[EvaluatedSignal],
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        match source {
            SignalSourceSpecification::Trace {
                artifact,
                raw_provenance,
                channel,
                quality_channel,
                quality_accept,
                interpolation,
                before,
                after,
                missing,
                time_mapping,
            } => self.evaluate_trace(
                node,
                *artifact,
                *raw_provenance,
                channel,
                quality_channel.as_ref(),
                *quality_accept,
                *interpolation,
                before,
                after,
                *missing,
                time_mapping.as_ref(),
                coordinate,
                same_coordinate_sequence,
            ),
            SignalSourceSpecification::SeededField {
                field_seed_domain,
                coordinate_frame,
                quantization_mm,
                correlation_mm,
                distribution,
                distribution_parameters,
            } => evaluate_seeded_field(
                node,
                field_seed_domain,
                coordinate_frame,
                *quantization_mm,
                *correlation_mm,
                distribution,
                distribution_parameters,
                coordinate,
                choice,
            ),
            SignalSourceSpecification::PointSet { .. }
            | SignalSourceSpecification::RegularGrid { .. }
            | SignalSourceSpecification::TiledGrid { .. }
            | SignalSourceSpecification::ZoneMap { .. }
            | SignalSourceSpecification::PathProfile { .. }
            | SignalSourceSpecification::TransmitterField { .. } => {
                self.evaluate_spatial_artifact(node, source, coordinate, inputs)
            }
            _ => Err(SignalEvaluationError::ArtifactSourceRequired(
                node.id.clone(),
            )),
        }
    }
}

impl DagSignalArtifactProvider<'_> {
    fn evaluate_spatial_artifact(
        &self,
        node: &SignalNode,
        source: &SignalSourceSpecification,
        coordinate: &SignalCoordinate,
        inputs: &[EvaluatedSignal],
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        evaluate_normalized_spatial_source(self.store, node, source, coordinate, inputs)
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_trace(
        &self,
        node: &SignalNode,
        artifact: ContentHash,
        raw_provenance: ContentHash,
        channel_id: &SignalId,
        quality_channel: Option<&SignalId>,
        quality_accept: Option<i64>,
        interpolation: SignalInterpolation,
        before: &SignalBoundaryBehavior,
        after: &SignalBoundaryBehavior,
        missing: MissingSampleBehavior,
        mapping: Option<&TraceTimeMapping>,
        coordinate: &SignalCoordinate,
        same_coordinate_sequence: u64,
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        let manifest = SignalTraceManifest::decode(&self.get(&artifact)?)
            .map_err(SignalEvaluationError::Trace)?;
        if manifest.content != artifact
            || manifest.provenance.raw_content != Some(raw_provenance)
            || !self
                .store
                .exists(&raw_provenance)
                .map_err(SignalEvaluationError::Store)?
        {
            return Err(SignalEvaluationError::TraceProvenanceMismatch);
        }
        let channel = manifest
            .channels
            .iter()
            .find(|channel| &channel.id == channel_id)
            .ok_or_else(|| SignalEvaluationError::MissingTraceChannel(channel_id.clone()))?;
        if channel.shape != node.output {
            return Err(SignalEvaluationError::TraceShapeMismatch(node.id.clone()));
        }
        let simulation_coordinate = trace_request_coordinate(coordinate)?;
        let event_sequence = channel.event_channel.then_some(same_coordinate_sequence);
        let result = self.sample_trace_channel(
            channel,
            simulation_coordinate,
            event_sequence,
            interpolation,
            before,
            after,
            missing,
            mapping,
        )?;
        if let (Some(quality_channel), Some(quality_accept)) = (quality_channel, quality_accept) {
            let quality = manifest
                .channels
                .iter()
                .find(|channel| &channel.id == quality_channel)
                .ok_or_else(|| {
                    SignalEvaluationError::MissingTraceChannel(quality_channel.clone())
                })?;
            let quality = self.sample_trace_channel(
                quality,
                simulation_coordinate,
                None,
                SignalInterpolation::HoldPrevious,
                &SignalBoundaryBehavior::Error,
                &SignalBoundaryBehavior::Hold,
                MissingSampleBehavior::Error,
                mapping,
            )?;
            let quality = quality.value()?;
            if numeric_as_i128(quality)? < i128::from(quality_accept) {
                return match missing {
                    MissingSampleBehavior::Inactive => Ok(EvaluatedSignal::Inactive),
                    _ => Err(SignalEvaluationError::TraceQualityRejected),
                };
            }
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn sample_trace_channel(
        &self,
        channel: &TraceChannel,
        mut coordinate: u64,
        event_sequence: Option<u64>,
        interpolation: SignalInterpolation,
        before: &SignalBoundaryBehavior,
        after: &SignalBoundaryBehavior,
        missing: MissingSampleBehavior,
        mapping: Option<&TraceTimeMapping>,
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        if channel.event_channel != event_sequence.is_some() {
            return Err(SignalEvaluationError::TraceEventCoordinateMismatch);
        }
        let first = map_trace_coordinate(channel.chunks[0].first_coordinate, mapping)?;
        let last = map_trace_coordinate(
            channel.chunks[channel.chunks.len() - 1].last_coordinate,
            mapping,
        )?;
        if coordinate < first {
            if matches!(before, SignalBoundaryBehavior::Repeat) {
                coordinate = repeat_coordinate(coordinate, first, last)?;
            } else {
                let nearest = self.load_trace_edge(channel, true)?;
                return evaluate_boundary(before, Some(&nearest.value), None);
            }
        } else if coordinate > last {
            if matches!(after, SignalBoundaryBehavior::Repeat) {
                coordinate = repeat_coordinate(coordinate, first, last)?;
            } else {
                let nearest = self.load_trace_edge(channel, false)?;
                return evaluate_boundary(after, Some(&nearest.value), None);
            }
        }
        let candidate = channel.chunks.partition_point(|chunk| {
            map_trace_coordinate(chunk.last_coordinate, mapping).is_ok_and(|last| last < coordinate)
        });
        let candidate = candidate.min(channel.chunks.len() - 1);
        let mut start = candidate;
        let mut end = candidate + 1;
        let mut mapped = self.load_mapped_trace_chunk(channel, candidate, mapping)?;
        loop {
            let lower = mapped.iter().any(|entry| {
                entry.coordinate <= coordinate && entry.validity == TraceValidity::Valid
            });
            let upper = mapped.iter().any(|entry| {
                entry.coordinate >= coordinate && entry.validity == TraceValidity::Valid
            });
            let exact_event = event_sequence.is_some_and(|sequence| {
                mapped.iter().any(|entry| {
                    entry.coordinate == coordinate && entry.event_sequence == Some(sequence)
                })
            });
            let need_upper = matches!(
                interpolation,
                SignalInterpolation::Nearest | SignalInterpolation::Linear { .. }
            );
            let expand_left = !channel.event_channel && !lower && start > 0;
            let expand_right = if channel.event_channel {
                if !exact_event && end < channel.chunks.len() {
                    map_trace_coordinate(channel.chunks[end].first_coordinate, mapping)?
                        <= coordinate
                } else {
                    false
                }
            } else {
                need_upper && !upper && end < channel.chunks.len()
            };
            if !expand_left && !expand_right {
                break;
            }
            if expand_left {
                start -= 1;
                let mut preceding = self.load_mapped_trace_chunk(channel, start, mapping)?;
                preceding.append(&mut mapped);
                mapped = preceding;
            }
            if expand_right {
                mapped.extend(self.load_mapped_trace_chunk(channel, end, mapping)?);
                end += 1;
            }
        }
        if mapped.windows(2).any(|pair| {
            if channel.event_channel {
                (pair[0].coordinate, pair[0].event_sequence)
                    >= (pair[1].coordinate, pair[1].event_sequence)
            } else {
                pair[0].coordinate >= pair[1].coordinate
            }
        }) {
            return Err(SignalEvaluationError::NonMonotoneTraceMapping);
        }
        sample_mapped_entries(
            &mut mapped,
            coordinate,
            event_sequence,
            interpolation,
            missing,
        )
    }

    fn load_mapped_trace_chunk(
        &self,
        channel: &TraceChannel,
        index: usize,
        mapping: Option<&TraceTimeMapping>,
    ) -> Result<Vec<MappedTraceEntry>, SignalEvaluationError> {
        let reference = &channel.chunks[index];
        let chunk = SignalTraceChunk::decode(&self.get(&reference.content)?)
            .map_err(SignalEvaluationError::Trace)?;
        if chunk.content != reference.content
            || chunk.channel != channel.id
            || chunk.event_channel != channel.event_channel
            || chunk.reference() != *reference
        {
            return Err(SignalEvaluationError::TraceChunkMismatch(reference.content));
        }
        chunk
            .entries
            .into_iter()
            .map(|entry| {
                Ok(MappedTraceEntry {
                    coordinate: map_trace_coordinate(entry.coordinate, mapping)?,
                    event_sequence: entry.event_sequence,
                    value: entry.value,
                    validity: entry.validity,
                })
            })
            .collect()
    }

    fn load_trace_edge(
        &self,
        channel: &TraceChannel,
        first: bool,
    ) -> Result<TraceEntry, SignalEvaluationError> {
        for offset in 0..channel.chunks.len() {
            let index = if first {
                offset
            } else {
                channel.chunks.len() - 1 - offset
            };
            let reference = &channel.chunks[index];
            let chunk = SignalTraceChunk::decode(&self.get(&reference.content)?)
                .map_err(SignalEvaluationError::Trace)?;
            if chunk.content != reference.content
                || chunk.channel != channel.id
                || chunk.event_channel != channel.event_channel
                || chunk.reference() != *reference
            {
                return Err(SignalEvaluationError::TraceChunkMismatch(reference.content));
            }
            let entry = if first {
                chunk
                    .entries
                    .into_iter()
                    .find(|entry| entry.validity == TraceValidity::Valid)
            } else {
                chunk
                    .entries
                    .into_iter()
                    .rev()
                    .find(|entry| entry.validity == TraceValidity::Valid)
            };
            if let Some(entry) = entry {
                return Ok(entry);
            }
        }
        Err(SignalEvaluationError::TraceSampleMissing)
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_seeded_field(
    node: &SignalNode,
    field_seed_domain: &SignalId,
    coordinate_frame: &SignalId,
    quantization_mm: [u64; 3],
    correlation_mm: [u64; 3],
    distribution: &SignalId,
    parameters: &[i64],
    coordinate: &SignalCoordinate,
    choice: &SignalChoiceContext,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let SignalCoordinate::Spatial {
        frame,
        x_mm,
        y_mm,
        z_mm,
        ..
    } = coordinate
    else {
        return Err(SignalEvaluationError::SpatialCoordinateRequired);
    };
    if frame != coordinate_frame {
        return Err(SignalEvaluationError::SpatialFrameMismatch);
    }
    let coordinates = [*x_mm, *y_mm, *z_mm];
    let mut material = Vec::new();
    material.extend_from_slice(&choice.scenario_seed.bytes);
    material.extend_from_slice(field_seed_domain.as_str().as_bytes());
    material.push(0);
    for index in 0..3 {
        let quantum = i64::try_from(quantization_mm[index])
            .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
        let correlation = i64::try_from(correlation_mm[index])
            .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
        let quantized = coordinates[index].div_euclid(quantum);
        let correlated = quantized.div_euclid(correlation.div_euclid(quantum).max(1));
        material.extend_from_slice(&correlated.to_be_bytes());
    }
    let hash = ContentHash::from_bytes(&material);
    let draw = u64::from_be_bytes(hash.bytes[..8].try_into().unwrap_or([0; 8]));
    let value = match distribution.as_str() {
        "uniform-integer" if parameters.len() == 2 => {
            let minimum = parameters[0];
            let maximum = parameters[1];
            if minimum > maximum {
                return Err(SignalEvaluationError::InvalidSpatialDistribution);
            }
            let width = i128::from(maximum) - i128::from(minimum) + 1;
            let offset = if width == i128::from(u64::MAX) + 1 {
                i128::from(draw)
            } else {
                i128::from(
                    draw % u64::try_from(width)
                        .map_err(|_| SignalEvaluationError::InvalidSpatialDistribution)?,
                )
            };
            SignalValue::I64(
                i64::try_from(i128::from(minimum) + offset)
                    .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
            )
        }
        "probability-millionths" if parameters.len() == 1 => {
            let maximum = parameters[0];
            if !(0..=1_000_000).contains(&maximum) {
                return Err(SignalEvaluationError::InvalidSpatialDistribution);
            }
            SignalValue::ProbabilityMillionths(
                u32::try_from(draw % (u64::try_from(maximum).unwrap_or(0) + 1))
                    .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
            )
        }
        "signed-hash" if parameters.is_empty() => {
            SignalValue::I64(i64::from_be_bytes(draw.to_be_bytes()))
        }
        _ => return Err(SignalEvaluationError::InvalidSpatialDistribution),
    };
    if value.value_type().as_ref() != Some(&node.output.value_type) {
        return Err(SignalEvaluationError::OutputShapeMismatch(node.id.clone()));
    }
    Ok(EvaluatedSignal::Value(value))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MappedTraceEntry {
    coordinate: u64,
    event_sequence: Option<u64>,
    value: SignalValue,
    validity: TraceValidity,
}

fn trace_request_coordinate(coordinate: &SignalCoordinate) -> Result<u64, SignalEvaluationError> {
    match coordinate {
        SignalCoordinate::VirtualTime { nanos } => Ok(*nanos),
        SignalCoordinate::Event { parent, .. } => match parent.as_ref() {
            SignalCoordinate::VirtualTime { nanos } => Ok(*nanos),
            _ => Err(SignalEvaluationError::TraceEventCoordinateMismatch),
        },
        _ => Err(SignalEvaluationError::VirtualTimeRequired),
    }
}

pub(super) fn map_trace_coordinate(
    coordinate: u64,
    mapping: Option<&TraceTimeMapping>,
) -> Result<u64, SignalEvaluationError> {
    let Some(mapping) = mapping else {
        return Ok(coordinate);
    };
    let delta = i128::from(coordinate)
        .checked_sub(i128::from(mapping.source_epoch))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let numerator = delta
        .checked_mul(i128::from(mapping.scale.numerator()))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let scaled = round_signed(
        numerator,
        u128::from(mapping.scale.denominator()),
        mapping.rounding,
    )?;
    let result = i128::from(mapping.virtual_epoch_nanos)
        .checked_add(scaled)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    u64::try_from(result).map_err(|_| SignalEvaluationError::ArithmeticOverflow)
}

fn repeat_coordinate(coordinate: u64, first: u64, last: u64) -> Result<u64, SignalEvaluationError> {
    let period = last
        .checked_sub(first)
        .ok_or(SignalEvaluationError::InvalidRepeatExtent)?;
    if period == 0 {
        return Err(SignalEvaluationError::InvalidRepeatExtent);
    }
    if coordinate < first {
        let distance = first - coordinate;
        let remainder = distance % period;
        Ok(if remainder == 0 {
            first
        } else {
            last - remainder
        })
    } else {
        Ok(first + (coordinate - first) % period)
    }
}

fn sample_mapped_entries(
    entries: &mut [MappedTraceEntry],
    coordinate: u64,
    event_sequence: Option<u64>,
    interpolation: SignalInterpolation,
    missing: MissingSampleBehavior,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if let Some(sequence) = event_sequence {
        let exact = entries
            .iter()
            .find(|entry| entry.coordinate == coordinate && entry.event_sequence == Some(sequence));
        return exact.map_or(Ok(EvaluatedSignal::Inactive), |entry| {
            accept_trace_entry(entry, missing)
        });
    }
    let upper = entries.partition_point(|entry| entry.coordinate <= coordinate);
    let exact = upper
        .checked_sub(1)
        .and_then(|index| entries.get(index))
        .filter(|entry| entry.coordinate == coordinate);
    if let Some(exact) = exact {
        if exact.validity == TraceValidity::Valid {
            return Ok(EvaluatedSignal::Value(exact.value.clone()));
        }
        match missing {
            MissingSampleBehavior::Error => return Err(SignalEvaluationError::TraceSampleMissing),
            MissingSampleBehavior::Inactive => return Ok(EvaluatedSignal::Inactive),
            MissingSampleBehavior::Hold | MissingSampleBehavior::Interpolate => {}
        }
    }
    let interpolation = if missing == MissingSampleBehavior::Hold {
        SignalInterpolation::HoldPrevious
    } else {
        interpolation
    };
    match interpolation {
        SignalInterpolation::Exact => handle_missing_trace(entries, upper, missing),
        SignalInterpolation::HoldPrevious => entries[..upper]
            .iter()
            .rev()
            .find(|entry| entry.validity == TraceValidity::Valid)
            .map(|entry| EvaluatedSignal::Value(entry.value.clone()))
            .ok_or(SignalEvaluationError::TraceSampleMissing),
        SignalInterpolation::Nearest => {
            let lower = entries[..upper]
                .iter()
                .rev()
                .find(|entry| entry.validity == TraceValidity::Valid);
            let upper = entries[upper..]
                .iter()
                .find(|entry| entry.validity == TraceValidity::Valid);
            let selected = match (lower, upper) {
                (Some(lower), Some(upper)) => {
                    if coordinate - lower.coordinate <= upper.coordinate - coordinate {
                        lower
                    } else {
                        upper
                    }
                }
                (Some(value), None) | (None, Some(value)) => value,
                (None, None) => {
                    return handle_missing_trace(
                        entries,
                        upper_index(entries, coordinate),
                        missing,
                    );
                }
            };
            Ok(EvaluatedSignal::Value(selected.value.clone()))
        }
        SignalInterpolation::Linear { rounding, overflow } => {
            let lower = entries[..upper]
                .iter()
                .rev()
                .find(|entry| entry.validity == TraceValidity::Valid);
            let upper_entry = entries[upper..]
                .iter()
                .find(|entry| entry.validity == TraceValidity::Valid);
            let (Some(lower), Some(upper_entry)) = (lower, upper_entry) else {
                return handle_missing_trace(entries, upper, missing);
            };
            if entries.iter().any(|entry| {
                entry.coordinate > lower.coordinate
                    && entry.coordinate < upper_entry.coordinate
                    && entry.validity == TraceValidity::Discontinuity
            }) {
                return Err(SignalEvaluationError::TraceDiscontinuity);
            }
            Ok(EvaluatedSignal::Value(interpolate_value(
                &lower.value,
                &upper_entry.value,
                coordinate - lower.coordinate,
                upper_entry.coordinate - lower.coordinate,
                rounding,
                overflow,
            )?))
        }
    }
}

fn upper_index(entries: &[MappedTraceEntry], coordinate: u64) -> usize {
    entries.partition_point(|entry| entry.coordinate <= coordinate)
}

fn accept_trace_entry(
    entry: &MappedTraceEntry,
    missing: MissingSampleBehavior,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    match entry.validity {
        TraceValidity::Valid => Ok(EvaluatedSignal::Value(entry.value.clone())),
        TraceValidity::InvalidQuality | TraceValidity::Missing | TraceValidity::Discontinuity => {
            match missing {
                MissingSampleBehavior::Inactive => Ok(EvaluatedSignal::Inactive),
                _ => Err(SignalEvaluationError::TraceSampleMissing),
            }
        }
    }
}

fn handle_missing_trace(
    entries: &[MappedTraceEntry],
    upper: usize,
    missing: MissingSampleBehavior,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    match missing {
        MissingSampleBehavior::Inactive => Ok(EvaluatedSignal::Inactive),
        MissingSampleBehavior::Hold => entries[..upper]
            .iter()
            .rev()
            .find(|entry| entry.validity == TraceValidity::Valid)
            .map(|entry| EvaluatedSignal::Value(entry.value.clone()))
            .ok_or(SignalEvaluationError::TraceSampleMissing),
        MissingSampleBehavior::Interpolate => Err(SignalEvaluationError::TraceSampleMissing),
        MissingSampleBehavior::Error => Err(SignalEvaluationError::TraceSampleMissing),
    }
}

fn numeric_as_i128(value: &SignalValue) -> Result<i128, SignalEvaluationError> {
    let (numerator, denominator) = numeric_fraction(value)?;
    if denominator != 1 {
        return Err(SignalEvaluationError::TypeMismatch);
    }
    Ok(numerator)
}

/// Mutable, checkpointable execution state for one signal program.
pub struct SignalEvaluator<'a> {
    program: &'a SignalProgram,
    artifacts: &'a dyn SignalArtifactProvider,
    boundary: SignalBoundarySnapshot,
    state: BTreeMap<SignalId, EvaluatorNodeState>,
    state_coordinates: BTreeMap<SignalId, (SignalCoordinate, u64)>,
    history: BTreeMap<SignalId, VecDeque<HistoryEntry>>,
    history_limits: BTreeMap<SignalId, usize>,
    retained_history: usize,
    emitted_events: Vec<StatefulSignalEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HistoryEntry {
    coordinate: SignalCoordinate,
    same_coordinate_sequence: u64,
    output: EvaluatedSignal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EvaluatorNodeState {
    Hysteresis {
        value: bool,
        last_transition_nanos: u64,
    },
    Debounce {
        committed: SignalValue,
        candidate: Option<SignalValue>,
        candidate_since_nanos: Option<u64>,
    },
    Integrator {
        accumulator: SignalValue,
        pending: SignalValue,
        previous_input: Option<SignalValue>,
        last_nanos: Option<u64>,
    },
    LeakyIntegrator {
        accumulator: SignalValue,
        previous_input: Option<SignalValue>,
        last_nanos: Option<u64>,
    },
    FiniteStateMachine {
        state: SignalId,
        timers: BTreeMap<SignalId, u64>,
    },
    MarkovChain {
        state: SignalId,
        transition_sequence: u64,
    },
    BurstProcess {
        bad: bool,
        transition_sequence: u64,
    },
    Counter {
        count: u64,
    },
    QueueModel {
        backlog: u32,
        service_remainder: u64,
        last_nanos: Option<u64>,
    },
}

impl<'a> SignalEvaluator<'a> {
    /// Creates an evaluator with validated declared initial state and empty history.
    ///
    /// # Errors
    ///
    /// Returns [`SignalEvaluationError`] when initial state, telemetry, or
    /// retained-history declarations exceed their hard or authored bounds.
    pub fn new(
        program: &'a SignalProgram,
        artifacts: &'a dyn SignalArtifactProvider,
        boundary: SignalBoundarySnapshot,
    ) -> Result<Self, SignalEvaluationError> {
        if boundary.telemetry.len() > HARD_SIGNAL_BOUNDARY_ITEMS {
            return Err(SignalEvaluationError::ResourceLimit);
        }
        let state = initial_states(program)?;
        for (id, value) in &state {
            let actual = encode_node_state(value)?.len();
            let declared = program
                .nodes()
                .iter()
                .find(|node| &node.id == id)
                .and_then(|node| match node.kind {
                    SignalNodeKind::Stateful { state_bytes, .. } => Some(state_bytes),
                    _ => None,
                })
                .ok_or_else(|| SignalEvaluationError::MissingState(id.clone()))?;
            if u64::try_from(actual).map_or(true, |actual| actual > declared) {
                return Err(SignalEvaluationError::StateBoundExceeded {
                    node: id.clone(),
                    actual,
                    declared,
                });
            }
        }
        let history_limits = history_limits(program);
        if history_limits
            .values()
            .try_fold(0_usize, |total, limit| total.checked_add(*limit))
            .is_none_or(|total| total > HARD_SIGNAL_HISTORY_ENTRIES)
        {
            return Err(SignalEvaluationError::ResourceLimit);
        }
        Ok(Self {
            program,
            artifacts,
            boundary,
            state,
            state_coordinates: BTreeMap::new(),
            history: BTreeMap::new(),
            history_limits,
            retained_history: 0,
            emitted_events: Vec::new(),
        })
    }

    /// Replaces the immutable start-of-boundary telemetry snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SignalEvaluationError::ResourceLimit`] when the snapshot
    /// exceeds the compiled telemetry-item ceiling.
    pub fn set_boundary_snapshot(
        &mut self,
        boundary: SignalBoundarySnapshot,
    ) -> Result<(), SignalEvaluationError> {
        if boundary.telemetry.len() > HARD_SIGNAL_BOUNDARY_ITEMS {
            return Err(SignalEvaluationError::ResourceLimit);
        }
        self.boundary = boundary;
        Ok(())
    }

    /// Drains state-machine events emitted since the previous drain.
    #[must_use]
    pub fn take_emitted_events(&mut self) -> Vec<StatefulSignalEvent> {
        std::mem::take(&mut self.emitted_events)
    }

    /// Encodes all mutable state, retained history, delayed telemetry, and
    /// pending state-machine events into one canonical checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SignalEvaluationError`] when a node exceeds its authored state
    /// bound, a compiled checkpoint/resource ceiling is exceeded, or a value
    /// cannot be encoded canonically.
    pub fn checkpoint(&self) -> Result<SignalEvaluatorCheckpoint, SignalEvaluationError> {
        if self.boundary.telemetry.len() > HARD_SIGNAL_BOUNDARY_ITEMS
            || self.state.len() > HARD_SIGNAL_BOUNDARY_ITEMS
            || self.state_coordinates.len() > HARD_SIGNAL_BOUNDARY_ITEMS
            || self.history.len() > HARD_SIGNAL_BOUNDARY_ITEMS
            || self.emitted_events.len() > HARD_SIGNAL_BOUNDARY_ITEMS
            || self.retained_history > HARD_SIGNAL_HISTORY_ENTRIES
        {
            return Err(SignalEvaluationError::ResourceLimit);
        }
        let mut writer = EvaluatorWriter::default();
        writer.bytes.extend_from_slice(EVALUATOR_CHECKPOINT_MAGIC);
        writer.u16(SIGNAL_EVALUATOR_VERSION);
        writer.bytes.extend_from_slice(&self.program.id().bytes);
        writer.count(self.boundary.telemetry.len())?;
        for (key, value) in &self.boundary.telemetry {
            writer.id(&key.adapter)?;
            writer.id(&key.target)?;
            writer.id(&key.field)?;
            writer.value(value)?;
        }
        writer.count(self.state.len())?;
        for (id, state) in &self.state {
            writer.id(id)?;
            let bytes = encode_node_state(state)?;
            let declared = self
                .program
                .nodes()
                .iter()
                .find(|node| &node.id == id)
                .and_then(|node| match node.kind {
                    SignalNodeKind::Stateful { state_bytes, .. } => Some(state_bytes),
                    _ => None,
                })
                .ok_or_else(|| SignalEvaluationError::MissingState(id.clone()))?;
            if u64::try_from(bytes.len()).map_or(true, |length| length > declared) {
                return Err(SignalEvaluationError::StateBoundExceeded {
                    node: id.clone(),
                    actual: bytes.len(),
                    declared,
                });
            }
            writer.blob(&bytes)?;
        }
        writer.count(self.state_coordinates.len())?;
        for (id, (coordinate, sequence)) in &self.state_coordinates {
            writer.id(id)?;
            writer.coordinate(coordinate)?;
            writer.u64(*sequence);
        }
        writer.count(self.history.len())?;
        for (id, entries) in &self.history {
            writer.id(id)?;
            writer.count(entries.len())?;
            for entry in entries {
                writer.coordinate(&entry.coordinate)?;
                writer.u64(entry.same_coordinate_sequence);
                writer.evaluated(&entry.output)?;
            }
        }
        writer.count(self.emitted_events.len())?;
        for event in &self.emitted_events {
            writer.id(&event.node)?;
            writer.id(&event.variant)?;
            writer.coordinate(&event.coordinate)?;
            writer.u64(event.same_coordinate_sequence);
        }
        if writer.bytes.len() > HARD_SIGNAL_EVALUATOR_CHECKPOINT_BYTES {
            return Err(SignalEvaluationError::CheckpointLimit);
        }
        let content = ContentHash::from_bytes(&writer.bytes);
        Ok(SignalEvaluatorCheckpoint {
            bytes: writer.bytes,
            content,
        })
    }

    /// Restores an evaluator from canonical checkpoint bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignalEvaluationError`] when bytes are malformed,
    /// noncanonical, oversized, for another program/version, incomplete, or
    /// violate a node's type, state, history, or resource contract.
    pub fn restore(
        program: &'a SignalProgram,
        artifacts: &'a dyn SignalArtifactProvider,
        checkpoint: &SignalEvaluatorCheckpoint,
    ) -> Result<Self, SignalEvaluationError> {
        if checkpoint.bytes.len() > HARD_SIGNAL_EVALUATOR_CHECKPOINT_BYTES
            || ContentHash::from_bytes(&checkpoint.bytes) != checkpoint.content
        {
            return Err(SignalEvaluationError::CheckpointContentMismatch);
        }
        decode_evaluator_checkpoint(program, artifacts, checkpoint)
    }

    /// Evaluates one exported output at one explicit coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`SignalEvaluationError`] for a non-exported output, domain
    /// mismatch, unavailable artifact or telemetry, inactive required input,
    /// non-monotone stateful evaluation, resource exhaustion, or checked
    /// arithmetic/type failure.
    pub fn evaluate(
        &mut self,
        request: &SignalEvaluationRequest,
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        if self.program.exported_shape(&request.output).is_none() {
            return Err(SignalEvaluationError::NotExported(request.output.clone()));
        }
        let mut memo = BTreeMap::new();
        let result = self.evaluate_node(&request.output, request, &mut memo)?;
        for ((id, coordinate, sequence), output) in memo {
            self.record_history(id, coordinate, sequence, output)?;
        }
        Ok(result)
    }

    fn evaluate_node(
        &mut self,
        id: &SignalId,
        request: &SignalEvaluationRequest,
        memo: &mut BTreeMap<(SignalId, SignalCoordinate, u64), EvaluatedSignal>,
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        let memo_key = (
            id.clone(),
            request.coordinate.clone(),
            request.same_coordinate_sequence,
        );
        if let Some(value) = memo.get(&memo_key) {
            return Ok(value.clone());
        }
        let node = self
            .program
            .nodes()
            .iter()
            .find(|node| &node.id == id)
            .ok_or_else(|| SignalEvaluationError::MissingNode(id.clone()))?;
        if node.domain != coordinate_domain_runtime(&request.coordinate) {
            return Err(SignalEvaluationError::DomainMismatch {
                node: id.clone(),
                expected: node.domain,
                actual: coordinate_domain_runtime(&request.coordinate),
            });
        }
        let inputs = if let SignalNodeKind::Pure(PureSignalSpecification::MergeEvents {
            source_sequence_limit,
        }) = &node.kind
        {
            self.evaluate_merged_event_input(node, request, memo, *source_sequence_limit)?
        } else if matches!(
            &node.kind,
            SignalNodeKind::Pure(PureSignalSpecification::FieldSample)
                | SignalNodeKind::Pure(PureSignalSpecification::ZoneContains { .. })
        ) {
            self.evaluate_spatial_inputs(node, request, memo)?
        } else {
            let mut inputs = Vec::with_capacity(node.inputs.len());
            for input in &node.inputs {
                inputs.push(self.evaluate_node(input, request, memo)?);
            }
            inputs
        };
        let output = match &node.kind {
            SignalNodeKind::Constant { value } => EvaluatedSignal::Value(value.clone()),
            SignalNodeKind::Source(source) => {
                self.evaluate_source(node, source, request, &inputs)?
            }
            SignalNodeKind::Pure(specification) => {
                self.evaluate_pure(node, specification, request, &inputs)?
            }
            SignalNodeKind::Stateful { specification, .. } => {
                self.evaluate_stateful(node, specification, request, &inputs)?
            }
        };
        validate_evaluated_shape(node, &output)?;
        memo.insert(memo_key, output.clone());
        Ok(output)
    }

    fn evaluate_merged_event_input(
        &mut self,
        node: &SignalNode,
        request: &SignalEvaluationRequest,
        memo: &mut BTreeMap<(SignalId, SignalCoordinate, u64), EvaluatedSignal>,
        source_sequence_limit: u64,
    ) -> Result<Vec<EvaluatedSignal>, SignalEvaluationError> {
        let source_index = request.same_coordinate_sequence / source_sequence_limit;
        let Some(source) = usize::try_from(source_index)
            .ok()
            .and_then(|index| node.inputs.get(index))
        else {
            return Ok(vec![EvaluatedSignal::Inactive]);
        };
        let mut local_request = request.clone();
        local_request.same_coordinate_sequence =
            request.same_coordinate_sequence % source_sequence_limit;
        Ok(vec![self.evaluate_node(source, &local_request, memo)?])
    }

    fn evaluate_spatial_inputs(
        &mut self,
        node: &SignalNode,
        request: &SignalEvaluationRequest,
        memo: &mut BTreeMap<(SignalId, SignalCoordinate, u64), EvaluatedSignal>,
    ) -> Result<Vec<EvaluatedSignal>, SignalEvaluationError> {
        let (field_id, position_id) = match &node.kind {
            SignalNodeKind::Pure(PureSignalSpecification::FieldSample) => {
                (&node.inputs[0], &node.inputs[1])
            }
            SignalNodeKind::Pure(PureSignalSpecification::ZoneContains { .. }) => {
                (&node.inputs[1], &node.inputs[0])
            }
            _ => return Err(SignalEvaluationError::InvalidOperator),
        };
        let position = self.evaluate_node(position_id, request, memo)?;
        let [x_mm, y_mm, z_mm] = position_vector(position.value()?)?;
        let field = self
            .program
            .nodes()
            .iter()
            .find(|candidate| &candidate.id == field_id)
            .ok_or_else(|| SignalEvaluationError::MissingNode(field_id.clone()))?;
        let frame = spatial_frame(field)?;
        let mut spatial_request = request.clone();
        spatial_request.coordinate = SignalCoordinate::Spatial {
            frame,
            x_mm,
            y_mm,
            z_mm,
            yaw_mdeg: 0,
            pitch_mdeg: 0,
            roll_mdeg: 0,
        };
        let sampled = self.evaluate_node(field_id, &spatial_request, memo)?;
        Ok(match &node.kind {
            SignalNodeKind::Pure(PureSignalSpecification::FieldSample) => {
                vec![sampled, position]
            }
            _ => vec![sampled, position],
        })
    }

    fn evaluate_source(
        &self,
        node: &SignalNode,
        source: &SignalSourceSpecification,
        request: &SignalEvaluationRequest,
        inputs: &[EvaluatedSignal],
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        match source {
            SignalSourceSpecification::Step { points, before } => {
                evaluate_step(points, before, &request.coordinate)
            }
            SignalSourceSpecification::Pulse {
                start,
                duration,
                inactive,
                active,
            } => {
                let coordinate = coordinate_offset(start, &request.coordinate)?;
                Ok(EvaluatedSignal::Value(if coordinate < *duration {
                    active.clone()
                } else {
                    inactive.clone()
                }))
            }
            SignalSourceSpecification::PeriodicPulse {
                epoch,
                period,
                width,
                phase,
                inactive,
                active,
            } => {
                let coordinate = coordinate_offset(epoch, &request.coordinate)?;
                let position = coordinate
                    .checked_add(*phase)
                    .ok_or(SignalEvaluationError::ArithmeticOverflow)?
                    % period;
                Ok(EvaluatedSignal::Value(if position < *width {
                    active.clone()
                } else {
                    inactive.clone()
                }))
            }
            SignalSourceSpecification::Ramp {
                start,
                end,
                start_value,
                end_value,
                rounding,
            } => evaluate_ramp(
                start,
                end,
                start_value,
                end_value,
                &request.coordinate,
                *rounding,
                SignalOverflow::Error,
            ),
            SignalSourceSpecification::Triangle {
                epoch,
                period,
                phase,
                minimum,
                maximum,
                rounding,
            } => evaluate_triangle(
                epoch,
                *period,
                *phase,
                minimum,
                maximum,
                &request.coordinate,
                *rounding,
            ),
            SignalSourceSpecification::Sawtooth {
                epoch,
                period,
                phase,
                minimum,
                maximum,
                rounding,
            } => evaluate_sawtooth(
                epoch,
                *period,
                *phase,
                minimum,
                maximum,
                &request.coordinate,
                *rounding,
            ),
            SignalSourceSpecification::EventSequence { events } => evaluate_event_sequence(
                events,
                &request.coordinate,
                request.same_coordinate_sequence,
            ),
            SignalSourceSpecification::Telemetry {
                adapter,
                target,
                field,
                ..
            } => self
                .boundary
                .telemetry
                .get(&SignalTelemetryKey {
                    adapter: adapter.clone(),
                    target: target.clone(),
                    field: field.clone(),
                })
                .cloned()
                .map(EvaluatedSignal::Value)
                .ok_or_else(|| SignalEvaluationError::MissingTelemetry {
                    adapter: adapter.clone(),
                    target: target.clone(),
                    field: field.clone(),
                }),
            SignalSourceSpecification::Bernoulli {
                probability_millionths,
                key_domain,
                opportunity_filter,
            } => {
                if !choice_applies(*key_domain, opportunity_filter.as_ref(), request)? {
                    return Ok(EvaluatedSignal::Inactive);
                }
                let draw = keyed_u64(node, request, *key_domain, 0) % 1_000_000;
                Ok(EvaluatedSignal::Value(SignalValue::Bool(
                    draw < u64::from(*probability_millionths),
                )))
            }
            SignalSourceSpecification::UniformInteger {
                minimum,
                maximum,
                key_domain,
                opportunity_filter,
            } => {
                if !choice_applies(*key_domain, opportunity_filter.as_ref(), request)? {
                    return Ok(EvaluatedSignal::Inactive);
                }
                let value = uniform_i64(node, request, *key_domain, *minimum, *maximum)?;
                Ok(EvaluatedSignal::Value(SignalValue::I64(value)))
            }
            SignalSourceSpecification::ExponentialWait {
                rate,
                sampler_table,
                key_domain,
                maximum_nanos,
                ..
            } => {
                choice_applies(*key_domain, None, request)?;
                let table = self.artifacts.inverse_cdf_table(sampler_table)?;
                if table.content() != *sampler_table
                    || table.distribution() != (InverseCdfDistribution::Exponential { rate: *rate })
                {
                    return Err(SignalEvaluationError::SamplerContractMismatch(
                        node.id.clone(),
                    ));
                }
                let sampled = table.sample(keyed_u64(node, request, *key_domain, 0));
                Ok(EvaluatedSignal::Value(SignalValue::DurationNanos(
                    maximum_nanos.map_or(sampled, |maximum| sampled.min(maximum)),
                )))
            }
            SignalSourceSpecification::WeibullWait {
                shape,
                scale_nanos,
                sampler_table,
                key_domain,
                maximum_nanos,
                ..
            } => {
                choice_applies(*key_domain, None, request)?;
                let table = self.artifacts.inverse_cdf_table(sampler_table)?;
                if table.content() != *sampler_table
                    || table.distribution()
                        != (InverseCdfDistribution::Weibull {
                            shape: *shape,
                            scale_nanos: *scale_nanos,
                        })
                {
                    return Err(SignalEvaluationError::SamplerContractMismatch(
                        node.id.clone(),
                    ));
                }
                let sampled = table.sample(keyed_u64(node, request, *key_domain, 0));
                Ok(EvaluatedSignal::Value(SignalValue::DurationNanos(
                    maximum_nanos.map_or(sampled, |maximum| sampled.min(maximum)),
                )))
            }
            SignalSourceSpecification::Trace { .. }
            | SignalSourceSpecification::PointSet { .. }
            | SignalSourceSpecification::RegularGrid { .. }
            | SignalSourceSpecification::TiledGrid { .. }
            | SignalSourceSpecification::ZoneMap { .. }
            | SignalSourceSpecification::PathProfile { .. }
            | SignalSourceSpecification::SeededField { .. }
            | SignalSourceSpecification::TransmitterField { .. } => {
                self.artifacts.evaluate_artifact_source(
                    node,
                    source,
                    &request.coordinate,
                    request.same_coordinate_sequence,
                    &request.choice,
                    inputs,
                )
            }
        }
    }

    fn evaluate_pure(
        &mut self,
        node: &SignalNode,
        specification: &PureSignalSpecification,
        request: &SignalEvaluationRequest,
        inputs: &[EvaluatedSignal],
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        match specification {
            PureSignalSpecification::Simple { operator, overflow } => evaluate_simple(
                node,
                *operator,
                *overflow,
                inputs,
                self.history.get(&node.inputs[0]),
            ),
            PureSignalSpecification::RatioArithmetic {
                operator,
                ratio,
                rounding,
                overflow,
            } => {
                let value = inputs[0].value()?;
                let ratio = if *operator == PureSignalOperator::DivideRatio {
                    let magnitude = i64::try_from(ratio.denominator())
                        .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
                    let reciprocal_numerator = if ratio.numerator() < 0 {
                        magnitude
                            .checked_neg()
                            .ok_or(SignalEvaluationError::ArithmeticOverflow)?
                    } else {
                        magnitude
                    };
                    ExactRatio::new(reciprocal_numerator, ratio.numerator().unsigned_abs())
                        .map_err(SignalEvaluationError::Program)?
                } else {
                    *ratio
                };
                Ok(EvaluatedSignal::Value(scale_value(
                    value,
                    ratio,
                    ExactRatio::new(0, 1).map_err(SignalEvaluationError::Program)?,
                    *rounding,
                    *overflow,
                )?))
            }
            PureSignalSpecification::Clamp {
                minimum, maximum, ..
            } => {
                let value = inputs[0].value()?;
                let value = if compare_numeric(value, minimum)?.is_lt() {
                    minimum.clone()
                } else if compare_numeric(value, maximum)?.is_gt() {
                    maximum.clone()
                } else {
                    value.clone()
                };
                Ok(EvaluatedSignal::Value(value))
            }
            PureSignalSpecification::LookupStep {
                points,
                before,
                after,
            } => evaluate_lookup_step(inputs[0].value()?, points, before, after),
            PureSignalSpecification::PiecewiseLinear {
                points,
                rounding,
                overflow,
            } => evaluate_piecewise_linear(inputs[0].value()?, points, *rounding, *overflow),
            PureSignalSpecification::EnumMap { entries } => {
                let SignalValue::Enum { variant, .. } = inputs[0].value()? else {
                    return Err(SignalEvaluationError::TypeMismatch);
                };
                entries
                    .iter()
                    .find(|(candidate, _)| candidate == variant)
                    .map(|(_, value)| EvaluatedSignal::Value(value.clone()))
                    .ok_or(SignalEvaluationError::UnmappedEnum)
            }
            PureSignalSpecification::UnitConvert {
                ratio,
                offset,
                rounding,
                overflow,
                ..
            } => Ok(EvaluatedSignal::Value(scale_value(
                inputs[0].value()?,
                *ratio,
                *offset,
                *rounding,
                *overflow,
            )?)),
            PureSignalSpecification::Delay { delay, .. } => {
                let target = subtract_coordinate(&request.coordinate, *delay)?;
                history_at(
                    self.history.get(&node.inputs[0]),
                    &target,
                    request.same_coordinate_sequence,
                )
            }
            PureSignalSpecification::SampleHold { cadence, epoch, .. } => {
                let elapsed = coordinate_offset(epoch, &request.coordinate)?;
                let target = add_coordinate(epoch, elapsed / cadence * cadence)?;
                if target == request.coordinate {
                    Ok(inputs[0].clone())
                } else {
                    history_at(
                        self.history.get(&node.inputs[0]),
                        &target,
                        request.same_coordinate_sequence,
                    )
                }
            }
            PureSignalSpecification::Window {
                operator,
                window,
                retained_samples,
                rounding,
                overflow,
                ..
            } => evaluate_window(
                *operator,
                *window,
                usize::try_from(*retained_samples)
                    .map_err(|_| SignalEvaluationError::ResourceLimit)?,
                *rounding,
                *overflow,
                &request.coordinate,
                request.same_coordinate_sequence,
                self.history.get(&node.inputs[0]),
                &inputs[0],
            ),
            PureSignalSpecification::Distance { metric, rounding } => {
                evaluate_distance(metric, *rounding, inputs)
            }
            PureSignalSpecification::ZoneContains { zone } => evaluate_zone_contains(zone, inputs),
            PureSignalSpecification::FieldSample => inputs
                .first()
                .cloned()
                .ok_or(SignalEvaluationError::TypeMismatch),
            PureSignalSpecification::OrientationDelta { convention } => {
                evaluate_orientation_delta(convention, inputs)
            }
            PureSignalSpecification::MergeEvents { .. } => merge_events(inputs),
            PureSignalSpecification::GateEvents => {
                if bool_value(inputs[1].value()?)? {
                    Ok(inputs[0].clone())
                } else {
                    Ok(EvaluatedSignal::Inactive)
                }
            }
        }
    }

    fn evaluate_stateful(
        &mut self,
        node: &SignalNode,
        specification: &StatefulSignalSpecification,
        request: &SignalEvaluationRequest,
        inputs: &[EvaluatedSignal],
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        let current = (request.coordinate.clone(), request.same_coordinate_sequence);
        if let Some(previous) = self.state_coordinates.get(&node.id) {
            if current < *previous {
                return Err(SignalEvaluationError::NonMonotoneEvaluation);
            }
            if current == *previous {
                return state_output(
                    node,
                    self.state
                        .get(&node.id)
                        .ok_or_else(|| SignalEvaluationError::MissingState(node.id.clone()))?,
                );
            }
        }
        let output = evaluate_stateful_node(
            node,
            specification,
            request,
            inputs,
            self.state
                .get_mut(&node.id)
                .ok_or_else(|| SignalEvaluationError::MissingState(node.id.clone()))?,
            &mut self.emitted_events,
        )?;
        self.state_coordinates.insert(node.id.clone(), current);
        Ok(output)
    }

    fn record_history(
        &mut self,
        id: SignalId,
        coordinate: SignalCoordinate,
        same_coordinate_sequence: u64,
        output: EvaluatedSignal,
    ) -> Result<(), SignalEvaluationError> {
        let Some(limit) = self.history_limits.get(&id).copied() else {
            return Ok(());
        };
        let entries = self.history.entry(id).or_default();
        if let Some(last) = entries.back() {
            if (&coordinate, same_coordinate_sequence)
                < (&last.coordinate, last.same_coordinate_sequence)
            {
                return Err(SignalEvaluationError::NonMonotoneEvaluation);
            }
            if coordinate == last.coordinate
                && same_coordinate_sequence == last.same_coordinate_sequence
            {
                if output != last.output {
                    return Err(SignalEvaluationError::NonDeterministicRepeat);
                }
                return Ok(());
            }
        }
        if entries.len() == limit {
            entries.pop_front();
            self.retained_history = self.retained_history.saturating_sub(1);
        }
        if self.retained_history == HARD_SIGNAL_HISTORY_ENTRIES {
            return Err(SignalEvaluationError::ResourceLimit);
        }
        entries.push_back(HistoryEntry {
            coordinate,
            same_coordinate_sequence,
            output,
        });
        self.retained_history += 1;
        Ok(())
    }
}

fn history_limits(program: &SignalProgram) -> BTreeMap<SignalId, usize> {
    let mut limits: BTreeMap<SignalId, usize> = BTreeMap::new();
    for node in program.nodes() {
        let (input, retained) = match &node.kind {
            SignalNodeKind::Pure(
                PureSignalSpecification::Delay {
                    retained_samples, ..
                }
                | PureSignalSpecification::SampleHold {
                    retained_samples, ..
                }
                | PureSignalSpecification::Window {
                    retained_samples, ..
                },
            ) => (node.inputs.first(), *retained_samples),
            SignalNodeKind::Pure(PureSignalSpecification::Simple {
                operator: PureSignalOperator::EdgeRising | PureSignalOperator::EdgeFalling,
                ..
            }) => (node.inputs.first(), 1),
            _ => (None, 0),
        };
        if let Some(input) = input {
            let retained = usize::try_from(retained).unwrap_or(usize::MAX);
            limits
                .entry(input.clone())
                .and_modify(|limit| *limit = (*limit).max(retained))
                .or_insert(retained);
        }
    }
    limits
}

fn initial_states(
    program: &SignalProgram,
) -> Result<BTreeMap<SignalId, EvaluatorNodeState>, SignalEvaluationError> {
    let mut states = BTreeMap::new();
    for node in program.nodes() {
        let SignalNodeKind::Stateful { specification, .. } = &node.kind else {
            continue;
        };
        let state = match specification {
            StatefulSignalSpecification::Hysteresis { initial, .. } => {
                EvaluatorNodeState::Hysteresis {
                    value: *initial,
                    last_transition_nanos: 0,
                }
            }
            StatefulSignalSpecification::Debounce { initial, .. } => EvaluatorNodeState::Debounce {
                committed: initial.clone(),
                candidate: None,
                candidate_since_nanos: None,
            },
            StatefulSignalSpecification::Integrator {
                initial,
                rounding,
                overflow,
                ..
            } => EvaluatorNodeState::Integrator {
                accumulator: initial.clone(),
                pending: scale_value_fraction(initial, 0, 1, *rounding, *overflow)?,
                previous_input: None,
                last_nanos: None,
            },
            StatefulSignalSpecification::LeakyIntegrator { initial, .. } => {
                EvaluatorNodeState::LeakyIntegrator {
                    accumulator: initial.clone(),
                    previous_input: None,
                    last_nanos: None,
                }
            }
            StatefulSignalSpecification::FiniteStateMachine { initial, .. } => {
                EvaluatorNodeState::FiniteStateMachine {
                    state: initial.clone(),
                    timers: BTreeMap::new(),
                }
            }
            StatefulSignalSpecification::MarkovChain { initial, .. } => {
                EvaluatorNodeState::MarkovChain {
                    state: initial.clone(),
                    transition_sequence: 0,
                }
            }
            StatefulSignalSpecification::BurstProcess { initial_bad, .. } => {
                EvaluatorNodeState::BurstProcess {
                    bad: *initial_bad,
                    transition_sequence: 0,
                }
            }
            StatefulSignalSpecification::Counter { initial, .. } => {
                EvaluatorNodeState::Counter { count: *initial }
            }
            StatefulSignalSpecification::QueueModel { .. } => EvaluatorNodeState::QueueModel {
                backlog: 0,
                service_remainder: 0,
                last_nanos: None,
            },
        };
        states.insert(node.id.clone(), state);
    }
    Ok(states)
}

#[allow(clippy::too_many_arguments)]
fn integrate_to_cadence(
    accumulator: &mut SignalValue,
    pending: &mut SignalValue,
    previous_input: &SignalValue,
    last_nanos: u64,
    now_nanos: u64,
    cadence_nanos: u64,
    time_unit_nanos: u64,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<(), SignalEvaluationError> {
    let last_bucket = last_nanos / cadence_nanos;
    let now_bucket = now_nanos / cadence_nanos;
    if last_bucket == now_bucket {
        let contribution = scale_value_fraction(
            previous_input,
            u128::from(now_nanos - last_nanos),
            u128::from(time_unit_nanos),
            rounding,
            overflow,
        )?;
        *pending = arithmetic_values(pending, &contribution, false, overflow)?;
        return Ok(());
    }

    let first_boundary = last_bucket
        .checked_add(1)
        .and_then(|bucket| bucket.checked_mul(cadence_nanos))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let first = scale_value_fraction(
        previous_input,
        u128::from(first_boundary - last_nanos),
        u128::from(time_unit_nanos),
        rounding,
        overflow,
    )?;
    *pending = arithmetic_values(pending, &first, false, overflow)?;
    *accumulator = arithmetic_values(accumulator, pending, false, overflow)?;

    *pending = scale_value_fraction(previous_input, 0, 1, rounding, overflow)?;
    let complete_cadences = now_bucket - last_bucket - 1;
    if complete_cadences > 0 {
        let per_cadence = scale_value_fraction(
            previous_input,
            u128::from(cadence_nanos),
            u128::from(time_unit_nanos),
            rounding,
            overflow,
        )?;
        let complete = scale_value_fraction(
            &per_cadence,
            u128::from(complete_cadences),
            1,
            rounding,
            overflow,
        )?;
        *accumulator = arithmetic_values(accumulator, &complete, false, overflow)?;
    }

    let final_boundary = now_bucket
        .checked_mul(cadence_nanos)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let tail = scale_value_fraction(
        previous_input,
        u128::from(now_nanos - final_boundary),
        u128::from(time_unit_nanos),
        rounding,
        overflow,
    )?;
    *pending = arithmetic_values(pending, &tail, false, overflow)?;
    Ok(())
}

fn validate_evaluated_shape(
    node: &SignalNode,
    output: &EvaluatedSignal,
) -> Result<(), SignalEvaluationError> {
    let EvaluatedSignal::Value(value) = output else {
        return Ok(());
    };
    if value.value_type().as_ref() != Some(&node.output.value_type) {
        return Err(SignalEvaluationError::OutputShapeMismatch(node.id.clone()));
    }
    Ok(())
}

fn coordinate_domain_runtime(coordinate: &SignalCoordinate) -> SignalDomain {
    match coordinate {
        SignalCoordinate::VirtualTime { .. } => SignalDomain::VirtualTime,
        SignalCoordinate::NodeCounter { .. } => SignalDomain::NodeCounter,
        SignalCoordinate::Operation { .. } => SignalDomain::Operation,
        SignalCoordinate::Spatial { .. } => SignalDomain::Spatial,
        SignalCoordinate::Event { .. } => SignalDomain::Event,
        SignalCoordinate::State { .. } => SignalDomain::State,
    }
}

fn coordinate_offset(
    epoch: &SignalCoordinate,
    coordinate: &SignalCoordinate,
) -> Result<u64, SignalEvaluationError> {
    match (epoch, coordinate) {
        (
            SignalCoordinate::VirtualTime { nanos: epoch },
            SignalCoordinate::VirtualTime { nanos },
        ) => nanos
            .checked_sub(*epoch)
            .ok_or(SignalEvaluationError::CoordinateBeforeEpoch),
        (
            SignalCoordinate::NodeCounter {
                node: epoch_node,
                retired_instructions: epoch,
            },
            SignalCoordinate::NodeCounter {
                node,
                retired_instructions,
            },
        ) if epoch_node == node => retired_instructions
            .checked_sub(*epoch)
            .ok_or(SignalEvaluationError::CoordinateBeforeEpoch),
        (
            SignalCoordinate::Operation {
                adapter: epoch_adapter,
                target: epoch_target,
                operation: epoch_operation,
                producer_sequence: epoch,
                suboperation: epoch_suboperation,
            },
            SignalCoordinate::Operation {
                adapter,
                target,
                operation,
                producer_sequence,
                suboperation,
            },
        ) if epoch_adapter == adapter
            && epoch_target == target
            && epoch_operation == operation
            && epoch_suboperation == suboperation =>
        {
            producer_sequence
                .checked_sub(*epoch)
                .ok_or(SignalEvaluationError::CoordinateBeforeEpoch)
        }
        (
            SignalCoordinate::State {
                adapter: epoch_adapter,
                target: epoch_target,
                boundary_sequence: epoch,
            },
            SignalCoordinate::State {
                adapter,
                target,
                boundary_sequence,
            },
        ) if epoch_adapter == adapter && epoch_target == target => boundary_sequence
            .checked_sub(*epoch)
            .ok_or(SignalEvaluationError::CoordinateBeforeEpoch),
        _ => Err(SignalEvaluationError::IncompatibleCoordinates),
    }
}

fn coordinate_nanos(coordinate: &SignalCoordinate) -> Result<u64, SignalEvaluationError> {
    match coordinate {
        SignalCoordinate::VirtualTime { nanos } => Ok(*nanos),
        _ => Err(SignalEvaluationError::VirtualTimeRequired),
    }
}

fn add_coordinate(
    epoch: &SignalCoordinate,
    delta: u64,
) -> Result<SignalCoordinate, SignalEvaluationError> {
    match epoch {
        SignalCoordinate::VirtualTime { nanos } => Ok(SignalCoordinate::VirtualTime {
            nanos: nanos
                .checked_add(delta)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
        }),
        SignalCoordinate::NodeCounter {
            node,
            retired_instructions,
        } => Ok(SignalCoordinate::NodeCounter {
            node: node.clone(),
            retired_instructions: retired_instructions
                .checked_add(delta)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
        }),
        SignalCoordinate::Operation {
            adapter,
            target,
            operation,
            producer_sequence,
            suboperation,
        } => Ok(SignalCoordinate::Operation {
            adapter: adapter.clone(),
            target: target.clone(),
            operation: operation.clone(),
            producer_sequence: producer_sequence
                .checked_add(delta)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
            suboperation: *suboperation,
        }),
        SignalCoordinate::State {
            adapter,
            target,
            boundary_sequence,
        } => Ok(SignalCoordinate::State {
            adapter: adapter.clone(),
            target: target.clone(),
            boundary_sequence: boundary_sequence
                .checked_add(delta)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
        }),
        SignalCoordinate::Spatial { .. } | SignalCoordinate::Event { .. } => {
            Err(SignalEvaluationError::IncompatibleCoordinates)
        }
    }
}

fn subtract_coordinate(
    coordinate: &SignalCoordinate,
    delta: u64,
) -> Result<SignalCoordinate, SignalEvaluationError> {
    match coordinate {
        SignalCoordinate::VirtualTime { nanos } => Ok(SignalCoordinate::VirtualTime {
            nanos: nanos
                .checked_sub(delta)
                .ok_or(SignalEvaluationError::CoordinateBeforeEpoch)?,
        }),
        SignalCoordinate::NodeCounter {
            node,
            retired_instructions,
        } => Ok(SignalCoordinate::NodeCounter {
            node: node.clone(),
            retired_instructions: retired_instructions
                .checked_sub(delta)
                .ok_or(SignalEvaluationError::CoordinateBeforeEpoch)?,
        }),
        SignalCoordinate::Operation {
            adapter,
            target,
            operation,
            producer_sequence,
            suboperation,
        } => Ok(SignalCoordinate::Operation {
            adapter: adapter.clone(),
            target: target.clone(),
            operation: operation.clone(),
            producer_sequence: producer_sequence
                .checked_sub(delta)
                .ok_or(SignalEvaluationError::CoordinateBeforeEpoch)?,
            suboperation: *suboperation,
        }),
        SignalCoordinate::State {
            adapter,
            target,
            boundary_sequence,
        } => Ok(SignalCoordinate::State {
            adapter: adapter.clone(),
            target: target.clone(),
            boundary_sequence: boundary_sequence
                .checked_sub(delta)
                .ok_or(SignalEvaluationError::CoordinateBeforeEpoch)?,
        }),
        SignalCoordinate::Spatial { .. } | SignalCoordinate::Event { .. } => {
            Err(SignalEvaluationError::IncompatibleCoordinates)
        }
    }
}

fn evaluate_step(
    points: &[SignalPoint],
    before: &SignalBoundaryBehavior,
    coordinate: &SignalCoordinate,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let repeated_coordinate;
    let coordinate =
        if coordinate < &points[0].coordinate && matches!(before, SignalBoundaryBehavior::Repeat) {
            let first = &points[0].coordinate;
            let last = &points[points.len() - 1].coordinate;
            let extent = coordinate_offset(first, last)?;
            if extent == 0 {
                return Err(SignalEvaluationError::InvalidRepeatExtent);
            }
            let distance = coordinate_offset(coordinate, first)?;
            let remainder = distance % extent;
            repeated_coordinate = if remainder == 0 {
                first.clone()
            } else {
                subtract_coordinate(last, remainder)?
            };
            &repeated_coordinate
        } else {
            coordinate
        };
    let index = points.partition_point(|point| point.coordinate <= *coordinate);
    if let Some(point) = index.checked_sub(1).and_then(|index| points.get(index)) {
        return Ok(EvaluatedSignal::Value(point.value.clone()));
    }
    evaluate_boundary(before, points.first().map(|point| &point.value), None)
}

pub(super) fn evaluate_boundary(
    behavior: &SignalBoundaryBehavior,
    nearest: Option<&SignalValue>,
    repeated: Option<&SignalValue>,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    match behavior {
        SignalBoundaryBehavior::Error => Err(SignalEvaluationError::OutsideSourceExtent),
        SignalBoundaryBehavior::Hold => nearest
            .cloned()
            .map(EvaluatedSignal::Value)
            .ok_or(SignalEvaluationError::OutsideSourceExtent),
        SignalBoundaryBehavior::Constant(value) => Ok(EvaluatedSignal::Value(value.clone())),
        SignalBoundaryBehavior::Repeat => repeated
            .cloned()
            .map(EvaluatedSignal::Value)
            .ok_or(SignalEvaluationError::InvalidRepeatExtent),
        SignalBoundaryBehavior::Inactive => Ok(EvaluatedSignal::Inactive),
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_ramp(
    start: &SignalCoordinate,
    end: &SignalCoordinate,
    start_value: &SignalValue,
    end_value: &SignalValue,
    coordinate: &SignalCoordinate,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if coordinate <= start {
        return Ok(EvaluatedSignal::Value(start_value.clone()));
    }
    if coordinate >= end {
        return Ok(EvaluatedSignal::Value(end_value.clone()));
    }
    let elapsed = coordinate_offset(start, coordinate)?;
    let width = coordinate_offset(start, end)?;
    Ok(EvaluatedSignal::Value(interpolate_value(
        start_value,
        end_value,
        elapsed,
        width,
        rounding,
        overflow,
    )?))
}

#[allow(clippy::too_many_arguments)]
fn evaluate_triangle(
    epoch: &SignalCoordinate,
    period: u64,
    phase: u64,
    minimum: &SignalValue,
    maximum: &SignalValue,
    coordinate: &SignalCoordinate,
    rounding: SignalRounding,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let position = coordinate_offset(epoch, coordinate)?
        .checked_add(phase)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?
        % period;
    let rising_width = period / 2;
    if rising_width == 0 {
        return Err(SignalEvaluationError::InvalidPeriod);
    }
    if position <= rising_width {
        Ok(EvaluatedSignal::Value(interpolate_value(
            minimum,
            maximum,
            position,
            rising_width,
            rounding,
            SignalOverflow::Error,
        )?))
    } else {
        Ok(EvaluatedSignal::Value(interpolate_value(
            maximum,
            minimum,
            position - rising_width,
            period - rising_width,
            rounding,
            SignalOverflow::Error,
        )?))
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_sawtooth(
    epoch: &SignalCoordinate,
    period: u64,
    phase: u64,
    minimum: &SignalValue,
    maximum: &SignalValue,
    coordinate: &SignalCoordinate,
    rounding: SignalRounding,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let position = coordinate_offset(epoch, coordinate)?
        .checked_add(phase)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?
        % period;
    Ok(EvaluatedSignal::Value(interpolate_value(
        minimum,
        maximum,
        position,
        period,
        rounding,
        SignalOverflow::Error,
    )?))
}

fn evaluate_event_sequence(
    events: &[SignalPoint],
    coordinate: &SignalCoordinate,
    sequence: u64,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let start = events.partition_point(|event| event.coordinate < *coordinate);
    let Some(event) = events[start..]
        .iter()
        .take_while(|event| event.coordinate == *coordinate)
        .find(|event| event.sequence == sequence)
    else {
        return Ok(EvaluatedSignal::Inactive);
    };
    Ok(EvaluatedSignal::Value(event.value.clone()))
}

fn choice_applies(
    domain: StochasticKeyDomain,
    opportunity_filter: Option<&SignalId>,
    request: &SignalEvaluationRequest,
) -> Result<bool, SignalEvaluationError> {
    match domain {
        StochasticKeyDomain::Opportunity if request.choice.opportunity.is_none() => {
            Err(SignalEvaluationError::OpportunityIdentityRequired)
        }
        StochasticKeyDomain::Transition if request.choice.transition_sequence.is_none() => {
            Err(SignalEvaluationError::TransitionIdentityRequired)
        }
        _ if opportunity_filter.is_some() && request.choice.opportunity.is_none() => {
            Err(SignalEvaluationError::OpportunityIdentityRequired)
        }
        _ => Ok(opportunity_filter.is_none_or(|filter| {
            request
                .choice
                .opportunity
                .as_ref()
                .is_some_and(|opportunity| opportunity.operation().as_str() == filter.as_str())
        })),
    }
}

fn keyed_u64(
    node: &SignalNode,
    request: &SignalEvaluationRequest,
    domain: StochasticKeyDomain,
    counter: u64,
) -> u64 {
    let mut material = Vec::new();
    material.extend_from_slice(&request.choice.scenario_seed.bytes);
    material.extend_from_slice(node.id.as_str().as_bytes());
    material.extend_from_slice(request.choice.consumer.as_str().as_bytes());
    material.push(match domain {
        StochasticKeyDomain::Opportunity => 0,
        StochasticKeyDomain::Transition => 1,
        StochasticKeyDomain::Coordinate => 2,
    });
    match domain {
        StochasticKeyDomain::Opportunity => {
            if let Some(opportunity) = &request.choice.opportunity {
                material.extend_from_slice(&opportunity.id().bytes);
            }
        }
        StochasticKeyDomain::Transition => material.extend_from_slice(
            &request
                .choice
                .transition_sequence
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        ),
        StochasticKeyDomain::Coordinate => {
            append_coordinate_bytes(&mut material, &request.coordinate);
            material.extend_from_slice(&request.same_coordinate_sequence.to_be_bytes());
        }
    }
    material.extend_from_slice(&counter.to_be_bytes());
    let hash = ContentHash::from_bytes(&material);
    u64::from_be_bytes(hash.bytes[..8].try_into().unwrap_or([0; 8]))
}

fn keyed_transition_u64(
    node: &SignalNode,
    request: &SignalEvaluationRequest,
    transition_sequence: u64,
) -> u64 {
    let mut keyed_request = request.clone();
    keyed_request.choice.transition_sequence = Some(transition_sequence);
    keyed_u64(node, &keyed_request, StochasticKeyDomain::Transition, 0)
}

fn append_coordinate_bytes(output: &mut Vec<u8>, coordinate: &SignalCoordinate) {
    match coordinate {
        SignalCoordinate::VirtualTime { nanos } => {
            output.push(0);
            output.extend_from_slice(&nanos.to_be_bytes());
        }
        SignalCoordinate::NodeCounter {
            node,
            retired_instructions,
        } => {
            output.push(1);
            output.extend_from_slice(node.as_str().as_bytes());
            output.push(0);
            output.extend_from_slice(&retired_instructions.to_be_bytes());
        }
        SignalCoordinate::Operation {
            adapter,
            target,
            operation,
            producer_sequence,
            suboperation,
        } => {
            output.push(2);
            for id in [adapter, target, operation] {
                output.extend_from_slice(id.as_str().as_bytes());
                output.push(0);
            }
            output.extend_from_slice(&producer_sequence.to_be_bytes());
            output.extend_from_slice(&suboperation.to_be_bytes());
        }
        SignalCoordinate::Spatial {
            frame,
            x_mm,
            y_mm,
            z_mm,
            yaw_mdeg,
            pitch_mdeg,
            roll_mdeg,
        } => {
            output.push(3);
            output.extend_from_slice(frame.as_str().as_bytes());
            output.push(0);
            for value in [x_mm, y_mm, z_mm, yaw_mdeg, pitch_mdeg, roll_mdeg] {
                output.extend_from_slice(&value.to_be_bytes());
            }
        }
        SignalCoordinate::Event { parent, sequence } => {
            output.push(4);
            append_coordinate_bytes(output, parent);
            output.extend_from_slice(&sequence.to_be_bytes());
        }
        SignalCoordinate::State {
            adapter,
            target,
            boundary_sequence,
        } => {
            output.push(5);
            output.extend_from_slice(adapter.as_str().as_bytes());
            output.push(0);
            output.extend_from_slice(target.as_str().as_bytes());
            output.push(0);
            output.extend_from_slice(&boundary_sequence.to_be_bytes());
        }
    }
}

fn uniform_i64(
    node: &SignalNode,
    request: &SignalEvaluationRequest,
    domain: StochasticKeyDomain,
    minimum: i64,
    maximum: i64,
) -> Result<i64, SignalEvaluationError> {
    let width = i128::from(maximum)
        .checked_sub(i128::from(minimum))
        .and_then(|value| value.checked_add(1))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let width = u128::try_from(width).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
    if width == (u128::from(u64::MAX) + 1) {
        return Ok(i64::from_be_bytes(
            keyed_u64(node, request, domain, 0).to_be_bytes(),
        ));
    }
    let width = u64::try_from(width).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
    let rejection = u64::MAX - u64::MAX % width;
    for counter in 0..=u64::MAX {
        let draw = keyed_u64(node, request, domain, counter);
        if draw < rejection {
            let offset = i128::from(draw % width);
            return i64::try_from(i128::from(minimum) + offset)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow);
        }
    }
    Err(SignalEvaluationError::KeyStreamExhausted)
}

fn evaluate_simple(
    node: &SignalNode,
    operator: PureSignalOperator,
    overflow: SignalOverflow,
    inputs: &[EvaluatedSignal],
    history: Option<&VecDeque<HistoryEntry>>,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if inputs
        .iter()
        .any(|input| input == &EvaluatedSignal::Inactive)
    {
        return Ok(EvaluatedSignal::Inactive);
    }
    let values = inputs
        .iter()
        .map(EvaluatedSignal::value)
        .collect::<Result<Vec<_>, _>>()?;
    let value = match operator {
        PureSignalOperator::Add => {
            let mut result = values[0].clone();
            for value in values.iter().skip(1) {
                result = arithmetic_values(&result, value, false, overflow)?;
            }
            result
        }
        PureSignalOperator::Subtract => arithmetic_values(values[0], values[1], true, overflow)?,
        PureSignalOperator::Absolute => absolute_value(values[0], overflow)?,
        PureSignalOperator::Negate => negate_value(values[0], overflow)?,
        PureSignalOperator::Min => {
            let mut result = values[0];
            for value in values.iter().skip(1) {
                if compare_numeric(value, result)?.is_lt() {
                    result = value;
                }
            }
            result.clone()
        }
        PureSignalOperator::Max => {
            let mut result = values[0];
            for value in values.iter().skip(1) {
                if compare_numeric(value, result)?.is_gt() {
                    result = value;
                }
            }
            result.clone()
        }
        PureSignalOperator::Equal => {
            SignalValue::Bool(compare_numeric(values[0], values[1])?.is_eq())
        }
        PureSignalOperator::NotEqual => {
            SignalValue::Bool(!compare_numeric(values[0], values[1])?.is_eq())
        }
        PureSignalOperator::Less => {
            SignalValue::Bool(compare_numeric(values[0], values[1])?.is_lt())
        }
        PureSignalOperator::LessEqual => {
            SignalValue::Bool(!compare_numeric(values[0], values[1])?.is_gt())
        }
        PureSignalOperator::Greater => {
            SignalValue::Bool(compare_numeric(values[0], values[1])?.is_gt())
        }
        PureSignalOperator::GreaterEqual => {
            SignalValue::Bool(!compare_numeric(values[0], values[1])?.is_lt())
        }
        PureSignalOperator::All => SignalValue::Bool(
            values
                .iter()
                .map(|value| bool_value(value))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .all(|value| value),
        ),
        PureSignalOperator::Any => SignalValue::Bool(
            values
                .iter()
                .map(|value| bool_value(value))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .any(|value| value),
        ),
        PureSignalOperator::Not => SignalValue::Bool(!bool_value(values[0])?),
        PureSignalOperator::Select => {
            if bool_value(values[0])? {
                values[1].clone()
            } else {
                values[2].clone()
            }
        }
        PureSignalOperator::EdgeRising | PureSignalOperator::EdgeFalling => {
            let current = bool_value(values[0])?;
            let previous = history
                .and_then(|history| history.back())
                .and_then(|entry| match &entry.output {
                    EvaluatedSignal::Value(SignalValue::Bool(value)) => Some(*value),
                    _ => None,
                })
                .unwrap_or(current);
            let edge = if operator == PureSignalOperator::EdgeRising {
                !previous && current
            } else {
                previous && !current
            };
            if !edge {
                return Ok(EvaluatedSignal::Inactive);
            }
            let SignalValueType::Event(schema) = &node.output.value_type else {
                return Err(SignalEvaluationError::TypeMismatch);
            };
            SignalValue::Event {
                schema: schema.clone(),
                payload: Vec::new(),
            }
        }
        _ => return Err(SignalEvaluationError::InvalidOperator),
    };
    Ok(EvaluatedSignal::Value(value))
}

fn bool_value(value: &SignalValue) -> Result<bool, SignalEvaluationError> {
    match value {
        SignalValue::Bool(value) => Ok(*value),
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

pub(super) fn arithmetic_values(
    left: &SignalValue,
    right: &SignalValue,
    subtract: bool,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    match (left, right) {
        (SignalValue::I64(left), SignalValue::I64(right)) => {
            let value = if subtract {
                i128::from(*left) - i128::from(*right)
            } else {
                i128::from(*left) + i128::from(*right)
            };
            Ok(SignalValue::I64(narrow_i64(value, overflow)?))
        }
        (SignalValue::U64(left), SignalValue::U64(right)) => {
            let value = if subtract {
                i128::from(*left) - i128::from(*right)
            } else {
                i128::from(*left) + i128::from(*right)
            };
            Ok(SignalValue::U64(narrow_u64(value, overflow)?))
        }
        (SignalValue::DurationNanos(left), SignalValue::DurationNanos(right)) => {
            let value = if subtract {
                i128::from(*left) - i128::from(*right)
            } else {
                i128::from(*left) + i128::from(*right)
            };
            Ok(SignalValue::DurationNanos(narrow_u64(value, overflow)?))
        }
        (SignalValue::RatePerSecond(left), SignalValue::RatePerSecond(right)) => {
            let value = if subtract {
                i128::from(*left) - i128::from(*right)
            } else {
                i128::from(*left) + i128::from(*right)
            };
            Ok(SignalValue::RatePerSecond(narrow_u64(value, overflow)?))
        }
        (SignalValue::ProbabilityMillionths(left), SignalValue::ProbabilityMillionths(right)) => {
            let value = if subtract {
                i128::from(*left) - i128::from(*right)
            } else {
                i128::from(*left) + i128::from(*right)
            };
            let maximum = 1_000_000_i128;
            let value = match overflow {
                SignalOverflow::Error if !(0..=maximum).contains(&value) => {
                    return Err(SignalEvaluationError::ArithmeticOverflow);
                }
                SignalOverflow::Saturate => value.clamp(0, maximum),
                SignalOverflow::Error => value,
            };
            Ok(SignalValue::ProbabilityMillionths(
                u32::try_from(value).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
            ))
        }
        (SignalValue::Ratio(left), SignalValue::Ratio(right)) => {
            let left_denominator = i128::from(left.denominator());
            let right_denominator = i128::from(right.denominator());
            let left_scaled = i128::from(left.numerator())
                .checked_mul(right_denominator)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let right_scaled = i128::from(right.numerator())
                .checked_mul(left_denominator)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let numerator = if subtract {
                left_scaled.checked_sub(right_scaled)
            } else {
                left_scaled.checked_add(right_scaled)
            }
            .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let denominator = left
                .denominator()
                .checked_mul(right.denominator())
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            Ok(SignalValue::Ratio(ratio_from_i128(
                numerator,
                denominator,
                overflow,
            )?))
        }
        (SignalValue::Vector2(left), SignalValue::Vector2(right)) => Ok(SignalValue::Vector2(
            vector_arithmetic(left, right, subtract, overflow)?,
        )),
        (SignalValue::Vector3(left), SignalValue::Vector3(right)) => Ok(SignalValue::Vector3(
            vector_arithmetic(left, right, subtract, overflow)?,
        )),
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

fn vector_arithmetic(
    left: &[SignalValue],
    right: &[SignalValue],
    subtract: bool,
    overflow: SignalOverflow,
) -> Result<Vec<SignalValue>, SignalEvaluationError> {
    if left.len() != right.len() {
        return Err(SignalEvaluationError::TypeMismatch);
    }
    left.iter()
        .zip(right)
        .map(|(left, right)| arithmetic_values(left, right, subtract, overflow))
        .collect()
}

fn absolute_value(
    value: &SignalValue,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    match value {
        SignalValue::I64(value) => Ok(SignalValue::I64(match value.checked_abs() {
            Some(value) => value,
            None if overflow == SignalOverflow::Saturate => i64::MAX,
            None => return Err(SignalEvaluationError::ArithmeticOverflow),
        })),
        SignalValue::Ratio(value) => Ok(SignalValue::Ratio(
            ExactRatio::new(
                match value.numerator().checked_abs() {
                    Some(value) => value,
                    None if overflow == SignalOverflow::Saturate => i64::MAX,
                    None => return Err(SignalEvaluationError::ArithmeticOverflow),
                },
                value.denominator(),
            )
            .map_err(SignalEvaluationError::Program)?,
        )),
        _ => Ok(value.clone()),
    }
}

fn negate_value(
    value: &SignalValue,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    match value {
        SignalValue::I64(value) => Ok(SignalValue::I64(match value.checked_neg() {
            Some(value) => value,
            None if overflow == SignalOverflow::Saturate => i64::MAX,
            None => return Err(SignalEvaluationError::ArithmeticOverflow),
        })),
        SignalValue::Ratio(value) => Ok(SignalValue::Ratio(
            ExactRatio::new(
                match value.numerator().checked_neg() {
                    Some(value) => value,
                    None if overflow == SignalOverflow::Saturate => i64::MAX,
                    None => return Err(SignalEvaluationError::ArithmeticOverflow),
                },
                value.denominator(),
            )
            .map_err(SignalEvaluationError::Program)?,
        )),
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

pub(super) fn compare_numeric(
    left: &SignalValue,
    right: &SignalValue,
) -> Result<std::cmp::Ordering, SignalEvaluationError> {
    let (left_numerator, left_denominator) = numeric_fraction(left)?;
    let (right_numerator, right_denominator) = numeric_fraction(right)?;
    let left = left_numerator
        .checked_mul(
            i128::try_from(right_denominator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
        )
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let right = right_numerator
        .checked_mul(
            i128::try_from(left_denominator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
        )
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    Ok(left.cmp(&right))
}

pub(super) fn numeric_fraction(value: &SignalValue) -> Result<(i128, u128), SignalEvaluationError> {
    match value {
        SignalValue::I64(value) => Ok((i128::from(*value), 1)),
        SignalValue::U64(value)
        | SignalValue::DurationNanos(value)
        | SignalValue::RatePerSecond(value) => Ok((i128::from(*value), 1)),
        SignalValue::ProbabilityMillionths(value) => Ok((i128::from(*value), 1)),
        SignalValue::Ratio(value) => Ok((
            i128::from(value.numerator()),
            u128::from(value.denominator()),
        )),
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

pub(super) fn scale_value(
    value: &SignalValue,
    ratio: ExactRatio,
    offset: ExactRatio,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    match value {
        SignalValue::Vector2(values) => Ok(SignalValue::Vector2(
            values
                .iter()
                .map(|value| scale_value(value, ratio, offset, rounding, overflow))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        SignalValue::Vector3(values) => Ok(SignalValue::Vector3(
            values
                .iter()
                .map(|value| scale_value(value, ratio, offset, rounding, overflow))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => {
            let (numerator, denominator) = numeric_fraction(value)?;
            let scaled_numerator = numerator
                .checked_mul(i128::from(ratio.numerator()))
                .and_then(|value| value.checked_mul(i128::from(offset.denominator())))
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let offset_numerator = i128::from(offset.numerator())
                .checked_mul(
                    i128::try_from(denominator)
                        .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
                )
                .and_then(|value| value.checked_mul(i128::from(ratio.denominator())))
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let result_numerator = scaled_numerator
                .checked_add(offset_numerator)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let result_denominator = denominator
                .checked_mul(u128::from(ratio.denominator()))
                .and_then(|value| value.checked_mul(u128::from(offset.denominator())))
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            value_from_fraction(
                value,
                result_numerator,
                result_denominator,
                rounding,
                overflow,
            )
        }
    }
}

pub(super) fn interpolate_value(
    start: &SignalValue,
    end: &SignalValue,
    elapsed: u64,
    width: u64,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    if width == 0 || elapsed > width {
        return Err(SignalEvaluationError::InvalidPeriod);
    }
    let difference = arithmetic_values(end, start, true, overflow)?;
    let divisor = gcd_u64(elapsed, width);
    let scaled = scale_value(
        &difference,
        ExactRatio::new(
            i64::try_from(elapsed / divisor)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
            width / divisor,
        )
        .map_err(SignalEvaluationError::Program)?,
        ExactRatio::new(0, 1).map_err(SignalEvaluationError::Program)?,
        rounding,
        overflow,
    )?;
    arithmetic_values(start, &scaled, false, overflow)
}

fn gcd_u64(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

pub(super) fn value_from_fraction(
    exemplar: &SignalValue,
    numerator: i128,
    denominator: u128,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    if denominator == 0 {
        return Err(SignalEvaluationError::DivisionByZero);
    }
    if matches!(exemplar, SignalValue::Ratio(_)) {
        let denominator =
            u64::try_from(denominator).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
        return Ok(SignalValue::Ratio(ratio_from_i128(
            numerator,
            denominator,
            overflow,
        )?));
    }
    let rounded = round_signed(numerator, denominator, rounding)?;
    match exemplar {
        SignalValue::I64(_) => Ok(SignalValue::I64(narrow_i64(rounded, overflow)?)),
        SignalValue::U64(_) => Ok(SignalValue::U64(narrow_u64(rounded, overflow)?)),
        SignalValue::DurationNanos(_) => {
            Ok(SignalValue::DurationNanos(narrow_u64(rounded, overflow)?))
        }
        SignalValue::RatePerSecond(_) => {
            Ok(SignalValue::RatePerSecond(narrow_u64(rounded, overflow)?))
        }
        SignalValue::ProbabilityMillionths(_) => {
            let value = match overflow {
                SignalOverflow::Saturate => rounded.clamp(0, 1_000_000),
                SignalOverflow::Error if !(0..=1_000_000).contains(&rounded) => {
                    return Err(SignalEvaluationError::ArithmeticOverflow);
                }
                SignalOverflow::Error => rounded,
            };
            Ok(SignalValue::ProbabilityMillionths(
                u32::try_from(value).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
            ))
        }
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

fn round_signed(
    numerator: i128,
    denominator: u128,
    rounding: SignalRounding,
) -> Result<i128, SignalEvaluationError> {
    let denominator =
        i128::try_from(denominator).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    if remainder == 0 {
        return Ok(quotient);
    }
    let direction = if numerator < 0 { -1 } else { 1 };
    let increment = match rounding {
        SignalRounding::TowardZero => 0,
        SignalRounding::AwayFromZero => direction,
        SignalRounding::Floor if numerator < 0 => -1,
        SignalRounding::Floor => 0,
        SignalRounding::Ceiling if numerator > 0 => 1,
        SignalRounding::Ceiling => 0,
        SignalRounding::NearestTiesToEven => {
            let doubled = remainder
                .unsigned_abs()
                .checked_mul(2)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let denominator = u128::try_from(denominator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
            if doubled > denominator || (doubled == denominator && quotient % 2 != 0) {
                direction
            } else {
                0
            }
        }
    };
    quotient
        .checked_add(increment)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)
}

fn ratio_from_i128(
    numerator: i128,
    denominator: u64,
    overflow: SignalOverflow,
) -> Result<ExactRatio, SignalEvaluationError> {
    let numerator = match i64::try_from(numerator) {
        Ok(value) => value,
        Err(_) if overflow == SignalOverflow::Saturate && numerator < 0 => i64::MIN,
        Err(_) if overflow == SignalOverflow::Saturate => i64::MAX,
        Err(_) => return Err(SignalEvaluationError::ArithmeticOverflow),
    };
    ExactRatio::new(numerator, denominator).map_err(SignalEvaluationError::Program)
}

fn narrow_i64(value: i128, overflow: SignalOverflow) -> Result<i64, SignalEvaluationError> {
    match i64::try_from(value) {
        Ok(value) => Ok(value),
        Err(_) if overflow == SignalOverflow::Saturate && value < 0 => Ok(i64::MIN),
        Err(_) if overflow == SignalOverflow::Saturate => Ok(i64::MAX),
        Err(_) => Err(SignalEvaluationError::ArithmeticOverflow),
    }
}

fn narrow_u64(value: i128, overflow: SignalOverflow) -> Result<u64, SignalEvaluationError> {
    match u64::try_from(value) {
        Ok(value) => Ok(value),
        Err(_) if overflow == SignalOverflow::Saturate && value < 0 => Ok(0),
        Err(_) if overflow == SignalOverflow::Saturate => Ok(u64::MAX),
        Err(_) => Err(SignalEvaluationError::ArithmeticOverflow),
    }
}

fn evaluate_lookup_step(
    input: &SignalValue,
    points: &[(SignalValue, SignalValue)],
    before: &SignalBoundaryBehavior,
    after: &SignalBoundaryBehavior,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if compare_numeric(input, &points[0].0)?.is_lt() {
        return evaluate_boundary(before, Some(&points[0].1), None);
    }
    if compare_numeric(input, &points[points.len() - 1].0)?.is_gt() {
        return evaluate_boundary(after, Some(&points[points.len() - 1].1), None);
    }
    let mut selected = &points[0].1;
    for (key, output) in points {
        if compare_numeric(key, input)?.is_gt() {
            break;
        }
        selected = output;
    }
    Ok(EvaluatedSignal::Value(selected.clone()))
}

pub(super) fn evaluate_piecewise_linear(
    input: &SignalValue,
    points: &[(SignalValue, SignalValue)],
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if !compare_numeric(input, &points[0].0)?.is_gt() {
        return Ok(EvaluatedSignal::Value(points[0].1.clone()));
    }
    if !compare_numeric(input, &points[points.len() - 1].0)?.is_lt() {
        return Ok(EvaluatedSignal::Value(points[points.len() - 1].1.clone()));
    }
    let upper = points.partition_point(|(key, _)| {
        !compare_numeric(key, input).is_ok_and(std::cmp::Ordering::is_gt)
    });
    let (lower_key, lower_value) = &points[upper - 1];
    let (upper_key, upper_value) = &points[upper];
    let (input_numerator, input_denominator) = numeric_fraction(input)?;
    let (lower_numerator, lower_denominator) = numeric_fraction(lower_key)?;
    let (upper_numerator, upper_denominator) = numeric_fraction(upper_key)?;
    let position_numerator = input_numerator
        .checked_mul(
            i128::try_from(lower_denominator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
        )
        .and_then(|value| {
            lower_numerator
                .checked_mul(i128::try_from(input_denominator).ok()?)
                .and_then(|lower| value.checked_sub(lower))
        })
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let position_denominator = input_denominator
        .checked_mul(lower_denominator)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let span_numerator = upper_numerator
        .checked_mul(
            i128::try_from(lower_denominator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
        )
        .and_then(|value| {
            lower_numerator
                .checked_mul(i128::try_from(upper_denominator).ok()?)
                .and_then(|lower| value.checked_sub(lower))
        })
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let span_denominator = upper_denominator
        .checked_mul(lower_denominator)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    if position_numerator < 0 || span_numerator <= 0 {
        return Err(SignalEvaluationError::ArithmeticOverflow);
    }
    let numerator = u128::try_from(position_numerator)
        .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?
        .checked_mul(span_denominator)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let denominator = position_denominator
        .checked_mul(
            u128::try_from(span_numerator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
        )
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let difference = arithmetic_values(upper_value, lower_value, true, overflow)?;
    let scaled = scale_value_fraction(&difference, numerator, denominator, rounding, overflow)?;
    Ok(EvaluatedSignal::Value(arithmetic_values(
        lower_value,
        &scaled,
        false,
        overflow,
    )?))
}

fn scale_value_fraction(
    value: &SignalValue,
    numerator: u128,
    denominator: u128,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    match value {
        SignalValue::Vector2(values) => Ok(SignalValue::Vector2(
            values
                .iter()
                .map(|value| {
                    scale_value_fraction(value, numerator, denominator, rounding, overflow)
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        SignalValue::Vector3(values) => Ok(SignalValue::Vector3(
            values
                .iter()
                .map(|value| {
                    scale_value_fraction(value, numerator, denominator, rounding, overflow)
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => {
            let (value_numerator, value_denominator) = numeric_fraction(value)?;
            let numerator = value_numerator
                .checked_mul(
                    i128::try_from(numerator)
                        .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
                )
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let denominator = value_denominator
                .checked_mul(denominator)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            value_from_fraction(value, numerator, denominator, rounding, overflow)
        }
    }
}

fn history_at(
    history: Option<&VecDeque<HistoryEntry>>,
    target: &SignalCoordinate,
    same_coordinate_sequence: u64,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    history
        .and_then(|history| {
            history.iter().rev().find(|entry| {
                (&entry.coordinate, entry.same_coordinate_sequence)
                    <= (target, same_coordinate_sequence)
            })
        })
        .map(|entry| entry.output.clone())
        .ok_or(SignalEvaluationError::HistoryUnavailable)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_window(
    operator: PureSignalOperator,
    window: u64,
    retained_samples: usize,
    rounding: SignalRounding,
    overflow: SignalOverflow,
    coordinate: &SignalCoordinate,
    same_coordinate_sequence: u64,
    history: Option<&VecDeque<HistoryEntry>>,
    current: &EvaluatedSignal,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let start = subtract_coordinate(coordinate, window)?;
    let mut values = history
        .into_iter()
        .flat_map(|history| history.iter())
        .filter(|entry| {
            entry.coordinate >= start
                && (&entry.coordinate, entry.same_coordinate_sequence)
                    < (coordinate, same_coordinate_sequence)
        })
        .filter_map(|entry| match &entry.output {
            EvaluatedSignal::Value(value) => Some(value.clone()),
            EvaluatedSignal::Inactive => None,
        })
        .collect::<Vec<_>>();
    if let EvaluatedSignal::Value(value) = current {
        values.push(value.clone());
    }
    if values.len() > retained_samples {
        values.drain(..values.len() - retained_samples);
    }
    if values.is_empty() {
        return Err(SignalEvaluationError::HistoryUnavailable);
    }
    let mut aggregate = values[0].clone();
    match operator {
        PureSignalOperator::WindowMin => {
            for value in values.iter().skip(1) {
                if compare_numeric(value, &aggregate)?.is_lt() {
                    aggregate = value.clone();
                }
            }
        }
        PureSignalOperator::WindowMax => {
            for value in values.iter().skip(1) {
                if compare_numeric(value, &aggregate)?.is_gt() {
                    aggregate = value.clone();
                }
            }
        }
        PureSignalOperator::WindowMean => {
            for value in values.iter().skip(1) {
                aggregate = arithmetic_values(&aggregate, value, false, overflow)?;
            }
            aggregate = scale_value_fraction(
                &aggregate,
                1,
                u128::try_from(values.len())
                    .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
                rounding,
                overflow,
            )?;
        }
        _ => return Err(SignalEvaluationError::InvalidOperator),
    }
    Ok(EvaluatedSignal::Value(aggregate))
}

fn evaluate_distance(
    metric: &SignalId,
    rounding: SignalRounding,
    inputs: &[EvaluatedSignal],
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let left = vector_i64(inputs[0].value()?)?;
    let right = vector_i64(inputs[1].value()?)?;
    if left.len() != right.len() {
        return Err(SignalEvaluationError::TypeMismatch);
    }
    let deltas = left
        .iter()
        .zip(right)
        .map(|(left, right)| i128::from(*left) - i128::from(right))
        .collect::<Vec<_>>();
    let distance = match metric.as_str() {
        "manhattan" => deltas
            .iter()
            .try_fold(0_i128, |total, delta| total.checked_add(delta.abs())),
        "euclidean-squared" => deltas.iter().try_fold(0_i128, |total, delta| {
            delta
                .checked_mul(*delta)
                .and_then(|square| total.checked_add(square))
        }),
        "euclidean" => {
            let squared = deltas
                .iter()
                .try_fold(0_u128, |total, delta| {
                    delta
                        .unsigned_abs()
                        .checked_mul(delta.unsigned_abs())
                        .and_then(|square| total.checked_add(square))
                })
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            Some(
                i128::try_from(integer_square_root(squared, rounding)?)
                    .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
            )
        }
        _ => return Err(SignalEvaluationError::UnknownMetric(metric.clone())),
    }
    .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    Ok(EvaluatedSignal::Value(SignalValue::I64(
        i64::try_from(distance).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
    )))
}

pub(super) fn integer_square_root(
    value: u128,
    rounding: SignalRounding,
) -> Result<u128, SignalEvaluationError> {
    if value < 2 {
        return Ok(value);
    }
    let mut low = 1_u128;
    let mut high = value.min(u128::from(u64::MAX));
    while low <= high {
        let middle = low + (high - low) / 2;
        if middle <= value / middle {
            low = middle + 1;
        } else {
            high = middle - 1;
        }
    }
    let floor = high;
    let exact = floor.checked_mul(floor) == Some(value);
    Ok(match rounding {
        SignalRounding::Ceiling | SignalRounding::AwayFromZero if !exact => floor + 1,
        SignalRounding::NearestTiesToEven if !exact => {
            let lower_delta = value - floor * floor;
            let upper = floor + 1;
            let upper_delta = upper * upper - value;
            if upper_delta < lower_delta || (upper_delta == lower_delta && floor % 2 == 1) {
                upper
            } else {
                floor
            }
        }
        _ => floor,
    })
}

fn vector_i64(value: &SignalValue) -> Result<Vec<i64>, SignalEvaluationError> {
    let values = match value {
        SignalValue::Vector2(values) | SignalValue::Vector3(values) => values,
        _ => return Err(SignalEvaluationError::TypeMismatch),
    };
    values
        .iter()
        .map(|value| match value {
            SignalValue::I64(value) => Ok(*value),
            _ => Err(SignalEvaluationError::TypeMismatch),
        })
        .collect()
}

fn evaluate_zone_contains(
    zone: &SignalId,
    inputs: &[EvaluatedSignal],
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let contains = match inputs[0].value()? {
        SignalValue::Enum { variant, .. } => variant == zone,
        SignalValue::Bool(value) => *value,
        _ => return Err(SignalEvaluationError::TypeMismatch),
    };
    Ok(EvaluatedSignal::Value(SignalValue::Bool(contains)))
}

pub(super) fn position_vector(value: &SignalValue) -> Result<[i64; 3], SignalEvaluationError> {
    match vector_i64(value)?.as_slice() {
        [x, y] => Ok([*x, *y, 0]),
        [x, y, z] => Ok([*x, *y, *z]),
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

fn spatial_frame(node: &SignalNode) -> Result<SignalId, SignalEvaluationError> {
    match &node.kind {
        SignalNodeKind::Source(
            SignalSourceSpecification::PointSet {
                coordinate_frame, ..
            }
            | SignalSourceSpecification::RegularGrid {
                coordinate_frame, ..
            }
            | SignalSourceSpecification::TiledGrid {
                coordinate_frame, ..
            }
            | SignalSourceSpecification::ZoneMap {
                coordinate_frame, ..
            }
            | SignalSourceSpecification::SeededField {
                coordinate_frame, ..
            },
        ) => Ok(coordinate_frame.clone()),
        _ => Err(SignalEvaluationError::SpatialFieldRequired(node.id.clone())),
    }
}

fn evaluate_orientation_delta(
    convention: &SignalId,
    inputs: &[EvaluatedSignal],
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if convention.as_str() != "yaw-pitch-roll-millidegrees" {
        return Err(SignalEvaluationError::UnknownOrientationConvention(
            convention.clone(),
        ));
    }
    let left = vector_i64(inputs[0].value()?)?;
    let right = vector_i64(inputs[1].value()?)?;
    let deltas = left
        .iter()
        .zip(right)
        .map(|(left, right)| {
            let raw = (i128::from(*left) - i128::from(right)).rem_euclid(360_000);
            let delta = if raw > 180_000 { raw - 360_000 } else { raw };
            i64::try_from(delta)
                .map(SignalValue::I64)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EvaluatedSignal::Value(if deltas.len() == 2 {
        SignalValue::Vector2(deltas)
    } else {
        SignalValue::Vector3(deltas)
    }))
}

fn merge_events(inputs: &[EvaluatedSignal]) -> Result<EvaluatedSignal, SignalEvaluationError> {
    Ok(inputs
        .iter()
        .find(|input| matches!(input, EvaluatedSignal::Value(_)))
        .cloned()
        .unwrap_or(EvaluatedSignal::Inactive))
}

fn state_output(
    node: &SignalNode,
    state: &EvaluatorNodeState,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let value = match state {
        EvaluatorNodeState::Hysteresis { value, .. }
        | EvaluatorNodeState::BurstProcess { bad: value, .. } => SignalValue::Bool(*value),
        EvaluatorNodeState::Debounce { committed, .. }
        | EvaluatorNodeState::Integrator {
            accumulator: committed,
            ..
        }
        | EvaluatorNodeState::LeakyIntegrator {
            accumulator: committed,
            ..
        } => committed.clone(),
        EvaluatorNodeState::FiniteStateMachine { state, .. }
        | EvaluatorNodeState::MarkovChain { state, .. } => {
            let SignalValueType::Enum(schema) = &node.output.value_type else {
                return Err(SignalEvaluationError::TypeMismatch);
            };
            SignalValue::Enum {
                schema: schema.clone(),
                variant: state.clone(),
            }
        }
        EvaluatorNodeState::Counter { count } => SignalValue::U64(*count),
        EvaluatorNodeState::QueueModel { backlog, .. } => SignalValue::U64(u64::from(*backlog)),
    };
    Ok(EvaluatedSignal::Value(value))
}

fn evaluate_stateful_node(
    node: &SignalNode,
    specification: &StatefulSignalSpecification,
    request: &SignalEvaluationRequest,
    inputs: &[EvaluatedSignal],
    state: &mut EvaluatorNodeState,
    emitted_events: &mut Vec<StatefulSignalEvent>,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    match (specification, &mut *state) {
        (
            StatefulSignalSpecification::Hysteresis {
                set_when,
                clear_when,
                minimum_residence_nanos,
                ..
            },
            EvaluatorNodeState::Hysteresis {
                value,
                last_transition_nanos,
            },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            let input = inputs[0].value()?;
            let desired = if *value {
                !compare_numeric(input, clear_when)?.is_lt()
            } else {
                !compare_numeric(input, set_when)?.is_lt()
            };
            if desired != *value
                && now.saturating_sub(*last_transition_nanos) >= *minimum_residence_nanos
            {
                *value = desired;
                *last_transition_nanos = now;
            }
        }
        (
            StatefulSignalSpecification::Debounce {
                residence_nanos, ..
            },
            EvaluatorNodeState::Debounce {
                committed,
                candidate,
                candidate_since_nanos,
            },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            let input = inputs[0].value()?;
            if input == committed {
                *candidate = None;
                *candidate_since_nanos = None;
            } else if candidate.as_ref() != Some(input) {
                *candidate = Some(input.clone());
                *candidate_since_nanos = Some(now);
            } else if candidate_since_nanos
                .is_some_and(|since| now.saturating_sub(since) >= *residence_nanos)
            {
                *committed = input.clone();
                *candidate = None;
                *candidate_since_nanos = None;
            }
        }
        (
            StatefulSignalSpecification::Integrator {
                cadence_nanos,
                time_unit_nanos,
                rounding,
                overflow,
                ..
            },
            EvaluatorNodeState::Integrator {
                accumulator,
                pending,
                previous_input,
                last_nanos,
            },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            let current_input = inputs[0].value()?.clone();
            if let Some(last) = *last_nanos {
                let delta = now
                    .checked_sub(last)
                    .ok_or(SignalEvaluationError::NonMonotoneEvaluation)?;
                let prior = previous_input
                    .as_ref()
                    .ok_or(SignalEvaluationError::InvalidState)?;
                if *cadence_nanos == 0 {
                    let contribution = scale_value_fraction(
                        prior,
                        u128::from(delta),
                        u128::from(*time_unit_nanos),
                        *rounding,
                        *overflow,
                    )?;
                    *accumulator = arithmetic_values(accumulator, &contribution, false, *overflow)?;
                } else if delta > 0 {
                    integrate_to_cadence(
                        accumulator,
                        pending,
                        prior,
                        last,
                        now,
                        *cadence_nanos,
                        *time_unit_nanos,
                        *rounding,
                        *overflow,
                    )?;
                }
            }
            *last_nanos = Some(now);
            *previous_input = Some(current_input);
        }
        (
            StatefulSignalSpecification::LeakyIntegrator {
                cadence_nanos,
                time_unit_nanos,
                decay_ratio,
                maximum_catch_up_steps,
                rounding,
                overflow,
                ..
            },
            EvaluatorNodeState::LeakyIntegrator {
                accumulator,
                previous_input,
                last_nanos,
            },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            let current_input = inputs[0].value()?.clone();
            if let Some(last) = *last_nanos {
                let elapsed = now
                    .checked_sub(last)
                    .ok_or(SignalEvaluationError::NonMonotoneEvaluation)?;
                let steps = elapsed / *cadence_nanos;
                if steps > u64::from(*maximum_catch_up_steps) {
                    return Err(SignalEvaluationError::CatchUpLimitExceeded {
                        requested: steps,
                        maximum: *maximum_catch_up_steps,
                    });
                }
                let prior = previous_input
                    .as_ref()
                    .ok_or(SignalEvaluationError::InvalidState)?;
                let contribution = scale_value_fraction(
                    prior,
                    u128::from(*cadence_nanos),
                    u128::from(*time_unit_nanos),
                    *rounding,
                    *overflow,
                )?;
                for _ in 0..steps {
                    let decayed = scale_value(
                        accumulator,
                        *decay_ratio,
                        ExactRatio::new(0, 1).map_err(SignalEvaluationError::Program)?,
                        *rounding,
                        *overflow,
                    )?;
                    *accumulator = arithmetic_values(&decayed, &contribution, false, *overflow)?;
                }
                *last_nanos = Some(
                    last.checked_add(
                        steps
                            .checked_mul(*cadence_nanos)
                            .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
                    )
                    .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
                );
            } else {
                *last_nanos = Some(now);
            }
            *previous_input = Some(current_input);
        }
        (
            StatefulSignalSpecification::FiniteStateMachine {
                transitions,
                unmatched_event,
                ..
            },
            EvaluatorNodeState::FiniteStateMachine { state, timers },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            let expired = timers
                .iter()
                .find_map(|(timer, deadline)| (*deadline <= now).then_some(timer.clone()));
            let input_event = match inputs.first() {
                Some(EvaluatedSignal::Value(SignalValue::Event { schema, .. })) => {
                    Some(schema.clone())
                }
                Some(EvaluatedSignal::Inactive) | None => expired.clone(),
                _ => return Err(SignalEvaluationError::TypeMismatch),
            };
            if let Some(expired) = expired {
                timers.remove(&expired);
            }
            if let Some(event) = input_event {
                let transition = transitions.iter().find(|transition| {
                    transition.from == *state
                        && transition.event == event
                        && transition.guard.as_ref().is_none_or(|guard| {
                            node.inputs
                                .iter()
                                .position(|input| input == guard)
                                .and_then(|index| inputs.get(index))
                                .and_then(|value| value.value().ok())
                                .and_then(|value| bool_value(value).ok())
                                == Some(true)
                        })
                });
                if let Some(transition) = transition {
                    *state = transition.to.clone();
                    for operation in &transition.timer_operations {
                        match operation {
                            StateMachineTimerOperation::Start {
                                timer,
                                duration_nanos,
                            } => {
                                timers.insert(
                                    timer.clone(),
                                    now.checked_add(*duration_nanos)
                                        .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
                                );
                            }
                            StateMachineTimerOperation::Cancel { timer } => {
                                timers.remove(timer);
                            }
                        }
                    }
                    if let Some(variant) = &transition.emit {
                        emitted_events.push(StatefulSignalEvent {
                            node: node.id.clone(),
                            variant: variant.clone(),
                            coordinate: request.coordinate.clone(),
                            same_coordinate_sequence: request.same_coordinate_sequence,
                        });
                    }
                } else if unmatched_event.as_str() != "ignore" {
                    return Err(SignalEvaluationError::UnmatchedStateMachineEvent {
                        state: state.clone(),
                        event,
                    });
                }
            }
        }
        (
            StatefulSignalSpecification::MarkovChain {
                states,
                opportunity,
                probability_rows,
                ..
            },
            EvaluatorNodeState::MarkovChain {
                state,
                transition_sequence,
            },
        ) => {
            let actual = request
                .choice
                .opportunity
                .as_ref()
                .ok_or(SignalEvaluationError::OpportunityIdentityRequired)?;
            if actual.operation().as_str() != opportunity.as_str() {
                return Err(SignalEvaluationError::OpportunityKindMismatch);
            }
            let row = states
                .iter()
                .position(|candidate| candidate == state)
                .and_then(|index| probability_rows.get(index))
                .ok_or(SignalEvaluationError::InvalidState)?;
            let draw = keyed_transition_u64(node, request, *transition_sequence) % 1_000_000;
            let mut cumulative = 0_u64;
            let selected = row
                .iter()
                .position(|probability| {
                    cumulative += u64::from(*probability);
                    draw < cumulative
                })
                .ok_or(SignalEvaluationError::InvalidProbabilityRow)?;
            *state = states[selected].clone();
            *transition_sequence = transition_sequence
                .checked_add(1)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
        }
        (
            StatefulSignalSpecification::BurstProcess {
                good_to_bad_millionths,
                bad_to_good_millionths,
                opportunity,
                ..
            },
            EvaluatorNodeState::BurstProcess {
                bad,
                transition_sequence,
            },
        ) => {
            let actual = request
                .choice
                .opportunity
                .as_ref()
                .ok_or(SignalEvaluationError::OpportunityIdentityRequired)?;
            if actual.operation().as_str() != opportunity.as_str() {
                return Err(SignalEvaluationError::OpportunityKindMismatch);
            }
            let probability = if *bad {
                *bad_to_good_millionths
            } else {
                *good_to_bad_millionths
            };
            if keyed_transition_u64(node, request, *transition_sequence) % 1_000_000
                < u64::from(probability)
            {
                *bad = !*bad;
            }
            *transition_sequence = transition_sequence
                .checked_add(1)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
        }
        (
            StatefulSignalSpecification::Counter {
                maximum,
                overflow,
                reset_event,
                ..
            },
            EvaluatorNodeState::Counter { count },
        ) => {
            if let EvaluatedSignal::Value(SignalValue::Event { schema, .. }) = &inputs[0] {
                if reset_event.as_ref() == Some(schema) {
                    *count = 0;
                } else if *count == *maximum {
                    if *overflow == SignalOverflow::Error {
                        return Err(SignalEvaluationError::ArithmeticOverflow);
                    }
                } else {
                    *count += 1;
                }
            }
        }
        (
            StatefulSignalSpecification::QueueModel {
                capacity, overflow, ..
            },
            EvaluatorNodeState::QueueModel {
                backlog,
                service_remainder,
                last_nanos,
            },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            if let Some(last) = *last_nanos {
                let elapsed = now
                    .checked_sub(last)
                    .ok_or(SignalEvaluationError::NonMonotoneEvaluation)?;
                let rate = match inputs[1].value()? {
                    SignalValue::RatePerSecond(value) | SignalValue::U64(value) => *value,
                    _ => return Err(SignalEvaluationError::TypeMismatch),
                };
                let service = u128::from(rate)
                    .checked_mul(u128::from(elapsed))
                    .and_then(|value| value.checked_add(u128::from(*service_remainder)))
                    .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
                let completed = service / 1_000_000_000;
                *service_remainder = u64::try_from(service % 1_000_000_000)
                    .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
                let completed = u32::try_from(completed).unwrap_or(u32::MAX);
                *backlog = backlog.saturating_sub(completed);
            }
            if matches!(inputs[0], EvaluatedSignal::Value(SignalValue::Event { .. })) {
                if *backlog < *capacity {
                    *backlog += 1;
                } else if overflow.as_str() == "error" {
                    return Err(SignalEvaluationError::QueueOverflow);
                } else if !matches!(overflow.as_str(), "drop-newest" | "drop-oldest") {
                    return Err(SignalEvaluationError::UnknownQueueOverflow(
                        overflow.clone(),
                    ));
                }
            }
            *last_nanos = Some(now);
        }
        _ => return Err(SignalEvaluationError::StateVariantMismatch),
    }
    state_output(node, state)
}

fn encode_node_state(state: &EvaluatorNodeState) -> Result<Vec<u8>, SignalEvaluationError> {
    let mut writer = EvaluatorWriter::default();
    match state {
        EvaluatorNodeState::Hysteresis {
            value,
            last_transition_nanos,
        } => {
            writer.byte(0);
            writer.boolean(*value);
            writer.u64(*last_transition_nanos);
        }
        EvaluatorNodeState::Debounce {
            committed,
            candidate,
            candidate_since_nanos,
        } => {
            writer.byte(1);
            writer.value(committed)?;
            writer.optional_value(candidate.as_ref())?;
            writer.optional_u64(*candidate_since_nanos);
        }
        EvaluatorNodeState::Integrator {
            accumulator,
            pending,
            previous_input,
            last_nanos,
        } => {
            writer.byte(2);
            writer.value(accumulator)?;
            writer.value(pending)?;
            writer.optional_value(previous_input.as_ref())?;
            writer.optional_u64(*last_nanos);
        }
        EvaluatorNodeState::LeakyIntegrator {
            accumulator,
            previous_input,
            last_nanos,
        } => {
            writer.byte(3);
            writer.value(accumulator)?;
            writer.optional_value(previous_input.as_ref())?;
            writer.optional_u64(*last_nanos);
        }
        EvaluatorNodeState::FiniteStateMachine { state, timers } => {
            writer.byte(4);
            writer.id(state)?;
            writer.count(timers.len())?;
            for (timer, deadline) in timers {
                writer.id(timer)?;
                writer.u64(*deadline);
            }
        }
        EvaluatorNodeState::MarkovChain {
            state,
            transition_sequence,
        } => {
            writer.byte(5);
            writer.id(state)?;
            writer.u64(*transition_sequence);
        }
        EvaluatorNodeState::BurstProcess {
            bad,
            transition_sequence,
        } => {
            writer.byte(6);
            writer.boolean(*bad);
            writer.u64(*transition_sequence);
        }
        EvaluatorNodeState::Counter { count } => {
            writer.byte(7);
            writer.u64(*count);
        }
        EvaluatorNodeState::QueueModel {
            backlog,
            service_remainder,
            last_nanos,
        } => {
            writer.byte(8);
            writer.u32(*backlog);
            writer.u64(*service_remainder);
            writer.optional_u64(*last_nanos);
        }
    }
    Ok(writer.bytes)
}

#[derive(Default)]
struct EvaluatorWriter {
    bytes: Vec<u8>,
}

impl EvaluatorWriter {
    fn byte(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn boolean(&mut self, value: bool) {
        self.byte(u8::from(value));
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn count(&mut self, value: usize) -> Result<(), SignalEvaluationError> {
        self.u32(u32::try_from(value).map_err(|_| SignalEvaluationError::CheckpointLimit)?);
        Ok(())
    }

    fn blob(&mut self, value: &[u8]) -> Result<(), SignalEvaluationError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn id(&mut self, value: &SignalId) -> Result<(), SignalEvaluationError> {
        self.blob(value.as_str().as_bytes())
    }

    fn optional_u64(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.u64(value);
            }
            None => self.byte(0),
        }
    }

    fn value(&mut self, value: &SignalValue) -> Result<(), SignalEvaluationError> {
        self.blob(&encode_signal_value(value).map_err(SignalEvaluationError::Trace)?)
    }

    fn optional_value(&mut self, value: Option<&SignalValue>) -> Result<(), SignalEvaluationError> {
        match value {
            Some(value) => {
                self.byte(1);
                self.value(value)
            }
            None => {
                self.byte(0);
                Ok(())
            }
        }
    }

    fn evaluated(&mut self, value: &EvaluatedSignal) -> Result<(), SignalEvaluationError> {
        match value {
            EvaluatedSignal::Inactive => {
                self.byte(0);
                Ok(())
            }
            EvaluatedSignal::Value(value) => {
                self.byte(1);
                self.value(value)
            }
        }
    }

    fn coordinate(&mut self, coordinate: &SignalCoordinate) -> Result<(), SignalEvaluationError> {
        match coordinate {
            SignalCoordinate::VirtualTime { nanos } => {
                self.byte(0);
                self.u64(*nanos);
            }
            SignalCoordinate::NodeCounter {
                node,
                retired_instructions,
            } => {
                self.byte(1);
                self.id(node)?;
                self.u64(*retired_instructions);
            }
            SignalCoordinate::Operation {
                adapter,
                target,
                operation,
                producer_sequence,
                suboperation,
            } => {
                self.byte(2);
                self.id(adapter)?;
                self.id(target)?;
                self.id(operation)?;
                self.u64(*producer_sequence);
                self.u32(*suboperation);
            }
            SignalCoordinate::Spatial {
                frame,
                x_mm,
                y_mm,
                z_mm,
                yaw_mdeg,
                pitch_mdeg,
                roll_mdeg,
            } => {
                self.byte(3);
                self.id(frame)?;
                for value in [x_mm, y_mm, z_mm, yaw_mdeg, pitch_mdeg, roll_mdeg] {
                    self.i64(*value);
                }
            }
            SignalCoordinate::Event { parent, sequence } => {
                self.byte(4);
                self.coordinate(parent)?;
                self.u64(*sequence);
            }
            SignalCoordinate::State {
                adapter,
                target,
                boundary_sequence,
            } => {
                self.byte(5);
                self.id(adapter)?;
                self.id(target)?;
                self.u64(*boundary_sequence);
            }
        }
        Ok(())
    }
}

struct EvaluatorReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> EvaluatorReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SignalEvaluationError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(SignalEvaluationError::MalformedCheckpoint)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(SignalEvaluationError::MalformedCheckpoint)?;
        self.cursor = end;
        Ok(value)
    }

    fn finish(&self) -> Result<(), SignalEvaluationError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(SignalEvaluationError::MalformedCheckpoint)
        }
    }

    fn byte(&mut self) -> Result<u8, SignalEvaluationError> {
        Ok(self.take(1)?[0])
    }

    fn boolean(&mut self) -> Result<bool, SignalEvaluationError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SignalEvaluationError::MalformedCheckpoint),
        }
    }

    fn u16(&mut self) -> Result<u16, SignalEvaluationError> {
        let bytes = self
            .take(2)?
            .try_into()
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, SignalEvaluationError> {
        let bytes = self
            .take(4)?
            .try_into()
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, SignalEvaluationError> {
        let bytes = self
            .take(8)?
            .try_into()
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn i64(&mut self) -> Result<i64, SignalEvaluationError> {
        let bytes = self
            .take(8)?
            .try_into()
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn count(&mut self, maximum: usize) -> Result<usize, SignalEvaluationError> {
        let value =
            usize::try_from(self.u32()?).map_err(|_| SignalEvaluationError::CheckpointLimit)?;
        if value > maximum {
            return Err(SignalEvaluationError::CheckpointLimit);
        }
        Ok(value)
    }

    fn blob(&mut self, maximum: usize) -> Result<&'a [u8], SignalEvaluationError> {
        let length = self.count(maximum)?;
        self.take(length)
    }

    fn id(&mut self) -> Result<SignalId, SignalEvaluationError> {
        let text = std::str::from_utf8(self.blob(FAULT_ID_MAX_BYTES)?)
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        SignalId::parse(text).map_err(SignalEvaluationError::Program)
    }

    fn hash(&mut self) -> Result<ContentHash, SignalEvaluationError> {
        let bytes = self
            .take(32)?
            .try_into()
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        Ok(ContentHash { bytes })
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, SignalEvaluationError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(SignalEvaluationError::MalformedCheckpoint),
        }
    }

    fn value(&mut self) -> Result<SignalValue, SignalEvaluationError> {
        decode_signal_value(self.blob(HARD_SIGNAL_EVENT_BYTES)?)
            .map_err(SignalEvaluationError::Trace)
    }

    fn optional_value(&mut self) -> Result<Option<SignalValue>, SignalEvaluationError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.value()?)),
            _ => Err(SignalEvaluationError::MalformedCheckpoint),
        }
    }

    fn evaluated(&mut self) -> Result<EvaluatedSignal, SignalEvaluationError> {
        match self.byte()? {
            0 => Ok(EvaluatedSignal::Inactive),
            1 => Ok(EvaluatedSignal::Value(self.value()?)),
            _ => Err(SignalEvaluationError::MalformedCheckpoint),
        }
    }

    fn coordinate(&mut self, depth: u8) -> Result<SignalCoordinate, SignalEvaluationError> {
        if depth > 8 {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
        match self.byte()? {
            0 => Ok(SignalCoordinate::VirtualTime { nanos: self.u64()? }),
            1 => Ok(SignalCoordinate::NodeCounter {
                node: self.id()?,
                retired_instructions: self.u64()?,
            }),
            2 => Ok(SignalCoordinate::Operation {
                adapter: self.id()?,
                target: self.id()?,
                operation: self.id()?,
                producer_sequence: self.u64()?,
                suboperation: self.u32()?,
            }),
            3 => Ok(SignalCoordinate::Spatial {
                frame: self.id()?,
                x_mm: self.i64()?,
                y_mm: self.i64()?,
                z_mm: self.i64()?,
                yaw_mdeg: self.i64()?,
                pitch_mdeg: self.i64()?,
                roll_mdeg: self.i64()?,
            }),
            4 => Ok(SignalCoordinate::Event {
                parent: Box::new(self.coordinate(depth + 1)?),
                sequence: self.u64()?,
            }),
            5 => Ok(SignalCoordinate::State {
                adapter: self.id()?,
                target: self.id()?,
                boundary_sequence: self.u64()?,
            }),
            _ => Err(SignalEvaluationError::MalformedCheckpoint),
        }
    }
}

fn decode_node_state(
    bytes: &[u8],
    specification: &StatefulSignalSpecification,
) -> Result<EvaluatorNodeState, SignalEvaluationError> {
    let mut reader = EvaluatorReader::new(bytes);
    let state = match (reader.byte()?, specification) {
        (0, StatefulSignalSpecification::Hysteresis { .. }) => EvaluatorNodeState::Hysteresis {
            value: reader.boolean()?,
            last_transition_nanos: reader.u64()?,
        },
        (1, StatefulSignalSpecification::Debounce { .. }) => EvaluatorNodeState::Debounce {
            committed: reader.value()?,
            candidate: reader.optional_value()?,
            candidate_since_nanos: reader.optional_u64()?,
        },
        (2, StatefulSignalSpecification::Integrator { .. }) => EvaluatorNodeState::Integrator {
            accumulator: reader.value()?,
            pending: reader.value()?,
            previous_input: reader.optional_value()?,
            last_nanos: reader.optional_u64()?,
        },
        (3, StatefulSignalSpecification::LeakyIntegrator { .. }) => {
            EvaluatorNodeState::LeakyIntegrator {
                accumulator: reader.value()?,
                previous_input: reader.optional_value()?,
                last_nanos: reader.optional_u64()?,
            }
        }
        (4, StatefulSignalSpecification::FiniteStateMachine { states, .. }) => {
            let state = reader.id()?;
            if !states.contains(&state) {
                return Err(SignalEvaluationError::InvalidState);
            }
            let count = reader.count(HARD_SIGNAL_STATES_PER_NODE_LIMIT as usize)?;
            let mut timers = BTreeMap::new();
            for _ in 0..count {
                let timer = reader.id()?;
                let deadline = reader.u64()?;
                if timers.insert(timer, deadline).is_some() {
                    return Err(SignalEvaluationError::MalformedCheckpoint);
                }
            }
            EvaluatorNodeState::FiniteStateMachine { state, timers }
        }
        (5, StatefulSignalSpecification::MarkovChain { states, .. }) => {
            let state = reader.id()?;
            if !states.contains(&state) {
                return Err(SignalEvaluationError::InvalidState);
            }
            EvaluatorNodeState::MarkovChain {
                state,
                transition_sequence: reader.u64()?,
            }
        }
        (6, StatefulSignalSpecification::BurstProcess { .. }) => EvaluatorNodeState::BurstProcess {
            bad: reader.boolean()?,
            transition_sequence: reader.u64()?,
        },
        (7, StatefulSignalSpecification::Counter { maximum, .. }) => {
            let count = reader.u64()?;
            if count > *maximum {
                return Err(SignalEvaluationError::InvalidState);
            }
            EvaluatorNodeState::Counter { count }
        }
        (8, StatefulSignalSpecification::QueueModel { capacity, .. }) => {
            let backlog = reader.u32()?;
            let service_remainder = reader.u64()?;
            if backlog > *capacity || service_remainder >= 1_000_000_000 {
                return Err(SignalEvaluationError::InvalidState);
            }
            EvaluatorNodeState::QueueModel {
                backlog,
                service_remainder,
                last_nanos: reader.optional_u64()?,
            }
        }
        _ => return Err(SignalEvaluationError::StateVariantMismatch),
    };
    reader.finish()?;
    if encode_node_state(&state)? != bytes {
        return Err(SignalEvaluationError::NonCanonicalCheckpoint);
    }
    Ok(state)
}

fn decode_evaluator_checkpoint<'a>(
    program: &'a SignalProgram,
    artifacts: &'a dyn SignalArtifactProvider,
    checkpoint: &SignalEvaluatorCheckpoint,
) -> Result<SignalEvaluator<'a>, SignalEvaluationError> {
    let mut reader = EvaluatorReader::new(&checkpoint.bytes);
    if reader.take(EVALUATOR_CHECKPOINT_MAGIC.len())? != EVALUATOR_CHECKPOINT_MAGIC
        || reader.u16()? != SIGNAL_EVALUATOR_VERSION
        || reader.hash()? != program.id()
    {
        return Err(SignalEvaluationError::CheckpointIdentityMismatch);
    }
    let telemetry_count = reader.count(HARD_SIGNAL_BOUNDARY_ITEMS)?;
    let mut telemetry = BTreeMap::new();
    for _ in 0..telemetry_count {
        let key = SignalTelemetryKey {
            adapter: reader.id()?,
            target: reader.id()?,
            field: reader.id()?,
        };
        let value = reader.value()?;
        if telemetry.insert(key, value).is_some() {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
    }
    let expected_state = program
        .nodes()
        .iter()
        .filter_map(|node| match &node.kind {
            SignalNodeKind::Stateful {
                specification,
                state_bytes,
            } => Some((node.id.clone(), (specification, *state_bytes))),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let state_count = reader.count(expected_state.len())?;
    if state_count != expected_state.len() {
        return Err(SignalEvaluationError::IncompleteCheckpoint);
    }
    let mut state = BTreeMap::new();
    for _ in 0..state_count {
        let id = reader.id()?;
        let (specification, declared) = expected_state
            .get(&id)
            .map(|(specification, declared)| (*specification, *declared))
            .ok_or_else(|| SignalEvaluationError::MissingState(id.clone()))?;
        let maximum = usize::try_from(declared)
            .unwrap_or(HARD_SIGNAL_NODE_RUNTIME_BYTES)
            .min(HARD_SIGNAL_NODE_RUNTIME_BYTES);
        let bytes = reader.blob(maximum)?;
        let decoded = decode_node_state(bytes, specification)?;
        if state.insert(id, decoded).is_some() {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
    }
    if state.keys().collect::<Vec<_>>() != expected_state.keys().collect::<Vec<_>>() {
        return Err(SignalEvaluationError::IncompleteCheckpoint);
    }
    let coordinate_count = reader.count(state.len())?;
    let mut state_coordinates = BTreeMap::new();
    for _ in 0..coordinate_count {
        let id = reader.id()?;
        let coordinate = reader.coordinate(0)?;
        let sequence = reader.u64()?;
        if !state.contains_key(&id)
            || state_coordinates
                .insert(id, (coordinate, sequence))
                .is_some()
        {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
    }
    let limits = history_limits(program);
    let history_node_count = reader.count(limits.len())?;
    let mut history = BTreeMap::new();
    let mut retained_history = 0_usize;
    for _ in 0..history_node_count {
        let id = reader.id()?;
        let limit = limits
            .get(&id)
            .copied()
            .ok_or_else(|| SignalEvaluationError::UnexpectedHistory(id.clone()))?;
        let count = reader.count(limit)?;
        retained_history = retained_history
            .checked_add(count)
            .ok_or(SignalEvaluationError::CheckpointLimit)?;
        if retained_history > HARD_SIGNAL_HISTORY_ENTRIES {
            return Err(SignalEvaluationError::CheckpointLimit);
        }
        let node = program
            .nodes()
            .iter()
            .find(|node| node.id == id)
            .ok_or_else(|| SignalEvaluationError::MissingNode(id.clone()))?;
        let mut entries = VecDeque::with_capacity(count);
        for _ in 0..count {
            let coordinate = reader.coordinate(0)?;
            let same_coordinate_sequence = reader.u64()?;
            let output = reader.evaluated()?;
            if coordinate_domain_runtime(&coordinate) != node.domain
                || entries.back().is_some_and(|prior: &HistoryEntry| {
                    (&prior.coordinate, prior.same_coordinate_sequence)
                        >= (&coordinate, same_coordinate_sequence)
                })
            {
                return Err(SignalEvaluationError::MalformedCheckpoint);
            }
            validate_evaluated_shape(node, &output)?;
            entries.push_back(HistoryEntry {
                coordinate,
                same_coordinate_sequence,
                output,
            });
        }
        if history.insert(id, entries).is_some() {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
    }
    let emitted_count = reader.count(HARD_SIGNAL_BOUNDARY_ITEMS)?;
    let mut emitted_events = Vec::with_capacity(emitted_count);
    for _ in 0..emitted_count {
        let node = reader.id()?;
        if !state.contains_key(&node) {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
        emitted_events.push(StatefulSignalEvent {
            node,
            variant: reader.id()?,
            coordinate: reader.coordinate(0)?,
            same_coordinate_sequence: reader.u64()?,
        });
    }
    reader.finish()?;
    let evaluator = SignalEvaluator {
        program,
        artifacts,
        boundary: SignalBoundarySnapshot { telemetry },
        state,
        state_coordinates,
        history,
        history_limits: limits,
        retained_history,
        emitted_events,
    };
    if evaluator.checkpoint()?.bytes != checkpoint.bytes {
        return Err(SignalEvaluationError::NonCanonicalCheckpoint);
    }
    Ok(evaluator)
}

/// Deterministic signal evaluation failure.
#[derive(Debug)]
pub enum SignalEvaluationError {
    /// Requested output is not exported by the program.
    NotExported(SignalId),
    /// A validated program unexpectedly omitted a referenced node.
    MissingNode(SignalId),
    /// Evaluation coordinate and node domain differ.
    DomainMismatch {
        /// Rejected node.
        node: SignalId,
        /// Declared domain.
        expected: SignalDomain,
        /// Supplied domain.
        actual: SignalDomain,
    },
    /// A required input explicitly evaluated inactive.
    InactiveInput,
    /// A produced value contradicted the node's static output shape.
    OutputShapeMismatch(SignalId),
    /// Required delayed telemetry was absent from the boundary snapshot.
    MissingTelemetry {
        /// Adapter identity.
        adapter: SignalId,
        /// Target identity.
        target: SignalId,
        /// Field identity.
        field: SignalId,
    },
    /// A stochastic source required an opportunity identity.
    OpportunityIdentityRequired,
    /// A stochastic source required a transition identity.
    TransitionIdentityRequired,
    /// Opportunity identity did not match the declared transition opportunity.
    OpportunityKindMismatch,
    /// Normalized sampler table identity or parameters differ from the source.
    SamplerContractMismatch(SignalId),
    /// A source coordinate preceded its epoch.
    CoordinateBeforeEpoch,
    /// Coordinates did not share a compatible scalar domain and identity.
    IncompatibleCoordinates,
    /// Operation requires virtual-time coordinates.
    VirtualTimeRequired,
    /// Evaluation was requested outside an explicit source extent.
    OutsideSourceExtent,
    /// Repeat behavior had no positive source extent.
    InvalidRepeatExtent,
    /// Period or interpolation span was zero or invalid.
    InvalidPeriod,
    /// Checked arithmetic overflowed or a value exceeded its declared range.
    ArithmeticOverflow,
    /// Division by zero was requested.
    DivisionByZero,
    /// Runtime values contradicted a validated type contract.
    TypeMismatch,
    /// Closed enum mapping omitted the supplied variant.
    UnmappedEnum,
    /// Operator schema and runtime dispatch differed.
    InvalidOperator,
    /// Required past state was not retained.
    HistoryUnavailable,
    /// Evaluation attempted to move mutable state backward.
    NonMonotoneEvaluation,
    /// Repeating the same coordinate produced a different value.
    NonDeterministicRepeat,
    /// A compiled evaluator resource ceiling was exceeded.
    ResourceLimit,
    /// A stateful operator needed more authored catch-up steps than permitted.
    CatchUpLimitExceeded {
        /// Number of cadence transitions required at this evaluation.
        requested: u64,
        /// Authored per-evaluation ceiling.
        maximum: u32,
    },
    /// Counter-key stream could not produce a rejection-sampled value.
    KeyStreamExhausted,
    /// Distance metric is outside the closed evaluator vocabulary.
    UnknownMetric(SignalId),
    /// Orientation convention is outside the closed evaluator vocabulary.
    UnknownOrientationConvention(SignalId),
    /// A spatial sampling input was not a registered field source.
    SpatialFieldRequired(SignalId),
    /// Artifact bytes did not match the requested content address.
    ArtifactContentMismatch(ContentHash),
    /// Provider was asked to evaluate a non-artifact source.
    ArtifactSourceRequired(SignalId),
    /// Trace manifest did not retain the source's required raw provenance.
    TraceProvenanceMismatch,
    /// Requested trace channel was absent.
    MissingTraceChannel(SignalId),
    /// Trace channel shape contradicted the signal declaration.
    TraceShapeMismatch(SignalId),
    /// Trace event/sample channel and request coordinate disagreed.
    TraceEventCoordinateMismatch,
    /// Trace chunk bytes contradicted their manifest reference.
    TraceChunkMismatch(ContentHash),
    /// Trace-to-simulation mapping collapsed or reordered coordinates.
    NonMonotoneTraceMapping,
    /// Requested trace sample was absent or invalid under its policy.
    TraceSampleMissing,
    /// Trace quality channel rejected the requested sample.
    TraceQualityRejected,
    /// Interpolation attempted to cross an explicit discontinuity.
    TraceDiscontinuity,
    /// A spatial source was evaluated without a spatial coordinate.
    SpatialCoordinateRequired,
    /// Spatial source and request coordinate frames differ.
    SpatialFrameMismatch,
    /// Seeded-field distribution or its exact parameters are invalid.
    InvalidSpatialDistribution,
    /// Normalized spatial artifact failed codec or geometry validation.
    SpatialArtifact(SpatialArtifactError),
    /// Spatial artifact kind, identity, shape, or authored parameters differ.
    SpatialArtifactMismatch(SignalId),
    /// Tiled manifest referenced a non-grid artifact.
    SpatialTileKind,
    /// Tiled manifest bounds contradicted the referenced grid.
    SpatialTileBounds,
    /// Spatial coordinate was outside the source's defined extent.
    SpatialOutsideExtent,
    /// Dense spatial index was outside its validated value array.
    SpatialArtifactIndex,
    /// Zone boundary rule is outside the closed vocabulary.
    UnknownSpatialBoundary(SignalId),
    /// Zone overlap rule is outside the closed vocabulary.
    UnknownZoneOverlap(SignalId),
    /// Mutable state was absent for a stateful node.
    MissingState(SignalId),
    /// Mutable state variant contradicted the node specification.
    StateVariantMismatch,
    /// Current finite-state-machine state was invalid.
    InvalidState,
    /// Markov probability selection failed despite validated row totals.
    InvalidProbabilityRow,
    /// Finite-state machine had no transition under an error policy.
    UnmatchedStateMachineEvent {
        /// Current state.
        state: SignalId,
        /// Input event.
        event: SignalId,
    },
    /// Bounded queue overflowed under the error policy.
    QueueOverflow,
    /// Queue overflow policy was outside the closed vocabulary.
    UnknownQueueOverflow(SignalId),
    /// One node's encoded mutable state exceeds its authored byte bound.
    StateBoundExceeded {
        /// Stateful node.
        node: SignalId,
        /// Encoded bytes.
        actual: usize,
        /// Authored maximum.
        declared: u64,
    },
    /// Evaluator checkpoint exceeds a count or byte ceiling.
    CheckpointLimit,
    /// Checkpoint bytes do not match their content address.
    CheckpointContentMismatch,
    /// Checkpoint version or signal-program identity differs.
    CheckpointIdentityMismatch,
    /// Checkpoint binary framing, ordering, or tags are malformed.
    MalformedCheckpoint,
    /// Decoded checkpoint does not reproduce the supplied bytes.
    NonCanonicalCheckpoint,
    /// Checkpoint omits required mutable state.
    IncompleteCheckpoint,
    /// Checkpoint retained history for a node with no declared consumer bound.
    UnexpectedHistory(SignalId),
    /// Nested signal-program contract failed.
    Program(SignalProgramError),
    /// Immutable artifact store failed.
    Store(DagStoreError),
    /// Normalized trace failed validation.
    Trace(TraceError),
    /// Normalized inverse-CDF table failed validation.
    Sampler(InverseCdfTableError),
}

impl fmt::Display for SignalEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "signal evaluation failed: {self:?}")
    }
}

impl Error for SignalEvaluationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Program(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Trace(error) => Some(error),
            Self::Sampler(error) => Some(error),
            Self::SpatialArtifact(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MemoryDagStore;

    fn id(value: &str) -> SignalId {
        match SignalId::parse(value) {
            Ok(value) => value,
            Err(error) => panic!("test signal ID must be valid: {error}"),
        }
    }

    fn object_id(value: &str) -> FaultObjectId {
        match FaultObjectId::parse(value) {
            Ok(value) => value,
            Err(error) => panic!("test object ID must be valid: {error}"),
        }
    }

    fn shape(value_type: SignalValueType, unit: SignalUnit) -> SignalShape {
        match SignalShape::new(value_type, unit, 0) {
            Ok(value) => value,
            Err(error) => panic!("test shape must be valid: {error}"),
        }
    }

    fn choice() -> SignalChoiceContext {
        SignalChoiceContext {
            scenario_seed: ContentHash::from_bytes(b"scenario"),
            consumer: object_id("consumer"),
            opportunity: None,
            transition_sequence: None,
        }
    }

    #[test]
    fn ramp_and_ratio_arithmetic_are_exact() {
        let value_shape = shape(SignalValueType::I64, SignalUnit::Dimensionless);
        let ramp = SignalNode {
            id: id("ramp"),
            domain: SignalDomain::VirtualTime,
            output: value_shape.clone(),
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::Ramp {
                start: SignalCoordinate::VirtualTime { nanos: 0 },
                end: SignalCoordinate::VirtualTime { nanos: 10 },
                start_value: SignalValue::I64(-10),
                end_value: SignalValue::I64(10),
                rounding: SignalRounding::NearestTiesToEven,
            }),
        };
        let scaled = SignalNode {
            id: id("scaled"),
            domain: SignalDomain::VirtualTime,
            output: value_shape,
            inputs: vec![id("ramp")],
            kind: SignalNodeKind::Pure(PureSignalSpecification::RatioArithmetic {
                operator: PureSignalOperator::MultiplyRatio,
                ratio: match ExactRatio::new(3, 2) {
                    Ok(value) => value,
                    Err(error) => panic!("test ratio must be valid: {error}"),
                },
                rounding: SignalRounding::NearestTiesToEven,
                overflow: SignalOverflow::Error,
            }),
        };
        let program = match SignalProgram::new(
            vec![scaled, ramp],
            vec![id("scaled")],
            SignalResourceLimits::default(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("test program must be valid: {error}"),
        };
        let store = MemoryDagStore::new();
        let provider = DagSignalArtifactProvider::new(&store);
        let mut evaluator =
            match SignalEvaluator::new(&program, &provider, SignalBoundarySnapshot::default()) {
                Ok(value) => value,
                Err(error) => panic!("test evaluator must initialize: {error}"),
            };
        let result = evaluator.evaluate(&SignalEvaluationRequest {
            output: id("scaled"),
            coordinate: SignalCoordinate::VirtualTime { nanos: 7 },
            same_coordinate_sequence: 0,
            choice: choice(),
        });
        assert!(matches!(
            result,
            Ok(EvaluatedSignal::Value(SignalValue::I64(6)))
        ));
    }

    #[test]
    fn ratio_division_preserves_a_negative_divisor() {
        let value_shape = shape(SignalValueType::I64, SignalUnit::Dimensionless);
        let input = SignalNode {
            id: id("input"),
            domain: SignalDomain::VirtualTime,
            output: value_shape.clone(),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::I64(8),
            },
        };
        let divided = SignalNode {
            id: id("divided"),
            domain: SignalDomain::VirtualTime,
            output: value_shape,
            inputs: vec![id("input")],
            kind: SignalNodeKind::Pure(PureSignalSpecification::RatioArithmetic {
                operator: PureSignalOperator::DivideRatio,
                ratio: match ExactRatio::new(-2, 1) {
                    Ok(value) => value,
                    Err(error) => panic!("test ratio must be valid: {error}"),
                },
                rounding: SignalRounding::NearestTiesToEven,
                overflow: SignalOverflow::Error,
            }),
        };
        let program = match SignalProgram::new(
            vec![divided, input],
            vec![id("divided")],
            SignalResourceLimits::default(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("test program must be valid: {error}"),
        };
        let store = MemoryDagStore::new();
        let provider = DagSignalArtifactProvider::new(&store);
        let mut evaluator =
            match SignalEvaluator::new(&program, &provider, SignalBoundarySnapshot::default()) {
                Ok(value) => value,
                Err(error) => panic!("test evaluator must initialize: {error}"),
            };
        assert!(matches!(
            evaluator.evaluate(&SignalEvaluationRequest {
                output: id("divided"),
                coordinate: SignalCoordinate::VirtualTime { nanos: 0 },
                same_coordinate_sequence: 0,
                choice: choice(),
            }),
            Ok(EvaluatedSignal::Value(SignalValue::I64(-4)))
        ));
    }

    #[test]
    fn field_sample_uses_content_addressed_grid_and_explicit_position() {
        let grid_shape = shape(SignalValueType::I64, SignalUnit::Millidecibels);
        let artifact = match NormalizedSpatialArtifact::new(
            id("city-frame"),
            grid_shape.clone(),
            SpatialArtifactKind::RegularGrid {
                origin_mm: [0; 3],
                cell_size_mm: [10; 3],
                dimensions: [2, 1, 1],
                values: vec![SignalValue::I64(-100), SignalValue::I64(-200)],
            },
        ) {
            Ok(value) => value,
            Err(error) => panic!("test grid must be valid: {error}"),
        };
        let store = MemoryDagStore::new();
        let stored = store.put(&artifact.encode());
        assert!(matches!(stored, Ok(content) if content == artifact.content()));
        let field = SignalNode {
            id: id("field"),
            domain: SignalDomain::Spatial,
            output: grid_shape.clone(),
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::RegularGrid {
                artifact: artifact.content(),
                coordinate_frame: id("city-frame"),
                origin_mm: [0; 3],
                cell_size_mm: [10; 3],
                dimensions: [2, 1, 1],
                interpolation: SignalInterpolation::Nearest,
                outside: SignalBoundaryBehavior::Error,
            }),
        };
        let position = SignalNode {
            id: id("position"),
            domain: SignalDomain::VirtualTime,
            output: shape(
                SignalValueType::Vector3(Box::new(SignalValueType::I64)),
                SignalUnit::Millimetres,
            ),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::Vector3(vec![
                    SignalValue::I64(9),
                    SignalValue::I64(0),
                    SignalValue::I64(0),
                ]),
            },
        };
        let sample = SignalNode {
            id: id("sample"),
            domain: SignalDomain::VirtualTime,
            output: grid_shape,
            inputs: vec![id("field"), id("position")],
            kind: SignalNodeKind::Pure(PureSignalSpecification::FieldSample),
        };
        let program = match SignalProgram::new(
            vec![sample, field, position],
            vec![id("sample")],
            SignalResourceLimits::default(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("test program must be valid: {error}"),
        };
        let provider = DagSignalArtifactProvider::new(&store);
        let mut evaluator =
            match SignalEvaluator::new(&program, &provider, SignalBoundarySnapshot::default()) {
                Ok(value) => value,
                Err(error) => panic!("test evaluator must initialize: {error}"),
            };
        let result = evaluator.evaluate(&SignalEvaluationRequest {
            output: id("sample"),
            coordinate: SignalCoordinate::VirtualTime { nanos: 1 },
            same_coordinate_sequence: 0,
            choice: choice(),
        });
        assert!(matches!(
            result,
            Ok(EvaluatedSignal::Value(SignalValue::I64(-200)))
        ));
    }

    #[test]
    fn checkpoint_restore_preserves_stateful_continuation() {
        let event_schema = id("arrival");
        let events = SignalNode {
            id: id("events"),
            domain: SignalDomain::VirtualTime,
            output: shape(
                SignalValueType::Event(event_schema.clone()),
                SignalUnit::Dimensionless,
            ),
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                events: vec![
                    SignalPoint {
                        coordinate: SignalCoordinate::VirtualTime { nanos: 1 },
                        sequence: 0,
                        value: SignalValue::Event {
                            schema: event_schema.clone(),
                            payload: Vec::new(),
                        },
                    },
                    SignalPoint {
                        coordinate: SignalCoordinate::VirtualTime { nanos: 2 },
                        sequence: 0,
                        value: SignalValue::Event {
                            schema: event_schema,
                            payload: Vec::new(),
                        },
                    },
                ],
            }),
        };
        let counter = SignalNode {
            id: id("counter"),
            domain: SignalDomain::VirtualTime,
            output: shape(SignalValueType::U64, SignalUnit::Dimensionless),
            inputs: vec![id("events")],
            kind: SignalNodeKind::Stateful {
                specification: StatefulSignalSpecification::Counter {
                    initial: 0,
                    maximum: 10,
                    overflow: SignalOverflow::Error,
                    reset_event: None,
                },
                state_bytes: 32,
            },
        };
        let program = match SignalProgram::new(
            vec![counter, events],
            vec![id("counter")],
            SignalResourceLimits::default(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("test program must be valid: {error}"),
        };
        let store = MemoryDagStore::new();
        let provider = DagSignalArtifactProvider::new(&store);
        let mut uninterrupted =
            match SignalEvaluator::new(&program, &provider, SignalBoundarySnapshot::default()) {
                Ok(value) => value,
                Err(error) => panic!("test evaluator must initialize: {error}"),
            };
        let first = SignalEvaluationRequest {
            output: id("counter"),
            coordinate: SignalCoordinate::VirtualTime { nanos: 1 },
            same_coordinate_sequence: 0,
            choice: choice(),
        };
        assert!(matches!(
            uninterrupted.evaluate(&first),
            Ok(EvaluatedSignal::Value(SignalValue::U64(1)))
        ));
        let checkpoint = match uninterrupted.checkpoint() {
            Ok(value) => value,
            Err(error) => panic!("test checkpoint must encode: {error}"),
        };
        let mut restored = match SignalEvaluator::restore(&program, &provider, &checkpoint) {
            Ok(value) => value,
            Err(error) => panic!("test checkpoint must restore: {error}"),
        };
        let second = SignalEvaluationRequest {
            output: id("counter"),
            coordinate: SignalCoordinate::VirtualTime { nanos: 2 },
            same_coordinate_sequence: 0,
            choice: choice(),
        };
        assert_eq!(
            uninterrupted.evaluate(&second).ok(),
            restored.evaluate(&second).ok()
        );
        assert_eq!(uninterrupted.checkpoint().ok(), restored.checkpoint().ok());
    }

    #[test]
    fn event_merge_maps_global_sequence_to_source_then_local_sequence() {
        let event_schema = id("merged-event");
        let event_shape = shape(
            SignalValueType::Event(event_schema.clone()),
            SignalUnit::Dimensionless,
        );
        let source = |source_id: &str, payload: u8| SignalNode {
            id: id(source_id),
            domain: SignalDomain::VirtualTime,
            output: event_shape.clone(),
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                events: vec![SignalPoint {
                    coordinate: SignalCoordinate::VirtualTime { nanos: 10 },
                    sequence: 0,
                    value: SignalValue::Event {
                        schema: event_schema.clone(),
                        payload: vec![payload],
                    },
                }],
            }),
        };
        let merge = SignalNode {
            id: id("merge"),
            domain: SignalDomain::VirtualTime,
            output: event_shape.clone(),
            inputs: vec![id("source-b"), id("source-a")],
            kind: SignalNodeKind::Pure(PureSignalSpecification::MergeEvents {
                source_sequence_limit: 4,
            }),
        };
        let program = match SignalProgram::new(
            vec![merge, source("source-b", 2), source("source-a", 1)],
            vec![id("merge")],
            SignalResourceLimits::default(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("test program must be valid: {error}"),
        };
        let store = MemoryDagStore::new();
        let provider = DagSignalArtifactProvider::new(&store);
        let mut evaluator =
            match SignalEvaluator::new(&program, &provider, SignalBoundarySnapshot::default()) {
                Ok(value) => value,
                Err(error) => panic!("test evaluator must initialize: {error}"),
            };
        let evaluate = |evaluator: &mut SignalEvaluator<'_>, sequence| {
            evaluator.evaluate(&SignalEvaluationRequest {
                output: id("merge"),
                coordinate: SignalCoordinate::VirtualTime { nanos: 10 },
                same_coordinate_sequence: sequence,
                choice: choice(),
            })
        };
        assert!(matches!(
            evaluate(&mut evaluator, 0),
            Ok(EvaluatedSignal::Value(SignalValue::Event { payload, .. })) if payload == vec![1]
        ));
        assert!(matches!(
            evaluate(&mut evaluator, 4),
            Ok(EvaluatedSignal::Value(SignalValue::Event { payload, .. })) if payload == vec![2]
        ));
    }

    #[test]
    fn trace_interpolate_policy_bridges_an_invalid_exact_sample() {
        let mut entries = vec![
            MappedTraceEntry {
                coordinate: 0,
                event_sequence: None,
                value: SignalValue::I64(0),
                validity: TraceValidity::Valid,
            },
            MappedTraceEntry {
                coordinate: 5,
                event_sequence: None,
                value: SignalValue::I64(99),
                validity: TraceValidity::InvalidQuality,
            },
            MappedTraceEntry {
                coordinate: 10,
                event_sequence: None,
                value: SignalValue::I64(10),
                validity: TraceValidity::Valid,
            },
        ];
        assert!(matches!(
            sample_mapped_entries(
                &mut entries,
                5,
                None,
                SignalInterpolation::Linear {
                    rounding: SignalRounding::NearestTiesToEven,
                    overflow: SignalOverflow::Error,
                },
                MissingSampleBehavior::Interpolate,
            ),
            Ok(EvaluatedSignal::Value(SignalValue::I64(5)))
        ));
    }

    #[test]
    fn cadence_integrator_commits_prior_input_at_boundaries() {
        let specification = StatefulSignalSpecification::Integrator {
            initial: SignalValue::I64(0),
            cadence_nanos: 10,
            time_unit_nanos: 10,
            rounding: SignalRounding::NearestTiesToEven,
            overflow: SignalOverflow::Error,
        };
        let node = SignalNode {
            id: id("integrator"),
            domain: SignalDomain::VirtualTime,
            output: shape(SignalValueType::I64, SignalUnit::Dimensionless),
            inputs: vec![id("input")],
            kind: SignalNodeKind::Stateful {
                specification: specification.clone(),
                state_bytes: 256,
            },
        };
        let mut state = EvaluatorNodeState::Integrator {
            accumulator: SignalValue::I64(0),
            pending: SignalValue::I64(0),
            previous_input: None,
            last_nanos: None,
        };
        let mut emitted = Vec::new();
        let mut evaluate = |nanos, input| {
            evaluate_stateful_node(
                &node,
                &specification,
                &SignalEvaluationRequest {
                    output: id("integrator"),
                    coordinate: SignalCoordinate::VirtualTime { nanos },
                    same_coordinate_sequence: 0,
                    choice: choice(),
                },
                &[EvaluatedSignal::Value(SignalValue::I64(input))],
                &mut state,
                &mut emitted,
            )
        };

        assert!(matches!(
            evaluate(0, 2),
            Ok(EvaluatedSignal::Value(SignalValue::I64(0)))
        ));
        assert!(matches!(
            evaluate(5, 4),
            Ok(EvaluatedSignal::Value(SignalValue::I64(0)))
        ));
        assert!(matches!(
            evaluate(10, 6),
            Ok(EvaluatedSignal::Value(SignalValue::I64(3)))
        ));
    }

    #[test]
    fn leaky_integrator_rejects_excess_catch_up_before_mutation() {
        let specification = StatefulSignalSpecification::LeakyIntegrator {
            initial: SignalValue::I64(0),
            cadence_nanos: 10,
            time_unit_nanos: 10,
            decay_ratio: match ExactRatio::new(1, 2) {
                Ok(value) => value,
                Err(error) => panic!("test ratio must be valid: {error}"),
            },
            maximum_catch_up_steps: 2,
            rounding: SignalRounding::NearestTiesToEven,
            overflow: SignalOverflow::Error,
        };
        let node = SignalNode {
            id: id("leaky"),
            domain: SignalDomain::VirtualTime,
            output: shape(SignalValueType::I64, SignalUnit::Dimensionless),
            inputs: vec![id("input")],
            kind: SignalNodeKind::Stateful {
                specification: specification.clone(),
                state_bytes: 256,
            },
        };
        let mut state = EvaluatorNodeState::LeakyIntegrator {
            accumulator: SignalValue::I64(0),
            previous_input: None,
            last_nanos: None,
        };
        let mut emitted = Vec::new();
        let first = evaluate_stateful_node(
            &node,
            &specification,
            &SignalEvaluationRequest {
                output: id("leaky"),
                coordinate: SignalCoordinate::VirtualTime { nanos: 0 },
                same_coordinate_sequence: 0,
                choice: choice(),
            },
            &[EvaluatedSignal::Value(SignalValue::I64(10))],
            &mut state,
            &mut emitted,
        );
        assert!(first.is_ok());
        let before = state.clone();
        let result = evaluate_stateful_node(
            &node,
            &specification,
            &SignalEvaluationRequest {
                output: id("leaky"),
                coordinate: SignalCoordinate::VirtualTime { nanos: 30 },
                same_coordinate_sequence: 0,
                choice: choice(),
            },
            &[EvaluatedSignal::Value(SignalValue::I64(10))],
            &mut state,
            &mut emitted,
        );
        assert!(matches!(
            result,
            Err(SignalEvaluationError::CatchUpLimitExceeded {
                requested: 3,
                maximum: 2,
            })
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn stochastic_keys_ignore_unselected_identity_domains() {
        let node = SignalNode {
            id: id("random"),
            domain: SignalDomain::VirtualTime,
            output: shape(SignalValueType::I64, SignalUnit::Dimensionless),
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::UniformInteger {
                minimum: 0,
                maximum: 10,
                key_domain: StochasticKeyDomain::Coordinate,
                opportunity_filter: None,
            }),
        };
        let request = SignalEvaluationRequest {
            output: id("random"),
            coordinate: SignalCoordinate::VirtualTime { nanos: 7 },
            same_coordinate_sequence: 2,
            choice: choice(),
        };
        let mut unrelated = request.clone();
        unrelated.choice.transition_sequence = Some(99);
        assert_eq!(
            keyed_u64(&node, &request, StochasticKeyDomain::Coordinate, 0),
            keyed_u64(&node, &unrelated, StochasticKeyDomain::Coordinate, 0)
        );

        let mut moved = unrelated.clone();
        moved.coordinate = SignalCoordinate::VirtualTime { nanos: 8 };
        moved.same_coordinate_sequence = 0;
        assert_eq!(
            keyed_u64(&node, &unrelated, StochasticKeyDomain::Transition, 0),
            keyed_u64(&node, &moved, StochasticKeyDomain::Transition, 0)
        );
    }

    #[test]
    fn window_includes_the_current_live_sample() {
        let result = evaluate_window(
            PureSignalOperator::WindowMean,
            10,
            4,
            SignalRounding::NearestTiesToEven,
            SignalOverflow::Error,
            &SignalCoordinate::VirtualTime { nanos: 10 },
            0,
            None,
            &EvaluatedSignal::Value(SignalValue::I64(7)),
        );
        assert!(matches!(
            result,
            Ok(EvaluatedSignal::Value(SignalValue::I64(7)))
        ));
    }
}
