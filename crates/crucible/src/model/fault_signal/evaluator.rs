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
use std::sync::Arc;

use super::*;
use crate::model::{DagStore, DagStoreError};

mod codec;
mod math;

use codec::*;
pub(super) use math::*;

/// Hard maximum event payload accepted by the evaluator.
pub const HARD_SIGNAL_EVENT_BYTES: usize = HARD_TRACE_VALUE_BYTES;
/// Hard maximum retained history entries across one evaluator.
pub const HARD_SIGNAL_HISTORY_ENTRIES: usize = 4_194_304;
/// Maximum serialized bytes retained for one signal node.
pub const HARD_SIGNAL_NODE_RUNTIME_BYTES: usize = 16_777_216;
/// Hard maximum delayed telemetry fields or pending emitted events.
pub const HARD_SIGNAL_BOUNDARY_ITEMS: usize = 262_144;
const EVALUATOR_CHECKPOINT_MAGIC: &[u8; 8] = b"CREVAL01";

/// Immutable canonical evaluator checkpoint bytes and content identity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
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
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, SignalEvaluationError> {
        let checkpoint = Self {
            content: ContentHash::from_bytes(&bytes),
            bytes,
        };
        let _ = SignalEvaluator::restore(program, artifacts, &checkpoint, resource_limits)?;
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
        resource_limits: FaultResourceLimits,
    ) -> Result<(), SignalEvaluationError> {
        let bytes = u64::try_from(self.bytes.len()).map_err(|_| {
            SignalEvaluationError::PlanResourceLimit(FaultResourceLimitError::Representation {
                field: "fat_checkpoint_bytes",
                value: u64::MAX,
            })
        })?;
        resource_limits
            .reserve("fat_checkpoint_bytes", 0, bytes)
            .map_err(SignalEvaluationError::PlanResourceLimit)?;
        if ContentHash::from_bytes(&self.bytes) != self.content {
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
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
        resource_limits: FaultResourceLimits,
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
        resource_limits: FaultResourceLimits,
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
                resource_limits,
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

/// Production artifact provider that owns a shared content-addressed store.
///
/// This form is suitable for long-lived scheduler continuations, while
/// [`DagSignalArtifactProvider`] remains convenient for scoped evaluation.
#[derive(Clone)]
pub struct OwnedDagSignalArtifactProvider {
    store: Arc<dyn DagStore>,
}

impl OwnedDagSignalArtifactProvider {
    /// Wraps a shared production content-addressed store.
    #[must_use]
    pub fn new(store: Arc<dyn DagStore>) -> Self {
        Self { store }
    }
}

impl SignalArtifactProvider for OwnedDagSignalArtifactProvider {
    fn inverse_cdf_table(
        &self,
        content: &ContentHash,
    ) -> Result<InverseCdfTable, SignalEvaluationError> {
        DagSignalArtifactProvider::new(self.store.as_ref()).inverse_cdf_table(content)
    }

    fn evaluate_artifact_source(
        &self,
        node: &SignalNode,
        source: &SignalSourceSpecification,
        coordinate: &SignalCoordinate,
        same_coordinate_sequence: u64,
        choice: &SignalChoiceContext,
        inputs: &[EvaluatedSignal],
        resource_limits: FaultResourceLimits,
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        DagSignalArtifactProvider::new(self.store.as_ref()).evaluate_artifact_source(
            node,
            source,
            coordinate,
            same_coordinate_sequence,
            choice,
            inputs,
            resource_limits,
        )
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
        resource_limits: FaultResourceLimits,
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        let chunk_limit = usize::try_from(resource_limits.trace_chunks_total)
            .map_err(|_| SignalEvaluationError::ResourceLimit)?;
        let manifest =
            SignalTraceManifest::decode_with_chunk_limit(&self.get(&artifact)?, chunk_limit)
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
    resource_limits: FaultResourceLimits,
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
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, SignalEvaluationError> {
        resource_limits
            .validate()
            .map_err(SignalEvaluationError::PlanResourceLimit)?;
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
            resource_limits,
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
        let checkpoint_bytes = u64::try_from(writer.bytes.len()).map_err(|_| {
            SignalEvaluationError::PlanResourceLimit(FaultResourceLimitError::Representation {
                field: "fat_checkpoint_bytes",
                value: u64::MAX,
            })
        })?;
        self.resource_limits
            .reserve("fat_checkpoint_bytes", 0, checkpoint_bytes)
            .map_err(SignalEvaluationError::PlanResourceLimit)?;
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
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, SignalEvaluationError> {
        checkpoint.validate_for_program(program, resource_limits)?;
        decode_evaluator_checkpoint(program, artifacts, checkpoint, resource_limits)
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
                    self.resource_limits,
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
            self.resource_limits,
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
    /// A scenario-owned evaluator resource reservation was rejected.
    PlanResourceLimit(FaultResourceLimitError),
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
            Self::PlanResourceLimit(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "evaluator_test.rs"]
mod tests;
