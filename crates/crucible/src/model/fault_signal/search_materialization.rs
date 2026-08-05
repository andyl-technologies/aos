//! Concrete, replayable materialization of bounded fault-search mutations.
//!
//! Mutation policies are authoring instructions for the explorer, never runtime
//! callbacks. This module turns one finite mutation schedule into an ordinary
//! fixed-policy [`SignalProgram`] and [`FaultBinding`] before execution. The
//! resulting program, binding, artifacts, and provenance digest are sufficient
//! for ordinary replay without invoking the explorer.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use super::*;
use crate::{DagStore, DagStoreError};

/// One exact replacement in a normalized trace channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceSampleMutation {
    /// Mapped virtual coordinate of the existing sample.
    pub coordinate: u64,
    /// Existing event sequence, or `None` for a scalar channel.
    pub event_sequence: Option<u64>,
    /// Replacement value with the channel's exact admitted type.
    pub value: SignalValue,
}

/// Concrete trace-window mutation selected by an explorer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceWindowMaterialization {
    /// Trace source node whose manifest is replaced.
    pub trace_node: SignalId,
    /// Nonempty canonical set of exact sample replacements.
    pub samples: Vec<TraceSampleMutation>,
}

/// One exact replacement of an authored piecewise transfer-function point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingPointMutation {
    /// Zero-based point index admitted by the binding search policy.
    pub index: u32,
    /// Complete replacement point.
    pub point: BindingMapPoint,
}

/// Concrete transfer-function mutation selected by an explorer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingMaterialization {
    /// Nonempty canonical set of point replacements.
    pub points: Vec<MappingPointMutation>,
}

/// Canonical description of the mutation applied to an executable case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaterializedSearchMutation {
    /// A normalized trace interval was replaced.
    TraceWindow(TraceWindowMaterialization),
    /// Piecewise mapping points were replaced.
    Mapping(MappingMaterialization),
}

/// An ordinary fixed-policy executable produced by one finite mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedSearchCase {
    /// Original signal-program identity.
    pub original_program: ContentHash,
    /// Binding identity retained across materialization.
    pub binding_id: FaultObjectId,
    /// Concrete fixed-policy signal program.
    pub program: SignalProgram,
    /// Concrete fixed-policy binding admitted against `program`.
    pub binding: FaultBinding,
    /// Exact mutation schedule.
    pub mutation: MaterializedSearchMutation,
    /// Content identity of the complete transformation.
    pub provenance: ContentHash,
    /// Newly created content-addressed artifacts in dependency order.
    pub artifacts: Vec<ContentHash>,
}

/// Materializes a bounded normalized-trace mutation and stores its artifacts.
///
/// Every requested coordinate must name one existing sample in the selected
/// channel and fall inside the binding's authored half-open mutation window.
/// The returned binding uses `fixed` search and is admitted against the new
/// program identity.
///
/// # Errors
///
/// Returns [`SearchMaterializationError`] for a wrong policy, an unknown or
/// non-trace node, duplicate/out-of-window samples, a type mismatch, an absent
/// artifact, a malformed trace, or failure to admit/store the result.
pub fn materialize_trace_window(
    program: &SignalProgram,
    binding: &FaultBinding,
    store: &dyn DagStore,
    mut mutation: TraceWindowMaterialization,
) -> Result<MaterializedSearchCase, SearchMaterializationError> {
    if binding.program() != program.id() {
        return Err(SearchMaterializationError::ProgramIdentity);
    }
    let BindingSearchPolicy::MutateTraceWindow {
        start_nanos,
        end_nanos,
        maximum_mutations,
    } = binding.search()
    else {
        return Err(SearchMaterializationError::WrongPolicy);
    };
    mutation.samples.sort_by_key(|sample| {
        (
            sample.coordinate,
            sample.event_sequence.unwrap_or_default(),
            sample.event_sequence.is_some(),
        )
    });
    if mutation.samples.is_empty()
        || u64::try_from(mutation.samples.len())
            .map_or(true, |count| count > maximum_mutations.get())
        || mutation.samples.windows(2).any(|pair| {
            (pair[0].coordinate, pair[0].event_sequence)
                == (pair[1].coordinate, pair[1].event_sequence)
        })
        || mutation
            .samples
            .iter()
            .any(|sample| sample.coordinate < *start_nanos || sample.coordinate >= *end_nanos)
    {
        return Err(SearchMaterializationError::InvalidMutation);
    }
    let mut nodes = program.nodes().to_vec();
    if !binding.signals().contains(&mutation.trace_node) {
        return Err(SearchMaterializationError::UnauthorizedTraceNode);
    }
    let node = nodes
        .iter_mut()
        .find(|node| node.id == mutation.trace_node)
        .ok_or(SearchMaterializationError::UnknownTraceNode)?;
    let SignalNodeKind::Source(SignalSourceSpecification::Trace {
        artifact,
        raw_provenance,
        channel,
        time_mapping,
        ..
    }) = &mut node.kind
    else {
        return Err(SearchMaterializationError::UnknownTraceNode);
    };
    let original_artifact = *artifact;
    let source_mapping = *time_mapping;
    let manifest_bytes = get_verified(store, original_artifact)?;
    let mut original_manifest =
        SignalTraceManifest::decode(&manifest_bytes).map_err(SearchMaterializationError::Trace)?;
    if original_manifest.content != original_artifact
        || original_manifest.provenance.raw_content != Some(*raw_provenance)
    {
        return Err(SearchMaterializationError::ContentMismatch);
    }
    let channel_shape = original_manifest
        .channels
        .iter()
        .find(|candidate| candidate.id == *channel)
        .map(|candidate| candidate.shape.clone())
        .ok_or(SearchMaterializationError::UnknownTraceChannel)?;
    if mutation.samples.iter().any(|sample| {
        sample.value.value_type().as_ref() != Some(&channel_shape.value_type)
            || sample.event_sequence.is_some()
                != matches!(channel_shape.value_type, SignalValueType::Event(_))
    }) {
        return Err(SearchMaterializationError::MutationType);
    }
    let replacements = mutation
        .samples
        .iter()
        .map(|sample| {
            (
                (sample.coordinate, sample.event_sequence),
                sample.value.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut replaced = BTreeSet::new();
    let mut changed_artifacts = Vec::new();
    let selected_channel = original_manifest
        .channels
        .iter_mut()
        .find(|candidate| candidate.id == *channel)
        .ok_or(SearchMaterializationError::UnknownTraceChannel)?;
    for reference in &mut selected_channel.chunks {
        let first = super::evaluator::map_trace_coordinate(
            reference.first_coordinate,
            source_mapping.as_ref(),
        )
        .map_err(SearchMaterializationError::Evaluation)?;
        let last = super::evaluator::map_trace_coordinate(
            reference.last_coordinate,
            source_mapping.as_ref(),
        )
        .map_err(SearchMaterializationError::Evaluation)?;
        if replacements
            .range((first, None)..=(last, Some(u64::MAX)))
            .next()
            .is_none()
        {
            continue;
        }
        let chunk_bytes = get_verified(store, reference.content)?;
        let old_chunk =
            SignalTraceChunk::decode(&chunk_bytes).map_err(SearchMaterializationError::Trace)?;
        if old_chunk.content != reference.content
            || old_chunk.channel != selected_channel.id
            || old_chunk.event_channel != selected_channel.event_channel
            || old_chunk.reference() != *reference
        {
            return Err(SearchMaterializationError::ContentMismatch);
        }
        let mut entries = old_chunk.entries;
        for entry in &mut entries {
            let mapped_coordinate =
                super::evaluator::map_trace_coordinate(entry.coordinate, source_mapping.as_ref())
                    .map_err(SearchMaterializationError::Evaluation)?;
            let key = (mapped_coordinate, entry.event_sequence);
            if let Some(value) = replacements.get(&key) {
                entry.value.clone_from(value);
                replaced.insert(key);
            }
        }
        let chunk = SignalTraceChunk::new(
            old_chunk.semantic_version,
            old_chunk.channel,
            old_chunk.event_channel,
            entries,
        )
        .map_err(SearchMaterializationError::Trace)?;
        put_verified(store, &chunk.encode(), chunk.content)?;
        *reference = chunk.reference();
        changed_artifacts.push(chunk.content);
    }
    if replaced.len() != replacements.len() {
        return Err(SearchMaterializationError::MissingSample);
    }
    let mutation_material =
        trace_mutation_material(program.id(), binding.id(), original_artifact, &mutation)?;
    let mut provenance = original_manifest.provenance;
    provenance.importer = FaultObjectId::parse("crucible-search-trace-mutation")
        .map_err(SearchMaterializationError::Contract)?;
    provenance.importer_version = 1;
    provenance.options = ContentHash::from_canonical_material(
        "crucible.trace-search-mutation-options.v1",
        &mutation_material,
    );
    let manifest = SignalTraceManifest::new(
        original_manifest.semantic_version,
        original_manifest.time_basis,
        original_manifest.time_mapping,
        original_manifest.coordinate_frame,
        original_manifest.redaction,
        original_manifest.channels,
        provenance,
    )
    .map_err(SearchMaterializationError::Trace)?;
    put_verified(store, &manifest.encode(), manifest.content)?;
    *artifact = manifest.content;
    let materialized_program =
        SignalProgram::new(nodes, program.exported_outputs().to_vec(), program.limits())
            .map_err(SearchMaterializationError::Program)?;
    let materialized_binding = binding
        .materialize_fixed(&materialized_program, binding.mapping().clone())
        .map_err(SearchMaterializationError::Binding)?;
    let mutation = MaterializedSearchMutation::TraceWindow(mutation);
    let provenance = materialization_digest(
        program.id(),
        binding,
        materialized_program.id(),
        &mutation_material,
    )?;
    changed_artifacts.push(manifest.content);
    Ok(MaterializedSearchCase {
        original_program: program.id(),
        binding_id: binding.id().clone(),
        program: materialized_program,
        binding: materialized_binding,
        mutation,
        provenance,
        artifacts: changed_artifacts,
    })
}

/// Materializes bounded piecewise mapping-point replacements.
///
/// # Errors
///
/// Returns [`SearchMaterializationError`] when the binding has a different
/// policy/mapping, a point is duplicate or unauthorized, the authored mutation
/// count is exceeded, or the resulting fixed binding fails admission.
pub fn materialize_mapping(
    program: &SignalProgram,
    binding: &FaultBinding,
    mut mutation: MappingMaterialization,
) -> Result<MaterializedSearchCase, SearchMaterializationError> {
    if binding.program() != program.id() {
        return Err(SearchMaterializationError::ProgramIdentity);
    }
    let BindingSearchPolicy::MutateMapping {
        point_indices,
        maximum_mutations,
    } = binding.search()
    else {
        return Err(SearchMaterializationError::WrongPolicy);
    };
    mutation.points.sort_by_key(|point| point.index);
    if mutation.points.is_empty()
        || u64::try_from(mutation.points.len())
            .map_or(true, |count| count > maximum_mutations.get())
        || mutation
            .points
            .windows(2)
            .any(|pair| pair[0].index == pair[1].index)
        || mutation
            .points
            .iter()
            .any(|point| point_indices.binary_search(&point.index).is_err())
    {
        return Err(SearchMaterializationError::InvalidMutation);
    }
    let BindingMapping::PiecewiseParameter {
        parameter,
        mut points,
        rounding,
        overflow,
    } = binding.mapping().clone()
    else {
        return Err(SearchMaterializationError::WrongPolicy);
    };
    for replacement in &mutation.points {
        let index = usize::try_from(replacement.index)
            .map_err(|_| SearchMaterializationError::InvalidMutation)?;
        let point = points
            .get_mut(index)
            .ok_or(SearchMaterializationError::InvalidMutation)?;
        point.clone_from(&replacement.point);
    }
    let mapping = BindingMapping::PiecewiseParameter {
        parameter,
        points,
        rounding,
        overflow,
    };
    let materialized_binding = binding
        .materialize_fixed(program, mapping)
        .map_err(SearchMaterializationError::Binding)?;
    let material = mapping_mutation_material(program.id(), binding.id(), &mutation)?;
    let mutation = MaterializedSearchMutation::Mapping(mutation);
    Ok(MaterializedSearchCase {
        original_program: program.id(),
        binding_id: binding.id().clone(),
        program: program.clone(),
        binding: materialized_binding,
        mutation,
        provenance: materialization_digest(program.id(), binding, program.id(), &material)?,
        artifacts: Vec::new(),
    })
}

fn put_verified(
    store: &dyn DagStore,
    bytes: &[u8],
    expected: ContentHash,
) -> Result<(), SearchMaterializationError> {
    let actual = store
        .put(bytes)
        .map_err(SearchMaterializationError::Store)?;
    if actual == expected {
        Ok(())
    } else {
        Err(SearchMaterializationError::ContentMismatch)
    }
}

fn get_verified(
    store: &dyn DagStore,
    expected: ContentHash,
) -> Result<Vec<u8>, SearchMaterializationError> {
    let bytes = store
        .get(&expected)
        .map_err(SearchMaterializationError::Store)?;
    if ContentHash::from_bytes(&bytes) == expected {
        Ok(bytes)
    } else {
        Err(SearchMaterializationError::ContentMismatch)
    }
}

fn trace_mutation_material(
    program: ContentHash,
    binding: &FaultObjectId,
    artifact: ContentHash,
    mutation: &TraceWindowMaterialization,
) -> Result<String, SearchMaterializationError> {
    let mut material = format!(
        "program={};binding={};artifact={};node={};samples=",
        program.to_hex(),
        binding.as_str(),
        artifact.to_hex(),
        mutation.trace_node.as_str(),
    );
    for sample in &mutation.samples {
        material.push_str(&format!(
            "{}:{:?}:{};",
            sample.coordinate,
            sample.event_sequence,
            hex_bytes(
                &super::trace::encode_signal_value(&sample.value)
                    .map_err(SearchMaterializationError::Trace)?
            ),
        ));
    }
    Ok(material)
}

fn mapping_mutation_material(
    program: ContentHash,
    binding: &FaultObjectId,
    mutation: &MappingMaterialization,
) -> Result<String, SearchMaterializationError> {
    let mut material = format!(
        "program={};binding={};points=",
        program.to_hex(),
        binding.as_str(),
    );
    for replacement in &mutation.points {
        material.push_str(&format!(
            "{}:{}:{};",
            replacement.index,
            hex_bytes(
                &super::trace::encode_signal_value(&replacement.point.input)
                    .map_err(SearchMaterializationError::Trace)?
            ),
            hex_bytes(
                &super::trace::encode_signal_value(&replacement.point.output)
                    .map_err(SearchMaterializationError::Trace)?
            ),
        ));
    }
    Ok(material)
}

fn materialization_digest(
    original_program: ContentHash,
    binding: &FaultBinding,
    materialized_program: ContentHash,
    mutation_material: &str,
) -> Result<ContentHash, SearchMaterializationError> {
    let binding_contract = binding
        .contract_digest()
        .map_err(SearchMaterializationError::BindingCodec)?;
    Ok(ContentHash::from_canonical_material(
        "crucible.materialized-binding-search.v1",
        &format!(
            "signal_evaluator_version={};effect_semantic_version={};search_materializer_version=1;original_program={};materialized_program={};binding_contract={};mutation={mutation_material}",
            SIGNAL_EVALUATOR_VERSION,
            EFFECT_SEMANTIC_VERSION,
            original_program.to_hex(),
            materialized_program.to_hex(),
            binding_contract.to_hex(),
        ),
    ))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

/// Failure to turn a bounded mutation policy into ordinary fixed inputs.
#[derive(Debug)]
pub enum SearchMaterializationError {
    /// Binding uses a different search policy or mapping.
    WrongPolicy,
    /// Binding was admitted against a different original signal program.
    ProgramIdentity,
    /// Trace node is not an exact authorized input of this binding.
    UnauthorizedTraceNode,
    /// Mutation count, identity, order, or authored window is invalid.
    InvalidMutation,
    /// Named signal node is absent or is not a normalized trace source.
    UnknownTraceNode,
    /// Trace manifest omits the source node's selected channel.
    UnknownTraceChannel,
    /// Replacement value contradicts the selected channel shape.
    MutationType,
    /// Mutation coordinate does not identify an existing source sample.
    MissingSample,
    /// Loaded manifest referenced no corresponding decoded chunk.
    MissingChunk,
    /// Store returned an identity other than the canonical object digest.
    ContentMismatch,
    /// Signal program or identifier validation failed.
    Program(SignalProgramError),
    /// Virtual-time projection of a stored trace coordinate failed.
    Evaluation(SignalEvaluationError),
    /// Closed fault identifier validation failed.
    Contract(FaultContractError),
    /// Concrete fixed binding failed admission.
    Binding(BindingError),
    /// Canonical binding-contract encoding failed.
    BindingCodec(serde_json::Error),
    /// Canonical trace codec validation failed.
    Trace(TraceError),
    /// Trace dependency loading failed.
    TraceStore(TraceArtifactStoreError),
    /// Content-addressed persistence failed.
    Store(DagStoreError),
}

impl fmt::Display for SearchMaterializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fault search materialization failed: {self:?}")
    }
}

impl Error for SearchMaterializationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Program(error) => Some(error),
            Self::Evaluation(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::Binding(error) => Some(error),
            Self::BindingCodec(error) => Some(error),
            Self::Trace(error) => Some(error),
            Self::TraceStore(error) => Some(error),
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "search_materialization_test.rs"]
mod tests;
