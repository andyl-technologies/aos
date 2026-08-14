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

mod types;

pub use types::*;

/// Enumerates the bounded Cartesian product of all mutation-enabled bindings.
///
/// Each returned plan contains only ordinary fixed-policy bindings at former
/// mutation sites. Candidate order is canonical and the total number of plans
/// may not exceed `search_choices_per_state` from the scenario resource
/// contract.
///
/// # Errors
///
/// Returns [`SearchMaterializationError`] when any authored candidate cannot be
/// materialized, a reconstructed plan fails admission, or the Cartesian product
/// exceeds the configured bound.
pub fn materialize_search_plans(
    plan: &FaultSignalPlan,
    store: &dyn DagStore,
) -> Result<Vec<MaterializedSearchPlan>, SearchMaterializationError> {
    if plan.bindings().iter().all(|binding| {
        !matches!(
            binding.search(),
            BindingSearchPolicy::MutateTraceWindow { .. }
                | BindingSearchPolicy::MutateMapping { .. }
        )
    }) {
        return Ok(Vec::new());
    }
    let mut frontier = vec![(plan.clone(), Vec::<MaterializedSearchCase>::new())];
    let mut complete = Vec::new();
    while let Some((current, applied)) = frontier.pop() {
        let Some(binding) = current.bindings().iter().find(|binding| {
            matches!(
                binding.search(),
                BindingSearchPolicy::MutateTraceWindow { .. }
                    | BindingSearchPolicy::MutateMapping { .. }
            )
        }) else {
            let mut seen_artifacts = BTreeSet::new();
            let artifacts = applied
                .iter()
                .flat_map(|case| case.artifacts.iter().copied())
                .filter(|artifact| seen_artifacts.insert(*artifact))
                .collect::<Vec<_>>();
            let material = applied
                .iter()
                .map(|case| case.provenance.to_hex())
                .collect::<Vec<_>>()
                .join(";");
            complete.push(MaterializedSearchPlan {
                provenance: ContentHash::from_canonical_material(
                    "crucible.materialized-fault-search-plan.v1",
                    &format!("plan={};cases={material}", current.id().to_hex()),
                ),
                plan: current,
                cases: applied,
                artifacts,
            });
            continue;
        };
        let program = current
            .programs()
            .iter()
            .find(|program| program.id() == binding.program())
            .ok_or(SearchMaterializationError::ProgramIdentity)?;
        let candidates = match binding.search() {
            BindingSearchPolicy::MutateTraceWindow { candidates, .. } => candidates
                .iter()
                .cloned()
                .map(MaterializedSearchMutation::TraceWindow)
                .collect::<Vec<_>>(),
            BindingSearchPolicy::MutateMapping { candidates, .. } => candidates
                .iter()
                .cloned()
                .map(MaterializedSearchMutation::Mapping)
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        for candidate in candidates.into_iter().rev() {
            let case = match candidate {
                MaterializedSearchMutation::TraceWindow(candidate) => {
                    materialize_trace_window(program, binding, store, candidate)?
                }
                MaterializedSearchMutation::Mapping(candidate) => {
                    materialize_mapping(program, binding, candidate)?
                }
            };
            let next = apply_materialized_search_case(&current, &case)?;
            let mut next_applied = applied.clone();
            next_applied.push(case);
            frontier.push((next, next_applied));
            if frontier.len().saturating_add(complete.len())
                > usize::try_from(plan.resource_limits().search_choices_per_state)
                    .unwrap_or(usize::MAX)
            {
                return Err(SearchMaterializationError::CandidateProductLimit);
            }
        }
    }
    complete.sort_by_key(|materialized| materialized.provenance);
    Ok(complete)
}

/// Enumerates every authored finite mutation as an ordinary executable case.
///
/// Candidates are returned in canonical binding and candidate order. The
/// materializer never synthesizes a value: every replacement and trace sample
/// coordinate comes from the admitted scenario contract.
///
/// # Errors
///
/// Returns [`SearchMaterializationError`] when a candidate can no longer be
/// materialized from its admitted program, binding, or artifact closure.
pub fn materialize_search_candidates(
    plan: &FaultSignalPlan,
    store: &dyn DagStore,
) -> Result<Vec<MaterializedSearchCase>, SearchMaterializationError> {
    let programs = plan
        .programs()
        .iter()
        .map(|program| (program.id(), program))
        .collect::<BTreeMap<_, _>>();
    let mut cases = Vec::new();
    for binding in plan.bindings() {
        let program = programs
            .get(&binding.program())
            .copied()
            .ok_or(SearchMaterializationError::ProgramIdentity)?;
        match binding.search() {
            BindingSearchPolicy::MutateTraceWindow { candidates, .. } => {
                for candidate in candidates {
                    cases.push(materialize_trace_window(
                        program,
                        binding,
                        store,
                        candidate.clone(),
                    )?);
                }
            }
            BindingSearchPolicy::MutateMapping { candidates, .. } => {
                for candidate in candidates {
                    cases.push(materialize_mapping(program, binding, candidate.clone())?);
                }
            }
            BindingSearchPolicy::Fixed
            | BindingSearchPolicy::BranchOutcome { .. }
            | BindingSearchPolicy::BranchTransition { .. }
            | BindingSearchPolicy::BranchParameter { .. } => {}
        }
    }
    Ok(cases)
}

/// Replaces one mutation binding and its program in the complete fault plan.
///
/// # Errors
///
/// Returns [`SearchMaterializationError`] if the original plan no longer
/// contains the candidate's exact program and binding or if final admission
/// rejects the reconstructed fixed-policy plan.
pub fn apply_materialized_search_case(
    plan: &FaultSignalPlan,
    case: &MaterializedSearchCase,
) -> Result<FaultSignalPlan, SearchMaterializationError> {
    let mut replaced_program = false;
    let programs = plan
        .programs()
        .iter()
        .map(|program| {
            if program.id() == case.original_program {
                replaced_program = true;
                case.program.clone()
            } else {
                program.clone()
            }
        })
        .collect::<Vec<_>>();
    let mut replaced_binding = false;
    let bindings = plan
        .bindings()
        .iter()
        .map(
            |binding| -> Result<FaultBinding, SearchMaterializationError> {
                if binding.id() == &case.binding_id && binding.program() == case.original_program {
                    replaced_binding = true;
                    Ok(case.binding.clone())
                } else if binding.program() == case.original_program {
                    binding
                        .rebind_program(&case.program, binding.search().clone())
                        .map_err(SearchMaterializationError::Binding)
                } else {
                    Ok(binding.clone())
                }
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    if !replaced_program || !replaced_binding {
        return Err(SearchMaterializationError::ProgramIdentity);
    }
    FaultSignalPlan::new(programs, bindings, plan.resource_limits())
        .map_err(SearchMaterializationError::Plan)
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
        candidates,
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
    if !binding.signals().contains(&mutation.trace_node) {
        return Err(SearchMaterializationError::UnauthorizedTraceNode);
    }
    if candidates.binary_search(&mutation).is_err()
        || mutation.samples.is_empty()
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
        candidates,
        maximum_mutations,
    } = binding.search()
    else {
        return Err(SearchMaterializationError::WrongPolicy);
    };
    mutation.points.sort_by_key(|point| point.index);
    if candidates.binary_search(&mutation).is_err()
        || mutation.points.is_empty()
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

mod support;

pub use support::SearchMaterializationError;
use support::*;

#[cfg(test)]
#[path = "search_materialization_test.rs"]
mod tests;
#[cfg(test)]
#[path = "search_materialization_trace_test.rs"]
mod trace_tests;
