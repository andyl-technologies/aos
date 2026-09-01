//! Focused deterministic binding runtime helpers.

use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MappingDecision {
    NoAction,
    Persistent(bool),
    Apply,
}

#[derive(Default)]
pub(super) struct SearchResolution {
    pub(super) selected_transition: Option<FaultObjectId>,
}

// crucible-lint: allow rust-allow -- search policy evaluation keeps all canonical identity and mutable decision inputs explicit.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_search_policy(
    program: ContentHash,
    binding: &FaultBinding,
    opportunity: Option<&FaultOpportunity>,
    sample_identity: ContentHash,
    values: &mut Vec<SignalValue>,
    decision: &mut MappingDecision,
    state: &mut BindingRuntimeState,
    overrides: &BTreeMap<SearchChoiceId, SearchOverride>,
    consumed_overrides: &mut std::collections::BTreeSet<SearchChoiceId>,
    coordinate: FaultCoordinate,
    evaluation: &mut BindingEvaluation,
    resource_limits: FaultResourceLimits,
) -> Result<SearchResolution, BindingRuntimeError> {
    let (candidates_digest, candidate_count, mut selected_index) = match binding.search() {
        BindingSearchPolicy::Fixed
        | BindingSearchPolicy::MutateTraceWindow { .. }
        | BindingSearchPolicy::MutateMapping { .. } => return Ok(SearchResolution::default()),
        BindingSearchPolicy::BranchOutcome { maximum_branches } => {
            if state.search_choice_count >= maximum_branches.get() {
                return Ok(SearchResolution::default());
            }
            (
                ContentHash::from_canonical_material(
                    "crucible.search-candidates.v1",
                    "outcome=false;outcome=true",
                ),
                2,
                Some(u32::from(*decision == MappingDecision::Apply)),
            )
        }
        BindingSearchPolicy::BranchTransition { candidates } => (
            object_candidates_digest(candidates),
            u32::try_from(candidates.len()).map_err(|_| BindingRuntimeError::SearchChoice)?,
            None,
        ),
        BindingSearchPolicy::BranchParameter { candidates, .. } => (
            mapped_values_digest(candidates, resource_limits)?,
            u32::try_from(candidates.len()).map_err(|_| BindingRuntimeError::SearchChoice)?,
            values.first().and_then(|value| {
                candidates
                    .iter()
                    .position(|candidate| candidate == value)
                    .and_then(|index| u32::try_from(index).ok())
            }),
        ),
    };
    resource_limits
        .reserve(
            "search_candidates_per_choice",
            0,
            u64::from(candidate_count),
        )
        .map_err(BindingRuntimeError::ResourceLimit)?;
    let id = SearchChoiceId::new(
        program,
        binding.id(),
        opportunity.map(FaultOpportunity::id),
        sample_identity,
        candidates_digest,
    );
    let mut resolution = SearchResolution::default();
    let overridden = if let Some(search_override) = overrides.get(&id) {
        if consumed_overrides.contains(&id) {
            return Err(BindingRuntimeError::SearchChoice);
        }
        if search_override.candidates_digest != candidates_digest
            || search_override.candidate_index >= candidate_count
        {
            return Err(BindingRuntimeError::SearchChoice);
        }
        selected_index = Some(search_override.candidate_index);
        let index = usize::try_from(search_override.candidate_index)
            .map_err(|_| BindingRuntimeError::SearchChoice)?;
        match binding.search() {
            BindingSearchPolicy::BranchOutcome { .. } => {
                *decision = if index == 0 {
                    MappingDecision::NoAction
                } else {
                    MappingDecision::Apply
                };
            }
            BindingSearchPolicy::BranchTransition { candidates } => {
                resolution.selected_transition = candidates.get(index).cloned();
            }
            BindingSearchPolicy::BranchParameter { candidates, .. } => {
                let selected = candidates
                    .get(index)
                    .cloned()
                    .ok_or(BindingRuntimeError::SearchChoice)?;
                values.clear();
                values.push(selected);
            }
            _ => return Err(BindingRuntimeError::SearchChoice),
        }
        true
    } else {
        false
    };
    resource_limits
        .reserve("search_choices_per_state", state.search_choice_count, 1)
        .map_err(BindingRuntimeError::ResourceLimit)?;
    state.search_choice_count = state
        .search_choice_count
        .checked_add(1)
        .ok_or(BindingRuntimeError::SearchChoice)?;
    if overridden {
        consumed_overrides.insert(id);
    }
    evaluation.search_choices.push(BindingSearchChoice {
        id,
        candidates_digest,
        candidate_count,
        selected_index,
        overridden,
    });
    let choice_evidence = ContentHash::from_canonical_material(
        "crucible.binding-search-choice.v1",
        &format!(
            "id={};selected={selected_index:?};overridden={overridden}",
            id.content_hash().to_hex()
        ),
    );
    evaluation.observations.push(FaultObservation {
        semantic_version: FAULT_RUNTIME_STATE_VERSION,
        kind: FaultObservationKind::EffectChoice,
        coordinate,
        binding: Some(binding.id().clone()),
        target: opportunity.map(|value| value.target().clone()),
        opportunity: opportunity.map(FaultOpportunity::id),
        evidence: choice_evidence,
    });
    Ok(resolution)
}

pub(super) fn object_candidates_digest(candidates: &[FaultObjectId]) -> ContentHash {
    let mut material = String::new();
    for candidate in candidates {
        material.push_str(candidate.as_str());
        material.push(';');
    }
    ContentHash::from_canonical_material("crucible.search-candidates.v1", &material)
}

// crucible-lint: allow rust-allow -- sample recording authenticates values, evidence, identity, coordinate, and opportunity together.
#[allow(clippy::too_many_arguments)]
pub(super) fn record_sample(
    binding: &FaultBinding,
    state: &mut BindingRuntimeState,
    values: &[SignalValue],
    evidence: ContentHash,
    sample_identity: ContentHash,
    coordinate: FaultCoordinate,
    opportunity: Option<&FaultOpportunity>,
    force: bool,
    evaluation: &mut BindingEvaluation,
    resource_limits: FaultResourceLimits,
) -> Result<bool, BindingRuntimeError> {
    let changed = state.last_sample_identity != Some(sample_identity);
    state.sample_count = state
        .sample_count
        .checked_add(1)
        .ok_or(BindingRuntimeError::ObservationSequenceOverflow)?;
    state.unchanged_sample_count = if changed {
        0
    } else {
        state
            .unchanged_sample_count
            .checked_add(1)
            .ok_or(BindingRuntimeError::ObservationSequenceOverflow)?
    };
    let retain = force
        || match binding.observability().samples {
            SampleObservation::EverySample => true,
            SampleObservation::ChangesAndEffects => changed,
            SampleObservation::EveryNth { stride } => {
                changed || state.unchanged_sample_count.is_multiple_of(stride.get())
            }
        };
    if retain {
        push_sample_observation(
            binding,
            values,
            evidence,
            changed,
            coordinate,
            opportunity,
            evaluation,
            resource_limits,
        )?;
    }
    Ok(retain)
}

// crucible-lint: allow rust-allow -- observation emission preserves every canonical sample and opportunity field.
#[allow(clippy::too_many_arguments)]
pub(super) fn push_sample_observation(
    binding: &FaultBinding,
    values: &[SignalValue],
    evidence: ContentHash,
    changed: bool,
    coordinate: FaultCoordinate,
    opportunity: Option<&FaultOpportunity>,
    evaluation: &mut BindingEvaluation,
    resource_limits: FaultResourceLimits,
) -> Result<(), BindingRuntimeError> {
    evaluation.observations.push(FaultObservation {
        semantic_version: FAULT_RUNTIME_STATE_VERSION,
        kind: if changed {
            FaultObservationKind::SignalTransition
        } else {
            FaultObservationKind::SignalSample
        },
        coordinate,
        binding: Some(binding.id().clone()),
        target: opportunity.map(|value| value.target().clone()),
        opportunity: opportunity.map(FaultOpportunity::id),
        evidence,
    });
    if binding.observability().retain_mapped_values {
        let bytes = encoded_values_len(values)?;
        reserve_usize_runtime(resource_limits, "effect_payload_bytes", 0, bytes)?;
        evaluation.retained_samples.push(RetainedBindingSample {
            binding: binding.id().clone(),
            coordinate,
            opportunity: opportunity.map(FaultOpportunity::id),
            values: Some(values.to_vec()),
            evidence,
        });
    }
    Ok(())
}

pub(super) fn encoded_values_len(values: &[SignalValue]) -> Result<usize, BindingRuntimeError> {
    values.iter().try_fold(0_usize, |total, value| {
        let encoded = encode_signal_value(value).map_err(BindingRuntimeError::Trace)?;
        total
            .checked_add(4)
            .and_then(|length| length.checked_add(encoded.len()))
            .ok_or(BindingRuntimeError::CountOverflow("effect_payload_bytes"))
    })
}
