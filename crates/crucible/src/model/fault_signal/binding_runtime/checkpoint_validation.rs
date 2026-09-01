//! Focused deterministic binding runtime helpers.

use super::*;
pub(super) fn validate_binding_checkpoint(
    program: &SignalProgram,
    bindings: &[FaultBinding],
    scenario_seed: ContentHash,
    resource_limits: FaultResourceLimits,
    checkpoint: &BindingRuntimeCheckpoint,
) -> Result<(), BindingRuntimeError> {
    resource_limits
        .validate()
        .map_err(BindingRuntimeError::ResourceLimit)?;
    reserve_usize_runtime(resource_limits, "bindings", 0, bindings.len())?;
    if checkpoint.semantic_version != FAULT_RUNTIME_STATE_VERSION
        || checkpoint.signal_program != program.id()
        || checkpoint.scenario_seed != scenario_seed
        || checkpoint.resource_limits != resource_limits
        || bindings.windows(2).any(|pair| pair[0].id() == pair[1].id())
        || bindings
            .iter()
            .any(|binding| binding.program() != program.id())
        || checkpoint.binding_contracts != bindings
        || bindings.iter().any(|binding| {
            matches!(
                binding.search(),
                BindingSearchPolicy::MutateTraceWindow { .. }
                    | BindingSearchPolicy::MutateMapping { .. }
            )
        })
    {
        return Err(BindingRuntimeError::CheckpointIdentity);
    }
    checkpoint
        .evaluator
        .validate_for_program(program, resource_limits)
        .map_err(|_| BindingRuntimeError::CheckpointState)?;
    if checkpoint.boundary_completed_cursor > checkpoint.scheduler_cursor
        || checkpoint.boundary_completed_cursor.is_some() && checkpoint.scheduler_cursor.is_none()
    {
        return Err(BindingRuntimeError::CheckpointState);
    }
    let binding_ids = bindings
        .iter()
        .map(FaultBinding::id)
        .collect::<std::collections::BTreeSet<_>>();
    if checkpoint
        .bindings
        .keys()
        .collect::<std::collections::BTreeSet<_>>()
        != binding_ids
    {
        return Err(BindingRuntimeError::CheckpointState);
    }
    let dynamic_ids = bindings
        .iter()
        .filter(|binding| matches!(binding.selector(), TargetSelector::DynamicPath { .. }))
        .map(FaultBinding::id)
        .collect::<std::collections::BTreeSet<_>>();
    reserve_usize_runtime(
        resource_limits,
        "resolved_effect_records",
        0,
        checkpoint.consumed_opportunities.len(),
    )?;
    reserve_usize_runtime(
        resource_limits,
        "search_choices_per_state",
        0,
        checkpoint.search_overrides.len(),
    )?;
    if checkpoint
        .dynamic_membership
        .keys()
        .collect::<std::collections::BTreeSet<_>>()
        != dynamic_ids
        || !checkpoint.consumed_search_overrides.is_subset(
            &checkpoint
                .search_overrides
                .keys()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
        )
    {
        return Err(BindingRuntimeError::CheckpointState);
    }
    for binding in bindings {
        let state = checkpoint
            .bindings
            .get(binding.id())
            .ok_or(BindingRuntimeError::CheckpointState)?;
        if state.pending_activation.is_some() != state.pending_since_nanos.is_some() {
            return Err(BindingRuntimeError::CheckpointState);
        }
        if state.last_sample_nanos.is_some() != state.last_sample_identity.is_some()
            || state.last_sample_nanos.is_some_and(|nanos| {
                checkpoint
                    .scheduler_cursor
                    .is_none_or(|cursor| nanos > cursor.virtual_nanos)
            })
            || state.pending_since_nanos.is_some_and(|nanos| {
                checkpoint
                    .scheduler_cursor
                    .is_none_or(|cursor| nanos > cursor.virtual_nanos)
            })
            || checkpoint.scheduler_cursor.is_none()
                && (state.sample_count != 0
                    || state.active
                    || state.transition_sequence != 0
                    || state.search_choice_count != 0)
        {
            return Err(BindingRuntimeError::CheckpointState);
        }
        resource_limits
            .reserve("search_choices_per_state", 0, state.search_choice_count)
            .map_err(BindingRuntimeError::ResourceLimit)?;
        if let BindingSearchPolicy::BranchOutcome { maximum_branches } = binding.search()
            && state.search_choice_count > maximum_branches.get()
        {
            return Err(BindingRuntimeError::CheckpointState);
        }
        validate_checkpoint_mapping_values(program, binding, state)?;
        match (&state.mapped_parameters, &state.mapping_output) {
            (Some(digest), Some(output))
                if mapping_output_matches(
                    &resolved_mapping_output(binding, &state.mapped_values, state.active)?,
                    output,
                    binding.search(),
                ) && resolved_mapping_output_digest(output, resource_limits)? == *digest => {}
            (None, None) if state.mapped_values.is_empty() => {}
            _ => return Err(BindingRuntimeError::CheckpointState),
        }
        if let Some(membership) = checkpoint.dynamic_membership.get(binding.id())
            && (membership.targets.allow_empty() != binding.selector().resolved().allow_empty()
                || membership.targets.targets().is_empty()
                    && !binding.selector().resolved().allow_empty()
                || membership.targets.targets().iter().any(|target| {
                    !binding
                        .effect()
                        .kind()
                        .descriptor()
                        .targets
                        .contains(&target.kind())
                })
                || !matches!(
                    binding.selector(),
                    TargetSelector::DynamicPath {
                        path,
                        membership_semantic_version,
                        ..
                    } if *path == membership.path
                        && *membership_semantic_version == membership.semantic_version
                )
                || membership.evidence == ContentHash::default())
        {
            return Err(BindingRuntimeError::CheckpointState);
        }
        if let Some(membership) = checkpoint.dynamic_membership.get(binding.id()) {
            reserve_usize_runtime(
                resource_limits,
                "resolved_targets_per_binding",
                0,
                membership.targets.targets().len(),
            )?;
        }
    }
    let binding_by_id = bindings
        .iter()
        .map(|binding| (binding.id(), binding))
        .collect::<BTreeMap<_, _>>();
    for (key, consumed) in &checkpoint.consumed_opportunities {
        let binding = binding_by_id
            .get(&key.binding)
            .ok_or(BindingRuntimeError::CheckpointState)?;
        if !matches!(
            binding.sampling(),
            BindingSampling::AtOpportunity
                | BindingSampling::AtEvent(BindingEventParent::OpportunityOperation)
                | BindingSampling::AtEvent(BindingEventParent::OpportunityState)
        ) || !binding
            .effect()
            .kind()
            .descriptor()
            .phases
            .contains(&key.phase)
            || !binding
                .opportunity_filter()
                .is_some_and(|filter| filter.operations.contains(key.operation))
            || !binding
                .effect()
                .kind()
                .descriptor()
                .targets
                .contains(&key.target.kind())
            || consumed.identity == ContentHash::default()
            || checkpoint.scheduler_cursor.is_none_or(|cursor| {
                FaultSchedulerCursor {
                    virtual_nanos: consumed.coordinate.virtual_nanos,
                    same_coordinate_sequence: consumed.same_coordinate_sequence,
                } > cursor
            })
        {
            return Err(BindingRuntimeError::CheckpointState);
        }
    }
    let mut expected_active = std::collections::BTreeSet::new();
    for binding in bindings {
        let state = &checkpoint.bindings[binding.id()];
        if !state.active {
            continue;
        }
        if binding.effect().lifetime() != EffectLifetime::Persistent {
            return Err(BindingRuntimeError::CheckpointState);
        }
        let targets = checkpoint.dynamic_membership.get(binding.id()).map_or_else(
            || binding.selector().resolved(),
            |membership| &membership.targets,
        );
        for target in targets.targets() {
            for phase in binding_phases(binding) {
                expected_active.insert(ActiveContributionKey {
                    target: target.clone(),
                    phase,
                    effect: binding.effect().kind(),
                    binding: binding.id().clone(),
                });
            }
        }
    }
    if checkpoint
        .active
        .entries()
        .keys()
        .collect::<std::collections::BTreeSet<_>>()
        != expected_active
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
    {
        return Err(BindingRuntimeError::CheckpointState);
    }
    for (key, contribution) in checkpoint.active.entries() {
        let binding = binding_by_id
            .get(&key.binding)
            .ok_or(BindingRuntimeError::CheckpointState)?;
        let state = &checkpoint.bindings[&key.binding];
        if contribution.request.as_ref() != binding.effect()
            || contribution.mapped_parameters != state.mapped_parameters.unwrap_or_default()
            || Some(contribution.mapping_output.as_ref()) != state.mapping_output.as_ref()
            || contribution.transition_sequence != state.transition_sequence
        {
            return Err(BindingRuntimeError::CheckpointState);
        }
    }
    let mut active_by_target = BTreeMap::<&ResolvedFaultTarget, usize>::new();
    for key in checkpoint.active.entries().keys() {
        let current = active_by_target.entry(&key.target).or_default();
        *current = current
            .checked_add(1)
            .ok_or(BindingRuntimeError::CountOverflow(
                "active_contributions_per_target",
            ))?;
    }
    for active in active_by_target.values() {
        reserve_usize_runtime(
            resource_limits,
            "active_contributions_per_target",
            0,
            *active,
        )?;
    }
    Ok(())
}

pub(super) fn validate_checkpoint_mapping_values(
    program: &SignalProgram,
    binding: &FaultBinding,
    state: &BindingRuntimeState,
) -> Result<(), BindingRuntimeError> {
    if state.unchanged_sample_count > state.sample_count
        || state.sample_count == 0 && state.last_sample_identity.is_some()
    {
        return Err(BindingRuntimeError::CheckpointState);
    }
    let valid = match (binding.mapping(), state.mapping_output.as_ref()) {
        (
            BindingMapping::ActiveWhenTrue { .. }
            | BindingMapping::ActiveWhenEqual { .. }
            | BindingMapping::Threshold { .. },
            Some(ResolvedMappingOutput::Activation { active }),
        ) => state.mapped_values.is_empty() && *active == state.active,
        (
            BindingMapping::MapParameter { parameter }
            | BindingMapping::PiecewiseParameter { parameter, .. },
            Some(ResolvedMappingOutput::Parameter {
                parameter: actual,
                value,
            }),
        ) => {
            actual == parameter
                && state.mapped_values.as_slice() == std::slice::from_ref(value)
                && parameter.accepts_value(value)
        }
        (
            BindingMapping::Hazard,
            Some(ResolvedMappingOutput::Hazard {
                probability_millionths,
            }),
        ) => {
            state.mapped_values == vec![SignalValue::ProbabilityMillionths(*probability_millionths)]
        }
        (BindingMapping::ImpulseOnEvent, Some(ResolvedMappingOutput::Impulse { event })) => {
            state.mapped_values.as_slice() == std::slice::from_ref(event)
        }
        (
            BindingMapping::StateTransition { transition_table },
            Some(ResolvedMappingOutput::StateTransition {
                transition_table: actual,
                request,
                selected_transition,
            }),
        ) => {
            actual == transition_table
                && state.mapped_values.as_slice() == std::slice::from_ref(request)
                && binding.transition_declaration().is_some_and(|declaration| {
                    declaration
                        .transitions
                        .get(request)
                        .unwrap_or(&declaration.default_transition)
                        == selected_transition
                        || matches!(
                            binding.search(),
                            BindingSearchPolicy::BranchTransition { candidates }
                                if candidates.contains(selected_transition)
                        )
                })
        }
        (
            BindingMapping::ServiceProfile { service_profile },
            Some(ResolvedMappingOutput::ServiceProfile {
                service_profile: actual,
                input_contracts,
                inputs,
            }),
        ) => {
            actual == service_profile
                && inputs == &state.mapped_values
                && binding.signals().len() == inputs.len()
                && binding
                    .service_declaration()
                    .is_some_and(|declaration| declaration.inputs == *input_contracts)
                && binding.signals().iter().zip(inputs).all(|(signal, value)| {
                    program
                        .exported_shape(signal)
                        .is_some_and(|shape| value.value_type().as_ref() == Some(&shape.value_type))
                })
        }
        (_, None) => {
            state.mapped_parameters.is_none() && state.mapped_values.is_empty() && !state.active
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(BindingRuntimeError::CheckpointState)
    }
}

pub(super) fn mapping_output_matches(
    expected: &ResolvedMappingOutput,
    actual: &ResolvedMappingOutput,
    search: &BindingSearchPolicy,
) -> bool {
    match (expected, actual) {
        (
            ResolvedMappingOutput::StateTransition {
                transition_table: expected_table,
                request: expected_request,
                selected_transition: expected_transition,
            },
            ResolvedMappingOutput::StateTransition {
                transition_table: actual_table,
                request: actual_request,
                selected_transition,
            },
        ) => {
            expected_table == actual_table
                && expected_request == actual_request
                && (selected_transition == expected_transition
                    || matches!(
                        search,
                        BindingSearchPolicy::BranchTransition { candidates }
                            if candidates.contains(selected_transition)
                    ))
        }
        _ => expected == actual,
    }
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}
