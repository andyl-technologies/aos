//! Resolved-action recording and authoritative replay interposition.

use super::*;

impl FaultBindingRuntime<'_> {
    // crucible-lint: allow rust-allow -- locked replay authenticates model, state, coordinate, opportunity, derivation, and trace inputs.
    #[allow(
        clippy::too_many_arguments,
        reason = "locked replay authenticates independent model, state, coordinate, opportunity, derivation, and trace inputs"
    )]
    pub(super) fn resolve_replay_actions(
        &mut self,
        generated: &[ResolvedBindingAction],
        states_before: &BTreeMap<FaultObjectId, BindingRuntimeState>,
        active_before: &ActiveContributionTable,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        opportunity: Option<&FaultOpportunity>,
        derivation_fingerprint: ContentHash,
        trace: &ResolvedEffectTrace,
    ) -> Result<Vec<ResolvedBindingAction>, BindingRuntimeError> {
        let item = trace
            .work_item_for_context(coordinate, same_coordinate_sequence, opportunity)
            .map_err(BindingRuntimeError::Runtime)?;
        let records = item.map_or_else(Vec::new, |item| item.records.clone());
        if trace.mode == FaultReplayMode::RecomputedCause {
            if item.is_none()
                || item.is_some_and(|item| item.derivation_fingerprint != derivation_fingerprint)
                || records.len() != generated.len()
                || records
                    .iter()
                    .zip(generated)
                    .any(|(record, action)| !record.matches_recomputed_action(action))
            {
                return Err(replay_mismatch(
                    trace.cursor,
                    opportunity.map(FaultOpportunity::id),
                ));
            }
            return Ok(generated.to_vec());
        }
        self.active = active_before.clone();
        for (binding, state) in &mut self.states {
            let prior = states_before
                .get(binding)
                .ok_or_else(|| BindingRuntimeError::MissingState(binding.clone()))?;
            state.active = prior.active;
            state.transition_sequence = prior.transition_sequence;
            state.pending_activation = prior.pending_activation;
            state.pending_since_nanos = prior.pending_since_nanos;
            state.mapped_parameters = prior.mapped_parameters;
            state.mapped_values.clone_from(&prior.mapped_values);
            state.mapping_output.clone_from(&prior.mapping_output);
        }
        let mut locked = Vec::with_capacity(records.len());
        for record in records {
            record
                .validate()
                .map_err(FaultRuntimeError::Contract)
                .map_err(BindingRuntimeError::Runtime)?;
            if matches!(trace.mode, FaultReplayMode::OutcomeOnlyNetwork(_))
                && (record.effect.descriptor().adapter != FaultAdapter::Network
                    || record.opportunity.is_none())
            {
                return Err(BindingRuntimeError::Runtime(
                    FaultRuntimeError::InvalidReplayTrace,
                ));
            }
            let action = match trace.mode {
                FaultReplayMode::OutcomeOnlyNetwork(_) => outcome_action(
                    &record,
                    opportunity.ok_or(BindingRuntimeError::Runtime(
                        FaultRuntimeError::InvalidReplayTrace,
                    ))?,
                ),
                FaultReplayMode::RecomputedCause | FaultReplayMode::LockedEffect => {
                    record.locked_action()
                }
            };
            let state = self
                .states
                .get_mut(&action.binding)
                .ok_or_else(|| BindingRuntimeError::MissingState(action.binding.clone()))?;
            if !matches!(action.cause, BindingActionCause::DynamicMembership { .. }) {
                state.transition_sequence = action.transition_sequence;
                state.mapped_parameters = Some(action.mapped_digest);
                state.mapped_values = mapping_output_values(&action.mapping_output);
                state.mapping_output = Some(action.mapping_output.as_ref().clone());
                match action.kind {
                    BindingActionKind::UpsertPersistent => state.active = true,
                    BindingActionKind::RemovePersistent => state.active = false,
                    BindingActionKind::Apply => {}
                }
            }
            self.update_active(&action)?;
            locked.push(action);
        }
        Ok(locked)
    }
}

fn replay_mismatch(index: usize, opportunity: Option<ContentHash>) -> BindingRuntimeError {
    BindingRuntimeError::Runtime(FaultRuntimeError::ReplayMismatch {
        index,
        expected: None,
        observed: opportunity.unwrap_or_default(),
    })
}

fn mapping_output_values(output: &ResolvedMappingOutput) -> Vec<SignalValue> {
    match output {
        ResolvedMappingOutput::Activation { .. } => Vec::new(),
        ResolvedMappingOutput::Parameter { value, .. } => vec![value.clone()],
        ResolvedMappingOutput::Hazard {
            probability_millionths,
        } => vec![SignalValue::ProbabilityMillionths(*probability_millionths)],
        ResolvedMappingOutput::Impulse { event } => vec![event.clone()],
        ResolvedMappingOutput::StateTransition { request, .. } => vec![request.clone()],
        ResolvedMappingOutput::ServiceProfile { inputs, .. } => inputs.clone(),
    }
}

pub(super) fn verify_replay_results(
    trace: &mut ResolvedEffectTrace,
    actions: &[ResolvedBindingAction],
    results: &[PreparedActionResult],
    coordinate: FaultCoordinate,
    same_coordinate_sequence: u64,
    opportunity: Option<&FaultOpportunity>,
) -> Result<(), BindingRuntimeError> {
    let item = trace
        .work_item_for_context(coordinate, same_coordinate_sequence, opportunity)
        .map_err(BindingRuntimeError::Runtime)?;
    let consumed = item.is_some();
    let records = item.map_or(&[][..], |item| item.records.as_slice());
    let matches = records.len() == actions.len()
        && actions.len() == results.len()
        && records
            .iter()
            .zip(actions)
            .zip(results)
            .all(|((record, action), result)| {
                let action_matches = match trace.mode {
                    FaultReplayMode::RecomputedCause => record.matches_recomputed_action(action),
                    FaultReplayMode::LockedEffect => record.locked_action() == *action,
                    FaultReplayMode::OutcomeOnlyNetwork(_) => opportunity
                        .is_some_and(|opportunity| outcome_action(record, opportunity) == *action),
                };
                action_matches
                    && result.precondition == record.precondition_digest
                    && result.observation.evidence == record.evidence_digest
            });
    if !matches {
        return Err(BindingRuntimeError::AdapterCommit(
            FaultRuntimeError::ReplayMismatch {
                index: trace.cursor,
                expected: records.first().and_then(|record| record.opportunity),
                observed: opportunity.map(FaultOpportunity::id).unwrap_or_default(),
            },
        ));
    }
    if consumed {
        trace
            .advance()
            .map_err(BindingRuntimeError::AdapterCommit)?;
    }
    Ok(())
}

fn outcome_action(
    record: &ResolvedEffectRecord,
    opportunity: &FaultOpportunity,
) -> ResolvedBindingAction {
    ResolvedBindingAction {
        target: opportunity.target().clone(),
        phase: opportunity.phase(),
        opportunity: Some(opportunity.id()),
        coordinate: opportunity.coordinate(),
        cause: BindingActionCause::Opportunity {
            identity: opportunity.id(),
            payload: opportunity.payload().clone(),
        },
        ..record.locked_action()
    }
}

pub(super) fn resolved_replay_work_item(
    actions: &[ResolvedBindingAction],
    results: &[PreparedActionResult],
    coordinate: FaultCoordinate,
    opportunity: Option<&FaultOpportunity>,
    same_coordinate_sequence: u64,
    derivation_fingerprint: ContentHash,
) -> Result<ResolvedReplayWorkItem, BindingRuntimeError> {
    let mut records = Vec::with_capacity(actions.len());
    for (action, result) in actions.iter().zip(results) {
        let record = ResolvedEffectRecord::from_committed_action(
            action,
            opportunity,
            same_coordinate_sequence,
            derivation_fingerprint,
            result.precondition,
            result.observation.evidence,
        )
        .map_err(FaultRuntimeError::Contract)
        .map_err(BindingRuntimeError::AdapterCommit)?;
        records.push(record);
    }
    ResolvedReplayWorkItem::new(
        coordinate,
        same_coordinate_sequence,
        opportunity,
        derivation_fingerprint,
        records,
    )
    .map_err(BindingRuntimeError::AdapterCommit)
}
