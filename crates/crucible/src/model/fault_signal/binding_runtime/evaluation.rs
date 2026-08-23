//! Focused binding runtime implementation responsibilities.

use super::*;

impl<'a> FaultBindingRuntime<'a> {
    // crucible-lint: allow rust-allow -- one atomic evaluation carries coordinate, opportunity, sink, replay, recording, and verification state.
    #[allow(
        clippy::too_many_arguments,
        reason = "one atomic binding evaluation carries coordinate, opportunity, sink, replay, recording, and verification state"
    )]
    pub(super) fn evaluate_matching(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        opportunity: Option<&FaultOpportunity>,
        sink: &mut dyn FaultActionSink,
        mut replay: Option<&mut ResolvedEffectTrace>,
        mut recorded: Option<&mut Vec<ResolvedReplayWorkItem>>,
        verify_replay_outcomes: bool,
    ) -> Result<BindingEvaluation, BindingRuntimeError> {
        self.ensure_usable()?;
        let cursor = FaultSchedulerCursor {
            virtual_nanos: coordinate.virtual_nanos,
            same_coordinate_sequence,
        };
        self.ensure_monotone(cursor)?;
        if opportunity.is_some()
            && !self.boundary_completed_cursor.is_some_and(|boundary| {
                boundary.virtual_nanos < cursor.virtual_nanos || boundary <= cursor
            })
        {
            return Err(BindingRuntimeError::OpportunityBeforeBoundary);
        }
        if opportunity.is_some()
            && !self.bindings.iter().any(|binding| {
                matches!(
                    binding.sampling(),
                    BindingSampling::AtOpportunity
                        | BindingSampling::AtEvent(
                            BindingEventParent::OpportunityOperation
                                | BindingEventParent::OpportunityState
                        )
                )
            })
        {
            return Ok(BindingEvaluation::default());
        }
        if opportunity.is_none() && self.boundary_completed_cursor == Some(cursor) {
            return Ok(BindingEvaluation {
                next_wakeup_nanos: self.next_wakeup_after(coordinate.virtual_nanos)?,
                ..BindingEvaluation::default()
            });
        }
        let evaluator_checkpoint = self
            .evaluator
            .checkpoint()
            .map_err(BindingRuntimeError::Evaluation)?;
        let states = self.states.clone();
        let active = self.active.clone();
        let consumed_opportunities = self.consumed_opportunities.clone();
        let consumed_search_overrides = self.consumed_search_overrides.clone();
        let replay_before = replay.as_deref().cloned();
        let recorded_before = recorded.as_deref().map_or(0, Vec::len);
        let authoritative_replay = replay
            .as_deref()
            .is_some_and(|trace| !matches!(trace.mode, FaultReplayMode::RecomputedCause));
        let mut model_evaluation = if authoritative_replay {
            Ok(BindingEvaluation::default())
        } else {
            self.evaluate_matching_inner(coordinate, same_coordinate_sequence, opportunity)
        };
        if let Ok(evaluation) = &mut model_evaluation
            && !authoritative_replay
        {
            evaluation.state_machine_events = self.evaluator.take_emitted_events();
        }
        let outcome = match model_evaluation {
            Ok(mut evaluation) => (|| {
                let derivation_fingerprint = self.derivation_fingerprint(&evaluation)?;
                if let Some(trace) = replay.as_deref() {
                    evaluation.actions = self.resolve_replay_actions(
                        &evaluation.actions,
                        &states,
                        &active,
                        coordinate,
                        same_coordinate_sequence,
                        opportunity,
                        derivation_fingerprint,
                        trace,
                    )?;
                }
                let recording_derivation_fingerprint = match replay.as_deref() {
                    Some(trace) if authoritative_replay => trace
                        .work_item_for_context(coordinate, same_coordinate_sequence, opportunity)
                        .map_err(BindingRuntimeError::Runtime)?
                        .map_or(derivation_fingerprint, |item| item.derivation_fingerprint),
                    _ => derivation_fingerprint,
                };
                let recorded_effects_before = recorded
                    .as_deref()
                    .map(|work_items| recorded_effect_count(work_items))
                    .transpose()?
                    .unwrap_or(0);
                if let Some(work_items) = recorded.as_deref() {
                    reserve_usize_runtime(
                        self.resource_limits,
                        "thin_replay_events",
                        work_items.len(),
                        1,
                    )?;
                    reserve_usize_runtime(
                        self.resource_limits,
                        "resolved_effect_records",
                        recorded_effects_before,
                        evaluation.actions.len(),
                    )?;
                }
                let replay_verification = if verify_replay_outcomes {
                    replay
                        .as_deref()
                        .map(|trace| {
                            verify_replay_action_shapes(
                                trace,
                                &evaluation.actions,
                                coordinate,
                                same_coordinate_sequence,
                                opportunity,
                            )
                        })
                        .transpose()?
                } else {
                    None
                };
                let staged_work_item = if recorded.is_some() {
                    Some(stage_resolved_replay_work_item(
                        &evaluation.actions,
                        coordinate,
                        opportunity,
                        same_coordinate_sequence,
                        recording_derivation_fingerprint,
                        self.resource_limits,
                        recorded_effects_before,
                    )?)
                } else {
                    None
                };
                if let Some(work_items) = recorded.as_deref_mut() {
                    try_reserve_runtime(work_items, self.resource_limits, "thin_replay_events", 1)?;
                }
                try_reserve_runtime(
                    &mut evaluation.observations,
                    self.resource_limits,
                    "event_records",
                    evaluation.actions.len(),
                )?;
                // A preview runs only against the deterministic in-memory
                // adapter ledger, which cannot sample QEMU's live icount. It
                // may therefore retain a node action's virtual-time-only
                // coordinate. Every committing path requires the backend
                // refinement before recording or replay verification.
                let transaction = prepare_actions(sink, &evaluation.actions)?;
                let results = commit_prepared_actions(
                    sink,
                    &evaluation.actions,
                    transaction,
                    !verify_replay_outcomes,
                )?;
                if let (Some(trace), Some(verification)) =
                    (replay.as_deref_mut(), replay_verification)
                {
                    verify_replay_results(trace, &evaluation.actions, &results, verification)?;
                }
                if let (Some(work_items), Some(staged)) =
                    (recorded.as_deref_mut(), staged_work_item)
                {
                    work_items.push(finalize_resolved_replay_work_item(
                        staged,
                        &evaluation.actions,
                        &results,
                    )?);
                }
                evaluation
                    .observations
                    .extend(results.into_iter().map(|result| result.observation));
                Ok(evaluation)
            })(),
            Err(error) => Err(error),
        };
        match outcome {
            Ok(evaluation) => {
                self.scheduler_cursor = Some(cursor);
                if opportunity.is_none() {
                    self.boundary_completed_cursor = Some(cursor);
                }
                Ok(evaluation)
            }
            Err(error) => {
                if matches!(
                    error,
                    BindingRuntimeError::AdapterAbort(_) | BindingRuntimeError::AdapterCommit(_)
                ) {
                    self.poisoned = true;
                    return Err(error);
                }
                self.states = states;
                self.active = active;
                self.consumed_opportunities = consumed_opportunities;
                self.consumed_search_overrides = consumed_search_overrides;
                if let (Some(trace), Some(before)) = (replay, replay_before.as_ref()) {
                    *trace = before.clone();
                }
                if let Some(records) = recorded {
                    records.truncate(recorded_before);
                }
                self.evaluator = match SignalEvaluator::restore(
                    self.program,
                    self.artifacts,
                    &evaluator_checkpoint,
                    self.resource_limits,
                ) {
                    Ok(evaluator) => evaluator,
                    Err(rollback_error) => {
                        self.poisoned = true;
                        return Err(BindingRuntimeError::Rollback(rollback_error));
                    }
                };
                Err(error)
            }
        }
    }

    pub(super) fn ensure_usable(&self) -> Result<(), BindingRuntimeError> {
        if self.poisoned {
            Err(BindingRuntimeError::Poisoned)
        } else {
            Ok(())
        }
    }

    pub(super) fn ensure_monotone(
        &self,
        cursor: FaultSchedulerCursor,
    ) -> Result<(), BindingRuntimeError> {
        if self
            .scheduler_cursor
            .is_some_and(|previous| previous > cursor)
        {
            Err(BindingRuntimeError::NonMonotoneBoundary)
        } else {
            Ok(())
        }
    }

    fn derivation_fingerprint(
        &self,
        evaluation: &BindingEvaluation,
    ) -> Result<ContentHash, BindingRuntimeError> {
        let checkpoint = self.checkpoint()?;
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&checkpoint, &mut encoded).map_err(|_error| {
            BindingRuntimeError::Runtime(FaultRuntimeError::CheckpointEncoding)
        })?;
        ciborium::ser::into_writer(&evaluation.state_machine_events, &mut encoded).map_err(
            |_error| BindingRuntimeError::Runtime(FaultRuntimeError::CheckpointEncoding),
        )?;
        Ok(ContentHash::from_bytes(&encoded))
    }

    fn evaluate_matching_inner(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        opportunity: Option<&FaultOpportunity>,
    ) -> Result<BindingEvaluation, BindingRuntimeError> {
        let mut evaluation = BindingEvaluation::default();
        for binding_index in 0..self.bindings.len() {
            let binding = self.bindings[binding_index].clone();
            if !binding_due(
                &binding,
                self.states
                    .get(binding.id())
                    .ok_or_else(|| BindingRuntimeError::MissingState(binding.id().clone()))?,
                coordinate.virtual_nanos,
                opportunity,
            ) || !opportunity_matches(&binding, opportunity)
            {
                continue;
            }
            let targets = self.targets_for(&binding)?;
            if let Some(opportunity) = opportunity
                && !targets.targets().contains(opportunity.target())
            {
                continue;
            }
            if let Some(opportunity) = opportunity
                && !self.admit_opportunity_delivery(&binding, opportunity)?
            {
                continue;
            }
            let Some(sampled_values) =
                self.evaluate_signals(&binding, coordinate, same_coordinate_sequence, opportunity)?
            else {
                self.handle_inactive_binding(
                    &binding,
                    targets.targets(),
                    coordinate,
                    opportunity,
                    &mut evaluation,
                )?;
                if let Some(opportunity) = opportunity {
                    self.record_opportunity_delivery(
                        &binding,
                        opportunity,
                        same_coordinate_sequence,
                    )?;
                }
                continue;
            };
            let raw_values = sampled_values;
            let value_digest = mapped_values_digest(&raw_values, self.resource_limits)?;
            let sample_identity = sample_identity_digest(
                &binding,
                &raw_values,
                value_digest,
                coordinate,
                same_coordinate_sequence,
                opportunity,
            );
            let mut values = map_parameter_values(&binding, raw_values.clone())?;
            let state = self
                .states
                .get_mut(binding.id())
                .ok_or_else(|| BindingRuntimeError::MissingState(binding.id().clone()))?;
            let prior_digest = state.mapped_parameters;
            state.last_sample_nanos = Some(coordinate.virtual_nanos);
            let sample_observed = record_sample(
                &binding,
                state,
                &raw_values,
                value_digest,
                sample_identity,
                coordinate,
                opportunity,
                false,
                &mut evaluation,
                self.resource_limits,
            )?;
            if matches!(binding.sampling(), BindingSampling::AtChange)
                && state.last_sample_identity == Some(sample_identity)
            {
                continue;
            }
            if matches!(binding.mapping(), BindingMapping::ImpulseOnEvent)
                && state.last_event_identity == Some(sample_identity)
            {
                continue;
            }
            let mut decision = map_binding(
                &binding,
                &values,
                state,
                coordinate.virtual_nanos,
                opportunity,
                self.scenario_seed,
            )?;
            let activation_value = match decision {
                MappingDecision::Persistent(active) => active,
                _ => state.active,
            };
            let search_resolution = apply_search_policy(
                self.program.id(),
                &binding,
                opportunity,
                search_decision_identity(
                    &binding,
                    value_digest,
                    coordinate,
                    same_coordinate_sequence,
                    state.transition_sequence,
                ),
                &mut values,
                &mut decision,
                state,
                &self.search_overrides,
                &mut self.consumed_search_overrides,
                coordinate,
                &mut evaluation,
                self.resource_limits,
            )?;
            let mut mapping_output = resolved_mapping_output(&binding, &values, activation_value)?;
            if let ResolvedMappingOutput::StateTransition {
                selected_transition,
                ..
            } = &mut mapping_output
                && let Some(search_transition) = search_resolution.selected_transition
            {
                *selected_transition = search_transition;
            }
            let action_values =
                if matches!(mapping_output, ResolvedMappingOutput::Activation { .. }) {
                    Vec::new()
                } else {
                    values.clone()
                };
            let digest = resolved_mapping_output_digest(&mapping_output, self.resource_limits)?;
            let action_count = evaluation.actions.len();
            self.apply_decision(
                &binding,
                targets.targets(),
                digest,
                coordinate,
                opportunity,
                decision,
                prior_digest,
                mapping_output.clone(),
                &mut evaluation,
            )?;
            if !sample_observed && evaluation.actions.len() != action_count {
                let state = self
                    .states
                    .get(binding.id())
                    .ok_or_else(|| BindingRuntimeError::MissingState(binding.id().clone()))?;
                push_sample_observation(
                    &binding,
                    &raw_values,
                    value_digest,
                    state.last_sample_identity != Some(sample_identity),
                    coordinate,
                    opportunity,
                    &mut evaluation,
                    self.resource_limits,
                )?;
            }
            if matches!(binding.mapping(), BindingMapping::Hazard)
                && matches!(binding.search(), BindingSearchPolicy::Fixed)
            {
                evaluation.observations.push(FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: FaultObservationKind::EffectChoice,
                    coordinate,
                    binding: Some(binding.id().clone()),
                    target: opportunity.map(|value| value.target().clone()),
                    opportunity: opportunity.map(FaultOpportunity::id),
                    evidence: digest,
                });
            }
            self.states
                .get_mut(binding.id())
                .ok_or_else(|| BindingRuntimeError::MissingState(binding.id().clone()))?
                .mapped_parameters = Some(digest);
            let state = self
                .states
                .get_mut(binding.id())
                .ok_or_else(|| BindingRuntimeError::MissingState(binding.id().clone()))?;
            state.last_sample_identity = Some(sample_identity);
            state.mapped_values = action_values;
            state.mapping_output = Some(mapping_output);
            if matches!(binding.mapping(), BindingMapping::ImpulseOnEvent) {
                state.last_event_identity = Some(sample_identity);
            }
            if let Some(opportunity) = opportunity {
                self.record_opportunity_delivery(&binding, opportunity, same_coordinate_sequence)?;
            }
        }
        if opportunity.is_none() {
            for signal in self.referenced_event_signals()? {
                let consumer = FaultObjectId::parse(signal.as_str())
                    .map_err(FaultRuntimeError::Contract)
                    .map_err(BindingRuntimeError::Runtime)?;
                let result = self
                    .evaluator
                    .evaluate(&SignalEvaluationRequest {
                        output: signal.clone(),
                        coordinate: SignalCoordinate::Event {
                            parent: Box::new(SignalCoordinate::VirtualTime {
                                nanos: coordinate.virtual_nanos,
                            }),
                            sequence: same_coordinate_sequence,
                        },
                        same_coordinate_sequence,
                        choice: SignalChoiceContext {
                            scenario_seed: self.scenario_seed,
                            consumer,
                            opportunity: None,
                            transition_sequence: None,
                        },
                    })
                    .map_err(BindingRuntimeError::Evaluation)?;
                if let EvaluatedSignal::Value(value @ SignalValue::Event { .. }) = result {
                    let evidence = ContentHash::from_bytes(
                        &encode_signal_value(&value).map_err(BindingRuntimeError::Trace)?,
                    );
                    evaluation.emitted_events.push(ReferencedSignalEvent {
                        signal,
                        coordinate,
                        same_coordinate_sequence,
                        value,
                        evidence,
                    });
                }
            }
        }
        evaluation.actions.sort_by(|left, right| {
            (&left.binding, &left.target, left.phase, left.kind).cmp(&(
                &right.binding,
                &right.target,
                right.phase,
                right.kind,
            ))
        });
        if opportunity.is_none() {
            evaluation.next_wakeup_nanos = self.next_wakeup_after(coordinate.virtual_nanos)?;
        }
        Ok(evaluation)
    }
}
