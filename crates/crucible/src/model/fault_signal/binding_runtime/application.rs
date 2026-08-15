//! Focused binding runtime implementation responsibilities.

use super::*;

impl<'a> FaultBindingRuntime<'a> {
    pub(super) fn referenced_event_signals(
        &self,
    ) -> Result<BTreeSet<SignalId>, BindingRuntimeError> {
        self.bindings
            .iter()
            .try_fold(BTreeSet::new(), |mut signals, binding| {
                let reference = match binding.effect().specification() {
                    EffectSpecification::Storage(StorageEffectSpecification::StallTimeout {
                        recovery_event,
                        ..
                    })
                    | EffectSpecification::Storage(
                        StorageEffectSpecification::FlushDisposition { recovery_event, .. },
                    ) => recovery_event.as_ref(),
                    _ => None,
                };
                if let Some(reference) = reference {
                    signals.insert(
                        SignalId::parse(reference.as_str())
                            .map_err(BindingRuntimeError::Program)?,
                    );
                }
                Ok(signals)
            })
    }

    pub(super) fn admit_opportunity_delivery(
        &self,
        binding: &FaultBinding,
        opportunity: &FaultOpportunity,
    ) -> Result<bool, BindingRuntimeError> {
        let key = ConsumedOpportunityKey {
            binding: binding.id().clone(),
            target: opportunity.target().clone(),
            phase: opportunity.phase(),
            operation: opportunity.operation(),
        };
        match self.consumed_opportunities.get(&key) {
            Some(state) if state.sequence > opportunity.sequence() => {
                Err(BindingRuntimeError::NonMonotoneOpportunity)
            }
            Some(state) if state.sequence == opportunity.sequence() => {
                if state.identity == opportunity.id() {
                    Ok(false)
                } else {
                    Err(BindingRuntimeError::OpportunitySequenceCollision)
                }
            }
            _ => Ok(true),
        }
    }

    pub(super) fn record_opportunity_delivery(
        &mut self,
        binding: &FaultBinding,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
    ) -> Result<(), BindingRuntimeError> {
        let key = ConsumedOpportunityKey {
            binding: binding.id().clone(),
            target: opportunity.target().clone(),
            phase: opportunity.phase(),
            operation: opportunity.operation(),
        };
        if !self.consumed_opportunities.contains_key(&key) {
            reserve_usize_runtime(
                self.resource_limits,
                "resolved_effect_records",
                self.consumed_opportunities.len(),
                1,
            )?;
        }
        self.consumed_opportunities.insert(
            key,
            ConsumedOpportunityState {
                sequence: opportunity.sequence(),
                identity: opportunity.id(),
                coordinate: opportunity.coordinate(),
                same_coordinate_sequence,
            },
        );
        Ok(())
    }

    pub(super) fn targets_for(
        &self,
        binding: &FaultBinding,
    ) -> Result<ResolvedTargetSet, BindingRuntimeError> {
        match binding.selector() {
            TargetSelector::DynamicPath { .. } => self
                .dynamic_membership
                .get(binding.id())
                .map(|membership| membership.targets.clone())
                .ok_or_else(|| BindingRuntimeError::NotDynamic(binding.id().clone())),
            selector => Ok(selector.resolved().clone()),
        }
    }

    pub(super) fn evaluate_signals(
        &mut self,
        binding: &FaultBinding,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        opportunity: Option<&FaultOpportunity>,
    ) -> Result<Option<Vec<SignalValue>>, BindingRuntimeError> {
        let transition_sequence = self
            .states
            .get(binding.id())
            .ok_or_else(|| BindingRuntimeError::MissingState(binding.id().clone()))?
            .transition_sequence;
        let mut values = Vec::with_capacity(binding.signals().len());
        for signal in binding.signals() {
            let node = self
                .program
                .exported_node(signal)
                .ok_or_else(|| BindingRuntimeError::MissingSignal(signal.clone()))?;
            let signal_coordinate = binding_coordinate(
                node.domain,
                coordinate,
                opportunity,
                binding.sampling(),
                same_coordinate_sequence,
            )?;
            let result = self
                .evaluator
                .evaluate(&SignalEvaluationRequest {
                    output: signal.clone(),
                    coordinate: signal_coordinate,
                    same_coordinate_sequence,
                    choice: SignalChoiceContext {
                        scenario_seed: self.scenario_seed,
                        consumer: binding.id().clone(),
                        opportunity: opportunity.cloned(),
                        transition_sequence: Some(transition_sequence),
                    },
                })
                .map_err(BindingRuntimeError::Evaluation)?;
            match result {
                EvaluatedSignal::Value(value) => values.push(value),
                EvaluatedSignal::Inactive => return Ok(None),
            }
        }
        Ok(Some(values))
    }

    pub(super) fn handle_inactive_binding(
        &mut self,
        binding: &FaultBinding,
        targets: &[ResolvedFaultTarget],
        coordinate: FaultCoordinate,
        opportunity: Option<&FaultOpportunity>,
        evaluation: &mut BindingEvaluation,
    ) -> Result<(), BindingRuntimeError> {
        let state = self
            .states
            .get_mut(binding.id())
            .ok_or_else(|| BindingRuntimeError::MissingState(binding.id().clone()))?;
        state.last_sample_nanos = Some(coordinate.virtual_nanos);
        let inactive_identity = ContentHash::from_canonical_material(
            "crucible.binding-inactive-sample.v1",
            &format!(
                "binding={};virtual_nanos={};retired_instructions={:?};opportunity={}",
                binding.id().as_str(),
                coordinate.virtual_nanos,
                coordinate.retired_instructions,
                opportunity
                    .map(FaultOpportunity::id)
                    .map_or_else(|| String::from("none"), |value| value.to_hex()),
            ),
        );
        let changed = state.last_sample_identity != Some(inactive_identity);
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
        let retain =
            if opportunity.is_some() && !binding.observability().record_inactive_opportunities {
                false
            } else {
                match binding.observability().samples {
                    SampleObservation::EverySample => true,
                    SampleObservation::ChangesAndEffects => changed,
                    SampleObservation::EveryNth { stride } => {
                        changed || state.unchanged_sample_count.is_multiple_of(stride.get())
                    }
                }
            };
        if retain {
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
                evidence: inactive_identity,
            });
            if binding.observability().retain_mapped_values {
                evaluation.retained_samples.push(RetainedBindingSample {
                    binding: binding.id().clone(),
                    coordinate,
                    opportunity: opportunity.map(FaultOpportunity::id),
                    values: None,
                    evidence: inactive_identity,
                });
            }
        }
        state.last_sample_identity = Some(inactive_identity);
        if binding.effect().lifetime() != EffectLifetime::Persistent || !state.active {
            return Ok(());
        }
        let mut mapped_digest = state
            .mapped_parameters
            .ok_or_else(|| BindingRuntimeError::MissingMappedValues(binding.id().clone()))?;
        let mut mapping_output = state
            .mapping_output
            .clone()
            .ok_or_else(|| BindingRuntimeError::MissingMappedValues(binding.id().clone()))?;
        let mut mapped_values = state.mapped_values.clone();
        if matches!(mapping_output, ResolvedMappingOutput::Activation { .. }) {
            mapping_output = ResolvedMappingOutput::Activation { active: false };
            mapped_digest = resolved_mapping_output_digest(&mapping_output, self.resource_limits)?;
            mapped_values.clear();
        }
        let transition_sequence = state
            .transition(false)
            .map_err(BindingRuntimeError::Runtime)?;
        state.mapped_parameters = Some(mapped_digest);
        state.mapped_values.clone_from(&mapped_values);
        state.mapping_output = Some(mapping_output.clone());
        let selected_targets: Vec<&ResolvedFaultTarget> =
            opportunity.map_or_else(|| targets.iter().collect(), |value| vec![value.target()]);
        let first_action = evaluation.actions.len();
        let shared_effect = Arc::new(binding.effect().clone());
        let shared_mapping_output = Arc::new(mapping_output);
        for target in selected_targets {
            append_membership_actions(
                binding,
                target,
                &binding_phases(binding),
                BindingActionKind::RemovePersistent,
                &shared_effect,
                &shared_mapping_output,
                mapped_digest,
                transition_sequence,
                coordinate,
                &BindingActionCause::Signal,
                evaluation,
            );
        }
        for action in &evaluation.actions[first_action..] {
            self.update_active(action)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply_decision(
        &mut self,
        binding: &FaultBinding,
        targets: &[ResolvedFaultTarget],
        mapped_digest: ContentHash,
        coordinate: FaultCoordinate,
        opportunity: Option<&FaultOpportunity>,
        decision: MappingDecision,
        prior_digest: Option<ContentHash>,
        mapping_output: ResolvedMappingOutput,
        evaluation: &mut BindingEvaluation,
    ) -> Result<(), BindingRuntimeError> {
        let state = self
            .states
            .get_mut(binding.id())
            .ok_or_else(|| BindingRuntimeError::MissingState(binding.id().clone()))?;
        let (kind, transition_sequence) = match decision {
            MappingDecision::NoAction => return Ok(()),
            MappingDecision::Persistent(active) => {
                let changed = state.active != active;
                let parameters_changed = prior_digest != Some(mapped_digest);
                if !changed && (!active || !parameters_changed) {
                    return Ok(());
                }
                let sequence = state
                    .transition(active)
                    .map_err(BindingRuntimeError::Runtime)?;
                (
                    if active {
                        BindingActionKind::UpsertPersistent
                    } else {
                        BindingActionKind::RemovePersistent
                    },
                    sequence,
                )
            }
            MappingDecision::Apply => {
                state.transition_sequence = state.transition_sequence.checked_add(1).ok_or(
                    BindingRuntimeError::Runtime(FaultRuntimeError::SequenceOverflow(
                        "binding_transition",
                    )),
                )?;
                (BindingActionKind::Apply, state.transition_sequence)
            }
        };
        let selected_targets: Vec<&ResolvedFaultTarget> = match (decision, opportunity) {
            (MappingDecision::Apply, Some(opportunity)) => vec![opportunity.target()],
            _ => targets.iter().collect(),
        };
        let phases: Vec<FaultPhase> = match (decision, opportunity) {
            (MappingDecision::Apply, Some(opportunity)) => vec![opportunity.phase()],
            (MappingDecision::Persistent(_), Some(_)) => binding
                .opportunity_filter()
                .map_or_else(Vec::new, |filter| filter.phases.iter().copied().collect()),
            _ => binding_phases(binding),
        };
        let shared_effect = Arc::new(binding.effect().clone());
        let shared_mapping_output = Arc::new(mapping_output);
        for target in selected_targets {
            for phase in &phases {
                let action = ResolvedBindingAction {
                    kind,
                    binding: binding.id().clone(),
                    target: target.clone(),
                    phase: *phase,
                    effect: shared_effect.clone(),
                    mapping_output: shared_mapping_output.clone(),
                    mapped_digest,
                    transition_sequence,
                    opportunity: opportunity.map(FaultOpportunity::id),
                    coordinate,
                    cause: opportunity.map_or(BindingActionCause::Signal, |value| {
                        BindingActionCause::Opportunity {
                            identity: value.id(),
                            payload: value.payload().clone(),
                        }
                    }),
                    expected_precondition: None,
                };
                self.update_active(&action)?;
                evaluation.actions.push(action);
            }
        }
        Ok(())
    }

    pub(super) fn update_active(
        &mut self,
        action: &ResolvedBindingAction,
    ) -> Result<(), BindingRuntimeError> {
        let key = ActiveContributionKey {
            target: action.target.clone(),
            phase: action.phase,
            effect: action.effect.kind(),
            binding: action.binding.clone(),
        };
        match action.kind {
            BindingActionKind::UpsertPersistent => {
                self.active
                    .activate(
                        key,
                        ActiveEffectContribution {
                            request: action.effect.clone(),
                            mapped_parameters: action.mapped_digest,
                            mapping_output: action.mapping_output.clone(),
                            transition_sequence: action.transition_sequence,
                        },
                        self.resource_limits,
                    )
                    .map_err(BindingRuntimeError::Runtime)?;
            }
            BindingActionKind::RemovePersistent => {
                let _ = self.active.deactivate(&key);
            }
            BindingActionKind::Apply => {}
        }
        Ok(())
    }
}
