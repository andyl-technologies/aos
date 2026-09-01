//! Focused binding runtime implementation responsibilities.

use super::*;

impl<'a> FaultBindingRuntime<'a> {
    pub(super) fn next_wakeup_after(&self, now: u64) -> Result<Option<u64>, BindingRuntimeError> {
        let mut next: Option<u64> = None;
        for binding in &self.bindings {
            let candidate = match binding.sampling() {
                BindingSampling::CadenceNanos(cadence) => now
                    .checked_div(cadence.get())
                    .and_then(|quotient| quotient.checked_add(1))
                    .and_then(|quotient| quotient.checked_mul(cadence.get())),
                _ => match (binding.mapping(), self.states.get(binding.id())) {
                    (
                        BindingMapping::Threshold {
                            residence_nanos: 1..,
                            ..
                        },
                        Some(BindingRuntimeState {
                            pending_since_nanos: Some(since),
                            ..
                        }),
                    ) => {
                        let BindingMapping::Threshold {
                            residence_nanos, ..
                        } = binding.mapping()
                        else {
                            return Err(BindingRuntimeError::WakeupOverflow);
                        };
                        since.checked_add(*residence_nanos)
                    }
                    _ => None,
                },
            };
            if let Some(candidate) = candidate {
                if candidate <= now {
                    continue;
                }
                next = Some(next.map_or(candidate, |current| current.min(candidate)));
            } else if matches!(binding.sampling(), BindingSampling::CadenceNanos(_)) {
                return Err(BindingRuntimeError::WakeupOverflow);
            }
        }
        for signal in self.referenced_event_signals()? {
            let mut pending = vec![signal];
            let mut visited = BTreeSet::new();
            while let Some(node_id) = pending.pop() {
                if !visited.insert(node_id.clone()) {
                    continue;
                }
                let node = self
                    .program
                    .nodes()
                    .iter()
                    .find(|node| node.id == node_id)
                    .ok_or_else(|| BindingRuntimeError::MissingSignal(node_id.clone()))?;
                if let SignalNodeKind::Source(SignalSourceSpecification::EventSequence { events }) =
                    &node.kind
                {
                    for event in events {
                        let SignalCoordinate::Event { parent, .. } = &event.coordinate else {
                            continue;
                        };
                        let SignalCoordinate::VirtualTime { nanos } = parent.as_ref() else {
                            continue;
                        };
                        if *nanos > now {
                            next = Some(next.map_or(*nanos, |current| current.min(*nanos)));
                            break;
                        }
                    }
                }
                pending.extend(node.inputs.iter().cloned());
            }
        }
        Ok(next)
    }

    /// Samples every due boundary/change/cadence binding.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError`] if signal evaluation, mapping, state
    /// transition, target resolution, or active-table mutation fails.
    pub fn evaluate_boundary(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        sink: &mut dyn FaultActionSink,
    ) -> Result<BindingEvaluation, BindingRuntimeError> {
        self.evaluate_matching(
            coordinate,
            same_coordinate_sequence,
            None,
            sink,
            None,
            None,
            true,
        )
    }

    pub(crate) fn evaluate_boundary_traced(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        sink: &mut dyn FaultActionSink,
        replay: Option<&mut ResolvedEffectTrace>,
        recorded: &mut Vec<ResolvedReplayWorkItem>,
    ) -> Result<BindingEvaluation, BindingRuntimeError> {
        self.evaluate_matching(
            coordinate,
            same_coordinate_sequence,
            None,
            sink,
            replay,
            Some(recorded),
            true,
        )
    }

    /// Samples every matching opportunity binding at one exact adapter phase.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError`] under the same conditions as
    /// [`Self::evaluate_boundary`], or if opportunity context is inconsistent.
    pub fn evaluate_opportunity(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
        sink: &mut dyn FaultActionSink,
    ) -> Result<BindingEvaluation, BindingRuntimeError> {
        self.evaluate_matching(
            opportunity.coordinate(),
            same_coordinate_sequence,
            Some(opportunity),
            sink,
            None,
            None,
            true,
        )
    }

    pub(crate) fn evaluate_opportunity_traced(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
        sink: &mut dyn FaultActionSink,
        replay: Option<&mut ResolvedEffectTrace>,
        recorded: &mut Vec<ResolvedReplayWorkItem>,
    ) -> Result<BindingEvaluation, BindingRuntimeError> {
        self.evaluate_matching(
            opportunity.coordinate(),
            same_coordinate_sequence,
            Some(opportunity),
            sink,
            replay,
            Some(recorded),
            true,
        )
    }

    pub(crate) fn preview_boundary_traced(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        sink: &mut dyn FaultActionSink,
        replay: Option<&mut ResolvedEffectTrace>,
    ) -> Result<BindingEvaluation, BindingRuntimeError> {
        self.evaluate_matching(
            coordinate,
            same_coordinate_sequence,
            None,
            sink,
            replay,
            None,
            false,
        )
    }

    pub(crate) fn preview_opportunity_traced(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
        sink: &mut dyn FaultActionSink,
        replay: Option<&mut ResolvedEffectTrace>,
    ) -> Result<BindingEvaluation, BindingRuntimeError> {
        self.evaluate_matching(
            opportunity.coordinate(),
            same_coordinate_sequence,
            Some(opportunity),
            sink,
            replay,
            None,
            false,
        )
    }

    /// Returns the canonical active contribution table.
    #[must_use]
    pub const fn active(&self) -> &ActiveContributionTable {
        &self.active
    }

    /// Returns per-binding mapping and transition state.
    #[must_use]
    pub const fn states(&self) -> &BTreeMap<FaultObjectId, BindingRuntimeState> {
        &self.states
    }

    /// Encodes the complete evaluator continuation.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError`] when the runtime is poisoned or evaluator
    /// state exceeds a bound.
    pub fn evaluator_checkpoint(&self) -> Result<SignalEvaluatorCheckpoint, BindingRuntimeError> {
        self.ensure_usable()?;
        self.evaluator
            .checkpoint()
            .map_err(BindingRuntimeError::Evaluation)
    }

    /// Captures every mutable bridge state item required for fat resume.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError`] if evaluator state cannot be encoded.
    pub fn checkpoint(&self) -> Result<BindingRuntimeCheckpoint, BindingRuntimeError> {
        self.ensure_usable()?;
        Ok(BindingRuntimeCheckpoint {
            semantic_version: FAULT_RUNTIME_STATE_VERSION,
            signal_program: self.program.id(),
            scenario_seed: self.scenario_seed,
            resource_limits: self.resource_limits,
            evaluator: self.evaluator_checkpoint()?,
            bindings: self.states.clone(),
            binding_contracts: self.bindings.clone(),
            active: self.active.clone(),
            dynamic_membership: self.dynamic_membership.clone(),
            consumed_opportunities: self.consumed_opportunities.clone(),
            search_overrides: self.search_overrides.clone(),
            consumed_search_overrides: self.consumed_search_overrides.clone(),
            scheduler_cursor: self.scheduler_cursor,
            boundary_completed_cursor: self.boundary_completed_cursor,
        })
    }

    /// Verifies that locked replay consumed every supplied search override once.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError::UnusedSearchOverride`] if any override was
    /// never reached by this execution.
    pub fn verify_search_overrides_consumed(&self) -> Result<(), BindingRuntimeError> {
        if self
            .search_overrides
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            == self.consumed_search_overrides
        {
            Ok(())
        } else {
            Err(BindingRuntimeError::UnusedSearchOverride)
        }
    }

    /// Restores a complete, authenticated binding-runtime continuation.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError`] if program/binding identity, evaluator
    /// bytes, mapping state, active contributions, dynamic membership, or
    /// opportunity continuation is incomplete or inconsistent.
    pub fn restore(
        program: &'a SignalProgram,
        mut bindings: Vec<FaultBinding>,
        artifacts: &'a dyn SignalArtifactProvider,
        scenario_seed: ContentHash,
        resource_limits: FaultResourceLimits,
        checkpoint: &BindingRuntimeCheckpoint,
    ) -> Result<Self, BindingRuntimeError> {
        bindings.sort_by(|left, right| left.id().cmp(right.id()));
        validate_binding_checkpoint(
            program,
            &bindings,
            scenario_seed,
            resource_limits,
            checkpoint,
        )?;
        Ok(Self {
            program,
            bindings,
            evaluator: SignalEvaluator::restore(
                program,
                artifacts,
                &checkpoint.evaluator,
                resource_limits,
            )
            .map_err(BindingRuntimeError::Evaluation)?,
            artifacts,
            scenario_seed: checkpoint.scenario_seed,
            resource_limits,
            states: checkpoint.bindings.clone(),
            active: checkpoint.active.clone(),
            dynamic_membership: checkpoint.dynamic_membership.clone(),
            consumed_opportunities: checkpoint.consumed_opportunities.clone(),
            search_overrides: checkpoint.search_overrides.clone(),
            consumed_search_overrides: checkpoint.consumed_search_overrides.clone(),
            scheduler_cursor: checkpoint.scheduler_cursor,
            boundary_completed_cursor: checkpoint.boundary_completed_cursor,
            poisoned: false,
        })
    }
}
