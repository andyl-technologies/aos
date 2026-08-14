//! Focused binding runtime implementation responsibilities.

use super::*;

impl<'a> FaultBindingRuntime<'a> {
    /// Creates a binding runtime with canonical binding order and empty state.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError`] for duplicate bindings, invalid initial
    /// dynamic membership, or evaluator initialization failure.
    pub fn new(
        program: &'a SignalProgram,
        bindings: Vec<FaultBinding>,
        artifacts: &'a dyn SignalArtifactProvider,
        boundary: SignalBoundarySnapshot,
        scenario_seed: ContentHash,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, BindingRuntimeError> {
        Self::new_with_search_overrides(
            program,
            bindings,
            artifacts,
            boundary,
            scenario_seed,
            resource_limits,
            BTreeMap::new(),
        )
    }

    /// Creates a runtime with concrete finite explorer/replay overrides.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError`] under the same conditions as
    /// [`Self::new`], or when override state exceeds its hard bound.
    pub fn new_with_search_overrides(
        program: &'a SignalProgram,
        mut bindings: Vec<FaultBinding>,
        artifacts: &'a dyn SignalArtifactProvider,
        boundary: SignalBoundarySnapshot,
        scenario_seed: ContentHash,
        resource_limits: FaultResourceLimits,
        search_overrides: BTreeMap<SearchChoiceId, SearchOverride>,
    ) -> Result<Self, BindingRuntimeError> {
        resource_limits
            .validate()
            .map_err(BindingRuntimeError::ResourceLimit)?;
        reserve_usize_runtime(
            resource_limits,
            "search_choices_per_state",
            0,
            search_overrides.len(),
        )?;
        bindings.sort_by(|left, right| left.id().cmp(right.id()));
        reserve_usize_runtime(resource_limits, "bindings", 0, bindings.len())?;
        if bindings.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(BindingRuntimeError::DuplicateBinding);
        }
        if bindings
            .iter()
            .any(|binding| binding.program() != program.id())
        {
            return Err(BindingRuntimeError::BindingProgramMismatch);
        }
        if bindings.iter().any(|binding| {
            matches!(
                binding.search(),
                BindingSearchPolicy::MutateTraceWindow { .. }
                    | BindingSearchPolicy::MutateMapping { .. }
            )
        }) {
            return Err(BindingRuntimeError::UnmaterializedSearchMutation);
        }
        let states = bindings
            .iter()
            .map(|binding| (binding.id().clone(), BindingRuntimeState::default()))
            .collect();
        let dynamic_membership = bindings
            .iter()
            .filter_map(|binding| match binding.selector() {
                TargetSelector::DynamicPath {
                    path,
                    initial,
                    membership_semantic_version,
                } => Some((
                    binding.id().clone(),
                    DynamicMembershipState {
                        path: path.clone(),
                        semantic_version: *membership_semantic_version,
                        sequence: 0,
                        evidence: membership_digest(path, initial),
                        targets: initial.clone(),
                    },
                )),
                _ => None,
            })
            .collect();
        Ok(Self {
            program,
            bindings,
            evaluator: SignalEvaluator::new(program, artifacts, boundary, resource_limits)
                .map_err(BindingRuntimeError::Evaluation)?,
            artifacts,
            scenario_seed,
            resource_limits,
            states,
            active: ActiveContributionTable::default(),
            dynamic_membership,
            consumed_opportunities: BTreeMap::new(),
            search_overrides,
            consumed_search_overrides: std::collections::BTreeSet::new(),
            scheduler_cursor: None,
            boundary_completed_cursor: None,
            poisoned: false,
        })
    }

    /// Replaces the one-boundary-delayed telemetry snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError`] if the snapshot exceeds evaluator bounds.
    pub fn set_boundary_snapshot(
        &mut self,
        boundary: SignalBoundarySnapshot,
    ) -> Result<(), BindingRuntimeError> {
        self.ensure_usable()?;
        self.evaluator
            .set_boundary_snapshot(boundary)
            .map_err(BindingRuntimeError::Evaluation)
    }

    /// Replaces one dynamic path's current resolved membership.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError`] if the binding is not dynamic or the
    /// supplied membership crosses adapters or violates its authored bound.
    pub fn update_dynamic_targets(
        &mut self,
        binding: &FaultObjectId,
        transition: DynamicMembershipTransition,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        sink: &mut dyn FaultActionSink,
    ) -> Result<BindingEvaluation, BindingRuntimeError> {
        self.ensure_usable()?;
        let cursor = FaultSchedulerCursor {
            virtual_nanos: coordinate.virtual_nanos,
            same_coordinate_sequence,
        };
        self.ensure_monotone(cursor)?;
        if !self.dynamic_membership.contains_key(binding) {
            return Err(BindingRuntimeError::NotDynamic(binding.clone()));
        }
        if transition
            .targets
            .adapter()
            .is_some_and(|adapter| adapter != FaultAdapter::Network)
        {
            return Err(BindingRuntimeError::DynamicTargetAdapter);
        }
        let admitted = self
            .bindings
            .iter()
            .find(|candidate| candidate.id() == binding)
            .cloned()
            .ok_or_else(|| BindingRuntimeError::MissingBinding(binding.clone()))?;
        let TargetSelector::DynamicPath {
            path,
            membership_semantic_version,
            ..
        } = admitted.selector()
        else {
            return Err(BindingRuntimeError::NotDynamic(binding.clone()));
        };
        let previous_membership = self
            .dynamic_membership
            .get(binding)
            .cloned()
            .ok_or_else(|| BindingRuntimeError::NotDynamic(binding.clone()))?;
        if transition.path != *path
            || transition.semantic_version != *membership_semantic_version
            || transition.sequence
                != previous_membership.sequence.checked_add(1).ok_or(
                    BindingRuntimeError::Runtime(FaultRuntimeError::SequenceOverflow(
                        "dynamic_membership",
                    )),
                )?
            || transition.evidence == ContentHash::default()
        {
            return Err(BindingRuntimeError::DynamicTransitionIdentity);
        }
        let targets = &transition.targets;
        reserve_usize_runtime(
            self.resource_limits,
            "resolved_targets_per_binding",
            0,
            targets.targets().len(),
        )?;
        if targets.allow_empty() != admitted.selector().resolved().allow_empty()
            || targets.targets().is_empty() && !admitted.selector().resolved().allow_empty()
        {
            return Err(BindingRuntimeError::DynamicTargetEmpty);
        }
        if targets.targets().iter().any(|target| {
            !admitted
                .effect()
                .kind()
                .descriptor()
                .targets
                .contains(&target.kind())
        }) {
            return Err(BindingRuntimeError::DynamicTargetKind);
        }
        let previous = previous_membership.targets;
        let state = self
            .states
            .get(binding)
            .cloned()
            .ok_or_else(|| BindingRuntimeError::MissingState(binding.clone()))?;
        let mut evaluation = BindingEvaluation::default();
        if state.active {
            let shared_effect = Arc::new(admitted.effect().clone());
            let shared_mapping_output = Arc::new(
                state
                    .mapping_output
                    .clone()
                    .ok_or_else(|| BindingRuntimeError::MissingMappedValues(binding.clone()))?,
            );
            let mapped_digest = state
                .mapped_parameters
                .ok_or_else(|| BindingRuntimeError::MissingMappedValues(binding.clone()))?;
            let phases = binding_phases(&admitted);
            for target in previous
                .targets()
                .iter()
                .filter(|target| !targets.targets().contains(target))
            {
                append_membership_actions(
                    &admitted,
                    target,
                    &phases,
                    BindingActionKind::RemovePersistent,
                    &shared_effect,
                    &shared_mapping_output,
                    mapped_digest,
                    state.transition_sequence,
                    coordinate,
                    &BindingActionCause::DynamicMembership {
                        path: transition.path.clone(),
                        sequence: transition.sequence,
                        evidence: transition.evidence,
                    },
                    &mut evaluation,
                );
            }
            for target in targets
                .targets()
                .iter()
                .filter(|target| !previous.targets().contains(target))
            {
                append_membership_actions(
                    &admitted,
                    target,
                    &phases,
                    BindingActionKind::UpsertPersistent,
                    &shared_effect,
                    &shared_mapping_output,
                    mapped_digest,
                    state.transition_sequence,
                    coordinate,
                    &BindingActionCause::DynamicMembership {
                        path: transition.path.clone(),
                        sequence: transition.sequence,
                        evidence: transition.evidence,
                    },
                    &mut evaluation,
                );
            }
        }
        evaluation.actions.sort_by(|left, right| {
            (&left.target, left.phase, left.kind).cmp(&(&right.target, right.phase, right.kind))
        });
        let next_wakeup_nanos = self.next_wakeup_after(coordinate.virtual_nanos)?;
        let active = self.active.clone();
        for action in &evaluation.actions {
            if let Err(error) = self.update_active(action) {
                self.active = active;
                return Err(error);
            }
        }
        match prepare_and_commit(sink, &evaluation.actions) {
            Ok(results) => evaluation
                .observations
                .extend(results.into_iter().map(|result| result.observation)),
            Err(error) => {
                if matches!(
                    error,
                    BindingRuntimeError::AdapterAbort(_) | BindingRuntimeError::AdapterCommit(_)
                ) {
                    self.poisoned = true;
                }
                self.active = active;
                return Err(error);
            }
        }
        let transition_evidence = transition.evidence;
        self.dynamic_membership.insert(
            binding.clone(),
            DynamicMembershipState {
                path: transition.path,
                semantic_version: transition.semantic_version,
                sequence: transition.sequence,
                evidence: transition.evidence,
                targets: transition.targets,
            },
        );
        evaluation.observations.push(FaultObservation {
            semantic_version: FAULT_RUNTIME_STATE_VERSION,
            kind: FaultObservationKind::AssociationTransition,
            coordinate,
            binding: Some(binding.clone()),
            target: None,
            opportunity: None,
            evidence: transition_evidence,
        });
        evaluation.next_wakeup_nanos = next_wakeup_nanos;
        self.scheduler_cursor = Some(cursor);
        Ok(evaluation)
    }
}
