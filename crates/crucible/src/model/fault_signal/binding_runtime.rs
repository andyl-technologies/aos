//! Runtime evaluation of signal-to-effect bindings.
//!
//! This module is the sole bridge from the deterministic signal evaluator to
//! production adapter actions. It owns mapping state, selector membership,
//! keyed hazard choices, persistent contributor installation, and causal
//! observations. Adapters never evaluate signal graphs or reinterpret mapping
//! schemas themselves.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use super::*;

/// Maximum aggregate canonical dynamic parameter bytes for one action.
pub const HARD_MAPPED_EFFECT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum prepared adapter actions emitted by one scheduler boundary.
pub const HARD_ACTIONS_PER_BOUNDARY: usize = 262_144;
/// Maximum retained canonical sample payload bytes per boundary.
pub const HARD_RETAINED_SAMPLE_BYTES: usize = 256 * 1024 * 1024;

/// One mutation requested of the owning production adapter.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BindingActionKind {
    /// Installs or replaces one persistent contribution.
    UpsertPersistent,
    /// Removes one persistent contribution.
    RemovePersistent,
    /// Applies one opportunity, impulse, or state-machine effect.
    Apply,
}

/// Canonical identity of the transition that produced an adapter action.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum BindingActionCause {
    /// A scheduled signal mapping transition.
    Signal,
    /// One exact adapter opportunity.
    Opportunity(ContentHash),
    /// One exact dynamic-path membership transition.
    DynamicMembership {
        /// Authored path identity.
        path: FaultObjectId,
        /// Path-owned transition sequence.
        sequence: u64,
        /// Route/association evidence.
        evidence: ContentHash,
    },
}

/// Fully resolved adapter input produced by one binding evaluation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedBindingAction {
    /// Requested adapter mutation.
    pub kind: BindingActionKind,
    /// Binding that caused the action.
    pub binding: FaultObjectId,
    /// Concrete target resolved before execution.
    pub target: ResolvedFaultTarget,
    /// Exact adapter phase.
    pub phase: FaultPhase,
    /// Validated typed effect template.
    pub effect: Arc<EffectRequest>,
    /// Closed typed mapping output consumed without adapter reinterpretation.
    pub mapping_output: Arc<ResolvedMappingOutput>,
    /// Canonical digest of the mapped value vector.
    pub mapped_digest: ContentHash,
    /// Binding transition sequence after this decision.
    pub transition_sequence: u64,
    /// Matching opportunity identity for opportunity-scoped actions.
    pub opportunity: Option<ContentHash>,
    /// Exact scheduler coordinate.
    pub coordinate: FaultCoordinate,
    /// Exact transition identity that caused this action.
    pub cause: BindingActionCause,
}

impl ResolvedBindingAction {
    /// Returns the canonical identity used to match an adapter result.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        let kind = match self.kind {
            BindingActionKind::UpsertPersistent => "upsert_persistent",
            BindingActionKind::RemovePersistent => "remove_persistent",
            BindingActionKind::Apply => "apply",
        };
        let cause = match &self.cause {
            BindingActionCause::Signal => String::from("signal"),
            BindingActionCause::Opportunity(identity) => {
                format!("opportunity:{}", identity.to_hex())
            }
            BindingActionCause::DynamicMembership {
                path,
                sequence,
                evidence,
            } => format!(
                "dynamic_membership:{}:{sequence}:{}",
                path.as_str(),
                evidence.to_hex()
            ),
        };
        let retired = self
            .coordinate
            .retired_instructions
            .map_or_else(|| String::from("none"), |value| value.to_string());
        let mut material = format!(
            "kind={kind};binding={};phase={};effect={};mapped={};transition={};opportunity={};virtual_nanos={};retired={retired};cause={cause};target=",
            self.binding.as_str(),
            self.phase.as_str(),
            self.effect.kind().as_str(),
            self.mapped_digest.to_hex(),
            self.transition_sequence,
            self.opportunity
                .map_or_else(|| String::from("none"), |value| value.to_hex()),
            self.coordinate.virtual_nanos,
        );
        self.target.append_canonical(&mut material);
        ContentHash::from_canonical_material("crucible.resolved-binding-action.v1", &material)
    }
}

/// One production-adapter preparation result corresponding to one action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedActionResult {
    /// Exact prepared action identity.
    pub action: ContentHash,
    /// Adapter-owned successful application evidence.
    pub observation: FaultObservation,
}

/// One prepared or committed atomic action batch.
///
/// `prepare_batch` returns the transaction with prediction-only results;
/// callers must not retain those results as application evidence. A successful
/// `commit_batch` returns the same transaction with backend-observed results.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreparedActionBatch {
    /// Adapter-owned opaque transaction identity used for the commit.
    pub transaction: ContentHash,
    /// Predicted results in exact action order, one per action.
    pub results: Vec<PreparedActionResult>,
}

/// Prepared adapter actions and pre-application observations from one boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BindingEvaluation {
    /// Adapter actions in canonical binding/target/phase order.
    pub actions: Vec<ResolvedBindingAction>,
    /// Causal observations in their production order.
    pub observations: Vec<FaultObservation>,
    /// Policy-retained canonical sample payloads.
    pub retained_samples: Vec<RetainedBindingSample>,
    /// Finite search decisions reached at this boundary.
    pub search_choices: Vec<BindingSearchChoice>,
    /// Earliest exact virtual-time boundary the scheduler must enqueue.
    pub next_wakeup_nanos: Option<u64>,
    /// Referenced exported event signals emitted at this boundary.
    pub emitted_events: Vec<ReferencedSignalEvent>,
    retained_sample_bytes: usize,
}

/// One emitted event explicitly referenced by an admitted effect contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferencedSignalEvent {
    /// Exported event signal identity.
    pub signal: SignalId,
    /// Exact scheduler coordinate at which it was observed.
    pub coordinate: FaultCoordinate,
    /// Stable order among evaluations at the same coordinate.
    pub same_coordinate_sequence: u64,
    /// Complete typed event value.
    pub value: SignalValue,
    /// Canonical digest of the typed event value.
    pub evidence: ContentHash,
}

/// One sample payload retained under a binding's observability policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedBindingSample {
    /// Binding that sampled the values.
    pub binding: FaultObjectId,
    /// Exact scheduler coordinate.
    pub coordinate: FaultCoordinate,
    /// Opportunity identity for opportunity-scoped samples.
    pub opportunity: Option<ContentHash>,
    /// Canonical sampled values, or `None` for explicit inactivity.
    pub values: Option<Vec<SignalValue>>,
    /// Sample identity retained by the observation record.
    pub evidence: ContentHash,
}

impl BindingRuntimeCheckpoint {
    /// Validates the complete bridge continuation against independent identity.
    ///
    /// # Errors
    ///
    /// Returns [`BindingRuntimeError`] for any identity, bound, or mutable-state
    /// inconsistency.
    pub fn validate(
        &self,
        program: &SignalProgram,
        bindings: &[FaultBinding],
        scenario_seed: ContentHash,
    ) -> Result<(), BindingRuntimeError> {
        let mut bindings = bindings.to_vec();
        bindings.sort_by(|left, right| left.id().cmp(right.id()));
        validate_binding_checkpoint(program, &bindings, scenario_seed, self)
    }
}

/// Two-phase production-adapter boundary for one fully resolved action batch.
pub trait FaultActionSink {
    /// Validates and prepares every action without changing visible state.
    ///
    /// Returned observations are predictions used only to prove complete action
    /// ordering. Actual application evidence is returned by `commit_batch`.
    ///
    /// # Errors
    ///
    /// Returns [`RejectedActionBatch`] when validation or application fails.
    /// The sink must roll back the entire batch before returning an error.
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>>;

    /// Discards one prepared transaction without changing visible state.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when the adapter cannot prove that all
    /// staged resources and mutations were discarded. The runtime becomes
    /// terminally poisoned after this error.
    fn abort_batch(&mut self, transaction: ContentHash) -> Result<(), FaultRuntimeError>;

    /// Atomically commits one previously prepared transaction and returns actual evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FaultActionCommitError::Rejected`] only when adapter-visible
    /// state remains unchanged. Returns [`FaultActionCommitError::Fatal`] when
    /// the backend cannot prove whether a destructive commit became visible;
    /// the owning runtime must become terminally poisoned.
    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError>;
}

/// Failure class for an atomic adapter commit.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FaultActionCommitError {
    /// The entire batch was rejected before any visible state changed.
    #[error("fault action commit was rejected: {0:?}")]
    Rejected(Box<RejectedActionBatch>),
    /// Visibility is ambiguous or partial and the run cannot safely continue.
    #[error("fault action commit became fatal: {0}")]
    Fatal(FaultRuntimeError),
}

/// Atomic adapter rejection with durable failure evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedActionBatch {
    /// Typed production-adapter failure.
    pub error: FaultRuntimeError,
    /// Adapter-owned `EffectRejected` observations with before-state evidence.
    pub observations: Vec<FaultObservation>,
    /// Exact action whose validation/application rejected, when applicable.
    pub rejected_action: Option<ContentHash>,
}

/// Mutable deterministic runtime for one validated program and binding set.
pub struct FaultBindingRuntime<'a> {
    program: &'a SignalProgram,
    bindings: Vec<FaultBinding>,
    evaluator: SignalEvaluator<'a>,
    artifacts: &'a dyn SignalArtifactProvider,
    scenario_seed: ContentHash,
    states: BTreeMap<FaultObjectId, BindingRuntimeState>,
    active: ActiveContributionTable,
    dynamic_membership: BTreeMap<FaultObjectId, DynamicMembershipState>,
    consumed_opportunities: BTreeMap<ConsumedOpportunityKey, ConsumedOpportunityState>,
    search_overrides: BTreeMap<SearchChoiceId, SearchOverride>,
    consumed_search_overrides: std::collections::BTreeSet<SearchChoiceId>,
    scheduler_cursor: Option<FaultSchedulerCursor>,
    boundary_completed_cursor: Option<FaultSchedulerCursor>,
    poisoned: bool,
}

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
    ) -> Result<Self, BindingRuntimeError> {
        Self::new_with_search_overrides(
            program,
            bindings,
            artifacts,
            boundary,
            scenario_seed,
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
        search_overrides: BTreeMap<SearchChoiceId, SearchOverride>,
    ) -> Result<Self, BindingRuntimeError> {
        if search_overrides.len() > HARD_SEARCH_OVERRIDES {
            return Err(BindingRuntimeError::SearchOverrideLimit);
        }
        bindings.sort_by(|left, right| left.id().cmp(right.id()));
        if bindings.len() > HARD_FAULT_BINDING_LIMIT {
            return Err(BindingRuntimeError::BindingLimit);
        }
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
            evaluator: SignalEvaluator::new(program, artifacts, boundary)
                .map_err(BindingRuntimeError::Evaluation)?,
            artifacts,
            scenario_seed,
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
            let changed_targets = previous
                .targets()
                .iter()
                .filter(|target| !targets.targets().contains(target))
                .count()
                .checked_add(
                    targets
                        .targets()
                        .iter()
                        .filter(|target| !previous.targets().contains(target))
                        .count(),
                )
                .ok_or(BindingRuntimeError::ActionLimit)?;
            ensure_action_capacity(evaluation.actions.len(), changed_targets, phases.len())?;
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
            Ok(observations) => evaluation.observations.extend(observations),
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

    fn next_wakeup_after(&self, now: u64) -> Result<Option<u64>, BindingRuntimeError> {
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
        self.evaluate_matching(coordinate, same_coordinate_sequence, None, sink)
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
        checkpoint: &BindingRuntimeCheckpoint,
    ) -> Result<Self, BindingRuntimeError> {
        bindings.sort_by(|left, right| left.id().cmp(right.id()));
        validate_binding_checkpoint(program, &bindings, scenario_seed, checkpoint)?;
        Ok(Self {
            program,
            bindings,
            evaluator: SignalEvaluator::restore(program, artifacts, &checkpoint.evaluator)
                .map_err(BindingRuntimeError::Evaluation)?,
            artifacts,
            scenario_seed: checkpoint.scenario_seed,
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

    fn evaluate_matching(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        opportunity: Option<&FaultOpportunity>,
        sink: &mut dyn FaultActionSink,
    ) -> Result<BindingEvaluation, BindingRuntimeError> {
        self.ensure_usable()?;
        let cursor = FaultSchedulerCursor {
            virtual_nanos: coordinate.virtual_nanos,
            same_coordinate_sequence,
        };
        self.ensure_monotone(cursor)?;
        if opportunity.is_some()
            && !self.boundary_completed_cursor.is_some_and(|boundary| {
                boundary.virtual_nanos == cursor.virtual_nanos && boundary <= cursor
            })
        {
            return Err(BindingRuntimeError::OpportunityBeforeBoundary);
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
        match self.evaluate_matching_inner(coordinate, same_coordinate_sequence, opportunity) {
            Ok(mut evaluation) => match prepare_and_commit(sink, &evaluation.actions) {
                Ok(observations) => {
                    evaluation.observations.extend(observations);
                    self.scheduler_cursor = Some(cursor);
                    if opportunity.is_none() {
                        self.boundary_completed_cursor = Some(cursor);
                    }
                    Ok(evaluation)
                }
                Err(error) => {
                    if matches!(
                        error,
                        BindingRuntimeError::AdapterAbort(_)
                            | BindingRuntimeError::AdapterCommit(_)
                    ) {
                        self.poisoned = true;
                    }
                    self.states = states;
                    self.active = active;
                    self.consumed_opportunities = consumed_opportunities;
                    self.consumed_search_overrides = consumed_search_overrides;
                    self.evaluator = match SignalEvaluator::restore(
                        self.program,
                        self.artifacts,
                        &evaluator_checkpoint,
                    ) {
                        Ok(evaluator) => evaluator,
                        Err(error) => {
                            self.poisoned = true;
                            return Err(BindingRuntimeError::Rollback(error));
                        }
                    };
                    Err(error)
                }
            },
            Err(error) => {
                self.states = states;
                self.active = active;
                self.consumed_opportunities = consumed_opportunities;
                self.consumed_search_overrides = consumed_search_overrides;
                self.evaluator = match SignalEvaluator::restore(
                    self.program,
                    self.artifacts,
                    &evaluator_checkpoint,
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

    fn ensure_usable(&self) -> Result<(), BindingRuntimeError> {
        if self.poisoned {
            Err(BindingRuntimeError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn ensure_monotone(&self, cursor: FaultSchedulerCursor) -> Result<(), BindingRuntimeError> {
        if self
            .scheduler_cursor
            .is_some_and(|previous| previous > cursor)
        {
            Err(BindingRuntimeError::NonMonotoneBoundary)
        } else {
            Ok(())
        }
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
            let value_digest = mapped_values_digest(&raw_values)?;
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
            let digest = resolved_mapping_output_digest(&mapping_output)?;
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

    fn referenced_event_signals(&self) -> Result<BTreeSet<SignalId>, BindingRuntimeError> {
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

    fn admit_opportunity_delivery(
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

    fn record_opportunity_delivery(
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
        if !self.consumed_opportunities.contains_key(&key)
            && self.consumed_opportunities.len() == HARD_CONSUMED_OPPORTUNITY_SCOPES
        {
            return Err(BindingRuntimeError::OpportunityStateLimit);
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

    fn targets_for(
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

    fn evaluate_signals(
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

    fn handle_inactive_binding(
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
            mapped_digest = resolved_mapping_output_digest(&mapping_output)?;
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
        ensure_action_capacity(
            evaluation.actions.len(),
            selected_targets.len(),
            binding_phases(binding).len(),
        )?;
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
    fn apply_decision(
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
        ensure_action_capacity(
            evaluation.actions.len(),
            selected_targets.len(),
            phases.len(),
        )?;
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
                        BindingActionCause::Opportunity(value.id())
                    }),
                };
                self.update_active(&action)?;
                evaluation.actions.push(action);
            }
        }
        Ok(())
    }

    fn update_active(&mut self, action: &ResolvedBindingAction) -> Result<(), BindingRuntimeError> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MappingDecision {
    NoAction,
    Persistent(bool),
    Apply,
}

#[derive(Default)]
struct SearchResolution {
    selected_transition: Option<FaultObjectId>,
}

#[allow(clippy::too_many_arguments)]
fn apply_search_policy(
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
            mapped_values_digest(candidates)?,
            u32::try_from(candidates.len()).map_err(|_| BindingRuntimeError::SearchChoice)?,
            values.first().and_then(|value| {
                candidates
                    .iter()
                    .position(|candidate| candidate == value)
                    .and_then(|index| u32::try_from(index).ok())
            }),
        ),
    };
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
    if state.search_choice_count >= HARD_SEARCH_CHOICES_PER_STATE {
        return Err(BindingRuntimeError::SearchChoiceLimit);
    }
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

fn object_candidates_digest(candidates: &[FaultObjectId]) -> ContentHash {
    let mut material = String::new();
    for candidate in candidates {
        material.push_str(candidate.as_str());
        material.push(';');
    }
    ContentHash::from_canonical_material("crucible.search-candidates.v1", &material)
}

#[allow(clippy::too_many_arguments)]
fn record_sample(
    binding: &FaultBinding,
    state: &mut BindingRuntimeState,
    values: &[SignalValue],
    evidence: ContentHash,
    sample_identity: ContentHash,
    coordinate: FaultCoordinate,
    opportunity: Option<&FaultOpportunity>,
    force: bool,
    evaluation: &mut BindingEvaluation,
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
        )?;
    }
    Ok(retain)
}

#[allow(clippy::too_many_arguments)]
fn push_sample_observation(
    binding: &FaultBinding,
    values: &[SignalValue],
    evidence: ContentHash,
    changed: bool,
    coordinate: FaultCoordinate,
    opportunity: Option<&FaultOpportunity>,
    evaluation: &mut BindingEvaluation,
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
        evaluation.retained_sample_bytes = evaluation
            .retained_sample_bytes
            .checked_add(bytes)
            .filter(|total| *total <= HARD_RETAINED_SAMPLE_BYTES)
            .ok_or(BindingRuntimeError::RetainedSampleLimit)?;
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

fn encoded_values_len(values: &[SignalValue]) -> Result<usize, BindingRuntimeError> {
    values.iter().try_fold(0_usize, |total, value| {
        let encoded = encode_signal_value(value).map_err(BindingRuntimeError::Trace)?;
        total
            .checked_add(4)
            .and_then(|length| length.checked_add(encoded.len()))
            .ok_or(BindingRuntimeError::RetainedSampleLimit)
    })
}

fn binding_due(
    binding: &FaultBinding,
    state: &BindingRuntimeState,
    now: u64,
    opportunity: Option<&FaultOpportunity>,
) -> bool {
    match binding.sampling() {
        BindingSampling::AtOpportunity => opportunity.is_some(),
        BindingSampling::AtBoundary | BindingSampling::AtChange => opportunity.is_none(),
        BindingSampling::CadenceNanos(cadence) => {
            opportunity.is_none()
                && now.is_multiple_of(cadence.get())
                && state.last_sample_nanos != Some(now)
        }
        BindingSampling::AtEvent(parent) => match parent {
            BindingEventParent::VirtualTime | BindingEventParent::NodeCounter { .. } => {
                opportunity.is_none()
            }
            BindingEventParent::OpportunityOperation | BindingEventParent::OpportunityState => {
                opportunity.is_some()
            }
        },
    }
}

fn opportunity_matches(binding: &FaultBinding, opportunity: Option<&FaultOpportunity>) -> bool {
    if !control_opportunity_matches(binding.effect(), opportunity) {
        return false;
    }
    match (binding.opportunity_filter(), opportunity) {
        (Some(filter), Some(opportunity)) => filter.matches(opportunity),
        (Some(_), None) => false,
        (None, Some(_)) => false,
        (None, None) => true,
    }
}

fn control_opportunity_matches(
    effect: &EffectRequest,
    opportunity: Option<&FaultOpportunity>,
) -> bool {
    let control_transform = match effect.specification() {
        EffectSpecification::Network(NetworkEffectSpecification::ControlResultTransform {
            technology,
            operations,
            ..
        }) => Some((technology, operations)),
        _ => None,
    };
    match opportunity.map(FaultOpportunity::payload) {
        Some(OpportunityPayload::NetworkControl { technology, .. }) => control_transform
            .is_some_and(|(expected_technology, operations)| {
                expected_technology == technology
                    && opportunity.is_some_and(|value| operations.contains(value.operation()))
            }),
        Some(_) => control_transform.is_none(),
        None => true,
    }
}

fn binding_phases(binding: &FaultBinding) -> Vec<FaultPhase> {
    binding.phases().iter().copied().collect()
}

fn membership_digest(path: &FaultObjectId, targets: &ResolvedTargetSet) -> ContentHash {
    let mut material = format!(
        "path={};allow_empty={};targets=",
        path.as_str(),
        targets.allow_empty()
    );
    for target in targets.targets() {
        target.append_canonical(&mut material);
        material.push(';');
    }
    ContentHash::from_canonical_material("crucible.dynamic-membership.v1", &material)
}

fn ensure_action_capacity(
    current: usize,
    target_count: usize,
    phase_count: usize,
) -> Result<(), BindingRuntimeError> {
    let additional = target_count
        .checked_mul(phase_count)
        .ok_or(BindingRuntimeError::ActionLimit)?;
    if current
        .checked_add(additional)
        .is_none_or(|total| total > HARD_ACTIONS_PER_BOUNDARY)
    {
        return Err(BindingRuntimeError::ActionLimit);
    }
    Ok(())
}

fn validate_prepared_batch(
    actions: &[ResolvedBindingAction],
    batch: PreparedActionBatch,
) -> Result<Vec<FaultObservation>, BindingRuntimeError> {
    if batch.transaction == ContentHash::default() || actions.len() != batch.results.len() {
        return Err(BindingRuntimeError::AdapterResult);
    }
    let mut observations = Vec::with_capacity(batch.results.len());
    for (action, result) in actions.iter().zip(batch.results) {
        let expected_kind = match action.kind {
            BindingActionKind::UpsertPersistent => FaultObservationKind::BindingActivation,
            BindingActionKind::RemovePersistent => FaultObservationKind::BindingDeactivation,
            BindingActionKind::Apply => FaultObservationKind::EffectApplied,
        };
        let observation = result.observation;
        if result.action != action.id()
            || observation.semantic_version != FAULT_RUNTIME_STATE_VERSION
            || observation.kind != expected_kind
            || observation.binding.as_ref() != Some(&action.binding)
            || observation.target.as_ref() != Some(&action.target)
            || observation.opportunity != action.opportunity
            || observation.coordinate != action.coordinate
            || observation.evidence == ContentHash::default()
        {
            return Err(BindingRuntimeError::AdapterResult);
        }
        observations.push(observation);
    }
    Ok(observations)
}

fn prepare_and_commit(
    sink: &mut dyn FaultActionSink,
    actions: &[ResolvedBindingAction],
) -> Result<Vec<FaultObservation>, BindingRuntimeError> {
    if actions.is_empty() {
        return Ok(Vec::new());
    }
    let prepared = match sink.prepare_batch(actions) {
        Ok(prepared) => prepared,
        Err(rejected) => {
            if validate_rejected_batch(actions, &rejected) {
                return Err(BindingRuntimeError::AdapterRejected(rejected));
            }
            return Err(BindingRuntimeError::AdapterResult);
        }
    };
    let transaction = prepared.transaction;
    match sink.commit_batch(transaction) {
        Ok(committed) if committed.transaction == transaction => {
            validate_prepared_batch(actions, committed).map_err(|_error| {
                BindingRuntimeError::AdapterCommit(FaultRuntimeError::IncompleteAdapterState)
            })
        }
        Ok(_) => Err(BindingRuntimeError::AdapterCommit(
            FaultRuntimeError::IncompleteAdapterState,
        )),
        Err(FaultActionCommitError::Rejected(rejected))
            if validate_rejected_batch(actions, &rejected) =>
        {
            Err(BindingRuntimeError::AdapterRejected(rejected))
        }
        Err(FaultActionCommitError::Rejected(_)) => Err(BindingRuntimeError::AdapterResult),
        Err(FaultActionCommitError::Fatal(error)) => Err(BindingRuntimeError::AdapterCommit(error)),
    }
}

fn validate_rejected_batch(actions: &[ResolvedBindingAction], batch: &RejectedActionBatch) -> bool {
    let Some(rejected) = batch.rejected_action else {
        return false;
    };
    let Some(action) = actions.iter().find(|action| action.id() == rejected) else {
        return false;
    };
    batch.observations.len() == 1
        && batch.observations.iter().all(|observation| {
            observation.semantic_version == FAULT_RUNTIME_STATE_VERSION
                && observation.kind == FaultObservationKind::EffectRejected
                && observation.binding.as_ref() == Some(&action.binding)
                && observation.target.as_ref() == Some(&action.target)
                && observation.opportunity == action.opportunity
                && observation.coordinate == action.coordinate
                && observation.evidence != ContentHash::default()
        })
}

#[allow(clippy::too_many_arguments)]
fn append_membership_actions(
    binding: &FaultBinding,
    target: &ResolvedFaultTarget,
    phases: &[FaultPhase],
    kind: BindingActionKind,
    effect: &Arc<EffectRequest>,
    mapping_output: &Arc<ResolvedMappingOutput>,
    mapped_digest: ContentHash,
    transition_sequence: u64,
    coordinate: FaultCoordinate,
    cause: &BindingActionCause,
    evaluation: &mut BindingEvaluation,
) {
    evaluation
        .actions
        .extend(phases.iter().map(|phase| ResolvedBindingAction {
            kind,
            binding: binding.id().clone(),
            target: target.clone(),
            phase: *phase,
            effect: effect.clone(),
            mapping_output: mapping_output.clone(),
            mapped_digest,
            transition_sequence,
            opportunity: None,
            coordinate,
            cause: cause.clone(),
        }));
}

fn binding_coordinate(
    domain: SignalDomain,
    coordinate: FaultCoordinate,
    opportunity: Option<&FaultOpportunity>,
    sampling: &BindingSampling,
    same_coordinate_sequence: u64,
) -> Result<SignalCoordinate, BindingRuntimeError> {
    match domain {
        SignalDomain::VirtualTime => Ok(SignalCoordinate::VirtualTime {
            nanos: coordinate.virtual_nanos,
        }),
        SignalDomain::NodeCounter => {
            let retired_instructions = coordinate
                .retired_instructions
                .ok_or(BindingRuntimeError::CounterCoordinateRequired)?;
            let node = opportunity
                .map(|opportunity| target_signal_id(opportunity.target()))
                .transpose()?
                .ok_or(BindingRuntimeError::OpportunityRequired)?;
            Ok(SignalCoordinate::NodeCounter {
                node,
                retired_instructions,
            })
        }
        SignalDomain::Operation => {
            let opportunity = opportunity.ok_or(BindingRuntimeError::OpportunityRequired)?;
            operation_signal_coordinate(opportunity)
        }
        SignalDomain::Event => {
            let BindingSampling::AtEvent(parent) = sampling else {
                return Err(BindingRuntimeError::EventParentRequired);
            };
            let parent = match parent {
                BindingEventParent::VirtualTime => SignalCoordinate::VirtualTime {
                    nanos: coordinate.virtual_nanos,
                },
                BindingEventParent::NodeCounter { node } => SignalCoordinate::NodeCounter {
                    node: node.clone(),
                    retired_instructions: coordinate
                        .retired_instructions
                        .ok_or(BindingRuntimeError::CounterCoordinateRequired)?,
                },
                BindingEventParent::OpportunityOperation => operation_signal_coordinate(
                    opportunity.ok_or(BindingRuntimeError::OpportunityRequired)?,
                )?,
                BindingEventParent::OpportunityState => {
                    let opportunity =
                        opportunity.ok_or(BindingRuntimeError::OpportunityRequired)?;
                    SignalCoordinate::State {
                        adapter: adapter_signal_id(opportunity.adapter())?,
                        target: target_signal_id(opportunity.target())?,
                        boundary_sequence: opportunity.sequence(),
                    }
                }
            };
            Ok(SignalCoordinate::Event {
                parent: Box::new(parent),
                sequence: same_coordinate_sequence,
            })
        }
        SignalDomain::State => {
            let opportunity = opportunity.ok_or(BindingRuntimeError::OpportunityRequired)?;
            Ok(SignalCoordinate::State {
                adapter: SignalId::parse(match opportunity.adapter() {
                    FaultAdapter::Network => "network",
                    FaultAdapter::Storage => "storage",
                    FaultAdapter::Node => "node",
                })
                .map_err(BindingRuntimeError::Program)?,
                target: target_signal_id(opportunity.target())?,
                boundary_sequence: opportunity.sequence(),
            })
        }
        SignalDomain::Spatial => Err(BindingRuntimeError::UnprojectedSpatialSignal),
    }
}

fn operation_signal_coordinate(
    opportunity: &FaultOpportunity,
) -> Result<SignalCoordinate, BindingRuntimeError> {
    Ok(SignalCoordinate::Operation {
        adapter: adapter_signal_id(opportunity.adapter())?,
        target: target_signal_id(opportunity.target())?,
        operation: SignalId::parse(opportunity.operation().as_str().replace('_', "-"))
            .map_err(BindingRuntimeError::Program)?,
        producer_sequence: opportunity.sequence(),
        suboperation: 0,
    })
}

fn adapter_signal_id(adapter: FaultAdapter) -> Result<SignalId, BindingRuntimeError> {
    SignalId::parse(match adapter {
        FaultAdapter::Network => "network",
        FaultAdapter::Storage => "storage",
        FaultAdapter::Node => "node",
    })
    .map_err(BindingRuntimeError::Program)
}

fn target_signal_id(target: &ResolvedFaultTarget) -> Result<SignalId, BindingRuntimeError> {
    let mut material = String::new();
    target.append_canonical(&mut material);
    SignalId::parse(format!(
        "target-{}",
        ContentHash::from_canonical_material("crucible.binding-target.v1", &material).to_hex()
    ))
    .map_err(BindingRuntimeError::Program)
}

fn map_binding(
    binding: &FaultBinding,
    values: &[SignalValue],
    state: &mut BindingRuntimeState,
    now: u64,
    opportunity: Option<&FaultOpportunity>,
    scenario_seed: ContentHash,
) -> Result<MappingDecision, BindingRuntimeError> {
    match binding.mapping() {
        BindingMapping::ActiveWhenTrue { invert } => match &values[0] {
            SignalValue::Bool(value) => Ok(MappingDecision::Persistent(*value != *invert)),
            _ => Err(BindingRuntimeError::MappingType),
        },
        BindingMapping::ActiveWhenEqual { value } => match &values[0] {
            SignalValue::Enum { variant, .. } => Ok(MappingDecision::Persistent(variant == value)),
            _ => Err(BindingRuntimeError::MappingType),
        },
        BindingMapping::Threshold {
            comparison,
            threshold,
            clear_threshold,
            residence_nanos,
        } => {
            let desired = if state.active {
                if let Some(clear_threshold) = clear_threshold {
                    !threshold_matches(
                        &values[0],
                        clear_threshold,
                        reverse_comparison(*comparison),
                    )?
                } else {
                    threshold_matches(&values[0], threshold, *comparison)?
                }
            } else {
                threshold_matches(&values[0], threshold, *comparison)?
            };
            if desired == state.active {
                state.pending_activation = None;
                state.pending_since_nanos = None;
                return Ok(MappingDecision::NoAction);
            }
            if state.pending_activation != Some(desired) {
                state.pending_activation = Some(desired);
                state.pending_since_nanos = Some(now);
                if *residence_nanos > 0 {
                    return Ok(MappingDecision::NoAction);
                }
            }
            if now.saturating_sub(state.pending_since_nanos.unwrap_or(now)) < *residence_nanos {
                Ok(MappingDecision::NoAction)
            } else {
                Ok(MappingDecision::Persistent(desired))
            }
        }
        BindingMapping::MapParameter { .. }
        | BindingMapping::PiecewiseParameter { .. }
        | BindingMapping::ServiceProfile { .. } => {
            if binding.effect().lifetime() == EffectLifetime::Persistent {
                Ok(MappingDecision::Persistent(true))
            } else {
                Ok(MappingDecision::Apply)
            }
        }
        BindingMapping::Hazard => {
            let SignalValue::ProbabilityMillionths(probability) = values[0] else {
                return Err(BindingRuntimeError::MappingType);
            };
            let opportunity = opportunity.ok_or(BindingRuntimeError::OpportunityRequired)?;
            let draw = exact_hazard_draw(scenario_seed, binding.id(), opportunity.id())?;
            Ok(if draw < probability {
                MappingDecision::Apply
            } else {
                MappingDecision::NoAction
            })
        }
        BindingMapping::ImpulseOnEvent => Ok(if matches!(values[0], SignalValue::Event { .. }) {
            MappingDecision::Apply
        } else {
            MappingDecision::NoAction
        }),
        BindingMapping::StateTransition { .. } => Ok(
            if matches!(
                values[0],
                SignalValue::Event { .. } | SignalValue::Enum { .. }
            ) {
                MappingDecision::Apply
            } else {
                MappingDecision::NoAction
            },
        ),
    }
}

fn exact_hazard_draw(
    scenario_seed: ContentHash,
    binding: &FaultObjectId,
    opportunity: ContentHash,
) -> Result<u32, BindingRuntimeError> {
    const WIDTH: u64 = 1_000_000;
    const MAX_ATTEMPTS: u64 = 64;
    let rejection = u64::MAX - u64::MAX % WIDTH;
    for counter in 0..MAX_ATTEMPTS {
        let material = format!(
            "seed={};binding={};opportunity={};counter={counter}",
            scenario_seed.to_hex(),
            binding.as_str(),
            opportunity.to_hex(),
        );
        let hash = ContentHash::from_canonical_material("crucible.binding-hazard.v1", &material);
        let draw = u64::from_be_bytes(
            hash.bytes[..8]
                .try_into()
                .map_err(|_| BindingRuntimeError::HazardKeyExhausted)?,
        );
        if draw < rejection {
            return u32::try_from(draw % WIDTH)
                .map_err(|_| BindingRuntimeError::HazardKeyExhausted);
        }
    }
    Err(BindingRuntimeError::HazardKeyExhausted)
}

fn map_parameter_values(
    binding: &FaultBinding,
    sampled_values: Vec<SignalValue>,
) -> Result<Vec<SignalValue>, BindingRuntimeError> {
    let BindingMapping::PiecewiseParameter {
        points,
        rounding,
        overflow,
        ..
    } = binding.mapping()
    else {
        return Ok(sampled_values);
    };
    let input = sampled_values
        .first()
        .ok_or(BindingRuntimeError::MappingType)?;
    let transfer = points
        .iter()
        .map(|point| (point.input.clone(), point.output.clone()))
        .collect::<Vec<_>>();
    match evaluate_piecewise_linear(input, &transfer, *rounding, *overflow)
        .map_err(BindingRuntimeError::Evaluation)?
    {
        EvaluatedSignal::Value(value) => Ok(vec![value]),
        EvaluatedSignal::Inactive => Err(BindingRuntimeError::MappingType),
    }
}

fn resolved_mapping_output(
    binding: &FaultBinding,
    values: &[SignalValue],
    activation_value: bool,
) -> Result<ResolvedMappingOutput, BindingRuntimeError> {
    match binding.mapping() {
        BindingMapping::ActiveWhenTrue { .. }
        | BindingMapping::ActiveWhenEqual { .. }
        | BindingMapping::Threshold { .. } => Ok(ResolvedMappingOutput::Activation {
            active: activation_value,
        }),
        BindingMapping::MapParameter { parameter }
        | BindingMapping::PiecewiseParameter { parameter, .. } => {
            Ok(ResolvedMappingOutput::Parameter {
                parameter: *parameter,
                value: values
                    .first()
                    .cloned()
                    .ok_or(BindingRuntimeError::MappingType)?,
            })
        }
        BindingMapping::Hazard => match values.first() {
            Some(SignalValue::ProbabilityMillionths(probability_millionths)) => {
                Ok(ResolvedMappingOutput::Hazard {
                    probability_millionths: *probability_millionths,
                })
            }
            _ => Err(BindingRuntimeError::MappingType),
        },
        BindingMapping::ImpulseOnEvent => match values.first() {
            Some(event @ SignalValue::Event { .. }) => Ok(ResolvedMappingOutput::Impulse {
                event: event.clone(),
            }),
            _ => Err(BindingRuntimeError::MappingType),
        },
        BindingMapping::StateTransition { transition_table } => {
            let request = values
                .first()
                .cloned()
                .ok_or(BindingRuntimeError::MappingType)?;
            let declaration = binding
                .transition_declaration()
                .ok_or(BindingRuntimeError::MappingDeclaration)?;
            let selected_transition = declaration
                .transitions
                .get(&request)
                .cloned()
                .unwrap_or_else(|| declaration.default_transition.clone());
            Ok(ResolvedMappingOutput::StateTransition {
                transition_table: transition_table.clone(),
                request,
                selected_transition,
            })
        }
        BindingMapping::ServiceProfile { service_profile } => {
            let declaration = binding
                .service_declaration()
                .ok_or(BindingRuntimeError::MappingDeclaration)?;
            Ok(ResolvedMappingOutput::ServiceProfile {
                service_profile: service_profile.clone(),
                input_contracts: declaration.inputs.clone(),
                inputs: values.to_vec(),
            })
        }
    }
}

fn reverse_comparison(comparison: ThresholdComparison) -> ThresholdComparison {
    match comparison {
        ThresholdComparison::LessThan => ThresholdComparison::GreaterThanOrEqual,
        ThresholdComparison::LessThanOrEqual => ThresholdComparison::GreaterThan,
        ThresholdComparison::GreaterThan => ThresholdComparison::LessThanOrEqual,
        ThresholdComparison::GreaterThanOrEqual => ThresholdComparison::LessThan,
    }
}

fn threshold_matches(
    value: &SignalValue,
    threshold: &SignalValue,
    comparison: ThresholdComparison,
) -> Result<bool, BindingRuntimeError> {
    let order = compare_numeric(value, threshold).map_err(BindingRuntimeError::Evaluation)?;
    Ok(match comparison {
        ThresholdComparison::LessThan => order.is_lt(),
        ThresholdComparison::LessThanOrEqual => !order.is_gt(),
        ThresholdComparison::GreaterThan => order.is_gt(),
        ThresholdComparison::GreaterThanOrEqual => !order.is_lt(),
    })
}

fn mapped_values_digest(values: &[SignalValue]) -> Result<ContentHash, BindingRuntimeError> {
    let mut bytes = Vec::new();
    for value in values {
        let encoded = encode_signal_value(value).map_err(BindingRuntimeError::Trace)?;
        if bytes
            .len()
            .checked_add(4)
            .and_then(|length| length.checked_add(encoded.len()))
            .is_none_or(|length| length > HARD_MAPPED_EFFECT_BYTES)
        {
            return Err(BindingRuntimeError::MappedValueLimit);
        }
        bytes.extend_from_slice(
            &u32::try_from(encoded.len())
                .map_err(|_| BindingRuntimeError::MappedValueLimit)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&encoded);
    }
    Ok(ContentHash::from_canonical_material(
        "crucible.binding-mapped-values.v1",
        &hex_bytes(&bytes),
    ))
}

fn sample_identity_digest(
    binding: &FaultBinding,
    values: &[SignalValue],
    mapped_digest: ContentHash,
    coordinate: FaultCoordinate,
    same_coordinate_sequence: u64,
    opportunity: Option<&FaultOpportunity>,
) -> ContentHash {
    if !values
        .iter()
        .any(|value| matches!(value, SignalValue::Event { .. }))
    {
        return mapped_digest;
    }
    let mut material = format!(
        "binding={};mapped={};virtual_nanos={};retired_instructions={:?};same_coordinate_sequence={};opportunity=",
        binding.id().as_str(),
        mapped_digest.to_hex(),
        coordinate.virtual_nanos,
        coordinate.retired_instructions,
        same_coordinate_sequence,
    );
    material.push_str(
        &opportunity
            .map(FaultOpportunity::id)
            .map_or_else(|| String::from("none"), |identity| identity.to_hex()),
    );
    ContentHash::from_canonical_material("crucible.binding-sample-identity.v1", &material)
}

fn search_decision_identity(
    binding: &FaultBinding,
    sample: ContentHash,
    coordinate: FaultCoordinate,
    same_coordinate_sequence: u64,
    transition_sequence: u64,
) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.binding-search-decision.v1",
        &format!(
            "binding={};sample={};virtual_nanos={};retired={};same_coordinate_sequence={same_coordinate_sequence};transition_sequence={transition_sequence}",
            binding.id().as_str(),
            sample.to_hex(),
            coordinate.virtual_nanos,
            coordinate
                .retired_instructions
                .map_or_else(|| String::from("none"), |value| value.to_string()),
        ),
    )
}

fn resolved_mapping_output_digest(
    output: &ResolvedMappingOutput,
) -> Result<ContentHash, BindingRuntimeError> {
    let material = match output {
        ResolvedMappingOutput::Activation { active } => format!("activation={active}"),
        ResolvedMappingOutput::Parameter { parameter, value } => format!(
            "parameter={};value={}",
            mapped_parameter_name(*parameter),
            encoded_value_material(value)?,
        ),
        ResolvedMappingOutput::Hazard {
            probability_millionths,
        } => format!("hazard={probability_millionths}"),
        ResolvedMappingOutput::Impulse { event } => {
            format!("impulse={}", encoded_value_material(event)?)
        }
        ResolvedMappingOutput::StateTransition {
            transition_table,
            request,
            selected_transition,
        } => format!(
            "state_transition={};selected={};request={}",
            transition_table.as_str(),
            selected_transition.as_str(),
            encoded_value_material(request)?,
        ),
        ResolvedMappingOutput::ServiceProfile {
            service_profile,
            input_contracts,
            inputs,
        } => format!(
            "service_profile={};contracts={};inputs={}",
            service_profile.as_str(),
            mapped_service_inputs_digest(input_contracts)?.to_hex(),
            mapped_values_digest(inputs)?.to_hex(),
        ),
    };
    Ok(ContentHash::from_canonical_material(
        "crucible.resolved-binding-output.v1",
        &material,
    ))
}

fn mapped_service_inputs_digest(
    inputs: &[ServiceProfileInput],
) -> Result<ContentHash, BindingRuntimeError> {
    let mut material = b"crucible.resolved-binding-service-inputs.v1\0".to_vec();
    for input in inputs {
        let role = input.role.as_str().as_bytes();
        let role_length =
            u64::try_from(role.len()).map_err(|_| BindingRuntimeError::MappedValueLimit)?;
        material.extend_from_slice(&role_length.to_be_bytes());
        material.extend_from_slice(role);
        let encoded = encode_signal_shape(&input.shape).map_err(BindingRuntimeError::Trace)?;
        let length =
            u64::try_from(encoded.len()).map_err(|_| BindingRuntimeError::MappedValueLimit)?;
        material.extend_from_slice(&length.to_be_bytes());
        material.extend_from_slice(&encoded);
    }
    Ok(ContentHash::from_bytes(&material))
}

fn encoded_value_material(value: &SignalValue) -> Result<String, BindingRuntimeError> {
    encode_signal_value(value)
        .map(|bytes| hex_bytes(&bytes))
        .map_err(BindingRuntimeError::Trace)
}

const fn mapped_parameter_name(parameter: MappedEffectParameter) -> &'static str {
    match parameter {
        MappedEffectParameter::Probability => "probability",
        MappedEffectParameter::DurationNanos => "duration_nanos",
        MappedEffectParameter::BitsPerSecond => "bits_per_second",
        MappedEffectParameter::BytesPerSecond => "bytes_per_second",
        MappedEffectParameter::OperationsPerSecond => "operations_per_second",
        MappedEffectParameter::CapacityRatio => "capacity_ratio",
        MappedEffectParameter::SignedOffset => "signed_offset",
        MappedEffectParameter::UnsignedCount => "unsigned_count",
    }
}

fn validate_binding_checkpoint(
    program: &SignalProgram,
    bindings: &[FaultBinding],
    scenario_seed: ContentHash,
    checkpoint: &BindingRuntimeCheckpoint,
) -> Result<(), BindingRuntimeError> {
    if checkpoint.semantic_version != FAULT_RUNTIME_STATE_VERSION
        || checkpoint.signal_program != program.id()
        || checkpoint.scenario_seed != scenario_seed
        || bindings.len() > HARD_FAULT_BINDING_LIMIT
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
        .validate_for_program(program)
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
    if checkpoint
        .dynamic_membership
        .keys()
        .collect::<std::collections::BTreeSet<_>>()
        != dynamic_ids
        || checkpoint.consumed_opportunities.len() > HARD_CONSUMED_OPPORTUNITY_SCOPES
        || checkpoint.search_overrides.len() > HARD_SEARCH_OVERRIDES
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
            || state.search_choice_count > HARD_SEARCH_CHOICES_PER_STATE
        {
            return Err(BindingRuntimeError::CheckpointState);
        }
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
                ) && resolved_mapping_output_digest(output)? == *digest => {}
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
    Ok(())
}

fn validate_checkpoint_mapping_values(
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
        (_, None) => state.sample_count == 0 && state.mapped_values.is_empty(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(BindingRuntimeError::CheckpointState)
    }
}

fn mapping_output_matches(
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

fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

/// Signal-to-effect runtime failure.
#[derive(Debug)]
pub enum BindingRuntimeError {
    /// Binding IDs are not unique.
    DuplicateBinding,
    /// Scenario exceeds the compiled binding-count ceiling.
    BindingLimit,
    /// One boundary exceeded the hard prepared-action ceiling.
    ActionLimit,
    /// Retained sample payloads exceeded the per-boundary byte ceiling.
    RetainedSampleLimit,
    /// Search override state exceeds the compiled ceiling.
    SearchOverrideLimit,
    /// Search mutation was not materialized into a concrete program/artifact.
    UnmaterializedSearchMutation,
    /// A binding was admitted against a different signal program.
    BindingProgramMismatch,
    /// Runtime state omitted one admitted binding.
    MissingState(FaultObjectId),
    /// Dynamic membership named no admitted binding.
    MissingBinding(FaultObjectId),
    /// Program no longer exposes one admitted signal.
    MissingSignal(SignalId),
    /// Active dynamic membership had no retained mapped value state.
    MissingMappedValues(FaultObjectId),
    /// A dynamic membership update named a static binding.
    NotDynamic(FaultObjectId),
    /// Dynamic path membership contained a non-network target.
    DynamicTargetAdapter,
    /// Dynamic path membership contained a target kind illegal for its effect.
    DynamicTargetKind,
    /// Dynamic membership became empty when the authored selector forbids it.
    DynamicTargetEmpty,
    /// Dynamic membership path, version, sequence, or evidence is invalid.
    DynamicTransitionIdentity,
    /// A required signal evaluated inactive.
    InactiveSignal(SignalId),
    /// An adapter delivered an older opportunity sequence for the same scope.
    NonMonotoneOpportunity,
    /// An adapter opportunity arrived before its same-time boundary completed.
    OpportunityBeforeBoundary,
    /// One scope reused an opportunity sequence for different immutable input.
    OpportunitySequenceCollision,
    /// Consumed opportunity scope state reached its hard ceiling.
    OpportunityStateLimit,
    /// Mapping received a value that contradicted its admitted type.
    MappingType,
    /// Runtime omitted an admitted named mapping declaration.
    MappingDeclaration,
    /// An opportunity-domain signal was sampled without an opportunity.
    OpportunityRequired,
    /// A node-counter signal lacked a retired-instruction coordinate.
    CounterCoordinateRequired,
    /// A spatial output was not projected through an explicit field-sample node.
    UnprojectedSpatialSignal,
    /// Event-domain evaluation omitted explicit parent provenance.
    EventParentRequired,
    /// Canonical mapped-value framing exceeded its integer count.
    MappedValueLimit,
    /// Keyed hazard rejection sampling exhausted its bounded counter space.
    HazardKeyExhausted,
    /// A per-binding observation counter exhausted `u64`.
    ObservationSequenceOverflow,
    /// Search candidate identity, bound, or override is inconsistent.
    SearchChoice,
    /// Search decisions reached the compiled per-state ceiling.
    SearchChoiceLimit,
    /// Locked replay ended before consuming every supplied override.
    UnusedSearchOverride,
    /// A required cadence or residence wakeup exceeded virtual time.
    WakeupOverflow,
    /// Scheduler boundary moved backward.
    NonMonotoneBoundary,
    /// Runtime is terminally poisoned after an impossible rollback failure.
    Poisoned,
    /// Checkpoint version, program, or binding identity differs.
    CheckpointIdentity,
    /// Checkpoint mutable state is incomplete or internally inconsistent.
    CheckpointState,
    /// Nested program validation failed while deriving runtime coordinates.
    Program(SignalProgramError),
    /// Nested signal evaluation failed.
    Evaluation(SignalEvaluationError),
    /// Evaluator rollback failed after a rejected atomic boundary.
    Rollback(SignalEvaluationError),
    /// Nested trace value codec failed.
    Trace(TraceError),
    /// Nested active-table or transition state failed.
    Runtime(FaultRuntimeError),
    /// The production adapter rejected an atomic action batch.
    AdapterRejected(Box<RejectedActionBatch>),
    /// Production adapter returned an incomplete or mismatched result batch.
    AdapterResult,
    /// Production adapter could not discard a prepared transaction.
    AdapterAbort(FaultRuntimeError),
    /// Production adapter commit visibility became ambiguous or partial.
    AdapterCommit(FaultRuntimeError),
}

impl fmt::Display for BindingRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fault binding evaluation failed: {self:?}")
    }
}

impl Error for BindingRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Program(error) => Some(error),
            Self::Evaluation(error) | Self::Rollback(error) => Some(error),
            Self::Trace(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::AdapterAbort(error) => Some(error),
            Self::AdapterCommit(error) => Some(error),
            Self::AdapterRejected(error) => Some(&error.error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "binding_runtime_test.rs"]
mod tests;
