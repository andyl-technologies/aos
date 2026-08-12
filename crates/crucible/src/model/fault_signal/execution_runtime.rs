//! Complete signal-to-adapter fault execution ownership.
//!
//! [`FaultExecutionRuntime`] is the production bridge between a scenario's
//! admitted signal program, binding evaluation, and the three transactional
//! adapter families. It owns one atomic checkpoint surface so callers never
//! persist evaluator state without the corresponding adapter state.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use super::*;

/// The complete live signal-driven fault engine for one non-empty plan.
pub struct FaultExecutionRuntime<'a> {
    signal_plan: ContentHash,
    resource_limits: FaultResourceLimits,
    program: &'a SignalProgram,
    bindings: Vec<FaultBinding>,
    scenario_seed: ContentHash,
    binding_runtime: FaultBindingRuntime<'a>,
    adapters: TransactionalFaultAdapters,
    replay: Option<ResolvedEffectTrace>,
    recorded_work_items: Vec<ResolvedReplayWorkItem>,
    retained_effects: BTreeSet<ContentHash>,
    branch_parent: Option<ContentHash>,
}

impl<'a> FaultExecutionRuntime<'a> {
    /// Admits live capabilities and creates an empty execution continuation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if the plan is empty or has more than
    /// one program, a live capability is absent, or evaluator state cannot be
    /// initialized.
    pub fn new(
        plan: &'a FaultSignalPlan,
        artifacts: &'a dyn SignalArtifactProvider,
        boundary: SignalBoundarySnapshot,
        scenario_seed: ContentHash,
        manifests: FaultAdapterManifests,
    ) -> Result<Self, FaultExecutionError> {
        let program = sole_program(plan)?;
        let resource_limits = plan.resource_limits();
        admit_manifests(plan.bindings(), &manifests)?;
        let bindings = plan.bindings().to_vec();
        let binding_runtime = FaultBindingRuntime::new(
            program,
            bindings.clone(),
            artifacts,
            boundary,
            scenario_seed,
            resource_limits,
        )?;
        let adapters = TransactionalFaultAdapters::new(manifests, resource_limits)?;
        Ok(Self {
            signal_plan: plan.id(),
            resource_limits,
            program,
            bindings,
            scenario_seed,
            binding_runtime,
            adapters,
            replay: None,
            recorded_work_items: Vec::new(),
            retained_effects: BTreeSet::new(),
            branch_parent: None,
        })
    }

    /// Restores one authenticated evaluator-and-adapter continuation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if identities, capabilities, canonical
    /// bytes, or the duplicated binding/adapter contribution views disagree.
    pub fn restore(
        plan: &'a FaultSignalPlan,
        artifacts: &'a dyn SignalArtifactProvider,
        scenario_seed: ContentHash,
        manifests: FaultAdapterManifests,
        checkpoint: &FaultRuntimeCheckpoint,
    ) -> Result<Self, FaultExecutionError> {
        let program = sole_program(plan)?;
        checkpoint.validate(plan, scenario_seed)?;
        if checkpoint.poisoned {
            return Err(FaultExecutionError::Poisoned);
        }
        admit_manifests(plan.bindings(), &manifests)?;
        let bindings = plan.bindings().to_vec();
        let binding_runtime = FaultBindingRuntime::restore(
            program,
            bindings.clone(),
            artifacts,
            scenario_seed,
            plan.resource_limits(),
            &checkpoint.binding_runtime,
        )?;
        let adapters = TransactionalFaultAdapters::restore(
            manifests,
            checkpoint.adapters.clone(),
            plan.resource_limits(),
        )?;
        validate_contribution_mirror(binding_runtime.active(), &adapters)?;
        Ok(Self {
            signal_plan: plan.id(),
            resource_limits: plan.resource_limits(),
            program,
            bindings,
            scenario_seed,
            binding_runtime,
            adapters,
            replay: checkpoint.replay.clone(),
            recorded_work_items: checkpoint.recorded_work_items.clone(),
            retained_effects: checkpoint.retained_effects.clone(),
            branch_parent: checkpoint.branch_parent,
        })
    }

    /// Evaluates every due non-opportunity binding at one scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if evaluation or an atomic production
    /// adapter transaction fails.
    pub fn evaluate_boundary(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
    ) -> Result<BindingEvaluation, FaultExecutionError> {
        Ok(self.binding_runtime.evaluate_boundary_traced(
            coordinate,
            same_coordinate_sequence,
            &mut self.adapters,
            self.replay.as_mut(),
            &mut self.recorded_work_items,
        )?)
    }

    /// Evaluates due bindings and atomically mirrors them into a live backend.
    ///
    /// The canonical adapter ledger and `backend` prepare the same ordered
    /// action batch. Successful observations come from `backend`; a rejection
    /// restores the canonical ledger to its exact before-state.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if evaluation fails, either participant
    /// rejects the batch, their action identities differ, or rollback fails.
    pub(crate) fn evaluate_boundary_with_backend<B>(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        backend: &mut B,
    ) -> Result<BindingEvaluation, FaultExecutionError>
    where
        B: FaultActionSink,
    {
        let mut sink = MirroredFaultActionSink::new(&mut self.adapters, backend);
        Ok(self.binding_runtime.evaluate_boundary_traced(
            coordinate,
            same_coordinate_sequence,
            &mut sink,
            self.replay.as_mut(),
            &mut self.recorded_work_items,
        )?)
    }

    /// Evaluates every binding matching one exact production opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if opportunity identity, evaluation, or
    /// atomic adapter application fails.
    pub fn evaluate_opportunity(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
    ) -> Result<BindingEvaluation, FaultExecutionError> {
        Ok(self.binding_runtime.evaluate_opportunity_traced(
            opportunity,
            same_coordinate_sequence,
            &mut self.adapters,
            self.replay.as_mut(),
            &mut self.recorded_work_items,
        )?)
    }

    /// Evaluates one opportunity and mirrors it into a live backend atomically.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] under the same conditions as
    /// [`Self::evaluate_boundary_with_backend`], plus invalid opportunity
    /// identity, target, or phase.
    pub(crate) fn evaluate_opportunity_with_backend<B>(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
        backend: &mut B,
    ) -> Result<BindingEvaluation, FaultExecutionError>
    where
        B: FaultActionSink,
    {
        let mut sink = MirroredFaultActionSink::new(&mut self.adapters, backend);
        Ok(self.binding_runtime.evaluate_opportunity_traced(
            opportunity,
            same_coordinate_sequence,
            &mut sink,
            self.replay.as_mut(),
            &mut self.recorded_work_items,
        )?)
    }

    fn preview_boundary(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
    ) -> Result<BindingEvaluation, FaultExecutionError> {
        Ok(self.binding_runtime.preview_boundary_traced(
            coordinate,
            same_coordinate_sequence,
            &mut self.adapters,
            self.replay.as_mut(),
        )?)
    }

    fn preview_opportunity(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
    ) -> Result<BindingEvaluation, FaultExecutionError> {
        Ok(self.binding_runtime.preview_opportunity_traced(
            opportunity,
            same_coordinate_sequence,
            &mut self.adapters,
            self.replay.as_mut(),
        )?)
    }

    /// Installs an unconsumed authoritative replay trace.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the trace is malformed, oversized,
    /// already consumed, or incompatible with outcome-only network replay.
    pub fn install_replay(
        &mut self,
        trace: ResolvedEffectTrace,
    ) -> Result<(), FaultExecutionError> {
        trace.validate(self.resource_limits)?;
        if trace.cursor != 0 {
            return Err(FaultRuntimeError::InvalidReplayTrace.into());
        }
        let previous = self.replay.replace(trace);
        if let Err(error) = self.checkpoint() {
            self.replay = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Requires the installed replay trace to be completely consumed.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when no replay is installed or records remain.
    pub fn verify_replay_exhausted(&self) -> Result<(), FaultExecutionError> {
        self.replay
            .as_ref()
            .ok_or(FaultRuntimeError::InvalidReplayTrace)?
            .require_exhausted()
            .map_err(FaultExecutionError::from)
    }

    /// Returns every committed effect as a fresh replay trace.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if the retained recording violates the
    /// selected replay mode or the plan's resolved-record limit.
    pub fn recorded_trace(
        &self,
        mode: FaultReplayMode,
    ) -> Result<ResolvedEffectTrace, FaultExecutionError> {
        let work_items = match mode {
            FaultReplayMode::OutcomeOnlyNetwork(_) => self
                .recorded_work_items
                .iter()
                .filter(|item| item.network_frame_key.is_some())
                .cloned()
                .collect(),
            FaultReplayMode::RecomputedCause | FaultReplayMode::LockedEffect => {
                self.recorded_work_items.clone()
            }
        };
        let trace = ResolvedEffectTrace {
            mode,
            work_items,
            cursor: 0,
        };
        trace.validate(self.resource_limits)?;
        Ok(trace)
    }

    /// Replaces one-boundary-delayed production telemetry.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if the telemetry snapshot exceeds the
    /// admitted resource contract.
    pub fn set_boundary_snapshot(
        &mut self,
        boundary: SignalBoundarySnapshot,
    ) -> Result<(), FaultExecutionError> {
        self.binding_runtime.set_boundary_snapshot(boundary)?;
        Ok(())
    }

    /// Returns the committed state for one production adapter family.
    #[must_use]
    pub const fn adapter(&self, adapter: FaultAdapter) -> &TransactionalAdapterRuntime {
        self.adapters.adapter(adapter)
    }

    /// Captures the evaluator, bindings, adapters, replay, and branch state.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if canonical state cannot be encoded or
    /// if a transaction is still in flight.
    pub fn checkpoint(&self) -> Result<FaultRuntimeCheckpoint, FaultExecutionError> {
        let checkpoint = FaultRuntimeCheckpoint {
            semantic_version: FAULT_RUNTIME_STATE_VERSION,
            signal_plan: self.signal_plan,
            resource_limits: self.resource_limits,
            binding_runtime: self.binding_runtime.checkpoint()?,
            adapters: self.adapters.checkpoints()?,
            replay: self.replay.clone(),
            recorded_work_items: self.recorded_work_items.clone(),
            retained_effects: self.retained_effects.clone(),
            branch_parent: self.branch_parent,
            poisoned: false,
        };
        let _ = checkpoint.canonical_bytes()?;
        Ok(checkpoint)
    }

    /// Returns the exact program identity owned by this continuation.
    #[must_use]
    pub const fn program_id(&self) -> ContentHash {
        self.program.id()
    }

    /// Returns the scenario seed identity owned by this continuation.
    #[must_use]
    pub const fn scenario_seed(&self) -> ContentHash {
        self.scenario_seed
    }

    /// Returns the canonical admitted binding contracts.
    #[must_use]
    pub fn bindings(&self) -> &[FaultBinding] {
        &self.bindings
    }
}

/// An owned, cloneable fault continuation suitable for scheduler state.
///
/// The evaluator itself borrows its immutable program and artifact provider.
/// This owner avoids a self-referential scheduler field by restoring that
/// evaluator from the authenticated checkpoint for each exact boundary, then
/// replacing the checkpoint only after the complete adapter transaction commits.
#[derive(Clone)]
pub struct OwnedFaultExecutionRuntime {
    plan: FaultSignalPlan,
    artifacts: Arc<dyn SignalArtifactProvider>,
    scenario_seed: ContentHash,
    manifests: FaultAdapterManifests,
    checkpoint: FaultRuntimeCheckpoint,
}

impl OwnedFaultExecutionRuntime {
    /// Creates an owned continuation from one admitted nonempty plan.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the plan, evaluator state, or live
    /// adapter capabilities cannot be admitted.
    pub fn new(
        plan: FaultSignalPlan,
        artifacts: Arc<dyn SignalArtifactProvider>,
        boundary: SignalBoundarySnapshot,
        scenario_seed: ContentHash,
        manifests: FaultAdapterManifests,
    ) -> Result<Self, FaultExecutionError> {
        let runtime = FaultExecutionRuntime::new(
            &plan,
            artifacts.as_ref(),
            boundary,
            scenario_seed,
            manifests.clone(),
        )?;
        let checkpoint = runtime.checkpoint()?;
        drop(runtime);
        Ok(Self {
            plan,
            artifacts,
            scenario_seed,
            manifests,
            checkpoint,
        })
    }

    /// Restores an owned continuation from authenticated runtime state.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the checkpoint does not match the
    /// plan, seed, evaluator, or admitted adapter capabilities.
    pub fn restore(
        plan: FaultSignalPlan,
        artifacts: Arc<dyn SignalArtifactProvider>,
        scenario_seed: ContentHash,
        manifests: FaultAdapterManifests,
        checkpoint: FaultRuntimeCheckpoint,
    ) -> Result<Self, FaultExecutionError> {
        if checkpoint.poisoned {
            checkpoint.validate(&plan, scenario_seed)?;
            admit_manifests(plan.bindings(), &manifests)?;
            return Ok(Self {
                plan,
                artifacts,
                scenario_seed,
                manifests,
                checkpoint,
            });
        }
        let runtime = FaultExecutionRuntime::restore(
            &plan,
            artifacts.as_ref(),
            scenario_seed,
            manifests.clone(),
            &checkpoint,
        )?;
        drop(runtime);
        Ok(Self {
            plan,
            artifacts,
            scenario_seed,
            manifests,
            checkpoint,
        })
    }

    /// Evaluates and commits every due boundary binding through a live backend.
    ///
    /// The stored continuation changes only after both the canonical adapter
    /// ledger and `backend` have committed the same ordered action batch.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] for restore, evaluation, adapter, or
    /// checkpoint failure. A failure leaves the prior continuation intact.
    pub fn evaluate_boundary_with_backend<B>(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        backend: &mut B,
    ) -> Result<BindingEvaluation, FaultExecutionError>
    where
        B: FaultActionSink,
    {
        self.preflight_checkpoint_capacity(coordinate, same_coordinate_sequence, None)?;
        let mut runtime = FaultExecutionRuntime::restore(
            &self.plan,
            self.artifacts.as_ref(),
            self.scenario_seed,
            self.manifests.clone(),
            &self.checkpoint,
        )?;
        let evaluation = match runtime.evaluate_boundary_with_backend(
            coordinate,
            same_coordinate_sequence,
            backend,
        ) {
            Ok(evaluation) => evaluation,
            Err(error) => {
                if terminal_execution_error(&error) {
                    self.checkpoint.poisoned = true;
                }
                return Err(error);
            }
        };
        let checkpoint = match runtime.checkpoint() {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.checkpoint.poisoned = true;
                return Err(error);
            }
        };
        self.checkpoint = checkpoint;
        Ok(evaluation)
    }

    /// Evaluates one boundary against the canonical production adapter ledger
    /// without changing this continuation or an external backend.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the current checkpoint cannot be
    /// restored or the deterministic evaluation is rejected.
    pub fn preview_boundary(
        &self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
    ) -> Result<BindingEvaluation, FaultExecutionError> {
        let mut runtime = FaultExecutionRuntime::restore(
            &self.plan,
            self.artifacts.as_ref(),
            self.scenario_seed,
            self.manifests.clone(),
            &self.checkpoint,
        )?;
        runtime.preview_boundary(coordinate, same_coordinate_sequence)
    }

    /// Replaces the one-boundary-delayed production telemetry snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the current continuation cannot be
    /// restored, the snapshot exceeds admitted bounds, or the updated state
    /// cannot be checkpointed.
    pub fn set_boundary_snapshot(
        &mut self,
        boundary: SignalBoundarySnapshot,
    ) -> Result<(), FaultExecutionError> {
        let mut runtime = FaultExecutionRuntime::restore(
            &self.plan,
            self.artifacts.as_ref(),
            self.scenario_seed,
            self.manifests.clone(),
            &self.checkpoint,
        )?;
        runtime.set_boundary_snapshot(boundary)?;
        self.checkpoint = runtime.checkpoint()?;
        Ok(())
    }

    /// Evaluates and commits one exact opportunity through a live backend.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] under the same transactional rules as
    /// [`Self::evaluate_boundary_with_backend`].
    pub fn evaluate_opportunity_with_backend<B>(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
        backend: &mut B,
    ) -> Result<BindingEvaluation, FaultExecutionError>
    where
        B: FaultActionSink,
    {
        self.preflight_checkpoint_capacity(
            opportunity.coordinate(),
            same_coordinate_sequence,
            Some(opportunity),
        )?;
        let mut runtime = FaultExecutionRuntime::restore(
            &self.plan,
            self.artifacts.as_ref(),
            self.scenario_seed,
            self.manifests.clone(),
            &self.checkpoint,
        )?;
        let evaluation = match runtime.evaluate_opportunity_with_backend(
            opportunity,
            same_coordinate_sequence,
            backend,
        ) {
            Ok(evaluation) => evaluation,
            Err(error) => {
                if terminal_execution_error(&error) {
                    self.checkpoint.poisoned = true;
                }
                return Err(error);
            }
        };
        let checkpoint = match runtime.checkpoint() {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.checkpoint.poisoned = true;
                return Err(error);
            }
        };
        self.checkpoint = checkpoint;
        Ok(evaluation)
    }

    fn preflight_checkpoint_capacity(
        &self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        opportunity: Option<&FaultOpportunity>,
    ) -> Result<(), FaultExecutionError> {
        let mut runtime = FaultExecutionRuntime::restore(
            &self.plan,
            self.artifacts.as_ref(),
            self.scenario_seed,
            self.manifests.clone(),
            &self.checkpoint,
        )?;
        let evaluation = match opportunity {
            Some(opportunity) => {
                runtime.preview_opportunity(opportunity, same_coordinate_sequence)?
            }
            None => runtime.preview_boundary(coordinate, same_coordinate_sequence)?,
        };
        let mut candidate = runtime.checkpoint()?;
        let derivation = ContentHash::from_bytes(b"checkpoint-capacity-preflight-derivation");
        let precondition = ContentHash::from_bytes(b"checkpoint-capacity-preflight-before");
        let evidence = ContentHash::from_bytes(b"checkpoint-capacity-preflight-evidence");
        let mut records = Vec::with_capacity(evaluation.actions.len());
        for action in &evaluation.actions {
            records.push(
                ResolvedEffectRecord::from_committed_action(
                    action,
                    opportunity,
                    same_coordinate_sequence,
                    derivation,
                    Some(precondition),
                    evidence,
                )
                .map_err(FaultRuntimeError::Contract)?,
            );
        }
        candidate
            .recorded_work_items
            .push(ResolvedReplayWorkItem::new(
                coordinate,
                same_coordinate_sequence,
                opportunity,
                derivation,
                records,
            )?);
        let _ = candidate.canonical_bytes()?;
        Ok(())
    }

    /// Evaluates one opportunity against the canonical production adapter
    /// ledger without changing this continuation or an external backend.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the current checkpoint cannot be
    /// restored or the deterministic evaluation is rejected.
    pub fn preview_opportunity(
        &self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
    ) -> Result<BindingEvaluation, FaultExecutionError> {
        let mut runtime = FaultExecutionRuntime::restore(
            &self.plan,
            self.artifacts.as_ref(),
            self.scenario_seed,
            self.manifests.clone(),
            &self.checkpoint,
        )?;
        runtime.preview_opportunity(opportunity, same_coordinate_sequence)
    }

    /// Returns the current authenticated continuation.
    #[must_use]
    pub const fn checkpoint(&self) -> &FaultRuntimeCheckpoint {
        &self.checkpoint
    }

    /// Installs a fresh authoritative replay trace into this continuation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the trace is invalid or the updated
    /// complete checkpoint exceeds its resource contract.
    pub fn install_replay(
        &mut self,
        trace: ResolvedEffectTrace,
    ) -> Result<(), FaultExecutionError> {
        trace.validate(self.plan.resource_limits())?;
        if trace.cursor != 0 {
            return Err(FaultRuntimeError::InvalidReplayTrace.into());
        }
        let mut candidate = self.checkpoint.clone();
        candidate.replay = Some(trace);
        let _ = candidate.canonical_bytes()?;
        self.checkpoint = candidate;
        Ok(())
    }

    /// Requires all installed replay records to have been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when no trace is installed or records remain.
    pub fn verify_replay_exhausted(&self) -> Result<(), FaultExecutionError> {
        self.checkpoint
            .replay
            .as_ref()
            .ok_or(FaultRuntimeError::InvalidReplayTrace)?
            .require_exhausted()
            .map_err(FaultExecutionError::from)
    }

    /// Returns all committed effects as an unconsumed replay trace.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the selected mode rejects a record.
    pub fn recorded_trace(
        &self,
        mode: FaultReplayMode,
    ) -> Result<ResolvedEffectTrace, FaultExecutionError> {
        let work_items = match mode {
            FaultReplayMode::OutcomeOnlyNetwork(_) => self
                .checkpoint
                .recorded_work_items
                .iter()
                .filter(|item| item.network_frame_key.is_some())
                .cloned()
                .collect(),
            FaultReplayMode::RecomputedCause | FaultReplayMode::LockedEffect => {
                self.checkpoint.recorded_work_items.clone()
            }
        };
        let trace = ResolvedEffectTrace {
            mode,
            work_items,
            cursor: 0,
        };
        trace.validate(self.plan.resource_limits())?;
        Ok(trace)
    }

    /// Returns whether backend visibility became ambiguous and execution ended.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.checkpoint.poisoned
    }

    /// Permanently poisons the continuation after ambiguous external visibility.
    ///
    /// Production owners call this when the fault adapter committed but a
    /// coupled scheduler or device mutation could not be proven complete. A
    /// poisoned continuation rejects every subsequent evaluation and cannot be
    /// restored as runnable state.
    pub fn poison(&mut self) {
        self.checkpoint.poisoned = true;
    }

    /// Returns the admitted signal and binding plan.
    #[must_use]
    pub const fn plan(&self) -> &FaultSignalPlan {
        &self.plan
    }

    /// Returns the authoritative scenario seed used for keyed effect choices.
    #[must_use]
    pub const fn scenario_seed(&self) -> ContentHash {
        self.scenario_seed
    }
}

impl fmt::Debug for OwnedFaultExecutionRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedFaultExecutionRuntime")
            .field("plan", &self.plan.id())
            .field("scenario_seed", &self.scenario_seed)
            .field("manifests", &self.manifests)
            .field("checkpoint", &self.checkpoint)
            .finish_non_exhaustive()
    }
}

fn sole_program(plan: &FaultSignalPlan) -> Result<&SignalProgram, FaultExecutionError> {
    match plan.programs() {
        [program] => Ok(program),
        [] => Err(FaultExecutionError::EmptyPlan),
        _ => Err(FaultExecutionError::ProgramCardinality),
    }
}

fn admit_manifests(
    bindings: &[FaultBinding],
    manifests: &FaultAdapterManifests,
) -> Result<(), FaultExecutionError> {
    for (adapter, manifest) in [
        (FaultAdapter::Network, &manifests.network),
        (FaultAdapter::Storage, &manifests.storage),
        (FaultAdapter::Node, &manifests.node),
    ] {
        let family = bindings
            .iter()
            .filter(|binding| binding.effect().kind().descriptor().adapter == adapter)
            .cloned()
            .collect::<Vec<_>>();
        manifest.admit(&family)?;
    }
    Ok(())
}

fn validate_contribution_mirror(
    binding: &ActiveContributionTable,
    adapters: &TransactionalFaultAdapters,
) -> Result<(), FaultExecutionError> {
    for adapter in [
        FaultAdapter::Network,
        FaultAdapter::Storage,
        FaultAdapter::Node,
    ] {
        let expected = binding
            .composition_groups()
            .into_iter()
            .filter(|group| group.effect.descriptor().adapter == adapter)
            .collect::<Vec<_>>();
        if expected != adapters.adapter(adapter).composition_groups() {
            return Err(FaultExecutionError::ContributionMirror);
        }
    }
    Ok(())
}

/// Failure to admit, evaluate, apply, checkpoint, or restore fault execution.
#[derive(Debug)]
pub enum FaultExecutionError {
    /// The scenario contains no signal program and needs no execution runtime.
    EmptyPlan,
    /// The scenario violates the closed one-program public schema.
    ProgramCardinality,
    /// Binding evaluation or evaluator state failed.
    Binding(BindingRuntimeError),
    /// Production adapter, checkpoint, replay, or capability state failed.
    Runtime(FaultRuntimeError),
    /// Binding and adapter checkpoints disagree about committed contributions.
    ContributionMirror,
    /// Empty-plan state and checkpoint runtime presence disagree.
    CheckpointPresence,
    /// A prior backend transaction had ambiguous or partial visibility.
    Poisoned,
}

impl From<BindingRuntimeError> for FaultExecutionError {
    fn from(value: BindingRuntimeError) -> Self {
        Self::Binding(value)
    }
}

impl From<FaultRuntimeError> for FaultExecutionError {
    fn from(value: FaultRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

impl fmt::Display for FaultExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fault execution failed: {self:?}")
    }
}

impl Error for FaultExecutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Binding(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::EmptyPlan
            | Self::ProgramCardinality
            | Self::ContributionMirror
            | Self::CheckpointPresence
            | Self::Poisoned => None,
        }
    }
}

fn terminal_execution_error(error: &FaultExecutionError) -> bool {
    matches!(
        error,
        FaultExecutionError::Poisoned
            | FaultExecutionError::Binding(
                BindingRuntimeError::AdapterAbort(_)
                    | BindingRuntimeError::AdapterCommit(_)
                    | BindingRuntimeError::Rollback(_)
                    | BindingRuntimeError::Poisoned
            )
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    struct NoArtifacts;

    impl SignalArtifactProvider for NoArtifacts {
        fn inverse_cdf_table(
            &self,
            content: &ContentHash,
        ) -> Result<InverseCdfTable, SignalEvaluationError> {
            Err(SignalEvaluationError::ArtifactContentMismatch(*content))
        }

        fn evaluate_artifact_source(
            &self,
            node: &SignalNode,
            _source: &SignalSourceSpecification,
            _coordinate: &SignalCoordinate,
            _same_coordinate_sequence: u64,
            _choice: &SignalChoiceContext,
            _inputs: &[EvaluatedSignal],
            _resource_limits: FaultResourceLimits,
        ) -> Result<EvaluatedSignal, SignalEvaluationError> {
            Err(SignalEvaluationError::ArtifactSourceRequired(
                node.id.clone(),
            ))
        }
    }

    fn object_id(value: &str) -> FaultObjectId {
        FaultObjectId::parse(value)
            .unwrap_or_else(|error| panic!("test object ID must be valid: {error}"))
    }

    fn signal_id(value: &str) -> SignalId {
        SignalId::parse(value)
            .unwrap_or_else(|error| panic!("test signal ID must be valid: {error}"))
    }

    fn manifest(adapter: FaultAdapter) -> FaultCapabilityManifest {
        FaultCapabilityManifest {
            backend: object_id(match adapter {
                FaultAdapter::Network => "network-production",
                FaultAdapter::Storage => "storage-production",
                FaultAdapter::Node => "node-production",
            }),
            capabilities: EffectKind::all()
                .iter()
                .filter(|kind| kind.descriptor().adapter == adapter)
                .map(|kind| {
                    FaultCapabilityId::parse(kind.descriptor().capability)
                        .unwrap_or_else(|error| panic!("registry capability: {error}"))
                })
                .collect::<BTreeSet<_>>(),
            bounds: BTreeMap::new(),
        }
    }

    fn manifests() -> FaultAdapterManifests {
        FaultAdapterManifests {
            network: manifest(FaultAdapter::Network),
            storage: manifest(FaultAdapter::Storage),
            node: manifest(FaultAdapter::Node),
        }
    }

    fn test_plan() -> FaultSignalPlan {
        let output = signal_id("output");
        let program = SignalProgram::new(
            vec![SignalNode {
                id: output.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
                    .unwrap_or_else(|error| panic!("test shape: {error}")),
                inputs: Vec::new(),
                kind: SignalNodeKind::Constant {
                    value: SignalValue::Bool(true),
                },
            }],
            vec![output.clone()],
            SignalResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test program: {error}"));
        let targets = ResolvedTargetSet::new(
            vec![ResolvedFaultTarget::NetworkSegment {
                segment: object_id("segment-a"),
                direction: FaultDirection::AToB,
            }],
            false,
        )
        .unwrap_or_else(|error| panic!("test targets: {error}"));
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state: NetworkAvailabilityState::Down,
                queued_policy: NetworkInFlightPolicy::Drop,
                in_flight_policy: NetworkInFlightPolicy::Drop,
            }),
        )
        .unwrap_or_else(|error| panic!("test effect: {error}"));
        let binding = FaultBinding::new(
            object_id("network-outage"),
            vec![output],
            BindingSampling::AtBoundary,
            BindingMapping::ActiveWhenTrue { invert: false },
            TargetSelector::Exact(targets),
            BTreeSet::from([FaultPhase::Admit]),
            effect,
            None,
            BindingSearchPolicy::Fixed,
            BindingObservabilityPolicy {
                samples: SampleObservation::ChangesAndEffects,
                record_inactive_opportunities: false,
                retain_mapped_values: true,
            },
            &program,
        )
        .unwrap_or_else(|error| panic!("test binding: {error}"));
        FaultSignalPlan::new(vec![program], vec![binding], FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("test plan: {error}"))
    }

    fn network_outcome_plan() -> FaultSignalPlan {
        let output = signal_id("frame-effect");
        let program = SignalProgram::new(
            vec![SignalNode {
                id: output.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(
                    SignalValueType::ProbabilityMillionths,
                    SignalUnit::ProbabilityMillionths,
                    0,
                )
                .unwrap_or_else(|error| panic!("test shape: {error}")),
                inputs: Vec::new(),
                kind: SignalNodeKind::Constant {
                    value: SignalValue::ProbabilityMillionths(1_000_000),
                },
            }],
            vec![output.clone()],
            SignalResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test program: {error}"));
        let targets = ResolvedTargetSet::new(
            vec![ResolvedFaultTarget::NetworkSegment {
                segment: object_id("segment-a"),
                direction: FaultDirection::AToB,
            }],
            false,
        )
        .unwrap_or_else(|error| panic!("test targets: {error}"));
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Opportunity,
            EffectSpecification::Network(NetworkEffectSpecification::Jitter {
                maximum_nanos: PositiveU64::new("maximum_nanos", 5)
                    .unwrap_or_else(|error| panic!("test jitter: {error}")),
                distribution: NetworkDistribution::Uniform,
                distribution_lookup: None,
            }),
        )
        .unwrap_or_else(|error| panic!("test effect: {error}"));
        let binding = FaultBinding::new(
            object_id("frame-delay"),
            vec![output],
            BindingSampling::AtOpportunity,
            BindingMapping::Hazard,
            TargetSelector::Exact(targets),
            BTreeSet::from([FaultPhase::Resolve]),
            effect,
            Some(OpportunityFilter {
                adapter: FaultAdapter::Network,
                operations: OperationSet::new(vec![FaultOperation::NetworkTraverse])
                    .unwrap_or_else(|error| panic!("test operation filter: {error}")),
                phases: BTreeSet::from([FaultPhase::Resolve]),
                target_kinds: BTreeSet::from([FaultTargetKind::NetworkSegment]),
            }),
            BindingSearchPolicy::Fixed,
            BindingObservabilityPolicy {
                samples: SampleObservation::ChangesAndEffects,
                record_inactive_opportunities: false,
                retain_mapped_values: true,
            },
            &program,
        )
        .unwrap_or_else(|error| panic!("test binding: {error}"));
        FaultSignalPlan::new(vec![program], vec![binding], FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("test plan: {error}"))
    }

    fn frame_opportunity(coordinate: FaultCoordinate, producer_sequence: u64) -> FaultOpportunity {
        frame_opportunity_with_operation(
            coordinate,
            producer_sequence,
            FaultOperation::NetworkTraverse,
        )
    }

    fn frame_opportunity_with_operation(
        coordinate: FaultCoordinate,
        producer_sequence: u64,
        operation: FaultOperation,
    ) -> FaultOpportunity {
        FaultOpportunity::new(
            ResolvedFaultTarget::NetworkSegment {
                segment: object_id("segment-a"),
                direction: FaultDirection::AToB,
            },
            operation,
            FaultPhase::Resolve,
            coordinate,
            producer_sequence,
            Some(FaultDirection::AToB),
            OpportunityPayload::NetworkFrame {
                producer: object_id("sender"),
                destination: object_id("receiver"),
                producer_sequence,
                protocol_expansion_path: Vec::new(),
                generated_response_depth: 0,
                generated_response_cause: None,
                forwarding_mutation_path: Vec::new(),
                length_bytes: 128,
                payload_digest: ContentHash::from_bytes(b"captured-frame"),
            },
        )
        .unwrap_or_else(|error| panic!("test opportunity: {error}"))
    }

    #[test]
    fn execution_checkpoint_restores_the_same_adapter_contributions() {
        let plan = test_plan();
        let seed = ContentHash::from_bytes(b"scenario-seed");
        let mut runtime = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("execution runtime: {error}"));
        let evaluation = runtime
            .evaluate_boundary(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                0,
            )
            .unwrap_or_else(|error| panic!("boundary: {error}"));
        assert_eq!(evaluation.actions.len(), 1);
        let checkpoint = runtime
            .checkpoint()
            .unwrap_or_else(|error| panic!("checkpoint: {error}"));
        let restored =
            FaultExecutionRuntime::restore(&plan, &NoArtifacts, seed, manifests(), &checkpoint)
                .unwrap_or_else(|error| panic!("restore: {error}"));
        assert_eq!(
            restored.adapter(FaultAdapter::Network).composition_groups(),
            runtime.adapter(FaultAdapter::Network).composition_groups()
        );
    }

    #[test]
    fn recorded_effects_execute_in_every_network_replay_mode() {
        let plan = test_plan();
        let seed = ContentHash::from_bytes(b"replay-seed");
        let coordinate = FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        };
        let mut recorder = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("recording runtime: {error}"));
        recorder
            .evaluate_boundary(coordinate, 0)
            .unwrap_or_else(|error| panic!("recording boundary: {error}"));

        for mode in [
            FaultReplayMode::RecomputedCause,
            FaultReplayMode::LockedEffect,
        ] {
            let trace = recorder
                .recorded_trace(mode)
                .unwrap_or_else(|error| panic!("recorded trace: {error}"));
            let mut replay = FaultExecutionRuntime::new(
                &plan,
                &NoArtifacts,
                SignalBoundarySnapshot::default(),
                seed,
                manifests(),
            )
            .unwrap_or_else(|error| panic!("replay runtime: {error}"));
            replay
                .install_replay(trace)
                .unwrap_or_else(|error| panic!("install replay: {error}"));
            let evaluation = replay
                .evaluate_boundary(coordinate, 0)
                .unwrap_or_else(|error| panic!("replay boundary: {error}"));
            assert_eq!(evaluation.actions.len(), 1);
            replay
                .verify_replay_exhausted()
                .unwrap_or_else(|error| panic!("replay exhaustion: {error}"));
            replay
                .checkpoint()
                .unwrap_or_else(|error| panic!("replay checkpoint: {error}"));
        }
    }

    #[test]
    fn outcome_replay_aligns_a_frame_without_rederiving_its_model() {
        let plan = network_outcome_plan();
        let seed = ContentHash::from_bytes(b"network-outcome-replay");
        let coordinate = FaultCoordinate {
            virtual_nanos: 10,
            retired_instructions: None,
        };
        let opportunity = frame_opportunity(coordinate, 7);
        let mut recorder = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("recording runtime: {error}"));
        recorder
            .evaluate_boundary(coordinate, 0)
            .unwrap_or_else(|error| panic!("recording boundary: {error}"));
        let pass = frame_opportunity_with_operation(coordinate, 6, FaultOperation::NetworkReceive);
        let passed = recorder
            .evaluate_opportunity(&pass, 1)
            .unwrap_or_else(|error| panic!("recording pass opportunity: {error}"));
        assert!(passed.actions.is_empty());
        let recorded = recorder
            .evaluate_opportunity(&opportunity, 2)
            .unwrap_or_else(|error| panic!("recording opportunity: {error}"));
        assert_eq!(recorded.actions.len(), 1);
        for alignment in [
            NetworkOutcomeAlignment::ExactFrameKey,
            NetworkOutcomeAlignment::ProducerDirectionSequence,
            NetworkOutcomeAlignment::ExactEventCoordinate,
            NetworkOutcomeAlignment::OrderedTimeBucket { width_nanos: 100 },
        ] {
            let trace = recorder
                .recorded_trace(FaultReplayMode::OutcomeOnlyNetwork(alignment))
                .unwrap_or_else(|error| panic!("outcome trace: {error}"));
            assert_eq!(trace.work_items.len(), 2);
            assert!(trace.work_items[0].records.is_empty());
            let replay_coordinate = if alignment == NetworkOutcomeAlignment::ExactEventCoordinate {
                coordinate
            } else {
                FaultCoordinate {
                    virtual_nanos: 20,
                    retired_instructions: None,
                }
            };
            let replay_opportunity = frame_opportunity(replay_coordinate, 7);
            let mut replay = FaultExecutionRuntime::new(
                &plan,
                &NoArtifacts,
                SignalBoundarySnapshot::default(),
                seed,
                manifests(),
            )
            .unwrap_or_else(|error| panic!("replay runtime: {error}"));
            replay
                .install_replay(trace)
                .unwrap_or_else(|error| panic!("install replay: {error}"));
            replay
                .evaluate_boundary(replay_coordinate, 0)
                .unwrap_or_else(|error| panic!("replay boundary: {error}"));
            let replay_pass = frame_opportunity_with_operation(
                replay_coordinate,
                6,
                FaultOperation::NetworkReceive,
            );
            let passed = replay
                .evaluate_opportunity(&replay_pass, 1)
                .unwrap_or_else(|error| panic!("replay pass opportunity: {error}"));
            assert!(passed.actions.is_empty());
            let outcome = replay
                .evaluate_opportunity(&replay_opportunity, 2)
                .unwrap_or_else(|error| panic!("replay opportunity: {error}"));
            assert_eq!(outcome.actions.len(), 1);
            assert_eq!(outcome.actions[0].effect, recorded.actions[0].effect);
            assert_eq!(
                outcome.actions[0].mapping_output,
                recorded.actions[0].mapping_output
            );
            assert_eq!(outcome.actions[0].coordinate, replay_coordinate);
            replay
                .verify_replay_exhausted()
                .unwrap_or_else(|error| panic!("replay exhaustion: {error}"));
        }
    }

    #[test]
    fn recomputed_replay_rejects_a_derivation_continuation_mismatch() {
        let plan = test_plan();
        let seed = ContentHash::from_bytes(b"recomputed-derivation-mismatch");
        let coordinate = FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        };
        let mut recorder = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("recorder: {error}"));
        recorder
            .evaluate_boundary(coordinate, 0)
            .unwrap_or_else(|error| panic!("recording boundary: {error}"));
        let mut trace = recorder
            .recorded_trace(FaultReplayMode::RecomputedCause)
            .unwrap_or_else(|error| panic!("trace: {error}"));
        let tampered = ContentHash::from_bytes(b"tampered");
        trace.work_items[0].derivation_fingerprint = tampered;
        for record in &mut trace.work_items[0].records {
            record.derivation_fingerprint = tampered;
        }
        let mut replay = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("replay: {error}"));
        replay
            .install_replay(trace)
            .unwrap_or_else(|error| panic!("install: {error}"));
        assert!(matches!(
            replay.evaluate_boundary(coordinate, 0),
            Err(FaultExecutionError::Binding(BindingRuntimeError::Runtime(
                FaultRuntimeError::ReplayMismatch { .. }
            )))
        ));
        assert_eq!(replay.replay.as_ref().map(|trace| trace.cursor), Some(0));
    }

    #[test]
    fn recomputed_replay_authenticates_a_zero_action_work_item() {
        let plan = network_outcome_plan();
        let seed = ContentHash::from_bytes(b"zero-action-recomputed-replay");
        let coordinate = FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        };
        let mut recorder = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("recorder: {error}"));
        let evaluation = recorder
            .evaluate_boundary(coordinate, 0)
            .unwrap_or_else(|error| panic!("zero-action boundary: {error}"));
        assert!(evaluation.actions.is_empty());
        let mut trace = recorder
            .recorded_trace(FaultReplayMode::RecomputedCause)
            .unwrap_or_else(|error| panic!("trace: {error}"));
        assert_eq!(trace.work_items.len(), 1);
        assert!(trace.work_items[0].records.is_empty());
        trace.work_items[0].derivation_fingerprint = ContentHash::from_bytes(b"tampered");

        let mut replay = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("replay: {error}"));
        replay
            .install_replay(trace)
            .unwrap_or_else(|error| panic!("install: {error}"));
        assert!(matches!(
            replay.evaluate_boundary(coordinate, 0),
            Err(FaultExecutionError::Binding(BindingRuntimeError::Runtime(
                FaultRuntimeError::ReplayMismatch { .. }
            )))
        ));
    }

    #[test]
    fn complete_checkpoint_identity_and_aggregate_limit_cover_nested_state() {
        let plan = test_plan();
        let seed = ContentHash::from_bytes(b"checkpoint-identity-seed");
        let mut runtime = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("runtime: {error}"));
        runtime
            .evaluate_boundary(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                0,
            )
            .unwrap_or_else(|error| panic!("boundary: {error}"));
        let checkpoint = runtime
            .checkpoint()
            .unwrap_or_else(|error| panic!("checkpoint: {error}"));
        let identity = checkpoint
            .content_id()
            .unwrap_or_else(|error| panic!("identity: {error}"));
        let bytes = checkpoint
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("checkpoint bytes: {error}"));
        let restored = FaultRuntimeCheckpoint::from_canonical_bytes(&bytes, &plan, seed)
            .unwrap_or_else(|error| panic!("checkpoint decode: {error}"));
        assert_eq!(restored, checkpoint);
        assert_eq!(
            restored
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("restored bytes: {error}")),
            bytes
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(FaultRuntimeCheckpoint::from_canonical_bytes(&trailing, &plan, seed).is_err());

        let mut mutated = checkpoint.clone();
        mutated.poisoned = true;
        assert_ne!(
            mutated
                .content_id()
                .unwrap_or_else(|error| panic!("mutated identity: {error}")),
            identity
        );
        let mut mutated = checkpoint.clone();
        mutated.binding_runtime.scheduler_cursor = Some(FaultSchedulerCursor {
            virtual_nanos: 1,
            same_coordinate_sequence: 0,
        });
        assert_ne!(
            mutated
                .content_id()
                .unwrap_or_else(|error| panic!("mutated identity: {error}")),
            identity
        );
        let mut mutated = checkpoint.clone();
        mutated.recorded_work_items[0].records[0].evidence_digest =
            ContentHash::from_bytes(b"changed");
        assert_ne!(
            mutated
                .content_id()
                .unwrap_or_else(|error| panic!("mutated identity: {error}")),
            identity
        );
        let mut mutated = checkpoint;
        mutated.resource_limits.fat_checkpoint_bytes = 1;
        assert!(matches!(
            mutated.canonical_bytes(),
            Err(FaultRuntimeError::ResourceLimit(_))
        ));
    }

    #[test]
    fn failed_replay_installation_leaves_the_owned_continuation_unchanged() {
        let base = test_plan();
        let seed = ContentHash::from_bytes(b"atomic-replay-install");
        let initial = OwnedFaultExecutionRuntime::new(
            base.clone(),
            Arc::new(NoArtifacts),
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("initial owner: {error}"));
        let initial_size = initial
            .checkpoint()
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("initial bytes: {error}"))
            .len();
        let limits = FaultResourceLimits {
            fat_checkpoint_bytes: u64::try_from(initial_size + 256)
                .unwrap_or_else(|error| panic!("test checkpoint size: {error}")),
            ..FaultResourceLimits::default()
        };
        let plan = FaultSignalPlan::new(base.programs().to_vec(), base.bindings().to_vec(), limits)
            .unwrap_or_else(|error| panic!("limited plan: {error}"));
        let mut owner = OwnedFaultExecutionRuntime::new(
            plan,
            Arc::new(NoArtifacts),
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("limited owner: {error}"));
        let before = owner
            .checkpoint()
            .content_id()
            .unwrap_or_else(|error| panic!("before identity: {error}"));
        let mut recorder = FaultExecutionRuntime::new(
            &base,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("recorder: {error}"));
        recorder
            .evaluate_boundary(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                0,
            )
            .unwrap_or_else(|error| panic!("recording boundary: {error}"));
        let work_item = recorder
            .recorded_work_items
            .first()
            .cloned()
            .unwrap_or_else(|| panic!("recording must contain one action"));
        let trace = ResolvedEffectTrace {
            mode: FaultReplayMode::LockedEffect,
            work_items: vec![work_item; 8],
            cursor: 0,
        };
        assert!(owner.install_replay(trace).is_err());
        assert!(owner.checkpoint().replay.is_none());
        assert_eq!(
            owner
                .checkpoint()
                .content_id()
                .unwrap_or_else(|error| panic!("after identity: {error}")),
            before
        );
    }

    #[test]
    fn checkpoint_growth_is_rejected_before_the_live_backend_commits() {
        let base = test_plan();
        let seed = ContentHash::from_bytes(b"precommit-checkpoint-capacity");
        let initial = OwnedFaultExecutionRuntime::new(
            base.clone(),
            Arc::new(NoArtifacts),
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("initial owner: {error}"));
        let initial_size = initial
            .checkpoint()
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("initial bytes: {error}"))
            .len();
        let limits = FaultResourceLimits {
            fat_checkpoint_bytes: u64::try_from(initial_size + 64)
                .unwrap_or_else(|error| panic!("test checkpoint size: {error}")),
            ..FaultResourceLimits::default()
        };
        let plan = FaultSignalPlan::new(base.programs().to_vec(), base.bindings().to_vec(), limits)
            .unwrap_or_else(|error| panic!("limited plan: {error}"));
        let mut owner = OwnedFaultExecutionRuntime::new(
            plan,
            Arc::new(NoArtifacts),
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("limited owner: {error}"));
        let before = owner
            .checkpoint()
            .content_id()
            .unwrap_or_else(|error| panic!("before identity: {error}"));
        let mut backend = HostFaultActionSink::new(limits);
        assert!(
            owner
                .evaluate_boundary_with_backend(
                    FaultCoordinate {
                        virtual_nanos: 0,
                        retired_instructions: None,
                    },
                    0,
                    &mut backend,
                )
                .is_err()
        );
        assert!(backend.state().is_empty());
        assert_eq!(
            owner
                .checkpoint()
                .content_id()
                .unwrap_or_else(|error| panic!("after identity: {error}")),
            before
        );
    }
}
