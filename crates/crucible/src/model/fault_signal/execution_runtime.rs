//! Complete signal-to-adapter fault execution ownership.
//!
//! [`FaultExecutionRuntime`] is the production bridge between a scenario's
//! admitted signal program, binding evaluation, and the three transactional
//! adapter families. It owns one atomic checkpoint surface so callers never
//! persist evaluator state without the corresponding adapter state.

use std::collections::{BTreeMap, BTreeSet};
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
        Self::new_with_search_overrides(
            plan,
            artifacts,
            boundary,
            scenario_seed,
            manifests,
            BTreeMap::new(),
        )
    }

    /// Admits live capabilities with concrete finite explorer overrides.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] under the same conditions as
    /// [`Self::new`], or when the override set exceeds admitted bounds.
    pub fn new_with_search_overrides(
        plan: &'a FaultSignalPlan,
        artifacts: &'a dyn SignalArtifactProvider,
        boundary: SignalBoundarySnapshot,
        scenario_seed: ContentHash,
        manifests: FaultAdapterManifests,
        search_overrides: BTreeMap<SearchChoiceId, SearchOverride>,
    ) -> Result<Self, FaultExecutionError> {
        let program = sole_program(plan)?;
        let resource_limits = plan.resource_limits();
        admit_manifests(plan.bindings(), &manifests)?;
        let bindings = plan.bindings().to_vec();
        let binding_runtime = FaultBindingRuntime::new_with_search_overrides(
            program,
            bindings.clone(),
            artifacts,
            boundary,
            scenario_seed,
            resource_limits,
            search_overrides,
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

    /// Requires every installed finite search override to be consumed once.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when any configured override was not
    /// reached by execution.
    pub fn verify_search_overrides_consumed(&self) -> Result<(), FaultExecutionError> {
        self.binding_runtime.verify_search_overrides_consumed()?;
        Ok(())
    }
}

mod capacity_preflight;
mod owned;

pub use owned::OwnedFaultExecutionRuntime;

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
#[path = "execution_runtime_replay_test.rs"]
mod replay_tests;
#[cfg(test)]
#[path = "execution_runtime_test_support.rs"]
mod test_support;
#[cfg(test)]
#[path = "execution_runtime_test.rs"]
mod tests;
