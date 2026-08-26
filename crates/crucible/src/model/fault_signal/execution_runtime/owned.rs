//! Owned fault-execution continuations for scheduler persistence.

use super::*;

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
        Self::new_with_search_overrides(
            plan,
            artifacts,
            boundary,
            scenario_seed,
            manifests,
            BTreeMap::new(),
        )
    }

    /// Creates an owned continuation with concrete finite explorer overrides.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] under the same conditions as
    /// [`Self::new`], or when the override set exceeds admitted bounds.
    pub fn new_with_search_overrides(
        plan: FaultSignalPlan,
        artifacts: Arc<dyn SignalArtifactProvider>,
        boundary: SignalBoundarySnapshot,
        scenario_seed: ContentHash,
        manifests: FaultAdapterManifests,
        search_overrides: BTreeMap<SearchChoiceId, SearchOverride>,
    ) -> Result<Self, FaultExecutionError> {
        let runtime = FaultExecutionRuntime::new_with_search_overrides(
            &plan,
            artifacts.as_ref(),
            boundary,
            scenario_seed,
            manifests.clone(),
            search_overrides,
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
        let candidate = runtime.checkpoint()?;
        let derivation = ContentHash::from_bytes(b"checkpoint-capacity-preflight-derivation");
        let precondition = ContentHash::from_bytes(b"checkpoint-capacity-preflight-before");
        let evidence = ContentHash::from_bytes(b"checkpoint-capacity-preflight-evidence");
        super::capacity_preflight::preflight_checkpoint_with_actions(
            &candidate,
            &evaluation.actions,
            coordinate,
            same_coordinate_sequence,
            opportunity,
            derivation,
            precondition,
            evidence,
        )?;
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

    /// Requires every installed finite search override to be consumed once.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when continuation restore fails or any
    /// configured override was not reached by execution.
    pub fn verify_search_overrides_consumed(&self) -> Result<(), FaultExecutionError> {
        let runtime = FaultExecutionRuntime::restore(
            &self.plan,
            self.artifacts.as_ref(),
            self.scenario_seed,
            self.manifests.clone(),
            &self.checkpoint,
        )?;
        runtime.verify_search_overrides_consumed()
    }

    /// Reports whether this continuation carries finite explorer overrides.
    #[must_use]
    pub fn has_search_overrides(&self) -> bool {
        !self.checkpoint.binding_runtime.search_overrides.is_empty()
    }

    /// Reports whether one exact finite search override was consumed.
    #[must_use]
    pub fn search_override_consumed(
        &self,
        choice: SearchChoiceId,
        expected: &SearchOverride,
    ) -> bool {
        self.checkpoint
            .binding_runtime
            .search_overrides
            .get(&choice)
            == Some(expected)
            && self
                .checkpoint
                .binding_runtime
                .consumed_search_overrides
                .contains(&choice)
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
