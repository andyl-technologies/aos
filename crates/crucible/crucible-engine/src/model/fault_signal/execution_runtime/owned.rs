//! Owned fault-execution continuations for scheduler persistence.

use super::*;

/// An owned, cloneable fault continuation suitable for scheduler state.
///
/// The evaluator itself borrows its immutable program and artifact provider.
/// This owner avoids a self-referential scheduler field by restoring that
/// evaluator from an authenticated bounded checkpoint for each exact boundary,
/// then replacing the checkpoint only after the complete adapter transaction
/// commits.
///
/// The resolved-effect trace is not part of that per-boundary round trip. The
/// owner keeps the recording writer and replay reader as live state, moves
/// them into the restored evaluator for one evaluation, and takes them back
/// afterwards, so per-boundary work never copies or re-encodes recorded work
/// items. [`Self::checkpoint`] combines the bounded state with the trace
/// position and replay cursor.
#[derive(Clone)]
pub struct OwnedFaultExecutionRuntime {
    plan: FaultSignalPlan,
    artifacts: Arc<dyn SignalArtifactProvider>,
    scenario_seed: ContentHash,
    manifests: FaultAdapterManifests,
    storage: FaultTraceStorage,
    /// Every checkpoint field except the trace position and replay cursor.
    bounded: FaultRuntimeCheckpoint,
    /// Authoritative recording writer and replay reader.
    trace: FaultTraceState,
    external_effect_count: u64,
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
        Self::new_with_storage(
            plan,
            artifacts,
            boundary,
            scenario_seed,
            manifests,
            search_overrides,
            FaultTraceStorage::default(),
        )
    }

    /// Creates an owned continuation that records its trace into `storage`.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] under the same conditions as
    /// [`Self::new_with_search_overrides`].
    pub fn new_with_storage(
        plan: FaultSignalPlan,
        artifacts: Arc<dyn SignalArtifactProvider>,
        boundary: SignalBoundarySnapshot,
        scenario_seed: ContentHash,
        manifests: FaultAdapterManifests,
        search_overrides: BTreeMap<SearchChoiceId, SearchOverride>,
        storage: FaultTraceStorage,
    ) -> Result<Self, FaultExecutionError> {
        let runtime = FaultExecutionRuntime::new_with_storage(
            &plan,
            artifacts.as_ref(),
            boundary,
            scenario_seed,
            manifests.clone(),
            search_overrides,
            &storage,
        )?;
        let _ = runtime.checkpoint()?;
        let bounded = runtime.bounded_checkpoint()?;
        let trace = runtime.into_trace();
        Ok(Self {
            plan,
            artifacts,
            scenario_seed,
            manifests,
            storage,
            bounded,
            trace,
            external_effect_count: 0,
        })
    }

    /// Restores an owned continuation from authenticated runtime state.
    ///
    /// The checkpoint's sealed trace segments must be readable from
    /// `storage`'s recording sink, and an installed replay's segments from its
    /// replay sources.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the checkpoint does not match the
    /// plan, seed, evaluator, or admitted adapter capabilities, or its trace
    /// state cannot be restored from `storage`.
    pub fn restore(
        plan: FaultSignalPlan,
        artifacts: Arc<dyn SignalArtifactProvider>,
        scenario_seed: ContentHash,
        manifests: FaultAdapterManifests,
        checkpoint: FaultRuntimeCheckpoint,
        storage: FaultTraceStorage,
    ) -> Result<Self, FaultExecutionError> {
        checkpoint.validate(&plan, scenario_seed)?;
        admit_manifests(plan.bindings(), &manifests)?;
        let trace = FaultTraceState::restore(&storage, &checkpoint)?;
        let mut bounded = checkpoint;
        bounded.recorded = ResolvedEffectTracePosition::empty();
        bounded.replay = None;
        if !bounded.poisoned {
            let runtime = FaultExecutionRuntime::restore_with_trace(
                &plan,
                artifacts.as_ref(),
                scenario_seed,
                manifests.clone(),
                &bounded,
                FaultTraceState::new(&storage, plan.resource_limits()),
            )?;
            drop(runtime);
        }
        Ok(Self {
            plan,
            artifacts,
            scenario_seed,
            manifests,
            storage,
            bounded,
            trace,
            external_effect_count: 0,
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
        self.commit_with(|runtime| {
            runtime.evaluate_boundary_with_backend(coordinate, same_coordinate_sequence, backend)
        })
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
        let mut runtime = self.preview_runtime()?;
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
        let mut runtime = self.preview_runtime()?;
        runtime.set_boundary_snapshot(boundary)?;
        self.bounded = runtime.bounded_checkpoint()?;
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
        self.commit_with(|runtime| {
            runtime.evaluate_opportunity_with_backend(
                opportunity,
                same_coordinate_sequence,
                backend,
            )
        })
    }

    /// Runs one committing evaluation against the live trace state.
    ///
    /// The trace state moves into the restored evaluator and back, so the
    /// evaluation appends to the authoritative writer without copying it. On
    /// failure the bounded checkpoint is unchanged; the replay reader returns
    /// to its position before the evaluation, and a terminal failure poisons
    /// the continuation.
    fn commit_with(
        &mut self,
        evaluate: impl FnOnce(
            &mut FaultExecutionRuntime<'_>,
        ) -> Result<BindingEvaluation, FaultExecutionError>,
    ) -> Result<BindingEvaluation, FaultExecutionError> {
        let mut runtime = FaultExecutionRuntime::restore_with_trace(
            &self.plan,
            self.artifacts.as_ref(),
            self.scenario_seed,
            self.manifests.clone(),
            &self.bounded,
            FaultTraceState::new(&self.storage, self.plan.resource_limits()),
        )?;
        let replay_before = self.trace.replay.clone();
        let placeholder = FaultTraceState::new(&self.storage, self.plan.resource_limits());
        runtime.replace_trace(std::mem::replace(&mut self.trace, placeholder));

        let outcome = evaluate(&mut runtime);
        let bounded = match &outcome {
            Ok(_) => runtime.bounded_checkpoint(),
            Err(_) => Ok(self.bounded.clone()),
        };
        let mut trace = runtime.into_trace();
        let evaluation = match outcome {
            Ok(evaluation) => evaluation,
            Err(error) => {
                trace.replay = replay_before;
                self.trace = trace;
                if terminal_execution_error(&error) {
                    self.bounded.poisoned = true;
                }
                return Err(error);
            }
        };
        self.trace = trace;
        match bounded {
            Ok(bounded) => {
                self.bounded = bounded;
                Ok(evaluation)
            }
            Err(error) => {
                self.bounded.poisoned = true;
                Err(error)
            }
        }
    }

    /// Restores an evaluator for read-only work over a copy of the replay
    /// reader and an empty recording.
    fn preview_runtime(&self) -> Result<FaultExecutionRuntime<'_>, FaultExecutionError> {
        let mut trace = FaultTraceState::new(&self.storage, self.plan.resource_limits());
        trace.replay = self.trace.replay.clone();
        FaultExecutionRuntime::restore_with_trace(
            &self.plan,
            self.artifacts.as_ref(),
            self.scenario_seed,
            self.manifests.clone(),
            &self.bounded,
            trace,
        )
    }

    fn preflight_checkpoint_capacity(
        &self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        opportunity: Option<&FaultOpportunity>,
    ) -> Result<(), FaultExecutionError> {
        let mut runtime = self.preview_runtime()?;
        let evaluation = match opportunity {
            Some(opportunity) => {
                runtime.preview_opportunity(opportunity, same_coordinate_sequence)?
            }
            None => runtime.preview_boundary(coordinate, same_coordinate_sequence)?,
        };
        let committed = self
            .trace
            .recorded
            .records()
            .checked_add(self.external_effect_count)
            .ok_or(FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
        let requested = u64::try_from(evaluation.actions.len())
            .map_err(|_| FaultRuntimeError::CountOverflow("resolved_effect_records"))?;
        self.plan
            .resource_limits()
            .reserve("resolved_effect_records", committed, requested)
            .map_err(FaultRuntimeError::ResourceLimit)?;
        let candidate = runtime.bounded_checkpoint()?;
        // The committed digests are unknown before the commit. A digest
        // encodes as 32 CBOR integers whose widths depend on their values, so
        // the widest digest makes the measurement an upper bound.
        let derivation = super::super::runtime::WIDEST_CONTENT_HASH;
        let precondition = derivation;
        let evidence = derivation;
        super::capacity_preflight::preflight_checkpoint_with_actions(
            &candidate,
            &self.trace,
            &evaluation.actions,
            super::capacity_preflight::CapacityWorkItemContext {
                coordinate,
                same_coordinate_sequence,
                opportunity,
                derivation_fingerprint: derivation,
                precondition_digest: precondition,
                evidence_digest: evidence,
            },
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
        let mut runtime = self.preview_runtime()?;
        runtime.preview_opportunity(opportunity, same_coordinate_sequence)
    }

    /// Returns the current authenticated continuation.
    ///
    /// The checkpoint combines the bounded evaluator and adapter state with
    /// the trace position and replay cursor; it never contains sealed work
    /// items.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the complete checkpoint exceeds
    /// its byte limit.
    pub fn checkpoint(&self) -> Result<FaultRuntimeCheckpoint, FaultExecutionError> {
        let mut checkpoint = self.bounded.clone();
        self.trace.fill(&mut checkpoint);
        let _ = checkpoint.canonical_bytes()?;
        Ok(checkpoint)
    }

    /// Returns the segment storage this continuation records into.
    #[must_use]
    pub const fn storage(&self) -> &FaultTraceStorage {
        &self.storage
    }

    /// Returns the number of committed signal effects without scanning history.
    #[must_use]
    pub const fn recorded_effect_count(&self) -> u64 {
        self.trace.recorded.records()
    }

    /// Sets committed effects owned by another adapter sharing this scenario budget.
    pub fn set_external_effect_count(&mut self, count: u64) {
        self.external_effect_count = count;
    }

    /// Installs a fresh authoritative replay trace into this continuation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when the trace exceeds the scenario's
    /// replay counters, its first segment cannot be read, or the updated
    /// complete checkpoint exceeds its resource contract.
    pub fn install_replay(
        &mut self,
        trace: ResolvedEffectTrace,
    ) -> Result<(), FaultExecutionError> {
        let reader = ResolvedEffectTraceReader::new(trace, self.plan.resource_limits())?;
        let previous = self.trace.replay.replace(reader);
        if let Err(error) = self.checkpoint() {
            self.trace.replay = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Requires all installed replay records to have been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when no trace is installed or records remain.
    pub fn verify_replay_exhausted(&self) -> Result<(), FaultExecutionError> {
        self.trace
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
        self.preview_runtime()?.verify_search_overrides_consumed()
    }

    /// Reports whether this continuation carries finite explorer overrides.
    #[must_use]
    pub fn has_search_overrides(&self) -> bool {
        !self.bounded.binding_runtime.search_overrides.is_empty()
    }

    /// Reports whether one exact finite search override was consumed.
    #[must_use]
    pub fn search_override_consumed(
        &self,
        choice: SearchChoiceId,
        expected: &SearchOverride,
    ) -> bool {
        self.bounded.binding_runtime.search_overrides.get(&choice) == Some(expected)
            && self
                .bounded
                .binding_runtime
                .consumed_search_overrides
                .contains(&choice)
    }

    /// Returns all committed effects as an unconsumed replay trace.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when a segment cannot be stored or
    /// read, or the selected mode rejects a record.
    pub fn recorded_trace(
        &self,
        mode: FaultReplayMode,
    ) -> Result<ResolvedEffectTrace, FaultExecutionError> {
        Ok(self.trace.recorded_trace(mode)?)
    }

    /// Returns whether backend visibility became ambiguous and execution ended.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.bounded.poisoned
    }

    /// Permanently poisons the continuation after ambiguous external visibility.
    ///
    /// Production owners call this when the fault adapter committed but a
    /// coupled scheduler or device mutation could not be proven complete. A
    /// poisoned continuation rejects every subsequent evaluation and cannot be
    /// restored as runnable state.
    pub fn poison(&mut self) {
        self.bounded.poisoned = true;
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
            .field("bounded", &self.bounded)
            .field("trace", &self.trace)
            .finish_non_exhaustive()
    }
}
