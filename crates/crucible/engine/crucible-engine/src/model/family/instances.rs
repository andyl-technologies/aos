//! Concrete scenario-family instances and self-contained reproduction artifacts.

use super::*;

/// Parametric generator over concrete, validated scenario definitions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioFamily {
    pub(in crate::model) space: FamilySpace,
    pub(in crate::model) node_template: NodeTemplate,
    pub(in crate::model) assertions: Vec<AssertionDef>,
    pub(in crate::model) fault_plan: FaultSignalPlan,
}

impl ScenarioFamily {
    /// Builds a scenario family from a parameter space and reusable node template.
    #[must_use]
    pub fn new(space: FamilySpace, node_template: NodeTemplate) -> Self {
        Self {
            space,
            node_template,
            assertions: Vec::new(),
            fault_plan: FaultSignalPlan::empty(),
        }
    }

    /// Returns the parameter space this family ranges over.
    #[must_use]
    pub fn space(&self) -> &FamilySpace {
        &self.space
    }

    /// Adds one assertion to every generated scenario's properties layer.
    #[must_use]
    pub fn property(mut self, assertion: AssertionDef) -> Self {
        self.assertions.push(assertion);
        self
    }

    /// Supplies the validated fault programs and bindings sampled by density.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when an authored
    /// density exceeds the number of available bindings.
    pub fn with_fault_plan(mut self, plan: FaultSignalPlan) -> Result<Self, EngineError> {
        if self.space.fault_densities.iter().any(|density| {
            usize::try_from(*density).map_or(true, |value| value > plan.bindings().len())
        }) {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "fault density exceeds the family plan binding count",
            });
        }
        self.fault_plan = plan;
        Ok(self)
    }

    /// Loads a canonical, fault-only plan for the family's sampled worlds.
    ///
    /// The first world authenticates the authored plan. Each later pinned
    /// instance revalidates its selected bindings against its own world.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] for malformed plan material, non-fault events,
    /// or a fault density exceeding the plan's admitted binding count.
    pub fn with_canonical_fault_plan_toml(self, input: &str) -> Result<Self, EngineError> {
        let first_world = self.build_world(self.space.sample(0)?)?;
        let plan = Plan::from_canonical_toml_for_world(&first_world, input)?;
        if !plan.event_graph().events().is_empty() {
            return Err(scenario_serialization_error(
                "scenario-family fault plan must not contain event-graph actions".to_owned(),
            ));
        }
        self.with_fault_plan(plan.fault_signals().clone())
    }

    /// Instantiates a concrete validated scenario at `params`.
    ///
    /// The returned [`PinnedScenario`] contains the concrete [`ScenarioDefForm`]
    /// used by execution and reproduction. It carries no reference back to this
    /// family, so callers can only run the pinned scenario definition.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyParameterOutOfSpace`] when `params`
    /// does not lie in the family space, or the usual world/plan/properties
    /// validation errors if the generated scenario is invalid.
    pub fn instantiate(&self, params: FamilyParams) -> Result<PinnedScenario, EngineError> {
        self.space.validate_params(params)?;
        let world = self.build_world(params)?;
        let plan = self.build_plan(&world, params)?;
        let properties = Properties::from_assertions_for_world(&world, self.assertions.clone())?;
        let form = ScenarioDefForm::from_components(&world, &plan, &properties, params.seed)?;
        Ok(PinnedScenario { params, form })
    }

    /// Samples and instantiates one deterministic parameter point.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`FamilySpace::sample`] or [`Self::instantiate`].
    pub fn instantiate_sample(&self, index: u64) -> Result<PinnedScenario, EngineError> {
        let params = self.space.sample(index)?;
        self.instantiate(params)
    }

    /// Selects one pinned family instance from authenticated coverage feedback.
    ///
    /// The returned energy is a deterministic admission budget input. Callers
    /// execute the pinned instance and feed its observed coverage into the next
    /// selection; this method does not invent a scheduler decision.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the family space or selected instance is invalid.
    pub fn sample_coverage_guided(
        &self,
        config: CoverageGuidedFuzzConfig,
        sequence: u64,
        feedback: &[EventLogCoverageFeedback],
    ) -> Result<(u64, PinnedScenario, u64), EngineError> {
        let cardinality = self.space.cardinality()?;
        let fingerprint = coverage_guided_fuzz_feedback_fingerprint(feedback, sequence);
        let sample_index =
            coverage_guided_fuzz_sample_index(config, sequence, fingerprint, cardinality);
        let energy = coverage_guided_fuzz_energy(config, sequence, fingerprint);

        Ok((sample_index, self.instantiate_sample(sample_index)?, energy))
    }

    /// Samples and mutates concrete scenarios using event-log coverage feedback.
    ///
    /// Each iteration chooses one family parameter point, pins that point to a
    /// concrete [`ScenarioDef`], and appends a typed campaign selection. Coverage influences only which deterministic
    /// samples are explored and how the returned candidates are ordered; it never
    /// changes the reduced execution semantics of a candidate.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when the family space
    /// cannot be counted, [`EngineError::ScenarioFamilyParameterOutOfSpace`] when
    /// a sampled point is invalid, or any validation error from
    /// [`Self::instantiate`] or [`try_step`].
    pub fn fuzz_coverage_guided(
        &self,
        config: CoverageGuidedFuzzConfig,
        feedback: &[EventLogCoverageFeedback],
    ) -> Result<CoverageGuidedFuzzRun, EngineError> {
        run_coverage_guided_fuzz(self, config, feedback)
    }

    /// Runs coverage-guided fuzzing with a durable content-addressed corpus.
    ///
    /// The corpus stores every retained input as a self-contained
    /// [`ReproductionArtifact`] in `store`. Admission is coverage-driven: a
    /// candidate is retained only when its coverage fingerprint has no existing
    /// corpus owner. Rejected duplicate coverage is reported as deterministic
    /// subsumption pruning rather than stored as a corpus entry.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageGuidedCorpusError::Engine`] when sampling, mutation,
    /// artifact capture, or replay validation fails. Returns
    /// [`CoverageGuidedCorpusError::Store`] when `store` cannot persist an
    /// admitted reproduction artifact.
    pub fn fuzz_coverage_guided_corpus<S>(
        &self,
        store: &S,
        config: CoverageGuidedFuzzConfig,
        corpus_config: CoverageGuidedCorpusConfig,
        feedback: &[EventLogCoverageFeedback],
    ) -> Result<CoverageGuidedCorpusRun, CoverageGuidedCorpusError>
    where
        S: DagStore + ?Sized,
    {
        run_coverage_guided_fuzz_corpus(self, store, config, corpus_config, feedback)
    }

    fn build_world(&self, params: FamilyParams) -> Result<World, EngineError> {
        let nodes = (0..params.topology_size)
            .map(|index| self.node_template.instantiate(family_node_id(index)))
            .collect::<Vec<_>>();
        let links = family_links(params)?;
        World::from_nodes_and_links(nodes, links)
    }

    fn build_plan(&self, world: &World, params: FamilyParams) -> Result<Plan, EngineError> {
        let density = usize::try_from(params.fault_density).map_err(|_| {
            EngineError::ScenarioFamilyInvalidSpace {
                reason: "fault density cannot be represented on this host",
            }
        })?;
        if density == 0 {
            return Ok(Plan::empty());
        }
        let selected = self.fault_plan.bindings().get(..density).ok_or(
            EngineError::ScenarioFamilyInvalidSpace {
                reason: "fault density exceeds the family plan binding count",
            },
        )?;
        let faults = FaultSignalPlan::new(
            self.fault_plan.programs().to_vec(),
            selected.to_vec(),
            self.fault_plan.resource_limits(),
        )
        .map_err(|error| {
            scenario_serialization_error(format!("sample family fault plan: {error}"))
        })?;
        Plan::empty().with_fault_signals_for_world(world, faults)
    }
}

/// A concrete scenario pinned from a [`ScenarioFamily`] parameter point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PinnedScenario {
    pub(in crate::model) params: FamilyParams,
    pub(in crate::model) form: ScenarioDefForm,
}

impl PinnedScenario {
    /// Returns the family parameters that produced this pinned instance.
    #[must_use]
    pub fn params(&self) -> FamilyParams {
        self.params
    }

    /// Returns the materialized concrete scenario form.
    #[must_use]
    pub fn form(&self) -> &ScenarioDefForm {
        &self.form
    }

    /// Consumes this pinned instance and returns its concrete scenario form.
    #[must_use]
    pub fn into_form(self) -> ScenarioDefForm {
        self.form
    }

    /// Reconstructs the concrete scenario definition used by execution.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        self.form.scenario_def()
    }

    /// Builds the genesis execution configuration while retaining the concrete form.
    #[must_use]
    pub fn genesis_configuration(&self) -> PinnedConfiguration {
        PinnedConfiguration {
            scenario: self.form.clone(),
            configuration: Configuration::genesis(self.scenario_def()),
        }
    }

    /// Returns the concrete scenario id.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.form.id()
    }
}

/// A run configuration pinned to a concrete materialized scenario form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PinnedConfiguration {
    pub(in crate::model) scenario: ScenarioDefForm,
    pub(in crate::model) configuration: Configuration,
}

impl PinnedConfiguration {
    /// Returns the concrete materialized scenario form for reproduction.
    #[must_use]
    pub fn scenario_form(&self) -> &ScenarioDefForm {
        &self.scenario
    }

    /// Returns the executable configuration handle for the pinned scenario.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Consumes this pinned configuration into its concrete parts.
    #[must_use]
    pub fn into_parts(self) -> (ScenarioDefForm, Configuration) {
        (self.scenario, self.configuration)
    }
}

/// A self-contained `(seed, scenario, schedule)` reproduction bundle.
///
/// The seed is not stored as a drifting side channel: it is the embedded
/// [`ScenarioDefForm`]'s own seed. The artifact carries only the complete
/// validated scenario form and recorded schedule, so its identity is exactly the
/// RFC tuple `(seed, scenario, schedule)` without a parent family or host path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReproductionArtifact {
    pub(in crate::model) id: ContentHash,
    pub(in crate::model) scenario: ScenarioDefForm,
    pub(in crate::model) schedule: Schedule,
}

impl ReproductionArtifact {
    /// Captures an artifact by reducing `schedule` from `scenario`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if the reduction function rejects the supplied
    /// scenario/schedule pair.
    pub fn capture(scenario: &ScenarioDefForm, schedule: &Schedule) -> Result<Self, EngineError> {
        let artifact = Self::from_recorded_parts(scenario.clone(), schedule.clone());
        let _ = artifact.replay()?;
        Ok(artifact)
    }

    /// Rebuilds an artifact from already-recorded self-contained parts.
    #[must_use]
    pub fn from_recorded_parts(scenario: ScenarioDefForm, schedule: Schedule) -> Self {
        let id =
            ContentHash::from_bytes(&reproduction_artifact_canonical_bytes(&scenario, &schedule));
        Self {
            id,
            scenario,
            schedule,
        }
    }

    /// Parses a compact canonical artifact representation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed artifact,
    /// scenario, or schedule bytes.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, REPRODUCTION_ARTIFACT_BINARY_MAGIC_V9)?;
        let scenario_bytes = reader.read_binary_blob_bounded(
            "reproduction-artifact.scenario",
            MAX_REPRODUCTION_SCENARIO_BLOB_BYTES,
        )?;
        let schedule_bytes = reader.read_binary_blob("reproduction-artifact.schedule")?;
        reader.finish()?;
        if !scenario_bytes.starts_with(SCENARIO_FORM_BINARY_MAGIC_V9) {
            return Err(scenario_serialization_error(
                "reproduction-artifact scenario version does not match its outer version",
            ));
        }

        let scenario = ScenarioDefForm::from_compact_binary(scenario_bytes)?;
        let schedule = Schedule::from_compact_binary(schedule_bytes)?;
        Ok(Self::from_recorded_parts(scenario, schedule))
    }

    /// Returns the BLAKE3 content address over this artifact's canonical bytes.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns the concrete serialized scenario form carried by this artifact.
    #[must_use]
    pub fn scenario_form(&self) -> &ScenarioDefForm {
        &self.scenario
    }

    /// Reconstructs the immutable scenario definition carried by this artifact.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        self.scenario.scenario_def()
    }

    /// Returns the scenario definition's root seed.
    #[must_use]
    pub fn seed(&self) -> Seed {
        self.scenario.seed()
    }

    /// Returns the recorded schedule carried by this artifact.
    #[must_use]
    pub fn schedule(&self) -> &Schedule {
        &self.schedule
    }

    /// Returns the canonical byte serialization hashed by [`Self::id`].
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        reproduction_artifact_canonical_bytes(&self.scenario, &self.schedule)
    }

    /// Serializes this artifact as compact canonical bytes.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        self.canonical_bytes()
    }

    /// Replays the artifact through producer validation and the reduction oracle.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if the reduction function rejects the embedded
    /// scenario/schedule pair or retained preemption producer evidence.
    pub fn replay(&self) -> Result<ReproductionReplay, EngineError> {
        validate_preemption_branch_schedule(&Configuration {
            def: self.scenario_def(),
            schedule: self.schedule.clone(),
        })?;
        let state = reduce(&self.scenario_def(), &self.schedule)?;
        Ok(ReproductionReplay {
            artifact: self.id,
            scenario: self.scenario.id(),
            schedule: self.schedule.content_hash(),
            state: state.id,
        })
    }

    /// Replays the artifact and compares the result with an external target state.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionArtifactReplayMismatch`] when the
    /// embedded scenario and schedule reduce to a state other than `expected`.
    /// Returns other [`EngineError`] variants if the reduction itself fails.
    pub fn verify_replay(&self, expected: ContentHash) -> Result<ReproductionReplay, EngineError> {
        let replay = self.replay()?;
        if replay.state != expected {
            return Err(EngineError::ReproductionArtifactReplayMismatch {
                artifact: self.id,
                expected,
                actual: replay.state,
            });
        }
        Ok(replay)
    }

    /// Captures the event-log debug/fork metadata for this reproduction artifact.
    ///
    /// The returned value records the causal-subsequence digest and fork-point
    /// index, not the full event log. Replaying the artifact can therefore
    /// recompute the log and compare against this compact record.
    #[must_use]
    pub fn event_log_debug_artifact(
        &self,
        fork_point: EventLogOffset,
        entries: &[crate::scheduler::SchedulerEventLogEntry],
    ) -> ReproductionEventLogArtifact {
        self.event_log_debug_artifact_with_segments(fork_point, entries, Vec::new())
    }

    /// Captures event-log debug/fork metadata with shared-store segment keys.
    ///
    /// `shared_store_segments` are optional content-addressed event-log segment
    /// keys. They let a shared store fetch retained log bytes, but replay
    /// correctness still comes from recomputing the log from the embedded
    /// scenario and schedule.
    #[must_use]
    pub fn event_log_debug_artifact_with_segments<I>(
        &self,
        fork_point: EventLogOffset,
        entries: &[crate::scheduler::SchedulerEventLogEntry],
        shared_store_segments: I,
    ) -> ReproductionEventLogArtifact
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let projection = crate::scheduler::event_log_causal_projection(entries);
        let coverage_fingerprint = coverage_fingerprint_from_event_log(entries);
        ReproductionEventLogArtifact::from_causal_projection(
            self.id,
            fork_point,
            projection.content_hash(),
            projection.canonical_bytes().len(),
            projection.len(),
            coverage_fingerprint,
            shared_store_segments,
        )
    }

    /// Replays the artifact and checks a reconstructed event log against metadata.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if replaying this artifact's scenario/schedule or
    /// reconstructing the replay log fails before comparison.
    pub fn verify_event_log_replay_with<F>(
        &self,
        event_log: &ReproductionEventLogArtifact,
        replay_log: F,
    ) -> Result<ReproductionEventLogReplay, EngineError>
    where
        F: FnOnce(
            &ReproductionArtifact,
            &ReproductionReplay,
        ) -> Result<Vec<crate::scheduler::SchedulerEventLogEntry>, EngineError>,
    {
        let reduction = self.replay()?;
        let reproduced_entries = replay_log(self, &reduction)?;
        let reproduced = crate::scheduler::event_log_causal_projection(&reproduced_entries);
        let reproduced_coverage_fingerprint =
            coverage_fingerprint_from_event_log(&reproduced_entries);
        Ok(ReproductionEventLogReplay {
            reduction,
            event_log_artifact: event_log.id(),
            artifact_matches: event_log.reproduction_artifact == self.id,
            fork_point: event_log.fork_point,
            expected_causal_subsequence: event_log.causal_subsequence,
            reproduced_causal_subsequence: reproduced.content_hash(),
            expected_causal_bytes: event_log.causal_subsequence_bytes,
            reproduced_causal_bytes: reproduced.canonical_bytes().len(),
            expected_causal_events: event_log.causal_subsequence_events,
            reproduced_causal_events: reproduced.len(),
            expected_coverage_fingerprint: event_log.coverage_fingerprint,
            reproduced_coverage_fingerprint,
            shared_store_segments: event_log.shared_store_segments.clone(),
        })
    }
}
