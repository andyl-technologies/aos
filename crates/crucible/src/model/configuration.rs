//! Scenario forms, configurations, decisions, and schedules.

use super::*;

/// A fully materialized scenario definition form for storage and exchange.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioDefForm {
    pub(super) world: World,
    pub(super) plan: Plan,
    pub(super) properties: Properties,
    pub(super) measurements: MeasurementDefinitions,
    pub(super) selectables: ScenarioSelectables,
    pub(super) seed: Seed,
    pub(super) app_random_draw_cap: u64,
    // Immutable validated components retain a fixed identity; reads allocate no material.
    definition: ScenarioDef,
}

impl ScenarioDefForm {
    /// Builds a serialized-form scenario from independently addressed components.
    ///
    /// The constructor validates that the plan and properties layer over `world`
    /// before the form can be serialized.
    ///
    /// # Errors
    ///
    /// Returns a world identity error when `world` carries non-canonical identity,
    /// a plan validation error when `plan` cannot layer over the static world, or a
    /// properties validation error when `properties` references undeclared nodes.
    pub fn from_components(
        world: &World,
        plan: &Plan,
        properties: &Properties,
        seed: Seed,
    ) -> Result<Self, EngineError> {
        Self::from_components_with_app_random_draw_cap(
            world,
            plan,
            properties,
            seed,
            DEFAULT_APP_RANDOM_DRAW_CAP,
        )
    }

    /// Builds a serialized-form scenario from independently addressed
    /// components and an app-random draw cap.
    ///
    /// The constructor validates that the plan and properties layer over `world`
    /// before the form can be serialized. The cap is part of the reconstructed
    /// scenario definition identity.
    ///
    /// # Errors
    ///
    /// Returns a world identity error when `world` carries non-canonical identity,
    /// a plan validation error when `plan` cannot layer over the static world, or a
    /// properties validation error when `properties` references undeclared nodes.
    pub fn from_components_with_app_random_draw_cap(
        world: &World,
        plan: &Plan,
        properties: &Properties,
        seed: Seed,
        app_random_draw_cap: u64,
    ) -> Result<Self, EngineError> {
        Self::from_components_with_measurements_and_app_random_draw_cap(
            world,
            plan,
            properties,
            &MeasurementDefinitions::empty(),
            seed,
            app_random_draw_cap,
        )
    }

    /// Builds a serialized-form scenario with measurement definitions and the
    /// default app-random draw cap.
    ///
    /// # Errors
    ///
    /// Returns the same world, plan, property, and measurement validation
    /// errors as [`Self::from_components_with_measurements_and_app_random_draw_cap`].
    pub fn from_components_with_measurements(
        world: &World,
        plan: &Plan,
        properties: &Properties,
        measurements: &MeasurementDefinitions,
        seed: Seed,
    ) -> Result<Self, EngineError> {
        Self::from_components_with_measurements_and_app_random_draw_cap(
            world,
            plan,
            properties,
            measurements,
            seed,
            DEFAULT_APP_RANDOM_DRAW_CAP,
        )
    }

    /// Builds a serialized-form scenario with measurement definitions and an
    /// app-random draw cap.
    ///
    /// # Errors
    ///
    /// Returns the same world, plan, and property validation errors as
    /// [`Self::from_components_with_app_random_draw_cap`]. Returns
    /// [`EngineError::ScenarioSerialization`] when `measurements` are not the
    /// canonical definitions for these exact scenario components.
    pub fn from_components_with_measurements_and_app_random_draw_cap(
        world: &World,
        plan: &Plan,
        properties: &Properties,
        measurements: &MeasurementDefinitions,
        seed: Seed,
        app_random_draw_cap: u64,
    ) -> Result<Self, EngineError> {
        let world = world.clone_admitted()?;
        let plan = plan.clone_admitted_for_world(&world)?;
        let properties = properties
            .clone_admitted_for_world(&world)?
            .into_resolved_for_context(&world, &plan)?;
        let measurements = measurements.clone_admitted_for_context(&world, &plan, &properties)?;
        Self::from_owned_components(
            world,
            plan,
            properties,
            measurements,
            ScenarioSelectables::empty(),
            seed,
            app_random_draw_cap,
        )
    }

    /// Consumes already admitted decoded components without a second deep copy.
    pub(super) fn from_owned_components(
        world: World,
        plan: Plan,
        properties: Properties,
        measurements: MeasurementDefinitions,
        selectables: ScenarioSelectables,
        seed: Seed,
        app_random_draw_cap: u64,
    ) -> Result<Self, EngineError> {
        validate_world_serialized_identity(&world)?;
        let properties = properties.into_resolved_for_context(&world, &plan)?;
        properties.validate_for_world(&world)?;
        plan.validate_for_world_with_properties(&world, &properties)?;
        let measurements = measurements.into_validated(&world, &plan, &properties)?;
        let definition = canonical_scenario_definition(
            &world,
            &plan,
            &properties,
            &measurements,
            &selectables,
            seed,
            app_random_draw_cap,
        )?;
        Ok(Self {
            world,
            plan,
            properties,
            measurements,
            selectables,
            seed,
            app_random_draw_cap,
            definition,
        })
    }

    /// Returns the serialized world component.
    #[must_use]
    pub fn world(&self) -> &World {
        &self.world
    }

    /// Returns the serialized plan component.
    #[must_use]
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Returns the serialized properties component.
    #[must_use]
    pub fn properties(&self) -> &Properties {
        &self.properties
    }

    /// Returns the serialized measurement-definition component.
    #[must_use]
    pub fn measurements(&self) -> &MeasurementDefinitions {
        &self.measurements
    }

    /// Returns the immutable scenario selectable declarations and ceilings.
    #[must_use]
    pub const fn selectables(&self) -> &ScenarioSelectables {
        &self.selectables
    }

    /// Returns the serialized scenario seed component.
    #[must_use]
    pub fn seed(&self) -> Seed {
        self.seed
    }

    /// Returns the serialized app-random draw cap component.
    #[must_use]
    pub fn app_random_draw_cap(&self) -> u64 {
        self.app_random_draw_cap
    }

    /// Reconstructs the immutable scenario definition handle.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        self.definition.clone()
    }

    /// Returns the content address of the reconstructed scenario definition.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.definition.id()
    }

    /// Rebuilds this scenario around a replacement validated plan.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when `plan` does not layer over the retained
    /// world and properties.
    pub fn with_plan(&self, plan: Plan) -> Result<Self, EngineError> {
        let retained = self.try_clone_admitted()?;
        Self::from_owned_components(
            retained.world,
            plan,
            retained.properties,
            retained.measurements,
            retained.selectables,
            retained.seed,
            retained.app_random_draw_cap,
        )
    }

    /// Rebuilds this scenario around an exact validated selectable catalog.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when the catalog does not
    /// decode canonically for this World or names an absent guest node.
    pub fn with_selectables(&self, selectables: ScenarioSelectables) -> Result<Self, EngineError> {
        let selectables =
            ScenarioSelectables::from_canonical_bytes(&self.world, selectables.canonical_body())?;
        let mut rebuilt = self.try_clone_admitted()?;
        rebuilt.selectables = selectables;
        rebuilt.refresh_definition()?;
        Ok(rebuilt)
    }

    fn refresh_definition(&mut self) -> Result<(), EngineError> {
        self.definition = canonical_scenario_definition(
            &self.world,
            &self.plan,
            &self.properties,
            &self.measurements,
            &self.selectables,
            self.seed,
            self.app_random_draw_cap,
        )?;
        Ok(())
    }

    /// Serializes this form as deterministic TOML.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if the TOML renderer rejects
    /// the internal DTO shape.
    pub fn to_canonical_toml(&self) -> Result<String, EngineError> {
        toml::to_string(&scenario_form_to_toml(self)?).map_err(|source| {
            scenario_serialization_error(format!("serialize scenario TOML: {source}"))
        })
    }

    /// Parses and validates a deterministic TOML scenario form.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed TOML or id
    /// mismatches, or the same validation errors as the component constructors
    /// when the parsed world, plan, or properties are invalid.
    pub fn from_canonical_toml(input: &str) -> Result<Self, EngineError> {
        validate_scenario_toml_size(input)?;
        validate_no_host_path_image_refs_in_toml(input)?;
        require_current_fault_schema(input)?;
        let toml = toml::from_str::<ScenarioDefToml>(input).map_err(|source| {
            scenario_serialization_error(format!("parse scenario TOML: {source}"))
        })?;
        scenario_form_from_toml(toml)
    }

    /// Serializes this form as the compact canonical binary representation.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(SCENARIO_FORM_BINARY_MAGIC_V9);
        write_scenario_form_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact binary scenario form.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed binary input or
    /// id mismatches, or the same validation errors as the component constructors
    /// when the parsed world, plan, or properties are invalid.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, SCENARIO_FORM_BINARY_MAGIC_V9)?;
        let form = read_scenario_form_binary(&mut reader)?;
        reader.finish()?;
        Ok(form)
    }

    /// Returns the canonical bytes used to compute this scenario definition's id.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        scenario_world_plan_properties_measurements_selectables_seed_app_random_cap_material(
            &self.world,
            &self.plan,
            &self.properties,
            &self.measurements,
            &self.selectables,
            self.seed,
            self.app_random_draw_cap,
        )
        .into_bytes()
    }
}

/// The only identity-bearing execution configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Configuration {
    /// The immutable definition of the run.
    pub def: ScenarioDef,
    /// The ordered decisions already taken for this definition.
    pub schedule: Schedule,
}

impl Configuration {
    /// Builds the genesis configuration for `def`.
    #[must_use]
    pub fn genesis(def: ScenarioDef) -> Self {
        Self {
            def,
            schedule: Schedule::empty(),
        }
    }

    /// Returns whether this configuration has an empty schedule.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.schedule.is_empty()
    }

    /// Computes the canonical identity of this configuration.
    ///
    /// The configuration identity is a pure function of the immutable scenario
    /// definition and the recorded schedule prefix. Runtime caches and
    /// materialized checkpoints do not contribute to this identity.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        canonical::configuration_hash(self)
    }

    /// Computes the RFC-named content-addressed configuration id.
    ///
    /// This is an alias for [`Configuration::content_hash`]. It exists so the
    /// execution model exposes the canonical `Configuration::id()` API.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.content_hash()
    }
}

/// Structurally validated campaign selection embedded in one schedule decision.
///
/// The wrapper retains the strict language-neutral selection bytes rather than
/// process-private consumer state. A replaying producer reconstructs the exact
/// opportunity and domain, decodes [`Self::selection`], and applies the value
/// only after the campaign replay validator succeeds.
/// Scheduler preemption branches also retain their bounded producer domain so
/// partial-order reduction can regenerate parent-bound selections after a swap.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SelectionDecision {
    canonical_selection: Vec<u8>,
    app_random_model_sample: bool,
    campaign_branch: bool,
    preemption_config: Option<Box<PreemptionBranchConfig>>,
}

impl SelectionDecision {
    /// Copies validated selection bytes and producer evidence under original resource custody.
    ///
    /// # Errors
    /// Refuses exhausted original metadata authority or allocation failure.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        let canonical_selection = admitted_clone::copy_vec(&self.canonical_selection)?;
        let preemption_config = match self.preemption_config.as_deref() {
            Some(config) => {
                crate::owned_decode::charge_array::<PreemptionBranchConfig>(1)
                    .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
                let node = NodeId {
                    name: admitted_clone::copy_string(&config.node.name)?,
                };
                Some(Box::new(PreemptionBranchConfig {
                    node,
                    deadline: config.deadline,
                    horizon: config.horizon,
                    step: config.step,
                    switch_from_vcpu: config.switch_from_vcpu,
                    switch_to_vcpu: config.switch_to_vcpu,
                    target_vcpu: config.target_vcpu,
                    irq: config.irq,
                }))
            }
            None => None,
        };
        Ok(Self {
            canonical_selection,
            app_random_model_sample: self.app_random_model_sample,
            campaign_branch: self.campaign_branch,
            preemption_config,
        })
    }

    /// Builds one schedule decision from a constructed campaign selection.
    #[must_use]
    pub fn new(selection: &crucible_campaign::Selection) -> Self {
        Self {
            canonical_selection: selection.canonical_bytes(),
            app_random_model_sample: crate::decision::is_app_random_model_selection(selection),
            campaign_branch: matches!(
                selection.origin(),
                crucible_campaign::SelectionOrigin::CampaignBranch { .. }
            ),
            preemption_config: None,
        }
    }

    /// Retains the bounded producer domain required to commute a preemption branch.
    ///
    /// # Errors
    ///
    /// Returns an error when `selection` is not a campaign branch.
    pub(crate) fn new_preemption_branch(
        selection: &crucible_campaign::Selection,
        config: &PreemptionBranchConfig,
    ) -> Result<Self, crucible_campaign::CampaignCodecError> {
        let mut decision = Self::new(selection);
        if !decision.campaign_branch || !config.has_bounded_domain() {
            return Err(crucible_campaign::CampaignCodecError::InvalidValue {
                reason: "preemption producer evidence requires a bounded campaign branch",
            });
        }
        decision.preemption_config = Some(Box::new(config.clone()));
        Ok(decision)
    }

    /// Decodes one strict canonical selection decision.
    ///
    /// # Errors
    ///
    /// Returns [`crucible_campaign::CampaignCodecError`] for malformed,
    /// noncanonical, invalid, or oversized selection bytes.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, crucible_campaign::CampaignCodecError> {
        let selection = crucible_campaign::Selection::from_canonical_bytes(bytes)?;
        Ok(Self::new(&selection))
    }

    /// Returns the strict language-neutral selection bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_selection
    }

    /// Returns whether this decision uses the standardized app-random model.
    ///
    /// The flag is derived from the canonical selection bytes and is not a
    /// separate serialized field.
    #[must_use]
    pub const fn is_app_random_model_sample(&self) -> bool {
        self.app_random_model_sample
    }

    /// Returns whether this decision was produced by a campaign branch.
    ///
    /// The flag is derived from the canonical selection bytes and is not a
    /// separate serialized field.
    #[must_use]
    pub const fn is_campaign_branch(&self) -> bool {
        self.campaign_branch
    }

    /// Returns the retained bounded preemption producer domain, if present.
    #[must_use]
    pub fn preemption_config(&self) -> Option<&PreemptionBranchConfig> {
        self.preemption_config.as_deref()
    }

    /// Decodes the retained campaign selection.
    ///
    /// Construction guarantees these bytes already passed strict structural
    /// decoding. Opportunity, domain, and origin-specific replay validation is
    /// still required before execution.
    ///
    /// # Errors
    ///
    /// Returns [`crucible_campaign::CampaignCodecError`] if in-memory bytes no
    /// longer form the canonical validated selection.
    pub fn selection(
        &self,
    ) -> Result<crucible_campaign::Selection, crucible_campaign::CampaignCodecError> {
        crucible_campaign::Selection::from_canonical_bytes(&self.canonical_selection)
    }
}

impl serde::Serialize for SelectionDecision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SelectionDecisionRef {
            canonical_selection: &self.canonical_selection,
            preemption_config: self.preemption_config.as_deref(),
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SelectionDecision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SelectionDecisionWire::deserialize(deserializer)?;
        let mut decision = Self::from_canonical_bytes(&wire.canonical_selection)
            .map_err(serde::de::Error::custom)?;
        if wire
            .preemption_config
            .as_ref()
            .is_some_and(|config| !decision.campaign_branch || !config.has_bounded_domain())
        {
            return Err(serde::de::Error::custom(
                "preemption producer evidence requires a bounded campaign branch",
            ));
        }
        decision.preemption_config = wire.preemption_config.map(Box::new);
        Ok(decision)
    }
}

#[derive(serde::Serialize)]
struct SelectionDecisionRef<'a> {
    canonical_selection: &'a [u8],
    preemption_config: Option<&'a PreemptionBranchConfig>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionDecisionWire {
    canonical_selection: Vec<u8>,
    preemption_config: Option<PreemptionBranchConfig>,
}

/// One resolved nondeterministic choice at a scheduling point.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Decision {
    /// A deterministic or recorded ordering of events at one virtual time.
    DeliveryOrder(DeliveryOrderDecision),
    /// A raw draw from a named deterministic decision stream.
    RngDraw(RngDecision),
    /// A search or fuzzing override at a scheduling point.
    Override(OverrideDecision),
    /// A vCPU switch or interrupt-preemption decision.
    Preemption(PreemptionDecision),
    /// An unresolved typed campaign selection requiring producer validation.
    Selection(SelectionDecision),
}

impl Decision {
    /// Returns whether `policy` proves this decision independent from `other`.
    ///
    /// Independence requires an explicit unordered-pair proof, known disjoint
    /// node sets, and no shared ordered decision resource. Unknown/global
    /// decision kinds are treated as dependent.
    #[must_use]
    pub fn is_independent_from(&self, other: &Self, policy: &PartialOrderReductionPolicy) -> bool {
        decisions_are_independent(self, other, policy)
    }

    /// Returns the deterministic ordering key used by partial-order reduction.
    ///
    /// Search uses this key only to pick one representative interleaving for
    /// decisions already proven independent; it is not part of configuration
    /// identity.
    #[must_use]
    pub fn reduction_order_key(&self) -> ContentHash {
        decision_reduction_order_key(self)
    }
}

/// A totally ordered sequence of [`Decision`] values.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Schedule {
    pub(super) decisions: Vec<Decision>,
    pub(super) _decode_custody: crate::owned_decode::DecodeCustody,
}

impl Schedule {
    /// Builds an empty schedule.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            decisions: Vec::new(),
            _decode_custody: crate::owned_decode::DecodeCustody::default(),
        }
    }

    /// Builds a schedule from decisions in recorded order.
    ///
    /// The caller owns semantic validity of the sequence; validation happens when
    /// the schedule is reduced against a [`ScenarioDef`].
    #[must_use]
    pub fn from_decisions<I>(decisions: I) -> Self
    where
        I: IntoIterator<Item = Decision>,
    {
        decisions
            .into_iter()
            .fold(Self::empty(), |schedule, decision| {
                schedule.appended(decision)
            })
    }

    /// Returns whether the schedule has no decisions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }

    /// Returns the number of decisions in this schedule.
    #[must_use]
    pub fn len(&self) -> usize {
        self.decisions.len()
    }

    /// Returns the decisions in their canonical order.
    #[must_use]
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    /// Returns the latest virtual-time coordinate carried by recorded decisions.
    ///
    /// Decisions without a time coordinate inherit the most recent recorded
    /// boundary. A schedule containing only timeless decisions returns `None`.
    #[must_use]
    pub fn recorded_virtual_time(&self) -> Option<VirtualTime> {
        self.decisions.iter().fold(None, |recorded, decision| {
            let at = match decision {
                Decision::DeliveryOrder(decision) => Some(decision.at),
                Decision::RngDraw(_)
                | Decision::Override(_)
                | Decision::Preemption(_)
                | Decision::Selection(_) => None,
            };
            match (recorded, at) {
                (Some(current), Some(at)) => Some(current.max(at)),
                (None, Some(at)) => Some(at),
                (recorded, None) => recorded,
            }
        })
    }

    /// Returns a schedule containing the first `len` decisions.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::PrefixTooLong`] when `len` is greater than the
    /// number of decisions in this schedule.
    pub fn prefix(&self, len: usize) -> Result<Self, ScheduleError> {
        if len > self.decisions.len() {
            return Err(ScheduleError::PrefixTooLong {
                requested: len,
                available: self.decisions.len(),
            });
        }

        Ok(Self {
            decisions: self.decisions[..len].to_vec(),
            _decode_custody: self._decode_custody.clone(),
        })
    }

    /// Returns the suffix after the first `len` decisions.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::PrefixTooLong`] when `len` is greater than the
    /// number of decisions in this schedule.
    pub fn suffix_from(&self, len: usize) -> Result<Self, ScheduleError> {
        if len > self.decisions.len() {
            return Err(ScheduleError::PrefixTooLong {
                requested: len,
                available: self.decisions.len(),
            });
        }

        Ok(Self {
            decisions: self.decisions[len..].to_vec(),
            _decode_custody: self._decode_custody.clone(),
        })
    }

    /// Returns a new schedule with `decision` appended.
    #[must_use]
    pub fn appended(&self, decision: Decision) -> Self {
        let mut decisions = self.decisions.clone();
        decisions.push(decision);
        Self {
            decisions,
            _decode_custody: self._decode_custody.clone(),
        }
    }

    /// Computes the canonical identity of this schedule.
    ///
    /// The hash includes every decision in order and changes when a decision is
    /// reordered, inserted, or modified.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        canonical::schedule_hash(self)
    }

    /// Serializes this schedule as compact canonical bytes.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(SCHEDULE_BINARY_MAGIC_V4);
        write_schedule_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact binary schedule.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed input, a
    /// schedule identity mismatch, or any schema other than current version 4.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, SCHEDULE_BINARY_MAGIC_V4)?;
        let schedule = read_schedule_binary(&mut reader)?;
        reader.finish()?;
        Ok(schedule)
    }
}

/// An error produced by schedule shape helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    /// The requested prefix is longer than the schedule.
    PrefixTooLong {
        /// The requested prefix length.
        requested: usize,
        /// The number of available decisions.
        available: usize,
    },
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrefixTooLong {
                requested,
                available,
            } => write!(
                f,
                "schedule prefix length {requested} exceeds available length {available}"
            ),
        }
    }
}

impl Error for ScheduleError {}
