//! Scenario forms, configurations, decisions, and schedules.

use super::*;

/// A fully materialized scenario definition form for storage and exchange.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioDefForm {
    pub(super) world: World,
    pub(super) plan: Plan,
    pub(super) properties: Properties,
    pub(super) seed: Seed,
    pub(super) app_random_draw_cap: u64,
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
        validate_world_serialized_identity(world)?;
        let properties = resolve_properties_dsl_for_context(world, plan, properties)?;
        match plan.event_graph() {
            Some(_) => {
                properties.validate_for_world(world)?;
                plan.validate_for_world_with_properties(world, &properties)?;
            }
            None => {
                plan.validate_for_world(world)?;
                properties.validate_for_world(world)?;
            }
        }
        Ok(Self {
            world: world.clone(),
            plan: plan.clone(),
            properties: properties.clone(),
            seed,
            app_random_draw_cap,
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
        self.world
            .scenario_def_from_components_with_app_random_draw_cap(
                &self.plan,
                &self.properties,
                self.seed,
                self.app_random_draw_cap,
            )
    }

    /// Returns the content address of the reconstructed scenario definition.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.scenario_def().id()
    }

    /// Serializes this form as deterministic TOML.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if the TOML renderer rejects
    /// the internal DTO shape.
    pub fn to_canonical_toml(&self) -> Result<String, EngineError> {
        toml::to_string(&scenario_form_to_toml(self)).map_err(|source| {
            scenario_serialization_error(format!("serialize scenario TOML: {source}"))
        })
    }

    /// Parses and validates a deterministic TOML scenario form.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed TOML or id
    /// mismatches, [`EngineError::PlanNegativeTime`],
    /// [`EngineError::PlanFaultUnknownDirection`], or
    /// [`EngineError::PlanFaultUnsupportedParam`] for localized serialized plan
    /// validation failures, or the same validation errors as the component
    /// constructors when the parsed world, plan, or properties are invalid.
    pub fn from_canonical_toml(input: &str) -> Result<Self, EngineError> {
        validate_no_host_path_image_refs_in_toml(input)?;
        validate_plan_entries_in_toml(input)?;
        let toml = toml::from_str::<ScenarioDefToml>(input).map_err(|source| {
            scenario_serialization_error(format!("parse scenario TOML: {source}"))
        })?;
        scenario_form_from_toml(toml)
    }

    /// Serializes this form as the compact canonical binary representation.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let includes_io_nodes = self.world.io_nodes().next().is_some();
        let magic = if includes_io_nodes {
            SCENARIO_FORM_BINARY_MAGIC_V2
        } else {
            SCENARIO_FORM_BINARY_MAGIC_V1
        };
        let mut writer = ScenarioBinaryWriter::new(magic);
        write_scenario_form_binary(self, &mut writer, includes_io_nodes);
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
        let (mut reader, includes_io_nodes) = scenario_binary_reader_for_versions(
            bytes,
            SCENARIO_FORM_BINARY_MAGIC_V1,
            SCENARIO_FORM_BINARY_MAGIC_V2,
        )?;
        let form = read_scenario_form_binary(&mut reader, includes_io_nodes)?;
        reader.finish()?;
        Ok(form)
    }

    /// Returns the canonical bytes used to compute this scenario definition's id.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        scenario_world_plan_properties_seed_app_random_cap_material(
            &self.world,
            &self.plan,
            &self.properties,
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
    /// execution model exposes the `Configuration::id()` API named in RFC-0010.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.content_hash()
    }
}

/// One resolved nondeterministic choice at a scheduling point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Decision {
    /// A deterministic or recorded ordering of events at one virtual time.
    DeliveryOrder(DeliveryOrderDecision),
    /// The recorded outcome of a probabilistic fault.
    FaultFires(FaultDecision),
    /// A raw draw from a named deterministic decision stream.
    RngDraw(RngDecision),
    /// A search or fuzzing override at a scheduling point.
    Override(OverrideDecision),
    /// A vCPU switch or interrupt-preemption decision.
    Preemption(PreemptionDecision),
    /// A served application-requested random value.
    AppRandom(AppRandomDecision),
    /// A boundary-applied imperative fault-control action.
    ControlFault(ControlFaultDecision),
}

impl Decision {
    /// Returns the set of nodes this decision is known to touch.
    ///
    /// `None` means the current model cannot prove the decision is node-local,
    /// so search reductions must treat it as dependent on other decisions.
    #[must_use]
    pub fn touched_nodes(&self) -> Option<BTreeSet<NodeId>> {
        decision_touched_nodes(self)
    }

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
}

impl Schedule {
    /// Builds an empty schedule.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            decisions: Vec::new(),
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
                Decision::FaultFires(decision) => Some(decision.at),
                Decision::ControlFault(decision) => Some(decision.at),
                Decision::RngDraw(_)
                | Decision::Override(_)
                | Decision::Preemption(_)
                | Decision::AppRandom(_) => None,
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
        })
    }

    /// Returns a new schedule with `decision` appended.
    #[must_use]
    pub fn appended(&self, decision: Decision) -> Self {
        let mut decisions = self.decisions.clone();
        decisions.push(decision);
        Self { decisions }
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
        let mut writer = ScenarioBinaryWriter::new(SCHEDULE_BINARY_MAGIC);
        write_schedule_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact binary schedule.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed binary input
    /// or a schedule id mismatch.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, SCHEDULE_BINARY_MAGIC)?;
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
