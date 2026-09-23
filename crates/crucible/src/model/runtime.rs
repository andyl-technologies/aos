//! Fork/search runtime state and top-level engine operations.

use super::*;
pub(super) mod coverage_guidance;
pub(super) mod search;

pub(super) use coverage_guidance::*;
pub(super) use search::*;

use crate::HostAssertionReport;

/// Result of a graph-level fork operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraphFork {
    /// Runtime produced for the fork base.
    pub base: TemporalGraphRuntime,
    /// Branch configuration produced by appending fork decisions.
    pub branch: Configuration,
    /// Thin checkpoint recorded for the branch.
    pub branch_checkpoint: Checkpoint,
}

impl TemporalGraphFork {
    /// Emits a self-contained reproduction artifact for the forked branch.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when artifact capture or replay validation fails.
    pub fn reproduction_artifact(
        &self,
        scenario: &ScenarioDefForm,
        finding_fingerprint: ContentHash,
    ) -> Result<FindingReproductionArtifact, EngineError> {
        FindingReproductionArtifact::capture(
            FindingDiscoveryPath::CampaignFork,
            finding_fingerprint,
            scenario,
            &self.branch,
        )
    }
}

/// Result of a graph-level search frontier expansion.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraphSearch {
    /// Frontier configuration expanded by the operation.
    pub frontier: ContentHash,
    /// Runtime realized for the frontier before decisions were enumerated.
    pub frontier_runtime: TemporalGraphRuntime,
    /// Reduced frontier enumeration report.
    pub frontier_report: FrontierReductionReport,
    /// Checkpoints returned by hot/cold materialization policy for explored children.
    pub materialized: Vec<Checkpoint>,
    /// Replay-oracle sampling report when active search sampling was enabled.
    pub replay_oracle_sampling: Option<SearchReplayOracleSamplingReport>,
}

/// Canonical-relabeling fingerprint for symmetry reduction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymmetryReductionKey {
    /// Hash of coverage plus node-local state under canonical node relabeling.
    pub fingerprint: ContentHash,
}

/// A caller-provided class of interchangeable nodes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymmetryClassId {
    /// Stable class name within one scenario.
    pub name: String,
}

/// Explicit interchangeable-node classes for symmetry reduction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SymmetryReductionClasses {
    /// Node-to-class mapping. Nodes absent from this map retain their identity.
    pub classes: BTreeMap<NodeId, SymmetryClassId>,
}

impl SymmetryReductionClasses {
    /// Builds an empty class map, which disables symmetry reduction.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `node` to an interchangeable class.
    #[must_use]
    pub fn with_node_class(mut self, node: NodeId, class: SymmetryClassId) -> Self {
        self.classes.insert(node, class);
        self
    }

    /// Returns whether no interchangeable classes are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }
}

/// Canonical ordering fingerprint for one independent decision pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartialOrderReductionKey {
    /// Hash of the canonical representative interleaving.
    pub fingerprint: ContentHash,
}

/// Explicit proof that one unordered pair of decisions is independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartialOrderIndependenceProof {
    /// Lower deterministic decision key.
    pub first: ContentHash,
    /// Higher deterministic decision key.
    pub second: ContentHash,
}

impl PartialOrderIndependenceProof {
    /// Builds an unordered independence proof for two decisions.
    #[must_use]
    pub fn new(left: &Decision, right: &Decision) -> Self {
        let left = left.reduction_order_key();
        let right = right.reduction_order_key();
        if left <= right {
            Self {
                first: left,
                second: right,
            }
        } else {
            Self {
                first: right,
                second: left,
            }
        }
    }
}

/// Explicit independence proofs for partial-order reduction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PartialOrderReductionPolicy {
    /// Proven independent unordered decision pairs.
    pub independent_pairs: BTreeSet<PartialOrderIndependenceProof>,
}

impl PartialOrderReductionPolicy {
    /// Builds an empty proof set, which disables partial-order skips.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an unordered independent decision pair proof.
    #[must_use]
    pub fn with_independent_pair(mut self, left: &Decision, right: &Decision) -> Self {
        self.independent_pairs
            .insert(PartialOrderIndependenceProof::new(left, right));
        self
    }

    /// Returns whether this policy proves `left` and `right` independent.
    #[must_use]
    pub fn proves_independent(&self, left: &Decision, right: &Decision) -> bool {
        self.independent_pairs
            .contains(&PartialOrderIndependenceProof::new(left, right))
    }
}

/// A live runtime-state handle produced by `instantiate`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuntimeState {
    /// The runtime state's content address.
    pub id: ContentHash,
    /// The configuration materialized by this runtime state.
    pub configuration: ContentHash,
    /// Per-node VM-state refs available to a fat checkpoint materialization.
    pub node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    /// Per-node retired instruction counters at the materialization point.
    pub node_icounts: BTreeMap<NodeId, Icount>,
    /// Scheduler-owned state reconstructed at the materialization point.
    pub scheduler: SchedulerState,
    /// Event-log offset from which a resumed run continues appending.
    pub event_log: EventLogOffset,
}

/// Appends one decision to a configuration without materializing runtime state.
///
/// # Errors
///
/// Returns [`EngineError::AppRandomDrawCapExceeded`] when appending `decision`
/// would put the configuration above its per-scenario app-random draw cap.
pub fn try_step(config: &Configuration, decision: Decision) -> Result<Configuration, EngineError> {
    let next = Configuration {
        def: config.def.clone(),
        schedule: config.schedule.appended(decision),
    };
    validate_app_random_draw_cap(&next.def, &next.schedule)?;
    Ok(next)
}

/// Computes the abstract state denoted by `def` and `schedule`.
///
/// # Errors
///
/// Returns [`EngineError::AppRandomDrawCapExceeded`] when `schedule` contains
/// more standardized typed app-random selections than `def` admits.
pub fn reduce(def: &ScenarioDef, schedule: &Schedule) -> Result<State, EngineError> {
    validate_app_random_draw_cap(def, schedule)?;
    Ok(State {
        id: canonical::reduced_state_hash(def, schedule),
    })
}

pub(super) fn validate_app_random_draw_cap(
    def: &ScenarioDef,
    schedule: &Schedule,
) -> Result<(), EngineError> {
    let actual = count_app_random_decisions(schedule);
    if actual > def.app_random_draw_cap {
        return Err(EngineError::AppRandomDrawCapExceeded {
            scenario: def.id,
            cap: def.app_random_draw_cap,
            actual,
        });
    }
    Ok(())
}

pub(super) fn validate_debug_gdb_endpoint(
    field: &'static str,
    value: &str,
) -> Result<(), EngineError> {
    if value.is_empty() || value.contains('\n') || value.contains('\0') {
        Err(EngineError::DebugGdbEndpointInvalid {
            field,
            value: value.to_owned(),
        })
    } else {
        Ok(())
    }
}

pub(super) fn count_app_random_decisions(schedule: &Schedule) -> u64 {
    let decisions = schedule.decisions();
    decisions
        .iter()
        .enumerate()
        .filter(|(index, _decision)| {
            crate::decision::is_app_random_schedule_decision(decisions, *index)
        })
        .count() as u64
}

/// Selects adaptive exploration arms deterministically for `budget` steps.
#[must_use]
pub fn run_adaptive_strategy_selection(
    config: &AdaptiveStrategyConfig,
    graph: &BTreeSet<ContentHash>,
    credits: &[AdaptiveStrategyCredit],
    budget: SearchBudget,
) -> AdaptiveStrategyRun {
    let rewards = adaptive_strategy_rewards_from_credits(credits);
    let graph_fingerprint = adaptive_strategy_graph_fingerprint(graph);
    let mut pulls = BTreeMap::<AdaptiveStrategyArm, u64>::new();
    let mut selections = Vec::new();
    for sequence in 0..budget.max_expansions {
        let arm =
            select_adaptive_strategy_arm(config, graph_fingerprint, &rewards, &pulls, sequence);
        let score = adaptive_strategy_arm_score(config, &rewards, &pulls, arm);
        pulls
            .entry(arm)
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        selections.push(AdaptiveStrategySelection {
            sequence,
            arm,
            score,
        });
    }
    AdaptiveStrategyRun {
        campaign_identity: config.campaign_identity(),
        graph_fingerprint,
        selections,
    }
}

/// Lints guidance/adaptive ordering source for forbidden floating-point tokens.
#[must_use]
pub fn lint_guidance_determinism_source(source: &str) -> GuidanceDeterminismLintReport {
    // The forbidden token is assembled with `concat!` so this scanner's own
    // source does not contain the literal it forbids, keeping determinism
    // gates that raw-grep this file for floating-point tokens from
    // self-triggering on the probe.
    let forbidden_hits = [concat!("f6", "4")]
        .iter()
        .filter(|token| source.contains(**token))
        .map(|token| (*token).to_string())
        .collect();
    GuidanceDeterminismLintReport { forbidden_hits }
}

/// Generates bounded typed preemption branch choices at an exact parent.
///
/// # Errors
///
/// Returns [`EngineError::ScenarioSerialization`] if the finite typed choice
/// records cannot be represented canonically.
pub fn preemption_branch_choices(
    parent: &Configuration,
    config: &PreemptionBranchConfig,
) -> Result<
    (
        crucible_campaign::ChoiceDiscovery,
        Vec<SearchFrontierChoice>,
    ),
    EngineError,
> {
    preemption_branch_choices_filtered(parent, config, None)
}

fn preemption_branch_choices_filtered(
    parent: &Configuration,
    config: &PreemptionBranchConfig,
    selected: Option<&Decision>,
) -> Result<
    (
        crucible_campaign::ChoiceDiscovery,
        Vec<SearchFrontierChoice>,
    ),
    EngineError,
> {
    if !config.has_bounded_domain() {
        return Err(EngineError::ScenarioSerialization {
            reason: String::from("preemption branch domain is empty or exceeds 4096 alternatives"),
        });
    }

    let mut retired = config.deadline.retired;
    let mut preemptions = Vec::new();
    while retired <= config.horizon.retired {
        preemptions.push(PreemptionDecision {
            node: config.node.clone(),
            at: Icount { retired },
            kind: PreemptionKind::VcpuSwitch {
                from_vcpu: config.switch_from_vcpu,
                to_vcpu: config.switch_to_vcpu,
            },
        });
        preemptions.push(PreemptionDecision {
            node: config.node.clone(),
            at: Icount { retired },
            kind: PreemptionKind::InterruptAt {
                target_vcpu: config.target_vcpu,
                irq: config.irq,
            },
        });
        let Some(next) = retired.checked_add(config.step) else {
            break;
        };
        if next == retired {
            break;
        }
        retired = next;
    }

    use crucible_campaign::{
        CampaignHash, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain, ChoiceSource,
        ChoiceValue, ConfigurationId, DiscreteAlternative, DiscreteDomain, ScenarioDefId,
        SelectableDeclaration, Selection,
    };

    let mut alternatives = BTreeMap::new();
    let mut alternative_ids = Vec::with_capacity(preemptions.len());
    for preemption in &preemptions {
        let alternative = preemption_alternative_id(preemption);
        let label = match preemption.kind {
            PreemptionKind::VcpuSwitch { .. } => format!("vcpu-switch-{}", preemption.at.retired),
            PreemptionKind::InterruptAt { .. } => format!("interrupt-{}", preemption.at.retired),
        };
        alternatives.insert(
            alternative,
            DiscreteAlternative::new(alternative, label, None).map_err(preemption_choice_error)?,
        );
        alternative_ids.push(alternative);
    }
    let Some(default) = alternative_ids.first().copied() else {
        return Err(EngineError::ScenarioSerialization {
            reason: String::from("preemption branch domain is empty"),
        });
    };
    let domain = ChoiceDomain::Discrete(
        DiscreteDomain::new(1, alternatives).map_err(preemption_choice_error)?,
    );
    let declaration = SelectableDeclaration::new(
        "scheduler-preemption",
        ChoiceSource::Scheduler {
            producer: String::from("crucible.preemption.v1"),
        },
        domain.clone(),
        ChoiceValue::Discrete(default),
        ChoiceClassContext::new(BTreeSet::from([
            String::from("per-event"),
            String::from("preemption"),
        ]))
        .map_err(preemption_choice_error)?,
        BTreeSet::from([
            String::from("bounded"),
            String::from("scheduler-interleaving"),
        ]),
        false,
    )
    .map_err(preemption_choice_error)?;
    let producer = CampaignHash::derive(
        "crucible.preemption.opportunity.v1",
        &Schedule::from_decisions(preemptions.iter().cloned().map(Decision::Preemption))
            .to_compact_binary(),
    );
    let opportunity = crucible_campaign::ChoiceOpportunity::new(
        ScenarioDefId::from_hash(CampaignHash::from_bytes(parent.def.id().bytes)),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::from_bytes(parent.id().bytes),
            producer,
        },
        "bounded-window",
        None,
    )
    .map_err(preemption_choice_error)?;
    let branch_point = opportunity.branch_point_id(ConfigurationId::from_hash(
        CampaignHash::from_bytes(parent.id().bytes),
    ));
    let sequences = preemptions
        .into_iter()
        .zip(alternative_ids)
        // Replay needs the complete domain identity, but only one selection.
        .filter(|(preemption, _)| {
            selected.is_none_or(|decision| {
                matches!(decision, Decision::Preemption(candidate) if candidate == preemption)
            })
        })
        .map(|(preemption, alternative)| {
            let selection = Selection::new_campaign_branch(
                &opportunity,
                &domain,
                ChoiceValue::Discrete(alternative),
                branch_point,
            )
            .map_err(preemption_choice_error)?;
            Ok([
                Decision::Selection(
                    SelectionDecision::new_preemption_branch(&selection, config)
                        .map_err(preemption_choice_error)?,
                ),
                Decision::Preemption(preemption),
            ])
        })
        .collect::<Result<Vec<_>, EngineError>>()?;
    let choices = SearchFrontierChoices::from_decision_sequences(sequences)
        .choices()
        .to_vec();
    let discovery = crucible_campaign::ChoiceDiscovery::new(declaration, domain, opportunity)
        .map_err(preemption_choice_error)?;
    Ok((discovery, choices))
}

fn preemption_choice_error(error: crucible_campaign::CampaignCodecError) -> EngineError {
    EngineError::ScenarioSerialization {
        reason: format!("preemption choice protocol rejected its producer records: {error}"),
    }
}

fn preemption_alternative_id(preemption: &PreemptionDecision) -> crucible_campaign::AlternativeId {
    let bytes =
        Schedule::from_decisions([Decision::Preemption(preemption.clone())]).to_compact_binary();
    crucible_campaign::AlternativeId::from_hash(crucible_campaign::CampaignHash::derive(
        "crucible.preemption.alternative.v1",
        &bytes,
    ))
}

/// Authenticates retained preemption producer evidence at every recorded parent.
///
/// # Errors
///
/// Returns [`EngineError::ScenarioSerialization`] when typed producer evidence
/// is missing or does not reproduce its selection and preemption at that prefix.
pub fn validate_preemption_branch_schedule(
    configuration: &Configuration,
) -> Result<(), EngineError> {
    let decisions = configuration.schedule.decisions();
    if !decisions.iter().enumerate().any(|(index, decision)| {
        matches!(decision, Decision::Selection(selection) if selection.preemption_config().is_some()
            || (selection.is_campaign_branch()
                && matches!(decisions.get(index + 1), Some(Decision::Preemption(_)))))
    }) {
        return Ok(());
    }

    let mut parent = Configuration::genesis(configuration.def.clone());
    for (index, decision) in decisions.iter().enumerate() {
        if let Decision::Selection(selection) = decision {
            if let Some(config) = selection.preemption_config() {
                let preemption = decisions
                    .get(index + 1)
                    .ok_or_else(|| preemption_producer_mismatch(index))?;
                let expected = preemption_choice_at(&parent, config, preemption)
                    .ok_or_else(|| preemption_producer_mismatch(index))?;
                if expected.as_slice() != &decisions[index..index + 2] {
                    return Err(preemption_producer_mismatch(index));
                }
            } else if let Some(Decision::Preemption(preemption)) = decisions.get(index + 1) {
                if selection.is_campaign_branch()
                    && matches!(
                        selection.selection().map_err(preemption_choice_error)?.value(),
                        crucible_campaign::ChoiceValue::Discrete(alternative)
                            if *alternative == preemption_alternative_id(preemption)
                    )
                {
                    return Err(EngineError::ScenarioSerialization {
                        reason: format!(
                            "preemption producer evidence is missing at decision {index}"
                        ),
                    });
                }
            }
        }
        parent = try_step(&parent, decision.clone())?;
    }
    Ok(())
}

fn preemption_producer_mismatch(index: usize) -> EngineError {
    EngineError::ScenarioSerialization {
        reason: format!("preemption producer evidence does not reproduce at decision {index}"),
    }
}

pub(super) fn preemption_choice_at(
    parent: &Configuration,
    config: &PreemptionBranchConfig,
    preemption: &Decision,
) -> Option<[Decision; 2]> {
    preemption_branch_choices_filtered(parent, config, Some(preemption))
        .ok()?
        .1
        .into_iter()
        .find_map(|choice| match choice.decisions() {
            [selection @ Decision::Selection(_), branch] if branch == preemption => {
                Some([selection.clone(), branch.clone()])
            }
            _ => None,
        })
}

/// Materializes `config` into a live runtime through `graph`.
///
/// Exact cached snapshots are checked against the replay oracle before they are
/// loaded whenever the graph has a baked genesis root for the scenario.
///
/// # Errors
///
/// Returns [`EngineError::MissingBakedGenesis`] when materialization reaches
/// genesis and the graph has no baked genesis checkpoint for the scenario.
/// Returns other [`EngineError`] variants when cached checkpoint metadata is
/// invalid or suffix replay does not reconstruct the requested configuration.
pub fn instantiate(
    graph: &TemporalGraph,
    config: &Configuration,
) -> Result<RuntimeState, EngineError> {
    validate_preemption_branch_schedule(config)?;
    instantiate_validated(graph, config)
}

fn instantiate_validated(
    graph: &TemporalGraph,
    config: &Configuration,
) -> Result<RuntimeState, EngineError> {
    if config.is_genesis() {
        let genesis =
            graph
                .genesis_snapshot(&config.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: config.def.id,
                })?;
        return load_snapshot(config, &genesis.checkpoint);
    }

    if let Some(snapshot) = graph.cached_snapshot(config) {
        if graph.has_replay_oracle_path(config)? {
            graph.replay_checkpoint(config, snapshot)?;
        }
        return load_snapshot(config, snapshot);
    }

    if let Some(ancestor) = graph.nearest_cached_ancestor(config)? {
        let ancestor_runtime = instantiate_validated(graph, &ancestor)?;
        let suffix = config
            .schedule
            .suffix_from(ancestor.schedule.len())
            .map_err(EngineError::SchedulePrefix)?;
        return replay_suffix(ancestor_runtime, &ancestor, &suffix, config);
    }

    let genesis = Configuration::genesis(config.def.clone());
    let genesis_runtime = instantiate_validated(graph, &genesis)?;
    let suffix = config
        .schedule
        .suffix_from(genesis.schedule.len())
        .map_err(EngineError::SchedulePrefix)?;
    replay_suffix(genesis_runtime, &genesis, &suffix, config)
}

/// Produces the genesis checkpoint for `world`.
///
/// # Errors
///
/// This pure model helper is total for a content-addressed [`World`] handle.
/// Backend-specific bake implementations may still return backend errors while
/// starting guests to their ready point and saving VM state.
pub fn bake(world: &World) -> Result<GenesisCheckpoint, EngineError> {
    world.validate_ready_point_policies()?;
    let def = world.scenario_def();
    let genesis = Configuration::genesis(def);

    let checkpoint = Checkpoint::from_recorded_configuration(
        &genesis,
        None,
        VirtualTime::default(),
        baked_node_icounts(world),
        CheckpointKind::Fat,
        baked_node_blobs(world),
    )?;

    Ok(GenesisCheckpoint { checkpoint })
}
