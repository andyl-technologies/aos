//! Fork/search runtime state and top-level engine operations.

use super::*;

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
            FindingDiscoveryPath::InteractiveFork,
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

/// Appends one decision to a configuration without materializing runtime state.
///
/// Prefer [`try_step`] in fallible engine paths. This compatibility helper is
/// intentionally loud when a caller tries to build an over-cap app-random
/// configuration.
///
/// # Panics
///
/// Panics when appending `decision` would put the configuration above its
/// per-scenario app-random draw cap.
#[must_use]
pub fn step(config: &Configuration, decision: Decision) -> Configuration {
    match try_step(config, decision) {
        Ok(next) => next,
        Err(error) => panic!("configuration step rejected: {error}"),
    }
}

/// Computes the abstract state denoted by `def` and `schedule`.
///
/// # Errors
///
/// Returns [`EngineError::AppRandomDrawCapExceeded`] when `schedule` contains
/// more [`Decision::AppRandom`] entries than `def` admits.
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
    schedule
        .decisions()
        .iter()
        .filter(|decision| matches!(decision, Decision::AppRandom(_)))
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

/// Generates bounded preemption branch decisions.
#[must_use]
pub fn preemption_branch_decisions(config: &PreemptionBranchConfig) -> Vec<Decision> {
    if config.step == 0 || config.deadline.retired > config.horizon.retired {
        return Vec::new();
    }

    let mut retired = config.deadline.retired;
    let mut decisions = Vec::new();
    while retired <= config.horizon.retired {
        decisions.push(Decision::Preemption(PreemptionDecision {
            node: config.node.clone(),
            at: Icount { retired },
            kind: PreemptionKind::VcpuSwitch {
                from_vcpu: config.switch_from_vcpu,
                to_vcpu: config.switch_to_vcpu,
            },
        }));
        decisions.push(Decision::Preemption(PreemptionDecision {
            node: config.node.clone(),
            at: Icount { retired },
            kind: PreemptionKind::InterruptAt {
                target_vcpu: config.target_vcpu,
                irq: config.irq,
            },
        }));
        let Some(next) = retired.checked_add(config.step) else {
            break;
        };
        if next == retired {
            break;
        }
        retired = next;
    }
    decisions
}

pub(super) fn run_coverage_guided_fuzz(
    family: &ScenarioFamily,
    config: CoverageGuidedFuzzConfig,
    feedback: &[EventLogCoverageFeedback],
) -> Result<CoverageGuidedFuzzRun, EngineError> {
    let cardinality = family.space().cardinality()?;
    let mut iterations = Vec::new();
    let mut seen_coverage = BTreeSet::new();
    let mut corpus = vec![coverage_guided_fuzz_seed_corpus_entry(config, cardinality)];

    for sequence in 0..config.iterations {
        let coverage_fingerprint = coverage_guided_fuzz_feedback_fingerprint(feedback, sequence);
        let selected_corpus_entry = coverage_guided_fuzz_select_corpus_entry(
            config,
            sequence,
            coverage_fingerprint,
            &corpus,
        );
        let energy = coverage_guided_fuzz_energy(config, sequence, coverage_fingerprint);
        let sample_index =
            coverage_guided_fuzz_sample_index(config, sequence, coverage_fingerprint, cardinality);
        let scenario = family.instantiate_sample(sample_index)?;
        let params = scenario.params();
        let root = scenario.genesis_configuration();
        let mutation =
            coverage_guided_fuzz_override_decision(config, sequence, sample_index, params);
        let configuration = try_step(root.configuration(), mutation.clone())?;
        let new_coverage = coverage_fingerprint != ContentHash::default()
            && seen_coverage.insert(coverage_fingerprint);
        if new_coverage {
            corpus.push(configuration.id());
        }
        iterations.push(CoverageGuidedFuzzIteration {
            sequence,
            sample_index,
            params,
            scenario,
            selected_corpus_entry,
            energy,
            configuration,
            mutation,
            coverage_fingerprint,
            new_coverage,
        });
    }

    let coverage_biased_order = coverage_guided_fuzz_order(&iterations);
    Ok(CoverageGuidedFuzzRun {
        config,
        iterations,
        coverage_biased_order,
    })
}

pub(super) fn run_coverage_guided_fuzz_corpus<S>(
    family: &ScenarioFamily,
    store: &S,
    config: CoverageGuidedFuzzConfig,
    corpus_config: CoverageGuidedCorpusConfig,
    feedback: &[EventLogCoverageFeedback],
) -> Result<CoverageGuidedCorpusRun, CoverageGuidedCorpusError>
where
    S: DagStore + ?Sized,
{
    let cardinality =
        family
            .space()
            .cardinality()
            .map_err(|source| CoverageGuidedCorpusError::Engine {
                operation: "count-family-space",
                source: Box::new(source),
            })?;
    let mut corpus = CoverageGuidedCorpus::new();
    let seed =
        family
            .instantiate_sample(0)
            .map_err(|source| CoverageGuidedCorpusError::Engine {
                operation: "instantiate-seed-corpus-entry",
                source: Box::new(source),
            })?;
    let seed_artifact =
        ReproductionArtifact::capture(seed.form(), &Schedule::empty()).map_err(|source| {
            CoverageGuidedCorpusError::Engine {
                operation: "capture-seed-corpus-artifact",
                source: Box::new(source),
            }
        })?;
    let seed_replay =
        seed_artifact
            .replay()
            .map_err(|source| CoverageGuidedCorpusError::Engine {
                operation: "replay-seed-corpus-artifact",
                source: Box::new(source),
            })?;
    let seed_store_key = persist_corpus_artifact(store, &seed_artifact)?;
    let seed_energy = coverage_guided_corpus_energy(
        corpus_config.seed,
        0,
        ContentHash::default(),
        seed_artifact.id(),
    );
    let seed_descriptor_key = persist_corpus_entry_descriptor(
        store,
        CoverageGuidedCorpusEntryDescriptor {
            artifact: seed_artifact.id(),
            store_key: seed_store_key,
            scenario: seed_replay.scenario,
            schedule: seed_replay.schedule,
            replayed_state: seed_replay.state,
            coverage_fingerprint: ContentHash::default(),
            energy: seed_energy,
            parent: None,
            origin: CoverageGuidedCorpusEntryOrigin::Seed,
        },
    )?;
    corpus.insert(CoverageGuidedCorpusEntry {
        artifact: seed_artifact.id(),
        store_key: seed_store_key,
        descriptor_key: seed_descriptor_key,
        scenario: seed_replay.scenario,
        schedule: seed_replay.schedule,
        replayed_state: seed_replay.state,
        coverage_fingerprint: ContentHash::default(),
        energy: seed_energy,
        parent: None,
        origin: CoverageGuidedCorpusEntryOrigin::Seed,
    });

    let mut iterations = Vec::new();
    let mut admissions = Vec::new();
    let mut store_puts = 2u64;
    let mut replay_oracle_validations = 1u64;

    for sequence in 0..config.iterations {
        let coverage_fingerprint = coverage_guided_fuzz_feedback_fingerprint(feedback, sequence);
        let selected_parent = coverage_guided_corpus_select_parent(
            &corpus,
            corpus_config,
            sequence,
            coverage_fingerprint,
        )
        .ok_or_else(|| CoverageGuidedCorpusError::Engine {
            operation: "select-corpus-parent",
            source: Box::new(EngineError::ScenarioFamilyInvalidSpace {
                reason: "coverage-guided corpus has no seed entry",
            }),
        })?;
        let sample_index =
            coverage_guided_fuzz_sample_index(config, sequence, coverage_fingerprint, cardinality);
        let scenario = family.instantiate_sample(sample_index).map_err(|source| {
            CoverageGuidedCorpusError::Engine {
                operation: "instantiate-fuzz-candidate",
                source: Box::new(source),
            }
        })?;
        let params = scenario.params();
        let root = scenario.genesis_configuration();
        let mutation =
            coverage_guided_fuzz_override_decision(config, sequence, sample_index, params);
        let configuration = try_step(root.configuration(), mutation.clone()).map_err(|source| {
            CoverageGuidedCorpusError::Engine {
                operation: "mutate-fuzz-candidate",
                source: Box::new(source),
            }
        })?;
        let artifact = ReproductionArtifact::capture(scenario.form(), &configuration.schedule)
            .map_err(|source| CoverageGuidedCorpusError::Engine {
                operation: "capture-fuzz-candidate-artifact",
                source: Box::new(source),
            })?;
        let replay = artifact
            .replay()
            .map_err(|source| CoverageGuidedCorpusError::Engine {
                operation: "replay-fuzz-candidate-artifact",
                source: Box::new(source),
            })?;
        replay_oracle_validations = replay_oracle_validations.saturating_add(1);
        let energy = coverage_guided_corpus_energy(
            corpus_config.seed,
            sequence.saturating_add(1),
            coverage_fingerprint,
            artifact.id(),
        );
        let decision = if let Some(retained) = corpus.entries.get(&artifact.id()) {
            CoverageGuidedCorpusAdmissionDecision::DuplicateArtifact {
                retained: retained.artifact,
            }
        } else if let Some(retained) = corpus.coverage_owner(coverage_fingerprint) {
            CoverageGuidedCorpusAdmissionDecision::PrunedSubsumedCoverage { retained }
        } else {
            let store_key = persist_corpus_artifact(store, &artifact)?;
            let descriptor_key = persist_corpus_entry_descriptor(
                store,
                CoverageGuidedCorpusEntryDescriptor {
                    artifact: artifact.id(),
                    store_key,
                    scenario: replay.scenario,
                    schedule: replay.schedule,
                    replayed_state: replay.state,
                    coverage_fingerprint,
                    energy,
                    parent: Some(selected_parent),
                    origin: CoverageGuidedCorpusEntryOrigin::FuzzIteration { sequence },
                },
            )?;
            store_puts = store_puts.saturating_add(2);
            corpus.insert(CoverageGuidedCorpusEntry {
                artifact: artifact.id(),
                store_key,
                descriptor_key,
                scenario: replay.scenario,
                schedule: replay.schedule,
                replayed_state: replay.state,
                coverage_fingerprint,
                energy,
                parent: Some(selected_parent),
                origin: CoverageGuidedCorpusEntryOrigin::FuzzIteration { sequence },
            });
            CoverageGuidedCorpusAdmissionDecision::AdmittedNewCoverage { store_key }
        };
        let new_coverage = decision.is_admitted();

        admissions.push(CoverageGuidedCorpusAdmission {
            sequence,
            artifact: artifact.id(),
            coverage_fingerprint,
            selected_parent,
            energy,
            decision,
        });
        iterations.push(CoverageGuidedFuzzIteration {
            sequence,
            sample_index,
            params,
            scenario,
            selected_corpus_entry: selected_parent,
            energy,
            configuration,
            mutation,
            coverage_fingerprint,
            new_coverage,
        });
    }

    let coverage_biased_order = coverage_guided_fuzz_order(&iterations);
    let retained_entries = corpus.len() as u64;
    Ok(CoverageGuidedCorpusRun {
        fuzz: CoverageGuidedFuzzRun {
            config,
            iterations,
            coverage_biased_order,
        },
        corpus,
        admissions,
        throughput: CoverageGuidedFuzzThroughputReport {
            target: corpus_config.throughput_target,
            generated_mutants: config.iterations,
            deterministic_work_units: config.iterations,
            replay_oracle_validations,
            store_puts,
            retained_entries,
        },
    })
}

pub(super) fn persist_corpus_artifact<S>(
    store: &S,
    artifact: &ReproductionArtifact,
) -> Result<ContentHash, CoverageGuidedCorpusError>
where
    S: DagStore + ?Sized,
{
    let store_key = store.put(&artifact.to_compact_binary()).map_err(|source| {
        CoverageGuidedCorpusError::Store {
            operation: "put-corpus-artifact",
            source,
        }
    })?;
    if store_key != artifact.id() {
        return Err(CoverageGuidedCorpusError::ArtifactStoreKeyMismatch {
            artifact: artifact.id(),
            store_key,
        });
    }
    Ok(store_key)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct CoverageGuidedCorpusEntryDescriptor {
    pub(super) artifact: ContentHash,
    pub(super) store_key: ContentHash,
    pub(super) scenario: ContentHash,
    pub(super) schedule: ContentHash,
    pub(super) replayed_state: ContentHash,
    pub(super) coverage_fingerprint: ContentHash,
    pub(super) energy: u64,
    pub(super) parent: Option<ContentHash>,
    pub(super) origin: CoverageGuidedCorpusEntryOrigin,
}

pub(super) fn persist_corpus_entry_descriptor<S>(
    store: &S,
    descriptor: CoverageGuidedCorpusEntryDescriptor,
) -> Result<ContentHash, CoverageGuidedCorpusError>
where
    S: DagStore + ?Sized,
{
    store
        .put(&coverage_guided_corpus_entry_descriptor_bytes(descriptor))
        .map_err(|source| CoverageGuidedCorpusError::Store {
            operation: "put-corpus-entry-descriptor",
            source,
        })
}

pub(super) fn coverage_guided_corpus_entry_descriptor_bytes(
    descriptor: CoverageGuidedCorpusEntryDescriptor,
) -> Vec<u8> {
    let origin = match descriptor.origin {
        CoverageGuidedCorpusEntryOrigin::Seed => String::from("seed"),
        CoverageGuidedCorpusEntryOrigin::FuzzIteration { sequence } => {
            format!("fuzz-iteration:{sequence}")
        }
    };
    let parent = descriptor
        .parent
        .map(ContentHash::to_hex)
        .unwrap_or_else(|| String::from("none"));
    format!(
        "crucible.coverage-guided-corpus.entry.v1\nartifact={}\nartifact_store={}\nscenario={}\nschedule={}\nreplayed_state={}\ncoverage={}\nenergy={}\nparent={parent}\norigin={origin}\n",
        descriptor.artifact.to_hex(),
        descriptor.store_key.to_hex(),
        descriptor.scenario.to_hex(),
        descriptor.schedule.to_hex(),
        descriptor.replayed_state.to_hex(),
        descriptor.coverage_fingerprint.to_hex(),
        descriptor.energy
    )
    .into_bytes()
}

pub(super) fn coverage_guided_fuzz_feedback_fingerprint(
    feedback: &[EventLogCoverageFeedback],
    sequence: u64,
) -> ContentHash {
    if feedback.is_empty() {
        return ContentHash::default();
    }

    let index = (sequence % feedback.len() as u64) as usize;
    feedback[index].fingerprint_for(EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing)
}

pub(super) fn coverage_guided_fuzz_seed_corpus_entry(
    config: CoverageGuidedFuzzConfig,
    cardinality: u64,
) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.coverage-guided-fuzz.seed-corpus-entry.v1",
        &format!(
            "meta_seed={}\ncardinality={cardinality}",
            config.meta_seed.to_hex()
        ),
    )
}

pub(super) fn coverage_guided_fuzz_select_corpus_entry(
    config: CoverageGuidedFuzzConfig,
    sequence: u64,
    coverage_fingerprint: ContentHash,
    corpus: &[ContentHash],
) -> ContentHash {
    let material = format!(
        "meta_seed={}\nsequence={sequence}\ncoverage={}\ncorpus_len={}",
        config.meta_seed.to_hex(),
        coverage_fingerprint.to_hex(),
        corpus.len()
    );
    let index = content_hash_low_u64(ContentHash::from_canonical_material(
        "crucible.coverage-guided-fuzz.corpus-selection.v1",
        &material,
    )) as usize
        % corpus.len();
    corpus[index]
}

pub(super) fn coverage_guided_corpus_select_parent(
    corpus: &CoverageGuidedCorpus,
    config: CoverageGuidedCorpusConfig,
    sequence: u64,
    coverage_fingerprint: ContentHash,
) -> Option<ContentHash> {
    let total_energy = corpus.entries.values().fold(0u64, |total, entry| {
        total.saturating_add(entry.energy.max(1))
    });
    if total_energy == 0 {
        return corpus.entries.keys().next().copied();
    }

    let material = format!(
        "seed={}\nsequence={sequence}\ncoverage={}\ncorpus={}",
        config.seed.to_hex(),
        coverage_fingerprint.to_hex(),
        corpus.fingerprint().to_hex()
    );
    let mut ticket = content_hash_low_u64(ContentHash::from_canonical_material(
        "crucible.coverage-guided-corpus.parent-selection.v1",
        &material,
    )) % total_energy;
    for entry in corpus.entries.values() {
        let weight = entry.energy.max(1);
        if ticket < weight {
            return Some(entry.artifact);
        }
        ticket = ticket.saturating_sub(weight);
    }
    corpus.entries.keys().next_back().copied()
}

pub(super) fn coverage_guided_corpus_energy(
    seed: Seed,
    sequence: u64,
    coverage_fingerprint: ContentHash,
    artifact: ContentHash,
) -> u64 {
    let material = format!(
        "seed={}\nsequence={sequence}\ncoverage={}\nartifact={}",
        seed.to_hex(),
        coverage_fingerprint.to_hex(),
        artifact.to_hex()
    );
    let base = content_hash_low_u64(ContentHash::from_canonical_material(
        "crucible.coverage-guided-corpus.energy.v1",
        &material,
    ));
    let novelty_floor = if coverage_fingerprint == ContentHash::default() {
        1
    } else {
        GUIDANCE_SCORE_ONE_MICRO
    };
    novelty_floor.saturating_add(base % GUIDANCE_SCORE_ONE_MICRO)
}

pub(super) fn coverage_guided_fuzz_energy(
    config: CoverageGuidedFuzzConfig,
    sequence: u64,
    coverage_fingerprint: ContentHash,
) -> u64 {
    let material = format!(
        "meta_seed={}\nsequence={sequence}\ncoverage={}",
        config.meta_seed.to_hex(),
        coverage_fingerprint.to_hex()
    );
    let base = content_hash_low_u64(ContentHash::from_canonical_material(
        "crucible.coverage-guided-fuzz.energy.v1",
        &material,
    ));
    1 + (base % 1024)
}

pub(super) fn coverage_guided_fuzz_sample_index(
    config: CoverageGuidedFuzzConfig,
    sequence: u64,
    coverage_fingerprint: ContentHash,
    cardinality: u64,
) -> u64 {
    let material = format!(
        "meta_seed={}\ncoverage={}",
        config.meta_seed.to_hex(),
        coverage_fingerprint.to_hex()
    );
    let bias = content_hash_low_u64(ContentHash::from_canonical_material(
        COVERAGE_GUIDED_FUZZ_SAMPLE_DOMAIN,
        &material,
    ));
    bias.wrapping_add(sequence) % cardinality
}

pub(super) fn coverage_guided_fuzz_override_decision(
    config: CoverageGuidedFuzzConfig,
    sequence: u64,
    sample_index: u64,
    params: FamilyParams,
) -> Decision {
    let material = format!(
        "meta_seed={}\nsequence={sequence}\nsample_index={sample_index}\nseed={}\nfault_density={}\ntopology_size={}\ntopology_shape={:?}",
        config.meta_seed.to_hex(),
        params.seed.to_hex(),
        params.fault_density.millionths(),
        params.topology_size,
        params.topology_shape
    );
    let choice = content_hash_low_u64(ContentHash::from_canonical_material(
        COVERAGE_GUIDED_FUZZ_OVERRIDE_DOMAIN,
        &material,
    ));
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: format!("coverage-guided-fuzz/{sequence:016}"),
        },
        choice: ChoiceTag {
            name: format!("mutant-{choice:016x}"),
        },
    })
}

pub(super) fn coverage_guided_fuzz_order(
    iterations: &[CoverageGuidedFuzzIteration],
) -> Vec<ContentHash> {
    let mut ordered = iterations.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        coverage_guided_fuzz_iteration_key(left)
            .cmp(&coverage_guided_fuzz_iteration_key(right))
            .then_with(|| left.configuration_id().cmp(&right.configuration_id()))
    });
    ordered
        .into_iter()
        .map(CoverageGuidedFuzzIteration::configuration_id)
        .collect()
}

pub(super) fn coverage_guided_fuzz_iteration_key(
    iteration: &CoverageGuidedFuzzIteration,
) -> (u8, u8, ContentHash) {
    let old_coverage = u8::from(!iteration.new_coverage);
    let unknown_coverage = u8::from(iteration.coverage_fingerprint == ContentHash::default());
    (
        old_coverage,
        unknown_coverage,
        iteration.coverage_fingerprint,
    )
}

pub(super) fn content_hash_low_u64(hash: ContentHash) -> u64 {
    u64::from_le_bytes([
        hash.bytes[0],
        hash.bytes[1],
        hash.bytes[2],
        hash.bytes[3],
        hash.bytes[4],
        hash.bytes[5],
        hash.bytes[6],
        hash.bytes[7],
    ])
}

pub(super) fn guidance_signal_score(
    signal: GuidanceSignalKind,
    input: GuidanceSignalInput,
) -> GuidanceScore {
    match signal {
        GuidanceSignalKind::Coverage => CoverageGuidanceSignal.score(input),
        GuidanceSignalKind::NoveltyRarity => NoveltyRarityGuidanceSignal.score(input),
        GuidanceSignalKind::AssertionProximity => AssertionProximityGuidanceSignal.score(input),
    }
}

pub(super) fn select_adaptive_strategy_arm(
    config: &AdaptiveStrategyConfig,
    graph_fingerprint: ContentHash,
    rewards: &BTreeMap<AdaptiveStrategyArm, AdaptiveStrategyReward>,
    pulls: &BTreeMap<AdaptiveStrategyArm, u64>,
    sequence: u64,
) -> AdaptiveStrategyArm {
    if !config.enabled {
        return AdaptiveStrategyArm::BreadthFirst;
    }
    if config.breadth_first_floor_interval != 0
        && sequence.is_multiple_of(config.breadth_first_floor_interval)
        && config.arms.contains(&AdaptiveStrategyArm::BreadthFirst)
    {
        return AdaptiveStrategyArm::BreadthFirst;
    }

    config
        .arms
        .iter()
        .copied()
        .max_by_key(|arm| {
            (
                adaptive_strategy_arm_score(config, rewards, pulls, *arm),
                adaptive_strategy_arm_tie_break(config.seed, graph_fingerprint, *arm),
                std::cmp::Reverse(*arm),
            )
        })
        .unwrap_or(AdaptiveStrategyArm::BreadthFirst)
}

pub(super) fn adaptive_strategy_arm_score(
    config: &AdaptiveStrategyConfig,
    rewards: &BTreeMap<AdaptiveStrategyArm, AdaptiveStrategyReward>,
    pulls: &BTreeMap<AdaptiveStrategyArm, u64>,
    arm: AdaptiveStrategyArm,
) -> u64 {
    let pull_count = pulls.get(&arm).copied().unwrap_or_default();
    if pull_count == 0 {
        return u64::MAX;
    }
    let reward = rewards.get(&arm).copied().unwrap_or_default();
    let reward_total = adaptive_strategy_reward_total(reward);
    let exploitation = u128::from(reward_total)
        .saturating_mul(u128::from(ADAPTIVE_UCB_SCORE_ONE_MICRO))
        .checked_div(u128::from(pull_count))
        .unwrap_or_default()
        .min(u128::from(u64::MAX)) as u64;
    let total_pulls = pulls
        .values()
        .copied()
        .fold(0u64, u64::saturating_add)
        .max(1);
    let log2_total_micros = u64::from(total_pulls.saturating_add(1).ilog2())
        .saturating_mul(ADAPTIVE_UCB_SCORE_ONE_MICRO);
    let exploration_root = integer_square_root(
        u128::from(log2_total_micros)
            .saturating_mul(u128::from(ADAPTIVE_UCB_SCORE_ONE_MICRO))
            .checked_div(u128::from(pull_count))
            .unwrap_or_default(),
    );
    let exploration = u128::from(config.ucb_exploration_weight_micros)
        .saturating_mul(exploration_root)
        .checked_div(u128::from(ADAPTIVE_UCB_SCORE_ONE_MICRO))
        .unwrap_or_default()
        .min(u128::from(u64::MAX)) as u64;
    exploitation.saturating_add(exploration)
}

pub(super) fn adaptive_strategy_reward_total(reward: AdaptiveStrategyReward) -> u64 {
    let failure = if reward.confirmed_failure {
        ADAPTIVE_CONFIRMED_FAILURE_REWARD
    } else {
        0
    };
    reward
        .new_coverage
        .saturating_add(reward.novelty_gain)
        .saturating_add(reward.assertion_proximity_progress)
        .saturating_add(failure)
}

pub(super) fn adaptive_strategy_arm_tie_break(
    seed: Seed,
    graph_fingerprint: ContentHash,
    arm: AdaptiveStrategyArm,
) -> u64 {
    let material = format!(
        "seed={}\ngraph={}\narm={arm:?}",
        seed.to_hex(),
        graph_fingerprint.to_hex()
    );
    content_hash_low_u64(ContentHash::from_canonical_material(
        "crucible.adaptive-strategy.ucb-tie-break.v1",
        &material,
    ))
}

pub(super) fn integer_square_root(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let mut low = 1u128;
    let mut high = value.min(u128::from(u64::MAX)).saturating_add(1);
    while low.saturating_add(1) < high {
        let midpoint = low.saturating_add(high.saturating_sub(low) / 2);
        if midpoint <= value / midpoint {
            low = midpoint;
        } else {
            high = midpoint;
        }
    }
    low
}

pub(super) fn adaptive_strategy_rewards_from_credits(
    credits: &[AdaptiveStrategyCredit],
) -> BTreeMap<AdaptiveStrategyArm, AdaptiveStrategyReward> {
    let mut ordered = credits.to_vec();
    ordered.sort_by_key(|credit| (credit.configuration, credit.arm));
    let mut rewards = BTreeMap::<AdaptiveStrategyArm, AdaptiveStrategyReward>::new();
    for credit in ordered {
        rewards
            .entry(credit.arm)
            .and_modify(|reward| {
                *reward = combine_adaptive_strategy_rewards(*reward, credit.reward);
            })
            .or_insert(credit.reward);
    }
    rewards
}

pub(super) fn combine_adaptive_strategy_rewards(
    left: AdaptiveStrategyReward,
    right: AdaptiveStrategyReward,
) -> AdaptiveStrategyReward {
    AdaptiveStrategyReward {
        new_coverage: left.new_coverage.saturating_add(right.new_coverage),
        novelty_gain: left.novelty_gain.saturating_add(right.novelty_gain),
        assertion_proximity_progress: left
            .assertion_proximity_progress
            .saturating_add(right.assertion_proximity_progress),
        confirmed_failure: left.confirmed_failure || right.confirmed_failure,
    }
}

pub(super) fn adaptive_strategy_graph_fingerprint(graph: &BTreeSet<ContentHash>) -> ContentHash {
    if graph.is_empty() {
        return ContentHash::default();
    }
    let material = graph
        .iter()
        .map(|hash| hash.to_hex())
        .collect::<Vec<_>>()
        .join("\n");
    ContentHash::from_canonical_material("crucible.adaptive-strategy.graph.v1", &material)
}

pub(super) fn adaptive_strategy_config_material(config: &AdaptiveStrategyConfig) -> String {
    let arms = config
        .arms
        .iter()
        .map(|arm| format!("{arm:?}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "seed={}\nenabled={}\nfairness_floor={}\nucb_exploration_weight_micros={}\narms={arms}",
        config.seed.to_hex(),
        config.enabled,
        config.breadth_first_floor_interval,
        config.ucb_exploration_weight_micros
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SearchFrontierCandidate {
    pub(super) configuration: Configuration,
    pub(super) depth: usize,
}

impl SearchFrontierCandidate {
    pub(super) fn new(configuration: Configuration) -> Self {
        let depth = configuration.schedule.len();
        Self {
            configuration,
            depth,
        }
    }

    pub(super) fn id(&self) -> ContentHash {
        self.configuration.id()
    }
}

pub(super) fn select_search_frontier_candidate(
    graph: &TemporalGraph,
    worklist: &[SearchFrontierCandidate],
    strategy: SearchStrategy,
    max_depth: Option<u64>,
    guidance: Option<(&GuidanceSearchConfig, &GuidanceSearchState)>,
) -> Option<usize> {
    worklist
        .iter()
        .enumerate()
        .filter(|(_, candidate)| search_depth_allows_expansion(max_depth, candidate.depth))
        .min_by(|(_, left), (_, right)| match (strategy, guidance) {
            (SearchStrategy::CoverageGuided, Some((config, state))) => {
                compare_guided_search_frontier_candidates(graph, left, right, config, state)
            }
            _ => compare_search_frontier_candidates(graph, left, right, strategy),
        })
        .map(|(index, _)| index)
}

pub(super) fn search_depth_allows_expansion(max_depth: Option<u64>, depth: usize) -> bool {
    match max_depth {
        Some(max_depth) => (depth as u64) < max_depth,
        None => true,
    }
}

pub(super) fn select_fleet_work_stealing_candidate(
    worklist: &[SearchFrontierCandidate],
    host_count: u64,
    seed: Seed,
    sequence: u64,
) -> Option<usize> {
    let host_index = fleet_claim_host_index(host_count, seed, sequence);
    worklist
        .iter()
        .enumerate()
        .min_by_key(|(_, candidate)| {
            (
                fleet_work_stealing_score(seed, sequence, host_index, candidate),
                candidate.depth,
                candidate.id(),
            )
        })
        .map(|(index, _)| index)
}

pub(super) fn fleet_claim_host_index(host_count: u64, seed: Seed, sequence: u64) -> u64 {
    let host_count = host_count.max(1);
    let hash = ContentHash::from_canonical_material(
        "crucible.fleet-equivalence.claim-host.v1",
        &format!("seed={}\nsequence={sequence}\n", seed.to_hex()),
    );
    content_hash_low_u64(hash) % host_count
}

pub(super) fn fleet_work_stealing_score(
    seed: Seed,
    sequence: u64,
    host_index: u64,
    candidate: &SearchFrontierCandidate,
) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.fleet-equivalence.claim-score.v1",
        &format!(
            "seed={}\nsequence={sequence}\nhost={host_index}\ndepth={}\nfrontier={}\n",
            seed.to_hex(),
            candidate.depth,
            candidate.id().to_hex()
        ),
    )
}

pub(super) fn compare_search_frontier_candidates(
    graph: &TemporalGraph,
    left: &SearchFrontierCandidate,
    right: &SearchFrontierCandidate,
    strategy: SearchStrategy,
) -> std::cmp::Ordering {
    match strategy {
        SearchStrategy::BreadthFirst => left
            .depth
            .cmp(&right.depth)
            .then_with(|| left.id().cmp(&right.id())),
        SearchStrategy::DepthFirst => right
            .depth
            .cmp(&left.depth)
            .then_with(|| left.id().cmp(&right.id())),
        SearchStrategy::Priority { seed } => search_priority_score(seed, left)
            .cmp(&search_priority_score(seed, right))
            .then_with(|| left.id().cmp(&right.id())),
        SearchStrategy::CoverageGuided => search_coverage_guided_key(graph, left)
            .cmp(&search_coverage_guided_key(graph, right))
            .then_with(|| left.id().cmp(&right.id())),
    }
}

pub(super) fn fleet_artifacts_are_byte_identical(
    single: &TemporalGraphSearchRun,
    fleet: &FleetWorkStealingSearchRun,
    single_finding_set: &BTreeSet<FleetFindingSetEntry>,
    fleet_finding_set: &BTreeSet<FleetFindingSetEntry>,
) -> bool {
    if single_finding_set != fleet_finding_set {
        return false;
    }
    let fleet_by_finding = fleet
        .discovered_failures
        .iter()
        .map(|failure| ((failure.fingerprint, failure.configuration), failure))
        .collect::<BTreeMap<_, _>>();

    single.discovered_failures.iter().all(|single_failure| {
        let key = (single_failure.fingerprint, single_failure.configuration);
        fleet_by_finding.get(&key).is_some_and(|fleet_failure| {
            single_failure
                .reproduction_artifact
                .artifact
                .canonical_bytes()
                == fleet_failure
                    .reproduction_artifact
                    .artifact
                    .canonical_bytes()
        })
    })
}

pub(super) fn fleet_equivalence_divergence(
    single: &TemporalGraphSearchRun,
    fleet: &FleetWorkStealingSearchRun,
    single_finding_set: &BTreeSet<FleetFindingSetEntry>,
    fleet_finding_set: &BTreeSet<FleetFindingSetEntry>,
) -> FleetEquivalenceDivergence {
    if single.root != fleet.root {
        return FleetEquivalenceDivergence {
            reason: "root-differs",
            fingerprint: None,
            configuration: Some(single.root),
            single_artifact: None,
            fleet_artifact: None,
            bisection: fleet_equivalence_bisection(single.root, "fleet-equivalence-root-differs"),
        };
    }
    if single.budget != fleet.config.total_budget {
        return FleetEquivalenceDivergence {
            reason: "budget-differs",
            fingerprint: None,
            configuration: Some(single.root),
            single_artifact: None,
            fleet_artifact: None,
            bisection: fleet_equivalence_bisection(single.root, "fleet-equivalence-budget-differs"),
        };
    }
    if single.explored_graph != fleet.explored_graph {
        let configuration = single
            .explored_graph
            .symmetric_difference(&fleet.explored_graph)
            .next()
            .copied()
            .unwrap_or(single.root);
        return FleetEquivalenceDivergence {
            reason: "explored-graph-differs",
            fingerprint: None,
            configuration: Some(configuration),
            single_artifact: None,
            fleet_artifact: None,
            bisection: fleet_equivalence_bisection(
                configuration,
                "fleet-equivalence-explored-graph-differs",
            ),
        };
    }
    if !single.exhausted || !fleet.exhausted {
        return FleetEquivalenceDivergence {
            reason: "not-exhausted",
            fingerprint: None,
            configuration: Some(single.root),
            single_artifact: None,
            fleet_artifact: None,
            bisection: fleet_equivalence_bisection(single.root, "fleet-equivalence-not-exhausted"),
        };
    }

    let single_by_finding = single
        .discovered_failures
        .iter()
        .map(|failure| ((failure.fingerprint, failure.configuration), failure))
        .collect::<BTreeMap<_, _>>();
    let fleet_by_finding = fleet
        .discovered_failures
        .iter()
        .map(|failure| ((failure.fingerprint, failure.configuration), failure))
        .collect::<BTreeMap<_, _>>();

    let mut keys = single_by_finding
        .keys()
        .chain(fleet_by_finding.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    if keys.is_empty() {
        keys.extend(
            single_finding_set
                .iter()
                .chain(fleet_finding_set.iter())
                .map(|entry| (entry.fingerprint, entry.configuration)),
        );
    }

    for (fingerprint, configuration) in keys {
        let single_failure = single_by_finding.get(&(fingerprint, configuration));
        let fleet_failure = fleet_by_finding.get(&(fingerprint, configuration));
        match (single_failure, fleet_failure) {
            (Some(single_failure), Some(fleet_failure))
                if single_failure
                    .reproduction_artifact
                    .artifact
                    .canonical_bytes()
                    != fleet_failure
                        .reproduction_artifact
                        .artifact
                        .canonical_bytes() =>
            {
                return FleetEquivalenceDivergence {
                    reason: "artifact-bytes-differ",
                    fingerprint: Some(fingerprint),
                    configuration: Some(configuration),
                    single_artifact: Some(single_failure.reproduction_artifact.artifact.id()),
                    fleet_artifact: Some(fleet_failure.reproduction_artifact.artifact.id()),
                    bisection: fleet_equivalence_bisection(
                        configuration,
                        "fleet-equivalence-artifact-bytes-differ",
                    ),
                };
            }
            (Some(single_failure), None) => {
                return FleetEquivalenceDivergence {
                    reason: "missing-from-fleet",
                    fingerprint: Some(fingerprint),
                    configuration: Some(configuration),
                    single_artifact: Some(single_failure.reproduction_artifact.artifact.id()),
                    fleet_artifact: None,
                    bisection: fleet_equivalence_bisection(
                        configuration,
                        "fleet-equivalence-missing-from-fleet",
                    ),
                };
            }
            (None, Some(fleet_failure)) => {
                return FleetEquivalenceDivergence {
                    reason: "extra-in-fleet",
                    fingerprint: Some(fingerprint),
                    configuration: Some(configuration),
                    single_artifact: None,
                    fleet_artifact: Some(fleet_failure.reproduction_artifact.artifact.id()),
                    bisection: fleet_equivalence_bisection(
                        configuration,
                        "fleet-equivalence-extra-in-fleet",
                    ),
                };
            }
            (Some(_), Some(_)) | (None, None) => {}
        }
    }

    FleetEquivalenceDivergence {
        reason: "finding-set-differs",
        fingerprint: None,
        configuration: None,
        single_artifact: None,
        fleet_artifact: None,
        bisection: fleet_equivalence_bisection(
            single.root,
            "fleet-equivalence-finding-set-differs",
        ),
    }
}

pub(super) fn fleet_equivalence_bisection(
    configuration: ContentHash,
    reason: &'static str,
) -> SearchReplayOracleBisectionRequest {
    SearchReplayOracleBisectionRequest {
        sequence: 0,
        checkpoint: configuration,
        reason,
    }
}

pub(super) fn search_priority_score(seed: Seed, candidate: &SearchFrontierCandidate) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    hash = fold_fnv_bytes(hash, SEARCH_PRIORITY_SCORE_DOMAIN);
    hash = fold_fnv_bytes(hash, &seed.bytes());
    fold_fnv_bytes(hash, &(candidate.depth as u64).to_le_bytes())
}

pub(super) fn search_coverage_guided_key(
    graph: &TemporalGraph,
    candidate: &SearchFrontierCandidate,
) -> (u8, ContentHash) {
    let coverage = search_candidate_coverage_fingerprint(graph, &candidate.configuration);
    CoverageGuidanceSignal.search_order_key(GuidanceSignalInput {
        coverage_fingerprint: coverage,
        ..GuidanceSignalInput::default()
    })
}

pub(super) fn search_candidate_coverage_fingerprint(
    graph: &TemporalGraph,
    configuration: &Configuration,
) -> ContentHash {
    graph
        .cached_snapshots
        .get(&configuration.id())
        .or_else(|| graph.checkpoint_nodes.get(&configuration.id()))
        .map(|checkpoint| checkpoint.coverage_fingerprint)
        .unwrap_or_default()
}

pub(super) fn search_run_reached_configurations(
    root: &Configuration,
    run: &TemporalGraphSearchRun,
) -> Vec<Configuration> {
    let mut configurations = BTreeMap::from([(root.id(), root.clone())]);
    for expansion in &run.expansions {
        for child in &expansion.search.frontier_report.explored {
            configurations
                .entry(child.configuration.id())
                .or_insert_with(|| child.configuration.clone());
        }
        for covered in &expansion.search.frontier_report.covered {
            configurations
                .entry(covered.configuration.id())
                .or_insert_with(|| covered.configuration.clone());
        }
    }
    configurations.into_values().collect()
}

pub(super) fn search_assertion_failure_fingerprint<O>(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    oracle: &mut O,
    predicate_scope: SearchAssertionPredicateScope,
) -> Result<Option<ContentHash>, EngineError>
where
    O: HostAssertionOracle + ?Sized,
{
    let recorded = recorded_assertion_log_from_schedule_for_search(&configuration.schedule)
        .map_err(|source| {
            scenario_serialization_error(format!(
                "search assertion retained log reconstruction failed: {source}"
            ))
        })?;
    search_assertion_failure_fingerprint_from_recorded_log(
        scenario,
        configuration,
        &recorded,
        oracle,
        predicate_scope,
    )
}

pub(super) fn search_assertion_failure_fingerprint_from_recorded_log<O>(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    recorded: &RecordedAssertionLog,
    oracle: &mut O,
    predicate_scope: SearchAssertionPredicateScope,
) -> Result<Option<ContentHash>, EngineError>
where
    O: HostAssertionOracle + ?Sized,
{
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(scenario.world())
        .check_run_with_oracle(scenario.properties(), recorded, oracle)
        .map_err(|source| {
            scenario_serialization_error(format!("search assertion check failed: {source}"))
        })?;
    Ok(report
        .outcomes()
        .iter()
        .find(|outcome| {
            prefix_safe_search_assertion_failure(
                scenario.properties(),
                outcome,
                predicate_scope,
                None,
                false,
            )
        })
        .map(|outcome| search_assertion_outcome_fingerprint(configuration.id(), outcome)))
}

pub(super) fn search_assertion_failure_fingerprint_from_retained_log(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    recorded: &RecordedAssertionLog,
    resolutions: &SearchRetainedLogPredicateResolutions,
    terminal_quiescence: Option<&SchedulerQuiescence>,
) -> Result<Option<ContentHash>, EngineError> {
    let mut checker = OfflineAssertionChecker::new()
        .with_world_white_box_policies(scenario.world())
        .with_resolved_code_points(
            resolutions
                .code_points
                .iter()
                .map(|(key, value)| ((key.0.clone(), key.1.clone()), *value)),
        )
        .with_resolved_mem_places(
            resolutions
                .mem_places
                .iter()
                .map(|(key, value)| ((key.0.clone(), key.1.clone()), value.clone())),
        );
    if let Some(quiescence) = terminal_quiescence.cloned() {
        checker = checker.with_terminal_scheduler_quiescence(quiescence);
    }
    let report = checker
        .check_run(scenario.properties(), recorded.entries())
        .map_err(|source| {
            scenario_serialization_error(format!(
                "search retained assertion check failed: {source}"
            ))
        })?;
    Ok(report
        .outcomes()
        .iter()
        .find(|outcome| {
            prefix_safe_search_assertion_failure(
                scenario.properties(),
                outcome,
                SearchAssertionPredicateScope::RetainedLog,
                Some(resolutions),
                terminal_quiescence.is_some_and(SchedulerQuiescence::is_quiescent),
            )
        })
        .map(|outcome| search_assertion_outcome_fingerprint(configuration.id(), outcome)))
}

pub(super) fn search_assertion_failure_fingerprint_with_named_truths(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    oracle: &mut SearchScheduleNamedPredicateHostOracle<'_>,
) -> Result<Option<ContentHash>, EngineError> {
    oracle.clear_missing_truths();
    let fingerprint = search_assertion_failure_fingerprint(
        scenario,
        configuration,
        oracle,
        SearchAssertionPredicateScope::ScheduleAndNamedTruths,
    )?;
    if oracle.has_missing_truths() {
        return Ok(None);
    }
    Ok(fingerprint)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SearchAssertionPredicateScope {
    ScheduleOnly,
    ScheduleAndNamedTruths,
    RetainedLog,
}

pub(super) fn prefix_safe_search_assertion_failure(
    properties: &Properties,
    outcome: &HostAssertionOutcome,
    predicate_scope: SearchAssertionPredicateScope,
    resolutions: Option<&SearchRetainedLogPredicateResolutions>,
    terminal_quiescent: bool,
) -> bool {
    let retained_scope = predicate_scope == SearchAssertionPredicateScope::RetainedLog;
    let terminal_complete_retained_quantifier = predicate_scope
        == SearchAssertionPredicateScope::RetainedLog
        && terminal_quiescent
        && matches!(
            outcome.quantifier,
            AssertionQuantifierKind::AfterQuiescence
                | AssertionQuantifierKind::Sometimes
                | AssertionQuantifierKind::Eventually
                | AssertionQuantifierKind::GuestSometimes
        );
    let supported_quantifier = matches!(
        outcome.quantifier,
        AssertionQuantifierKind::Always | AssertionQuantifierKind::Reachable
    ) || terminal_complete_retained_quantifier;
    let terminal_complete_retained_reachability_failure = predicate_scope
        == SearchAssertionPredicateScope::RetainedLog
        && terminal_quiescent
        && matches!(
            outcome.quantifier,
            AssertionQuantifierKind::Reachable | AssertionQuantifierKind::GuestReachable
        )
        && outcome.kind == HostAssertionOutcomeKind::NeverReachedFail;
    let supported_failure_kind = outcome.kind == HostAssertionOutcomeKind::Violated
        || terminal_complete_retained_reachability_failure;
    let event_backed_retained_guest_marker_failure = retained_scope
        && matches!(
            outcome.quantifier,
            AssertionQuantifierKind::GuestAlways | AssertionQuantifierKind::GuestUnreachable
        )
        && outcome.kind == HostAssertionOutcomeKind::Violated;
    let terminal_retained_guest_marker_failure = retained_scope
        && terminal_quiescent
        && (outcome.quantifier == AssertionQuantifierKind::GuestSometimes
            && outcome.kind == HostAssertionOutcomeKind::Violated
            || outcome.quantifier == AssertionQuantifierKind::GuestReachable
                && outcome.kind == HostAssertionOutcomeKind::NeverReachedFail);
    let retained_guest_marker_failure =
        event_backed_retained_guest_marker_failure || terminal_retained_guest_marker_failure;
    let allow_terminal_quiescence_predicates = predicate_scope
        == SearchAssertionPredicateScope::RetainedLog
        && terminal_quiescent
        && outcome.quantifier == AssertionQuantifierKind::AfterQuiescence;
    supported_failure_kind
        && (retained_guest_marker_failure
            || supported_quantifier
                && assertion_uses_only_search_schedule_predicates(
                    properties,
                    &outcome.assertion,
                    predicate_scope,
                    resolutions,
                    allow_terminal_quiescence_predicates,
                ))
}

pub(super) fn assertion_uses_only_search_schedule_predicates(
    properties: &Properties,
    assertion: &AssertionId,
    predicate_scope: SearchAssertionPredicateScope,
    resolutions: Option<&SearchRetainedLogPredicateResolutions>,
    allow_terminal_quiescence_predicates: bool,
) -> bool {
    properties
        .assertions()
        .iter()
        .find(|candidate| &candidate.id == assertion)
        .is_some_and(|candidate| {
            property_uses_only_search_schedule_predicates(
                &candidate.property,
                predicate_scope,
                resolutions,
                allow_terminal_quiescence_predicates,
            )
        })
}

pub(super) fn property_uses_only_search_schedule_predicates(
    property: &Property,
    predicate_scope: SearchAssertionPredicateScope,
    resolutions: Option<&SearchRetainedLogPredicateResolutions>,
    allow_terminal_quiescence_predicates: bool,
) -> bool {
    match property {
        Property::Always { predicate }
        | Property::Sometimes { predicate }
        | Property::Reachable { predicate, .. } => predicate_uses_only_search_schedule_predicates(
            predicate,
            predicate_scope,
            resolutions,
            false,
        ),
        Property::AfterQuiescence { predicate } => predicate_uses_only_search_schedule_predicates(
            predicate,
            predicate_scope,
            resolutions,
            allow_terminal_quiescence_predicates,
        ),
        Property::Eventually {
            trigger, property, ..
        } => {
            predicate_uses_only_search_schedule_predicates(
                trigger,
                predicate_scope,
                resolutions,
                false,
            ) && predicate_uses_only_search_schedule_predicates(
                property,
                predicate_scope,
                resolutions,
                false,
            )
        }
    }
}

pub(super) fn predicate_uses_only_search_schedule_predicates(
    predicate: &Predicate,
    predicate_scope: SearchAssertionPredicateScope,
    resolutions: Option<&SearchRetainedLogPredicateResolutions>,
    allow_terminal_quiescence_predicates: bool,
) -> bool {
    match predicate {
        Predicate::FaultActive { .. } => true,
        Predicate::Named { .. } => {
            predicate_scope == SearchAssertionPredicateScope::ScheduleAndNamedTruths
        }
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
            predicates.iter().all(|predicate| {
                predicate_uses_only_search_schedule_predicates(
                    predicate,
                    predicate_scope,
                    resolutions,
                    allow_terminal_quiescence_predicates,
                )
            })
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            predicate_uses_only_search_schedule_predicates(
                predicate,
                predicate_scope,
                resolutions,
                allow_terminal_quiescence_predicates,
            )
        }
        Predicate::At { .. }
        | Predicate::After { .. }
        | Predicate::Timer { .. }
        | Predicate::NetworkMatch { .. }
        | Predicate::ConsoleMatch { .. }
        | Predicate::IoPattern { .. }
        | Predicate::NodeState { .. }
        | Predicate::AssertionState { .. }
        | Predicate::GuestMarker { .. } => {
            predicate_scope == SearchAssertionPredicateScope::RetainedLog
        }
        Predicate::CoveragePoint {
            point: CodePoint::GuestAddress { .. },
            ..
        } => predicate_scope == SearchAssertionPredicateScope::RetainedLog,
        Predicate::CoveragePoint { node, point } => {
            predicate_scope == SearchAssertionPredicateScope::RetainedLog
                && resolutions
                    .is_some_and(|resolutions| resolutions.resolves_code_point(node, point))
        }
        Predicate::MemoryPredicate {
            place: MemPlace::PhysicalAddress { .. } | MemPlace::Register { .. },
            ..
        } => predicate_scope == SearchAssertionPredicateScope::RetainedLog,
        Predicate::MemoryPredicate { node, place, .. } => {
            predicate_scope == SearchAssertionPredicateScope::RetainedLog
                && resolutions
                    .is_some_and(|resolutions| resolutions.resolves_mem_place(node, place))
        }
        Predicate::Quiescent => {
            predicate_scope == SearchAssertionPredicateScope::RetainedLog
                && allow_terminal_quiescence_predicates
        }
    }
}

pub(super) fn search_assertion_outcome_fingerprint(
    configuration: ContentHash,
    outcome: &HostAssertionOutcome,
) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.search.assertion-failure.v1",
        &search_assertion_outcome_fingerprint_material(configuration, outcome),
    )
}

pub(super) fn search_assertion_outcome_fingerprint_material(
    configuration: ContentHash,
    outcome: &HostAssertionOutcome,
) -> String {
    format!(
        "configuration={}\nassertion={}\nquantifier={}\nkind={:?}\nlifecycle={:?}\nat={}\nmessage={}\nreason={}",
        content_hash_hex(configuration),
        outcome.assertion.name,
        failure_assertion_quantifier_label(outcome.quantifier),
        outcome.kind,
        outcome.lifecycle,
        outcome.at.ticks,
        outcome.message,
        outcome.reason
    )
}

pub(super) fn record_search_discovered_failure(
    configuration: &Configuration,
    scenario: Option<&ScenarioDefForm>,
    failure_oracle: &SearchFailureOracle,
    discovered_configurations: &mut BTreeSet<ContentHash>,
    discovered_failures: &mut Vec<SearchDiscoveredFailure>,
) -> Result<(), EngineError> {
    let configuration_id = configuration.id();
    if let Some(fingerprint) = failure_oracle.failure_for(configuration_id)
        && discovered_configurations.insert(configuration_id)
    {
        let scenario = scenario.ok_or(EngineError::ReproductionScenarioMismatch {
            expected: configuration.def.id,
            actual: ContentHash::default(),
        })?;
        let reproduction_artifact = FindingReproductionArtifact::capture(
            FindingDiscoveryPath::StateSpaceSearch,
            fingerprint,
            scenario,
            configuration,
        )?;
        discovered_failures.push(SearchDiscoveredFailure {
            configuration: configuration_id,
            fingerprint,
            reproduction_artifact,
        });
    }
    Ok(())
}

pub(super) fn search_frontier_choices(runtime: &RuntimeState) -> Vec<SearchFrontierChoice> {
    runtime.scheduler.search_frontier.choices().to_vec()
}

pub(super) fn is_genuine_search_frontier_decision(decision: &Decision) -> bool {
    match decision {
        Decision::DeliveryOrder(_) => false,
        Decision::FaultFires(_) | Decision::RngDraw(_) | Decision::Override(_) => true,
        Decision::Preemption(_) | Decision::AppRandom(_) | Decision::ControlFault(_) => false,
    }
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
        let ancestor_runtime = instantiate(graph, &ancestor)?;
        let suffix = config
            .schedule
            .suffix_from(ancestor.schedule.len())
            .map_err(EngineError::SchedulePrefix)?;
        return replay_suffix(ancestor_runtime, &ancestor, &suffix, config);
    }

    let genesis = Configuration::genesis(config.def.clone());
    let genesis_runtime = instantiate(graph, &genesis)?;
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
