//! Deterministic guidance signals, adaptive strategy policy, and fleet evidence.

use super::*;

/// Built-in deterministic guidance signal identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuidanceSignalKind {
    /// Coverage projection feedback from the unified event log.
    Coverage,
    /// Inverse-frequency novelty over a deterministic rarity table.
    NoveltyRarity,
    /// Assertion-proximity progress from observational event-log entries.
    AssertionProximity,
}

/// Input material read by guidance signals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct GuidanceSignalInput {
    /// Coverage projection fingerprint for the candidate checkpoint.
    pub coverage_fingerprint: ContentHash,
    /// Number of times the candidate's novelty key has already appeared.
    pub rarity_count: u64,
    /// Best remaining assertion-proximity distance, if known.
    pub assertion_proximity_distance: Option<u64>,
}

/// A deterministic fixed-point guidance score.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuidanceScore {
    /// Integer micro-units; guidance never uses floating-point scores.
    pub micros: u64,
}

/// Read-only scoring signal for guided exploration.
pub trait GuidanceSignal {
    /// Returns the stable built-in signal identity.
    fn kind(&self) -> GuidanceSignalKind;

    /// Returns the deterministic fixed-point score for `input`.
    fn score(&self, input: GuidanceSignalInput) -> GuidanceScore;
}

/// Coverage-only guidance signal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CoverageGuidanceSignal;

impl GuidanceSignal for CoverageGuidanceSignal {
    fn kind(&self) -> GuidanceSignalKind {
        GuidanceSignalKind::Coverage
    }

    fn score(&self, input: GuidanceSignalInput) -> GuidanceScore {
        if input.coverage_fingerprint == ContentHash::default() {
            return GuidanceScore { micros: 0 };
        }

        GuidanceScore {
            micros: u64::MAX - content_hash_low_u64(input.coverage_fingerprint),
        }
    }
}

impl CoverageGuidanceSignal {
    /// Returns the exact ordering key used by existing coverage-guided search.
    #[must_use]
    pub fn search_order_key(&self, input: GuidanceSignalInput) -> (u8, ContentHash) {
        let unknown_coverage = u8::from(input.coverage_fingerprint == ContentHash::default());
        (unknown_coverage, input.coverage_fingerprint)
    }
}

/// Novelty/rarity guidance signal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoveltyRarityGuidanceSignal;

impl GuidanceSignal for NoveltyRarityGuidanceSignal {
    fn kind(&self) -> GuidanceSignalKind {
        GuidanceSignalKind::NoveltyRarity
    }

    fn score(&self, input: GuidanceSignalInput) -> GuidanceScore {
        GuidanceScore {
            micros: GUIDANCE_SCORE_ONE_MICRO / input.rarity_count.saturating_add(1),
        }
    }
}

/// Assertion-proximity guidance signal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AssertionProximityGuidanceSignal;

impl GuidanceSignal for AssertionProximityGuidanceSignal {
    fn kind(&self) -> GuidanceSignalKind {
        GuidanceSignalKind::AssertionProximity
    }

    fn score(&self, input: GuidanceSignalInput) -> GuidanceScore {
        let Some(distance) = input.assertion_proximity_distance else {
            return GuidanceScore { micros: 0 };
        };
        GuidanceScore {
            micros: GUIDANCE_SCORE_ONE_MICRO / distance.saturating_add(1),
        }
    }
}

/// Fixed-point weight for one built-in guidance signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuidanceSignalWeight {
    /// Signal receiving this weight.
    pub signal: GuidanceSignalKind,
    /// Integer micro-weight used in deterministic weighted sums.
    pub weight_micros: u64,
}

/// Deterministic fixed-order guidance signal composition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GuidanceSignalComposition {
    pub(super) weights: Vec<GuidanceSignalWeight>,
}

impl GuidanceSignalComposition {
    /// Builds the default coverage-only guidance composition.
    #[must_use]
    pub fn coverage_only() -> Self {
        Self {
            weights: vec![GuidanceSignalWeight {
                signal: GuidanceSignalKind::Coverage,
                weight_micros: GUIDANCE_SCORE_ONE_MICRO,
            }],
        }
    }

    /// Builds a deterministic composition from `weights`.
    ///
    /// Weights are sorted by signal identity so authoring order cannot change the
    /// fixed-point accumulation order.
    #[must_use]
    pub fn new(weights: Vec<GuidanceSignalWeight>) -> Self {
        let mut weights = weights;
        weights.sort();
        Self { weights }
    }

    /// Returns the fixed ordered weights.
    #[must_use]
    pub fn weights(&self) -> &[GuidanceSignalWeight] {
        &self.weights
    }

    /// Scores `input` with a deterministic fixed-point weighted sum.
    #[must_use]
    pub fn score(&self, input: GuidanceSignalInput) -> GuidanceScore {
        let mut total = 0u128;
        for weight in &self.weights {
            let score = guidance_signal_score(weight.signal, input);
            total = total.saturating_add(
                u128::from(score.micros).saturating_mul(u128::from(weight.weight_micros)),
            );
        }
        GuidanceScore {
            micros: (total / u128::from(GUIDANCE_SCORE_ONE_MICRO)).min(u128::from(u64::MAX)) as u64,
        }
    }
}

/// One adaptive strategy arm in deterministic order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdaptiveStrategyArm {
    /// Breadth-first exploration floor.
    BreadthFirst,
    /// Coverage-guided frontier ordering.
    CoverageGuided,
    /// Seeded priority frontier ordering.
    Priority,
}

/// Optional deterministic adaptive strategy-selection configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveStrategyConfig {
    /// Root seed for deterministic UCB tie-breaking.
    pub seed: Seed,
    /// Fixed ordered expansion arms.
    pub arms: Vec<AdaptiveStrategyArm>,
    /// Every Nth expansion is forced to breadth-first when nonzero.
    pub breadth_first_floor_interval: u64,
    /// Fixed-point multiplier for the deterministic UCB exploration term.
    pub ucb_exploration_weight_micros: u64,
    /// Whether adaptive selection is enabled.
    pub enabled: bool,
}

impl AdaptiveStrategyConfig {
    /// Builds the off-by-default adaptive strategy configuration.
    #[must_use]
    pub fn disabled(seed: Seed) -> Self {
        Self {
            seed,
            arms: vec![AdaptiveStrategyArm::BreadthFirst],
            breadth_first_floor_interval: 1,
            ucb_exploration_weight_micros: DEFAULT_ADAPTIVE_UCB_EXPLORATION_WEIGHT_MICROS,
            enabled: false,
        }
    }

    /// Builds an enabled deterministic adaptive strategy configuration.
    #[must_use]
    pub fn enabled(
        seed: Seed,
        arms: Vec<AdaptiveStrategyArm>,
        breadth_first_floor_interval: u64,
    ) -> Self {
        let mut arms = arms;
        arms.sort();
        arms.dedup();
        if arms.is_empty() {
            arms.push(AdaptiveStrategyArm::BreadthFirst);
        }
        Self {
            seed,
            arms,
            breadth_first_floor_interval,
            ucb_exploration_weight_micros: DEFAULT_ADAPTIVE_UCB_EXPLORATION_WEIGHT_MICROS,
            enabled: true,
        }
    }

    /// Computes the content-addressed campaign identity component for this config.
    #[must_use]
    pub fn campaign_identity(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            "crucible.adaptive-strategy.config.v1",
            &adaptive_strategy_config_material(self),
        )
    }
}

/// Deterministic reward credited to an adaptive strategy arm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AdaptiveStrategyReward {
    /// Reward for new coverage.
    pub new_coverage: u64,
    /// Reward for rarity/novelty gain.
    pub novelty_gain: u64,
    /// Reward for assertion-proximity progress.
    pub assertion_proximity_progress: u64,
    /// Dominant reward for a confirmed failure.
    pub confirmed_failure: bool,
}

/// One deterministic adaptive reward credit from a realized graph node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveStrategyCredit {
    /// Arm that produced the credited node.
    pub arm: AdaptiveStrategyArm,
    /// Content-addressed node receiving the reward.
    pub configuration: ContentHash,
    /// Reward observed for the node.
    pub reward: AdaptiveStrategyReward,
}

/// One deterministic adaptive arm selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveStrategySelection {
    /// Zero-based selection sequence.
    pub sequence: u64,
    /// Selected arm.
    pub arm: AdaptiveStrategyArm,
    /// Integer score used for selection.
    pub score: u64,
}

/// Result of deterministic adaptive strategy selection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveStrategyRun {
    /// Campaign identity including the adaptive configuration.
    pub campaign_identity: ContentHash,
    /// Content-addressed graph fingerprint used as deterministic campaign input.
    pub graph_fingerprint: ContentHash,
    /// Ordered arm selections.
    pub selections: Vec<AdaptiveStrategySelection>,
}

/// Configuration for preemption branch generation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreemptionBranchConfig {
    /// Node whose vCPU is preempted.
    pub node: NodeId,
    /// First eligible exact logical tick.
    pub deadline: SimInstant,
    /// Last eligible exact logical tick.
    pub horizon: SimInstant,
    /// Positive exact-tick stride between branches.
    pub step: u64,
    /// vCPU currently running before a switch branch.
    pub switch_from_vcpu: VcpuId,
    /// vCPU selected by a switch branch.
    pub switch_to_vcpu: VcpuId,
    /// Target vCPU for the interrupt.
    pub target_vcpu: VcpuId,
    /// Interrupt vector to deliver.
    pub irq: IrqVector,
}

impl PreemptionBranchConfig {
    pub(crate) fn has_bounded_domain(&self) -> bool {
        // Each exact tick yields a switch and an interrupt alternative.
        const MAX_PREEMPTION_BRANCH_SLOTS: u64 = 2_048;

        if self.step == 0 {
            return false;
        }
        self.horizon
            .ticks
            .checked_sub(self.deadline.ticks)
            .and_then(|span| (span / self.step).checked_add(1))
            .is_some_and(|slots| slots <= MAX_PREEMPTION_BRANCH_SLOTS)
    }
}

/// Result of preemption branch expansion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreemptionBranchRun {
    /// Typed scheduler opportunity that owns these alternatives.
    pub discovery: crucible_campaign::ChoiceDiscovery,
    /// Decisions considered for branching.
    pub decisions: Vec<Decision>,
    /// Reduced frontier report for the generated children.
    pub report: FrontierReductionReport,
    /// Replay-oracle-validated checkpoints for explored children and covered representatives.
    pub materialized: Vec<Checkpoint>,
}

/// Result of the guidance determinism source lint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct GuidanceDeterminismLintReport {
    /// Forbidden floating-point ordering tokens found in the inspected source.
    pub forbidden_hits: Vec<String>,
}

impl GuidanceDeterminismLintReport {
    /// Returns whether the lint found no forbidden tokens.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.forbidden_hits.is_empty()
    }
}

/// One frontier expansion in a strategy-driven graph search.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchExpansion {
    /// Zero-based deterministic expansion sequence number.
    pub sequence: u64,
    /// Checkpoint expanded at this sequence number.
    pub frontier: ContentHash,
    /// Number of recorded decisions in `frontier`.
    pub depth: usize,
    /// Single-frontier search result produced for `frontier`.
    pub search: TemporalGraphSearch,
}

/// A failure discovered by a strategy-driven graph search.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchDiscoveredFailure {
    /// Configuration where the failure was observed.
    pub configuration: ContentHash,
    /// Stable failure fingerprint used for deterministic deduplication.
    pub fingerprint: ContentHash,
    /// Self-contained artifact captured when search discovered the failure.
    pub reproduction_artifact: FindingReproductionArtifact,
}

impl SearchDiscoveredFailure {
    /// Returns the self-contained artifact emitted by the search path.
    #[must_use]
    pub fn reproduction_artifact(&self) -> &FindingReproductionArtifact {
        &self.reproduction_artifact
    }
}

/// One fleet work claim from the shared frontier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FleetWorkClaim {
    /// Zero-based deterministic claim sequence.
    pub sequence: u64,
    /// Logical host that won this claim.
    pub host_index: u64,
    /// Checkpoint expanded by the claim.
    pub frontier: ContentHash,
    /// Number of recorded decisions in `frontier`.
    pub depth: usize,
    /// Single-frontier search result produced by this claim.
    pub search: TemporalGraphSearch,
}

/// Result of a deterministic shared-worklist fleet search.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FleetWorkStealingSearchRun {
    /// Root checkpoint supplied to the fleet.
    pub root: ContentHash,
    /// Fleet configuration used to order claims.
    pub config: FleetWorkStealingConfig,
    /// Deduplicated content-addressed graph reached by the fleet.
    pub explored_graph: BTreeSet<ContentHash>,
    /// Work claims in exact deterministic claim order.
    pub claims: Vec<FleetWorkClaim>,
    /// Failures discovered by the fleet.
    pub discovered_failures: Vec<SearchDiscoveredFailure>,
    /// Whether the shared frontier was exhausted before the budget stopped the run.
    pub exhausted: bool,
}

/// Content-addressed finding entry compared by `gate:fleet-equivalence`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FleetFindingSetEntry {
    /// Stable finding fingerprint.
    pub fingerprint: ContentHash,
    /// Configuration where the finding was observed.
    pub configuration: ContentHash,
    /// Self-contained reproduction artifact id.
    pub artifact: ContentHash,
    /// Reduced state reached by replaying the artifact.
    pub replayed_state: ContentHash,
}

impl FleetFindingSetEntry {
    fn from_failure(failure: &SearchDiscoveredFailure) -> Self {
        Self {
            fingerprint: failure.fingerprint,
            configuration: failure.configuration,
            artifact: failure.reproduction_artifact.artifact.id(),
            replayed_state: failure.reproduction_artifact.replay.state,
        }
    }
}

/// Localized fleet-equivalence mismatch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FleetEquivalenceDivergence {
    /// Stable mismatch category.
    pub reason: &'static str,
    /// Finding fingerprint at the first sorted mismatch, if known.
    pub fingerprint: Option<ContentHash>,
    /// Configuration at the first sorted mismatch, if known.
    pub configuration: Option<ContentHash>,
    /// Single-host artifact at the mismatch, if any.
    pub single_artifact: Option<ContentHash>,
    /// Fleet artifact at the mismatch, if any.
    pub fleet_artifact: Option<ContentHash>,
    /// Replay-oracle bisection handoff for the mismatching artifact/configuration.
    pub bisection: SearchReplayOracleBisectionRequest,
}

/// Result of comparing a single-host search with a fleet search.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FleetEquivalenceReport {
    /// Whether both runs started from the same content-addressed root.
    pub root_equal: bool,
    /// Whether both runs used the same total frontier-expansion budget.
    pub budget_equal: bool,
    /// Whether both runs reached the same deduplicated graph.
    pub explored_graph_equal: bool,
    /// Whether both runs exhausted the reachable frontier before the budget ended.
    pub both_exhausted: bool,
    /// Single-host content-addressed finding set.
    pub single_finding_set: BTreeSet<FleetFindingSetEntry>,
    /// Fleet content-addressed finding set.
    pub fleet_finding_set: BTreeSet<FleetFindingSetEntry>,
    /// Single-host discovery order, retained only for diagnostics.
    pub single_discovery_order: Vec<FleetFindingSetEntry>,
    /// Fleet discovery order, retained only for diagnostics.
    pub fleet_discovery_order: Vec<FleetFindingSetEntry>,
    /// Whether the finding sets match order-insensitively.
    pub finding_sets_equal: bool,
    /// Whether every shared finding carries byte-identical artifacts.
    pub artifacts_byte_identical: bool,
    /// Whether the diagnostic discovery order happened to match.
    pub discovery_order_equal: bool,
    /// First localized mismatch, if the equivalence proof failed.
    pub divergence: Option<FleetEquivalenceDivergence>,
}

impl FleetEquivalenceReport {
    /// Compares a single-host exhaustive search and a shared-worklist fleet run.
    #[must_use]
    pub fn compare(single: &TemporalGraphSearchRun, fleet: &FleetWorkStealingSearchRun) -> Self {
        let single_discovery_order = single
            .discovered_failures
            .iter()
            .map(FleetFindingSetEntry::from_failure)
            .collect::<Vec<_>>();
        let fleet_discovery_order = fleet
            .discovered_failures
            .iter()
            .map(FleetFindingSetEntry::from_failure)
            .collect::<Vec<_>>();
        let single_finding_set = single_discovery_order
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let fleet_finding_set = fleet_discovery_order
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let root_equal = single.root == fleet.root;
        let budget_equal = single.budget == fleet.config.total_budget;
        let explored_graph_equal = single.explored_graph == fleet.explored_graph;
        let both_exhausted = single.exhausted && fleet.exhausted;
        let finding_sets_equal = single_finding_set == fleet_finding_set;
        let artifacts_byte_identical = fleet_artifacts_are_byte_identical(
            single,
            fleet,
            &single_finding_set,
            &fleet_finding_set,
        );
        let discovery_order_equal = single_discovery_order == fleet_discovery_order;
        let divergence = (!root_equal
            || !budget_equal
            || !explored_graph_equal
            || !both_exhausted
            || !finding_sets_equal
            || !artifacts_byte_identical)
            .then(|| {
                fleet_equivalence_divergence(single, fleet, &single_finding_set, &fleet_finding_set)
            });

        Self {
            root_equal,
            budget_equal,
            explored_graph_equal,
            both_exhausted,
            single_finding_set,
            fleet_finding_set,
            single_discovery_order,
            fleet_discovery_order,
            finding_sets_equal,
            artifacts_byte_identical,
            discovery_order_equal,
            divergence,
        }
    }

    /// Returns whether the fleet-equivalence proof passed.
    #[must_use]
    pub const fn passes(&self) -> bool {
        self.root_equal
            && self.budget_equal
            && self.explored_graph_equal
            && self.both_exhausted
            && self.finding_sets_equal
            && self.artifacts_byte_identical
            && self.divergence.is_none()
    }
}
