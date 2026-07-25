//! Deterministic UCB state and evidence for adaptive search campaigns.
//!
//! Bandit state is campaign-owned: it reads realized graph observations and
//! chooses the next frontier ordering arm, but it never enters reduction,
//! configuration identity, checkpoint identity, or reproduction artifacts.

use super::*;

/// Fixed-point scale used by deterministic UCB scores.
pub const ADAPTIVE_UCB_SCORE_ONE_MICRO: u64 = 1_000_000;

/// Default fixed-point exploration weight for deterministic UCB.
pub const DEFAULT_ADAPTIVE_UCB_EXPLORATION_WEIGHT_MICROS: u64 =
    ADAPTIVE_UCB_SCORE_ONE_MICRO;

/// Signal and bandit configuration hashed into one adaptive campaign identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveCampaignConfig {
    /// Deterministic UCB arm-selection configuration.
    pub strategy: AdaptiveStrategyConfig,
    /// Fixed-point guidance composition used by coverage-guided arms.
    pub guidance: GuidanceSearchConfig,
}

impl AdaptiveCampaignConfig {
    /// Builds an adaptive campaign from its bandit and guidance configurations.
    #[must_use]
    pub fn new(strategy: AdaptiveStrategyConfig, guidance: GuidanceSearchConfig) -> Self {
        Self { strategy, guidance }
    }

    /// Returns the content-addressed identity of the signal and bandit configuration.
    #[must_use]
    pub fn campaign_identity(&self) -> ContentHash {
        let weights = self
            .guidance
            .composition
            .weights()
            .iter()
            .map(|weight| format!("{:?}:{}", weight.signal, weight.weight_micros))
            .collect::<Vec<_>>()
            .join(",");
        ContentHash::from_canonical_material(
            "crucible.adaptive-campaign.config.v1",
            &format!(
                "strategy={}\nguidance={weights}",
                self.strategy.campaign_identity().to_hex()
            ),
        )
    }
}

/// One arm selection made by an integrated adaptive campaign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveCampaignSelection {
    /// Zero-based expansion sequence.
    pub sequence: u64,
    /// Expansion-ordering arm selected by deterministic UCB.
    pub arm: AdaptiveStrategyArm,
    /// Content-addressed frontier selected under the arm.
    pub frontier: ContentHash,
    /// Fixed-point UCB score used for the arm selection.
    pub score_micros: u64,
}

/// Reproducible evidence from one integrated adaptive search campaign.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveCampaignRun {
    /// Content address of the signal and bandit configuration.
    pub campaign_identity: ContentHash,
    /// Content-addressed graph fingerprint after the campaign.
    pub graph_fingerprint: ContentHash,
    /// Root configuration of the campaign.
    pub root: ContentHash,
    /// Expansion budget supplied to the campaign.
    pub budget: SearchBudget,
    /// Deduplicated graph realized by the campaign.
    pub explored_graph: BTreeSet<ContentHash>,
    /// Expansion reports in deterministic campaign order.
    pub expansions: Vec<SearchExpansion>,
    /// Failures carrying bare scenario-and-schedule reproduction artifacts.
    pub discovered_failures: Vec<SearchDiscoveredFailure>,
    /// Whether the shared frontier was exhausted before the budget stopped the campaign.
    pub exhausted: bool,
    /// Deterministic UCB arm-selection trace.
    pub selections: Vec<AdaptiveCampaignSelection>,
    /// Realized-node rewards applied in content-address order.
    pub credits: Vec<AdaptiveStrategyCredit>,
}

#[derive(Clone, Debug, Default)]
pub(in crate::model) struct AdaptiveCampaignState {
    pulls: BTreeMap<AdaptiveStrategyArm, u64>,
    rewards: BTreeMap<AdaptiveStrategyArm, AdaptiveStrategyReward>,
    seen_coverage: BTreeSet<ContentHash>,
    best_assertion_distance: Option<u64>,
    selections: Vec<AdaptiveCampaignSelection>,
    credits: Vec<AdaptiveStrategyCredit>,
}

impl AdaptiveCampaignState {
    pub(in crate::model) fn observe_root(
        &mut self,
        graph: &TemporalGraph,
        root: &Configuration,
        guidance: &GuidanceSearchState,
    ) {
        let observation = guidance.observation_for(graph, root);
        self.seen_coverage.insert(observation.coverage_fingerprint);
        self.best_assertion_distance = observation.assertion_proximity_distance;
    }

    pub(in crate::model) fn select(
        &mut self,
        config: &AdaptiveStrategyConfig,
        graph: &BTreeSet<ContentHash>,
        sequence: u64,
    ) -> (AdaptiveStrategyArm, u64) {
        let graph_fingerprint = adaptive_strategy_graph_fingerprint(graph);
        let arm = select_adaptive_strategy_arm(
            config,
            graph_fingerprint,
            &self.rewards,
            &self.pulls,
            sequence,
        );
        let score = adaptive_strategy_arm_score(
            config,
            &self.rewards,
            &self.pulls,
            arm,
        );
        (arm, score)
    }

    pub(in crate::model) fn record_selection(
        &mut self,
        sequence: u64,
        arm: AdaptiveStrategyArm,
        frontier: ContentHash,
        score_micros: u64,
    ) {
        self.pulls
            .entry(arm)
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        self.selections.push(AdaptiveCampaignSelection {
            sequence,
            arm,
            frontier,
            score_micros,
        });
    }

    pub(in crate::model) fn credit_realized(
        &mut self,
        graph: &TemporalGraph,
        guidance: &GuidanceSearchState,
        arm: AdaptiveStrategyArm,
        realized: &BTreeMap<ContentHash, bool>,
    ) {
        for (configuration, confirmed_failure) in realized {
            let Some(configuration_value) = graph.recorded_configurations.get(configuration) else {
                continue;
            };
            let observation = guidance.observation_for(graph, configuration_value);
            let new_coverage = u64::from(
                self.seen_coverage
                    .insert(observation.coverage_fingerprint),
            );
            let rarity_count = guidance
                .rarity()
                .count(observation.coverage_fingerprint)
                .max(1);
            let novelty_gain = ADAPTIVE_UCB_SCORE_ONE_MICRO / rarity_count;
            let assertion_proximity_progress =
                match (self.best_assertion_distance, observation.assertion_proximity_distance) {
                    (Some(previous), Some(current)) if current < previous => previous - current,
                    _ => 0,
                };
            if let Some(current) = observation.assertion_proximity_distance {
                self.best_assertion_distance = Some(
                    self.best_assertion_distance
                        .map_or(current, |previous| previous.min(current)),
                );
            }
            let credit = AdaptiveStrategyCredit {
                arm,
                configuration: *configuration,
                reward: AdaptiveStrategyReward {
                    new_coverage,
                    novelty_gain,
                    assertion_proximity_progress,
                    confirmed_failure: *confirmed_failure,
                },
            };
            self.rewards
                .entry(arm)
                .and_modify(|reward| {
                    *reward = combine_adaptive_strategy_rewards(*reward, credit.reward);
                })
                .or_insert(credit.reward);
            self.credits.push(credit);
        }
    }

    pub(in crate::model) fn finish(
        self,
        config: &AdaptiveCampaignConfig,
        search: TemporalGraphSearchRun,
    ) -> AdaptiveCampaignRun {
        AdaptiveCampaignRun {
            campaign_identity: config.campaign_identity(),
            graph_fingerprint: adaptive_strategy_graph_fingerprint(&search.explored_graph),
            root: search.root,
            budget: search.budget,
            explored_graph: search.explored_graph,
            expansions: search.expansions,
            discovered_failures: search.discovered_failures,
            exhausted: search.exhausted,
            selections: self.selections,
            credits: self.credits,
        }
    }
}

pub(in crate::model) fn adaptive_arm_search_strategy(
    arm: AdaptiveStrategyArm,
    seed: Seed,
) -> SearchStrategy {
    match arm {
        AdaptiveStrategyArm::BreadthFirst => SearchStrategy::BreadthFirst,
        AdaptiveStrategyArm::CoverageGuided => SearchStrategy::CoverageGuided,
        AdaptiveStrategyArm::Priority => SearchStrategy::Priority { seed },
    }
}
