//! Deterministic, read-only guidance state for temporal-graph search.
//!
//! Guidance observations are deliberately kept outside [`TemporalGraph`].
//! They can order frontier expansion, but they cannot enter configuration,
//! checkpoint, graph, or reproduction-artifact identities.

use super::*;

/// Configuration for composite guided frontier selection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GuidanceSearchConfig {
    /// Fixed-point signals applied to each candidate.
    pub composition: GuidanceSignalComposition,
}

impl Default for GuidanceSearchConfig {
    fn default() -> Self {
        Self {
            composition: GuidanceSignalComposition::coverage_only(),
        }
    }
}

/// Read-only feedback associated with one content-addressed configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct GuidanceObservation {
    /// Coverage projection fingerprint for the configuration.
    pub coverage_fingerprint: ContentHash,
    /// Minimum assertion distance derived from the unified event log.
    pub assertion_proximity_distance: Option<u64>,
}

/// Deterministically maintained frequency table for coverage observations.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct GuidanceRarityTable {
    counts: BTreeMap<ContentHash, u64>,
}

impl GuidanceRarityTable {
    fn observe(&mut self, coverage_fingerprint: ContentHash) {
        self.counts
            .entry(coverage_fingerprint)
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
    }

    /// Returns the number of admitted configurations with `coverage_fingerprint`.
    #[must_use]
    pub fn count(&self, coverage_fingerprint: ContentHash) -> u64 {
        self.counts
            .get(&coverage_fingerprint)
            .copied()
            .unwrap_or_default()
    }
}

/// Reader-only guidance observations and deterministic campaign rarity state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct GuidanceSearchState {
    observations: BTreeMap<ContentHash, GuidanceObservation>,
    admitted_configurations: BTreeSet<ContentHash>,
    rarity: GuidanceRarityTable,
}

impl GuidanceSearchState {
    /// Records coverage and assertion-distance feedback from unified event-log entries.
    ///
    /// The minimum proximity value comes from the assertion-proximity projection,
    /// which owns the assertion layer's structural distance metric.
    pub fn record_event_log_observation(
        &mut self,
        configuration: &Configuration,
        entries: &[crate::scheduler::SchedulerEventLogEntry],
    ) {
        let proximity = crate::scheduler::event_log_assertion_proximity_projection(entries);
        let assertion_proximity_distance = proximity
            .entries()
            .iter()
            .map(|entry| entry.distance)
            .min()
            .map(|distance| u64::try_from(distance).unwrap_or(u64::MAX));
        self.observations.insert(
            configuration.id(),
            GuidanceObservation {
                coverage_fingerprint: crate::scheduler::coverage_fingerprint_from_event_log(
                    entries,
                ),
                assertion_proximity_distance,
            },
        );
    }

    /// Records explicit read-only feedback for `configuration`.
    pub fn record_observation(
        &mut self,
        configuration: &Configuration,
        observation: GuidanceObservation,
    ) {
        self.observations.insert(configuration.id(), observation);
    }

    /// Returns the observation used for `configuration`, if one was supplied.
    #[must_use]
    pub fn observation(&self, configuration: ContentHash) -> Option<GuidanceObservation> {
        self.observations.get(&configuration).copied()
    }

    /// Returns the campaign-owned rarity table.
    #[must_use]
    pub fn rarity(&self) -> &GuidanceRarityTable {
        &self.rarity
    }

    pub(in crate::model) fn admit_candidate(
        &mut self,
        graph: &TemporalGraph,
        configuration: &Configuration,
    ) {
        if !self.admitted_configurations.insert(configuration.id()) {
            return;
        }
        let observation = self.observation_for(graph, configuration);
        self.rarity.observe(observation.coverage_fingerprint);
    }

    pub(in crate::model) fn signal_input(
        &self,
        graph: &TemporalGraph,
        configuration: &Configuration,
    ) -> GuidanceSignalInput {
        let observation = self.observation_for(graph, configuration);
        GuidanceSignalInput {
            coverage_fingerprint: observation.coverage_fingerprint,
            rarity_count: self
                .rarity
                .count(observation.coverage_fingerprint)
                .saturating_sub(1),
            assertion_proximity_distance: observation.assertion_proximity_distance,
        }
    }

    fn observation_for(
        &self,
        graph: &TemporalGraph,
        configuration: &Configuration,
    ) -> GuidanceObservation {
        self.observations
            .get(&configuration.id())
            .copied()
            .unwrap_or_else(|| GuidanceObservation {
                coverage_fingerprint: search_candidate_coverage_fingerprint(graph, configuration),
                assertion_proximity_distance: None,
            })
    }
}

pub(in crate::model) fn compare_guided_search_frontier_candidates(
    graph: &TemporalGraph,
    left: &SearchFrontierCandidate,
    right: &SearchFrontierCandidate,
    config: &GuidanceSearchConfig,
    state: &GuidanceSearchState,
) -> std::cmp::Ordering {
    if guidance_composition_is_coverage_only(&config.composition) {
        return search_coverage_guided_key(graph, left)
            .cmp(&search_coverage_guided_key(graph, right))
            .then_with(|| left.id().cmp(&right.id()));
    }

    let left_score = config
        .composition
        .score(state.signal_input(graph, &left.configuration));
    let right_score = config
        .composition
        .score(state.signal_input(graph, &right.configuration));
    right_score
        .cmp(&left_score)
        .then_with(|| left.id().cmp(&right.id()))
}

fn guidance_composition_is_coverage_only(composition: &GuidanceSignalComposition) -> bool {
    let [weight] = composition.weights() else {
        return false;
    };
    weight.signal == GuidanceSignalKind::Coverage
        && weight.weight_micros == GUIDANCE_SCORE_ONE_MICRO
}
