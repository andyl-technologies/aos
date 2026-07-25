//! Composite-guidance entrypoint for the shared temporal-graph search driver.

use super::*;

pub(in crate::model) enum SearchCampaignMode<'a> {
    Guided {
        config: &'a GuidanceSearchConfig,
        state: &'a mut GuidanceSearchState,
    },
    Adaptive {
        config: &'a AdaptiveCampaignConfig,
        guidance: &'a mut GuidanceSearchState,
        state: &'a mut AdaptiveCampaignState,
    },
}

impl SearchCampaignMode<'_> {
    fn admit_candidate(&mut self, graph: &TemporalGraph, configuration: &Configuration) {
        let guidance = match self {
            Self::Guided { state, .. } => state,
            Self::Adaptive { guidance, .. } => guidance,
        };
        guidance.admit_candidate(graph, configuration);
    }

    fn guidance(
        &self,
        strategy: SearchStrategy,
    ) -> Option<(&GuidanceSearchConfig, &GuidanceSearchState)> {
        if strategy != SearchStrategy::CoverageGuided {
            return None;
        }
        match self {
            Self::Guided { config, state } => Some((config, state)),
            Self::Adaptive {
                config, guidance, ..
            } => Some((&config.guidance, guidance)),
        }
    }

    fn select_arm(
        &mut self,
        graph: &BTreeSet<ContentHash>,
        sequence: u64,
    ) -> Option<(AdaptiveStrategyArm, u64, Seed)> {
        match self {
            Self::Guided { .. } => None,
            Self::Adaptive { config, state, .. } => {
                let (arm, score) = state.select(&config.strategy, graph, sequence);
                Some((arm, score, config.strategy.seed))
            }
        }
    }

    fn record_selection(
        &mut self,
        sequence: u64,
        arm: AdaptiveStrategyArm,
        frontier: ContentHash,
        score_micros: u64,
    ) {
        if let Self::Adaptive { state, .. } = self {
            state.record_selection(sequence, arm, frontier, score_micros);
        }
    }

    fn credit_realized(
        &mut self,
        graph: &TemporalGraph,
        arm: AdaptiveStrategyArm,
        realized: &BTreeMap<ContentHash, bool>,
    ) {
        if let Self::Adaptive {
            guidance, state, ..
        } = self
        {
            state.credit_realized(graph, guidance, arm, realized);
        }
    }
}

impl TemporalGraph {
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::model) fn search_with_strategy_inner(
        &mut self,
        root: &Configuration,
        strategy: SearchStrategy,
        budget: SearchBudget,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        scenario: Option<&ScenarioDefForm>,
        failure_oracle: &SearchFailureOracle,
        max_depth: Option<u64>,
        mut campaign: Option<SearchCampaignMode<'_>>,
        sampling_config: Option<&SearchReplayOracleSamplingConfig>,
        mut sampling_report: Option<&mut SearchReplayOracleSamplingReport>,
    ) -> Result<TemporalGraphSearchRun, EngineError> {
        let mut worklist = vec![SearchFrontierCandidate::new(root.clone())];
        let mut scheduled = BTreeSet::from([root.id()]);
        let mut expanded = BTreeSet::new();
        let mut explored_graph = BTreeSet::from([root.id()]);
        let mut expansions = Vec::new();
        let mut discovered_failures = Vec::new();
        let mut discovered_failure_configurations = BTreeSet::new();
        let mut sampling_sequence_offset = 0;
        if let Some(campaign) = campaign.as_mut() {
            campaign.admit_candidate(self, root);
        }
        record_search_discovered_failure(
            root,
            scenario,
            failure_oracle,
            &mut discovered_failure_configurations,
            &mut discovered_failures,
        )?;

        while (expansions.len() as u64) < budget.max_expansions {
            let sequence = expansions.len() as u64;
            let adaptive_selection = campaign
                .as_mut()
                .and_then(|campaign| campaign.select_arm(&explored_graph, sequence));
            let active_strategy = adaptive_selection
                .map(|(arm, _, seed)| adaptive_arm_search_strategy(arm, seed))
                .unwrap_or(strategy);
            let guidance = campaign
                .as_ref()
                .and_then(|campaign| campaign.guidance(active_strategy));
            let Some(index) = select_search_frontier_candidate(
                self,
                &worklist,
                active_strategy,
                max_depth,
                guidance,
            ) else {
                break;
            };
            let candidate = worklist.remove(index);
            if !expanded.insert(candidate.id()) {
                continue;
            }
            if let (Some(campaign), Some((arm, score_micros, _))) =
                (campaign.as_mut(), adaptive_selection)
            {
                campaign.record_selection(sequence, arm, candidate.id(), score_micros);
            }

            let search = match sampling_config {
                Some(config) => self.search_with_replay_oracle_sampling_offset(
                    &candidate.configuration,
                    reduction_policy.clone(),
                    materialization_policy,
                    trigger,
                    config,
                    sampling_sequence_offset,
                )?,
                None => self.search(
                    &candidate.configuration,
                    reduction_policy.clone(),
                    materialization_policy,
                    trigger,
                )?,
            };
            if let (Some(total), Some(frontier_report)) = (
                sampling_report.as_deref_mut(),
                search.replay_oracle_sampling.as_ref(),
            ) {
                merge_search_replay_oracle_sampling_report(total, frontier_report);
            }
            if sampling_config.is_some() {
                sampling_sequence_offset =
                    sampling_sequence_offset.saturating_add(search.materialized.len() as u64);
            }
            let mut realized = BTreeMap::new();
            for child in &search.frontier_report.explored {
                let child_id = child.configuration.id();
                if explored_graph.insert(child_id) {
                    realized.insert(child_id, failure_oracle.failure_for(child_id).is_some());
                }
                record_search_discovered_failure(
                    &child.configuration,
                    scenario,
                    failure_oracle,
                    &mut discovered_failure_configurations,
                    &mut discovered_failures,
                )?;
                if scheduled.insert(child_id) {
                    if let Some(campaign) = campaign.as_mut() {
                        campaign.admit_candidate(self, &child.configuration);
                    }
                    worklist.push(SearchFrontierCandidate::new(child.configuration.clone()));
                }
            }
            for covered in &search.frontier_report.covered {
                if let Some(representative) = self
                    .recorded_configurations
                    .get(&covered.representative)
                    .cloned()
                {
                    let representative_id = representative.id();
                    if explored_graph.insert(representative_id) {
                        realized.insert(
                            representative_id,
                            failure_oracle.failure_for(representative_id).is_some(),
                        );
                    }
                    record_search_discovered_failure(
                        &representative,
                        scenario,
                        failure_oracle,
                        &mut discovered_failure_configurations,
                        &mut discovered_failures,
                    )?;
                    if scheduled.insert(representative_id) {
                        if let Some(campaign) = campaign.as_mut() {
                            campaign.admit_candidate(self, &representative);
                        }
                        worklist.push(SearchFrontierCandidate::new(representative));
                    }
                }
            }
            if let (Some(campaign), Some((arm, _, _))) = (campaign.as_mut(), adaptive_selection) {
                campaign.credit_realized(self, arm, &realized);
            }

            expansions.push(SearchExpansion {
                sequence,
                frontier: candidate.id(),
                depth: candidate.depth,
                search,
            });
        }

        Ok(TemporalGraphSearchRun {
            root: root.id(),
            strategy,
            budget,
            explored_graph,
            expansions,
            discovered_failures,
            exhausted: worklist.is_empty(),
        })
    }

    /// Searches with fixed-point composite guidance over the shared expansion path.
    ///
    /// The default [`GuidanceSearchConfig`] uses the exact existing
    /// [`SearchStrategy::CoverageGuided`] ordering. Other compositions combine
    /// coverage, campaign-owned rarity, and assertion-distance observations,
    /// with configuration content address as the final tie-break. Guidance state
    /// is reader-only and cannot alter configuration or checkpoint identities.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the root or a selected frontier cannot be
    /// realized, reduced, recorded, or materialized.
    pub fn search_with_guidance(
        &mut self,
        root: &Configuration,
        budget: SearchBudget,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        config: &GuidanceSearchConfig,
        state: &mut GuidanceSearchState,
    ) -> Result<TemporalGraphSearchRun, EngineError> {
        let failure_oracle = SearchFailureOracle::none();
        self.search_with_strategy_inner(
            root,
            SearchStrategy::CoverageGuided,
            budget,
            FrontierReductionPolicy::none(),
            materialization_policy,
            trigger,
            None,
            &failure_oracle,
            None,
            Some(SearchCampaignMode::Guided { config, state }),
            None,
            None,
        )
    }

    /// Runs deterministic UCB arm selection inside the shared search campaign loop.
    ///
    /// Rewards are derived only from content-addressed realized nodes and are
    /// credited in content-address order. The selected arm changes frontier
    /// ordering only; every child still uses the same reduction, materialization,
    /// failure capture, and replayable configuration path as non-adaptive search.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not describe `root`. Returns other [`EngineError`] values when
    /// expansion, reduction, materialization, or reproduction capture fails.
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    pub fn search_adaptive_campaign(
        &mut self,
        scenario: &ScenarioDefForm,
        root: &Configuration,
        budget: SearchBudget,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
        failure_oracle: &SearchFailureOracle,
        config: &AdaptiveCampaignConfig,
        guidance: &mut GuidanceSearchState,
    ) -> Result<AdaptiveCampaignRun, EngineError> {
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != root.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: root.def.id,
                actual: scenario_def.id,
            });
        }
        let mut state = AdaptiveCampaignState::default();
        guidance.admit_candidate(self, root);
        state.observe_root(self, root, guidance);
        let search = self.search_with_strategy_inner(
            root,
            SearchStrategy::BreadthFirst,
            budget,
            reduction_policy,
            materialization_policy,
            trigger,
            Some(scenario),
            failure_oracle,
            None,
            Some(SearchCampaignMode::Adaptive {
                config,
                guidance,
                state: &mut state,
            }),
            None,
            None,
        )?;
        Ok(state.finish(config, search))
    }
}
