//! Composite-guidance entrypoint for the shared temporal-graph search driver.

use super::*;

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
        guidance_config: Option<&GuidanceSearchConfig>,
        mut guidance_state: Option<&mut GuidanceSearchState>,
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
        if let Some(state) = guidance_state.as_deref_mut() {
            state.admit_candidate(self, root);
        }
        record_search_discovered_failure(
            root,
            scenario,
            failure_oracle,
            &mut discovered_failure_configurations,
            &mut discovered_failures,
        )?;

        while (expansions.len() as u64) < budget.max_expansions {
            let Some(index) = select_search_frontier_candidate(
                self,
                &worklist,
                strategy,
                max_depth,
                guidance_config.zip(guidance_state.as_deref()),
            ) else {
                break;
            };
            let candidate = worklist.remove(index);
            if !expanded.insert(candidate.id()) {
                continue;
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
            for child in &search.frontier_report.explored {
                let child_id = child.configuration.id();
                explored_graph.insert(child_id);
                record_search_discovered_failure(
                    &child.configuration,
                    scenario,
                    failure_oracle,
                    &mut discovered_failure_configurations,
                    &mut discovered_failures,
                )?;
                if scheduled.insert(child_id) {
                    if let Some(state) = guidance_state.as_deref_mut() {
                        state.admit_candidate(self, &child.configuration);
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
                    explored_graph.insert(representative_id);
                    record_search_discovered_failure(
                        &representative,
                        scenario,
                        failure_oracle,
                        &mut discovered_failure_configurations,
                        &mut discovered_failures,
                    )?;
                    if scheduled.insert(representative_id) {
                        if let Some(state) = guidance_state.as_deref_mut() {
                            state.admit_candidate(self, &representative);
                        }
                        worklist.push(SearchFrontierCandidate::new(representative));
                    }
                }
            }

            expansions.push(SearchExpansion {
                sequence: expansions.len() as u64,
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
            Some(config),
            Some(state),
            None,
            None,
        )
    }
}
