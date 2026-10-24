//! Reduction-aware temporal-graph search entry point.

use super::*;

impl TemporalGraph {
    /// Searches with graph-level symmetry and partial-order reductions enabled.
    ///
    /// Reductions are applied by the same single-frontier expansion path as
    /// [`Self::search`]. Covered partial-order candidates schedule their
    /// canonical representative instead, making the reduced graph independent of
    /// which frontier strategy reaches the non-canonical ordering first.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the root, a selected frontier, or an admitted
    /// reduction representative cannot be recorded, realized, reduced, or
    /// materialized.
    pub fn search_with_strategy_reduced(
        &mut self,
        root: &Configuration,
        strategy: SearchStrategy,
        budget: SearchBudget,
        reduction_policy: FrontierReductionPolicy,
        materialization_policy: MaterializationPolicy,
        trigger: MaterializationTrigger,
    ) -> Result<TemporalGraphSearchRun, EngineError> {
        let failure_oracle = SearchFailureOracle::none();
        self.search_with_strategy_inner(
            root,
            strategy,
            budget,
            reduction_policy,
            materialization_policy,
            trigger,
            None,
            &failure_oracle,
            None,
            None,
            None,
            None,
        )
    }
}
