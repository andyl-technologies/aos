//! Binds authored ordinary demands to the actual closed Clock/gem5 preparation.
//!
//! The selection wrapper changes the complete source-owned world identity. It
//! never replaces the native initialization, fresh exact certificate or actual
//! all-owner preparation barrier with a portable capability assertion.

use super::{ResolvedCapabilityWorld, bind_original_requirements, policy, refused};
use crate::{node_observed_executor::NodeObservedError, node_scenario::NodeScenario};

impl ResolvedCapabilityWorld {
    pub(in crate::node_observed_executor::factory) fn preserving_group_selections(
        &self,
    ) -> Result<&[super::super::InstalledNodeSelection], NodeObservedError> {
        if !policy::gem5_group_preserving(&self.candidate.selections) {
            return Err(refused(
                "capability candidate is outside the complete preserving group",
            ));
        }
        policy::matches(
            &self.candidate.selections,
            &self.scenario,
            &self.requirements,
        )?;
        Ok(&self.candidate.selections)
    }

    /// Checks an explicit original capture or restart demand for every selected owner.
    ///
    /// # Errors
    /// Refuses another family, an unsupported action or an omitted mandatory
    /// full-owner operation. Merely carrying a capable profile is insufficient.
    pub(crate) fn require_preserving_group_action(
        &self,
        operation: &str,
    ) -> Result<(), NodeObservedError> {
        self.preserving_group_selections()?;
        if !matches!(operation, "capture" | "durable_restart")
            || self.requirements.nodes.iter().any(|demand| {
                !demand.guarantees.durable_restart
                    || !demand
                        .operations
                        .iter()
                        .any(|required| required.operation.as_str() == operation)
            })
        {
            return Err(refused(
                "native action lacks complete original mandatory owner demands",
            ));
        }
        Ok(())
    }

    pub(in crate::node_observed_executor::factory) fn gem5_preserving_scenario(
        &self,
        baseline: &NodeScenario,
    ) -> Result<NodeScenario, NodeObservedError> {
        if !policy::gem5_group_preserving(&self.candidate.selections) {
            return Err(refused(
                "capability selection has no full preserving group policy",
            ));
        }
        policy::matches(&self.candidate.selections, baseline, &self.requirements)?;
        let selected = bind_original_requirements(
            baseline.clone(),
            &self.requirements,
            &self.requirements_bytes,
        )?;
        if selected.canonical_bytes()? != self.scenario.canonical_bytes()? {
            return Err(refused(
                "preserving capability source changed before preparation",
            ));
        }
        Ok(selected)
    }

    pub(in crate::node_observed_executor::factory) fn gem5_scenario(
        &self,
        baseline: &NodeScenario,
    ) -> Result<NodeScenario, NodeObservedError> {
        if !policy::gem5_ordinary(&self.candidate.selections)
            && !policy::gem5_storage_group(&self.candidate.selections)
        {
            return Err(refused(
                "capability selection is outside the installed live Clock/gem5 roster",
            ));
        }
        policy::matches(&self.candidate.selections, baseline, &self.requirements)?;
        let selected = bind_original_requirements(
            baseline.clone(),
            &self.requirements,
            &self.requirements_bytes,
        )?;
        if selected.canonical_bytes()? != self.scenario.canonical_bytes()? {
            return Err(refused(
                "authored Clock/gem5 capability world changed before preparation",
            ));
        }
        Ok(selected)
    }
}
