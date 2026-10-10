//! Binds authored ordinary demands to the actual closed Clock/gem5 preparation.
//!
//! The selection wrapper changes the complete source-owned world identity. It
//! never replaces the native initialization, fresh exact certificate or actual
//! all-owner preparation barrier with a portable capability assertion.

use super::{ResolvedCapabilityWorld, bind_original_requirements, policy, refused};
use crate::{node_observed_executor::NodeObservedError, node_scenario::NodeScenario};

impl ResolvedCapabilityWorld {
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
