//! Live signal-fault campaign admission and discovery at quantum boundaries.

use super::*;

impl ProductionVmLifecycleLoop {
    /// Enables exact live signal-fault campaign promotion from this boundary.
    ///
    /// Callers activate promotion only after deterministic prefix
    /// materialization reaches the attempt's admitted start. Previously
    /// retained search frontiers remain replay evidence and are not emitted.
    pub fn enable_signal_fault_campaign_promotion(&mut self) {
        self.promote_signal_fault_campaign_choices = true;
    }

    /// Installs the exact nonterminal frontier for the active modeled attempt.
    ///
    /// The scheduler composes this caller-owned frontier with its trigger,
    /// branch, topology, and rendezvous horizons before it advances a backend.
    /// Passing `None` clears the prior attempt's frontier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `frontier` precedes
    /// the scheduler's committed frontier.
    pub fn set_attempt_stop_frontier(
        &mut self,
        frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        self.inner
            .loop_impl_mut()
            .set_attempt_stop_frontier(frontier)
    }

    pub(super) fn authenticate_signal_fault_campaign_branch(
        &self,
        branch: &crucible::SignalFaultCampaignBranch,
    ) -> Result<(), SchedulerError> {
        let authenticated = if let Some((choice, expected)) = branch.expected_search_override() {
            self.fault_runtime
                .lock()
                .map_err(|_| SchedulerError::BoundaryViolation {
                    message: String::from("production fault runtime lock is poisoned"),
                })?
                .search_override_consumed(choice, &expected)
        } else {
            self.inner
                .loop_impl()
                .search_frontiers()
                .iter()
                .any(|frontier| branch.matches_runtime_frontier(frontier))
        };
        if !authenticated {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "signal-fault campaign branch has no exact observed producer choice",
                ),
            });
        }
        Ok(())
    }

    /// Normalizes only signal-fault frontiers first observed by this quantum.
    ///
    /// The scheduler retains older frontiers for checkpoint and replay
    /// authentication. Re-emitting that history as a later discovery would
    /// manufacture a branch point after execution had already passed it, so
    /// callers supply the frontier count captured before the quantum began.
    pub(super) fn signal_fault_campaign_discoveries_at_current_boundary_since(
        &self,
        first: usize,
    ) -> Result<Vec<crucible::campaign::ChoiceDiscovery>, SchedulerError> {
        if !self.promote_signal_fault_campaign_choices {
            return Ok(Vec::new());
        }
        let frontiers = self.inner.loop_impl().search_frontiers();
        let current = frontiers
            .get(first..)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("signal-fault frontier history shrank during one quantum"),
            })?;
        if current.len() > crucible::MAX_SIGNAL_FAULT_CAMPAIGN_BRANCHES {
            return Err(SchedulerError::ResourceLimit {
                field: "signal-fault campaign discoveries",
                current: 0,
                requested: u64::try_from(current.len()).unwrap_or(u64::MAX),
                configured: u64::try_from(crucible::MAX_SIGNAL_FAULT_CAMPAIGN_BRANCHES)
                    .unwrap_or(u64::MAX),
                hard: u64::try_from(crucible::MAX_SIGNAL_FAULT_CAMPAIGN_BRANCHES)
                    .unwrap_or(u64::MAX),
            });
        }

        let mut charged_records = BTreeSet::new();
        let mut charged_bytes = 0usize;
        let mut discoveries = Vec::with_capacity(current.len());
        let configuration = self.inner.loop_impl().configuration();
        let at = self.inner.loop_impl().frontier();
        for frontier in current
            .iter()
            .filter(|frontier| frontier.configuration == *configuration && frontier.at == at)
        {
            let discovery = crucible::SignalFaultSelectable::from_frontier(frontier)
                .and_then(|selectable| selectable.discovery())
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("normalize live signal-fault campaign discovery: {error}"),
                })?;
            for (id, bytes) in [
                (
                    discovery.opportunity().declaration().content_id(),
                    discovery.declaration().canonical_bytes().len(),
                ),
                (
                    discovery.opportunity().domain().content_id(),
                    discovery.domain().canonical_bytes().len(),
                ),
                (
                    discovery
                        .opportunity()
                        .id()
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!(
                                "identify live signal-fault campaign discovery: {error}"
                            ),
                        })?
                        .content_id(),
                    discovery.opportunity().canonical_bytes().len(),
                ),
            ] {
                if !charged_records.insert(id) {
                    continue;
                }
                charged_bytes = charged_bytes.checked_add(bytes).ok_or_else(|| {
                    SchedulerError::ResourceLimit {
                        field: "signal-fault campaign discovery bytes",
                        current: 0,
                        requested: u64::MAX,
                        configured: u64::try_from(
                            crucible::campaign::MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES,
                        )
                        .unwrap_or(u64::MAX),
                        hard: u64::try_from(
                            crucible::campaign::MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES,
                        )
                        .unwrap_or(u64::MAX),
                    }
                })?;
                if charged_bytes > crucible::campaign::MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES {
                    return Err(SchedulerError::ResourceLimit {
                        field: "signal-fault campaign discovery bytes",
                        current: 0,
                        requested: u64::try_from(charged_bytes).unwrap_or(u64::MAX),
                        configured: u64::try_from(
                            crucible::campaign::MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES,
                        )
                        .unwrap_or(u64::MAX),
                        hard: u64::try_from(
                            crucible::campaign::MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES,
                        )
                        .unwrap_or(u64::MAX),
                    });
                }
            }
            discoveries.push(discovery);
        }
        Ok(discoveries)
    }

    pub(super) fn append_live_signal_fault_campaign_discoveries(
        &self,
        first: usize,
        outcome: &mut QuantumOutcome,
    ) -> Result<(), SchedulerError> {
        outcome
            .discovered_choices
            .extend(self.signal_fault_campaign_discoveries_at_current_boundary_since(first)?);
        Ok(())
    }
}
