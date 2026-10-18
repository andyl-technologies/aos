//! Non-destructive settlement of a production world's final boundary.
//!
//! A world that stops at a stable boundary may be kept as a hot-fork template
//! instead of being torn down. Its attempt must still seal exactly the log a
//! shutdown would have produced. [`ProductionVmLifecycleLoop::drain_final_boundary_for_retention`]
//! settles that boundary without teardown, and declines without side effects
//! whenever ordinary shutdown would report a lifecycle error or discard
//! teardown-only state, so the caller then shuts down as before and observes
//! the same outcome. A decline names the first refusing check as a
//! [`RetentionDrainRefusal`], whose token is stable for diagnostics.

use super::*;

/// Outcome of settling a production world's final boundary for retention.
#[derive(Debug, PartialEq, Eq)]
pub enum RetentionDrain {
    /// The boundary settled and these entries were appended to the log.
    ///
    /// They are exactly what [`QuantumLoop::shutdown`] would publish for this
    /// boundary. Callers retain the world only when the list is empty.
    Settled(Vec<SchedulerEventLogEntry>),
    /// Nothing changed; the world must be shut down as before.
    Declined(RetentionDrainRefusal),
}

/// The first check that keeps a production world from being retained.
///
/// Checks run in declaration order, so a world failing several reports the
/// earliest. [`Self::token`] is the stable diagnostic spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionDrainRefusal {
    /// Installed branch effect choices were not all consumed.
    PendingBranchEffectChoices,
    /// Signal-fault campaign branches remain to be applied.
    PendingSignalFaultBranches,
    /// A debugger gateway is still installed.
    DebugGateway,
    /// A debugger attachment is still active.
    DebugAttach,
    /// A debugger gateway still requires teardown.
    DebugGatewayTeardown,
    /// Debugger ownership of a candidate is indeterminate.
    IndeterminateDebugCandidate,
    /// A node-lease cleanup failed and its lease remains quarantined.
    NodeLeaseCleanupFailed,
    /// The retained event log starts after genesis.
    RetainedLogAfterGenesis,
    /// Selected campaign network effects were not all regenerated.
    CampaignEffectReplayUnexhausted,
    /// The installed fault replay plan was not exhausted.
    FaultReplayUnexhausted,
    /// Installed fault search overrides were not all consumed.
    SearchOverridesUnconsumed,
    /// The backend owner holds state that only teardown may discard.
    Boundary(crucible::FinalBoundaryRefusal),
}

impl RetentionDrainRefusal {
    /// Returns the stable kebab-case token naming this refusal in diagnostics.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::PendingBranchEffectChoices => "pending-branch-effect-choices",
            Self::PendingSignalFaultBranches => "pending-signal-fault-branches",
            Self::DebugGateway => "debug-gateway",
            Self::DebugAttach => "debug-attach",
            Self::DebugGatewayTeardown => "debug-gateway-teardown",
            Self::IndeterminateDebugCandidate => "indeterminate-debug-candidate",
            Self::NodeLeaseCleanupFailed => "node-lease-cleanup-failed",
            Self::RetainedLogAfterGenesis => "retained-log-after-genesis",
            Self::CampaignEffectReplayUnexhausted => "campaign-effect-replay-unexhausted",
            Self::FaultReplayUnexhausted => "fault-replay-unexhausted",
            Self::SearchOverridesUnconsumed => "search-overrides-unconsumed",
            Self::Boundary(refusal) => refusal.token(),
        }
    }
}

impl ProductionVmLifecycleLoop {
    /// Settles the final committed boundary and keeps the world running.
    ///
    /// Returns [`RetentionDrain::Declined`], changing nothing, when the world
    /// is not retainable: it holds unconsumed branch effect choices or
    /// signal-fault branches, unexhausted fault or campaign-effect replay,
    /// unconsumed search overrides, debugger ownership, failed node-lease
    /// cleanup, a retained log that starts after genesis, or backend state
    /// only teardown may discard, such as a guest stop awaiting its reply.
    /// Otherwise returns [`RetentionDrain::Settled`] with the entries that
    /// [`QuantumLoop::shutdown`] would publish for this boundary, already
    /// appended to the log.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the fault runtime lock is poisoned or
    /// the boundary cannot be settled. The world must then be shut down.
    pub fn drain_final_boundary_for_retention(&mut self) -> Result<RetentionDrain, SchedulerError> {
        if let Some(refusal) = self.retention_refusal()? {
            return Ok(RetentionDrain::Declined(refusal));
        }

        // The refusal check covered every backend condition that declines
        // settlement, so a missing settlement here means the two disagree.
        self.inner
            .drain_final_boundary()?
            .map(RetentionDrain::Settled)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "final boundary declined settlement after its refusal check passed",
                ),
            })
    }

    /// Returns the first check that refuses retention, reading state only.
    ///
    /// The lifecycle checks mirror those [`QuantumLoop::shutdown`] reports as
    /// failures; the backend check names state its cleanup-only path discards.
    fn retention_refusal(&self) -> Result<Option<RetentionDrainRefusal>, SchedulerError> {
        if let Some(refusal) = self.lifecycle_retention_refusal() {
            return Ok(Some(refusal));
        }
        if let Some(refusal) = self.fault_runtime_retention_refusal()? {
            return Ok(Some(refusal));
        }
        Ok(self
            .inner
            .final_boundary_refusal()
            .map(RetentionDrainRefusal::Boundary))
    }

    fn lifecycle_retention_refusal(&self) -> Option<RetentionDrainRefusal> {
        let loop_impl = self.inner.loop_impl();
        let checks = [
            (
                loop_impl.pending_branch_effect_choice_count() != 0,
                RetentionDrainRefusal::PendingBranchEffectChoices,
            ),
            (
                !self.signal_fault_branches.is_empty(),
                RetentionDrainRefusal::PendingSignalFaultBranches,
            ),
            (
                self.debug_gateway.is_some(),
                RetentionDrainRefusal::DebugGateway,
            ),
            (
                self.debug_attach.is_some(),
                RetentionDrainRefusal::DebugAttach,
            ),
            (
                self.debug_gateway_teardown_required,
                RetentionDrainRefusal::DebugGatewayTeardown,
            ),
            (
                self.indeterminate_debug_candidate.is_some(),
                RetentionDrainRefusal::IndeterminateDebugCandidate,
            ),
            (
                self.node_lease_cleanup_failed,
                RetentionDrainRefusal::NodeLeaseCleanupFailed,
            ),
            (
                loop_impl.event_log().retained_base_events() != 0,
                RetentionDrainRefusal::RetainedLogAfterGenesis,
            ),
            (
                self.inner
                    .network_output_interceptor()
                    .verify_campaign_effect_replay_exhausted()
                    .is_err(),
                RetentionDrainRefusal::CampaignEffectReplayUnexhausted,
            ),
        ];
        checks
            .into_iter()
            .find_map(|(refused, refusal)| refused.then_some(refusal))
    }

    fn fault_runtime_retention_refusal(
        &self,
    ) -> Result<Option<RetentionDrainRefusal>, SchedulerError> {
        if !self.fault_replay_installed && !self.fault_search_overrides_installed {
            return Ok(None);
        }

        let runtime = self
            .fault_runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?;
        if self.fault_replay_installed && runtime.verify_replay_exhausted().is_err() {
            return Ok(Some(RetentionDrainRefusal::FaultReplayUnexhausted));
        }
        if self.fault_search_overrides_installed
            && runtime.verify_search_overrides_consumed().is_err()
        {
            return Ok(Some(RetentionDrainRefusal::SearchOverridesUnconsumed));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
