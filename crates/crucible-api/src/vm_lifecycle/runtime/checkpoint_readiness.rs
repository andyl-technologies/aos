//! Named reasons a production lifecycle boundary is not exact-checkpoint ready.
//!
//! Readiness and capture must agree: every state that portable capture or
//! hot-fork continuation capture refuses is also reported here as not ready,
//! so callers that poll readiness keep driving instead of attempting a capture
//! that fails closed.

use std::fmt;

use super::*;

/// Names the first condition that keeps the current boundary from an exact checkpoint.
///
/// Conditions are checked in a fixed order, so the reported reason is
/// deterministic for a given lifecycle state. Every reason is transient from
/// the caller's view: driving further ordinary quanta may settle it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProductionExactCheckpointNotReady {
    /// Host RUN outcomes are retained after a failed canonical publication.
    HeldHostOutcomes,
    /// A committed stop is still held as an unsettled host continuation.
    ///
    /// Held peer outcomes and the stopping RUN are host state that no exact
    /// checkpoint carries.
    UnsettledHostContinuation,
    /// A World-network preselection withholds a TX suffix published by replay.
    LiveNetworkPreselection,
    /// A campaign marker or choice park is still open.
    CampaignParks,
    /// Branch-effect choices are pending at this boundary.
    BranchEffectChoices,
    /// Signal-fault replay branches are not yet applied.
    SignalFaultBranches,
    /// Emitted network output is still ahead of the shared frontier.
    PendingNetworkOutputs,
    /// A selectable catalog outside the initial execution boundary has not frozen.
    SelectableCatalogs,
    /// An admitted device coroutine on this node crosses the boundary.
    DeviceIo {
        /// Node whose device I/O is not quiescent.
        node: NodeId,
    },
    /// A selectable reply on this node is not checkpoint quiescent.
    SelectableReply {
        /// Node whose selectable reply is still in flight.
        node: NodeId,
    },
}

impl fmt::Display for ProductionExactCheckpointNotReady {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeldHostOutcomes => {
                formatter.write_str("host RUN outcomes are held after a failed publication")
            }
            Self::UnsettledHostContinuation => formatter.write_str(
                "physical checkpoint cannot retain held or unpublished host RUN outcomes",
            ),
            Self::LiveNetworkPreselection => {
                formatter.write_str("a World-network preselection withholds a TX suffix")
            }
            Self::CampaignParks => formatter.write_str("campaign parks are still open"),
            Self::BranchEffectChoices => {
                formatter.write_str("branch-effect choices are still pending")
            }
            Self::SignalFaultBranches => {
                formatter.write_str("signal-fault replay branches are still pending")
            }
            Self::PendingNetworkOutputs => {
                formatter.write_str("emitted network output is ahead of the shared frontier")
            }
            Self::SelectableCatalogs => formatter.write_str("a selectable catalog has not frozen"),
            Self::DeviceIo { node } => {
                write!(
                    formatter,
                    "device I/O on node {} is not quiescent",
                    node.name
                )
            }
            Self::SelectableReply { node } => {
                write!(
                    formatter,
                    "selectable reply on node {} is not quiescent",
                    node.name
                )
            }
        }
    }
}

impl ProductionVmLifecycleLoop {
    /// Reports whether every live node can enter an exact checkpoint now.
    ///
    /// A false result means an already-admitted device coroutine crosses the
    /// current scheduler boundary, a selectable catalog outside the initial
    /// execution boundary has not frozen, emitted network output is still
    /// ahead of the shared frontier, or another condition named by
    /// [`ProductionExactCheckpointNotReady`] holds. The caller may drive
    /// another ordinary quantum and retry; checkpoint capture itself never
    /// advances through the deterministic completion coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when a live node is missing from the backend
    /// set or its shared device-I/O state cannot be inspected consistently.
    pub fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(self.exact_checkpoint_refusal()?.is_none())
    }

    /// Names the first condition that keeps the current boundary from an exact checkpoint.
    ///
    /// Returns `None` exactly when [`Self::exact_checkpoint_ready`] reports
    /// true. Conditions are checked in a fixed order, so the named reason is
    /// deterministic for a given lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when a live node is missing from the backend
    /// set or its shared device-I/O state cannot be inspected consistently.
    pub fn exact_checkpoint_refusal(
        &mut self,
    ) -> Result<Option<ProductionExactCheckpointNotReady>, SchedulerError> {
        if let Some(refusal) = self.host_state_checkpoint_refusal() {
            return Ok(Some(refusal));
        }

        let _pending = self
            .inner
            .backend_mut()
            .drain_pending_selectable_requests()?;
        let configuration = self.inner.loop_impl().configuration().clone();
        let event_log_events = self.inner.loop_impl().event_log().offset().events;
        let selectable_catalog_plans = self.inner.backend().selectable_catalog_plans();
        let live_nodes = self
            .source
            .world()
            .vm_nodes()
            .iter()
            .filter(|node| {
                self.node_service_states.get(&node.id) == Some(&ProductionNodeServiceState::Running)
            })
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        if !selectable_catalogs_checkpoint_ready(
            &configuration,
            self.initial_lifecycle_observations_pending,
            event_log_events,
            &live_nodes,
            &selectable_catalog_plans,
        ) {
            return Ok(Some(ProductionExactCheckpointNotReady::SelectableCatalogs));
        }

        for node in live_nodes {
            if !self
                .inner
                .backend_mut()
                .checkpoint_device_io_is_quiescent(&node)?
            {
                return Ok(Some(ProductionExactCheckpointNotReady::DeviceIo { node }));
            }
            if !self
                .inner
                .backend_mut()
                .selectable_reply_is_checkpoint_quiescent(&node)?
            {
                return Ok(Some(ProductionExactCheckpointNotReady::SelectableReply {
                    node,
                }));
            }
        }
        Ok(None)
    }

    // Host-side conditions need no backend inspection, so they are checked
    // before draining selectable requests or querying any live node.
    fn host_state_checkpoint_refusal(&self) -> Option<ProductionExactCheckpointNotReady> {
        use ProductionExactCheckpointNotReady as NotReady;

        if self.pending_held_host_outcomes.is_some() {
            return Some(NotReady::HeldHostOutcomes);
        }
        // Capture refuses a held stop and its peers' RUN plans because no
        // exact checkpoint carries them; readiness must not claim otherwise.
        if self.inner.has_unsettled_host_continuation() {
            return Some(NotReady::UnsettledHostContinuation);
        }
        // A World-network preselection is published by thin replay from an
        // earlier admitted ancestor; its withheld TX suffix is not snapshot state.
        if self.inner.live_network_preselection().is_some() {
            return Some(NotReady::LiveNetworkPreselection);
        }
        if self.inner.has_campaign_parks() {
            return Some(NotReady::CampaignParks);
        }
        if self.inner.loop_impl().pending_branch_effect_choice_count() != 0 {
            return Some(NotReady::BranchEffectChoices);
        }
        if !self.signal_fault_branches.is_empty() {
            return Some(NotReady::SignalFaultBranches);
        }
        if self.inner.pending_network_output_count() != 0 {
            return Some(NotReady::PendingNetworkOutputs);
        }
        None
    }
}
