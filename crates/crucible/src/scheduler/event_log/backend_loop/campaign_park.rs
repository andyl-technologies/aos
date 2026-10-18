//! Campaign-marker holds settled by parking until an all-VM atomic choice.
//!
//! A held campaign marker otherwise blocks every further quantum until its
//! atomic choice is released, while that choice needs every VM parked at the
//! same marker. Parking settles the hold without a backend release: the VM
//! stays physically paused, stops participating in RUNs and the frontier, and
//! its held peers publish normally. At the validated all-parked boundary the
//! parks join one frontier before the boundary checkpoint is captured.

use super::held_stop::{HeldHostStopKind, HeldHostStopWitness};
use super::*;

impl<B, I> BackendQuantumLoop<SingleScheduler, B, I>
where
    B: ConcurrentSimulationBackend,
    I: BackendNetworkOutputInterceptor<SingleScheduler, B> + Clone,
{
    /// Settles one held campaign marker by parking its VM and publishing peers.
    ///
    /// No backend control is sent; the VM remains physically paused at the
    /// committed marker. Returned outcomes must be published once through the
    /// lifecycle pipeline, exactly as for [`Self::settle_held_host_stop`].
    ///
    /// # Errors
    ///
    /// Rejects a witness that is not a campaign marker, a stale witness, an
    /// already parked VM, or failed peer publication.
    pub fn park_held_campaign_marker(
        &mut self,
        witness: &HeldHostStopWitness,
    ) -> Result<Vec<QuantumOutcome>, SchedulerError> {
        if witness.kind() != HeldHostStopKind::CampaignMarker {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("only a held campaign marker can park"),
            });
        }

        let ((), outcomes) = self.settle_held_host_stop(witness, |scheduler, _, _| {
            scheduler.park_campaign_marker_node(witness.node())
        })?;
        // Removing the parked VM can raise the frontier without any peer
        // completing; queued delivery must observe the same coordinate.
        self.committed_frontier = self.committed_frontier.max(self.loop_impl.frontier);
        Ok(outcomes)
    }

    /// Joins every parked VM to one frontier at the all-parked boundary.
    ///
    /// Pending frames from each parked VM keep their pre-join emission times.
    /// Returns the joined nodes in node order.
    ///
    /// # Errors
    ///
    /// Rejects a poisoned, preselected, or still-held continuation, and any
    /// join the scheduler rejects. Nothing changes on failure.
    pub fn join_campaign_parks_to_frontier(&mut self) -> Result<Vec<NodeId>, SchedulerError> {
        if self.has_unsettled_host_continuation() || self.preselection.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("campaign parks join only after every held stop has settled"),
            });
        }

        let parked = self.loop_impl.campaign_parked_nodes();
        let mut frozen = Vec::with_capacity(parked.len());
        for node in &parked {
            frozen.push((
                node.clone(),
                self.pending_network_output_times_for_node(node)?,
            ));
        }

        let joined = self.loop_impl.join_campaign_parks_to_frontier()?;
        for (node, times) in frozen {
            self.retain_pending_network_output_times(&node, times);
        }
        self.committed_frontier = self.committed_frontier.max(self.loop_impl.frontier);
        Ok(joined)
    }

    /// Reports whether any VM is parked awaiting its atomic marker choice.
    #[must_use]
    pub fn has_campaign_parks(&self) -> bool {
        self.loop_impl.has_campaign_parks()
    }
}
