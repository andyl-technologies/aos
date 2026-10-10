//! Campaign-marker parks that wait for an all-VM atomic choice.
//!
//! A network fault phase applies one atomic choice only after every VM has
//! parked at the same campaign marker. VMs reach their markers at staggered
//! times, so an early park must stop running without pinning the live
//! frontier for the VMs still on their way. Once the all-parked boundary is
//! validated, each parked VM joins the committed frontier exactly as a
//! reactivated VM does: its physical counter stays at the park and its
//! logical clock moves to the frontier. Parks are live scheduler state;
//! a checkpoint is refused while any node remains parked.

use super::inactive_time::check_native_deadline_shift;
use super::*;

impl SingleScheduler {
    /// Parks one VM at its committed campaign marker.
    ///
    /// The VM stops being selected for RUNs and no longer holds back the
    /// frontier. Its physical counter and logical clock are unchanged until
    /// [`SingleScheduler::join_campaign_parks_to_frontier`].
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `node` is not a
    /// live VM, is already parked or inactive, or when the frontier cannot be
    /// projected from the remaining participants.
    pub fn park_campaign_marker_node(&mut self, node: &NodeId) -> Result<(), SchedulerError> {
        let index = self.vm_node_index(node)?;
        if self.nodes[index].scheduling_inactive() {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "campaign marker park requires a live, unparked VM `{}`",
                    node.name
                ),
            });
        }

        self.nodes[index].campaign_parked = true;
        // Removing a participant can only raise the live minimum; an
        // all-parked world retains the committed frontier.
        self.frontier = frontier_for(&self.nodes, Some(self.frontier))?;
        Ok(())
    }

    /// Reports whether any VM is parked awaiting an atomic marker choice.
    #[must_use]
    pub fn has_campaign_parks(&self) -> bool {
        self.nodes.iter().any(|node| node.campaign_parked)
    }

    /// Returns the VMs parked awaiting an atomic marker choice, in node order.
    #[must_use]
    pub fn campaign_parked_nodes(&self) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|node| node.campaign_parked)
            .map(|node| node.id.node.clone())
            .collect()
    }

    /// Joins every parked VM to a common frontier and clears its park.
    ///
    /// While another participant is live, parks join the committed frontier.
    /// Once no participant is live, staggered parks may lie beyond it, so the
    /// frontier first advances to the latest park: no VM's clock moves
    /// backward and earlier parks skip their waiting time as an inactive VM
    /// does. Each VM keeps its physical counter; its logical clock is anchored
    /// at the frontier and its native timer reports keep their remaining
    /// duration. The VM remains physically paused until its backend release.
    /// Returns the joined nodes in node order.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when a parked VM's clock
    /// lies beyond the frontier of a world with live participants, or when a
    /// native timer deadline would overflow. Nothing changes on failure.
    pub fn join_campaign_parks_to_frontier(&mut self) -> Result<Vec<NodeId>, SchedulerError> {
        let mut parks = Vec::new();
        for (index, node) in self.nodes.iter().enumerate() {
            if node.campaign_parked {
                parks.push((index, self.node_current_time(node)?));
            }
        }
        let live = self.nodes.iter().any(|node| !node.scheduling_inactive());
        let latest_park = parks.iter().map(|(_, current)| current.ticks).max();
        let target = match latest_park {
            Some(latest) if !live => self.frontier.ticks.max(latest),
            _ => self.frontier.ticks,
        };

        let mut joins = Vec::with_capacity(parks.len());
        for (index, current) in parks {
            let node = &self.nodes[index];
            if current.ticks > target {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "parked VM `{}` at {} lies beyond frontier {}",
                        node.id.node.name, current.ticks, target
                    ),
                });
            }
            let delta = target - current.ticks;
            check_native_deadline_shift(node, delta, "joining parked")?;
            joins.push((index, delta));
        }

        self.frontier = VirtualTime { ticks: target };
        let mut joined = Vec::with_capacity(joins.len());
        for (index, delta) in joins {
            if delta != 0 {
                self.reanchor_node_to_frontier(index, delta);
            }
            self.nodes[index].campaign_parked = false;
            joined.push(self.nodes[index].id.node.clone());
        }
        Ok(joined)
    }
}
