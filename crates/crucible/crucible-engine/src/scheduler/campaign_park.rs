//! Campaign-marker parks that wait for an all-VM atomic choice.
//!
//! A network fault phase applies one atomic choice only after every VM has
//! parked at the same campaign marker. VMs reach their markers at staggered
//! times, so an early park must stop running without pinning the live
//! frontier for the VMs still on their way. Once the all-parked boundary is
//! validated, each parked VM joins the committed frontier exactly as a
//! reactivated VM does: its physical counter stays at the park and its
//! logical clock moves to the frontier. Frames that peers sent toward a
//! parked VM wait in its inbound links and are delivered once it resumes.
//! Parks are live scheduler state; a checkpoint is refused while any node
//! remains parked.

use super::inactive_time::check_native_deadline_shift;
use super::*;

/// One directed World link staged to resume its joined receiver.
type ResumedInboundLink = ((LinkId, NetworkLinkDirection), crucible_device::NetLink);

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
    /// duration. Frames still in flight toward a joined VM stay in its inbound
    /// links; any due inside the interval it skipped become due at its first
    /// deliverable instant after the frontier, in emission order. The VM
    /// remains physically paused until its backend release. Returns the
    /// joined nodes in node order.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when a parked VM's clock
    /// lies beyond the frontier of a world with live participants, when a
    /// native timer deadline would overflow, or when an inbound link cannot
    /// resume its receiver. Nothing changes on failure.
    pub fn join_campaign_parks_to_frontier(&mut self) -> Result<Vec<NodeId>, SchedulerError> {
        let mut parks = Vec::new();
        for (index, node) in self.nodes.iter().enumerate() {
            if node.campaign_parked {
                parks.push((index, self.node_scheduler_time(node)?));
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
        let resumed_links = self.resume_parked_inbound_links(&joins, target)?;

        self.frontier = VirtualTime { ticks: target };
        for (key, link) in resumed_links {
            if let Some(runtime) = self.world_network_links.get_mut(&key) {
                runtime.link = link;
            }
        }
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

    /// Stages the inbound links of joined VMs at their resume instant.
    ///
    /// A parked VM consumes no frames, so peers that keep running leave
    /// frames in flight toward it. The join moves its clock to the frontier
    /// without it observing the skipped interval; frames due inside that
    /// interval become due at its first deliverable instant rather than in
    /// its past, and later frames keep their exact delivery. Links are staged
    /// on copies so a refused join changes nothing.
    fn resume_parked_inbound_links(
        &self,
        joins: &[(usize, u64)],
        target: u64,
    ) -> Result<Vec<ResumedInboundLink>, SchedulerError> {
        let joined = joins
            .iter()
            .map(|(index, _delta)| &self.nodes[*index].id.node)
            .collect::<BTreeSet<_>>();
        let resume_tick = self.network_tick_for_time(SimInstant { ticks: target });

        let mut resumed = Vec::new();
        for (key, runtime) in &self.world_network_links {
            if !joined.contains(runtime.target()) {
                continue;
            }
            let mut link = runtime.link.clone();
            link.resume_consumer_at(resume_tick)
                .map_err(|source| SchedulerError::BoundaryViolation {
                    message: format!(
                        "World network link {:?} ({:?}) cannot resume its parked receiver at tick {resume_tick}: {source}",
                        runtime.canonical_id.name, runtime.direction
                    ),
                })?;
            resumed.push((key.clone(), link));
        }
        Ok(resumed)
    }
}
