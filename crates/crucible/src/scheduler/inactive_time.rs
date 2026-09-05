//! Global clock ownership while VM instruction counters are inactive.
//!
//! Powered-off nodes retain physical counters, but do not hold back the live
//! frontier. A world with no active nodes can still reach a scheduled host
//! evaluation without issuing a backend RUN. Reactivation joins the current
//! frontier and preserves the remaining duration of native timer reports.

use super::*;

impl SingleScheduler {
    /// Projects the complete activity batch before publishing any part of it.
    pub(super) fn frontier_after_activity_change(
        &self,
        activity_for: impl Fn(&NodeId) -> Option<SchedulerNodeActivity>,
    ) -> Result<VirtualTime, SchedulerError> {
        let mut frontier: Option<u64> = None;
        for node in &self.nodes {
            let activity = if node.id.kind == SchedulingNodeKind::Vm {
                activity_for(&node.id.node).unwrap_or(node.activity)
            } else {
                node.activity
            };
            if matches!(
                activity,
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
            ) {
                continue;
            }
            let mut time = self.node_current_time(node)?.nanos;
            if matches!(
                node.activity,
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
            ) {
                time = time.max(self.frontier.ticks);
            }
            frontier = Some(frontier.map_or(time, |current| current.min(time)));
        }
        Ok(VirtualTime {
            ticks: frontier.unwrap_or(self.frontier.ticks),
        })
    }

    pub(super) fn all_nodes_inactive(&self) -> bool {
        self.nodes.iter().all(|node| {
            matches!(
                node.activity,
                SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
            )
        })
    }

    /// Advances only the host clock, never a powered-off backend counter.
    pub(super) fn advance_inactive_clock(&mut self) -> bool {
        if !self.all_nodes_inactive() {
            return false;
        }
        let next = [self.trigger_wakeup, self.signal_fault_wakeup]
            .into_iter()
            .flatten()
            .chain(
                self.topology_changes
                    .iter()
                    .filter_map(|change| change.activation_time),
            )
            .filter(|at| at.nanos > self.frontier.ticks)
            .min();
        let Some(next) = next else {
            return false;
        };
        let target = next
            .min(self.time_limit)
            .min(self.branch_frontier_cap.unwrap_or(next));
        if target.nanos <= self.frontier.ticks {
            return false;
        }
        self.frontier = VirtualTime {
            ticks: target.nanos,
        };
        true
    }

    /// Validates all timer arithmetic before a lifecycle batch changes any node.
    pub(super) fn resume_time_delta(
        &self,
        index: usize,
        activity: SchedulerNodeActivity,
    ) -> Result<u64, SchedulerError> {
        let node = &self.nodes[index];
        if !matches!(
            node.activity,
            SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
        ) || matches!(
            activity,
            SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
        ) {
            return Ok(0);
        }
        let delta = self
            .frontier
            .ticks
            .saturating_sub(self.node_current_time(node)?.nanos);
        let native_timer = match node.exact_local_event {
            ExactLocalEvent::TimerDeadline { virtual_time } => Some(virtual_time),
            _ => None,
        };
        for deadline in native_timer.into_iter().chain(
            node.vcpu_idle_states
                .iter()
                .filter_map(|vcpu| vcpu.next_deadline),
        ) {
            if deadline.nanos.checked_add(delta).is_none() {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "reactivating node `{}` overflows a native timer deadline",
                        node.id.node.name
                    ),
                });
            }
        }
        Ok(delta)
    }

    /// Commits the previously checked resume delta without retiring instructions.
    pub(super) fn commit_node_activity(
        &mut self,
        index: usize,
        activity: SchedulerNodeActivity,
        resume_delta: u64,
    ) {
        let node = &mut self.nodes[index];
        if resume_delta != 0 {
            node.time_mapping = NodeTimeMapping {
                anchor_counter: node.counter,
                anchor_time: SimInstant {
                    nanos: self.frontier.ticks,
                },
            };
            // The entire batch preflights these sums. Device completions are
            // reprojected from physical counters by refresh_device_horizons;
            // global input, trigger, and fault deadlines must not move.
            if let ExactLocalEvent::TimerDeadline { virtual_time } = &mut node.exact_local_event {
                virtual_time.nanos += resume_delta;
            }
            for vcpu in &mut node.vcpu_idle_states {
                if let Some(deadline) = &mut vcpu.next_deadline {
                    deadline.nanos += resume_delta;
                }
            }
        }
        node.activity = activity;
        if matches!(
            activity,
            SchedulerNodeActivity::Halted | SchedulerNodeActivity::Done
        ) {
            self.device_horizons.remove(&node.id.node);
        }
    }
}
