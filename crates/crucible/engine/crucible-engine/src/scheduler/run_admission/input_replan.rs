//! Actor-authorized physical replanning after exact input settlement.
//!
//! A private planner projection uses the backend's retained reached coordinate.
//! It never becomes committed scheduler state: final STEP retains the original
//! node counter, configuration and event prefix until the backend fully stops.

use super::*;

impl SingleScheduler {
    #[cfg(test)]
    pub(in crate::scheduler) fn refresh_input_boundary_run(
        &mut self,
        run: &PreparedHostRun,
        reached: NodeCounter,
    ) -> Result<PreparedHostRun, SchedulerError> {
        self.refresh_physical_boundary_run(run, reached, None)
    }

    pub(in crate::scheduler) fn refresh_physical_boundary_run(
        &mut self,
        run: &PreparedHostRun,
        reached: NodeCounter,
        held_delivery: Option<&super::super::event_log::HeldDeliveryCeiling>,
    ) -> Result<PreparedHostRun, SchedulerError> {
        let node = self
            .nodes
            .get(run.plan.index)
            .ok_or_else(|| admission_error("input replanning lost its scheduler node"))?;
        if node.id != run.plan.node
            || node.counter != run.plan.before
            || reached < run.plan.before
            || reached.ticks > run.plan.target_counter
            || reached.ticks > run.admission.owner.semantic_horizon
        {
            return Err(admission_error("input replanning changed its retained RUN"));
        }
        let next_input = self.prepared_run_next_input(node)?;
        if next_input.is_some_and(|input| input <= reached) {
            return Err(admission_error(
                "fixed-T input resolution left an unresolved due input",
            ));
        }

        let mut refreshed = run.clone();
        let mut target = run.plan.target_counter;
        if reached.ticks < run.admission.owner.semantic_horizon {
            self.validate_input_replan_context(run)?;

            // Only this temporary planner view moves. No frontier, STEP, clock
            // mapping or configuration is advanced by the physical report.
            let mut projection = self.clone();
            projection.nodes[run.plan.index].counter = reached;
            let projected_node = &projection.nodes[run.plan.index];
            let candidate = projection
                .advance_candidate(
                    run.plan.index,
                    projected_node,
                    projection.shared_rendezvous_cap()?,
                    projection.pending_topology_activation_cap()?,
                )?
                .ok_or_else(|| admission_error("input continuation has no fresh planner cap"))?;
            let fresh = projection.advance_plan_draft(&candidate)?;
            target = fresh
                .target_counter
                .min(run.admission.owner.semantic_horizon);
            if let Some(input) = next_input {
                target = target.min(input.ticks);
            }
            if let Some(ceiling) = held_delivery
                && let Some(bound) = ceiling.bound(self, node)?
            {
                target = target.min(bound.ticks);
            }
            if target <= reached.ticks {
                return Err(admission_error(
                    "input continuation has no positive physical window",
                ));
            }
            refreshed.plan.quiescent_horizon = if target == fresh.target_counter {
                fresh.quiescent_horizon
            } else {
                None
            };
        } else if target != reached.ticks {
            return Err(admission_error(
                "terminal input stop differs from its semantic horizon",
            ));
        }

        let target_time = self.node_time_for_counter(node, NodeCounter { ticks: target })?;
        let subdivision = self.planned_run_subdivision(&run.plan.node, run.plan.before, target)?;
        let publication =
            self.publish_run_ceiling(run.plan.node.clone(), reached, target, target_time)?;
        let revision = publication
            .sequence
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or_else(|| admission_error("input boundary publication revision exhausted"))?;
        refreshed.preemptions = self.planned_preemptions_for_authorized_run(
            &run.plan.node,
            run.plan.before,
            &publication,
            run.authorized_preemption_horizon,
        )?;
        refreshed.plan.target_counter = target;
        refreshed.plan.projected_target_time = target_time;
        refreshed.plan.subdivision = subdivision;
        refreshed.plan.ceiling = publication;
        refreshed.admission = PreparedRunAdmission {
            owner: Arc::clone(&run.admission.owner),
            input_inventory: PreparedRunInputInventory {
                generation: revision,
                next_input,
                _source: Arc::new(self.clone()),
            },
            dispatch_horizon: ExecutionHorizon {
                icount: Icount { retired: target },
            },
        };
        Ok(refreshed)
    }

    fn validate_input_replan_context(&self, run: &PreparedHostRun) -> Result<(), SchedulerError> {
        let original = &run.admission.owner._source;
        let command = self
            .preemption_requests
            .iter()
            .find(|command| command.node == run.plan.node.node);
        let context_current = run.canonical_lineage.as_ref().map_or_else(
            || {
                original.configuration == self.configuration
                    && original.event_log.offset() == self.event_log.offset()
            },
            |lineage| lineage.validate_context(original, self),
        );
        if !context_current
            || original.effective_topology != self.effective_topology
            || original.topology_epoch != self.topology_epoch
            || run.admission.owner.command.as_ref() != command
            || original.nodes[run.plan.index].time_mapping
                != self.nodes[run.plan.index].time_mapping
        {
            return Err(admission_error(
                "input continuation changed its immutable context or command authorization",
            ));
        }
        Ok(())
    }
}
