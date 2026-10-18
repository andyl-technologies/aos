//! Private canonical extensions issued by one live held-output union.
//!
//! These records retain actual scheduler states on both sides of canonical
//! publication. They never replace a RUN's immutable owner or enter a public
//! protocol, checkpoint, or numeric authority token.

use super::held_stop::HeldHostStopController;
use super::*;

// An actor refuses before a further effect when its private evidence budget is
// exhausted. Retention cannot grow without bound under repeated physical waves.
const MAX_CANONICAL_EXTENSIONS: u64 = 1024;

#[derive(Debug)]
struct CanonicalExtension {
    previous: Option<Arc<CanonicalExtension>>,
    before: Arc<SingleScheduler>,
    after: Arc<SingleScheduler>,
    affected_node: NodeId,
    generation: u64,
}

#[derive(Clone, Debug)]
pub(in crate::scheduler) struct HeldRunLineage {
    controller: HeldHostStopController,
    union: Arc<()>,
    actor_generation: u64,
    root: Arc<SingleScheduler>,
    tip: Option<Arc<CanonicalExtension>>,
}

fn rejected(message: &str) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.to_owned(),
    }
}

fn same_context(left: &SingleScheduler, right: &SingleScheduler) -> bool {
    left.configuration == right.configuration
        && left.event_log.offset() == right.event_log.offset()
        && left.effective_topology == right.effective_topology
        && left.topology_epoch == right.topology_epoch
        && left.preemption_requests == right.preemption_requests
        && left.nodes.len() == right.nodes.len()
        && left
            .nodes
            .iter()
            .zip(&right.nodes)
            .all(|(left, right)| left.id == right.id && left.time_mapping == right.time_mapping)
}

impl HeldRunLineage {
    pub(super) fn begin(
        controller: HeldHostStopController,
        actor_generation: u64,
        scheduler: &SingleScheduler,
    ) -> Self {
        Self {
            controller,
            union: Arc::new(()),
            actor_generation,
            root: Arc::new(scheduler.clone()),
            tip: None,
        }
    }

    pub(in crate::scheduler) fn current_source(&self) -> &SingleScheduler {
        self.tip.as_ref().map_or(&self.root, |tip| &tip.after)
    }

    pub(super) fn context_is_current(&self, scheduler: &SingleScheduler) -> bool {
        same_context(self.current_source(), scheduler)
    }

    pub(super) fn authenticate(
        &self,
        controller: &HeldHostStopController,
        actor_generation: u64,
        run: &PreparedHostRun,
        scheduler: &SingleScheduler,
    ) -> Result<(), SchedulerError> {
        let retained = run
            .canonical_lineage
            .as_ref()
            .ok_or_else(|| rejected("held RUN has no actual canonical union lineage"))?;
        let same_tip = match (&self.tip, &retained.tip) {
            (None, None) => true,
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        };
        if self.controller != *controller
            || self.actor_generation != actor_generation
            || !Arc::ptr_eq(&self.union, &retained.union)
            || !same_tip
            || !same_context(self.current_source(), scheduler)
        {
            return Err(rejected(
                "held RUN changed its canonical actor, union or extension tip",
            ));
        }
        Ok(())
    }

    pub(super) fn extend_commit(
        &mut self,
        before: &SingleScheduler,
        after: &SingleScheduler,
        affected_node: &NodeId,
    ) -> Result<(), SchedulerError> {
        self.ensure_extension_room()?;
        if !same_context(self.current_source(), before)
            || before.configuration.def != after.configuration.def
            || before.effective_topology != after.effective_topology
            || before.topology_epoch != after.topology_epoch
            || after.event_log.offset().events < before.event_log.offset().events
            || after.event_log.offset().bytes < before.event_log.offset().bytes
            || before.nodes.len() != after.nodes.len()
            || before
                .nodes
                .iter()
                .zip(&after.nodes)
                .any(|(before, after)| {
                    before.id != after.id
                        || before.time_mapping != after.time_mapping
                        || (before.id.node != *affected_node && before.counter != after.counter)
                })
            || before
                .preemption_requests
                .iter()
                .filter(|command| command.node != *affected_node)
                .ne(after
                    .preemption_requests
                    .iter()
                    .filter(|command| command.node != *affected_node))
        {
            return Err(rejected("canonical commit changed unrelated RUN authority"));
        }
        let generation = self
            .tip
            .as_ref()
            .map_or(Some(1), |tip| tip.generation.checked_add(1))
            .ok_or_else(|| rejected("canonical extension generation exhausted"))?;
        self.tip = Some(Arc::new(CanonicalExtension {
            previous: self.tip.clone(),
            before: Arc::new(before.clone()),
            after: Arc::new(after.clone()),
            affected_node: affected_node.clone(),
            generation,
        }));
        Ok(())
    }

    pub(super) fn ensure_extension_room(&self) -> Result<(), SchedulerError> {
        if self
            .tip
            .as_ref()
            .is_some_and(|tip| tip.generation >= MAX_CANONICAL_EXTENSIONS)
        {
            return Err(rejected("canonical extension evidence capacity exhausted"));
        }
        Ok(())
    }

    pub(in crate::scheduler) fn validate_context(
        &self,
        original: &SingleScheduler,
        scheduler: &SingleScheduler,
    ) -> bool {
        // Rewalk the retained chain rather than accepting a matching final
        // hash or numeric generation as authority for an unrelated mutation.
        let mut cursor = self.tip.as_ref();
        let mut origin_bound = same_context(original, &self.root);
        while let Some(extension) = cursor {
            origin_bound |= same_context(original, &extension.after);
            let previous = extension
                .previous
                .as_ref()
                .map_or(&self.root, |tip| &tip.after);
            if !same_context(previous, &extension.before)
                || !extension
                    .after
                    .nodes
                    .iter()
                    .any(|node| node.id.node == extension.affected_node)
            {
                return false;
            }
            cursor = extension.previous.as_ref();
        }
        origin_bound && same_context(self.current_source(), scheduler)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared_peer_commit() -> (
        SingleScheduler,
        PreparedHostRun,
        HeldRunLineage,
        HeldHostStopController,
    ) {
        let nodes = ["a", "b"]
            .into_iter()
            .map(|name| SchedulerScenarioNode {
                id: SchedulerNodeId {
                    node: NodeId {
                        name: name.to_owned(),
                    },
                    kind: SchedulingNodeKind::Vm,
                },
                counter: NodeCounter { ticks: 0 },
                activity: SchedulerNodeActivity::Runnable,
                network_lookahead: NetworkLookahead::Infinite,
                exact_local_event: ExactLocalEvent::NoArmedTimer,
            })
            .collect();
        let scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
            "private-canonical-lineage",
            64,
            SimInstant { ticks: 64 },
            nodes,
            Vec::new(),
        ))
        .unwrap_or_else(|error| panic!("actual planner fixture: {error}"));
        let mut prepared = scheduler
            .prepare_host_concurrent_quantum_limited(
                QuantumRequest {
                    configuration: scheduler.configuration().clone(),
                    control: Vec::new(),
                },
                2,
            )
            .unwrap_or_else(|error| panic!("actual two-node finalized PICK: {error}"));
        let controller = HeldHostStopController::new();
        let mut lineage = HeldRunLineage::begin(controller.clone(), 1, &prepared.next);
        let mut run = prepared.runs.remove(0);
        run.canonical_lineage = Some(lineage.clone());
        let peer = prepared.runs.remove(0);
        let before = prepared.next.clone();
        // The physical reached coordinate models a backend stop. The actual
        // scheduler STEP and its immutable configuration/prefix are exercised.
        prepared
            .next
            .commit_prepared_host_run(peer, 40, &[], Vec::new(), Vec::new())
            .unwrap_or_else(|error| panic!("actual canonical peer STEP: {error}"));
        lineage
            .extend_commit(
                &before,
                &prepared.next,
                &NodeId {
                    name: String::from("b"),
                },
            )
            .unwrap_or_else(|error| {
                panic!("live actor records exact before/after publication: {error}")
            });
        (prepared.next, run, lineage, controller)
    }

    #[test]
    fn canonical_peer_extension_preserves_original_owner_and_rejects_replayed_tip() {
        let (mut scheduler, mut run, lineage, controller) = prepared_peer_commit();
        assert!(
            lineage
                .authenticate(&controller, 1, &run, &scheduler)
                .is_err()
        );
        run.canonical_lineage = Some(lineage.clone());
        lineage
            .authenticate(&controller, 1, &run, &scheduler)
            .unwrap_or_else(|error| panic!("exact live extension tip: {error}"));
        let original = run.admission.clone();
        let refreshed = scheduler
            .refresh_input_boundary_run(&run, NodeCounter { ticks: 10 })
            .unwrap_or_else(|error| {
                panic!("peer STEP is a retained private canonical extension: {error}")
            });
        assert_eq!(
            refreshed.admission.control_token(),
            original.control_token()
        );
        assert_eq!(refreshed.admission.context(), original.context());
        assert_eq!(refreshed.plan.before, NodeCounter { ticks: 0 });

        let foreign = HeldRunLineage::begin(controller.clone(), 1, &scheduler);
        assert!(
            foreign
                .authenticate(&controller, 1, &run, &scheduler)
                .is_err()
        );
        assert!(
            lineage
                .authenticate(&HeldHostStopController::new(), 1, &run, &scheduler)
                .is_err()
        );
        assert!(
            lineage
                .authenticate(&controller, 2, &run, &scheduler)
                .is_err()
        );
    }

    #[test]
    fn unrelated_prefix_configuration_topology_command_and_mapping_refuse_extension_readmission() {
        for change in 0..5 {
            let (mut scheduler, mut run, lineage, controller) = prepared_peer_commit();
            run.canonical_lineage = Some(lineage.clone());
            match change {
                0 => {
                    QuantumLoop::append_backend_observable_events(
                        &mut scheduler,
                        vec![ObservableEvent::console_output(
                            VirtualTime { ticks: 40 },
                            NodeId {
                                name: String::from("b"),
                            },
                            b"unrelated".to_vec(),
                        )],
                    )
                    .unwrap_or_else(|error| panic!("actual unrelated prefix append: {error}"));
                }
                1 => {
                    scheduler.configuration =
                        Configuration::genesis(crate::ScenarioDef::from_canonical_material(
                            "unrelated-definition",
                            "changed",
                        ))
                }
                2 => scheduler.topology_epoch += 1,
                3 => scheduler.preemption_requests.push(PreemptionDecision {
                    node: run.plan.node.node.clone(),
                    at: SimInstant { ticks: 60 },
                    kind: PreemptionKind::VcpuSwitch {
                        from_vcpu: VcpuId { index: 0 },
                        to_vcpu: VcpuId { index: 1 },
                    },
                }),
                _ => {
                    scheduler.nodes[run.plan.index].time_mapping = NodeTimeMapping {
                        anchor_counter: NodeCounter { ticks: 1 },
                        anchor_time: SimInstant::EPOCH,
                    }
                }
            }
            let publications = scheduler.ceiling_publications.len();
            assert!(
                lineage
                    .authenticate(&controller, 1, &run, &scheduler)
                    .is_err()
            );
            assert!(
                scheduler
                    .refresh_input_boundary_run(&run, NodeCounter { ticks: 10 })
                    .is_err()
            );
            assert_eq!(scheduler.ceiling_publications.len(), publications);
            assert_eq!(
                scheduler.nodes[run.plan.index].counter,
                NodeCounter { ticks: 0 }
            );
        }
    }
}
