//! Private canonical extensions issued by one live held-output union.
//!
//! These records retain the exact typed context compared on both sides of
//! canonical publication, without duplicating unrelated scheduler histories.
//! They never replace a RUN's immutable owner or enter a public
//! protocol, checkpoint, or numeric authority token.

use super::held_stop::HeldHostStopController;
use super::*;

// An actor refuses before a further effect when its private evidence budget is
// exhausted. Retention cannot grow without bound under repeated physical waves.
const MAX_CANONICAL_EXTENSIONS: u64 = 1024;

#[derive(Debug)]
struct CanonicalExtension {
    previous: Option<Arc<CanonicalExtension>>,
    before: Arc<RetainedRunContext>,
    after: Arc<RetainedRunContext>,
    affected_node: NodeId,
    generation: u64,
}

#[derive(Clone, Debug)]
pub(in crate::scheduler) struct HeldRunLineage {
    controller: HeldHostStopController,
    union: Arc<()>,
    actor_generation: u64,
    root: Arc<RetainedRunContext>,
    tip: Option<Arc<CanonicalExtension>>,
}

fn rejected(message: &str) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.to_owned(),
    }
}

// Retains every field in the held-lineage context predicate. Full RUN owners
// and input inventories retain their original scheduler independently; this
// projection supplies neither planner state nor permission to dispatch a RUN.
#[derive(Debug, PartialEq, Eq)]
struct RetainedRunContext {
    configuration: Configuration,
    event_log_offset: EventLogOffset,
    effective_topology: SchedulerLookaheadGraph,
    topology_epoch: u64,
    preemption_requests: Vec<PreemptionDecision>,
    nodes: Vec<(SchedulerNodeId, NodeTimeMapping)>,
}

impl RetainedRunContext {
    fn capture(scheduler: &SingleScheduler) -> Self {
        Self {
            configuration: scheduler.configuration.clone(),
            event_log_offset: scheduler.event_log.offset(),
            effective_topology: scheduler.effective_topology.clone(),
            topology_epoch: scheduler.topology_epoch,
            preemption_requests: scheduler.preemption_requests.clone(),
            nodes: scheduler
                .nodes
                .iter()
                .map(|node| (node.id.clone(), node.time_mapping))
                .collect(),
        }
    }

    fn matches(&self, scheduler: &SingleScheduler) -> bool {
        self.configuration == scheduler.configuration
            && self.event_log_offset == scheduler.event_log.offset()
            && self.effective_topology == scheduler.effective_topology
            && self.topology_epoch == scheduler.topology_epoch
            && self.preemption_requests == scheduler.preemption_requests
            && self.nodes.len() == scheduler.nodes.len()
            && self
                .nodes
                .iter()
                .zip(&scheduler.nodes)
                .all(|((id, mapping), node)| *id == node.id && *mapping == node.time_mapping)
    }
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
            root: Arc::new(RetainedRunContext::capture(scheduler)),
            tip: None,
        }
    }

    fn current_context(&self) -> &RetainedRunContext {
        self.tip.as_ref().map_or(&self.root, |tip| &tip.after)
    }

    pub(super) fn context_is_current(&self, scheduler: &SingleScheduler) -> bool {
        self.current_context().matches(scheduler)
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
            || !self.current_context().matches(scheduler)
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
        if !self.current_context().matches(before)
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
            before: Arc::new(RetainedRunContext::capture(before)),
            after: Arc::new(RetainedRunContext::capture(after)),
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
        let mut origin_bound = self.root.matches(original);
        while let Some(extension) = cursor {
            origin_bound |= extension.after.matches(original);
            let previous = extension
                .previous
                .as_ref()
                .map_or(&self.root, |tip| &tip.after);
            if previous.as_ref() != extension.before.as_ref()
                || !extension
                    .after
                    .nodes
                    .iter()
                    .any(|(id, _)| id.node == extension.affected_node)
            {
                return false;
            }
            cursor = extension.previous.as_ref();
        }
        origin_bound && self.current_context().matches(scheduler)
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
        SingleScheduler,
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
        (prepared.next, run, lineage, controller, before)
    }

    #[test]
    fn canonical_peer_extension_preserves_original_owner_and_rejects_replayed_tip() {
        let (mut scheduler, mut run, lineage, controller, _) = prepared_peer_commit();
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
            let (mut scheduler, mut run, lineage, controller, _) = prepared_peer_commit();
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

    // Kept independently from the projection as the original comparison oracle.
    fn original_same_context(left: &SingleScheduler, right: &SingleScheduler) -> bool {
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

    fn original_validate_context(
        root: &SingleScheduler,
        extensions: &[(SingleScheduler, SingleScheduler, NodeId)],
        original: &SingleScheduler,
        scheduler: &SingleScheduler,
    ) -> bool {
        let mut origin_bound = original_same_context(original, root);
        for (index, (before, after, affected)) in extensions.iter().enumerate().rev() {
            origin_bound |= original_same_context(original, after);
            let previous = index
                .checked_sub(1)
                .map_or(root, |prior| &extensions[prior].1);
            if !original_same_context(previous, before)
                || !after.nodes.iter().any(|node| node.id.node == *affected)
            {
                return false;
            }
        }
        let current = extensions.last().map_or(root, |(_, after, _)| after);
        origin_bound && original_same_context(current, scheduler)
    }

    fn command(node: &NodeId) -> PreemptionDecision {
        PreemptionDecision {
            node: node.clone(),
            at: SimInstant { ticks: 60 },
            kind: PreemptionKind::VcpuSwitch {
                from_vcpu: VcpuId { index: 0 },
                to_vcpu: VcpuId { index: 1 },
            },
        }
    }

    fn mutate_context(scheduler: &mut SingleScheduler, change: usize) {
        match change {
            0 => {}
            1 => {
                scheduler.configuration.def = crate::ScenarioDef::from_canonical_material(
                    "foreign-definition",
                    "same-prefix-is-not-authority",
                )
            }
            2 => {
                scheduler.configuration.schedule =
                    scheduler
                        .configuration
                        .schedule
                        .appended(crate::Decision::Preemption(command(
                            &scheduler.nodes[0].id.node,
                        )))
            }
            3 => scheduler.event_log.offset.prefix = ContentHash::from_bytes(b"foreign-prefix"),
            4 => {
                scheduler.event_log.offset.appended_segment =
                    Some(ContentHash::from_bytes(b"foreign-segment"))
            }
            5 => scheduler.event_log.offset.bytes += 1,
            6 => scheduler.event_log.offset.events += 1,
            7 => {
                scheduler.effective_topology =
                    SchedulerLookaheadGraph::from_edges([SchedulerLookaheadEdge {
                        from: scheduler.nodes[0].id.clone(),
                        to: scheduler.nodes[1].id.clone(),
                        minimum_latency: SimDuration { ticks: 1 },
                    }])
            }
            8 => scheduler.topology_epoch += 1,
            9 => scheduler
                .preemption_requests
                .push(command(&scheduler.nodes[0].id.node)),
            10 => {
                scheduler.nodes.pop();
            }
            11 => scheduler.nodes.swap(0, 1),
            12 => scheduler.nodes[0].id.node.name.push_str("-foreign"),
            13 => scheduler.nodes[0].id.kind = SchedulingNodeKind::Disk,
            14 => scheduler.nodes[0].time_mapping.anchor_counter.ticks += 1,
            15 => scheduler.nodes[0].time_mapping.anchor_time.ticks += 1,
            // These fields are intentionally absent from the original context
            // predicate. Extension admission checks unaffected counters itself.
            16 => scheduler.nodes[0].counter.ticks += 1,
            17 => scheduler.quanta += 1,
            18 => scheduler.nodes[0].ready_point_mapping.anchor_counter.ticks += 1,
            _ => panic!("unknown context mutation"),
        }
    }

    #[test]
    fn retained_context_matches_original_predicate_for_every_field() {
        let (scheduler, mut run, lineage, controller, original) = prepared_peer_commit();
        run.canonical_lineage = Some(lineage.clone());
        let context = RetainedRunContext::capture(&scheduler);

        for change in 0..19 {
            let mut changed = scheduler.clone();
            mutate_context(&mut changed, change);
            let expected = original_same_context(&scheduler, &changed);
            assert_eq!(expected, change == 0 || change >= 16, "mutation {change}");
            assert_eq!(context.matches(&changed), expected, "mutation {change}");
            assert_eq!(
                lineage.context_is_current(&changed),
                expected,
                "mutation {change}"
            );
            assert_eq!(
                lineage.validate_context(&original, &changed),
                expected,
                "mutation {change}"
            );
            assert_eq!(
                lineage.authenticate(&controller, 1, &run, &changed).is_ok(),
                expected,
                "mutation {change}"
            );
        }
        let mut refreshed_scheduler = scheduler.clone();
        let refreshed = refreshed_scheduler
            .refresh_input_boundary_run(&run, NodeCounter { ticks: 10 })
            .unwrap_or_else(|error| panic!("actual modeled canonical operation failed: {error}"));
        assert!(refreshed.admission.shares_semantic_owner(&run.admission));
        let mut commands = scheduler.clone();
        commands.preemption_requests = vec![
            command(&commands.nodes[0].id.node),
            command(&commands.nodes[1].id.node),
        ];
        let ordered = RetainedRunContext::capture(&commands);
        let mut reordered = commands.clone();
        reordered.preemption_requests.reverse();
        assert!(!original_same_context(&commands, &reordered));
        assert!(!ordered.matches(&reordered));
    }

    #[test]
    fn projected_extension_keeps_unaffected_counter_and_command_refusals() {
        let (scheduler, _, lineage, _, _) = prepared_peer_commit();
        let affected = scheduler.nodes[1].id.node.clone();
        for change in 1..=16 {
            let mut next = scheduler.clone();
            mutate_context(&mut next, change);
            let mut attempted = lineage.clone();
            let tip = attempted
                .tip
                .as_ref()
                .unwrap_or_else(|| panic!("actual canonical extension must retain its tip"))
                .clone();
            // New Schedule and monotonically extended offsets are legitimate
            // affected-node publications, as in the original predicate.
            let expected = matches!(change, 2..=6);
            if matches!(change, 3 | 4) {
                // Prefix identities can change on append; byte/event regression
                // is still separately checked below.
                assert!(next.event_log.offset().events >= scheduler.event_log.offset().events);
            }
            assert_eq!(
                attempted
                    .extend_commit(&scheduler, &next, &affected)
                    .is_ok(),
                expected,
                "mutation {change}"
            );
            if !expected {
                assert!(Arc::ptr_eq(
                    attempted.tip.as_ref().unwrap_or_else(|| panic!(
                        "actual canonical extension must retain its tip"
                    )),
                    &tip
                ));
            }
        }
        for regress_bytes in [false, true] {
            let mut next = scheduler.clone();
            if regress_bytes {
                next.event_log.offset.bytes = scheduler
                    .event_log
                    .offset()
                    .bytes
                    .checked_sub(1)
                    .unwrap_or_else(|| panic!("actual peer STEP must emit nonempty log material"));
            } else {
                next.event_log.offset.events = scheduler
                    .event_log
                    .offset()
                    .events
                    .checked_sub(1)
                    .unwrap_or_else(|| panic!("actual peer STEP must emit nonempty log material"));
            }
            assert!(
                lineage
                    .clone()
                    .extend_commit(&scheduler, &next, &affected)
                    .is_err()
            );
        }
    }

    #[test]
    fn projected_chain_preserves_origin_walk_and_retires_exact_contexts() {
        let (mut scheduler, mut run, mut lineage, _, root_source) = prepared_peer_commit();
        run.canonical_lineage = Some(lineage.clone());
        let root_owner = Arc::new(root_source);
        assert!(lineage.root.matches(&root_owner));
        let original_admission = run.admission.clone();
        let before = scheduler.clone();
        let stale = lineage.clone();
        let old_tip = lineage
            .tip
            .as_ref()
            .unwrap_or_else(|| panic!("actual canonical extension must retain its tip"))
            .clone();
        let old_context = Arc::downgrade(&old_tip.after);
        let affected = scheduler.nodes[1].id.node.clone();
        QuantumLoop::append_backend_observable_events(
            &mut scheduler,
            vec![ObservableEvent::console_output(
                VirtualTime { ticks: 40 },
                affected.clone(),
                b"actual-second-publication".to_vec(),
            )],
        )
        .unwrap_or_else(|error| panic!("actual modeled canonical operation failed: {error}"));
        lineage
            .extend_commit(&before, &scheduler, &affected)
            .unwrap_or_else(|error| panic!("actual modeled canonical operation failed: {error}"));
        let original_extensions = [
            (
                root_owner.as_ref().clone(),
                before.clone(),
                affected.clone(),
            ),
            (before.clone(), scheduler.clone(), affected.clone()),
        ];
        for original in [root_owner.as_ref(), &before, &scheduler] {
            for change in 0..19 {
                let mut changed = scheduler.clone();
                mutate_context(&mut changed, change);
                assert_eq!(
                    lineage.validate_context(original, &changed),
                    original_validate_context(
                        &root_owner,
                        &original_extensions,
                        original,
                        &changed
                    ),
                    "original chain oracle, mutation {change}",
                );
            }
        }
        assert!(lineage.validate_context(&root_owner, &scheduler));
        assert!(lineage.validate_context(&before, &scheduler));
        assert!(lineage.validate_context(&scheduler, &scheduler));
        assert!(!stale.validate_context(&root_owner, &scheduler));
        assert!(!lineage.validate_context(&root_owner, &before));
        let mut foreign = root_owner.as_ref().clone();
        mutate_context(&mut foreign, 1);
        assert!(!lineage.validate_context(&foreign, &scheduler));
        let current_context = Arc::downgrade(
            &lineage
                .tip
                .as_ref()
                .unwrap_or_else(|| panic!("actual canonical extension must retain its tip"))
                .after,
        );
        drop(lineage);
        assert!(current_context.upgrade().is_none());
        assert!(old_context.upgrade().is_some());
        drop(old_tip);
        drop(stale);
        // The original held RUN still retains its exact older tip and owner.
        assert!(old_context.upgrade().is_some());
        assert!(original_admission.shares_semantic_owner(&run.admission));
        drop(run);
        assert!(old_context.upgrade().is_none());
        assert_eq!(root_owner.configuration.def, scheduler.configuration.def);
    }

    #[test]
    fn projected_lineage_keeps_capacity_refusal_before_context_validation() {
        let (scheduler, _, mut lineage, _, _) = prepared_peer_commit();
        let affected = scheduler.nodes[1].id.node.clone();
        // No-op publications exercise only the private capacity boundary, not
        // physical execution or an allocation/RSS measurement.
        for _ in 1..MAX_CANONICAL_EXTENSIONS {
            lineage
                .extend_commit(&scheduler, &scheduler, &affected)
                .unwrap_or_else(|error| {
                    panic!("actual modeled canonical operation failed: {error}")
                });
        }
        let tip = lineage
            .tip
            .as_ref()
            .unwrap_or_else(|| panic!("actual canonical extension must retain its tip"))
            .clone();
        let mut foreign = scheduler.clone();
        mutate_context(&mut foreign, 1);
        let error = lineage
            .extend_commit(&foreign, &scheduler, &affected)
            .err()
            .unwrap_or_else(|| panic!("exhausted lineage must refuse before context validation"));
        assert!(
            matches!(error, SchedulerError::BoundaryViolation { message } if message == "canonical extension evidence capacity exhausted")
        );
        assert!(Arc::ptr_eq(
            lineage
                .tip
                .as_ref()
                .unwrap_or_else(|| panic!("actual canonical extension must retain its tip")),
            &tip
        ));
    }
}
