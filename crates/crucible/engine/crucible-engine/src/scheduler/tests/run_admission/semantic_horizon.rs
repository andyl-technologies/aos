//! Same-source semantic authorization and conservative physical-wave bounds.

use super::*;

fn topology_scheduler(exact: ExactLocalEvent, inputs: Vec<ScheduledEvent>) -> SingleScheduler {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "semantic-horizon-topology",
        64,
        SimInstant { ticks: 64 },
        vec![
            test_scenario_node(
                "a",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                exact,
            ),
            runnable("b"),
        ],
        inputs,
    )
    .with_effective_topology_edges(vec![SchedulerLookaheadEdge::new(
        scheduler_node("b", SchedulingNodeKind::Vm),
        scheduler_node("a", SchedulingNodeKind::Vm),
        SimDuration { ticks: 6 },
    )]);
    SingleScheduler::new(scenario).expect("actual topology installs its moving lookahead")
}

fn horizon(scheduler: &SingleScheduler) -> (u64, u64) {
    let prepared = prepare(scheduler);
    let run = prepared
        .runs
        .iter()
        .find(|run| run.plan.node.node.name == "a")
        .expect("conservative PICK selects the bound consumer");
    (
        run.admission.dispatch_horizon().icount.retired,
        run.admission.semantic_horizon().icount.retired,
    )
}

#[test]
fn only_moving_topology_lookahead_is_physical_only() {
    let scheduler = topology_scheduler(ExactLocalEvent::NoArmedTimer, Vec::new());
    assert_eq!(horizon(&scheduler), (6, 64));

    let fixed = test_scheduler(
        vec![test_scenario_node(
            "a",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Finite(SimDuration { ticks: 6 }),
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    );
    assert_eq!(horizon(&fixed), (6, 6));
}

#[test]
fn internal_cap_horizon_cannot_publish_a_semantic_step() {
    let scheduler = topology_scheduler(ExactLocalEvent::NoArmedTimer, Vec::new());
    let prepared = prepare(&scheduler);
    let configuration = scheduler.configuration().clone();
    let offset = scheduler.event_log_offset();
    let completed = prepared
        .runs
        .iter()
        .map(|run| {
            ConcurrentBackendRunResult::Completed(ConcurrentBackendRunOutcome {
                node: run.admission.node().clone(),
                step: StepObservation::from_advance_outcome(
                    VirtualTime {
                        ticks: run.plan.target_counter,
                    },
                    crate::AdvanceOutcome::ReachedHorizon,
                ),
                rng_evidence: Vec::new(),
                network_outputs: Vec::new(),
                observations: Vec::new(),
            })
        })
        .collect();
    let mut actor = BackendQuantumLoop::new(scheduler, MockSimulationBackend::new());

    assert!(
        actor
            .complete_prepared_host_run_set(prepared, completed)
            .is_err()
    );
    assert_eq!(actor.loop_impl().configuration(), &configuration);
    assert_eq!(actor.loop_impl().event_log_offset(), offset);
    assert!(
        actor
            .loop_impl()
            .nodes
            .iter()
            .all(|node| node.counter.ticks == 0)
    );
}

#[test]
fn known_input_and_exact_local_timer_remain_hard_semantic_bounds() {
    let input = event(
        30,
        &scheduler_node("a", SchedulingNodeKind::Vm),
        &scheduler_node("network", SchedulingNodeKind::Network),
        0,
        b"known",
    );
    let scheduler = topology_scheduler(ExactLocalEvent::NoArmedTimer, vec![input]);
    assert_eq!(horizon(&scheduler), (6, 30));

    let timer = topology_scheduler(
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { ticks: 20 },
        },
        Vec::new(),
    );
    assert_eq!(horizon(&timer), (6, 20));
}

#[test]
fn original_command_and_actor_frontiers_remain_hard_semantic_bounds() {
    let mut scheduler = topology_scheduler(ExactLocalEvent::NoArmedTimer, Vec::new());
    scheduler.preemption_requests.push(PreemptionDecision {
        node: NodeId {
            name: String::from("a"),
        },
        at: SimInstant { ticks: 20 },
        kind: PreemptionKind::VcpuSwitch {
            from_vcpu: VcpuId { index: 0 },
            to_vcpu: VcpuId { index: 1 },
        },
    });
    assert_eq!(horizon(&scheduler), (6, 20));

    let mut scheduler = topology_scheduler(ExactLocalEvent::NoArmedTimer, Vec::new());
    scheduler
        .set_trigger_wakeup(Some(VirtualTime { ticks: 30 }), None)
        .expect("actual trigger deadline");
    scheduler
        .set_branch_frontier_cap(VirtualTime { ticks: 25 })
        .expect("actual branch frontier");
    scheduler
        .set_attempt_stop_frontier(Some(VirtualTime { ticks: 20 }))
        .expect("actual attempt frontier");
    assert_eq!(horizon(&scheduler), (6, 20));
    scheduler
        .set_attempt_stop_frontier(None)
        .expect("actual attempt scope ends");
    assert_eq!(horizon(&scheduler), (6, 25));
    scheduler.clear_branch_frontier_cap();
    assert_eq!(horizon(&scheduler), (6, 30));
}
