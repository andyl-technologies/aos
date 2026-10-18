//! Genuine scheduler replanning with modeled physical boundary observations.
//!
//! Real PICK, queue RESOLVE, cap publication and STEP are exercised here. The
//! coordinate supplied to the private actor seam models the backend receipt;
//! these tests establish no native stop, consumption or execution authority.

use super::*;

fn prepared_late_input_run() -> (SingleScheduler, PreparedHostRun) {
    prepared_late_input_run_with_command(None)
}

fn prepared_late_input_run_with_command(
    command_at: Option<u64>,
) -> (SingleScheduler, PreparedHostRun) {
    let node = test_scenario_node(
        "a",
        0,
        SchedulerNodeActivity::Runnable,
        NetworkLookahead::Infinite,
        ExactLocalEvent::NoArmedTimer,
    );
    let mut scheduler = test_scheduler(vec![node], Vec::new());
    if let Some(at) = command_at {
        scheduler.preemption_requests.push(PreemptionDecision {
            node: NodeId {
                name: String::from("a"),
            },
            at: SimInstant { ticks: at },
            kind: PreemptionKind::VcpuSwitch {
                from_vcpu: VcpuId { index: 0 },
                to_vcpu: VcpuId { index: 1 },
            },
        });
    }
    let mut prepared = scheduler
        .prepare_host_concurrent_quantum_limited(
            QuantumRequest {
                configuration: scheduler.configuration().clone(),
                control: Vec::new(),
            },
            1,
        )
        .expect("real PICK publishes original natural RUN");
    let mut run = prepared.runs.remove(0);
    let mut scheduler = prepared.next;
    let first = if command_at.is_some() { 10 } else { 30 };
    let producer = scheduler_node("network", SchedulingNodeKind::Network);
    scheduler.pending_events.extend([
        event(first, &run.plan.node, &producer, 0, b"first"),
        event(46, &run.plan.node, &producer, 1, b"second"),
    ]);
    scheduler
        .tighten_cap_boundary_admission(&mut run, NodeCounter { ticks: first })
        .expect("fresh actual queue bounds a no-motion physical readmission");
    assert_eq!(
        run.admission.semantic_horizon().icount.retired,
        command_at.unwrap_or(64)
    );
    assert_eq!(run.admission.dispatch_horizon().icount.retired, first);
    (scheduler, run)
}

#[test]
fn original_authorized_preemption_caps_fresh_window_and_is_consumed_once() {
    let (mut scheduler, run) = prepared_late_input_run_with_command(Some(20));
    let command = scheduler.preemption_requests[0].clone();
    let input = resolve_due_scheduled_events(
        &mut scheduler.pending_events,
        &run.plan.node,
        SimInstant { ticks: 10 },
    )
    .expect("real first input resolves before retained command");
    assert_eq!(input.len(), 1);

    let mut refreshed = scheduler
        .refresh_input_boundary_run(&run, NodeCounter { ticks: 10 })
        .expect("fresh planner window respects original command horizon");
    assert_eq!(refreshed.plan.before, NodeCounter { ticks: 0 });
    assert_eq!(refreshed.admission.semantic_horizon().icount.retired, 20);
    assert_eq!(refreshed.admission.dispatch_horizon().icount.retired, 20);
    assert_eq!(
        refreshed.admission.input_inventory().next_input(),
        Some(NodeCounter { ticks: 46 })
    );
    assert_eq!(
        refreshed.admission.control_token(),
        run.admission.control_token()
    );
    assert_eq!(refreshed.admission.context(), run.admission.context());
    assert_eq!(refreshed.preemptions.len(), 1);
    assert_eq!(refreshed.preemptions[0].decision, command);
    assert_eq!(scheduler.preemption_requests, vec![command.clone()]);

    refreshed.staged_input_events = input;
    let outcome = scheduler
        .commit_prepared_host_run(refreshed, 20, &[command], Vec::new(), Vec::new())
        .expect("one actual modeled native acknowledgement commits the command");
    assert_eq!(outcome.resolved_events.len(), 1);
    assert!(scheduler.preemption_requests.is_empty());
    assert_eq!(scheduler.pending_events.len(), 1);
    assert_eq!(scheduler.pending_events[0].key.virtual_time().ticks, 46);
    assert_eq!(
        scheduler.last_advance.as_ref().expect("final STEP").before,
        NodeCounter { ticks: 0 }
    );
}

fn resolve_first_input(scheduler: &mut SingleScheduler, run: &PreparedHostRun) {
    let due = resolve_due_scheduled_events(
        &mut scheduler.pending_events,
        &run.plan.node,
        SimInstant { ticks: 30 },
    )
    .expect("actual pending queue resolves first delivery");
    assert_eq!(due.len(), 1);
}

#[test]
fn fresh_windows_retain_original_owner_and_commit_origin_after_two_inputs() {
    let (mut scheduler, run) = prepared_late_input_run();
    let original = run.admission.clone();
    let configuration = scheduler.configuration.clone();
    let prefix = scheduler.event_log.offset();
    let frontier = scheduler.frontier;
    resolve_first_input(&mut scheduler, &run);

    let refreshed = scheduler
        .refresh_input_boundary_run(&run, NodeCounter { ticks: 30 })
        .expect("actor authorizes next real queue cap");
    assert_eq!(refreshed.admission.dispatch_horizon().icount.retired, 46);
    assert_eq!(
        refreshed.admission.control_token(),
        original.control_token()
    );
    assert_eq!(refreshed.admission.context(), original.context());
    assert_eq!(refreshed.plan.before, NodeCounter { ticks: 0 });
    assert_eq!(
        refreshed.plan.ceiling.current_icount,
        NodeCounter { ticks: 30 }
    );
    assert_eq!(scheduler.nodes[0].counter, NodeCounter { ticks: 0 });
    assert_eq!(scheduler.configuration, configuration);
    assert_eq!(scheduler.event_log.offset(), prefix);
    assert_eq!(scheduler.frontier, frontier);
    assert!(
        refreshed.admission.input_inventory().generation()
            > original.input_inventory().generation()
    );

    let due = resolve_due_scheduled_events(
        &mut scheduler.pending_events,
        &run.plan.node,
        SimInstant { ticks: 46 },
    )
    .expect("actual second delivery resolves separately");
    assert_eq!(due.len(), 1);
    let final_run = scheduler
        .refresh_input_boundary_run(&refreshed, NodeCounter { ticks: 46 })
        .expect("complete real inventory authorizes remaining original horizon");
    assert_eq!(final_run.admission.dispatch_horizon().icount.retired, 64);
    assert_eq!(final_run.admission.semantic_horizon().icount.retired, 64);
    assert_eq!(final_run.admission.context(), original.context());
    assert_eq!(final_run.admission.input_inventory().next_input(), None);
    assert_eq!(scheduler.nodes[0].counter, NodeCounter { ticks: 0 });

    scheduler
        .commit_prepared_host_run(final_run, 64, &[], Vec::new(), Vec::new())
        .expect("only final settled backend observation permits real STEP");
    assert_eq!(
        scheduler
            .last_advance
            .as_ref()
            .expect("STEP emitted")
            .before,
        NodeCounter { ticks: 0 }
    );
    assert_eq!(scheduler.nodes[0].counter, NodeCounter { ticks: 64 });
}

#[test]
fn fresh_branch_cap_tightens_continuation_without_discarding_next_input() {
    let (mut scheduler, run) = prepared_late_input_run();
    resolve_first_input(&mut scheduler, &run);
    scheduler
        .set_branch_frontier_cap(VirtualTime { ticks: 40 })
        .expect("actual current branch bound installs");

    let refreshed = scheduler
        .refresh_input_boundary_run(&run, NodeCounter { ticks: 30 })
        .expect("new physical cap obeys fresh planner branch");
    assert_eq!(refreshed.admission.dispatch_horizon().icount.retired, 40);
    assert_eq!(
        refreshed.admission.input_inventory().next_input(),
        Some(NodeCounter { ticks: 46 })
    );
    assert_eq!(refreshed.admission.semantic_horizon().icount.retired, 64);
    assert_eq!(refreshed.admission.context(), run.admission.context());
}

#[test]
fn unresolved_input_and_reached_mismatch_refuse_before_publication() {
    let (mut scheduler, run) = prepared_late_input_run();
    let publications = scheduler.ceiling_publications.len();
    assert!(
        scheduler
            .refresh_input_boundary_run(&run, NodeCounter { ticks: 30 })
            .is_err()
    );
    assert!(
        scheduler
            .refresh_input_boundary_run(&run, NodeCounter { ticks: 31 })
            .is_err()
    );
    assert_eq!(scheduler.ceiling_publications.len(), publications);
    assert_eq!(scheduler.nodes[0].counter, NodeCounter { ticks: 0 });
}

#[test]
fn changed_prefix_topology_command_and_clock_mapping_refuse_retained_motion() {
    for change in 0..4 {
        let (mut scheduler, run) = prepared_late_input_run();
        resolve_first_input(&mut scheduler, &run);
        match change {
            0 => {
                QuantumLoop::append_backend_observable_events(
                    &mut scheduler,
                    vec![ObservableEvent::console_output(
                        VirtualTime { ticks: 1 },
                        run.plan.node.node.clone(),
                        b"changed-prefix".to_vec(),
                    )],
                )
                .expect("actual event prefix changes");
            }
            1 => scheduler.topology_epoch += 1,
            2 => scheduler.preemption_requests.push(PreemptionDecision {
                node: run.plan.node.node.clone(),
                at: SimInstant { ticks: 60 },
                kind: PreemptionKind::VcpuSwitch {
                    from_vcpu: VcpuId { index: 0 },
                    to_vcpu: VcpuId { index: 1 },
                },
            }),
            _ => {
                scheduler.nodes[0].time_mapping = NodeTimeMapping {
                    anchor_counter: NodeCounter { ticks: 1 },
                    anchor_time: SimInstant::EPOCH,
                }
            }
        }
        let publications = scheduler.ceiling_publications.len();
        let error = scheduler
            .refresh_input_boundary_run(&run, NodeCounter { ticks: 30 })
            .expect_err("changed immutable source cannot authorize another window");
        assert!(error.to_string().contains("immutable context"));
        assert_eq!(scheduler.ceiling_publications.len(), publications);
        assert_eq!(scheduler.nodes[0].counter, NodeCounter { ticks: 0 });
    }
}
