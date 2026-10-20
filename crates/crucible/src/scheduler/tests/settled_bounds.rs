//! Bounded RUN ceilings and settled scheduler time (RFC-0010 SCHED-12).
//!
//! A node may stop below its ceiling while it is settled through that
//! ceiling. These tests pin how the scheduler keeps the two clocks apart:
//! rendezvous, caps, batching and representability read settled time, while
//! runnable lookahead producers and the backend-facing RUN start read the
//! actual clock.

use super::*;

const LATENCY: u64 = 30;

fn bounded_pair(rendezvous: Option<u64>) -> SingleScheduler {
    let nodes = ["a", "b"]
        .into_iter()
        .map(|name| {
            test_scenario_node(
                name,
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            )
        })
        .collect();
    let edges = [("a", "b"), ("b", "a")]
        .into_iter()
        .map(|(from, to)| {
            SchedulerLookaheadEdge::new(
                scheduler_node(from, SchedulingNodeKind::Vm),
                scheduler_node(to, SchedulingNodeKind::Vm),
                SimDuration { ticks: LATENCY },
            )
        })
        .collect();
    let mut scenario = SchedulerLivenessScenario::from_canonical_material(
        "settled-bounds",
        64,
        SimInstant { ticks: 1_000 },
        nodes,
        Vec::new(),
    )
    .with_effective_topology_edges(edges);
    if let Some(interval) = rendezvous {
        scenario = scenario
            .with_rendezvous_interval(SimDuration { ticks: interval })
            .unwrap_or_else(|error| panic!("rendezvous interval: {error}"));
    }
    SingleScheduler::new(scenario).unwrap_or_else(|error| panic!("settled fixture: {error}"))
}

/// Places `node` at actual clock `counter`, settled through `settled`.
fn place(scheduler: &mut SingleScheduler, node: &str, counter: u64, settled: u64, idle: bool) {
    let runtime = scheduler
        .nodes
        .iter_mut()
        .find(|runtime| runtime.id.node.name == node)
        .unwrap_or_else(|| panic!("fixture node `{node}`"));
    runtime.counter = NodeCounter { ticks: counter };
    runtime.settled = NodeCounter { ticks: settled };
    runtime.idle_parked = idle;
}

fn refresh_frontier(scheduler: &mut SingleScheduler) {
    scheduler.frontier = frontier_for(&scheduler.nodes, Some(scheduler.frontier))
        .unwrap_or_else(|error| panic!("fixture frontier: {error}"));
}

fn bounded_request(scheduler: &SingleScheduler) -> QuantumRequest {
    QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    }
}

#[test]
fn frontier_is_the_minimum_settled_time_not_the_minimum_clock() {
    let mut scheduler = bounded_pair(None);
    place(&mut scheduler, "a", 61, 100, false);
    place(&mut scheduler, "b", 99, 120, false);
    refresh_frontier(&mut scheduler);

    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 100 });
}

#[test]
fn rendezvous_is_satisfied_by_settlement_and_records_the_actual_clock() {
    let mut scheduler = bounded_pair(Some(100));
    place(&mut scheduler, "a", 61, 100, false);
    place(&mut scheduler, "b", 100, 100, false);
    refresh_frontier(&mut scheduler);

    scheduler
        .record_rendezvous(
            SchedulerRendezvousPurpose::AssertionDrain,
            SimInstant { ticks: 100 },
        )
        .unwrap_or_else(|error| panic!("settled rendezvous: {error}"));
    let record = scheduler
        .rendezvous_records()
        .iter()
        .next_back()
        .unwrap_or_else(|| panic!("recorded rendezvous"))
        .clone();
    let clocks = record
        .nodes
        .iter()
        .map(|node| (node.node.node.name.as_str(), node.virtual_time.ticks))
        .collect::<Vec<_>>();
    assert_eq!(clocks, vec![("a", 61), ("b", 100)]);

    place(&mut scheduler, "a", 61, 99, false);
    let error = scheduler
        .record_rendezvous(
            SchedulerRendezvousPurpose::AssertionDrain,
            SimInstant { ticks: 100 },
        )
        .expect_err("a node settled short of the rendezvous must refuse");
    assert!(error.to_string().contains("settled=99"), "{error}");
}

#[test]
fn rendezvous_caps_advance_from_settled_time_when_clocks_stop_short() {
    let mut scheduler = bounded_pair(Some(100));
    place(&mut scheduler, "a", 61, 100, false);
    place(&mut scheduler, "b", 99, 100, false);
    refresh_frontier(&mut scheduler);

    // Reissuing the reached rendezvous would never let a short clock progress.
    assert_eq!(
        scheduler
            .shared_rendezvous_cap()
            .unwrap_or_else(|error| panic!("cap: {error}")),
        Some(SimInstant { ticks: 200 })
    );
}

#[test]
fn representable_advance_must_exceed_settled_time() {
    let mut scheduler = bounded_pair(None);
    place(&mut scheduler, "a", 40, 100, false);
    let key = scheduler
        .node_timeline_key(&scheduler.nodes[0], 0)
        .unwrap_or_else(|error| panic!("key: {error}"));
    let candidate = |ticks| AdvanceCandidate {
        index: 0,
        key: key.clone(),
        target_time: SimInstant { ticks },
        quiescent_horizon: None,
        conservative_dependency: None,
        icount_rounding: SchedulerIcountRounding::ConservativeFloor,
    };

    assert!(
        !scheduler
            .candidate_has_representable_advance(&candidate(90))
            .unwrap_or_else(|error| panic!("projection: {error}"))
    );
    assert!(
        !scheduler
            .candidate_has_representable_advance(&candidate(100))
            .unwrap_or_else(|error| panic!("projection: {error}"))
    );
    assert!(
        scheduler
            .candidate_has_representable_advance(&candidate(101))
            .unwrap_or_else(|error| panic!("projection: {error}"))
    );
}

#[test]
fn idle_parked_producers_lend_their_settled_ceiling_to_strict_lookahead() {
    // Each node parked idle at clock 0 and settled through 100. Lookahead
    // from the parked clocks would bound both below their settled time.
    let mut scheduler = bounded_pair(None);
    place(&mut scheduler, "a", 0, 100, true);
    place(&mut scheduler, "b", 0, 100, true);
    refresh_frontier(&mut scheduler);

    let prepared = scheduler
        .prepare_host_concurrent_quantum_for_contract(
            bounded_request(&scheduler),
            usize::MAX,
            crate::BackendDispatchContract::BoundedControl,
        )
        .unwrap_or_else(|error| panic!("idle peers must not deadlock: {error}"));
    let ceilings = prepared
        .runs
        .iter()
        .map(|run| {
            (
                run.plan.node.node.name.as_str(),
                run.plan.before.ticks,
                run.plan.ceiling.max_advance_icount,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(ceilings, vec![("a", 0, 129), ("b", 0, 129)]);
}

#[test]
fn runnable_producers_hold_strict_lookahead_to_their_actual_clock() {
    let first_ceiling = |producer_idle: bool| {
        let mut scheduler = bounded_pair(None);
        place(&mut scheduler, "a", 90, 100, producer_idle);
        place(&mut scheduler, "b", 95, 100, false);
        refresh_frontier(&mut scheduler);
        let prepared = scheduler
            .prepare_host_concurrent_quantum_for_contract(
                bounded_request(&scheduler),
                usize::MAX,
                crate::BackendDispatchContract::BoundedControl,
            )
            .unwrap_or_else(|error| panic!("strict bounded preparation: {error}"));
        prepared
            .runs
            .iter()
            .map(|run| {
                (
                    run.plan.node.node.name.clone(),
                    run.plan.ceiling.max_advance_icount,
                )
            })
            .collect::<Vec<_>>()
    };

    // `b` stops strictly before runnable `a`'s actual clock plus the latency;
    // `a`'s settled ceiling does not widen that bound.
    assert_eq!(first_ceiling(false), vec![(String::from("b"), 119)]);
    // Once `a` is parked idle, its settled ceiling bounds its next output:
    // `b` may run to 129, so `a`'s own strict 124 becomes the first RUN.
    assert_eq!(first_ceiling(true), vec![(String::from("a"), 124)]);
}

fn prepared_single_run(scheduler: &SingleScheduler) -> (SingleScheduler, PreparedHostRun) {
    let prepared = scheduler
        .prepare_host_concurrent_quantum_for_contract(
            bounded_request(scheduler),
            1,
            crate::BackendDispatchContract::BoundedControl,
        )
        .unwrap_or_else(|error| panic!("bounded preparation: {error}"));
    let mut runs = prepared.runs;
    assert_eq!(runs.len(), 1);
    (prepared.next, runs.remove(0))
}

#[test]
fn settled_commit_keeps_its_ceiling_and_adopts_the_actual_clock() {
    let scheduler = bounded_pair(None);
    let (mut next, run) = prepared_single_run(&scheduler);
    let index = run.plan.index;
    let ceiling = run.plan.ceiling.max_advance_icount;
    assert_eq!(ceiling, LATENCY - 1);

    next.commit_prepared_host_run(
        run,
        HostRunReport {
            reached: ceiling - 13,
            settled_through: ceiling,
            idle_parked: false,
        },
        &[],
        Vec::new(),
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("settled commit: {error}"));

    assert_eq!(
        next.nodes[index].counter,
        NodeCounter {
            ticks: ceiling - 13
        }
    );
    assert_eq!(next.nodes[index].settled, NodeCounter { ticks: ceiling });
    let advance = next
        .last_advance
        .clone()
        .unwrap_or_else(|| panic!("committed advance"));
    assert_eq!(
        advance.after,
        NodeCounter {
            ticks: ceiling - 13
        }
    );
    assert_eq!(advance.settled_after, NodeCounter { ticks: ceiling });
}

#[test]
fn commit_refuses_partial_settlement() {
    let scheduler = bounded_pair(None);
    let (mut next, run) = prepared_single_run(&scheduler);
    let ceiling = run.plan.ceiling.max_advance_icount;

    let error = next
        .commit_prepared_host_run(
            run,
            HostRunReport {
                reached: ceiling - 13,
                settled_through: ceiling - 1,
                idle_parked: false,
            },
            &[],
            Vec::new(),
            Vec::new(),
        )
        .expect_err("settlement must cover the stop or the whole ceiling");
    assert!(error.to_string().contains("settled through"), "{error}");
}

#[test]
fn settled_gap_refuses_a_skipped_native_deadline() {
    let mut scheduler = bounded_pair(None);
    scheduler.nodes[0].vcpu_idle_states = vec![SchedulerVcpuIdleState {
        vcpu: VcpuId { index: 0 },
        halted: false,
        next_deadline: Some(SimInstant { ticks: 20 }),
        pending_input: false,
    }];
    let (mut next, run) = prepared_single_run(&scheduler);
    assert_eq!(run.plan.index, 0);
    let ceiling = run.plan.ceiling.max_advance_icount;
    assert_eq!(ceiling, 20);

    let error = next
        .commit_prepared_host_run(
            run,
            HostRunReport {
                reached: 15,
                settled_through: ceiling,
                idle_parked: false,
            },
            &[],
            Vec::new(),
            Vec::new(),
        )
        .expect_err("an exact native deadline inside the gap must refuse");
    assert!(
        error.to_string().contains("skipped native deadline 20"),
        "{error}"
    );
}
