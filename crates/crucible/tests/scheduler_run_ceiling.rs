//! Checks the T-SCHED-14 RUN max-advance ceiling publication.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulingNodeKind, Shift, SimDuration, SimInstant, SingleScheduler, VirtualTime,
};

#[cfg(feature = "test-double")]
use crucible_shmem::{
    FrameEntry, KIND_VM, NodeSlot, PendingInputPublication, RegionAllocation, RegionConfig,
    SLOT_NET_ROUTER,
};

#[test]
fn run_publishes_one_max_advance_ceiling_for_selected_node() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "run-ceiling-single-publication",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(10),
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 4 },
            },
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(scheduler_node("runner")));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 4 });
    assert_eq!(scheduler.run_ceiling_publications().len(), 1);
    let publication = &scheduler.run_ceiling_publications()[0];
    assert_eq!(publication.sequence, 0);
    assert_eq!(publication.quantum, 0);
    assert_eq!(publication.node, scheduler_node("runner"));
    assert_eq!(publication.current_icount, NodeCounter { ticks: 0 });
    assert_eq!(publication.max_advance_icount, 4);
    assert_eq!(publication.target_time, SimInstant { nanos: 4 });
}

#[test]
fn each_run_gets_one_ceiling_and_no_intermediate_publication() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "run-ceiling-one-per-run",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![
            scenario_node(
                "node-a",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(3),
                ExactLocalEvent::NoArmedTimer,
            ),
            scenario_node(
                "node-b",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(5),
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        Vec::new(),
    ))
    .expect("scenario should build");

    let first = drive_one_quantum(&mut scheduler);
    let second = drive_one_quantum(&mut scheduler);

    assert_eq!(first.advanced_node, Some(scheduler_node("node-a")));
    assert_eq!(second.advanced_node, Some(scheduler_node("node-b")));
    assert_eq!(scheduler.run_ceiling_publications().len(), 2);
    assert_eq!(scheduler.run_ceiling_publications()[0].sequence, 0);
    assert_eq!(scheduler.run_ceiling_publications()[0].quantum, 0);
    assert_eq!(
        scheduler.run_ceiling_publications()[0].max_advance_icount,
        3
    );
    assert_eq!(scheduler.run_ceiling_publications()[1].sequence, 1);
    assert_eq!(scheduler.run_ceiling_publications()[1].quantum, 1);
    assert_eq!(
        scheduler.run_ceiling_publications()[1].max_advance_icount,
        5
    );
}

#[test]
fn control_only_quantum_publishes_no_run_ceiling() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "run-ceiling-control-only",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "idle",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("empty quantum should drive");

    assert_eq!(outcome.advanced_node, None);
    assert!(scheduler.run_ceiling_publications().is_empty());
}

#[test]
fn run_consumes_the_published_ceiling_as_its_target() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "run-ceiling-consumed-target",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "runner",
            2,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(7),
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);
    let publication = &scheduler.run_ceiling_publications()[0];

    assert_eq!(publication.current_icount, NodeCounter { ticks: 2 });
    assert_eq!(publication.max_advance_icount, 9);
    assert_eq!(
        outcome.frontier,
        VirtualTime {
            ticks: publication.max_advance_icount,
        }
    );
}

#[test]
#[cfg(feature = "test-double")]
fn published_ceiling_converts_to_and_publishes_through_shmem_abi() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "run-ceiling-shmem-abi",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(6),
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    ))
    .expect("scenario should build");
    let _outcome = drive_one_quantum(&mut scheduler);
    let publication = &scheduler.run_ceiling_publications()[0];
    let ceiling = publication
        .to_shmem_ceiling()
        .expect("publication should authorize as a shmem ceiling");
    let slot = NodeSlot::new(KIND_VM);

    slot.publish_scheduler_ceiling(ceiling)
        .expect("slot should accept the scheduler ceiling");

    assert_eq!(slot.load_node_ceiling(), publication.max_advance_icount);
}

#[test]
#[cfg(feature = "test-double")]
fn published_ceiling_writes_pending_inputs_before_futex_wake() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "run-ceiling-shmem-input-before-wake",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(6),
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    ))
    .expect("scenario should build");
    let _outcome = drive_one_quantum(&mut scheduler);
    let publication = &scheduler.run_ceiling_publications()[0];
    let mut region =
        RegionAllocation::new_model(RegionConfig::new(1, 2, 0)).expect("region model should build");
    let dst_slot = 0;
    let src_slot = SLOT_NET_ROUTER as u32;
    let input = frame(6, src_slot, 1, b"ready");
    let pending = [PendingInputPublication::new(src_slot, input.clone())];

    let handoff = publication
        .publish_to_shmem_after_inputs(&mut region, dst_slot, &pending)
        .expect("publication should hand off inputs before waking");

    assert_eq!(handoff.pending_input_count, 1);
    assert_eq!(handoff.max_advance_icount, publication.max_advance_icount);
    assert_eq!(
        region.peek_directed_frame(src_slot, dst_slot),
        Ok(Some(input.clone()))
    );
    let snapshot = region
        .node_slot(dst_slot)
        .expect("VM slot should exist")
        .snapshot();
    assert_eq!(snapshot.max_advance_icount, publication.max_advance_icount);
    assert_eq!(snapshot.wake_signal, 1);
}

fn drive_one_quantum(scheduler: &mut SingleScheduler) -> crucible::QuantumOutcome {
    scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("scheduler should drive one quantum")
}

fn scenario_node(
    name: &str,
    counter: u64,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead,
        exact_local_event,
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}

#[cfg(feature = "test-double")]
fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    FrameEntry::new(delivery_icount, src_node, seq, payload).expect("test frame should be valid")
}
