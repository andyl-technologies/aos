//! Checks that a guest choice is offered at a deterministic per-node cut.
//!
//! Nodes run on their own clocks to different horizons. The offered cut is
//! the per-node clock vector, the offered configuration, and the event-log
//! prefix at the publication break. It must not depend on the host worker
//! count, and re-executing the same log reaches the same cut and the same
//! post-settlement history.

use super::*;

/// Per-node clocks at the offered cut, in canonical node order.
type CutVector = Vec<(String, u64)>;

/// Everything observable about an offered choice.
#[derive(Debug, PartialEq)]
struct OfferedCut {
    source: NodeId,
    pause: u64,
    clocks: CutVector,
    configuration: Configuration,
    log_offset: EventLogOffset,
    log: Vec<SchedulerEventLogEntry>,
}

const SOURCE_PAUSE: u64 = 30;
const LINK_LATENCY: u64 = 10;

/// A coupled source/peer pair and a disconnected node, with a
/// guest-selectable stop on the source after several quanta.
///
/// The pair bound each other at the other's clock plus the link latency; the
/// disconnected node has no inbound edge and runs to the scenario limit.
fn skewed_adapter() -> Adapter {
    let nodes = vec![
        test_scenario_node(
            "a-source",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        ),
        test_scenario_node(
            "m-peer",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        ),
        test_scenario_node(
            "z-free",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        ),
    ];
    let mut backend = GuestStopBackend::new(&[(
        "a-source",
        SOURCE_PAUSE,
        BackendPhysicalStop::GuestSelectable,
    )]);
    // Control 3 completes every physical ceiling, as the QEMU contract does.
    backend.base.control_v3 = true;
    let mut scheduler = test_scheduler(nodes, Vec::new());
    let edge = |from: &str, to: &str| {
        SchedulerLookaheadEdge::new(
            scheduler_node(from, SchedulingNodeKind::Vm),
            scheduler_node(to, SchedulingNodeKind::Vm),
            SimDuration {
                ticks: LINK_LATENCY,
            },
        )
    };
    scheduler.effective_topology = SchedulerLookaheadGraph::from_edges(vec![
        edge("a-source", "m-peer"),
        edge("m-peer", "a-source"),
    ]);
    BackendQuantumLoop::new(scheduler, backend)
}

fn drive_with(adapter: &mut Adapter, workers: usize) {
    let configuration = adapter.loop_impl().configuration().clone();
    adapter
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            workers,
        )
        .unwrap_or_else(|error| panic!("{workers}-worker quantum should drive: {error}"));
}

fn clocks(adapter: &Adapter) -> CutVector {
    adapter
        .loop_impl()
        .nodes
        .iter()
        .map(|node| (node.id.node.name.clone(), node.counter.ticks))
        .collect()
}

fn log(adapter: &Adapter) -> Vec<SchedulerEventLogEntry> {
    adapter
        .loop_impl()
        .event_log()
        .retained_entries()
        .iter()
        .cloned()
        .collect()
}

/// Drives until the source's choice is offered and records the cut.
fn drive_to_offer(adapter: &mut Adapter, workers: usize) -> (HeldHostStopWitness, OfferedCut) {
    // The source pauses at tick 30 with a 10-tick lookahead, so the offer
    // arrives within a few quanta; the bound only turns a regression into a
    // failure instead of a hang.
    for _ in 0..16 {
        if let Some(witness) = adapter.held_host_stop_witness() {
            // Validation proves the live prefix is the witness's offered one.
            adapter
                .validate_held_host_stop(&witness)
                .unwrap_or_else(|error| panic!("offer should match its prefix: {error}"));
            let cut = OfferedCut {
                source: witness.node().clone(),
                pause: witness.physical_pause().ticks,
                clocks: clocks(adapter),
                configuration: adapter.loop_impl().configuration().clone(),
                log_offset: adapter.loop_impl().event_log_offset(),
                log: log(adapter),
            };
            return (witness, cut);
        }
        drive_with(adapter, workers);
    }
    panic!("{workers}-worker attempt never offered the source choice");
}

/// Releases the offered choice and drives the world to the scenario limit.
fn settle_and_finish(adapter: &mut Adapter, witness: &HeldHostStopWitness, workers: usize) {
    adapter
        .settle_held_host_stop(witness, |_, backend, _| backend.release(witness))
        .unwrap_or_else(|error| panic!("offered choice should settle: {error}"));
    while !adapter
        .loop_impl()
        .reached_time_limit()
        .unwrap_or_else(|error| panic!("terminal state should be inspectable: {error}"))
    {
        drive_with(adapter, workers);
    }
}

#[test]
fn a_choice_is_offered_at_the_same_cut_for_every_worker_count() {
    let (_, serialized) = drive_to_offer(&mut skewed_adapter(), 1);

    for workers in [2, 3] {
        let (_, parallel) = drive_to_offer(&mut skewed_adapter(), workers);
        assert_eq!(parallel, serialized, "{workers} workers moved the cut");
    }

    assert_eq!(serialized.source.name, "a-source");
    assert_eq!(serialized.pause, SOURCE_PAUSE);
    // The cut is the published world prefix at the offer, not the physical
    // positions of the VMs. The source stands at its pause. The coupled peer
    // has published its RUN through 27, the last settled endpoint at or
    // before the pause; its RUN to 36 stays held until the choice settles.
    // The disconnected node ran to the limit in the first wave, and that whole
    // RUN is held, so the cut still shows it at 0. Nothing beyond the pause is
    // published, so the choice cannot observe any later event.
    assert_eq!(
        serialized.clocks,
        vec![
            (String::from("a-source"), SOURCE_PAUSE),
            (String::from("m-peer"), 27),
            (String::from("z-free"), 0),
        ]
    );
}

#[test]
fn re_executing_the_log_reproduces_the_cut_and_the_settled_history() {
    let mut original = skewed_adapter();
    let (original_witness, original_cut) = drive_to_offer(&mut original, 3);
    settle_and_finish(&mut original, &original_witness, 3);

    // Replay from the same scenario with a different worker count: it must
    // reach the identical offered cut and, after the same selection, the
    // identical history and per-node clocks.
    let mut replay = skewed_adapter();
    let (replay_witness, replay_cut) = drive_to_offer(&mut replay, 1);
    assert_eq!(replay_cut, original_cut);
    assert_eq!(
        replay_cut.log[..],
        log(&original)[..replay_cut.log.len()],
        "the offered prefix must be a prefix of the settled history"
    );

    settle_and_finish(&mut replay, &replay_witness, 1);
    assert_eq!(log(&replay), log(&original));
    assert_eq!(clocks(&replay), clocks(&original));
    assert_eq!(
        replay.loop_impl().configuration(),
        original.loop_impl().configuration()
    );
}
