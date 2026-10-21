//! Physical replay of recorded preemptions on a rebased-ready-point VM, and
//! model-only decisions that must leave a halted thin node in place.

use super::*;

use crucible::{
    ExactLocalEvent, NetworkLookahead, NodeCounter, QuantumLoop, QuantumRequest,
    SchedulerEventLogPayload, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerScenarioNode, SchedulingNodeKind, SimInstant, SingleScheduler,
};

/// Physical counter at which the VM's ready point anchors scheduler time zero.
const READY_COUNTER: u64 = 1_000;

/// Scheduler time of the explorer preemption, before the ready-point offset.
const PREEMPTION_TIME: u64 = 5;

/// Live scheduler evidence for one recorded preemption on the replayed VM.
struct RecordedPreemption {
    world: World,
    node: NodeId,
    scheduler: SingleScheduler,
}

/// Drives a live scheduler until it records an `InterruptAt` preemption.
///
/// The preemption request names the physical counter, as the explorer does;
/// the scheduler projects it to scheduler time through the VM's mapping.
fn recorded_rebased_preemption() -> Result<RecordedPreemption, Box<dyn std::error::Error>> {
    let node = NodeId {
        name: String::from("receiver"),
    };
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("guarded replay preemption"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount {
                retired: READY_COUNTER,
            },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let scheduler_node = SchedulerNodeId {
        node: node.clone(),
        kind: SchedulingNodeKind::Vm,
    };
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "replay-rebased-preemption",
        16,
        SimInstant { ticks: 16 },
        vec![SchedulerScenarioNode {
            id: scheduler_node.clone(),
            counter: NodeCounter {
                ticks: READY_COUNTER,
            },
            activity: SchedulerNodeActivity::Runnable,
            network_lookahead: NetworkLookahead::Infinite,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    )
    .with_ready_point_counter(
        scheduler_node,
        NodeCounter {
            ticks: READY_COUNTER,
        },
    )
    .with_preemption_request(PreemptionDecision {
        node: node.clone(),
        at: SimInstant {
            ticks: READY_COUNTER + PREEMPTION_TIME,
        },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 32 },
        },
    })
    .with_world(&world);
    let mut scheduler = SingleScheduler::new(scenario)?;

    for _ in 0..16 {
        if scheduler
            .configuration()
            .schedule
            .decision_history()
            .iter()
            .any(|decision| matches!(decision, Decision::Preemption(_)))
        {
            return Ok(RecordedPreemption {
                world,
                node,
                scheduler,
            });
        }
        scheduler.drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })?;
    }
    Err("scheduler did not record the preemption".into())
}

/// Replays the recorded steps on a scripted thin node from its ready point.
fn replay_recorded_steps(
    recorded: &RecordedPreemption,
    halted: bool,
) -> Result<(ScriptedPhysicalReplay, Icount), Box<dyn std::error::Error>> {
    let checkpoint = recorded.scheduler.checkpoint()?;
    let segments = recorded.scheduler.event_log_segment_store();
    let configuration = recorded.scheduler.configuration();
    let steps = authenticated_replay_steps(
        &recorded.world,
        configuration,
        &checkpoint,
        segments.as_ref(),
        1,
        &recorded.node,
        0,
    )?;

    let mut replay = empty_physical_replay();
    replay.node = recorded.node.clone();
    replay.preemption.halted = halted;
    let target = Icount { retired: 1_000_000 };
    let mut state = Icount {
        retired: READY_COUNTER,
    };
    for step in steps {
        let ReplayStep::Decision { index } = step else {
            return Err("scenario recorded an unexpected input".into());
        };
        let decision = &configuration.schedule.decision_history()[index];
        state = replay_one_nonselection_decision_boundary(&mut replay, state, target, decision)?;
    }
    Ok((replay, state))
}

#[test]
fn recorded_interrupt_at_replays_physically_at_its_rebased_counter()
-> Result<(), Box<dyn std::error::Error>> {
    let recorded = recorded_rebased_preemption()?;
    let preemption_counter = Icount {
        retired: READY_COUNTER + PREEMPTION_TIME,
    };

    // The log places the decision at scheduler time; its own counter is
    // physical. Only the counter names where the live guest was preempted.
    let segments = recorded.scheduler.event_log_segment_store();
    let entry = recorded
        .scheduler
        .checkpoint()?
        .event_log_entries(segments.as_ref())
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|entry| {
            matches!(
                entry.payload(),
                SchedulerEventLogPayload::Decision(Decision::Preemption(_))
            )
        })
        .ok_or("preemption decision entry is absent")?;
    assert_eq!(entry.at().ticks, PREEMPTION_TIME);

    // A halted guest's clock moves to the commanded counter. A running guest
    // takes the command at its first boundary at or after it, never by a
    // time-only advance; the counter lies 5 ticks past its ready boundary.
    let first_boundary = Icount {
        retired: READY_COUNTER + crucible::SIM_TICKS_PER_INSTRUCTION,
    };
    let window_end = Icount {
        retired: preemption_counter.retired + crucible::SIM_TICKS_PER_INSTRUCTION - 1,
    };
    for (halted, taken) in [(false, first_boundary), (true, preemption_counter)] {
        let (replay, state) = replay_recorded_steps(&recorded, halted)?;

        assert_eq!(state, taken, "halted={halted}");
        assert_eq!(replay.preemption.applied, vec![taken], "halted={halted}");
        assert!(
            replay.advances.iter().all(|ceiling| *ceiling <= window_end),
            "halted={halted}: {:?}",
            replay.advances
        );
    }
    Ok(())
}

#[test]
fn a_running_replay_that_cannot_reach_the_preemption_boundary_refuses() {
    // The checkpoint target ends inside the window, below the running
    // guest's first boundary after the command, so the preemption cannot be
    // taken where the live guest took it.
    let mut replay = empty_physical_replay();
    let state = Icount { retired: 2_000 };
    let decision = PreemptionDecision {
        node: replay.node.clone(),
        at: SimInstant { ticks: 2_010 },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 32 },
        },
    };

    let result = replay_one_nonselection_decision_boundary(
        &mut replay,
        state,
        Icount { retired: 2_030 },
        &Decision::Preemption(decision),
    );

    assert!(result.is_err(), "{result:?}");
    assert!(replay.preemption.applied.is_empty());
    assert!(
        replay
            .advances
            .iter()
            .all(|ceiling| ceiling.retired <= 2_030)
    );
}

#[test]
fn recorded_preemption_at_the_thin_counter_refuses_with_a_typed_decline() {
    let mut replay = empty_physical_replay();
    let at = Icount { retired: 2_000 };
    let decision = PreemptionDecision {
        node: replay.node.clone(),
        at: SimInstant { ticks: at.retired },
        kind: PreemptionKind::VcpuSwitch {
            from_vcpu: VcpuId { index: 0 },
            to_vcpu: VcpuId { index: 1 },
        },
    };

    let result = replay_one_nonselection_decision_boundary(
        &mut replay,
        at,
        Icount { retired: 1_000_000 },
        &Decision::Preemption(decision),
    );

    assert!(matches!(
        result,
        Err(QemuVmRealizationError::ReplayOracleUnsupported {
            effect: QemuReplayOracleUnsupportedEffect::PreemptionNotAhead {
                at: 2_000,
                current: 2_000,
            },
            ..
        })
    ));
    assert!(replay.advances.is_empty());
}

#[test]
fn model_only_decisions_leave_a_halted_thin_node_in_place() -> Result<(), Box<dyn std::error::Error>>
{
    // A halted guest settles below every ceiling without moving its clock.
    // The removed one-instruction hop refused this node as "paused before
    // its one-instruction boundary"; model-only decisions need no motion.
    let mut replay = empty_physical_replay();
    replay.preemption.halted = true;
    let parked = Icount { retired: 1_000 };
    let target = Icount { retired: 1_000_000 };
    let foreign_preemption = Decision::Preemption(PreemptionDecision {
        node: NodeId {
            name: String::from("other-node"),
        },
        at: crucible::SimInstant { ticks: 2_000 },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 32 },
        },
    });
    let rng = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("halted-model-only"),
        value: 3,
    });

    let state = replay_one_nonselection_decision_boundary(&mut replay, parked, target, &rng)?;
    let state =
        replay_one_nonselection_decision_boundary(&mut replay, state, target, &foreign_preemption)?;

    assert_eq!(state, parked);
    assert!(replay.advances.is_empty());
    assert!(replay.preemption.applied.is_empty());
    Ok(())
}
