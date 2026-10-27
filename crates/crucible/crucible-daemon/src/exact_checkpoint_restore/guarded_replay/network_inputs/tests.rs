//! Native schedule and input-plan regressions without a QEMU process.

use super::*;

use crucible_engine::{
    Decision, ExactLocalEvent, Icount, IrqVector, LinkDef, NetworkLookahead, NodeCounter,
    NodeTemplate, PreemptionDecision, PreemptionKind, QuantumLoop, QuantumRequest, ReadyPoint,
    ScheduledEvent, ScheduledEventKey, SchedulerLivenessScenario, SchedulerNodeActivity,
    SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, SharedTimelineKey, SimInstant,
    SingleScheduler, VcpuId, WhiteBoxPolicy, WorldNode,
};

fn world_node(name: &str) -> WorldNode {
    WorldNode {
        id: NodeId {
            name: name.to_owned(),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("replay planner {name}"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn scheduler_node(node: &NodeId, activity: SchedulerNodeActivity) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: SchedulerNodeId {
            node: node.clone(),
            kind: SchedulingNodeKind::Vm,
        },
        counter: NodeCounter { ticks: 0 },
        activity,
        network_lookahead: NetworkLookahead::Infinite,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
}

fn input_event(
    receiver: &NodeId,
    producer: &SchedulerNodeId,
    at: u64,
    sequence: u64,
) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::new(
            SharedTimelineKey {
                virtual_time: SimInstant { ticks: at },
                node: SchedulerNodeId {
                    node: receiver.clone(),
                    kind: SchedulingNodeKind::Vm,
                },
                sequence,
            },
            producer.clone(),
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: receiver.clone(),
            payload: vec![u8::try_from(sequence).unwrap_or(0)],
        }),
    }
}

fn resolved_input_entries(
    scheduler: &SingleScheduler,
) -> Result<Vec<crucible_engine::SchedulerEventLogEntry>, Box<dyn std::error::Error>> {
    let segments = scheduler.event_log_segment_store();
    let entries = scheduler
        .checkpoint()?
        .event_log_entries(segments.as_ref())
        .collect::<Result<Vec<_>, _>>()?;

    Ok(entries
        .into_iter()
        .filter(|entry| {
            matches!(
                entry.payload(),
                SchedulerEventLogPayload::ResolvedHappening(ScheduledEvent {
                    payload: ScheduledEventPayload::BackendInput(_),
                    ..
                })
            )
        })
        .collect())
}

fn drive_until_resolved_inputs(
    scheduler: &mut SingleScheduler,
    expected: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..16 {
        scheduler.drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })?;
        if resolved_input_entries(scheduler)?.len() == expected {
            return Ok(());
        }
    }
    Err(format!("scheduler did not resolve {expected} inputs").into())
}

#[test]
fn replay_plan_preserves_input_decision_input_order_and_rejects_wrong_generation_or_count()
-> Result<(), Box<dyn std::error::Error>> {
    let sender = NodeId {
        name: String::from("sender"),
    };
    let receiver = NodeId {
        name: String::from("receiver"),
    };
    let world = World::from_nodes_and_links(
        vec![world_node("sender"), world_node("receiver")],
        vec![LinkDef::new(sender.clone(), receiver.clone())?],
    )?;
    let link = world.links()[0].scheduler_node_id();
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "replay-input-decision-order",
        16,
        SimInstant { ticks: 16 },
        vec![
            scheduler_node(&receiver, SchedulerNodeActivity::Runnable),
            scheduler_node(&sender, SchedulerNodeActivity::Done),
        ],
        vec![
            input_event(&receiver, &link, 1, 0),
            input_event(&receiver, &link, 2, 1),
        ],
    )
    .with_preemption_request(PreemptionDecision {
        node: receiver.clone(),
        at: SimInstant { ticks: 1 },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 32 },
        },
    })
    .with_world(&world);
    let mut scheduler = SingleScheduler::new(scenario)?;
    drive_until_resolved_inputs(&mut scheduler, 2)?;

    let checkpoint = scheduler.checkpoint()?;
    let segments = scheduler.event_log_segment_store();
    let segments = segments.as_ref();
    let configuration = scheduler.configuration();
    let steps = authenticated_replay_steps(
        &world,
        configuration,
        &checkpoint,
        segments,
        1,
        &receiver,
        2,
    )?;

    assert_eq!(steps.len(), 5);
    assert!(
        matches!(steps[0], ReplayStep::Input { delivery_icount, .. } if delivery_icount.retired == 1)
    );
    assert!(matches!(steps[1], ReplayStep::Decision { index: 0 }));
    assert!(matches!(steps[2], ReplayStep::Decision { index: 1 }));
    assert!(
        matches!(steps[3], ReplayStep::Input { delivery_icount, .. } if delivery_icount.retired == 2)
    );
    assert!(matches!(steps[4], ReplayStep::Decision { index: 2 }));
    assert!(matches!(
        configuration.schedule.decision_history()[1],
        Decision::Preemption(_)
    ));
    let sender_steps =
        authenticated_replay_steps(&world, configuration, &checkpoint, segments, 1, &sender, 0)?;
    assert!(matches!(
        sender_steps.as_slice(),
        [
            ReplayStep::Decision { index: 0 },
            ReplayStep::Decision { index: 1 },
            ReplayStep::Decision { index: 2 }
        ]
    ));
    assert!(
        authenticated_replay_steps(
            &world,
            configuration,
            &checkpoint,
            segments,
            2,
            &receiver,
            2,
        )
        .is_err()
    );
    assert!(
        authenticated_replay_steps(
            &world,
            configuration,
            &checkpoint,
            segments,
            1,
            &receiver,
            1,
        )
        .is_err()
    );
    let wrong_world = World::from_nodes(vec![world_node("sender"), world_node("receiver")])?;
    assert!(
        authenticated_replay_steps(
            &wrong_world,
            configuration,
            &checkpoint,
            segments,
            1,
            &receiver,
            2,
        )
        .is_err()
    );
    Ok(())
}

/// Physical counter at which a rebased receiver's ready point anchors scheduler
/// time zero. Every live delivery to it lands this far past its scheduler time.
const READY_COUNTER: u64 = 1_000;

/// Two-node world whose receiver's ready point follows counter zero.
struct RebasedReceiver {
    world: World,
    receiver: NodeId,
    scenario: SchedulerLivenessScenario,
}

/// Builds a [`RebasedReceiver`] with one input at each scheduler time.
fn rebased_receiver_scenario(
    input_times: [u64; 2],
) -> Result<RebasedReceiver, Box<dyn std::error::Error>> {
    let sender = NodeId {
        name: String::from("sender"),
    };
    let receiver = NodeId {
        name: String::from("receiver"),
    };
    let world = World::from_nodes_and_links(
        vec![world_node("sender"), world_node("receiver")],
        vec![LinkDef::new(sender.clone(), receiver.clone())?],
    )?;
    let link = world.links()[0].scheduler_node_id();

    let mut rebased_receiver = scheduler_node(&receiver, SchedulerNodeActivity::Runnable);
    rebased_receiver.counter = NodeCounter {
        ticks: READY_COUNTER,
    };
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "replay-input-rebased-counter",
        16,
        SimInstant { ticks: 16 },
        vec![
            rebased_receiver,
            scheduler_node(&sender, SchedulerNodeActivity::Done),
        ],
        vec![
            input_event(&receiver, &link, input_times[0], 0),
            input_event(&receiver, &link, input_times[1], 1),
        ],
    )
    .with_ready_point_counter(
        SchedulerNodeId {
            node: receiver.clone(),
            kind: SchedulingNodeKind::Vm,
        },
        NodeCounter {
            ticks: READY_COUNTER,
        },
    )
    .with_world(&world);

    Ok(RebasedReceiver {
        world,
        receiver,
        scenario,
    })
}

/// One resolved input's scheduler tick and recorded physical counter.
type RecordedInputStamp = (u64, Option<Icount>);

/// Returns every resolved input's [`RecordedInputStamp`] in log order.
fn recorded_input_stamps(
    scheduler: &SingleScheduler,
) -> Result<Vec<RecordedInputStamp>, Box<dyn std::error::Error>> {
    Ok(resolved_input_entries(scheduler)?
        .iter()
        .map(|entry| (entry.time().stamp.tick.ticks, entry.time().stamp.retired))
        .collect())
}

/// Returns the physical delivery counters of the receiver's replay plan.
fn replay_plan_deliveries(
    world: &World,
    scheduler: &SingleScheduler,
    receiver: &NodeId,
) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    let checkpoint = scheduler.checkpoint()?;
    let segments = scheduler.event_log_segment_store();
    let steps = authenticated_replay_steps(
        world,
        scheduler.configuration(),
        &checkpoint,
        segments.as_ref(),
        1,
        receiver,
        2,
    )?;

    Ok(steps
        .iter()
        .filter_map(|step| match step {
            ReplayStep::Input {
                delivery_icount, ..
            } => Some(delivery_icount.retired),
            ReplayStep::Decision { .. } => None,
        })
        .collect())
}

#[test]
fn replay_plan_delivers_inputs_at_the_recorded_physical_counter_of_a_rebased_vm()
-> Result<(), Box<dyn std::error::Error>> {
    let RebasedReceiver {
        world,
        receiver,
        scenario,
    } = rebased_receiver_scenario([1, 2])?;
    let mut scheduler = SingleScheduler::new(scenario)?;
    drive_until_resolved_inputs(&mut scheduler, 2)?;

    // The live log keeps scheduler time and the physical counter apart.
    assert_eq!(
        recorded_input_stamps(&scheduler)?,
        vec![
            (
                1,
                Some(Icount {
                    retired: READY_COUNTER + 1
                })
            ),
            (
                2,
                Some(Icount {
                    retired: READY_COUNTER + 2
                })
            ),
        ]
    );
    // Thin replay must deliver at the counter, not at scheduler time.
    assert_eq!(
        replay_plan_deliveries(&world, &scheduler, &receiver)?,
        vec![READY_COUNTER + 1, READY_COUNTER + 2]
    );
    Ok(())
}

#[test]
fn exact_scheduler_restore_keeps_the_rebased_physical_delivery_counter()
-> Result<(), Box<dyn std::error::Error>> {
    let input_times = [2, 12];

    let RebasedReceiver {
        world,
        receiver,
        scenario,
    } = rebased_receiver_scenario(input_times)?;
    let mut uninterrupted = SingleScheduler::new(scenario)?;
    drive_until_resolved_inputs(&mut uninterrupted, 2)?;

    // Stop after the first delivery, restore that continuation into a fresh
    // scheduler sharing the sealed log, and resolve the second input there.
    let mut original = SingleScheduler::new(rebased_receiver_scenario(input_times)?.scenario)?;
    drive_until_resolved_inputs(&mut original, 1)?;
    let checkpoint = original.checkpoint()?;
    let mut restored = SingleScheduler::new_with_event_log_segment_store(
        rebased_receiver_scenario(input_times)?.scenario,
        original.event_log_segment_store(),
    )?;
    checkpoint.restore_into(&mut restored)?;
    drive_until_resolved_inputs(&mut restored, 2)?;

    let expected = vec![
        (
            input_times[0],
            Some(Icount {
                retired: READY_COUNTER + input_times[0],
            }),
        ),
        (
            input_times[1],
            Some(Icount {
                retired: READY_COUNTER + input_times[1],
            }),
        ),
    ];
    assert_eq!(recorded_input_stamps(&uninterrupted)?, expected);
    assert_eq!(recorded_input_stamps(&restored)?, expected);
    assert_eq!(
        replay_plan_deliveries(&world, &restored, &receiver)?,
        replay_plan_deliveries(&world, &uninterrupted, &receiver)?
    );
    Ok(())
}

mod unsupported_effects;
