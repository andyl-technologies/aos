//! Native schedule and input-plan regressions without a QEMU process.

use super::*;

use crucible::{
    Decision, ExactLocalEvent, IrqVector, LinkDef, NetworkLookahead, NodeCounter, NodeTemplate,
    PreemptionDecision, PreemptionKind, QuantumLoop, QuantumRequest, ReadyPoint, ScheduledEvent,
    ScheduledEventKey, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerScenarioNode, SchedulingNodeKind, SharedTimelineKey, Shift, SimInstant,
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
        icount_shift: 0,
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
                virtual_time: SimInstant { nanos: at },
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
        Shift::new(0)?,
        16,
        SimInstant { nanos: 16 },
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
        at: Icount { retired: 1 },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 32 },
        },
    })
    .with_world(&world);
    let mut scheduler = SingleScheduler::new(scenario)?;

    for _ in 0..16 {
        scheduler.drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })?;
        let input_count = scheduler
            .checkpoint()?
            .retained_event_log_entries()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.payload(),
                    SchedulerEventLogPayload::ResolvedHappening(ScheduledEvent {
                        payload: ScheduledEventPayload::BackendInput(_),
                        ..
                    })
                )
            })
            .count();
        if input_count == 2 {
            break;
        }
    }
    let checkpoint = scheduler.checkpoint()?;
    let configuration = scheduler.configuration();
    let steps = authenticated_replay_steps(&world, configuration, &checkpoint, 1, &receiver, 2)?;

    assert_eq!(steps.len(), 5);
    assert!(matches!(steps[0], ReplayStep::Input { delivery, .. } if delivery.retired == 1));
    assert!(matches!(steps[1], ReplayStep::Decision { index: 0 }));
    assert!(matches!(steps[2], ReplayStep::Decision { index: 1 }));
    assert!(matches!(steps[3], ReplayStep::Input { delivery, .. } if delivery.retired == 2));
    assert!(matches!(steps[4], ReplayStep::Decision { index: 2 }));
    assert!(matches!(
        configuration.schedule.decisions()[1],
        Decision::Preemption(_)
    ));
    let sender_steps =
        authenticated_replay_steps(&world, configuration, &checkpoint, 1, &sender, 0)?;
    assert!(matches!(
        sender_steps.as_slice(),
        [
            ReplayStep::Decision { index: 0 },
            ReplayStep::Decision { index: 1 },
            ReplayStep::Decision { index: 2 }
        ]
    ));
    assert!(
        authenticated_replay_steps(&world, configuration, &checkpoint, 2, &receiver, 2,).is_err()
    );
    assert!(
        authenticated_replay_steps(&world, configuration, &checkpoint, 1, &receiver, 1,).is_err()
    );
    let wrong_world = World::from_nodes(vec![world_node("sender"), world_node("receiver")])?;
    assert!(
        authenticated_replay_steps(&wrong_world, configuration, &checkpoint, 1, &receiver, 2,)
            .is_err()
    );
    Ok(())
}
