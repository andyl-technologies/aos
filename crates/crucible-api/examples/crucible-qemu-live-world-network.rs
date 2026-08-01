//! Certifies the production lifecycle's two-VM hostless World network route.

use std::error::Error;
use std::time::Duration;

use crucible::{
    Action, Condition, ControlOperation, ControlOperationKind, Event, EventGraph, EventId, Fault,
    FaultTag, Icount, LinkDef, LinkLossProbability, MembershipFault, NodeFault, NodeId,
    NodeTemplate, Plan, Properties, QuantumLoop, QuantumRequest, ReadyPoint, RestartPolicy,
    ScenarioDefForm, Seed, SimDuration, WhiteBoxPolicy, World, WorldNode,
};
use crucible_api::{
    ProductionRootImageFormat, ProductionVmLifecycleConfig, build_production_vm_lifecycle_loop,
};

fn node(name: &str) -> WorldNode {
    WorldNode {
        id: NodeId {
            name: String::from(name),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let [qemu, plugin, kernel, root_image, initrd] = args.as_slice() else {
        return Err(
            "usage: crucible-qemu-live-world-network QEMU PLUGIN KERNEL ROOT INITRD".into(),
        );
    };
    let left = NodeId {
        name: String::from("node-a"),
    };
    let right = NodeId {
        name: String::from("node-b"),
    };
    let link = LinkDef::with_transport(
        left.clone(),
        right.clone(),
        SimDuration {
            nanos: 3_999_000_000,
        },
        SimDuration { nanos: 0 },
        LinkLossProbability::from_millionths(250_000)?,
        None,
    )?;
    let world = World::from_nodes_and_links(vec![node(&left.name), node(&right.name)], vec![link])?;
    let source = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(0x5eed),
    )?;
    let scenario = source.scenario_def();
    let config = ProductionVmLifecycleConfig::new(qemu, plugin, kernel, root_image)
        .with_root_image_format(ProductionRootImageFormat::Raw)
        .with_initrd(initrd)
        .with_kernel_cmdline_prefix("console=ttyS0 quiet net.ifnames=0 init=/init")
        .with_run_ceiling_icount(12_000_000_000)
        .with_quantum_budget(4_000_000_000)
        .with_completion_timeout(Duration::from_secs(180));
    let mut lifecycle = build_production_vm_lifecycle_loop(&scenario, &source, &config)?;
    let mut configuration = crucible::Configuration::genesis(scenario.clone());
    let mut network_decisions = 0_usize;
    let mut delivered_frames = 0_usize;
    let mut selected_branch = None;
    for quantum in 0..12_u64 {
        let outcome = lifecycle.drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })?;
        configuration = outcome.configuration;
        network_decisions = network_decisions.saturating_add(
            outcome
                .decisions
                .iter()
                .filter(|decision| matches!(decision, crucible::Decision::FaultFires(_)))
                .count(),
        );
        delivered_frames = delivered_frames.saturating_add(
            outcome
                .resolved_events
                .iter()
                .filter(|event| {
                    matches!(
                        event.payload,
                        crucible::ScheduledEventPayload::BackendInput(_)
                    )
                })
                .count(),
        );
        selected_branch = lifecycle
            .search_frontiers()?
            .into_iter()
            .flat_map(|frontier| frontier.choices.choices().to_vec())
            .find(|choice| {
                matches!(
                    choice.decisions().first(),
                    Some(crucible::Decision::Override(override_decision))
                        if override_decision.choice.name == "loss-fire"
                )
            });
        if network_decisions > 0 && delivered_frames > 0 && selected_branch.is_some() {
            println!("completed_quantum={quantum}");
            break;
        }
    }
    let selected_branch = selected_branch.ok_or_else(|| {
        format!(
            "no live loss branch after 12 quanta: network_decisions={network_decisions} delivered_frames={delivered_frames}"
        )
    })?;
    if network_decisions == 0 || delivered_frames == 0 {
        return Err(format!(
            "no complete guest-output route after 12 quanta: network_decisions={network_decisions} delivered_frames={delivered_frames}"
        )
        .into());
    }
    lifecycle.shutdown()?;
    let checkpoint_node = NodeId {
        name: String::from("checkpoint-node"),
    };
    let checkpoint_world =
        World::from_nodes_and_links(vec![node(&checkpoint_node.name)], Vec::new())?;
    let checkpoint_source = ScenarioDefForm::from_components(
        &checkpoint_world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(0xc0ffee),
    )?;
    let checkpoint_scenario = checkpoint_source.scenario_def();
    let mut ready_lifecycle =
        build_production_vm_lifecycle_loop(&checkpoint_scenario, &checkpoint_source, &config)?;
    let ready_crash_tag = FaultTag::from_name("live-qemu-process-crash");
    let ready_crash = ready_lifecycle.drive_quantum(QuantumRequest {
        configuration: crucible::Configuration::genesis(checkpoint_scenario.clone()),
        control: vec![ControlOperation {
            sequence: 1,
            kind: ControlOperationKind::InjectFault {
                tag: ready_crash_tag.clone(),
                fault: Fault::Node(NodeFault::Crash {
                    node: checkpoint_node.clone(),
                    restart: RestartPolicy::FromReadyPoint,
                }),
            },
        }],
    })?;
    if ready_lifecycle.live_node_count() != 0 || ready_lifecycle.reconciled_crash_count() != 1 {
        return Err("intended crash did not stop the single QEMU process".into());
    }
    let _ready_restart = ready_lifecycle.drive_quantum(QuantumRequest {
        configuration: ready_crash.configuration,
        control: vec![ControlOperation {
            sequence: 2,
            kind: ControlOperationKind::HealFault {
                tag: ready_crash_tag,
            },
        }],
    })?;
    if ready_lifecycle.live_node_count() != 1 || ready_lifecycle.reconciled_restart_count() != 1 {
        return Err("ready-point restart did not relaunch the single QEMU process".into());
    }
    ready_lifecycle.shutdown()?;
    let stay_down_tag = FaultTag::from_name("live-qemu-stay-down");
    let stay_down_heal_event = EventId::from_name("heal-stay-down-node");
    let stay_down_plan = Plan::from_event_graph_for_world(
        &checkpoint_world,
        EventGraph::new_for_world(
            vec![
                Event::once(
                    EventId::from_name("crash-stay-down-node"),
                    None,
                    Action::InjectFault {
                        tag: stay_down_tag.clone(),
                        fault: MembershipFault::Crash {
                            node: checkpoint_node.clone(),
                            restart: RestartPolicy::StayDown,
                        },
                    },
                ),
                Event::once(
                    stay_down_heal_event.clone(),
                    Some(Condition::fault_active(stay_down_tag.clone())),
                    Action::HealFault {
                        tag: stay_down_tag.clone(),
                    },
                ),
                Event::once(
                    EventId::from_name("start-stay-down-node"),
                    Some(Condition::all_of(vec![
                        Condition::after(SimDuration { nanos: 0 }, stay_down_heal_event),
                        Condition::not(Condition::fault_active(stay_down_tag)),
                    ])),
                    Action::StartNode {
                        node: checkpoint_node.clone(),
                    },
                ),
            ],
            &checkpoint_world,
        )?,
    )?;
    let stay_down_source = ScenarioDefForm::from_components(
        &checkpoint_world,
        &stay_down_plan,
        &Properties::empty(),
        Seed::from_u64(0x5a7d0),
    )?;
    let stay_down_scenario = stay_down_source.scenario_def();
    let mut stay_down_lifecycle =
        build_production_vm_lifecycle_loop(&stay_down_scenario, &stay_down_source, &config)?;
    let _stay_down_outcome = stay_down_lifecycle.drive_quantum(QuantumRequest {
        configuration: crucible::Configuration::genesis(stay_down_scenario),
        control: Vec::new(),
    })?;
    if stay_down_lifecycle.live_node_count() != 1
        || stay_down_lifecycle.reconciled_restart_count() != 2
        || stay_down_lifecycle.reconciled_crash_count() != 1
    {
        return Err(format!(
            "event-graph StartNode did not relaunch the StayDown QEMU process: live={} crashes={} restarts={}",
            stay_down_lifecycle.live_node_count(),
            stay_down_lifecycle.reconciled_crash_count(),
            stay_down_lifecycle.reconciled_restart_count()
        )
        .into());
    }
    stay_down_lifecycle.shutdown()?;
    let mut checkpoint_lifecycle =
        build_production_vm_lifecycle_loop(&checkpoint_scenario, &checkpoint_source, &config)?;
    let checkpoint_advance = checkpoint_lifecycle.drive_quantum(QuantumRequest {
        configuration: crucible::Configuration::genesis(checkpoint_scenario),
        control: Vec::new(),
    })?;
    let checkpoint = checkpoint_lifecycle.drive_quantum(QuantumRequest {
        configuration: checkpoint_advance.configuration,
        control: vec![ControlOperation {
            sequence: 1,
            kind: ControlOperationKind::Snapshot,
        }],
    })?;
    let checkpoint_crash_tag = FaultTag::from_name("live-qemu-checkpoint-crash");
    let checkpoint_crash = checkpoint_lifecycle.drive_quantum(QuantumRequest {
        configuration: checkpoint.configuration,
        control: vec![ControlOperation {
            sequence: 2,
            kind: ControlOperationKind::InjectFault {
                tag: checkpoint_crash_tag.clone(),
                fault: Fault::Node(NodeFault::Crash {
                    node: checkpoint_node,
                    restart: RestartPolicy::FromLastCheckpoint,
                }),
            },
        }],
    })?;
    if checkpoint_lifecycle.live_node_count() != 0
        || checkpoint_lifecycle.reconciled_crash_count() != 1
    {
        return Err("checkpoint crash did not stop the single QEMU process".into());
    }
    let checkpoint_restart = checkpoint_lifecycle.drive_quantum(QuantumRequest {
        configuration: checkpoint_crash.configuration,
        control: vec![ControlOperation {
            sequence: 3,
            kind: ControlOperationKind::HealFault {
                tag: checkpoint_crash_tag,
            },
        }],
    })?;
    let _checkpoint_restart_configuration = checkpoint_restart.configuration;
    if checkpoint_lifecycle.live_node_count() != 1
        || checkpoint_lifecycle.reconciled_restart_count() != 1
    {
        return Err("checkpoint thin replay did not install the replacement QEMU process".into());
    }
    checkpoint_lifecycle.shutdown()?;
    let override_decision = match selected_branch.decisions().first() {
        Some(crucible::Decision::Override(override_decision)) => override_decision.clone(),
        _ => return Err("live loss branch did not begin with its exact override".into()),
    };
    let expected_decisions = selected_branch.decisions().to_vec();
    let branch_config = config
        .clone()
        .with_branch_network_choices(vec![override_decision]);
    let mut branch = build_production_vm_lifecycle_loop(&scenario, &source, &branch_config)?;
    let mut branch_configuration = crucible::Configuration::genesis(scenario);
    let mut branch_matched = false;
    for _ in 0..12_u64 {
        let outcome = branch.drive_quantum(QuantumRequest {
            configuration: branch_configuration,
            control: Vec::new(),
        })?;
        branch_configuration = outcome.configuration;
        if outcome
            .decisions
            .windows(expected_decisions.len())
            .any(|window| window == expected_decisions)
        {
            branch_matched = true;
            break;
        }
    }
    branch.shutdown()?;
    if !branch_matched {
        return Err("live QEMU replay did not consume the selected network branch".into());
    }
    println!("PASS");
    println!("gate=gate:live-world-network");
    println!("backend=production-qemu-lifecycle");
    println!("topology=two-vm-hostless-world-link");
    println!("network_decisions={network_decisions}");
    println!("delivered_frames={delivered_frames}");
    println!("search_branch=loss-fire");
    println!("branch_decisions_match=true");
    println!("process_crash_stopped=true");
    println!("ready_point_process_relaunched=true");
    println!("stay_down_start_node_process_relaunched=true");
    println!("last_checkpoint_thin_replay_relaunched=true");
    Ok(())
}
