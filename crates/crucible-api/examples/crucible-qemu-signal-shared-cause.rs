//! Certifies one signal event across live network, storage, and QEMU adapters.
//!
//! The two guests and block sub-node are ordinary production lifecycle
//! participants. Before the event, the guest creates both a queued frame and a
//! completed volatile-cache write. One event then powers down the declared
//! forwarder, loses that cache entry, and crashes/restarts the owning QEMU
//! process. The executable also proves exact checkpoint continuation and
//! locked-effect replay from fresh processes.

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use crucible::model::{
    BindingActionCause, BindingActionKind, BindingEventParent, BindingMapping,
    BindingObservabilityPolicy, BindingSampling, BindingSearchPolicy, DagStore,
    EFFECT_SEMANTIC_VERSION, EffectKind, EffectLifetime, EffectRequest, EffectSpecification,
    FaultBinding, FaultObjectId, FaultPhase, FaultResourceLimits, FaultSignalPlan, MemoryDagStore,
    NetworkEffectSpecification, NetworkForwarderTransition, NetworkQueueDiscipline,
    NetworkQueueOverflow, NetworkStatePolicy, NodeBootPolicy, NodeEffectSpecification,
    NodeLifecycleTransition, NodeStatePolicy, PositiveU64, ResolvedFaultTarget, ResolvedTargetSet,
    SignalCoordinate, SignalDomain, SignalId, SignalNode, SignalNodeKind, SignalPoint,
    SignalResourceLimits, SignalShape, SignalSourceSpecification, SignalUnit, SignalValue,
    SignalValueType, StorageEffectSpecification, StorageVolatileCacheLossKind,
    StorageVolatileCacheLossSelector, TargetSelector, WorldCompletionDurability,
    WorldDiscardSemantics, WorldFlushSemantics, WorldNetworkForwarder, WorldNetworkForwarderKind,
    WorldNetworkInterface, WorldNetworkPath, WorldNetworkPathHop, WorldNetworkQueue,
    WorldNetworkQueueDiscipline, WorldNetworkQueueOverflow, WorldNetworkSegment,
    WorldNetworkSegmentKind, WorldNetworkTechnology, WorldStorageFaultDevice, WorldStorageKind,
    WorldStorageMedia, WorldStoragePersistence,
};
use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentAddressedBlobRef, ContentHash, Icount,
    LinkDef, LinkLossProbability, NodeId, NodeTemplate, Plan, Properties, QuantumLoop,
    QuantumRequest, ReadyPoint, ScenarioDefForm, SchedulerNodeActivity, Seed, SimDuration,
    WhiteBoxPolicy, World, WorldBlockLatency, WorldIoCoreConfig, WorldIoNode, WorldNode,
    WorldNodeDef,
};
use crucible_api::{
    ProductionFaultEvidenceSnapshot, ProductionRootImageFormat, ProductionVmLifecycleConfig,
    ProductionVmLifecycleLoop, build_production_vm_lifecycle_loop,
    build_production_vm_lifecycle_loop_from_checkpoint,
};

#[path = "crucible_qemu_signal_shared_cause/evidence.rs"]
mod evidence;
use evidence::{exact_shared_event_effects, exact_terminal_matrix, reached_restarted_node};
#[path = "crucible_qemu_signal_shared_cause/terminal_matrix.rs"]
mod terminal_matrix;
use terminal_matrix::*;

const EVENT_NANOS: u64 = 8_000_000_000;
const DEVICE_BYTES: u64 = 1_048_576;

fn id(value: &str) -> Result<FaultObjectId, Box<dyn Error>> {
    Ok(FaultObjectId::parse(value)?)
}

fn signal_id(value: &str) -> Result<SignalId, Box<dyn Error>> {
    Ok(SignalId::parse(value)?)
}

fn positive(field: &'static str, value: u64) -> Result<PositiveU64, Box<dyn Error>> {
    Ok(PositiveU64::new(field, value)?)
}

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

fn event_binding(
    binding_id: &str,
    output: &SignalId,
    target: ResolvedFaultTarget,
    specification: EffectSpecification,
    program: &crucible::model::SignalProgram,
) -> Result<FaultBinding, Box<dyn Error>> {
    Ok(FaultBinding::new(
        id(binding_id)?,
        vec![output.clone()],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        TargetSelector::Exact(ResolvedTargetSet::new(vec![target], false)?),
        [FaultPhase::Boundary].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            specification,
        )?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        program,
    )?)
}

fn persistent_queue_binding(
    output: &SignalId,
    program: &crucible::model::SignalProgram,
) -> Result<FaultBinding, Box<dyn Error>> {
    Ok(FaultBinding::new(
        id("shared-cause-queue-policy")?,
        vec![output.clone()],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(ResolvedTargetSet::new(
            vec![ResolvedFaultTarget::NetworkQueue {
                owner: id("rack-forwarder")?,
                queue: id("rack-egress")?,
            }],
            false,
        )?),
        [FaultPhase::Queue].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::QueuePolicy {
                capacity_bytes: positive("capacity_bytes", 4_194_304)?,
                capacity_frames: crucible::model::BoundedCount::new(
                    crucible::model::CountLimit::QueueEntries,
                    4096,
                )?,
                discipline: NetworkQueueDiscipline::Fifo,
                discipline_parameters: None,
                overflow: NetworkQueueOverflow::TailDrop,
                typed_error: None,
            }),
        )?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        program,
    )?)
}

fn shared_cause_plan(device: ContentHash) -> Result<FaultSignalPlan, Box<dyn Error>> {
    let event = signal_id("rack-power-loss")?;
    let (terminal_matrix_event, terminal_matrix_node) = terminal_matrix_signal()?;
    let queue_enabled = signal_id("queue-enabled")?;
    let schema = signal_id("rack-power-event-v1")?;
    let program = crucible::model::SignalProgram::new(
        vec![
            SignalNode {
                id: event.clone(),
                domain: SignalDomain::Event,
                output: SignalShape::new(
                    SignalValueType::Event(schema.clone()),
                    SignalUnit::Dimensionless,
                    0,
                )?,
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                    events: vec![SignalPoint {
                        coordinate: SignalCoordinate::Event {
                            parent: Box::new(SignalCoordinate::VirtualTime { nanos: EVENT_NANOS }),
                            sequence: 0,
                        },
                        sequence: 0,
                        value: SignalValue::Event {
                            schema,
                            payload: b"rack-power-loss".to_vec(),
                        },
                    }],
                }),
            },
            terminal_matrix_node,
            SignalNode {
                id: queue_enabled.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)?,
                inputs: Vec::new(),
                kind: SignalNodeKind::Constant {
                    value: SignalValue::Bool(true),
                },
            },
        ],
        vec![
            event.clone(),
            terminal_matrix_event.clone(),
            queue_enabled.clone(),
        ],
        SignalResourceLimits::default(),
    )?;
    let mut bindings = vec![
        persistent_queue_binding(&queue_enabled, &program)?,
        event_binding(
            "shared-power-forwarder",
            &event,
            ResolvedFaultTarget::NetworkForwarder {
                forwarder: id("rack-forwarder")?,
            },
            EffectSpecification::Network(NetworkEffectSpecification::ForwarderLifecycle {
                transition: NetworkForwarderTransition::PowerLoss,
                downtime_nanos: positive("downtime_nanos", 8_000_000_000)?,
                queue_policy: NetworkStatePolicy::Clear,
                table_policy: NetworkStatePolicy::Clear,
            }),
            &program,
        )?,
        event_binding(
            "shared-power-storage",
            &event,
            ResolvedFaultTarget::BlockDevice { device },
            EffectSpecification::Storage(StorageEffectSpecification::VolatileCacheLoss {
                selector: StorageVolatileCacheLossSelector::All,
                loss: StorageVolatileCacheLossKind::PowerLoss,
            }),
            &program,
        )?,
        event_binding(
            "shared-power-node",
            &event,
            ResolvedFaultTarget::Node {
                node: id("node-a")?,
            },
            EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                transition: NodeLifecycleTransition::Crash,
                downtime_nanos: 1_000_000_000,
                boot_policy: NodeBootPolicy::Immediate,
                volatile_state_policy: NodeStatePolicy::Preserve,
                device_state_policy: NodeStatePolicy::Clear,
            }),
            &program,
        )?,
    ];
    bindings.extend(terminal_matrix_bindings(&terminal_matrix_event, &program)?);
    Ok(FaultSignalPlan::new(
        vec![program],
        bindings,
        FaultResourceLimits::default(),
    )?)
}

fn topology() -> Result<crucible::model::WorldFaultTopology, Box<dyn Error>> {
    Ok(crucible::model::WorldFaultTopology {
        network_interfaces: vec![
            WorldNetworkInterface {
                id: signal_id("node-a-if")?,
                endpoint: signal_id("node-a")?,
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            },
            WorldNetworkInterface {
                id: signal_id("forwarder-left")?,
                endpoint: signal_id("rack-forwarder")?,
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            },
            WorldNetworkInterface {
                id: signal_id("forwarder-right")?,
                endpoint: signal_id("rack-forwarder")?,
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            },
            WorldNetworkInterface {
                id: signal_id("node-b-if")?,
                endpoint: signal_id("node-b")?,
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            },
        ],
        network_segments: vec![
            WorldNetworkSegment {
                id: signal_id("node-a-to-forwarder")?,
                kind: WorldNetworkSegmentKind::Ethernet,
                interface_a: signal_id("node-a-if")?,
                interface_b: signal_id("forwarder-left")?,
                minimum_latency_nanos: 1,
                mtu_bytes: 1514,
                medium: None,
                forwarders: vec![signal_id("rack-forwarder")?],
                fault_domains: Vec::new(),
            },
            WorldNetworkSegment {
                id: signal_id("forwarder-to-node-b")?,
                kind: WorldNetworkSegmentKind::Ethernet,
                interface_a: signal_id("forwarder-right")?,
                interface_b: signal_id("node-b-if")?,
                minimum_latency_nanos: 1,
                mtu_bytes: 1514,
                medium: None,
                forwarders: vec![signal_id("rack-forwarder")?],
                fault_domains: Vec::new(),
            },
        ],
        network_forwarders: vec![WorldNetworkForwarder {
            id: signal_id("rack-forwarder")?,
            kind: WorldNetworkForwarderKind::Router,
            ports: vec![signal_id("forwarder-left")?, signal_id("forwarder-right")?],
            table_capacity: 4096,
            fault_domains: Vec::new(),
        }],
        network_queues: vec![WorldNetworkQueue {
            id: signal_id("rack-egress")?,
            owner: signal_id("rack-forwarder")?,
            capacity_packets: 4096,
            capacity_bytes: 4_194_304,
            discipline: WorldNetworkQueueDiscipline::Fifo,
            overflow: WorldNetworkQueueOverflow::DropTail,
            fault_domains: Vec::new(),
        }],
        network_paths: vec![
            WorldNetworkPath {
                id: signal_id("rack-path-a-to-b")?,
                direction: crucible::model::FaultDirection::AToB,
                hops: vec![
                    WorldNetworkPathHop::Segment {
                        segment: signal_id("node-a-to-forwarder")?,
                        direction: crucible::model::FaultDirection::AToB,
                    },
                    WorldNetworkPathHop::Forwarder {
                        forwarder: signal_id("rack-forwarder")?,
                    },
                    WorldNetworkPathHop::Queue {
                        queue: signal_id("rack-egress")?,
                    },
                    WorldNetworkPathHop::Segment {
                        segment: signal_id("forwarder-to-node-b")?,
                        direction: crucible::model::FaultDirection::AToB,
                    },
                ],
                mtu_bytes: 1514,
            },
            WorldNetworkPath {
                id: signal_id("rack-path-b-to-a")?,
                direction: crucible::model::FaultDirection::BToA,
                hops: vec![
                    WorldNetworkPathHop::Segment {
                        segment: signal_id("forwarder-to-node-b")?,
                        direction: crucible::model::FaultDirection::BToA,
                    },
                    WorldNetworkPathHop::Forwarder {
                        forwarder: signal_id("rack-forwarder")?,
                    },
                    WorldNetworkPathHop::Queue {
                        queue: signal_id("rack-egress")?,
                    },
                    WorldNetworkPathHop::Segment {
                        segment: signal_id("node-a-to-forwarder")?,
                        direction: crucible::model::FaultDirection::BToA,
                    },
                ],
                mtu_bytes: 1514,
            },
        ],
        storage_devices: vec![WorldStorageFaultDevice {
            id: signal_id("shared-block-contract")?,
            device: signal_id("shared-block")?,
            kind: WorldStorageKind::Block,
            persistence: WorldStoragePersistence {
                logical_block_bytes: 512,
                physical_sector_bytes: 4096,
                atomic_write_bytes: 512,
                length_bytes: DEVICE_BYTES,
                discard_granularity_bytes: 4096,
                maximum_request_bytes: 65_536,
                volatile_cache_bytes: 1_048_576,
                controller_buffer_bytes: 0,
                flush_semantics: WorldFlushSemantics::WritebackBarrier,
                discard_semantics: WorldDiscardSemantics::DeterministicZero,
                completion_durability: WorldCompletionDurability::VolatileCacheAccepted,
                cache_entries: 4096,
                controller_entries: 0,
                persistence_dependencies: 4096,
                retained_versions_per_interval: 16,
            },
            media: WorldStorageMedia::Ram { page_bytes: 4096 },
            fault_domains: Vec::new(),
        }],
        ..crucible::model::WorldFaultTopology::default()
    })
}

fn build_source() -> Result<(ScenarioDefForm, Arc<MemoryDagStore>), Box<dyn Error>> {
    let artifacts = Arc::new(MemoryDagStore::new());
    let base = vec![0_u8; DEVICE_BYTES as usize];
    let base_hash = artifacts.put(&base)?;
    let left = node("node-a");
    let right = node("node-b");
    let block = WorldIoNode::block(
        NodeId {
            name: String::from("shared-block"),
        },
        left.id.clone(),
        WorldIoCoreConfig::new(0),
        ContentAddressedBlobRef::from_hash(base_hash),
        DEVICE_BYTES,
        WorldBlockLatency::new(1_000, 1_000, 1_000, 1_000, 1),
    );
    let link = LinkDef::with_transport(
        left.id.clone(),
        right.id.clone(),
        SimDuration {
            nanos: 1_000_000_000,
        },
        SimDuration { nanos: 0 },
        LinkLossProbability::ZERO,
        Some(1_000),
    )?;
    let world = World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(left),
            WorldNodeDef::Vm(right),
            WorldNodeDef::Io(block.clone()),
        ],
        vec![link],
    )?
    .with_fault_topology(topology()?)?;
    let faults = shared_cause_plan(block.fault_target_hash())?;
    let completion_timer = crucible::TimerId {
        name: String::from("inactive-world-completion"),
    };
    let graph = crucible::EventGraph::builder()
        .event("inactive-world-checkpoint")
        .when(crucible::Condition::at(crucible::VirtualTime {
            ticks: INACTIVE_CHECKPOINT_NANOS,
        }))
        .action(crucible::Action::arm_timer(
            completion_timer.clone(),
            SimDuration { nanos: 1024 },
        ))
        .event("inactive-world-complete")
        .when(crucible::Condition::AllOf {
            predicates: vec![
                crucible::Condition::at(crucible::VirtualTime {
                    ticks: INACTIVE_COMPLETION_NANOS,
                }),
                crucible::Condition::timer(completion_timer),
            ],
        })
        .action(crucible::Action::Pass)
        .build_for_world(&world)?;
    let plan = Plan::from_event_graph_for_world(&world, graph)?
        .with_fault_signals_for_world(&world, faults)?;
    let source = ScenarioDefForm::from_components(
        &world,
        &plan,
        &Properties::empty(),
        Seed::from_u64(0x5ca1ed),
    )?;
    Ok((source, artifacts))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let [qemu, plugin, kernel, root_image, initrd, run_state_root] = args.as_slice() else {
        return Err("usage: crucible-qemu-signal-shared-cause QEMU PLUGIN KERNEL ROOT INITRD RUN_STATE_ROOT".into());
    };
    let (source, artifacts) = build_source()?;
    let scenario = source.scenario_def();
    let config = ProductionVmLifecycleConfig::new(qemu, plugin, kernel, root_image, run_state_root)
        .with_root_image_format(ProductionRootImageFormat::Raw)
        .with_initrd(initrd)
        .with_kernel_cmdline_prefix("console=ttyS0 quiet net.ifnames=0 init=/init")
        .with_world_artifacts(artifacts.clone())
        .with_signal_artifacts(artifacts)
        .with_run_ceiling_icount(96_000_000_000)
        .with_quantum_budget(1_000_000_000)
        .with_completion_timeout(Duration::from_secs(180));
    let mut lifecycle = build_production_vm_lifecycle_loop(&scenario, &source, &config)?;
    let mut configuration = Configuration::genesis(scenario.clone());
    let mut before = None;
    let mut last_precondition = None;
    for quantum in 0..64 {
        eprintln!("shared-cause phase=precondition quantum={quantum} begin");
        let outcome = lifecycle.drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })?;
        configuration = outcome.configuration;
        let evidence = lifecycle.fault_evidence_snapshot()?;
        let queued = evidence
            .network_queues
            .iter()
            .map(|queue| queue.reservations)
            .sum::<usize>();
        let queue_finish = evidence
            .network_queues
            .iter()
            .filter_map(|queue| queue.last_finish_nanos)
            .max();
        let volatile = evidence
            .block_devices
            .iter()
            .map(|device| device.volatile_entries)
            .sum::<usize>();
        last_precondition = Some((evidence.frontier.ticks, queued, volatile));
        eprintln!(
            "shared-cause phase=precondition quantum={quantum} frontier={} queue={queued} queue_finish={queue_finish:?} volatile={volatile}",
            evidence.frontier.ticks,
        );
        if evidence.frontier.ticks < EVENT_NANOS
            && queued > 0
            && queue_finish.is_some_and(|finish| finish > EVENT_NANOS)
            && volatile > 0
            && lifecycle.exact_checkpoint_ready()?
        {
            before = Some(evidence);
            break;
        }
    }
    let before = before.ok_or_else(|| {
        let (frontier, queued, volatile) = last_precondition.unwrap_or_default();
        format!(
            "live guest did not establish queue and volatile-cache state: \
             frontier={frontier}, queue_reservations={queued}, volatile_entries={volatile}"
        )
    })?;
    let checkpoint_configuration = configuration.clone();
    let checkpoint_frontier = before.frontier;
    eprintln!(
        "shared-cause phase=capture begin frontier={}",
        checkpoint_frontier.ticks
    );
    let closure = lifecycle
        .capture_checkpoint(&checkpoint_configuration)?
        .ok_or("production lifecycle did not return an exact execution closure")?;
    eprintln!("shared-cause phase=capture complete");

    let (after, after_configuration) =
        drive_to_restarted_node(&mut lifecycle, configuration, "primary")?;
    if after.network_outages.is_empty()
        || !after.network_queues.is_empty()
        || after
            .block_devices
            .iter()
            .any(|device| device.volatile_entries != 0)
        || !exact_shared_event_effects(&before, &after)
    {
        return Err("shared event did not produce all production consequences".into());
    }
    let before_block = before
        .block_devices
        .first()
        .ok_or("missing pre-event block evidence")?;
    let after_block = after
        .block_devices
        .first()
        .ok_or("missing post-event block evidence")?;
    let zero_prefix =
        ContentHash::from_bytes(&vec![
            0_u8;
            usize::try_from(after_block.visible_prefix_bytes)?
        ]);
    if before_block.visible_prefix_digest == zero_prefix
        || after_block.visible_prefix_digest != zero_prefix
        || after_block.actual_durable_frontier != before_block.actual_durable_frontier
    {
        return Err("volatile cache loss did not restore durable visible bytes exactly".into());
    }
    let locked = after
        .locked_effect_trace
        .clone()
        .ok_or("locked replay trace absent")?;
    let (terminal_matrix, inactive_configuration) =
        drive_to_terminal_matrix(&mut lifecycle, after_configuration, &after)?;
    if lifecycle.live_node_count() != 1 || !exact_terminal_matrix(&after, &terminal_matrix) {
        return Err("production terminal lifecycle ownership matrix is not exact".into());
    }
    eprintln!("shared-cause phase=inactive-capture begin");
    let inactive_closure = lifecycle
        .capture_checkpoint(&inactive_configuration)?
        .ok_or("inactive world did not return an exact execution closure")?;
    eprintln!("shared-cause phase=inactive-completion begin");
    let inactive_log = complete_inactive_world(
        &mut lifecycle,
        inactive_configuration.clone(),
        &terminal_matrix,
    )?;
    lifecycle.shutdown()?;

    eprintln!("shared-cause phase=inactive-restore begin");
    let inactive_checkpoint = checkpoint_reference(
        &inactive_configuration,
        terminal_matrix.frontier,
        inactive_closure,
    );
    let mut inactive_restored = build_production_vm_lifecycle_loop_from_checkpoint(
        &scenario,
        &source,
        &config,
        &inactive_checkpoint,
    )?;
    let restored_inactive_log = complete_inactive_world(
        &mut inactive_restored,
        inactive_configuration,
        &terminal_matrix,
    )?;
    inactive_restored.shutdown()?;
    eprintln!("shared-cause phase=inactive-restore complete");
    if inactive_log != restored_inactive_log {
        return Err(
            "inactive-world checkpoint changed the exact completion event-log segment".into(),
        );
    }

    let checkpoint = checkpoint_reference(&checkpoint_configuration, checkpoint_frontier, closure);
    let mut restored = build_production_vm_lifecycle_loop_from_checkpoint(
        &scenario,
        &source,
        &config,
        &checkpoint,
    )?;
    let (restored_after, _) =
        drive_to_restarted_node(&mut restored, checkpoint_configuration, "restored")?;
    restored.shutdown()?;
    if restored_after != after {
        return Err("exact checkpoint continuation changed shared-cause evidence".into());
    }

    let replay_config = config.clone().with_fault_replay(locked);
    let mut replay = build_production_vm_lifecycle_loop(&scenario, &source, &replay_config)?;
    let replay_configuration = Configuration::genesis(scenario);
    let (replay_after, _) = drive_to_restarted_node(&mut replay, replay_configuration, "replay")?;
    replay.shutdown()?;
    if replay_after != after {
        return Err("locked-effect replay changed shared-cause evidence".into());
    }

    println!("PASS");
    println!("gate=gate:signal-shared-cause");
    println!("backend=production-qemu-lifecycle");
    println!("pre_event_queue_and_volatile_cache=true");
    println!("pre_event_queue_finish_after_event=true");
    println!("network_storage_node_same_event=true");
    println!("shared_event_effect_records=3");
    println!("node_effective_icount_authenticated=true");
    println!("exact_checkpoint_evidence_match=true");
    println!("locked_effect_replay_evidence_match=true");
    println!("inactive_world_exact_trigger_without_run=true");
    println!("inactive_world_checkpoint_event_log_match=true");
    println!(
        "terminal_row=node-a|transition=power_off|generation_delta=1|service_state=powered_off|scheduler_activity=halted|process_ownership=exact"
    );
    println!(
        "terminal_row=node-b|transition=permanent_failure|generation_delta=0|service_state=permanently_failed|scheduler_activity=done|process_ownership=absent"
    );
    Ok(())
}
