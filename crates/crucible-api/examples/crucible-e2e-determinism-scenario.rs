//! Materializes the native representative scenario for `gate:e2e-determinism`.
//!
//! The scenario has three production QEMU guests, a block sub-node, a 9p
//! sub-node, and one signal plan covering partition, loss, latency, and crash.
//! Its host properties exercise the always, eventually, and sometimes
//! quantifiers. The executable emits the canonical scenario TOML or installs
//! the immutable I/O objects in a [`LocalDagStore`] for the public CLI.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;

use crucible::model::{
    BindingMapping, BindingObservabilityPolicy, BindingSampling, BindingSearchPolicy, DagStore,
    EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest, EffectSpecification, FaultAdapter,
    FaultBinding, FaultDirection, FaultObjectId, FaultOperation, FaultPhase, FaultResourceLimits,
    FaultSignalPlan, FaultTargetKind, NetworkAvailabilityState, NetworkEffectSpecification,
    NetworkInFlightPolicy, NodeBootPolicy, NodeEffectSpecification, NodeLifecycleTransition,
    NodeStatePolicy, OperationSet, OpportunityFilter, PositiveU64, ProbabilityMillionths,
    ResolvedFaultTarget, ResolvedTargetSet, SignalCoordinate, SignalDomain, SignalId, SignalNode,
    SignalNodeKind, SignalPoint, SignalResourceLimits, SignalShape, SignalSourceSpecification,
    SignalUnit, SignalValue, SignalValueType, TargetSelector, WorldCompletionDurability,
    WorldDiscardSemantics, WorldFlushSemantics, WorldNetworkInterface, WorldNetworkSegment,
    WorldNetworkSegmentKind, WorldNetworkTechnology, WorldStorageFaultDevice, WorldStorageKind,
    WorldStorageMedia, WorldStoragePersistence,
};
use crucible::{
    Action, AssertionDef, AssertionId, AssertionPhase, ContentAddressedBlobRef, ContentHash,
    EventGraph, GuestWorkloadBinary, Icount, IoEventKind, LinkDef, LinkLossProbability,
    LocalDagStore, NodeId, NodeLifecycle, NodeTemplate, Plan, Predicate, Properties, Property,
    ReadyPoint, ScenarioDefForm, Seed, SimDuration, VirtualTime, VmArchitecture, WhiteBoxPolicy,
    World, WorldBlockLatency, WorldIoCoreConfig, WorldIoNode, WorldNinePLatency, WorldNode,
    WorldNodeDef,
};
use crucible_device::ninep::{FsTree, Node as NinePNode};

const BLOCK_BYTES: usize = 1_048_576;
const PARTITION_START_NANOS: u64 = 8_000_000_000;
const PARTITION_DURATION_NANOS: u64 = 2_000_000_000;
const LATENCY_START_NANOS: u64 = 10_000_000_000;
const LATENCY_DURATION_NANOS: u64 = 2_000_000_000;
const LOSS_START_NANOS: u64 = 12_000_000_000;
const LOSS_DURATION_NANOS: u64 = 2_000_000_000;
const CRASH_NANOS: u64 = 9_000_000_000;
const REQUIRED_EFFECTS_COMPLETE_NANOS: u64 = 15_000_000_000;
const PROPERTY_DEADLINE_TICKS: u64 = 40_000_000_000;

/// Emits the canonical scenario or populates a content-addressed store.
///
/// # Errors
///
/// Returns an error when the command line is invalid, scenario construction
/// fails, or an immutable I/O object cannot be stored under its declared hash.
fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [mode] if mode == "--emit-scenario" => {
            print!("{}", representative_scenario()?.to_canonical_toml()?);
        }
        [mode, root] if mode == "--populate-store" => {
            populate_store(root.as_ref())?;
        }
        _ => {
            return Err(
                "usage: crucible-e2e-determinism-scenario --emit-scenario | --populate-store ROOT"
                    .into(),
            );
        }
    }
    Ok(())
}

/// Builds the complete representative scenario used by the native fleet gate.
fn representative_scenario() -> Result<ScenarioDefForm, Box<dyn Error>> {
    let nginx = vm_node(
        "nginx",
        GuestWorkloadBinary::Httpd.selected_cmdline("console=ttyS0 address=10.0.0.2 port=8080"),
        WhiteBoxPolicy::Disabled,
    );
    let curl = vm_node(
        "curl",
        GuestWorkloadBinary::ClientLoop.selected_cmdline(
            "console=ttyS0 address=10.0.0.3 target=10.0.0.2:8080 count=1 continue=1 probe-block=1",
        ),
        WhiteBoxPolicy::Enabled,
    );
    let io_probe = vm_node(
        "io-probe",
        GuestWorkloadBinary::Benchmark.selected_cmdline("console=ttyS0 role=io-probe"),
        WhiteBoxPolicy::Enabled,
    );

    let block_bytes = block_artifact();
    let block = WorldIoNode::block(
        node_id("probe-block"),
        curl.id.clone(),
        WorldIoCoreConfig::new(0),
        ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(&block_bytes)),
        BLOCK_BYTES as u64,
        WorldBlockLatency::new(1_000, 1_000, 1_000, 1_000, 1),
    );
    let ninep_bytes = ninep_artifact()?.canonical_bytes();
    let ninep = WorldIoNode::ninep(
        node_id("probe-ninep"),
        io_probe.id.clone(),
        WorldIoCoreConfig::new(0),
        ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(&ninep_bytes)),
        WorldNinePLatency::new(1_000, 1_000, 1),
    );

    let links = vec![
        link("curl", "nginx")?,
        link("io-probe", "nginx")?,
        link("curl", "io-probe")?,
    ];
    let world = World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(nginx),
            WorldNodeDef::Vm(curl),
            WorldNodeDef::Vm(io_probe),
            WorldNodeDef::Io(block.clone()),
            WorldNodeDef::Io(ninep),
        ],
        links,
    )?
    .with_fault_topology(fault_topology()?)?;

    let properties = representative_properties(&world)?;
    let assertion_ids = properties
        .assertions()
        .iter()
        .map(|assertion| assertion.id.clone())
        .collect::<Vec<_>>();
    let graph = EventGraph::builder()
        .event("pass-on-workload-and-io")
        .when(Predicate::all_of(vec![
            Predicate::assertion_state(
                AssertionId::from_name("curl-receives-http-200"),
                AssertionPhase::Satisfied,
            ),
            Predicate::assertion_state(
                AssertionId::from_name("io-probe-eventually-restarts"),
                AssertionPhase::Satisfied,
            ),
            Predicate::assertion_state(
                AssertionId::from_name("io-probe-complete"),
                AssertionPhase::Satisfied,
            ),
            Predicate::assertion_state(
                AssertionId::from_name("curl-block-read-complete"),
                AssertionPhase::Satisfied,
            ),
            Predicate::once(Predicate::io_pattern(node_id("curl"), IoEventKind::Any)),
            Predicate::once(Predicate::io_pattern(
                node_id("io-probe"),
                IoEventKind::NineP,
            )),
            Predicate::once(Predicate::node_state(
                node_id("io-probe"),
                NodeLifecycle::Crashed,
            )),
            Predicate::node_state(node_id("io-probe"), NodeLifecycle::Started),
            Predicate::at(VirtualTime {
                ticks: REQUIRED_EFFECTS_COMPLETE_NANOS,
            }),
        ]))
        .action(Action::pass())
        .build_with_assertions_for_world(assertion_ids.clone(), &world)?;
    let plan = Plan::from_event_graph_with_assertions_for_world(&world, assertion_ids, graph)?
        .with_fault_signals(representative_fault_plan()?);

    Ok(ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(0xe2e),
        0,
    )?)
}

fn representative_properties(world: &World) -> Result<Properties, Box<dyn Error>> {
    let always_available = AssertionDef {
        id: AssertionId::from_name("service-guests-do-not-crash"),
        message: String::from("Nginx and Curl remain running throughout the fault campaign"),
        property: Property::Always {
            predicate: Predicate::not(Predicate::any_of(vec![
                Predicate::node_state(node_id("nginx"), NodeLifecycle::Crashed),
                Predicate::node_state(node_id("curl"), NodeLifecycle::Crashed),
            ])),
        },
    };
    let http_succeeds = AssertionDef::guest_sometimes(
        AssertionId::from_name("curl-receives-http-200"),
        "Curl receives an HTTP 200 response during the fault campaign",
    );
    let block_read_completes = AssertionDef::guest_sometimes(
        AssertionId::from_name("curl-block-read-complete"),
        "Curl reports a successful read from its block sub-node",
    );
    let io_probe_completes = AssertionDef::guest_sometimes(
        AssertionId::from_name("io-probe-complete"),
        "The I/O probe reports a successful read from its 9p sub-node",
    );
    let io_probe_restarts = AssertionDef {
        id: AssertionId::from_name("io-probe-eventually-restarts"),
        message: String::from("After the I/O probe crashes, it eventually restarts"),
        property: Property::Eventually {
            trigger: Predicate::node_state(node_id("io-probe"), NodeLifecycle::Crashed),
            property: Predicate::node_state(node_id("io-probe"), NodeLifecycle::Started),
            deadline: VirtualTime {
                ticks: PROPERTY_DEADLINE_TICKS,
            },
        },
    };

    Ok(Properties::from_assertions_for_world(
        world,
        vec![
            always_available,
            http_succeeds,
            block_read_completes,
            io_probe_completes,
            io_probe_restarts,
        ],
    )?)
}

fn representative_fault_plan() -> Result<FaultSignalPlan, Box<dyn Error>> {
    let partition = signal_id("partition-window")?;
    let latency = signal_id("latency-window")?;
    let loss = signal_id("loss-window")?;
    let crash = signal_id("probe-crash")?;
    let crash_schema = signal_id("probe-crash-v1")?;
    let nodes = vec![
        pulse_node(
            partition.clone(),
            SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)?,
            PARTITION_START_NANOS,
            PARTITION_DURATION_NANOS,
            SignalValue::Bool(false),
            SignalValue::Bool(true),
        ),
        pulse_node(
            latency.clone(),
            SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)?,
            LATENCY_START_NANOS,
            LATENCY_DURATION_NANOS,
            SignalValue::Bool(false),
            SignalValue::Bool(true),
        ),
        pulse_node(
            loss.clone(),
            SignalShape::new(
                SignalValueType::ProbabilityMillionths,
                SignalUnit::ProbabilityMillionths,
                0,
            )?,
            LOSS_START_NANOS,
            LOSS_DURATION_NANOS,
            SignalValue::ProbabilityMillionths(0),
            SignalValue::ProbabilityMillionths(1_000_000),
        ),
        SignalNode {
            id: crash.clone(),
            domain: SignalDomain::Event,
            output: SignalShape::new(
                SignalValueType::Event(crash_schema.clone()),
                SignalUnit::Dimensionless,
                0,
            )?,
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                events: vec![SignalPoint {
                    coordinate: SignalCoordinate::Event {
                        parent: Box::new(SignalCoordinate::VirtualTime { nanos: CRASH_NANOS }),
                        sequence: 0,
                    },
                    sequence: 0,
                    value: SignalValue::Event {
                        schema: crash_schema,
                        payload: b"restart-io-probe".to_vec(),
                    },
                }],
            }),
        },
    ];
    let program = crucible::model::SignalProgram::new(
        nodes,
        vec![
            partition.clone(),
            latency.clone(),
            loss.clone(),
            crash.clone(),
        ],
        SignalResourceLimits::default(),
    )?;

    let network_target = ResolvedFaultTarget::NetworkSegment {
        segment: object_id("curl-nginx-segment")?,
        direction: FaultDirection::AToB,
    };
    let bindings = vec![
        persistent_binding(
            "partition-curl-to-nginx",
            partition,
            network_target.clone(),
            FaultPhase::Admit,
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state: NetworkAvailabilityState::Down,
                queued_policy: NetworkInFlightPolicy::Drop,
                in_flight_policy: NetworkInFlightPolicy::Drop,
            }),
            &program,
        )?,
        persistent_binding(
            "latency-curl-to-nginx",
            latency,
            network_target.clone(),
            FaultPhase::Resolve,
            EffectSpecification::Network(NetworkEffectSpecification::PropagationDelay {
                delay_nanos: Some(positive("delay_nanos", 200_000_000)?),
                distance_velocity_lookup: None,
            }),
            &program,
        )?,
        hazard_binding("loss-curl-to-nginx", loss, network_target, &program)?,
        crash_binding(crash, &program)?,
    ];

    Ok(FaultSignalPlan::new(
        vec![program],
        bindings,
        FaultResourceLimits::default(),
    )?)
}

fn pulse_node(
    id: SignalId,
    output: SignalShape,
    start_nanos: u64,
    duration: u64,
    inactive: SignalValue,
    active: SignalValue,
) -> SignalNode {
    SignalNode {
        id,
        domain: SignalDomain::VirtualTime,
        output,
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::Pulse {
            start: SignalCoordinate::VirtualTime { nanos: start_nanos },
            duration,
            inactive,
            active,
        }),
    }
}

fn persistent_binding(
    binding: &str,
    output: SignalId,
    target: ResolvedFaultTarget,
    phase: FaultPhase,
    specification: EffectSpecification,
    program: &crucible::model::SignalProgram,
) -> Result<FaultBinding, Box<dyn Error>> {
    Ok(FaultBinding::new(
        object_id(binding)?,
        vec![output],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        exact_target(target)?,
        [phase].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            specification,
        )?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        program,
    )?)
}

fn hazard_binding(
    binding: &str,
    output: SignalId,
    target: ResolvedFaultTarget,
    program: &crucible::model::SignalProgram,
) -> Result<FaultBinding, Box<dyn Error>> {
    Ok(FaultBinding::new(
        object_id(binding)?,
        vec![output],
        BindingSampling::AtOpportunity,
        BindingMapping::Hazard,
        exact_target(target)?,
        [FaultPhase::Resolve].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Opportunity,
            EffectSpecification::Network(NetworkEffectSpecification::FrameLoss {
                probability: Some(ProbabilityMillionths::new(1_000_000)?),
                outcome: None,
            }),
        )?,
        Some(OpportunityFilter {
            adapter: FaultAdapter::Network,
            operations: OperationSet::new(vec![FaultOperation::NetworkTraverse])?,
            phases: [FaultPhase::Resolve].into_iter().collect(),
            target_kinds: [FaultTargetKind::NetworkSegment].into_iter().collect(),
        }),
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        program,
    )?)
}

fn crash_binding(
    output: SignalId,
    program: &crucible::model::SignalProgram,
) -> Result<FaultBinding, Box<dyn Error>> {
    Ok(FaultBinding::new(
        object_id("crash-io-probe")?,
        vec![output],
        BindingSampling::AtEvent(crucible::model::BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        exact_target(ResolvedFaultTarget::Node {
            node: object_id("io-probe")?,
        })?,
        [FaultPhase::Boundary].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                transition: NodeLifecycleTransition::Crash,
                downtime_nanos: 100_000_000,
                boot_policy: NodeBootPolicy::Immediate,
                volatile_state_policy: NodeStatePolicy::Preserve,
                device_state_policy: NodeStatePolicy::Clear,
            }),
        )?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        program,
    )?)
}

fn exact_target(target: ResolvedFaultTarget) -> Result<TargetSelector, Box<dyn Error>> {
    Ok(TargetSelector::Exact(ResolvedTargetSet::new(
        vec![target],
        false,
    )?))
}

fn fault_topology() -> Result<crucible::model::WorldFaultTopology, Box<dyn Error>> {
    let curl_interface = signal_id("curl-if")?;
    let nginx_interface = signal_id("nginx-if")?;
    let probe_interface = signal_id("io-probe-if")?;
    let segment = signal_id("curl-nginx-segment")?;
    Ok(crucible::model::WorldFaultTopology {
        network_interfaces: vec![
            WorldNetworkInterface {
                id: curl_interface.clone(),
                endpoint: signal_id("curl")?,
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            },
            WorldNetworkInterface {
                id: nginx_interface.clone(),
                endpoint: signal_id("nginx")?,
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            },
            WorldNetworkInterface {
                id: probe_interface.clone(),
                endpoint: signal_id("io-probe")?,
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            },
        ],
        network_segments: vec![
            network_segment(segment, curl_interface.clone(), nginx_interface.clone()),
            network_segment(
                signal_id("probe-nginx-segment")?,
                probe_interface.clone(),
                nginx_interface,
            ),
            network_segment(
                signal_id("curl-probe-segment")?,
                curl_interface,
                probe_interface,
            ),
        ],
        storage_devices: vec![WorldStorageFaultDevice {
            id: signal_id("probe-block-contract")?,
            device: signal_id("probe-block")?,
            kind: WorldStorageKind::Block,
            persistence: WorldStoragePersistence {
                logical_block_bytes: 512,
                physical_sector_bytes: 4096,
                atomic_write_bytes: 512,
                length_bytes: BLOCK_BYTES as u64,
                discard_granularity_bytes: 4096,
                maximum_request_bytes: 65_536,
                volatile_cache_bytes: BLOCK_BYTES as u64,
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

fn network_segment(
    id: SignalId,
    interface_a: SignalId,
    interface_b: SignalId,
) -> WorldNetworkSegment {
    WorldNetworkSegment {
        id,
        kind: WorldNetworkSegmentKind::Ethernet,
        interface_a,
        interface_b,
        minimum_latency_nanos: 1,
        mtu_bytes: 1514,
        medium: None,
        forwarders: Vec::new(),
        fault_domains: Vec::new(),
    }
}

fn populate_store(root: &Path) -> Result<(), Box<dyn Error>> {
    let store = LocalDagStore::new(root);
    let block = block_artifact();
    let tree = ninep_artifact()?.canonical_bytes();
    let block_hash = store.put(&block)?;
    let ninep_hash = store.put(&tree)?;
    let scenario = representative_scenario()?;
    let expected = scenario
        .world()
        .io_nodes()
        .map(|node| match &node.kind {
            crucible::WorldIoNodeKind::Block { base_image, .. } => base_image.hash(),
            crucible::WorldIoNodeKind::NineP { tree, .. } => tree.hash(),
        })
        .collect::<Vec<_>>();
    if !expected.contains(&block_hash) || !expected.contains(&ninep_hash) {
        return Err("stored World I/O identities differ from the scenario".into());
    }
    println!("block={}", block_hash.to_hex());
    println!("ninep={}", ninep_hash.to_hex());
    Ok(())
}

fn block_artifact() -> Vec<u8> {
    let mut bytes = vec![0_u8; BLOCK_BYTES];
    bytes[..18].copy_from_slice(b"CRUCIBLE-BLOCK-OK\n");
    bytes
}

fn ninep_artifact() -> Result<FsTree, Box<dyn Error>> {
    let children = BTreeMap::from([(
        String::from("probe.txt"),
        NinePNode::File {
            content: b"CRUCIBLE-9P-OK\n".to_vec(),
        },
    )]);
    Ok(FsTree::try_new(NinePNode::Directory { children })?)
}

fn vm_node(name: &str, cmdline: String, white_box: WhiteBoxPolicy) -> WorldNode {
    WorldNode {
        id: node_id(name),
        arch: VmArchitecture::X86_64,
        memory_mib: 256,
        cmdline,
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: 7,
        kernel: Some(blob("aos-linux-crucible")),
        root_image: Some(blob("aos-e2e-determinism-root-image")),
        initrd: None,
    }
}

fn link(left: &str, right: &str) -> Result<LinkDef, Box<dyn Error>> {
    Ok(LinkDef::with_transport(
        node_id(left),
        node_id(right),
        SimDuration { nanos: 5_000_000 },
        SimDuration { nanos: 500_000 },
        LinkLossProbability::ZERO,
        Some(1_000_000_000),
    )?)
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn signal_id(value: &str) -> Result<SignalId, Box<dyn Error>> {
    Ok(SignalId::parse(value)?)
}

fn object_id(value: &str) -> Result<FaultObjectId, Box<dyn Error>> {
    Ok(FaultObjectId::parse(value)?)
}

fn positive(field: &'static str, value: u64) -> Result<PositiveU64, Box<dyn Error>> {
    Ok(PositiveU64::new(field, value)?)
}

fn blob(name: &str) -> ContentAddressedBlobRef {
    ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
        "crucible.e2e-determinism.asset.v1",
        name,
    ))
}
