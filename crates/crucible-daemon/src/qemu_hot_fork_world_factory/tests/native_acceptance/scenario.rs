//! Representative traffic and host-I/O scenario for native whole-world forks.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use crucible::model::{
    Aggregation, BoundarySelector, CohortPolicy, MeasurementDefinition, MeasurementDefinitions,
    MeasurementId, MeasurementInstanceKey, MetricDefinition, MetricId, MetricSource,
    MetricValueType, UnitId, WorldNodeDef,
};
use crucible::model::{
    BindingEventParent, BindingMapping, BindingObservabilityPolicy, BindingSampling,
    BindingSearchPolicy, DagStore, EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest,
    EffectSpecification, FaultAdapter, FaultBinding, FaultDirection, FaultObjectId, FaultOperation,
    FaultPhase, FaultResourceLimits, FaultSignalPlan, FaultTargetKind, NetworkEffectSpecification,
    NetworkForwarderTransition, NetworkStatePolicy, NinePResultKind, NodeBootPolicy,
    NodeEffectSpecification, NodeLifecycleTransition, NodeStatePolicy, OperationSet,
    OpportunityFilter, ResolvedFaultTarget, ResolvedTargetSet, SampleObservation, SignalCoordinate,
    SignalDomain, SignalId, SignalNode, SignalNodeKind, SignalPoint, SignalResourceLimits,
    SignalShape, SignalSourceSpecification, SignalUnit, SignalValue, SignalValueType,
    StorageEffectSpecification, StorageVolatileCacheLossKind, StorageVolatileCacheLossSelector,
    TargetSelector, WorldNetworkForwarder, WorldNetworkForwarderKind, WorldNetworkInterface,
    WorldNetworkPathHop, WorldNetworkQueue, WorldNetworkSegment, WorldNetworkTechnology,
    WorldStorageFaultDevice, WorldStorageKind,
};
use crucible::{
    AssertionDef, AssertionId, ContentAddressedBlobRef, ContentHash, LinkDef, LinkLossProbability,
    MarkerId, NodeId, Plan, Properties, Property, ScenarioDefForm, ScenarioSelectableLimits,
    ScenarioSelectables, Seed, SimDuration, World,
};
use crucible_campaign::{
    ChoiceClassContext, ChoiceDomain, ChoiceSource, ChoiceValue, ExactRational, IntegerDomain,
    IntegerRepresentation, IntegerValue, SelectableDeclaration,
};

pub(super) const PERMANENT_FAILURE_NANOS: u64 = 30_000_000_000;
pub(super) const NINEP_FAULT_WINDOW_NANOS: u64 = 5_000_000_000;
const NATIVE_LINK_LATENCY_NANOS: u64 = 5_000_000_000;
pub(super) const INACTIVE_WORLD_NANOS: u64 = 80_000_000_000;
pub(super) const REACTIVATION_NANOS: u64 = 81_000_000_000;

fn native_world(fixture: &str, kernel: &Path, root_image: &Path) -> Result<World, Box<dyn Error>> {
    // The reviewed Phase 4 fixture uses symbolic launch asset identities. Bind
    // the files selected by this native gate before deriving its new world ID.
    let base = ScenarioDefForm::from_canonical_toml(fixture)?;
    let kernel_identity = ContentHash::from_reader(File::open(kernel)?)?;
    let root_image_identity = ContentHash::from_reader(File::open(root_image)?)?;
    let mut nodes = base.world().nodes().to_vec();

    for node in &mut nodes {
        let WorldNodeDef::Vm(vm) = node else {
            continue;
        };
        if vm.kernel.is_none() || vm.root_image.is_none() {
            return Err("representative VM omits a reviewed launch asset".into());
        }
        vm.kernel = Some(ContentAddressedBlobRef::from_hash(kernel_identity));
        vm.root_image = Some(ContentAddressedBlobRef::from_hash(root_image_identity));
    }

    Ok(
        World::from_node_defs_and_links(nodes, base.world().links().to_vec())?
            .with_fault_topology(base.world().fault_topology().clone())?,
    )
}

/// Builds the native acceptance scenario from the reviewed three-node fixture.
pub(super) fn build(
    fixture: &str,
    artifacts: Arc<dyn DagStore>,
    kernel: &Path,
    root_image: &Path,
) -> Result<(ScenarioDefForm, Arc<dyn DagStore>), Box<dyn Error>> {
    let world = with_shared_fault_path(native_world(fixture, kernel, root_image)?)?;
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![
            AssertionDef::guest_sometimes(
                AssertionId::from_name("curl-receives-http-200"),
                "Curl receives an HTTP 200 response",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("curl-block-read-complete"),
                "Curl reads the block continuation",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("io-probe-complete"),
                "The I/O probe reads the 9p continuation",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("io-probe-fault-observed"),
                "The I/O probe observes the injected 9p error",
            ),
            AssertionDef {
                id: AssertionId::from_name("curl-remains-running"),
                message: String::from("Curl remains available"),
                property: Property::Always {
                    predicate: crucible::Predicate::not(crucible::Predicate::node_state(
                        node_id("curl"),
                        crucible::NodeLifecycle::Crashed,
                    )),
                },
            },
        ],
    )?;
    let plan = Plan::empty().with_fault_signals_for_world(&world, shared_fault_plan(&world)?)?;
    let source = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(0x000a_701c),
        0,
    )?;

    Ok((source, artifacts))
}

/// Builds the representative scenario with a pending typed choice and measurement window.
pub(super) fn build_equivalence(
    fixture: &str,
    artifacts: Arc<dyn DagStore>,
    kernel: &Path,
    root_image: &Path,
) -> Result<(ScenarioDefForm, Arc<dyn DagStore>), Box<dyn Error>> {
    let world = with_shared_fault_path(native_world(fixture, kernel, root_image)?)?;
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![
            AssertionDef::guest_sometimes(
                AssertionId::from_name("curl-receives-http-200"),
                "Curl receives an HTTP 200 response",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("curl-block-read-complete"),
                "Curl reads the block continuation",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("io-probe-complete"),
                "The I/O probe reads the 9p continuation",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("io-probe-fault-observed"),
                "The I/O probe observes the injected 9p error",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("hot-fork-continuation-complete"),
                "The selected continuation completes",
            ),
            AssertionDef {
                id: AssertionId::from_name("curl-remains-running"),
                message: String::from("Curl remains available"),
                property: Property::Always {
                    predicate: crucible::Predicate::not(crucible::Predicate::node_state(
                        node_id("curl"),
                        crucible::NodeLifecycle::Crashed,
                    )),
                },
            },
        ],
    )?;
    let plan = Plan::empty().with_fault_signals_for_world(&world, shared_fault_plan(&world)?)?;
    let measurements = equivalence_measurements(&world, &plan, &properties)?;
    let selectables = equivalence_selectables(&world)?;
    let source = ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        &measurements,
        Seed::from_u64(0x000a_701c),
        0,
    )?
    .with_selectables(selectables)?;

    Ok((source, artifacts))
}

/// Builds a one-VM production fixture with both block and 9p continuations.
pub(super) fn build_single_node_equivalence(
    fixture: &str,
    artifacts: Arc<dyn DagStore>,
    kernel: &Path,
    root_image: &Path,
) -> Result<(ScenarioDefForm, Arc<dyn DagStore>), Box<dyn Error>> {
    let world = native_world(fixture, kernel, root_image)?;
    let mut node = world
        .vm_nodes()
        .iter()
        .find(|node| node.id.name == "curl")
        .cloned()
        .ok_or("representative fixture has no curl VM")?;
    node.cmdline = String::from("console=ttyS0 crucible.workload=hot-fork-single");
    let owner = node.id.clone();
    let mut nodes = vec![WorldNodeDef::Vm(node)];
    nodes.extend(world.io_nodes().cloned().map(|mut io| {
        io.owner = owner.clone();
        WorldNodeDef::Io(io)
    }));
    let world = World::from_node_defs_and_links(nodes, Vec::new())?;
    let plan = Plan::empty();
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef::guest_sometimes(
            AssertionId::from_name("hot-fork-continuation-complete"),
            "The selected continuation completes",
        )],
    )?;
    let measurements = equivalence_measurements(&world, &plan, &properties)?;
    let selectables = equivalence_selectables(&world)?;
    let source = ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        &measurements,
        Seed::from_u64(0x000a_701d),
        0,
    )?
    .with_selectables(selectables)?;

    Ok((source, artifacts))
}

/// Builds the one-VM equivalence workload at an exact guest-memory size.
pub(super) fn build_single_node_equivalence_with_memory(
    fixture: &str,
    artifacts: Arc<dyn DagStore>,
    memory_mib: u32,
    kernel: &Path,
    root_image: &Path,
) -> Result<(ScenarioDefForm, Arc<dyn DagStore>), Box<dyn Error>> {
    let world = native_world(fixture, kernel, root_image)?;
    let mut node = world
        .vm_nodes()
        .iter()
        .find(|node| node.id.name == "curl")
        .cloned()
        .ok_or("representative fixture has no curl VM")?;
    node.cmdline = String::from("console=ttyS0 crucible.workload=hot-fork-single");
    node.memory_mib = memory_mib;
    let owner = node.id.clone();
    let mut nodes = vec![WorldNodeDef::Vm(node)];
    nodes.extend(world.io_nodes().cloned().map(|mut io| {
        io.owner = owner.clone();
        WorldNodeDef::Io(io)
    }));
    let world = World::from_node_defs_and_links(nodes, Vec::new())?;
    let plan = Plan::empty();
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef::guest_sometimes(
            AssertionId::from_name("hot-fork-continuation-complete"),
            "The selected continuation completes",
        )],
    )?;
    let measurements = equivalence_measurements(&world, &plan, &properties)?;
    let selectables = equivalence_selectables(&world)?;
    let source = ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        &measurements,
        Seed::from_u64(0x000a_701f + u64::from(memory_mib)),
        0,
    )?
    .with_selectables(selectables)?;

    Ok((source, artifacts))
}

/// Builds the one-VM workload with four ordered choices for depth scaling.
pub(super) fn build_single_node_scaling(
    fixture: &str,
    artifacts: Arc<dyn DagStore>,
    kernel: &Path,
    root_image: &Path,
) -> Result<(ScenarioDefForm, Arc<dyn DagStore>), Box<dyn Error>> {
    let world = native_world(fixture, kernel, root_image)?;
    let mut node = world
        .vm_nodes()
        .iter()
        .find(|node| node.id.name == "curl")
        .cloned()
        .ok_or("representative fixture has no curl VM")?;
    node.cmdline = String::from("console=ttyS0 crucible.workload=hot-fork-scaling");
    let world = World::from_node_defs_and_links(vec![WorldNodeDef::Vm(node)], Vec::new())?;
    let plan = Plan::empty();
    let properties = Properties::from_assertions_for_world(&world, Vec::new())?;
    let measurements = equivalence_measurements(&world, &plan, &properties)?;
    let selectables = equivalence_selectables(&world)?;
    let source = ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        &measurements,
        Seed::from_u64(0x000a_701e),
        0,
    )?
    .with_selectables(selectables)?;

    Ok((source, artifacts))
}

fn equivalence_measurements(
    world: &World,
    plan: &Plan,
    properties: &Properties,
) -> Result<MeasurementDefinitions, Box<dyn Error>> {
    Ok(MeasurementDefinitions::new(
        world,
        plan,
        properties,
        vec![MeasurementDefinition {
            id: MeasurementId::parse("hot-fork-window")?,
            begin: BoundarySelector::GuestMarker {
                marker: MarkerId::from_name("hot-fork-window-begin"),
                instance: Some(MeasurementInstanceKey::parse("instance-1")?),
            },
            end: BoundarySelector::GuestMarker {
                marker: MarkerId::from_name("hot-fork-window-end"),
                instance: Some(MeasurementInstanceKey::parse("instance-1")?),
            },
            timeout: None,
            cohort: CohortPolicy::All(vec![node_id("curl")]),
            metrics: vec![MetricDefinition {
                id: MetricId::parse("selected-retry")?,
                value_type: MetricValueType::UnsignedInteger,
                unit: UnitId::parse("samples")?,
                source: MetricSource::Guest,
                aggregation: Aggregation::Last,
            }],
        }],
    )?)
}

fn equivalence_selectables(world: &World) -> Result<ScenarioSelectables, Box<dyn Error>> {
    let retry_domain = ChoiceDomain::Integer(IntegerDomain::new(
        1,
        IntegerRepresentation::Unsigned64,
        IntegerValue::Unsigned(1),
        IntegerValue::Unsigned(9),
        2,
        Some(String::from("quanta")),
        ExactRational::new(1, 1)?,
        Vec::new(),
    )?);
    let declaration = SelectableDeclaration::new(
        "hot-fork.retry-quanta",
        ChoiceSource::Guest {
            node: String::from("curl"),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        retry_domain,
        ChoiceValue::Integer(IntegerValue::Unsigned(3)),
        ChoiceClassContext::new(BTreeSet::new())?,
        BTreeSet::from([String::from("hot-fork-equivalence")]),
        true,
    )?;
    Ok(ScenarioSelectables::new(
        world,
        ScenarioSelectableLimits::new(4, 8, 16, 32)?,
        vec![declaration],
    )?)
}

fn shared_fault_plan(world: &World) -> Result<FaultSignalPlan, Box<dyn Error>> {
    let event = signal_id("shared-power-loss")?;
    let ninep_fault = signal_id("ninep-read-fault")?;
    let inactive_event = signal_id("inactive-world")?;
    let boot_event = signal_id("reactivate-curl")?;
    let schema = signal_id("shared-power-loss-v1")?;
    let shared_event_node = SignalNode {
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
                    parent: Box::new(SignalCoordinate::VirtualTime {
                        ticks: PERMANENT_FAILURE_NANOS * crucible::SIM_TICKS_PER_NS,
                    }),
                    sequence: 0,
                },
                sequence: 0,
                value: SignalValue::Event {
                    schema,
                    payload: b"shared-power-loss".to_vec(),
                },
            }],
        }),
    };
    let ninep_node = SignalNode {
        id: ninep_fault.clone(),
        domain: SignalDomain::VirtualTime,
        output: SignalShape::new(
            SignalValueType::ProbabilityMillionths,
            SignalUnit::ProbabilityMillionths,
            0,
        )?,
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::Pulse {
            start: SignalCoordinate::VirtualTime {
                ticks: PERMANENT_FAILURE_NANOS * crucible::SIM_TICKS_PER_NS,
            },
            duration: NINEP_FAULT_WINDOW_NANOS * crucible::SIM_TICKS_PER_NS,
            inactive: SignalValue::ProbabilityMillionths(0),
            active: SignalValue::ProbabilityMillionths(1_000_000),
        }),
    };
    let inactive_node = event_node(
        inactive_event.clone(),
        "inactive-world-v1",
        b"inactive-world",
        INACTIVE_WORLD_NANOS,
    )?;
    let boot_node = event_node(
        boot_event.clone(),
        "reactivate-curl-v1",
        b"reactivate-curl",
        REACTIVATION_NANOS,
    )?;
    let program = crucible::model::SignalProgram::new(
        vec![shared_event_node, ninep_node, inactive_node, boot_node],
        vec![
            event.clone(),
            ninep_fault.clone(),
            inactive_event.clone(),
            boot_event.clone(),
        ],
        SignalResourceLimits::default(),
    )?;
    let block = world
        .io_nodes()
        .find(|node| node.id.name == "probe-block")
        .ok_or("representative fixture has no block node")?;
    let ninep = world
        .io_nodes()
        .find(|node| node.id.name == "probe-ninep")
        .ok_or("representative fixture has no 9p node")?;
    let bindings = vec![
        event_binding(
            "shared-power-network",
            &event,
            ResolvedFaultTarget::NetworkForwarder {
                forwarder: object_id("shared-forwarder")?,
            },
            EffectSpecification::Network(NetworkEffectSpecification::ForwarderLifecycle {
                transition: NetworkForwarderTransition::PowerLoss,
                downtime_nanos: crucible::model::PositiveU64::new(
                    "downtime_nanos",
                    NINEP_FAULT_WINDOW_NANOS,
                )?,
                queue_policy: NetworkStatePolicy::Clear,
                table_policy: NetworkStatePolicy::Clear,
            }),
            &program,
        )?,
        event_binding(
            "shared-power-block",
            &event,
            ResolvedFaultTarget::BlockDevice {
                device: block.fault_target_hash(),
            },
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
                node: object_id("nginx")?,
            },
            EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                transition: NodeLifecycleTransition::PermanentFailure,
                downtime_nanos: 0,
                boot_policy: NodeBootPolicy::Immediate,
                volatile_state_policy: NodeStatePolicy::Preserve,
                device_state_policy: NodeStatePolicy::Clear,
            }),
            &program,
        )?,
        FaultBinding::new(
            object_id("ninep-read-errno")?,
            vec![ninep_fault],
            BindingSampling::AtOpportunity,
            BindingMapping::Hazard,
            TargetSelector::Exact(ResolvedTargetSet::new(
                vec![ResolvedFaultTarget::NinePDevice {
                    device: ninep.fault_target_hash(),
                }],
                false,
            )?),
            [FaultPhase::Resolve].into_iter().collect(),
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::Opportunity,
                EffectSpecification::Storage(StorageEffectSpecification::NinePResult {
                    operations: OperationSet::new(vec![FaultOperation::StorageRead])?,
                    kind: NinePResultKind::Errno,
                    errno: Some(5),
                    version: None,
                    object: None,
                }),
            )?,
            Some(OpportunityFilter {
                adapter: FaultAdapter::Storage,
                operations: OperationSet::new(vec![FaultOperation::StorageRead])?,
                phases: [FaultPhase::Resolve].into_iter().collect(),
                target_kinds: [FaultTargetKind::NinePDevice].into_iter().collect(),
            }),
            BindingSearchPolicy::Fixed,
            BindingObservabilityPolicy {
                samples: SampleObservation::ChangesAndEffects,
                record_inactive_opportunities: false,
                retain_mapped_values: true,
            },
            &program,
        )?,
        event_binding(
            "inactive-power-off-curl",
            &inactive_event,
            ResolvedFaultTarget::Node {
                node: object_id("curl")?,
            },
            node_lifecycle(NodeLifecycleTransition::PowerOff),
            &program,
        )?,
        event_binding(
            "inactive-power-off-io-probe",
            &inactive_event,
            ResolvedFaultTarget::Node {
                node: object_id("io-probe")?,
            },
            node_lifecycle(NodeLifecycleTransition::PowerOff),
            &program,
        )?,
        event_binding(
            "reactivate-curl",
            &boot_event,
            ResolvedFaultTarget::Node {
                node: object_id("curl")?,
            },
            node_lifecycle(NodeLifecycleTransition::Boot),
            &program,
        )?,
    ];

    Ok(FaultSignalPlan::new(
        vec![program],
        bindings,
        FaultResourceLimits::default(),
    )?)
}

fn event_node(
    id: SignalId,
    schema: &str,
    payload: &[u8],
    nanos: u64,
) -> Result<SignalNode, Box<dyn Error>> {
    let schema = signal_id(schema)?;
    Ok(SignalNode {
        id,
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
                    parent: Box::new(SignalCoordinate::VirtualTime {
                        ticks: nanos * crucible::SIM_TICKS_PER_NS,
                    }),
                    sequence: 0,
                },
                sequence: 0,
                value: SignalValue::Event {
                    schema,
                    payload: payload.to_vec(),
                },
            }],
        }),
    })
}

fn node_lifecycle(transition: NodeLifecycleTransition) -> EffectSpecification {
    EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
        transition,
        downtime_nanos: 0,
        boot_policy: NodeBootPolicy::Immediate,
        volatile_state_policy: NodeStatePolicy::Preserve,
        device_state_policy: NodeStatePolicy::Clear,
    })
}

fn event_binding(
    id: &str,
    event: &SignalId,
    target: ResolvedFaultTarget,
    specification: EffectSpecification,
    program: &crucible::model::SignalProgram,
) -> Result<FaultBinding, Box<dyn Error>> {
    Ok(FaultBinding::new(
        object_id(id)?,
        vec![event.clone()],
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

fn with_shared_fault_path(world: World) -> Result<World, Box<dyn Error>> {
    let mut topology = world.fault_topology().clone();
    let block_contract = topology
        .storage_devices
        .iter()
        .find(|device| device.device.as_str() == "probe-block")
        .cloned()
        .ok_or("representative fixture has no block fault contract")?;
    topology.storage_devices.push(WorldStorageFaultDevice {
        id: signal_id("probe-ninep-contract")?,
        device: signal_id("probe-ninep")?,
        kind: WorldStorageKind::NineP,
        persistence: block_contract.persistence,
        media: block_contract.media,
        fault_domains: Vec::new(),
    });

    let forwarder = signal_id("shared-forwarder")?;
    let queue = signal_id("shared-egress")?;
    let left = signal_id("shared-forwarder-left")?;
    let right = signal_id("shared-forwarder-right")?;
    topology.network_interfaces.extend([
        WorldNetworkInterface {
            id: left.clone(),
            endpoint: forwarder.clone(),
            technology: WorldNetworkTechnology::Ethernet,
            addresses: Vec::new(),
            fault_domains: Vec::new(),
        },
        WorldNetworkInterface {
            id: right.clone(),
            endpoint: forwarder.clone(),
            technology: WorldNetworkTechnology::Ethernet,
            addresses: Vec::new(),
            fault_domains: Vec::new(),
        },
    ]);
    topology.network_forwarders.push(WorldNetworkForwarder {
        id: forwarder.clone(),
        kind: WorldNetworkForwarderKind::Router,
        ports: vec![left, right],
        table_capacity: 4096,
        fault_domains: Vec::new(),
    });
    topology.network_queues.push(WorldNetworkQueue {
        id: queue.clone(),
        owner: forwarder.clone(),
        capacity_packets: 4096,
        capacity_bytes: 4_194_304,
        discipline: crucible::model::WorldNetworkQueueDiscipline::Fifo,
        overflow: crucible::model::WorldNetworkQueueOverflow::DropTail,
        fault_domains: Vec::new(),
    });
    let replaced_segment = signal_id("curl-nginx-segment")?;
    let segment_index = topology
        .network_segments
        .iter()
        .position(|candidate| candidate.id == replaced_segment)
        .ok_or("representative fixture has no curl-nginx network segment")?;
    let declared_segment = topology.network_segments.remove(segment_index);
    let left_segment = signal_id("curl-shared-segment")?;
    let right_segment = signal_id("shared-nginx-segment")?;
    topology.network_segments.extend([
        WorldNetworkSegment {
            id: left_segment.clone(),
            kind: declared_segment.kind,
            interface_a: declared_segment.interface_a,
            interface_b: signal_id("shared-forwarder-left")?,
            minimum_latency_nanos: declared_segment.minimum_latency_nanos,
            mtu_bytes: declared_segment.mtu_bytes,
            medium: declared_segment.medium.clone(),
            forwarders: vec![forwarder.clone()],
            fault_domains: declared_segment.fault_domains.clone(),
        },
        WorldNetworkSegment {
            id: right_segment.clone(),
            kind: declared_segment.kind,
            interface_a: signal_id("shared-forwarder-right")?,
            interface_b: declared_segment.interface_b,
            minimum_latency_nanos: declared_segment.minimum_latency_nanos,
            mtu_bytes: declared_segment.mtu_bytes,
            medium: declared_segment.medium,
            forwarders: vec![forwarder.clone()],
            fault_domains: declared_segment.fault_domains,
        },
    ]);
    let mut inserted = false;
    for path in &mut topology.network_paths {
        if path
            .hops
            .iter()
            .any(|hop| matches!(hop, WorldNetworkPathHop::Segment { segment: candidate, .. } if candidate == &replaced_segment))
        {
            let mut hops = Vec::with_capacity(path.hops.len() + 3);
            for hop in path.hops.drain(..) {
                let WorldNetworkPathHop::Segment {
                    segment: candidate,
                    direction,
                } = &hop
                else {
                    hops.push(hop);
                    continue;
                };
                if candidate == &replaced_segment {
                    let (first, second) = match direction {
                        FaultDirection::AToB => (&left_segment, &right_segment),
                        FaultDirection::BToA => (&right_segment, &left_segment),
                        _ => {
                            return Err(
                                "network segment path uses a non-segment direction".into()
                            );
                        }
                    };
                    hops.push(WorldNetworkPathHop::Segment {
                        segment: first.clone(),
                        direction: *direction,
                    });
                    hops.push(WorldNetworkPathHop::Forwarder {
                        forwarder: forwarder.clone(),
                    });
                    hops.push(WorldNetworkPathHop::Queue {
                        queue: queue.clone(),
                    });
                    hops.push(WorldNetworkPathHop::Segment {
                        segment: second.clone(),
                        direction: *direction,
                    });
                    inserted = true;
                } else {
                    hops.push(hop);
                }
            }
            path.hops = hops;
        }
    }
    if !inserted {
        return Err("representative fixture has no curl-nginx network path".into());
    }

    let links = world
        .links()
        .iter()
        .map(|link| {
            let (left, right) = link.endpoints();
            LinkDef::with_transport(
                left.clone(),
                right.clone(),
                SimDuration {
                    ticks: NATIVE_LINK_LATENCY_NANOS * crucible::SIM_TICKS_PER_NS,
                },
                SimDuration { ticks: 0 },
                LinkLossProbability::ZERO,
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(
        World::from_node_defs_and_links(world.nodes().to_vec(), links)?
            .with_fault_topology(topology)?,
    )
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn signal_id(name: &str) -> Result<SignalId, Box<dyn Error>> {
    Ok(SignalId::parse(name)?)
}

fn object_id(name: &str) -> Result<FaultObjectId, Box<dyn Error>> {
    Ok(FaultObjectId::parse(name)?)
}

#[test]
fn native_world_binds_selected_launch_asset_bytes() {
    let fixture =
        include_str!("../../../../../../tests/crucible/fixtures/e2e-determinism.scenario.toml");
    let base = ScenarioDefForm::from_canonical_toml(fixture).expect("parse reviewed scenario");
    let directory = tempfile::tempdir().expect("create test directory");
    let kernel = directory.path().join("kernel");
    let root_image = directory.path().join("root.ext4");
    std::fs::write(&kernel, b"selected kernel bytes").expect("write selected kernel");
    std::fs::write(&root_image, b"selected root bytes").expect("write selected root image");

    let world = native_world(fixture, &kernel, &root_image).expect("bind selected assets");
    let expected_kernel = ContentHash::from_bytes(b"selected kernel bytes");
    let expected_root = ContentHash::from_bytes(b"selected root bytes");

    assert_ne!(world.id(), base.world().id());
    assert_eq!(world.links(), base.world().links());
    assert_eq!(world.fault_topology(), base.world().fault_topology());
    for node in world.vm_nodes().iter() {
        assert_eq!(
            node.kernel.map(ContentAddressedBlobRef::hash),
            Some(expected_kernel)
        );
        assert_eq!(
            node.root_image.map(ContentAddressedBlobRef::hash),
            Some(expected_root)
        );
    }
}

#[test]
fn representative_world_admits_the_shared_fault_path() {
    let fixture =
        include_str!("../../../../../../tests/crucible/fixtures/e2e-determinism.scenario.toml");
    let base = ScenarioDefForm::from_canonical_toml(fixture).expect("parse reviewed scenario");
    let world = with_shared_fault_path(base.world().clone()).expect("build shared fault topology");
    let topology = world.fault_topology();

    assert!(world.links().iter().all(|link| {
        link.latency().ticks == NATIVE_LINK_LATENCY_NANOS * crucible::SIM_TICKS_PER_NS
            && link.jitter().ticks == 0
            && link.loss() == LinkLossProbability::ZERO
            && link.bandwidth_bps().is_none()
    }));

    assert!(
        topology
            .network_forwarders
            .iter()
            .any(|forwarder| forwarder.id.as_str() == "shared-forwarder")
    );
    assert!(
        topology
            .network_queues
            .iter()
            .any(|queue| queue.id.as_str() == "shared-egress")
    );
    assert!(topology.network_paths.iter().any(|path| {
        path.hops.iter().any(|hop| {
            matches!(hop, WorldNetworkPathHop::Forwarder { forwarder }
                if forwarder.as_str() == "shared-forwarder")
        })
    }));
}
