//! Tests for world-owned fault topology validation.

use super::*;

fn id(value: &str) -> SignalId {
    SignalId::parse(value)
        .unwrap_or_else(|error| panic!("test signal ID should be canonical: {error}"))
}

fn two_endpoint_topology() -> WorldFaultTopology {
    WorldFaultTopology {
        network_interfaces: vec![
            WorldNetworkInterface {
                id: id("if-a"),
                endpoint: id("vm-a"),
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            },
            WorldNetworkInterface {
                id: id("if-b"),
                endpoint: id("vm-b"),
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            },
        ],
        network_segments: vec![WorldNetworkSegment {
            id: id("segment-ab"),
            kind: WorldNetworkSegmentKind::Ethernet,
            interface_a: id("if-a"),
            interface_b: id("if-b"),
            minimum_latency_nanos: 1,
            mtu_bytes: 1500,
            medium: None,
            forwarders: Vec::new(),
            fault_domains: Vec::new(),
        }],
        network_paths: vec![
            WorldNetworkPath {
                id: id("path-ab"),
                direction: FaultDirection::AToB,
                hops: vec![WorldNetworkPathHop::Segment {
                    segment: id("segment-ab"),
                    direction: FaultDirection::AToB,
                }],
                mtu_bytes: 1500,
            },
            WorldNetworkPath {
                id: id("path-ba"),
                direction: FaultDirection::BToA,
                hops: vec![WorldNetworkPathHop::Segment {
                    segment: id("segment-ab"),
                    direction: FaultDirection::BToA,
                }],
                mtu_bytes: 1500,
            },
        ],
        ..WorldFaultTopology::default()
    }
}

#[test]
fn route_fault_targets_preserve_physical_order_and_direction() {
    let topology = two_endpoint_topology();
    let forward = topology
        .network_route_fault_targets("vm-a", "vm-b", 0)
        .unwrap_or_else(|error| panic!("forward route should resolve: {error}"));
    assert_eq!(forward.len(), 4);
    assert!(matches!(
        &forward[0].target,
        ResolvedFaultTarget::NetworkInterface { endpoint, interface }
            if endpoint.as_str() == "vm-a" && interface.as_str() == "if-a"
    ));
    assert_eq!(forward[0].direction, FaultDirection::Egress);
    assert!(matches!(
        &forward[2].target,
        ResolvedFaultTarget::NetworkSegment { segment, direction }
            if segment.as_str() == "segment-ab" && *direction == FaultDirection::AToB
    ));
    assert_eq!(forward[3].direction, FaultDirection::Ingress);
    assert_eq!(
        forward[2].phases(),
        &[
            FaultPhase::Admit,
            FaultPhase::Queue,
            FaultPhase::Resolve,
            FaultPhase::Deliver,
        ]
    );

    let reverse = topology
        .network_route_fault_targets("vm-b", "vm-a", 0)
        .unwrap_or_else(|error| panic!("reverse route should resolve: {error}"));
    assert!(matches!(
        &reverse[2].target,
        ResolvedFaultTarget::NetworkSegment { direction, .. }
            if *direction == FaultDirection::BToA
    ));
}

#[test]
fn route_fault_targets_require_a_declared_path() {
    let topology = two_endpoint_topology();
    let missing = FaultObjectId::parse("missing-path")
        .unwrap_or_else(|error| panic!("test path should be valid: {error}"));
    assert!(matches!(
        topology.network_route_fault_targets_with_path("vm-a", "vm-b", 0, Some(&missing)),
        Err(WorldFaultTopologyError::Invalid(
            "network route path override"
        ))
    ));
    assert!(
        WorldFaultTopology::default()
            .network_route_fault_targets("vm-a", "vm-b", 0)
            .unwrap_or_else(|error| panic!("empty topology should remain inert: {error}"))
            .is_empty()
    );
}

#[test]
fn route_fault_targets_select_one_path_and_only_its_explicit_queues() {
    let mut topology = two_endpoint_topology();
    for queue in ["explicit-queue", "owner-only-queue"] {
        topology.network_queues.push(WorldNetworkQueue {
            id: id(queue),
            owner: id("if-a"),
            capacity_packets: 8,
            capacity_bytes: 4096,
            discipline: WorldNetworkQueueDiscipline::Fifo,
            overflow: WorldNetworkQueueOverflow::DropTail,
            fault_domains: Vec::new(),
        });
    }
    topology.network_paths.extend([
        WorldNetworkPath {
            id: id("path-a"),
            direction: FaultDirection::AToB,
            hops: vec![
                WorldNetworkPathHop::Segment {
                    segment: id("segment-ab"),
                    direction: FaultDirection::AToB,
                },
                WorldNetworkPathHop::Queue {
                    queue: id("explicit-queue"),
                },
            ],
            mtu_bytes: 1500,
        },
        WorldNetworkPath {
            id: id("path-z"),
            direction: FaultDirection::AToB,
            hops: vec![WorldNetworkPathHop::Segment {
                segment: id("segment-ab"),
                direction: FaultDirection::AToB,
            }],
            mtu_bytes: 1500,
        },
    ]);

    let route = topology
        .network_route_fault_targets("vm-a", "vm-b", 0)
        .unwrap_or_else(|error| panic!("direct route should resolve: {error}"));
    assert_eq!(route.len(), 5);
    assert!(route.iter().any(|stage| matches!(
        &stage.target,
        ResolvedFaultTarget::NetworkPath { path_version, .. }
            if path_version.as_str() == "path-a"
    )));
    assert!(route.iter().any(|stage| matches!(
        &stage.target,
        ResolvedFaultTarget::NetworkQueue { queue, .. }
            if queue.as_str() == "explicit-queue"
    )));
    assert!(route.iter().all(|stage| !matches!(
        &stage.target,
        ResolvedFaultTarget::NetworkPath { path_version, .. }
            if path_version.as_str() == "path-z"
    )));
    assert!(route.iter().all(|stage| !matches!(
        &stage.target,
        ResolvedFaultTarget::NetworkQueue { queue, .. }
            if queue.as_str() == "owner-only-queue"
    )));
}

#[test]
fn node_dram_geometry_accepts_only_the_live_qemu_mapping() {
    WorldNodeDramGeometry::qemu_v1()
        .validate()
        .unwrap_or_else(|error| panic!("live QEMU geometry should validate: {error}"));

    let unsupported = WorldNodeDramGeometry {
        channels: 4,
        ..WorldNodeDramGeometry::qemu_v1()
    };
    assert!(matches!(
        unsupported.validate(),
        Err(WorldFaultTopologyError::Invalid(
            "node DRAM geometry must match qemu 2c2r16b64"
        ))
    ));
}

fn node_capabilities_with_register(register: WorldNodeRegister) -> WorldNodeFaultCapabilities {
    WorldNodeFaultCapabilities {
        id: id("node-capabilities"),
        node: id("vm-a"),
        architecture: WorldNodeArchitecture::X86_64,
        cpu_model: "crucible-x86-64-v1".to_owned(),
        register_schema: ContentHash::default(),
        registers: vec![register],
        address_spaces: vec![WorldNodeAddressSpace {
            id: id("guest-ram"),
            start_address: 0,
            length_bytes: 4096,
        }],
        page_bytes: 4096,
        dram_geometry: WorldNodeDramGeometry::qemu_v1(),
        interrupts: Vec::new(),
        clock_sources: Vec::new(),
        accelerators: Vec::new(),
        semantic_version: 1,
    }
}

#[test]
fn node_register_manifest_distinguishes_writable_and_reference_only_rows() {
    let reference_only = WorldNodeRegister {
        id: id("implementation-status"),
        name: "implementation-status".to_owned(),
        numeric_id: 1,
        group: WorldNodeRegisterGroup::System,
        width_bits: 8,
        per_vcpu: true,
        model_phases: Vec::new(),
        side_effects: Vec::new(),
        impulse: false,
        persistent: false,
        vmstate: false,
        writable_mask_hex: "00".to_owned(),
        reserved_mask_hex: "00".to_owned(),
        ignored_mask_hex: "00".to_owned(),
        read_only_mask_hex: "ff".to_owned(),
    };
    node_capabilities_with_register(reference_only.clone())
        .validate()
        .unwrap_or_else(|error| panic!("reference-only register should validate: {error}"));

    let mut falsely_mutable = reference_only;
    falsely_mutable.impulse = true;
    assert!(matches!(
        node_capabilities_with_register(falsely_mutable).validate(),
        Err(WorldFaultTopologyError::Invalid(
            "node register mask partition"
        ))
    ));

    let writable = WorldNodeRegister {
        id: id("rax"),
        name: "rax".to_owned(),
        numeric_id: 2,
        group: WorldNodeRegisterGroup::GeneralPurpose,
        width_bits: 8,
        per_vcpu: true,
        model_phases: vec![FaultPhase::BeforeInstruction],
        side_effects: Vec::new(),
        impulse: true,
        persistent: false,
        vmstate: true,
        writable_mask_hex: "0f".to_owned(),
        reserved_mask_hex: "30".to_owned(),
        ignored_mask_hex: "40".to_owned(),
        read_only_mask_hex: "80".to_owned(),
    };
    assert!(writable.range_is_writable(0, 4));
    assert!(!writable.range_is_writable(3, 2));
    node_capabilities_with_register(writable)
        .validate()
        .unwrap_or_else(|error| panic!("writable register should validate: {error}"));
}

fn reference_only_register() -> WorldNodeRegister {
    WorldNodeRegister {
        id: id("implementation-status"),
        name: "implementation-status".to_owned(),
        numeric_id: 1,
        group: WorldNodeRegisterGroup::System,
        width_bits: 8,
        per_vcpu: true,
        model_phases: Vec::new(),
        side_effects: Vec::new(),
        impulse: false,
        persistent: false,
        vmstate: false,
        writable_mask_hex: "00".to_owned(),
        reserved_mask_hex: "00".to_owned(),
        ignored_mask_hex: "00".to_owned(),
        read_only_mask_hex: "ff".to_owned(),
    }
}

fn x86_interrupt() -> WorldNodeInterrupt {
    WorldNodeInterrupt {
        id: id("timer-route"),
        controller: id("local-apic"),
        source: id("lapic-timer"),
        controller_version: "qemu-x86-local-apic-v1".to_owned(),
        family: WorldNodeInterruptFamily::X86Timer,
        vector_start: 32,
        vector_end: 255,
        replacement_vector_start: 32,
        replacement_vector_end: 255,
        trigger: WorldNodeInterruptTrigger::Edge,
        polarity: WorldNodeInterruptPolarity::ActiveHigh,
        target_vcpus: vec![0, 1],
        model_phases: vec![
            FaultPhase::Raise,
            FaultPhase::Route,
            FaultPhase::InterruptDeliver,
        ],
        priority: 128,
        delivery_drop: WorldNodeInterruptDeliveryDrop::ConsumeEdge,
        vmstate: true,
    }
}

#[test]
fn node_interrupt_manifest_is_closed_and_architecture_specific() {
    let mut capabilities = node_capabilities_with_register(reference_only_register());
    capabilities.interrupts = vec![x86_interrupt()];
    capabilities
        .validate()
        .unwrap_or_else(|error| panic!("complete x86 interrupt row should validate: {error}"));

    let mut wrong_architecture = capabilities.clone();
    wrong_architecture.architecture = WorldNodeArchitecture::Aarch64;
    assert!(matches!(
        wrong_architecture.validate(),
        Err(WorldFaultTopologyError::Invalid(
            "node interrupt architecture family"
        ))
    ));

    let mut impossible_trigger = capabilities.clone();
    impossible_trigger.interrupts[0].family = WorldNodeInterruptFamily::X86Msi;
    impossible_trigger.interrupts[0].trigger = WorldNodeInterruptTrigger::Level;
    impossible_trigger.interrupts[0].delivery_drop =
        WorldNodeInterruptDeliveryDrop::RependAssertedLevel;
    assert!(matches!(
        impossible_trigger.validate(),
        Err(WorldFaultTopologyError::Invalid(
            "node interrupt architecture trigger"
        ))
    ));

    let mut uncheckpointed = capabilities.clone();
    uncheckpointed.interrupts[0].vmstate = false;
    assert!(matches!(
        uncheckpointed.validate(),
        Err(WorldFaultTopologyError::Invalid(
            "node interrupt VMState coverage"
        ))
    ));

    let mut bad_range = capabilities;
    bad_range.interrupts[0].replacement_vector_end = 31;
    assert!(matches!(
        bad_range.validate(),
        Err(WorldFaultTopologyError::Invalid(
            "node interrupt vector range"
        ))
    ));
}
