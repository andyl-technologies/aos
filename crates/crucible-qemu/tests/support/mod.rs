//! Shared exact fault-capability fixtures for launch integration tests.

#![allow(dead_code)]

use crucible::model::{
    ContentHash, FaultPhase, SignalId, WorldNodeArchitecture, WorldNodeClockSource,
    WorldNodeDramGeometry, WorldNodeFaultCapabilities, WorldNodeRegister, WorldNodeRegisterGroup,
};
use crucible_qemu::QemuFaultCapabilityRequirement;
use crucible_shmem::{
    FAULT_REGISTER_CAPABILITY_IMPULSE, FAULT_REGISTER_CAPABILITY_VMSTATE, FaultCapabilityScope,
    FaultRegisterCapabilityManifestV1, FaultRegisterCapabilityRowV1, FaultRegisterGroupV1,
};

/// Returns one canonical x86-64 World declaration for launch-only tests.
pub fn x86_fault_node(node_name: &str, realized_cpu_type: &str) -> WorldNodeFaultCapabilities {
    let manifest = FaultRegisterCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        cpu_model: realized_cpu_type.to_owned(),
        rows: vec![FaultRegisterCapabilityRowV1 {
            numeric_id: 1,
            name: "rax".to_owned(),
            width_bits: 8,
            group: FaultRegisterGroupV1::GeneralPurpose,
            model_phase_mask: 1 << (11 - 1),
            side_effects: 0,
            capabilities: FAULT_REGISTER_CAPABILITY_IMPULSE | FAULT_REGISTER_CAPABILITY_VMSTATE,
            writable_mask: vec![0x0f],
            reserved_mask: vec![0x30],
            ignored_mask: vec![0x40],
            read_only_mask: vec![0x80],
        }],
    };
    let encoded = manifest
        .encode()
        .unwrap_or_else(|error| panic!("test manifest should encode: {error}"));
    let id = |value: &str| {
        SignalId::parse(value)
            .unwrap_or_else(|error| panic!("test signal ID should be canonical: {error}"))
    };
    WorldNodeFaultCapabilities {
        id: id("node-capabilities"),
        node: id(node_name),
        architecture: WorldNodeArchitecture::X86_64,
        cpu_model: manifest.cpu_model,
        register_schema: ContentHash::from_bytes(&encoded),
        registers: vec![WorldNodeRegister {
            id: id("rax"),
            name: "rax".to_owned(),
            numeric_id: 1,
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
        }],
        address_spaces: Vec::new(),
        page_bytes: 4096,
        dram_geometry: WorldNodeDramGeometry::qemu_v1(),
        interrupts: Vec::new(),
        hardware_errors: Vec::new(),
        clock_sources: vec![WorldNodeClockSource::qemu_x86_tsc_v1(id("x86-tsc-vcpu-0"))],
        accelerators: Vec::new(),
        ready_markers: Vec::new(),
        semantic_version: 1,
    }
}

/// Returns the exact production requirement for one launch-only fixture.
pub fn x86_fault_requirement(
    node_name: &str,
    realized_cpu_type: &str,
) -> QemuFaultCapabilityRequirement {
    QemuFaultCapabilityRequirement::current_v1_for_node(&x86_fault_node(
        node_name,
        realized_cpu_type,
    ))
    .unwrap_or_else(|error| panic!("test fault capability should bind: {error}"))
}
