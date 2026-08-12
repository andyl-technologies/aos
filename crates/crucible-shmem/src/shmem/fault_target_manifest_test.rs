//! Codec, golden-vector, and hostile manifest tests.
use super::*;

const REGISTER_MANIFEST_GOLDEN_HEX: &str =
    include_str!("../../tests/fixtures/fault_register_manifest_v1.hex");

fn row(name: &str, numeric_id: u32) -> FaultRegisterCapabilityRowV1 {
    FaultRegisterCapabilityRowV1 {
        numeric_id,
        name: name.to_owned(),
        width_bits: 8,
        group: FaultRegisterGroupV1::GeneralPurpose,
        model_phase_mask: 1 << (13 - 1),
        side_effects: 0,
        capabilities: FAULT_REGISTER_CAPABILITY_IMPULSE | FAULT_REGISTER_CAPABILITY_VMSTATE,
        writable_mask: vec![0x0f],
        reserved_mask: vec![0x30],
        ignored_mask: vec![0x40],
        read_only_mask: vec![0x80],
    }
}

fn interrupt_row(id: &str, vector: u32) -> FaultInterruptCapabilityRowV1 {
    FaultInterruptCapabilityRowV1 {
        id: id.to_owned(),
        controller: "local-apic".to_owned(),
        source: "lapic-timer".to_owned(),
        controller_version: "qemu-x86-local-apic-v1".to_owned(),
        family: FaultInterruptFamilyV1::X86Timer,
        vector_start: vector,
        vector_end: vector,
        replacement_vector_start: 32,
        replacement_vector_end: 255,
        trigger: FaultInterruptTriggerV1::Edge,
        polarity: FaultInterruptPolarityV1::ActiveHigh,
        target_vcpus: vec![0, 1],
        model_phase_mask: (1 << (23 - 1)) | (1 << (24 - 1)) | (1 << (26 - 1)),
        priority: 128,
        delivery_drop: FaultInterruptDeliveryDropV1::ConsumeEdge,
        vmstate: true,
    }
}

fn hardware_row(id: &str, corrected: bool) -> FaultHardwareErrorCapabilityRowV1 {
    FaultHardwareErrorCapabilityRowV1 {
        id: id.to_owned(),
        bank: "x86.mca.bank".to_owned(),
        channel: "x86.memory.channel".to_owned(),
        rank: "x86.memory.rank".to_owned(),
        firmware: "x86-mca".to_owned(),
        state: "x86-mca-bank-record".to_owned(),
        record_kind: FaultHardwareErrorRecordKindV1::X86MachineCheck,
        error_class: if corrected {
            FaultHardwareErrorClassV1::Corrected
        } else {
            FaultHardwareErrorClassV1::Recoverable
        },
        mechanism: FaultHardwareErrorMechanismV1::X86Mca,
        visibility_mask: if corrected {
            FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY
        } else {
            FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION
        },
        bank_number: 0,
        bank_count: 10,
        vector: 18,
        status_required: 1 << 63,
        status_allowed: u64::MAX,
        syndrome_required: 0,
        syndrome_allowed: u32::MAX.into(),
        model_phase_mask: 1 << (11 - 1),
        privilege_mask: FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK,
        corrected,
        maskable: false,
        vmstate: true,
    }
}

fn complete_x86_hardware_rows() -> Vec<FaultHardwareErrorCapabilityRowV1> {
    let mut fatal = hardware_row("x86.machine-check.fatal", false);
    fatal.error_class = FaultHardwareErrorClassV1::Fatal;
    fatal.status_required |= 1 << 57;
    vec![
        hardware_row("x86.machine-check.corrected", true),
        fatal,
        hardware_row("x86.machine-check.recoverable", false),
    ]
}

#[test]
fn query_codec_rejects_unknown_kinds_and_reserved_bytes() {
    let query = FaultTargetManifestQueryV1 {
        kind: FaultTargetManifestKind::Register,
    };
    let encoded = query.encode();
    assert_eq!(FaultTargetManifestQueryV1::decode(&encoded), Ok(query));
    let interrupt_query = FaultTargetManifestQueryV1 {
        kind: FaultTargetManifestKind::Interrupt,
    };
    assert_eq!(
        FaultTargetManifestQueryV1::decode(&interrupt_query.encode()),
        Ok(interrupt_query)
    );
    let hardware_query = FaultTargetManifestQueryV1 {
        kind: FaultTargetManifestKind::HardwareError,
    };
    assert_eq!(
        FaultTargetManifestQueryV1::decode(&hardware_query.encode()),
        Ok(hardware_query)
    );
    let clock_query = FaultTargetManifestQueryV1 {
        kind: FaultTargetManifestKind::Clock,
    };
    assert_eq!(
        FaultTargetManifestQueryV1::decode(&clock_query.encode()),
        Ok(clock_query)
    );

    let mut unknown = encoded;
    unknown[10..12].copy_from_slice(&99_u16.to_le_bytes());
    assert_eq!(
        FaultTargetManifestQueryV1::decode(&unknown),
        Err(FaultAbiError::CapabilityInvariant)
    );
    let mut reserved = encoded;
    reserved[15] = 1;
    assert_eq!(
        FaultTargetManifestQueryV1::decode(&reserved),
        Err(FaultAbiError::ReservedNonzero)
    );
}

#[test]
fn register_manifest_round_trips_canonical_rows_and_masks() {
    let manifest = FaultRegisterCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        cpu_model: "crucible-x86-64-v1".to_owned(),
        rows: vec![row("rax", 1), row("rbx", 2)],
    };
    let encoded = manifest
        .encode()
        .unwrap_or_else(|error| panic!("manifest should encode: {error}"));
    assert_eq!(
        FaultRegisterCapabilityManifestV1::decode(&encoded),
        Ok(manifest)
    );
}

#[test]
fn register_manifest_carries_non_writable_rows_without_mutation_hooks() {
    let read_only = FaultRegisterCapabilityRowV1 {
        numeric_id: 1,
        name: "implementation-status".to_owned(),
        width_bits: 8,
        group: FaultRegisterGroupV1::System,
        model_phase_mask: 0,
        side_effects: 0,
        capabilities: FAULT_REGISTER_CAPABILITY_VMSTATE,
        writable_mask: vec![0],
        reserved_mask: vec![0],
        ignored_mask: vec![0],
        read_only_mask: vec![u8::MAX],
    };
    let manifest = FaultRegisterCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        cpu_model: "crucible-x86-64-v1".to_owned(),
        rows: vec![read_only.clone()],
    };
    let encoded = manifest
        .encode()
        .unwrap_or_else(|error| panic!("read-only row should encode: {error}"));
    assert_eq!(
        FaultRegisterCapabilityManifestV1::decode(&encoded),
        Ok(manifest)
    );

    let mut incorrectly_mutable = read_only;
    incorrectly_mutable.capabilities |= FAULT_REGISTER_CAPABILITY_IMPULSE;
    assert_eq!(
        FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            cpu_model: "crucible-x86-64-v1".to_owned(),
            rows: vec![incorrectly_mutable],
        }
        .encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );
}

#[test]
fn register_manifest_golden_vector_is_frozen() {
    let manifest = FaultRegisterCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        cpu_model: "crucible-x86-64-v1".to_owned(),
        rows: vec![row("rax", 1), row("rbx", 2)],
    };
    let encoded = manifest
        .encode()
        .unwrap_or_else(|error| panic!("golden manifest should encode: {error}"));
    let actual = encoded
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(actual, REGISTER_MANIFEST_GOLDEN_HEX.trim());
    assert_eq!(
        FaultRegisterCapabilityManifestV1::decode(&encoded),
        Ok(manifest)
    );
}

#[test]
fn register_manifest_rejects_overlap_gaps_order_and_digest_drift() {
    let mut overlapping = row("rax", 1);
    overlapping.reserved_mask[0] |= 1;
    assert_eq!(
        FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            cpu_model: "crucible-x86-64-v1".to_owned(),
            rows: vec![overlapping],
        }
        .encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let unsorted = FaultRegisterCapabilityManifestV1 {
        architecture: FaultCapabilityScope::Aarch64,
        cpu_model: "crucible-aarch64-v1".to_owned(),
        rows: vec![row("x1", 2), row("x0", 1)],
    };
    assert_eq!(unsorted.encode(), Err(FaultAbiError::CapabilityInvariant));

    let duplicate_id = FaultRegisterCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        cpu_model: "crucible-x86-64-v1".to_owned(),
        rows: vec![row("rax", 1), row("rbx", 1)],
    };
    assert_eq!(
        duplicate_id.encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let duplicate_name = FaultRegisterCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        cpu_model: "crucible-x86-64-v1".to_owned(),
        rows: vec![row("rax", 1), row("rax", 2)],
    };
    assert_eq!(
        duplicate_name.encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let valid = FaultRegisterCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        cpu_model: "crucible-x86-64-v1".to_owned(),
        rows: vec![row("rax", 1)],
    };
    let mut corrupt = valid
        .encode()
        .unwrap_or_else(|error| panic!("manifest should encode: {error}"));
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert_eq!(
        FaultRegisterCapabilityManifestV1::decode(&corrupt),
        Err(FaultAbiError::PayloadDigest)
    );
}

#[test]
fn interrupt_manifest_round_trips_and_rejects_incomplete_controller_semantics() {
    let manifest = FaultInterruptCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        rows: vec![
            interrupt_row("timer-route-a", 48),
            interrupt_row("timer-route-b", 49),
        ],
    };
    let encoded = manifest
        .encode()
        .unwrap_or_else(|error| panic!("interrupt manifest should encode: {error}"));
    assert_eq!(
        FaultInterruptCapabilityManifestV1::decode(&encoded),
        Ok(manifest.clone())
    );

    let mut wrong_architecture = manifest.clone();
    wrong_architecture.architecture = FaultCapabilityScope::Aarch64;
    assert_eq!(
        wrong_architecture.encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let mut unsorted_targets = manifest.clone();
    unsorted_targets.rows[0].target_vcpus = vec![1, 0];
    assert_eq!(
        unsorted_targets.encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let mut missing_vmstate = manifest.clone();
    missing_vmstate.rows[0].vmstate = false;
    assert_eq!(
        missing_vmstate.encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let mut corrupt = encoded;
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert_eq!(
        FaultInterruptCapabilityManifestV1::decode(&corrupt),
        Err(FaultAbiError::PayloadDigest)
    );
}

#[test]
fn hardware_error_manifest_round_trips_real_mca_rows() {
    let manifest = FaultHardwareErrorCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        rows: complete_x86_hardware_rows(),
    };
    let encoded = manifest
        .encode()
        .unwrap_or_else(|error| panic!("hardware manifest should encode: {error}"));
    assert_eq!(
        FaultHardwareErrorCapabilityManifestV1::decode(&encoded),
        Ok(manifest)
    );

    let empty = FaultHardwareErrorCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        rows: Vec::new(),
    };
    let encoded_empty = empty
        .encode()
        .unwrap_or_else(|error| panic!("empty realized manifest should encode: {error}"));
    assert_eq!(
        FaultHardwareErrorCapabilityManifestV1::decode(&encoded_empty),
        Ok(empty)
    );
}

#[test]
fn clock_manifest_round_trips_and_rejects_noncanonical_sources() {
    let row = |id: &str| FaultClockCapabilityRowV1 {
        id: id.to_owned(),
        implementation: "target/i386/tcg".to_owned(),
        source_kind: 1,
        base_domain: 1,
        timer_relationship: 0,
        width_bits: 64,
        flags: 0,
        frequency_numerator: 1_000_000_000,
        frequency_denominator: 1,
        model_phase_mask: 1 << (28 - 1),
        vmstate: true,
        monotonicity: 2,
    };
    let manifest = FaultClockCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        rows: vec![row("x86-tsc")],
    };
    let encoded = manifest
        .encode()
        .unwrap_or_else(|error| panic!("clock manifest should encode: {error}"));
    assert_eq!(
        FaultClockCapabilityManifestV1::decode(&encoded),
        Ok(manifest.clone())
    );

    let mut duplicate = manifest.clone();
    duplicate.rows.push(row("x86-tsc"));
    assert_eq!(duplicate.encode(), Err(FaultAbiError::CapabilityInvariant));
    let mut invalid_monotonicity = manifest;
    invalid_monotonicity.rows[0].monotonicity = 0;
    assert_eq!(
        invalid_monotonicity.encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );
}

#[test]
fn accelerator_manifest_round_trips_and_rejects_incomplete_devices() {
    let row = FaultAcceleratorCapabilityRowV1 {
        id: "accelerator-0".to_owned(),
        implementation: "virtio-crucible-accelerator-v1".to_owned(),
        class_mask: 0x7,
        fault_family_mask: 0xf,
        queue_start: 0,
        queue_end: 0,
        queue_depth: 64,
        maximum_input_bytes: 4_608,
        maximum_output_bytes: 4_608,
        device_memory_bytes: 65_536,
        ecc_mode_mask: 0x3,
        job_kind_count: 3,
        vmstate: true,
    };
    let manifest = FaultAcceleratorCapabilityManifestV1 {
        rows: vec![row.clone()],
    };
    let encoded = manifest
        .encode()
        .unwrap_or_else(|error| panic!("accelerator manifest should encode: {error}"));
    assert_eq!(
        FaultAcceleratorCapabilityManifestV1::decode(&encoded),
        Ok(manifest.clone())
    );

    let mut missing_fault_family = manifest.clone();
    missing_fault_family.rows[0].fault_family_mask = 0x7;
    assert_eq!(
        missing_fault_family.encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let mut missing_vmstate = manifest.clone();
    missing_vmstate.rows[0].vmstate = false;
    assert_eq!(
        missing_vmstate.encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let mut duplicate = manifest.clone();
    duplicate.rows.push(row);
    assert_eq!(duplicate.encode(), Err(FaultAbiError::CapabilityInvariant));

    let mut corrupt = encoded;
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert_eq!(
        FaultAcceleratorCapabilityManifestV1::decode(&corrupt),
        Err(FaultAbiError::PayloadDigest)
    );
}

#[test]
fn fault_system_manifest_is_fixed_authenticated_and_fail_closed() {
    let manifest = FaultSystemCapabilityManifestV1 {
        semantic_version: 1,
        vmstate_format_version: 1,
        vmstate_section_count: 10,
        vmstate_sections_sha256: [1; 32],
        qemu_build_id: [2; 32],
        qemu_patch_series_hash: [3; 32],
        shmem_header_hash: [4; 32],
    };
    let encoded = manifest
        .encode()
        .unwrap_or_else(|error| panic!("system manifest should encode: {error}"));
    assert_eq!(
        FaultSystemCapabilityManifestV1::decode(&encoded),
        Ok(manifest)
    );
    let mut reserved = encoded;
    reserved[28] = 1;
    assert_eq!(
        FaultSystemCapabilityManifestV1::decode(&reserved),
        Err(FaultAbiError::HeaderLength)
    );
    let mut missing_identity = manifest;
    missing_identity.qemu_build_id = [0; 32];
    assert_eq!(
        missing_identity.encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );
    let mut unknown_sections = manifest;
    unknown_sections.vmstate_section_count = 11;
    assert_eq!(
        unknown_sections.encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );
}

#[test]
fn hardware_error_manifest_rejects_partial_or_mismatched_rows() {
    let manifest = |row| FaultHardwareErrorCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        rows: vec![row],
    };

    let mut wrong_architecture = hardware_row("x86.machine-check.corrected", true);
    wrong_architecture.mechanism = FaultHardwareErrorMechanismV1::Aarch64Ras;
    assert_eq!(
        manifest(wrong_architecture).encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let mut wrong_class = hardware_row("x86.machine-check.corrected", true);
    wrong_class.error_class = FaultHardwareErrorClassV1::Synchronous;
    assert_eq!(
        manifest(wrong_class).encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let mut exception_corrected = hardware_row("x86.machine-check.corrected", true);
    exception_corrected.visibility_mask = FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION;
    assert_eq!(
        manifest(exception_corrected).encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let mut missing_vmstate = FaultHardwareErrorCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        rows: complete_x86_hardware_rows(),
    };
    missing_vmstate.rows[0].vmstate = false;
    assert!(missing_vmstate.encode().is_ok());

    let mut invalid_mask = hardware_row("x86.machine-check.corrected", true);
    invalid_mask.status_allowed = 0;
    assert_eq!(
        manifest(invalid_mask).encode(),
        Err(FaultAbiError::CapabilityInvariant)
    );

    let unsorted = FaultHardwareErrorCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        rows: vec![
            hardware_row("x86.machine-check.recoverable", false),
            hardware_row("x86.machine-check.corrected", true),
        ],
    };
    assert_eq!(unsorted.encode(), Err(FaultAbiError::CapabilityInvariant));

    let valid = FaultHardwareErrorCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        rows: complete_x86_hardware_rows(),
    };
    let mut corrupt = valid
        .encode()
        .unwrap_or_else(|error| panic!("hardware manifest should encode: {error}"));
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert_eq!(
        FaultHardwareErrorCapabilityManifestV1::decode(&corrupt),
        Err(FaultAbiError::PayloadDigest)
    );
}
