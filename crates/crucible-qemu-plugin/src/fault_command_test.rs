//! Fault-command bridge codec, translation, and hostile-input tests.
use super::*;
use crucible_shmem::{
    DequeuedFaultResult, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR, FAULT_COMMAND_FLAG_NONE,
    FAULT_COMMAND_SEMANTIC_VERSION, dequeue_fault_result, enqueue_fault_command,
};

#[test]
fn lifecycle_evidence_uses_the_scheduler_logical_coordinate() {
    let mut raw = vec![0_u8; 304];
    raw[..8].copy_from_slice(b"CRUCLIF1");
    raw[24..32].copy_from_slice(&12_u64.to_le_bytes());
    let event = QemuFaultEvent {
        observed_icount: 12,
        ..QemuFaultEvent::default()
    };

    let translated = translate_lifecycle_evidence(&raw, &event, 40)
        .unwrap_or_else(|error| panic!("valid lifecycle evidence should translate: {error}"));
    assert_eq!(
        u64::from_le_bytes(
            translated[24..32]
                .try_into()
                .unwrap_or_else(|_| panic!("translated coordinate should have eight bytes"))
        ),
        52
    );
    assert_eq!(&translated[..24], &raw[..24]);
    assert_eq!(&translated[32..], &raw[32..]);

    let mismatched = QemuFaultEvent {
        observed_icount: 13,
        ..QemuFaultEvent::default()
    };
    assert_eq!(
        translate_lifecycle_evidence(&raw, &mismatched, 40),
        Err(FaultCommandBridgeError::EventEnvelope)
    );
    assert_eq!(
        translate_lifecycle_evidence(&raw, &event, u64::MAX),
        Err(FaultCommandBridgeError::CoordinateOverflow)
    );
}

fn complete_x86_hardware_manifest(
    recoverable: FaultHardwareErrorCapabilityRowV1,
) -> FaultHardwareErrorCapabilityManifestV1 {
    let mut corrected = recoverable.clone();
    corrected.id = "x86.machine-check.corrected".to_owned();
    corrected.error_class = FaultHardwareErrorClassV1::Corrected;
    corrected.visibility_mask = crucible_shmem::FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY;
    corrected.status_required = 1_u64 << 63;
    corrected.corrected = true;
    let mut fatal = recoverable.clone();
    fatal.id = "x86.machine-check.fatal".to_owned();
    fatal.error_class = FaultHardwareErrorClassV1::Fatal;
    fatal.status_required |= 1_u64 << 57;
    FaultHardwareErrorCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        rows: vec![corrected, fatal, recoverable],
    }
}

fn complete_aarch64_hardware_manifest(
    corrected_memory: FaultHardwareErrorCapabilityRowV1,
) -> FaultHardwareErrorCapabilityManifestV1 {
    let ras = |id: &str, class, maskable: bool| FaultHardwareErrorCapabilityRowV1 {
        id: id.to_owned(),
        bank: "aarch64.ras.delivery-state".to_owned(),
        channel: "aarch64.memory.channel".to_owned(),
        rank: "aarch64.memory.rank".to_owned(),
        firmware: "aarch64-ras".to_owned(),
        state: if maskable {
            "aarch64-disr-serror".to_owned()
        } else {
            "aarch64-esr-far-data-abort".to_owned()
        },
        record_kind: FaultHardwareErrorRecordKindV1::Aarch64Ras,
        error_class: class,
        mechanism: FaultHardwareErrorMechanismV1::Aarch64Ras,
        visibility_mask: crucible_shmem::FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION,
        bank_number: 0,
        bank_count: 1,
        vector: if maskable { 47 } else { 3 },
        status_required: 0,
        status_allowed: 0,
        syndrome_required: 0x10,
        syndrome_allowed: u32::MAX.into(),
        model_phase_mask: 1 << (11 - 1),
        privilege_mask: crucible_shmem::FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK,
        corrected: false,
        maskable,
        vmstate: true,
    };
    let mut uncorrectable_memory = corrected_memory.clone();
    uncorrectable_memory.id = "memory.ecc.uncorrectable".to_owned();
    uncorrectable_memory.error_class = FaultHardwareErrorClassV1::Recoverable;
    uncorrectable_memory.visibility_mask =
        crucible_shmem::FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION;
    uncorrectable_memory.corrected = false;
    let rows = vec![
        ras(
            "aarch64.ras.asynchronous",
            FaultHardwareErrorClassV1::Asynchronous,
            true,
        ),
        ras(
            "aarch64.ras.asynchronous-fatal",
            FaultHardwareErrorClassV1::Fatal,
            true,
        ),
        ras(
            "aarch64.ras.synchronous",
            FaultHardwareErrorClassV1::Synchronous,
            false,
        ),
        ras(
            "aarch64.ras.synchronous-fatal",
            FaultHardwareErrorClassV1::Fatal,
            false,
        ),
        corrected_memory,
        uncorrectable_memory,
    ];
    FaultHardwareErrorCapabilityManifestV1 {
        architecture: FaultCapabilityScope::Aarch64,
        rows,
    }
}

#[test]
fn bridge_accepts_every_canonical_qemu_result_status() {
    for value in 1_u16..=14 {
        let status = result_status(value)
            .unwrap_or_else(|error| panic!("canonical status {value} was rejected: {error}"));
        assert_eq!(status as u16, value);
    }
    assert!(matches!(
        result_status(15),
        Err(FaultCommandBridgeError::QemuStatus { value: 15 })
    ));
}

#[test]
fn bridge_translates_capabilities_and_local_rejections_at_logical_time() {
    const COMMAND_ARENA_OFFSET: u64 = 4_096;
    const RESULT_ARENA_OFFSET: u64 = 8_192;
    const EVENT_ARENA_OFFSET: u64 = 12_288;
    TEST_CAPABILITY_RESULT_PENDING.with(|pending| pending.set(None));
    let target_node_hash = *blake3::hash(b"node").as_bytes();
    let command_ring = RingHeader::new();
    let command_arena_header = FaultPayloadArenaHeader::new();
    let mut command_slots = vec![FaultCommandSlotV1::new(); 4];
    let mut command_arena = vec![0_u8; 512];
    let result_ring = RingHeader::new();
    let result_arena_header = FaultPayloadArenaHeader::new();
    let mut result_slots = vec![FaultResultSlotV1::new(); 4];
    let mut result_arena = vec![0_u8; 512];
    let event_ring = RingHeader::new();
    let event_arena_header = FaultPayloadArenaHeader::new();
    let mut event_slots = vec![FaultEventSlotV1::new(); 4];
    let mut event_arena = vec![0_u8; 512];
    let apis = QemuFaultCommandApis::test_stub();
    let capability_payload = encode_fault_capability_manifest(
        &apis
            .capability_rows()
            .unwrap_or_else(|error| panic!("test capabilities: {error}")),
    )
    .unwrap_or_else(|error| panic!("test manifest: {error}"));
    let mut bridge = FaultCommandBridge {
        apis,
        target_node_hash,
        commands: StableFaultCommandTransport {
            ring: NonNull::from(&command_ring),
            slots: NonNull::new(command_slots.as_mut_ptr())
                .unwrap_or_else(|| panic!("test command slots must be non-empty")),
            slot_count: command_slots.len(),
            arena_header: NonNull::from(&command_arena_header),
            arena: NonNull::new(command_arena.as_mut_ptr())
                .unwrap_or_else(|| panic!("test command arena must be non-empty")),
            arena_len: command_arena.len(),
            arena_region_offset: COMMAND_ARENA_OFFSET,
        },
        results: StableFaultResultTransport {
            ring: NonNull::from(&result_ring),
            slots: NonNull::new(result_slots.as_mut_ptr())
                .unwrap_or_else(|| panic!("test result slots must be non-empty")),
            slot_count: result_slots.len(),
            arena_header: NonNull::from(&result_arena_header),
            arena: NonNull::new(result_arena.as_mut_ptr())
                .unwrap_or_else(|| panic!("test result arena must be non-empty")),
            arena_len: result_arena.len(),
            arena_region_offset: RESULT_ARENA_OFFSET,
        },
        events: StableFaultEventTransport {
            ring: NonNull::from(&event_ring),
            slots: NonNull::new(event_slots.as_mut_ptr())
                .unwrap_or_else(|| panic!("test event slots must be non-empty")),
            slot_count: event_slots.len(),
            arena_header: NonNull::from(&event_arena_header),
            arena: NonNull::new(event_arena.as_mut_ptr())
                .unwrap_or_else(|| panic!("test event arena must be non-empty")),
            arena_len: event_arena.len(),
            arena_region_offset: EVENT_ARENA_OFFSET,
        },
        last_sequence: 0,
        capability_payload: capability_payload.clone(),
        capability_queries: BTreeSet::new(),
        register_manifest_payload: None,
        interrupt_manifest_payload: None,
        hardware_error_manifest_payload: None,
        clock_manifest_payload: None,
        accelerator_manifest_payload: None,
        system_manifest_payload: Vec::new(),
        register_evidence_identity: None,
        instruction_evidence_identity: None,
        register_commands: BTreeMap::new(),
        active_register_bindings: BTreeMap::new(),
        instruction_commands: BTreeMap::new(),
        active_instruction_bindings: BTreeMap::new(),
        exception_commands: BTreeMap::new(),
        memory_ecc_commands: BTreeMap::new(),
        clock_commands: BTreeMap::new(),
        active_clock_bindings: BTreeMap::new(),
        accelerator_commands: BTreeMap::new(),
        active_accelerator_bindings: BTreeMap::new(),
        prepared_commands: BTreeSet::new(),
        prepare_only_commands: BTreeSet::new(),
        pending_command: None,
        initialized: true,
    };
    let command = |kind, sequence, node_hash| FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: kind,
        command_flags: FAULT_COMMAND_FLAG_NONE,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: sequence,
        target_node_hash: node_hash,
        target_icount: 50,
        authorization_ceiling_icount: 50,
        binding_hash: *blake3::hash(b"binding").as_bytes(),
        opportunity_hash: [0; 32],
        expected_precondition_hash: [0; 32],
        payload_hash: [0; 32],
        payload_offset: 0,
        payload_length: 0,
    };
    for header in [
        command(FaultCommandKind::QueryCapabilities, 1, target_node_hash),
        command(FaultCommandKind::BoundaryProbe, 2, [7; 32]),
        command(FaultCommandKind::BoundaryProbe, 2, target_node_hash),
    ] {
        enqueue_fault_command(
            &command_ring,
            &mut command_slots,
            &command_arena_header,
            &mut command_arena,
            COMMAND_ARENA_OFFSET,
            header,
            &[],
        )
        .unwrap_or_else(|error| panic!("enqueue test command: {error}"));
    }

    bridge
        .pump(40, 12)
        .unwrap_or_else(|error| panic!("pump test commands: {error}"));
    let results = (0..3)
        .map(|_index| {
            dequeue_fault_result(
                &result_ring,
                &result_slots,
                &result_arena_header,
                &result_arena,
                RESULT_ARENA_OFFSET,
            )
            .unwrap_or_else(|error| panic!("dequeue test result: {error}"))
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        &results[0],
        Some(DequeuedFaultResult::Valid { header, payload })
            if header.status == FaultResultStatus::Applied
                && header.observed_icount == 50
                && header.applied_icount == 50
                && header.evidence_hash == *blake3::hash(&capability_payload).as_bytes()
                && payload == &capability_payload
    ));
    for (result, expected_status) in results[1..].iter().zip([
        FaultResultStatus::InvalidTarget,
        FaultResultStatus::DuplicateSequence,
    ]) {
        assert!(matches!(
            result,
            Some(DequeuedFaultResult::Valid { header, payload })
                if header.status == expected_status
                    && header.observed_icount == 52
                    && header.applied_icount == 0
                    && payload.is_empty()
        ));
    }

    let pending_command = QemuFaultCommand {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::QueryCapabilities as u16,
        command_flags: FAULT_COMMAND_FLAG_NONE,
        phase: FaultBoundaryPhase::NodeBoundary as u16,
        reserved: 0,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: 99,
        target_node_hash,
        target_icount: 40,
        authorization_ceiling_icount: 40,
        binding_hash: [0; 32],
        opportunity_hash: [0; 32],
        expected_precondition_hash: [0; 32],
    };
    assert_eq!(test_submit(&pending_command, std::ptr::null(), 0), 0);
    for command_sequence in 10..14 {
        enqueue_fault_result(
            &result_ring,
            &mut result_slots,
            &result_arena_header,
            &mut result_arena,
            RESULT_ARENA_OFFSET,
            FaultResultHeaderV1 {
                abi_major: FAULT_COMMAND_ABI_MAJOR,
                abi_minor: FAULT_COMMAND_ABI_MINOR,
                command_kind: FaultCommandKind::BoundaryProbe as u16,
                status: FaultResultStatus::InvalidTarget,
                semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
                command_sequence,
                observed_icount: 52,
                applied_icount: 0,
                capability_version: 1,
                phase: FaultBoundaryPhase::NodeBoundary,
                before_hash: [0; 32],
                after_hash: [0; 32],
                evidence_hash: [0; 32],
                result_payload_hash: [0; 32],
                result_offset: 0,
                result_length: 0,
            },
            &[],
        )
        .unwrap_or_else(|error| panic!("fill result ring: {error}"));
    }

    bridge
        .pump(40, 12)
        .unwrap_or_else(|error| panic!("pump under backpressure: {error}"));
    TEST_CAPABILITY_RESULT_PENDING.with(|pending| assert!(pending.get().is_some()));
    let _released = dequeue_fault_result(
        &result_ring,
        &result_slots,
        &result_arena_header,
        &result_arena,
        RESULT_ARENA_OFFSET,
    )
    .unwrap_or_else(|error| panic!("release result capacity: {error}"));
    bridge
        .pump(40, 12)
        .unwrap_or_else(|error| panic!("pump after backpressure: {error}"));
    TEST_CAPABILITY_RESULT_PENDING.with(|pending| assert!(pending.get().is_none()));
    let mut saw_pending_result = false;
    while let Some(result) = dequeue_fault_result(
        &result_ring,
        &result_slots,
        &result_arena_header,
        &result_arena,
        RESULT_ARENA_OFFSET,
    )
    .unwrap_or_else(|error| panic!("drain result: {error}"))
    {
        if matches!(
            result,
            DequeuedFaultResult::Valid { header, .. } if header.command_sequence == 99
        ) {
            saw_pending_result = true;
        }
    }
    assert!(saw_pending_result);

    let prepared_sequence = 100;
    bridge.clock_commands.insert(
        prepared_sequence,
        ClockCommandExpectation {
            operation: NodeFaultOperationV1::Upsert,
            command_kind: FaultCommandKind::ClockTransform as u16,
            binding_hash: [1; 32],
            model_phase: 28,
            source_ids: vec![[2; 32]],
            parameters: ClockCommandParameters::Remove,
        },
    );
    let prepared = QemuFaultResult {
        status: FaultResultStatus::Prepared as u16,
        command_sequence: prepared_sequence,
        ..QemuFaultResult::default()
    };
    bridge.prepare_only_commands.insert(prepared_sequence);
    assert!(bridge.retain_prepared_correlation(&prepared));
    assert!(bridge.retain_prepared_correlation(&prepared));
    assert!(bridge.clock_commands.contains_key(&prepared_sequence));
    bridge.release_prepare_only_correlations(prepared_sequence);
    assert!(bridge.clock_commands.contains_key(&prepared_sequence));
    bridge.release_prepare_only_correlations(prepared_sequence + 1);
    assert!(!bridge.clock_commands.contains_key(&prepared_sequence));
    assert!(bridge.prepared_commands.is_empty());
    assert!(bridge.prepare_only_commands.is_empty());
}

#[test]
fn register_evidence_binds_vcpu_and_terminal_cursor_phase() {
    use sha2::{Digest as _, Sha256};

    const HEADER: usize = 160;
    let before = [0_u8; 8];
    let mut after = before;
    after[0] = 1;
    let expected_before: [u8; 32] = Sha256::digest(before).into();
    let expected_after: [u8; 32] = Sha256::digest(after).into();
    let identity = RegisterEvidenceIdentity {
        architecture: FaultCapabilityScope::X86_64,
        manifest_digest: [1; 32],
        cpu_model_digest: [2; 32],
        rows: vec![FaultRegisterCapabilityRowV1 {
            numeric_id: 1,
            name: "rax".to_owned(),
            width_bits: 64,
            group: FaultRegisterGroupV1::GeneralPurpose,
            model_phase_mask: (1_u64 << 10) | (1_u64 << 11),
            side_effects: 0,
            capabilities: FAULT_REGISTER_CAPABILITY_IMPULSE
                | crucible_shmem::FAULT_REGISTER_CAPABILITY_VMSTATE,
            writable_mask: vec![0xff; 8],
            reserved_mask: vec![0; 8],
            ignored_mask: vec![0; 8],
            read_only_mask: vec![0; 8],
        }],
    };
    let mut expectation = RegisterMutationExpectation {
        vcpu_index: 0,
        numeric_id: 1,
        model_phase: 12,
        mutation_kind: FaultRegisterMutationKindV1::BitFlip,
        first_bit: 0,
        bit_count: 1,
        mask: vec![1],
        value: vec![0],
    };
    let mut raw = vec![0_u8; HEADER + before.len() + after.len() + 2];
    raw[..8].copy_from_slice(b"CRUCQRW1");
    raw[8..10].copy_from_slice(&1_u16.to_le_bytes());
    raw[10..12].copy_from_slice(&(FaultCapabilityScope::X86_64 as u16).to_le_bytes());
    raw[12..14].copy_from_slice(&12_u16.to_le_bytes());
    raw[20..24].copy_from_slice(&1_u32.to_le_bytes());
    raw[24..28].copy_from_slice(&(FaultRegisterMutationKindV1::BitFlip as u32).to_le_bytes());
    raw[36..40].copy_from_slice(&0_u32.to_le_bytes());
    raw[40..44].copy_from_slice(&1_u32.to_le_bytes());
    raw[44..48].copy_from_slice(&8_u32.to_le_bytes());
    raw[48..52].copy_from_slice(&8_u32.to_le_bytes());
    raw[52..56].copy_from_slice(&1_u32.to_le_bytes());
    raw[56..64].copy_from_slice(&256_u64.to_le_bytes());
    raw[72..80].copy_from_slice(&256_u64.to_le_bytes());
    raw[80..88].copy_from_slice(&256_u64.to_le_bytes());
    raw[88..120].fill(3);
    raw[120..152].fill(4);
    raw[152..156].copy_from_slice(&1_u32.to_le_bytes());
    raw[HEADER..HEADER + before.len()].copy_from_slice(&before);
    raw[HEADER + before.len()..HEADER + before.len() + after.len()].copy_from_slice(&after);
    raw[HEADER + before.len() + after.len()] = 1;
    let observation = |expected_model_phase| RegisterEvidenceObservation {
        identity: &identity,
        logical_icount_offset: 0,
        expected_raw_icount: 256,
        expected_model_phase,
        expected_before,
        expected_after,
    };

    assert!(translate_register_evidence(&raw, observation(Some(12)), &expectation).is_ok());

    raw[120..152].fill(3);
    assert!(matches!(
        translate_register_evidence(&raw, observation(Some(12)), &expectation,),
        Err(FaultCommandBridgeError::RegisterEvidence)
    ));
    raw[120..152].fill(4);

    raw[88..120].fill(0);
    assert!(matches!(
        translate_register_evidence(&raw, observation(Some(12)), &expectation,),
        Err(FaultCommandBridgeError::RegisterEvidence)
    ));
    raw[88..120].fill(3);

    raw[16..20].copy_from_slice(&1_u32.to_le_bytes());
    raw[64..72].copy_from_slice(&1_u64.to_le_bytes());
    assert!(matches!(
        translate_register_evidence(&raw, observation(Some(12)), &expectation,),
        Err(FaultCommandBridgeError::RegisterEvidence)
    ));

    raw[16..20].fill(0);
    raw[64..72].fill(0);
    raw[12..14].copy_from_slice(&11_u16.to_le_bytes());
    expectation.model_phase = 11;
    assert!(matches!(
        translate_register_evidence(&raw, observation(Some(11)), &expectation,),
        Err(FaultCommandBridgeError::RegisterEvidence)
    ));

    raw[12..14].copy_from_slice(&12_u16.to_le_bytes());
    raw[72..80].copy_from_slice(&257_u64.to_le_bytes());
    expectation.model_phase = 12;
    assert!(matches!(
        translate_register_evidence(&raw, observation(Some(12)), &expectation,),
        Err(FaultCommandBridgeError::RegisterEvidence)
    ));
}

fn instruction_evidence_fixture() -> (
    Vec<u8>,
    InstructionEvidenceIdentity,
    RegisterEvidenceIdentity,
    QemuFaultEvent,
    InstructionCommandExpectation,
) {
    const HEADER: usize = 608;
    let instruction = [0x90_u8];
    let mut raw = vec![0_u8; HEADER + instruction.len()];
    raw[..8].copy_from_slice(b"CRUCINS1");
    raw[8..10].copy_from_slice(&3_u16.to_le_bytes());
    raw[10..12].copy_from_slice(&(FaultCapabilityScope::X86_64 as u16).to_le_bytes());
    raw[12..16].copy_from_slice(&(FaultInstructionMutationKindV1::Skip as u32).to_le_bytes());
    raw[24..28].copy_from_slice(&0x0100_0001_u32.to_le_bytes());
    raw[32..40].copy_from_slice(&0x1000_u64.to_le_bytes());
    raw[40..48].copy_from_slice(&0x2000_u64.to_le_bytes());
    raw[48..56].copy_from_slice(&17_u64.to_le_bytes());
    raw[56..60].copy_from_slice(&1_u32.to_le_bytes());
    raw[64..96].copy_from_slice(&sha2::Sha256::digest(instruction));
    raw[192..224].fill(3);
    raw[224..256].fill(4);
    raw[288..320].fill(5);
    raw[320..352].fill(6);
    raw[352..384].fill(7);
    raw[384..416].fill(8);
    raw[416..448].fill(1);
    raw[448..480].fill(2);
    raw[480..488].copy_from_slice(&4096_u64.to_le_bytes());
    raw[488..496].copy_from_slice(&4096_u64.to_le_bytes());
    raw[496..504].copy_from_slice(&128_u64.to_le_bytes());
    raw[504..512].copy_from_slice(&128_u64.to_le_bytes());
    let before_state = instruction_system_digest([1; 32], [5; 32], [7; 32], 4096, 128);
    let after_state = instruction_system_digest([2; 32], [6; 32], [8; 32], 4096, 128);
    raw[96..128].copy_from_slice(&before_state);
    raw[128..160].copy_from_slice(&after_state);
    raw[568..600].copy_from_slice(&before_state);
    raw[512..520].copy_from_slice(&0x2000_u64.to_le_bytes());
    raw[528..532].copy_from_slice(&1_u32.to_le_bytes());
    raw[HEADER] = instruction[0];
    let identity = InstructionEvidenceIdentity {
        architecture: FaultCapabilityScope::X86_64,
        manifest_sha256: [3; 32],
    };
    let register_identity = RegisterEvidenceIdentity {
        architecture: FaultCapabilityScope::X86_64,
        manifest_digest: [9; 32],
        cpu_model_digest: [10; 32],
        rows: Vec::new(),
    };
    let expectation = InstructionCommandExpectation {
        operation: NodeFaultOperationV1::Upsert,
        binding_hash: [12; 32],
        generation: 3,
        action_hash: [13; 32],
        target_hash: [14; 32],
        vcpu_index: 0,
        model_phase: 11,
        pc_start: 0x1000,
        pc_length: 1,
        instruction_bytes: Some(instruction.to_vec()),
        opcode_class: Some(0x0100_0001),
        input_state_sha256: None,
        mutation_kind: FaultInstructionMutationKindV1::Skip,
        replay_total: 0,
        next_replay_ordinal: 0,
        register_mutation: None,
    };
    let event = QemuFaultEvent {
        command_kind: FaultCommandKind::CpuInstructionTransform as u16,
        outcome: FaultEventOutcomeV1::Applied as u16,
        model_phase: 11,
        target_kind: NodeFaultTargetKindV1::Vcpu as u16,
        evidence_length: 1,
        event_sequence: 1,
        rule_command_sequence: 2,
        observed_icount: 17,
        generation: 3,
        binding_hash: [12; 32],
        opportunity_hash: sha2::Sha256::digest(&raw).into(),
        action_hash: [13; 32],
        target_hash: [14; 32],
        before_hash: before_state,
        after_hash: after_state,
    };
    (raw, identity, register_identity, event, expectation)
}

#[test]
fn instruction_apply_terminal_results_retain_expectation_until_evidence_event() {
    let (_raw, _identity, _register_identity, event, mut expectation) =
        instruction_evidence_fixture();
    expectation.operation = NodeFaultOperationV1::Apply;
    for status in [FaultResultStatus::Applied, FaultResultStatus::InternalError] {
        let mut commands = BTreeMap::from([(event.rule_command_sequence, expectation.clone())]);
        let mut active_bindings = BTreeMap::new();

        track_instruction_result(
            &mut commands,
            &mut active_bindings,
            event.rule_command_sequence,
            status as u16,
        )
        .unwrap_or_else(|error| panic!("terminal Apply result must remain correlatable: {error}"));

        assert!(commands.contains_key(&event.rule_command_sequence));
        assert!(active_bindings.is_empty());
        commands.remove(&event.rule_command_sequence);
        assert!(commands.is_empty());
    }
}

#[test]
fn instruction_resource_terminal_translates_and_releases_correlation() {
    let (_raw, _identity, _register_identity, mut event, mut expectation) =
        instruction_evidence_fixture();
    let attempted_sha256 = [9_u8; 32];
    let mut terminal = [0_u8; crucible_shmem::FAULT_TERMINAL_EVIDENCE_V1_BYTES];

    terminal[..8].copy_from_slice(&crucible_shmem::FAULT_QUEUE_TERMINAL_EVIDENCE_MAGIC_V1);
    terminal[8..12].copy_from_slice(
        &(crucible_shmem::FaultTerminalReasonV1::EventCapacity as u32).to_le_bytes(),
    );
    terminal[12..16].copy_from_slice(&15_u32.to_le_bytes());
    terminal[16..20].copy_from_slice(&16_u32.to_le_bytes());
    terminal[20..22].copy_from_slice(&(FaultEventOutcomeV1::Applied as u16).to_le_bytes());
    terminal[24..32].copy_from_slice(&608_u64.to_le_bytes());
    terminal[32..64].copy_from_slice(&attempted_sha256);
    terminal[66..68].copy_from_slice(&1_u16.to_le_bytes());
    event.outcome = FaultEventOutcomeV1::Error as u16;
    event.opportunity_hash = attempted_sha256;
    expectation.operation = NodeFaultOperationV1::Apply;

    assert_eq!(
        translate_terminal_instruction_evidence(&terminal, &event, &expectation)
            .unwrap_or_else(|error| panic!("correlated terminal evidence: {error}")),
        terminal
    );
    let mut commands = BTreeMap::from([(event.rule_command_sequence, expectation)]);
    let mut active_bindings = BTreeMap::new();
    track_terminal_instruction_event(
        &mut commands,
        &mut active_bindings,
        event.rule_command_sequence,
    )
    .unwrap_or_else(|error| panic!("terminal event correlation: {error}"));
    assert!(commands.is_empty());

    let mut wrong_hash = event;
    wrong_hash.opportunity_hash[0] ^= 1;
    let (_, _, _, _, expectation) = instruction_evidence_fixture();
    assert!(matches!(
        translate_terminal_instruction_evidence(&terminal, &wrong_hash, &expectation),
        Err(FaultCommandBridgeError::InstructionEvidence)
    ));
}

#[test]
fn instruction_replay_events_require_exact_sequence_and_terminalize_once() {
    let (raw, identity, register_identity, event, mut expectation) = instruction_evidence_fixture();
    let canonical = translate_instruction_evidence(
        &raw,
        &identity,
        &register_identity,
        0,
        &event,
        &expectation,
    )
    .unwrap_or_else(|error| panic!("translate replay-sequence fixture: {error}"));
    let mut evidence = FaultInstructionEvidenceV1::decode(&canonical)
        .unwrap_or_else(|error| panic!("decode replay-sequence fixture: {error}"));
    evidence.mutation_kind = FaultInstructionMutationKindV1::Replay;
    evidence.replay_total = 2;
    expectation.operation = NodeFaultOperationV1::Apply;
    expectation.mutation_kind = FaultInstructionMutationKindV1::Replay;
    expectation.replay_total = 2;

    let mut commands = BTreeMap::from([(event.rule_command_sequence, expectation.clone())]);
    for ordinal in 0..=2 {
        evidence.replay_ordinal = ordinal;
        let payload = evidence
            .encode()
            .unwrap_or_else(|error| panic!("encode replay ordinal {ordinal}: {error}"));
        track_instruction_event(&mut commands, event.rule_command_sequence, &payload)
            .unwrap_or_else(|error| panic!("track replay ordinal {ordinal}: {error}"));
        assert_eq!(commands.is_empty(), ordinal == 2);
    }

    let mut commands = BTreeMap::from([(event.rule_command_sequence, expectation.clone())]);
    evidence.replay_ordinal = 1;
    let out_of_order = evidence
        .encode()
        .unwrap_or_else(|error| panic!("encode out-of-order replay: {error}"));
    assert!(matches!(
        track_instruction_event(&mut commands, event.rule_command_sequence, &out_of_order,),
        Err(FaultCommandBridgeError::InstructionEvidence)
    ));

    evidence.replay_ordinal = 0;
    evidence.outcome = FaultInstructionEvidenceOutcomeV1::Applied;
    let first = evidence
        .encode()
        .unwrap_or_else(|error| panic!("encode first replay event: {error}"));
    track_instruction_event(&mut commands, event.rule_command_sequence, &first)
        .unwrap_or_else(|error| panic!("track first replay event: {error}"));
    evidence.replay_ordinal = 1;
    evidence.outcome = FaultInstructionEvidenceOutcomeV1::Error;
    let error = evidence
        .encode()
        .unwrap_or_else(|error| panic!("encode fail-closed replay event: {error}"));
    track_instruction_event(&mut commands, event.rule_command_sequence, &error)
        .unwrap_or_else(|error| panic!("track fail-closed replay event: {error}"));
    assert!(commands.is_empty());
}

#[test]
fn instruction_bridge_rejects_uncorrelated_private_evidence() {
    let (raw, identity, register_identity, event, expectation) = instruction_evidence_fixture();
    assert!(
        translate_instruction_evidence(
            &raw,
            &identity,
            &register_identity,
            5,
            &event,
            &expectation,
        )
        .is_ok()
    );

    for mutate in [(608_usize, 0xcc_u8), (24, 2), (416, 9)] {
        let mut malformed = raw.clone();
        malformed[mutate.0] = mutate.1;
        let mut correlated_event = event;
        correlated_event.opportunity_hash = sha2::Sha256::digest(&malformed).into();
        assert!(matches!(
            translate_instruction_evidence(
                &malformed,
                &identity,
                &register_identity,
                5,
                &correlated_event,
                &expectation,
            ),
            Err(FaultCommandBridgeError::InstructionEvidence)
        ));
    }

    let mut wrong_generation = event;
    wrong_generation.generation += 1;
    assert!(matches!(
        translate_instruction_evidence(
            &raw,
            &identity,
            &register_identity,
            5,
            &wrong_generation,
            &expectation,
        ),
        Err(FaultCommandBridgeError::InstructionEvidence)
    ));
}

#[test]
fn instruction_bridge_requires_actual_device_io_for_device_replay() {
    let (mut raw, identity, register_identity, mut event, mut expectation) =
        instruction_evidence_fixture();
    let transcript = FaultInstructionPortIoEvidenceV1 {
        entries: vec![crucible_shmem::FaultInstructionPortIoEntryV1 {
            direction: crucible_shmem::FaultInstructionPortIoDirectionV1::Write,
            port: 0xe9,
            value: vec![b'X'],
            completed: true,
        }],
    }
    .encode()
    .unwrap_or_else(|error| panic!("valid device-I/O transcript: {error}"));
    raw[12..16].copy_from_slice(&(FaultInstructionMutationKindV1::Replay as u32).to_le_bytes());
    raw[20..24].copy_from_slice(&1_u32.to_le_bytes());
    raw[24..28].copy_from_slice(&0x0100_0008_u32.to_le_bytes());
    raw[28..32].copy_from_slice(&(1_u32 << 5).to_le_bytes());
    raw[60..64].copy_from_slice(&(transcript.len() as u32).to_le_bytes());
    raw[608] = 0xee;
    raw[64..96].copy_from_slice(&sha2::Sha256::digest([0xee]));
    raw.extend_from_slice(&transcript);
    event.opportunity_hash = sha2::Sha256::digest(&raw).into();
    expectation.instruction_bytes = Some(vec![0xee]);
    expectation.opcode_class = Some(0x0100_0008);
    expectation.mutation_kind = FaultInstructionMutationKindV1::Replay;
    expectation.replay_total = 1;

    let canonical = translate_instruction_evidence(
        &raw,
        &identity,
        &register_identity,
        5,
        &event,
        &expectation,
    )
    .unwrap_or_else(|error| panic!("device replay with an authenticated transaction: {error}"));
    let decoded = FaultInstructionEvidenceV1::decode(&canonical)
        .unwrap_or_else(|error| panic!("canonical device-replay evidence: {error}"));
    assert_eq!(
        FaultInstructionPortIoEvidenceV1::decode(&decoded.detail)
            .unwrap_or_else(|error| panic!("canonical nested transcript: {error}"))
            .entries[0]
            .port,
        0xe9
    );

    raw.truncate(609);
    raw[60..64].fill(0);
    event.opportunity_hash = sha2::Sha256::digest(&raw).into();
    assert!(matches!(
        translate_instruction_evidence(
            &raw,
            &identity,
            &register_identity,
            5,
            &event,
            &expectation,
        ),
        Err(FaultCommandBridgeError::InstructionEvidence)
    ));
}

fn exception_evidence_fixture() -> (
    Vec<u8>,
    InstructionEvidenceIdentity,
    QemuFaultEvent,
    ExceptionCommandExpectation,
) {
    let mut raw = vec![0_u8; 192];
    raw[..8].copy_from_slice(b"CRUCEXC1");
    raw[8..10].copy_from_slice(&2_u16.to_le_bytes());
    raw[10..12].copy_from_slice(&(FaultCapabilityScope::X86_64 as u16).to_le_bytes());
    raw[12..14].copy_from_slice(&2_u16.to_le_bytes());
    raw[20..24].copy_from_slice(&6_u32.to_le_bytes());
    raw[40..48].copy_from_slice(&10_u64.to_le_bytes());
    raw[49] = 1;
    raw[51] = 1;
    raw[56..64].copy_from_slice(&17_u64.to_le_bytes());
    raw[64..72].copy_from_slice(&0x3000_u64.to_le_bytes());
    raw[72..76].copy_from_slice(&6_u32.to_le_bytes());
    raw[96..128].fill(1);
    raw[128..160].fill(2);
    let identity = InstructionEvidenceIdentity {
        architecture: FaultCapabilityScope::X86_64,
        manifest_sha256: [3; 32],
    };
    let expectation = ExceptionCommandExpectation {
        binding_hash: [12; 32],
        generation: 4,
        action_hash: [13; 32],
        target_hash: [14; 32],
        architecture: FaultCapabilityScope::X86_64,
        model_phase: 2,
        vcpu_index: 0,
        vector: 6,
        syndrome: 0,
        fault_address: None,
        before_instruction: true,
        maskable: false,
        hardware_record: None,
    };
    let event = QemuFaultEvent {
        command_kind: FaultCommandKind::CpuException as u16,
        outcome: FaultEventOutcomeV1::Applied as u16,
        model_phase: 2,
        target_kind: NodeFaultTargetKindV1::Vcpu as u16,
        evidence_length: 1,
        event_sequence: 1,
        rule_command_sequence: 2,
        observed_icount: 17,
        generation: 4,
        binding_hash: [12; 32],
        opportunity_hash: sha2::Sha256::digest(&raw).into(),
        action_hash: [13; 32],
        target_hash: [14; 32],
        before_hash: [1; 32],
        after_hash: [2; 32],
    };
    (raw, identity, event, expectation)
}

#[test]
fn exception_bridge_requires_proven_architectural_delivery() {
    let (raw, identity, event, expectation) = exception_evidence_fixture();
    assert!(translate_exception_evidence(&raw, &identity, 5, &event, &expectation).is_ok());

    let mut wrong_delivery = raw.clone();
    wrong_delivery[72] = 7;
    let mut correlated_event = event;
    correlated_event.opportunity_hash = sha2::Sha256::digest(&wrong_delivery).into();
    assert!(matches!(
        translate_exception_evidence(
            &wrong_delivery,
            &identity,
            5,
            &correlated_event,
            &expectation,
        ),
        Err(FaultCommandBridgeError::ExceptionEvidence)
    ));

    let mut not_applied = event;
    not_applied.outcome = FaultEventOutcomeV1::Suppressed as u16;
    assert!(matches!(
        translate_exception_evidence(&raw, &identity, 5, &not_applied, &expectation),
        Err(FaultCommandBridgeError::ExceptionEvidence)
    ));
}

#[test]
fn hardware_exception_bridge_requires_manifest_identity_and_real_state_transition() {
    let status = (1_u64 << 63) | (1_u64 << 61);
    let global_status = 1_u64 << 2;
    let address = 0x1234_5000_u64;
    let row = FaultHardwareErrorCapabilityRowV1 {
        id: "x86.machine-check.recoverable".to_owned(),
        bank: "x86.mca.bank".to_owned(),
        channel: "x86.memory.channel".to_owned(),
        rank: "x86.memory.rank".to_owned(),
        firmware: "x86-mca".to_owned(),
        state: "x86-mca-bank-record-machine-check".to_owned(),
        record_kind: FaultHardwareErrorRecordKindV1::X86MachineCheck,
        error_class: FaultHardwareErrorClassV1::Recoverable,
        mechanism: FaultHardwareErrorMechanismV1::X86Mca,
        visibility_mask: crucible_shmem::FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION,
        bank_number: 0,
        bank_count: 10,
        vector: 18,
        status_required: status,
        status_allowed: u64::MAX,
        syndrome_required: 0,
        syndrome_allowed: u32::MAX.into(),
        model_phase_mask: 1 << (11 - 1),
        privilege_mask: crucible_shmem::FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK,
        corrected: false,
        maskable: false,
        vmstate: true,
    };
    let manifest = complete_x86_hardware_manifest(row.clone())
        .encode()
        .unwrap_or_else(|error| panic!("valid x86 hardware manifest: {error}"));
    let expectation = ExceptionCommandExpectation {
        binding_hash: [12; 32],
        generation: 4,
        action_hash: [13; 32],
        target_hash: [14; 32],
        architecture: FaultCapabilityScope::X86_64,
        model_phase: 11,
        vcpu_index: 0,
        vector: 18,
        syndrome: 0,
        fault_address: Some(address),
        before_instruction: true,
        maskable: false,
        hardware_record: Some(HardwareExceptionExpectation::X86MachineCheck {
            bank: 2,
            status,
            global_status,
            address: Some(address),
            misc: None,
            corrected: false,
        }),
    };
    let mut raw = vec![0_u8; 744];
    raw[..8].copy_from_slice(b"CRUCEXC1");
    raw[8..10].copy_from_slice(&2_u16.to_le_bytes());
    raw[10..12].copy_from_slice(&(FaultCapabilityScope::X86_64 as u16).to_le_bytes());
    raw[12..14].copy_from_slice(&11_u16.to_le_bytes());
    raw[20..24].copy_from_slice(&18_u32.to_le_bytes());
    raw[32..40].copy_from_slice(&address.to_le_bytes());
    raw[40..48].copy_from_slice(&10_u64.to_le_bytes());
    raw[48] = 1;
    raw[49] = 1;
    raw[51] = 2;
    raw[56..64].copy_from_slice(&17_u64.to_le_bytes());
    raw[72..76].copy_from_slice(&18_u32.to_le_bytes());
    raw[76] = 1;
    raw[88..96].copy_from_slice(&address.to_le_bytes());
    raw[96..128].fill(1);
    raw[128..160].fill(2);
    raw[160..162].copy_from_slice(&2_u16.to_le_bytes());
    raw[164..168].copy_from_slice(&2_u32.to_le_bytes());
    raw[168..176].copy_from_slice(&status.to_le_bytes());
    raw[176..184].copy_from_slice(&global_status.to_le_bytes());
    raw[184..192].copy_from_slice(&address.to_le_bytes());
    raw[201] = 1;
    raw[256..288].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.id));
    raw[288..320].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.bank));
    raw[320..352].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.channel));
    raw[352..384].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.rank));
    raw[384..388].copy_from_slice(&2_u32.to_le_bytes());
    for offset in [392_usize, 520] {
        raw[offset..offset + 8].copy_from_slice(b"CRUCHCS1");
        raw[offset + 8..offset + 12]
            .copy_from_slice(&(FaultCapabilityScope::X86_64 as u32).to_le_bytes());
        raw[offset + 12..offset + 16].copy_from_slice(&2_u32.to_le_bytes());
        raw[offset + 16..offset + 20].copy_from_slice(&2_u32.to_le_bytes());
    }
    raw[520 + 40..520 + 48].copy_from_slice(&status.to_le_bytes());
    raw[520 + 48..520 + 56].copy_from_slice(&address.to_le_bytes());
    raw[520 + 64..520 + 72].copy_from_slice(&global_status.to_le_bytes());
    raw[648..680].copy_from_slice(&sha2::Sha256::digest(&manifest));
    raw[680..712].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.firmware));
    raw[712..744].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.state));
    let event = QemuFaultEvent {
        command_kind: FaultCommandKind::CpuException as u16,
        outcome: FaultEventOutcomeV1::Applied as u16,
        model_phase: 11,
        target_kind: NodeFaultTargetKindV1::Vcpu as u16,
        evidence_length: 1,
        event_sequence: 1,
        rule_command_sequence: 2,
        observed_icount: 17,
        generation: 4,
        binding_hash: [12; 32],
        opportunity_hash: sha2::Sha256::digest(&raw).into(),
        action_hash: [13; 32],
        target_hash: [14; 32],
        before_hash: [1; 32],
        after_hash: [2; 32],
    };
    assert_eq!(
        translate_hardware_exception_evidence(&raw, &manifest, &event, &expectation),
        Ok(raw.clone())
    );

    let mut corrupt = raw;
    corrupt[520 + 40] ^= 1;
    let mut correlated = event;
    correlated.opportunity_hash = sha2::Sha256::digest(&corrupt).into();
    assert!(matches!(
        translate_hardware_exception_evidence(&corrupt, &manifest, &correlated, &expectation,),
        Err(FaultCommandBridgeError::HardwareErrorEvidence)
    ));
}

#[test]
fn hardware_ecc_bridge_requires_exact_ghes_record_transition() {
    let address = 0x8123_4000_u64;
    let syndrome = 0x55aa_u64;
    let row = FaultHardwareErrorCapabilityRowV1 {
        id: "memory.ecc.corrected".to_owned(),
        bank: "memory.bank-0".to_owned(),
        channel: "memory.channel-0".to_owned(),
        rank: "memory.rank-0".to_owned(),
        firmware: "acpi-apei-ghes-sea".to_owned(),
        state: "acpi-ghes-cper-record".to_owned(),
        record_kind: FaultHardwareErrorRecordKindV1::MemoryEcc,
        error_class: FaultHardwareErrorClassV1::Corrected,
        mechanism: FaultHardwareErrorMechanismV1::AcpiGhes,
        visibility_mask: crucible_shmem::FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY,
        bank_number: 0,
        bank_count: 1,
        vector: 3,
        status_required: 0,
        status_allowed: 0,
        syndrome_required: 0,
        syndrome_allowed: u64::MAX,
        model_phase_mask: 1 << (9 - 1),
        privilege_mask: crucible_shmem::FAULT_HARDWARE_ERROR_PRIVILEGE_V1_MASK,
        corrected: true,
        maskable: false,
        vmstate: true,
    };
    let manifest = complete_aarch64_hardware_manifest(row.clone())
        .encode()
        .unwrap_or_else(|error| panic!("valid GHES manifest: {error}"));
    let mut raw = vec![0_u8; 1376];
    raw[..8].copy_from_slice(b"CRUCHWE1");
    raw[8..10].copy_from_slice(&1_u16.to_le_bytes());
    raw[10..12].copy_from_slice(&(FaultCapabilityScope::Aarch64 as u16).to_le_bytes());
    raw[12..16].copy_from_slice(&4_u32.to_le_bytes());
    raw[16..24].copy_from_slice(&17_u64.to_le_bytes());
    raw[24..32].copy_from_slice(&address.to_le_bytes());
    raw[32..40].copy_from_slice(&syndrome.to_le_bytes());
    raw[40..48].copy_from_slice(&2_u64.to_le_bytes());
    raw[48] = 1;
    raw[64..96].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.id));
    raw[96..128].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.bank));
    raw[128..160].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.channel));
    raw[160..192].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.rank));
    raw[320..352].copy_from_slice(&sha2::Sha256::digest(&manifest));
    raw[352..384].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.firmware));
    raw[384..416].copy_from_slice(&crucible_shmem::fault_object_id_hash_v1(&row.state));
    for offset in [416_usize, 544, 672] {
        raw[offset..offset + 8].copy_from_slice(b"CRUCHCS1");
    }
    for offset in [800_usize, 992, 1184] {
        raw[offset..offset + 8].copy_from_slice(b"CRUCGHS1");
        raw[offset + 16..offset + 20].copy_from_slice(&172_u32.to_le_bytes());
    }
    raw[800 + 8..800 + 16].copy_from_slice(&1_u64.to_le_bytes());
    for offset in [992_usize, 1184] {
        let record = offset + 20;
        raw[record..record + 4].copy_from_slice(&0x12_u32.to_le_bytes());
        raw[record + 12..record + 16].copy_from_slice(&152_u32.to_le_bytes());
        raw[record + 16..record + 20].copy_from_slice(&2_u32.to_le_bytes());
        raw[record + 20..record + 36].copy_from_slice(&[
            0x14, 0x11, 0xbc, 0xa5, 0x64, 0x6f, 0xde, 0x4e, 0xb8, 0x63, 0x3e, 0x83, 0xed, 0x7c,
            0x83, 0xb1,
        ]);
        raw[record + 36..record + 40].copy_from_slice(&2_u32.to_le_bytes());
        raw[record + 40..record + 42].copy_from_slice(&0x300_u16.to_le_bytes());
        raw[record + 44..record + 48].copy_from_slice(&80_u32.to_le_bytes());
        raw[record + 92..record + 100].copy_from_slice(&0xc052_u64.to_le_bytes());
        raw[record + 108..record + 116].copy_from_slice(&address.to_le_bytes());
    }
    let event = QemuFaultEvent {
        command_kind: FaultCommandKind::MemoryEccEvent as u16,
        outcome: FaultEventOutcomeV1::Applied as u16,
        model_phase: 9,
        target_kind: NodeFaultTargetKindV1::Memory as u16,
        evidence_length: 1,
        event_sequence: 1,
        rule_command_sequence: 2,
        observed_icount: 17,
        generation: 4,
        binding_hash: [12; 32],
        opportunity_hash: sha2::Sha256::digest(&raw).into(),
        action_hash: [13; 32],
        target_hash: [14; 32],
        before_hash: [1; 32],
        after_hash: [2; 32],
    };
    let expectation = MemoryEccCommandExpectation {
        binding_hash: [12; 32],
        generation: 4,
        action_hash: [13; 32],
        target_hash: [14; 32],
        model_phase: 9,
        target_vcpu: 0,
        kind: 1,
        address,
        syndrome,
        bank: crucible_shmem::fault_object_id_hash_v1(&row.bank),
        channel: crucible_shmem::fault_object_id_hash_v1(&row.channel),
        rank: crucible_shmem::fault_object_id_hash_v1(&row.rank),
        visibility: serde_json::json!({"kind": "telemetry_only"}),
    };
    assert_eq!(
        translate_hardware_ecc_evidence(&raw, &manifest, &event, &expectation),
        Ok(raw.clone())
    );

    let mut corrupt = raw;
    corrupt[992 + 128] ^= 1;
    let mut correlated = event;
    correlated.opportunity_hash = sha2::Sha256::digest(&corrupt).into();
    assert!(matches!(
        translate_hardware_ecc_evidence(&corrupt, &manifest, &correlated, &expectation),
        Err(FaultCommandBridgeError::HardwareErrorEvidence)
    ));
}

#[path = "fault_command_test/clock_tests.rs"]
mod clock_tests;
