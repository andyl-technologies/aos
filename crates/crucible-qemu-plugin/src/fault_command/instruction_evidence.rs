//! Instruction, register, exception, and hardware-error evidence translation.

use super::*;
/// Updates bridge-side instruction expectations after QEMU publishes a command result.
///
/// A terminal one-shot `Apply` result deliberately retains its expectation until
/// the corresponding applied or fail-closed evidence event has been translated
/// and published.
pub(super) fn track_instruction_result(
    commands: &mut BTreeMap<u64, InstructionCommandExpectation>,
    active_bindings: &mut BTreeMap<[u8; 32], u64>,
    command_sequence: u64,
    status: u16,
) -> Result<(), FaultCommandBridgeError> {
    let command = commands
        .get(&command_sequence)
        .cloned()
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    if status == FaultResultStatus::Applied as u16 {
        match command.operation {
            NodeFaultOperationV1::Upsert => {
                if let Some(prior) = active_bindings.insert(command.binding_hash, command_sequence)
                {
                    if prior != command_sequence {
                        commands.remove(&prior);
                    }
                }
            }
            NodeFaultOperationV1::Remove => {
                if let Some(prior) = active_bindings.remove(&command.binding_hash) {
                    commands.remove(&prior);
                }
                commands.remove(&command_sequence);
            }
            NodeFaultOperationV1::Apply => {}
        }
    } else if command.operation != NodeFaultOperationV1::Apply
        || status != FaultResultStatus::InternalError as u16
    {
        commands.remove(&command_sequence);
    }
    Ok(())
}

/// Advances exact replay-event correlation and releases terminal one-shot state.
pub(super) fn track_instruction_event(
    commands: &mut BTreeMap<u64, InstructionCommandExpectation>,
    command_sequence: u64,
    payload: &[u8],
) -> Result<(), FaultCommandBridgeError> {
    let evidence = FaultInstructionEvidenceV1::decode(payload)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let command = commands
        .get_mut(&command_sequence)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    if evidence.replay_ordinal != command.next_replay_ordinal
        || evidence.replay_total != command.replay_total
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let terminal = evidence.outcome != FaultInstructionEvidenceOutcomeV1::Applied
        || evidence.mutation_kind != FaultInstructionMutationKindV1::Replay
        || evidence.replay_ordinal == evidence.replay_total;
    if terminal {
        if command.operation == NodeFaultOperationV1::Apply {
            commands.remove(&command_sequence);
        } else {
            command.next_replay_ordinal = 0;
        }
    } else {
        command.next_replay_ordinal = command
            .next_replay_ordinal
            .checked_add(1)
            .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    }
    Ok(())
}

/// Releases the command identity correlated with one global terminal event.
pub(super) fn track_terminal_instruction_event(
    commands: &mut BTreeMap<u64, InstructionCommandExpectation>,
    active_bindings: &mut BTreeMap<[u8; 32], u64>,
    command_sequence: u64,
) -> Result<(), FaultCommandBridgeError> {
    let command = commands
        .remove(&command_sequence)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    if active_bindings.get(&command.binding_hash) == Some(&command_sequence) {
        active_bindings.remove(&command.binding_hash);
    }
    Ok(())
}

pub(super) fn target_manifest_capability_row(
    architecture: FaultCapabilityScope,
    register_manifest_digest: [u8; 32],
    interrupt_manifest_digest: Option<[u8; 32]>,
    hardware_error_manifest_digest: Option<[u8; 32]>,
    clock_manifest_digest: Option<[u8; 32]>,
    accelerator_manifest_digest: Option<[u8; 32]>,
) -> FaultCapabilityRowV1 {
    let name = b"qemu.target-manifest.node.v1";
    let schema = b"crucible.target-manifest-query.v1;kinds=register,interrupt,hardware-error,clock,accelerator";
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_HASH_DOMAIN);
    hasher.update(name);
    hasher.update(&[0]);
    hasher.update(schema);
    hasher.update(&[0]);
    hasher.update(&register_manifest_digest);
    match interrupt_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match hardware_error_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match clock_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match accelerator_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    FaultCapabilityRowV1 {
        command_kind: FaultCommandKind::QueryTargetManifest,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        scope: architecture,
        phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
        maximum_payload_bytes: FAULT_TARGET_MANIFEST_QUERY_V1_BYTES as u32,
        maximum_pending_commands: 1,
        required_feature_bits: FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION
            | interrupt_manifest_digest.map_or(0, |_digest| FAULT_CAPABILITY_FEATURE_INTERRUPT)
            | hardware_error_manifest_digest
                .map_or(0, |_digest| FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR)
            | clock_manifest_digest.map_or(0, |_digest| FAULT_CAPABILITY_FEATURE_GUEST_CLOCK),
        capability_hash: *hasher.finalize().as_bytes(),
    }
}

pub(super) fn register_capability_hash(
    architecture: FaultCapabilityScope,
    manifest_digest: [u8; 32],
) -> [u8; 32] {
    let name = match architecture {
        FaultCapabilityScope::X86_64 => b"qemu.register.mutate.x86_64.v1".as_slice(),
        FaultCapabilityScope::Aarch64 => b"qemu.register.mutate.aarch64.v1".as_slice(),
        _ => b"qemu.register.mutate.invalid.v1".as_slice(),
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_HASH_DOMAIN);
    hasher.update(name);
    hasher.update(&[0]);
    hasher.update(b"crucible.node-fault-payload.v1");
    hasher.update(&[0]);
    hasher.update(&manifest_digest);
    *hasher.finalize().as_bytes()
}

pub(super) fn register_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
    identity: &RegisterEvidenceIdentity,
) -> Result<RegisterCommandExpectation, FaultCommandBridgeError> {
    let decoded = NodeFaultPayloadV1::decode(payload)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    if decoded.operation == NodeFaultOperationV1::Remove {
        return Ok(RegisterCommandExpectation {
            operation: decoded.operation,
            binding_hash,
            mutation: None,
        });
    }
    let field = |tag| {
        decoded
            .fields
            .iter()
            .find(|field| field.tag == tag)
            .ok_or(FaultCommandBridgeError::RegisterEvidence)
    };
    let u32_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)
    };
    let register_identity: [u8; 32] = field(node_fault_field::T3)?
        .value
        .as_slice()
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let row = identity
        .rows
        .iter()
        .find(|row| crucible_shmem::fault_object_id_hash_v1(&row.name) == register_identity)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
    let mutation_kind = match u32_field(node_fault_field::P4)? {
        1 => FaultRegisterMutationKindV1::BitFlip,
        2 => FaultRegisterMutationKindV1::Stuck,
        3 => FaultRegisterMutationKindV1::Replace,
        _ => return Err(FaultCommandBridgeError::RegisterEvidence),
    };
    Ok(RegisterCommandExpectation {
        operation: decoded.operation,
        binding_hash,
        mutation: Some(RegisterMutationExpectation {
            vcpu_index: u32_field(node_fault_field::T1)?,
            numeric_id: row.numeric_id,
            model_phase: decoded.model_phase,
            mutation_kind,
            first_bit: u32_field(node_fault_field::P2)?,
            bit_count: u32_field(node_fault_field::P3)?,
            mask: field(node_fault_field::P5)?.value.clone(),
            value: field(node_fault_field::P7)?.value.clone(),
        }),
    })
}

pub(super) fn instruction_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
    identity: &RegisterEvidenceIdentity,
) -> Result<InstructionCommandExpectation, FaultCommandBridgeError> {
    let decoded = NodeFaultPayloadV1::decode(payload)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let field = |tag| {
        decoded
            .fields
            .iter()
            .find(|field| field.tag == tag)
            .ok_or(FaultCommandBridgeError::InstructionEvidence)
    };
    let u32_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)
    };
    let selector = policy_json(&field(node_fault_field::P1)?.value, false)?;
    let selector = selector
        .as_object()
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let pc_start = json_u64(selector.get("pc_start"))?;
    let pc_length = json_u64(selector.get("pc_length"))?;
    if pc_length == 0 || pc_start.checked_add(pc_length).is_none() {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let instruction_bytes = match selector.get("instruction_bytes") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(hex_bytes(value)?),
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    if instruction_bytes
        .as_ref()
        .is_some_and(|bytes| bytes.is_empty() || bytes.len() > 32)
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let opcode_class = match selector.get("opcode_class") {
        Some(serde_json::Value::Null) => None,
        value => Some(
            u32::try_from(json_u64(value)?)
                .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?,
        ),
    };
    let input_state_sha256 = match selector.get("input_state_sha256") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(
            hex_bytes(value)?
                .try_into()
                .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?,
        ),
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    let vcpu_index = u32_field(node_fault_field::T1)?;
    let mutation_kind = match u32_field(node_fault_field::P2)? {
        1 => FaultInstructionMutationKindV1::ResultCorrupt,
        2 => FaultInstructionMutationKindV1::Skip,
        3 => FaultInstructionMutationKindV1::Replay,
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    let replay_total = u32_field(node_fault_field::P5)?;
    let register_mutation = if mutation_kind == FaultInstructionMutationKindV1::ResultCorrupt {
        let register_identity: [u8; 32] = field(node_fault_field::P3)?
            .value
            .as_slice()
            .try_into()
            .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
        let row = identity
            .rows
            .iter()
            .find(|row| crucible_shmem::fault_object_id_hash_v1(&row.name) == register_identity)
            .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
        let mutation = policy_json(&field(node_fault_field::P4)?.value, false)?;
        Some(result_register_expectation(vcpu_index, row, &mutation)?)
    } else {
        None
    };
    Ok(InstructionCommandExpectation {
        operation: decoded.operation,
        binding_hash,
        generation: decoded.generation,
        action_hash: decoded.action_hash,
        target_hash: decoded.target_hash,
        vcpu_index,
        model_phase: decoded.model_phase,
        pc_start,
        pc_length,
        instruction_bytes,
        opcode_class,
        input_state_sha256,
        mutation_kind,
        replay_total,
        next_replay_ordinal: 0,
        register_mutation,
    })
}

pub(super) fn exception_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
) -> Result<ExceptionCommandExpectation, FaultCommandBridgeError> {
    let decoded = NodeFaultPayloadV1::decode(payload)
        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?;
    let field = |tag| {
        decoded
            .fields
            .iter()
            .find(|field| field.tag == tag)
            .ok_or(FaultCommandBridgeError::ExceptionEvidence)
    };
    if decoded.operation != NodeFaultOperationV1::Apply {
        return Err(FaultCommandBridgeError::ExceptionEvidence);
    }
    let exception = policy_json(&field(node_fault_field::P1)?.value, true)?;
    let exception = exception
        .as_object()
        .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
    let architecture = match exception
        .get("architecture")
        .and_then(|value| value.as_str())
    {
        Some("x86_64") => FaultCapabilityScope::X86_64,
        Some("aarch64") => FaultCapabilityScope::Aarch64,
        _ => return Err(FaultCommandBridgeError::ExceptionEvidence),
    };
    let fault_address = match exception.get("fault_address") {
        Some(serde_json::Value::Null) => None,
        value => {
            Some(json_u64(value).map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?)
        }
    };
    let maskable = exception
        .get("maskable")
        .and_then(serde_json::Value::as_bool)
        .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
    let record = exception
        .get("record")
        .and_then(serde_json::Value::as_object)
        .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
    let record_kind = record
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
    let optional_u64 = |value: Option<&serde_json::Value>| match value {
        Some(serde_json::Value::Null) => Ok(None),
        value => json_u64(value)
            .map(Some)
            .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence),
    };
    let hardware_record = match record_kind {
        "architecture_default" if record.get("parameters").is_none() => None,
        "x86_machine_check" => {
            let parameters = record
                .get("parameters")
                .and_then(serde_json::Value::as_object)
                .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
            Some(HardwareExceptionExpectation::X86MachineCheck {
                bank: u32::try_from(
                    json_u64(parameters.get("bank"))
                        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
                )
                .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
                status: json_u64(parameters.get("status"))
                    .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
                global_status: json_u64(parameters.get("global_status"))
                    .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
                address: optional_u64(parameters.get("address"))?,
                misc: optional_u64(parameters.get("misc"))?,
                corrected: parameters
                    .get("corrected")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
            })
        }
        "aarch64_ras" => {
            let parameters = record
                .get("parameters")
                .and_then(serde_json::Value::as_object)
                .ok_or(FaultCommandBridgeError::ExceptionEvidence)?;
            Some(HardwareExceptionExpectation::Aarch64Ras {
                esr: json_u64(parameters.get("esr"))
                    .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
                far: optional_u64(parameters.get("far"))?,
                disr: optional_u64(parameters.get("disr"))?,
                asynchronous: parameters
                    .get("asynchronous")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
                corrected: parameters
                    .get("corrected")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
                fatal: parameters
                    .get("fatal")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
            })
        }
        _ => return Err(FaultCommandBridgeError::ExceptionEvidence),
    };
    let vcpu_index = field(node_fault_field::T1)?
        .value
        .as_slice()
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?;
    Ok(ExceptionCommandExpectation {
        binding_hash,
        generation: decoded.generation,
        action_hash: decoded.action_hash,
        target_hash: decoded.target_hash,
        architecture,
        model_phase: decoded.model_phase,
        vcpu_index,
        vector: u32::try_from(
            json_u64(exception.get("vector"))
                .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
        )
        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
        syndrome: json_u64(exception.get("syndrome"))
            .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?,
        fault_address,
        before_instruction: exception
            .get("before_instruction")
            .and_then(|value| value.as_bool())
            .ok_or(FaultCommandBridgeError::ExceptionEvidence)?,
        maskable,
        hardware_record,
    })
}

pub(super) fn memory_ecc_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
) -> Result<MemoryEccCommandExpectation, FaultCommandBridgeError> {
    let decoded = NodeFaultPayloadV1::decode(payload)
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
    let field = |tag| {
        decoded
            .fields
            .iter()
            .find(|field| field.tag == tag)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)
    };
    if decoded.operation != NodeFaultOperationV1::Apply {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let u32_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)
    };
    let u64_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)
    };
    let hash_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)
    };
    Ok(MemoryEccCommandExpectation {
        binding_hash,
        generation: decoded.generation,
        action_hash: decoded.action_hash,
        target_hash: decoded.target_hash,
        model_phase: decoded.model_phase,
        target_vcpu: u32_field(node_fault_field::P8)?,
        kind: u32_field(node_fault_field::P1)?,
        address: u64_field(node_fault_field::P2)?,
        syndrome: u64_field(node_fault_field::P3)?,
        bank: hash_field(node_fault_field::P4)?,
        channel: hash_field(node_fault_field::P5)?,
        rank: hash_field(node_fault_field::P6)?,
        visibility: policy_json(&field(node_fault_field::P7)?.value, true)?,
    })
}

pub(super) fn clock_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
    command_kind: FaultCommandKind,
) -> Result<ClockCommandExpectation, FaultCommandBridgeError> {
    let decoded =
        NodeFaultPayloadV1::decode(payload).map_err(|_| FaultCommandBridgeError::ClockEvidence)?;
    if decoded.operation == NodeFaultOperationV1::Remove {
        return Ok(ClockCommandExpectation {
            operation: decoded.operation,
            command_kind: command_kind as u16,
            binding_hash,
            model_phase: decoded.model_phase,
            source_ids: Vec::new(),
            parameters: ClockCommandParameters::Remove,
        });
    }
    let field = |tag| {
        decoded
            .fields
            .iter()
            .find(|field| field.tag == tag)
            .ok_or(FaultCommandBridgeError::ClockEvidence)
    };
    let u32_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::ClockEvidence)
    };
    let u64_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::ClockEvidence)
    };
    let i64_field = |tag| {
        field(tag)?
            .value
            .as_slice()
            .try_into()
            .map(i64::from_le_bytes)
            .map_err(|_source| FaultCommandBridgeError::ClockEvidence)
    };
    let clock_policy_json = |tag| {
        let json = field(tag)?
            .value
            .strip_prefix(b"CRUCJSN1")
            .ok_or(FaultCommandBridgeError::ClockEvidence)?;
        serde_json::from_slice(json).map_err(|_source| FaultCommandBridgeError::ClockEvidence)
    };
    let tag = if command_kind == FaultCommandKind::ClockTransform {
        node_fault_field::T1
    } else {
        node_fault_field::P1
    };
    let value = decoded
        .fields
        .iter()
        .find(|field| field.tag == tag)
        .ok_or(FaultCommandBridgeError::ClockEvidence)?
        .value
        .as_slice();
    if value.is_empty() || value.len() % 32 != 0 {
        return Err(FaultCommandBridgeError::ClockEvidence);
    }
    let parameters = if command_kind == FaultCommandKind::ClockTransform {
        let ratio = field(node_fault_field::P4)?.value.as_slice();
        let numerator = i64::from_le_bytes(
            ratio[..8]
                .try_into()
                .map_err(|_source| FaultCommandBridgeError::ClockEvidence)?,
        );
        let numerator =
            u64::try_from(numerator).map_err(|_source| FaultCommandBridgeError::ClockEvidence)?;
        let kind = u32_field(node_fault_field::P2)?;
        ClockCommandParameters::Transform {
            kind,
            signed_value: i64_field(node_fault_field::P3)?,
            ratio: [
                numerator,
                u64::from_le_bytes(
                    ratio[8..16]
                        .try_into()
                        .map_err(|_source| FaultCommandBridgeError::ClockEvidence)?,
                ),
            ],
            unsigned_value: u64_field(node_fault_field::P5)?,
            process: if matches!(kind, 4..=6) {
                Some(clock_policy_json(node_fault_field::P6)?)
            } else {
                None
            },
            monotonicity: u32_field(node_fault_field::P7)?,
            overdue_policy: u32_field(node_fault_field::P8)?,
        }
    } else {
        ClockCommandParameters::SourceState {
            transition: clock_policy_json(node_fault_field::P2)?,
            synchronization: clock_policy_json(node_fault_field::P3)?,
        }
    };
    Ok(ClockCommandExpectation {
        operation: decoded.operation,
        command_kind: command_kind as u16,
        binding_hash,
        model_phase: decoded.model_phase,
        source_ids: value
            .chunks_exact(32)
            .map(|chunk| chunk.try_into())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| FaultCommandBridgeError::ClockEvidence)?,
        parameters,
    })
}

pub(super) fn accelerator_command_expectation(
    payload: &[u8],
    binding_hash: [u8; 32],
    command_kind: FaultCommandKind,
) -> Result<AcceleratorCommandExpectation, FaultCommandBridgeError> {
    let decoded = NodeFaultPayloadV1::decode(payload)
        .map_err(|_| FaultCommandBridgeError::AcceleratorEvidence)?;
    let fields = decoded
        .fields
        .into_iter()
        .map(|field| (field.tag, field.value))
        .collect();
    Ok(AcceleratorCommandExpectation {
        operation: decoded.operation,
        command_kind: command_kind as u16,
        binding_hash,
        generation: decoded.generation,
        action_hash: decoded.action_hash,
        target_hash: decoded.target_hash,
        model_phase: decoded.model_phase,
        fields,
    })
}

pub(super) fn result_register_expectation(
    vcpu_index: u32,
    row: &FaultRegisterCapabilityRowV1,
    mutation: &serde_json::Value,
) -> Result<RegisterMutationExpectation, FaultCommandBridgeError> {
    let root = mutation
        .as_object()
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let kind = root
        .get("kind")
        .and_then(|value| value.as_str())
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let parameters = root
        .get("parameters")
        .and_then(|value| value.as_object())
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let width_bytes = usize::try_from(row.width_bits)
        .ok()
        .and_then(|bits| bits.checked_add(7))
        .map(|bits| bits / 8)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let (mutation_kind, mask, value) = match kind {
        "bit_flip" => (
            FaultRegisterMutationKindV1::BitFlip,
            hex_json(parameters.get("mask"))?,
            vec![0],
        ),
        "stuck" => (
            FaultRegisterMutationKindV1::Stuck,
            hex_json(parameters.get("mask"))?,
            hex_json(parameters.get("value"))?,
        ),
        "replace" => {
            let value = hex_json(parameters.get("value"))?;
            let mut mask = vec![u8::MAX; width_bytes];
            if row.width_bits % 8 != 0 {
                mask[width_bytes - 1] = (1_u8 << (row.width_bits % 8)) - 1;
            }
            (FaultRegisterMutationKindV1::Replace, mask, value)
        }
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    if mask.len() != width_bytes
        || (mutation_kind != FaultRegisterMutationKindV1::BitFlip && value.len() != width_bytes)
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    Ok(RegisterMutationExpectation {
        vcpu_index,
        numeric_id: row.numeric_id,
        model_phase: 12,
        mutation_kind,
        first_bit: 0,
        bit_count: row.width_bits,
        mask,
        value,
    })
}

pub(super) fn policy_json(
    bytes: &[u8],
    exception: bool,
) -> Result<serde_json::Value, FaultCommandBridgeError> {
    let invalid = || {
        if exception {
            FaultCommandBridgeError::ExceptionEvidence
        } else {
            FaultCommandBridgeError::InstructionEvidence
        }
    };
    let json = bytes.strip_prefix(b"CRUCJSN1").ok_or_else(invalid)?;
    serde_json::from_slice(json).map_err(|_source| invalid())
}

pub(super) fn json_u64(value: Option<&serde_json::Value>) -> Result<u64, FaultCommandBridgeError> {
    value
        .and_then(serde_json::Value::as_u64)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)
}

pub(super) fn hex_json(
    value: Option<&serde_json::Value>,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    value
        .and_then(serde_json::Value::as_str)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)
        .and_then(hex_bytes)
}

pub(super) fn hex_bytes(value: &str) -> Result<Vec<u8>, FaultCommandBridgeError> {
    if value.len() % 2 != 0 {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            nibble(pair[0])
                .zip(nibble(pair[1]))
                .map(|(high, low)| high << 4 | low)
                .ok_or(FaultCommandBridgeError::InstructionEvidence)
        })
        .collect()
}

pub(super) fn translate_register_evidence(
    raw: &[u8],
    identity: &RegisterEvidenceIdentity,
    logical_icount_offset: u64,
    expected_raw_icount: u64,
    expected_model_phase: Option<u16>,
    expected_before: [u8; 32],
    expected_after: [u8; 32],
    expectation: &RegisterMutationExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    const HEADER: usize = 160;
    if raw.len() < HEADER
        || raw[..8] != *b"CRUCQRW1"
        || raw_u16(raw, 8)? != 1
        || raw[14..16] != [0, 0]
        || raw[156..160].iter().any(|byte| *byte != 0)
    {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let architecture = FaultCapabilityScope::from_u16(raw_u16(raw, 10)?)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    if architecture != identity.architecture {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let model_phase = raw_u16(raw, 12)?;
    if expected_model_phase.is_some_and(|expected| expected != model_phase)
        || model_phase != expectation.model_phase
        || raw_u64(raw, 56)? != expected_raw_icount
    {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let before_len = usize::try_from(raw_u32(raw, 44)?)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let after_len = usize::try_from(raw_u32(raw, 48)?)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let mask_len = usize::try_from(raw_u32(raw, 52)?)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let value_len = usize::try_from(raw_u32(raw, 152)?)
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    if raw.len()
        != HEADER
            .checked_add(before_len)
            .and_then(|length| length.checked_add(after_len))
            .and_then(|length| length.checked_add(mask_len))
            .and_then(|length| length.checked_add(value_len))
            .ok_or(FaultCommandBridgeError::RegisterEvidence)?
    {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let mutation_kind = match raw_u32(raw, 24)? {
        1 => FaultRegisterMutationKindV1::BitFlip,
        2 => FaultRegisterMutationKindV1::Stuck,
        3 => FaultRegisterMutationKindV1::Replace,
        _ => return Err(FaultCommandBridgeError::RegisterEvidence),
    };
    if mutation_kind != expectation.mutation_kind {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let observed_icount = raw_u64(raw, 56)?
        .checked_add(logical_icount_offset)
        .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
    let before_start = HEADER;
    let after_start = before_start + before_len;
    let mask_start = after_start + after_len;
    let value_start = mask_start + mask_len;
    let execution_fingerprint: [u8; 32] = raw[88..120]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let baseline_fingerprint: [u8; 32] = raw[120..152]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)?;
    let numeric_id = raw_u32(raw, 20)?;
    let row = identity
        .rows
        .iter()
        .find(|row| row.numeric_id == numeric_id)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
    let expected_width = usize::try_from(row.width_bits)
        .ok()
        .and_then(|bits| bits.checked_add(7))
        .map(|bits| bits / 8)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
    let declared_side_effects = raw_u32(raw, 28)?;
    let first_bit = raw_u32(raw, 36)?;
    let bit_count = raw_u32(raw, 40)?;
    let mutation_bytes = usize::try_from(bit_count)
        .ok()
        .and_then(|bits| bits.checked_add(7))
        .map(|bits| bits / 8)
        .ok_or(FaultCommandBridgeError::RegisterEvidence)?;
    if before_len != expected_width
        || after_len != expected_width
        || mask_len != mutation_bytes
        || value_len
            != if mutation_kind == FaultRegisterMutationKindV1::BitFlip {
                1
            } else {
                mutation_bytes
            }
        || declared_side_effects != row.side_effects
        || model_phase == 0
        || model_phase > 64
        || row.model_phase_mask & (1_u64 << (model_phase - 1)) == 0
        || (expected_model_phase.is_none()
            && row.capabilities & FAULT_REGISTER_CAPABILITY_IMPULSE == 0)
        || first_bit
            .checked_add(bit_count)
            .is_none_or(|end| end > row.width_bits)
    {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    if raw_u32(raw, 16)? != expectation.vcpu_index
        || raw_u64(raw, 64)? != u64::from(expectation.vcpu_index)
        || numeric_id != expectation.numeric_id
        || first_bit != expectation.first_bit
        || bit_count != expectation.bit_count
        || raw[mask_start..value_start] != expectation.mask
        || raw[value_start..] != expectation.value
        || execution_fingerprint == [0; 32]
        || baseline_fingerprint == [0; 32]
        || ((baseline_fingerprint != execution_fingerprint)
            != (raw[before_start..after_start] != raw[after_start..mask_start]))
        || (expected_model_phase.is_none() && baseline_fingerprint == execution_fingerprint)
    {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let raw_mask = &raw[mask_start..value_start];
    for bit in 0..bit_count {
        if raw_mask[bit as usize / 8] & (1_u8 << (bit % 8)) != 0
            && row.writable_mask[(first_bit + bit) as usize / 8] & (1_u8 << ((first_bit + bit) % 8))
                == 0
        {
            return Err(FaultCommandBridgeError::RegisterEvidence);
        }
    }
    let evidence = FaultRegisterMutationEvidenceV1 {
        architecture,
        model_phase,
        vcpu_index: raw_u32(raw, 16)?,
        numeric_id,
        mutation_kind,
        declared_side_effects,
        performed_side_effects: raw_u32(raw, 32)?,
        first_bit,
        bit_count,
        observed_icount,
        rr_current_vcpu: raw_u64(raw, 64)?,
        rr_cursor_position: raw_u64(raw, 72)?,
        rr_switch_quantum: raw_u64(raw, 80)?,
        manifest_digest: identity.manifest_digest,
        cpu_model_digest: identity.cpu_model_digest,
        before_sha256: expected_before,
        after_sha256: expected_after,
        execution_fingerprint_sha256: execution_fingerprint,
        before: raw[before_start..after_start].to_vec(),
        after: raw[after_start..mask_start].to_vec(),
        mask: raw[mask_start..value_start].to_vec(),
        value: raw[value_start..].to_vec(),
    };
    evidence
        .encode()
        .map_err(|_source| FaultCommandBridgeError::RegisterEvidence)
}

/// Validates a generic terminal record that replaced instruction evidence.
pub(super) fn translate_terminal_instruction_evidence(
    raw: &[u8],
    event: &QemuFaultEvent,
    expectation: &InstructionCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    let evidence = FaultTerminalEvidenceV1::decode(raw)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    if event.outcome != FaultEventOutcomeV1::Error as u16
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.target_kind != NodeFaultTargetKindV1::Vcpu as u16
        || evidence.attempted_payload_sha256 != event.opportunity_hash
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    Ok(raw.to_vec())
}

pub(super) fn translate_instruction_evidence(
    raw: &[u8],
    identity: &InstructionEvidenceIdentity,
    register_identity: &RegisterEvidenceIdentity,
    logical_icount_offset: u64,
    event: &QemuFaultEvent,
    expectation: &InstructionCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    const HEADER: usize = 608;
    let invalid = |_| FaultCommandBridgeError::InstructionEvidence;
    if raw.len() < HEADER
        || raw[..8] != *b"CRUCINS1"
        || raw_u16(raw, 8).map_err(invalid)? != 3
        || raw[600..608].iter().any(|byte| *byte != 0)
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.target_kind != NodeFaultTargetKindV1::Vcpu as u16
        || raw_u64(raw, 48).map_err(invalid)? != event.observed_icount
        || raw[96..128] != event.before_hash
        || raw[128..160] != event.after_hash
        || raw[192..224] != identity.manifest_sha256
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let raw_digest: [u8; 32] = sha2::Sha256::digest(raw).into();
    if raw_digest != event.opportunity_hash {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let before_cpu: [u8; 32] = raw[416..448]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let after_cpu: [u8; 32] = raw[448..480]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let before_ram: [u8; 32] = raw[288..320]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let after_ram: [u8; 32] = raw[320..352]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let before_device: [u8; 32] = raw[352..384]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let after_device: [u8; 32] = raw[384..416]
        .try_into()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    if instruction_system_digest(
        before_cpu,
        before_ram,
        before_device,
        raw_u64(raw, 480).map_err(invalid)?,
        raw_u64(raw, 496).map_err(invalid)?,
    ) != event.before_hash
        || instruction_system_digest(
            after_cpu,
            after_ram,
            after_device,
            raw_u64(raw, 488).map_err(invalid)?,
            raw_u64(raw, 504).map_err(invalid)?,
        ) != event.after_hash
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let architecture = FaultCapabilityScope::from_u16(raw_u16(raw, 10).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    if architecture != identity.architecture || architecture != register_identity.architecture {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let mutation_kind = match raw_u32(raw, 12).map_err(invalid)? {
        1 => FaultInstructionMutationKindV1::ResultCorrupt,
        2 => FaultInstructionMutationKindV1::Skip,
        3 => FaultInstructionMutationKindV1::Replay,
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    let outcome = match event.outcome {
        value if value == FaultEventOutcomeV1::Applied as u16 => {
            FaultInstructionEvidenceOutcomeV1::Applied
        }
        value if value == FaultEventOutcomeV1::Suppressed as u16 => {
            FaultInstructionEvidenceOutcomeV1::Suppressed
        }
        value if value == FaultEventOutcomeV1::Error as u16 => {
            FaultInstructionEvidenceOutcomeV1::Error
        }
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    if outcome == FaultInstructionEvidenceOutcomeV1::Applied {
        if expectation
            .input_state_sha256
            .is_some_and(|expected| raw[568..600] != expected)
        {
            return Err(FaultCommandBridgeError::InstructionEvidence);
        }
    } else if outcome == FaultInstructionEvidenceOutcomeV1::Suppressed
        && (expectation.input_state_sha256.is_none()
            || raw[96..128] != raw[128..160]
            || expectation.input_state_sha256 == raw[568..600].try_into().ok())
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let instruction_len = usize::try_from(raw_u32(raw, 56).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let detail_len = usize::try_from(raw_u32(raw, 60).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let expected_len = HEADER
        .checked_add(instruction_len)
        .and_then(|length| length.checked_add(detail_len))
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    let destination_count = usize::try_from(raw_u32(raw, 164).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let page_count = usize::try_from(raw_u32(raw, 528).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    if raw.len() != expected_len
        || destination_count > 4
        || !(1..=2).contains(&page_count)
        || raw_u32(raw, 160).map_err(invalid)? != expectation.vcpu_index
        || mutation_kind != expectation.mutation_kind
        || raw_u32(raw, 20).map_err(invalid)? != expectation.replay_total
        || raw_u32(raw, 532).map_err(invalid)?
            != u32::from(expectation.input_state_sha256.is_some())
        || raw[536..568] != expectation.input_state_sha256.unwrap_or([0; 32])
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let pc = raw_u64(raw, 32).map_err(invalid)?;
    if pc < expectation.pc_start
        || pc >= expectation.pc_start + expectation.pc_length
        || expectation
            .instruction_bytes
            .as_ref()
            .is_some_and(|expected| expected.as_slice() != &raw[HEADER..HEADER + instruction_len])
        || expectation
            .opcode_class
            .is_some_and(|expected| expected != raw_u32(raw, 24).unwrap_or(0))
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let raw_detail = &raw[HEADER + instruction_len..];
    let detail = match (outcome, &expectation.register_mutation, mutation_kind) {
        (
            FaultInstructionEvidenceOutcomeV1::Applied,
            Some(register),
            FaultInstructionMutationKindV1::ResultCorrupt,
        ) => {
            let translated = translate_register_evidence(
                raw_detail,
                register_identity,
                logical_icount_offset,
                event.observed_icount,
                Some(12),
                event.before_hash,
                event.after_hash,
                register,
            )?;
            if !(0..destination_count)
                .any(|index| raw_u32(raw, 168 + index * 4).ok() == Some(register.numeric_id))
            {
                return Err(FaultCommandBridgeError::InstructionEvidence);
            }
            translated
        }
        (
            FaultInstructionEvidenceOutcomeV1::Applied,
            None,
            FaultInstructionMutationKindV1::Replay,
        ) if raw_u32(raw, 24).map_err(invalid)? == 0x0100_0008 => {
            let transcript = FaultInstructionPortIoEvidenceV1::decode(raw_detail)
                .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
            if transcript.entries.iter().any(|entry| !entry.completed) {
                return Err(FaultCommandBridgeError::InstructionEvidence);
            }
            transcript
                .encode()
                .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?
        }
        (
            FaultInstructionEvidenceOutcomeV1::Applied,
            None,
            FaultInstructionMutationKindV1::Skip | FaultInstructionMutationKindV1::Replay,
        ) if raw_detail.is_empty() => Vec::new(),
        (FaultInstructionEvidenceOutcomeV1::Suppressed, _, _) if raw_detail.is_empty() => {
            Vec::new()
        }
        (FaultInstructionEvidenceOutcomeV1::Error, _, _) if raw_detail.len() <= 32 => {
            raw_detail.to_vec()
        }
        _ => return Err(FaultCommandBridgeError::InstructionEvidence),
    };
    let observed_icount = event
        .observed_icount
        .checked_add(logical_icount_offset)
        .ok_or(FaultCommandBridgeError::CoordinateOverflow)?;
    let evidence = FaultInstructionEvidenceV1 {
        architecture,
        mutation_kind,
        outcome,
        replay_ordinal: raw_u32(raw, 16).map_err(invalid)?,
        replay_total: raw_u32(raw, 20).map_err(invalid)?,
        opcode_class: raw_u32(raw, 24).map_err(invalid)?,
        flags: raw_u32(raw, 28).map_err(invalid)?,
        pc,
        physical_address: raw_u64(raw, 40).map_err(invalid)?,
        observed_icount,
        vcpu_index: raw_u32(raw, 160).map_err(invalid)?,
        destinations: (0..destination_count)
            .map(|index| raw_u32(raw, 168 + index * 4).map_err(invalid))
            .collect::<Result<_, _>>()?,
        instruction_sha256: raw[64..96]
            .try_into()
            .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?,
        before_state_sha256: event.before_hash,
        after_state_sha256: event.after_hash,
        manifest_sha256: identity.manifest_sha256,
        before_cpu_sha256: before_cpu,
        after_cpu_sha256: after_cpu,
        input_state_sha256: expectation.input_state_sha256,
        matched_input_state_sha256: raw[568..600]
            .try_into()
            .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?,
        code_page_bases: (0..page_count)
            .map(|index| raw_u64(raw, 512 + index * 8).map_err(invalid))
            .collect::<Result<_, _>>()?,
        code_page_sha256: (0..page_count)
            .map(|index| {
                raw.get(224 + index * 32..256 + index * 32)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(FaultCommandBridgeError::InstructionEvidence)
            })
            .collect::<Result<_, _>>()?,
        before_ram_sha256: before_ram,
        after_ram_sha256: after_ram,
        before_device_sha256: before_device,
        after_device_sha256: after_device,
        before_ram_bytes: raw_u64(raw, 480).map_err(invalid)?,
        after_ram_bytes: raw_u64(raw, 488).map_err(invalid)?,
        before_device_bytes: raw_u64(raw, 496).map_err(invalid)?,
        after_device_bytes: raw_u64(raw, 504).map_err(invalid)?,
        instruction_bytes: raw[HEADER..HEADER + instruction_len].to_vec(),
        detail,
    };
    evidence
        .encode()
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)
}

pub(super) fn translate_exception_evidence(
    raw: &[u8],
    identity: &InstructionEvidenceIdentity,
    logical_icount_offset: u64,
    event: &QemuFaultEvent,
    expectation: &ExceptionCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    let invalid = |_| FaultCommandBridgeError::ExceptionEvidence;
    if raw.len() != 192
        || raw[..8] != *b"CRUCEXC1"
        || raw_u16(raw, 8).map_err(invalid)? != 2
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.target_kind != NodeFaultTargetKindV1::Vcpu as u16
        || event.outcome != FaultEventOutcomeV1::Applied as u16
        || raw_u64(raw, 56).map_err(invalid)? != event.observed_icount
        || raw[96..128] != event.before_hash
        || raw[128..160] != event.after_hash
        || raw[14..16].iter().any(|byte| *byte != 0)
        || raw[52..56].iter().any(|byte| *byte != 0)
        || raw[77..80].iter().any(|byte| *byte != 0)
        || raw[160..192].iter().any(|byte| *byte != 0)
    {
        return Err(FaultCommandBridgeError::ExceptionEvidence);
    }
    let raw_digest: [u8; 32] = sha2::Sha256::digest(raw).into();
    let architecture = FaultCapabilityScope::from_u16(raw_u16(raw, 10).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)?;
    let has_address = raw[48] == 1;
    if raw_digest != event.opportunity_hash
        || architecture != identity.architecture
        || architecture != expectation.architecture
        || raw_u16(raw, 12).map_err(invalid)? != expectation.model_phase
        || raw_u32(raw, 16).map_err(invalid)? != expectation.vcpu_index
        || raw_u32(raw, 20).map_err(invalid)? != expectation.vector
        || raw_u64(raw, 24).map_err(invalid)? != expectation.syndrome
        || has_address != expectation.fault_address.is_some()
        || raw_u64(raw, 32).map_err(invalid)? != expectation.fault_address.unwrap_or(0)
        || raw[49] != u8::from(expectation.before_instruction)
        || raw[50] != u8::from(expectation.maskable)
        || raw[51] != 1
        || expectation.hardware_record.is_some()
        || raw_u32(raw, 72).map_err(invalid)? != expectation.vector
        || raw[76] != u8::from(has_address)
        || raw_u64(raw, 80).map_err(invalid)? != expectation.syndrome
        || raw_u64(raw, 88).map_err(invalid)? != expectation.fault_address.unwrap_or(0)
    {
        return Err(FaultCommandBridgeError::ExceptionEvidence);
    }
    let evidence = FaultExceptionEvidenceV1 {
        architecture,
        model_phase: expectation.model_phase,
        vcpu_index: expectation.vcpu_index,
        vector: expectation.vector,
        syndrome: expectation.syndrome,
        fault_address: expectation.fault_address,
        before_instruction: expectation.before_instruction,
        command_icount: raw_u64(raw, 40)
            .map_err(invalid)?
            .checked_add(logical_icount_offset)
            .ok_or(FaultCommandBridgeError::CoordinateOverflow)?,
        delivered_icount: event
            .observed_icount
            .checked_add(logical_icount_offset)
            .ok_or(FaultCommandBridgeError::CoordinateOverflow)?,
        entry_pc: raw_u64(raw, 64).map_err(invalid)?,
        before_sha256: event.before_hash,
        after_sha256: event.after_hash,
    };
    evidence
        .encode()
        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)
}

pub(super) fn translate_hardware_exception_evidence(
    raw: &[u8],
    manifest_payload: &[u8],
    event: &QemuFaultEvent,
    expectation: &ExceptionCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    const BEFORE_STATE: usize = 392;
    const AFTER_STATE: usize = 520;
    let invalid = |_| FaultCommandBridgeError::HardwareErrorEvidence;
    if raw.len() != 744
        || raw[..8] != *b"CRUCEXC1"
        || raw_u16(raw, 8).map_err(invalid)? != 2
        || raw[51] != 2
        || raw[14..16].iter().any(|byte| *byte != 0)
        || raw[52..56].iter().any(|byte| *byte != 0)
        || raw[77..80].iter().any(|byte| *byte != 0)
        || raw[205..256].iter().any(|byte| *byte != 0)
        || raw[388..392].iter().any(|byte| *byte != 0)
        || raw[BEFORE_STATE..BEFORE_STATE + 8] != *b"CRUCHCS1"
        || raw[AFTER_STATE..AFTER_STATE + 8] != *b"CRUCHCS1"
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.target_kind != NodeFaultTargetKindV1::Vcpu as u16
        || event.outcome != FaultEventOutcomeV1::Applied as u16
        || raw_u64(raw, 56).map_err(invalid)? != event.observed_icount
        || raw[96..128] != event.before_hash
        || raw[128..160] != event.after_hash
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let raw_digest: [u8; 32] = sha2::Sha256::digest(raw).into();
    if raw_digest != event.opportunity_hash {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let manifest = FaultHardwareErrorCapabilityManifestV1::decode(manifest_payload)
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
    let row_index = usize::try_from(raw_u32(raw, 384).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
    let row = manifest
        .rows
        .get(row_index)
        .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
    if raw[256..288] != crucible_shmem::fault_object_id_hash_v1(&row.id)
        || raw[288..320] != crucible_shmem::fault_object_id_hash_v1(&row.bank)
        || raw[320..352] != crucible_shmem::fault_object_id_hash_v1(&row.channel)
        || raw[352..384] != crucible_shmem::fault_object_id_hash_v1(&row.rank)
        || &raw[648..680] != sha2::Sha256::digest(manifest_payload).as_slice()
        || raw[680..712] != crucible_shmem::fault_object_id_hash_v1(&row.firmware)
        || raw[712..744] != crucible_shmem::fault_object_id_hash_v1(&row.state)
        || manifest.architecture != expectation.architecture
        || raw_u16(raw, 10).map_err(invalid)? != expectation.architecture as u16
        || raw_u16(raw, 12).map_err(invalid)? != expectation.model_phase
        || raw_u32(raw, 16).map_err(invalid)? != expectation.vcpu_index
        || raw_u32(raw, 20).map_err(invalid)? != expectation.vector
        || raw_u64(raw, 24).map_err(invalid)? != expectation.syndrome
        || raw_u64(raw, 32).map_err(invalid)? != expectation.fault_address.unwrap_or(0)
        || raw[48] != u8::from(expectation.fault_address.is_some())
        || raw[49] != u8::from(expectation.before_instruction)
        || raw_u32(raw, BEFORE_STATE + 8).map_err(invalid)? != expectation.architecture as u32
        || raw_u32(raw, AFTER_STATE + 8).map_err(invalid)? != expectation.architecture as u32
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let record = raw_u16(raw, 160).map_err(invalid)?;
    match (&row.record_kind, &expectation.hardware_record) {
        (
            FaultHardwareErrorRecordKindV1::X86MachineCheck,
            Some(HardwareExceptionExpectation::X86MachineCheck {
                bank: expected_bank,
                status: expected_status,
                global_status: expected_global_status,
                address: expected_address,
                misc: expected_misc,
                corrected: expected_corrected,
            }),
        ) if record == 2 => {
            let bank = raw_u32(raw, 164).map_err(invalid)?;
            let status = raw_u64(raw, 168).map_err(invalid)?;
            let before_status = raw_u64(raw, BEFORE_STATE + 40).map_err(invalid)?;
            let preserves_uncorrectable = raw[200] == 1
                && before_status & ((1_u64 << 63) | (1_u64 << 61))
                    == ((1_u64 << 63) | (1_u64 << 61));
            let merged_status = if preserves_uncorrectable {
                before_status | (1_u64 << 62)
            } else if before_status & (1_u64 << 63) != 0 {
                status | (1_u64 << 62)
            } else {
                status
            };
            if bank != *expected_bank
                || status != *expected_status
                || raw_u64(raw, 176).map_err(invalid)? != *expected_global_status
                || raw_u64(raw, 184).map_err(invalid)? != expected_address.unwrap_or(0)
                || raw_u64(raw, 192).map_err(invalid)? != expected_misc.unwrap_or(0)
                || raw[200] != u8::from(*expected_corrected)
                || raw[201] != u8::from(expected_address.is_some())
                || raw[202] != u8::from(expected_misc.is_some())
                || raw[203] != 0
                || raw[204] != 0
                || raw[50] != u8::from(expectation.maskable)
                || (*expected_corrected
                    && (raw_u64(raw, 64).map_err(invalid)? != 0
                        || raw_u32(raw, 72).map_err(invalid)? != 0
                        || raw[76] != 0
                        || raw_u64(raw, 80).map_err(invalid)? != 0
                        || raw_u64(raw, 88).map_err(invalid)? != 0))
                || (!*expected_corrected
                    && (raw_u32(raw, 72).map_err(invalid)? != expectation.vector
                        || raw[76] != u8::from(expectation.fault_address.is_some())
                        || raw_u64(raw, 80).map_err(invalid)? != expectation.syndrome
                        || raw_u64(raw, 88).map_err(invalid)?
                            != expectation.fault_address.unwrap_or(0)))
                || bank < row.bank_number
                || bank >= row.bank_number + row.bank_count
                || status & row.status_required != row.status_required
                || status & !row.status_allowed != 0
                || raw_u32(raw, BEFORE_STATE + 16).map_err(invalid)? != bank
                || raw_u32(raw, AFTER_STATE + 16).map_err(invalid)? != bank
                || raw_u64(raw, AFTER_STATE + 40).map_err(invalid)? != merged_status
                || (!preserves_uncorrectable
                    && raw_u64(raw, AFTER_STATE + 48).map_err(invalid)?
                        != raw_u64(raw, 184).map_err(invalid)?)
                || (!preserves_uncorrectable
                    && raw_u64(raw, AFTER_STATE + 56).map_err(invalid)?
                        != raw_u64(raw, 192).map_err(invalid)?)
                || raw_u64(raw, AFTER_STATE + 64).map_err(invalid)?
                    != raw_u64(raw, 176).map_err(invalid)?
            {
                return Err(FaultCommandBridgeError::HardwareErrorEvidence);
            }
        }
        (
            FaultHardwareErrorRecordKindV1::Aarch64Ras,
            Some(HardwareExceptionExpectation::Aarch64Ras {
                esr: expected_esr,
                far: expected_far,
                disr: expected_disr,
                asynchronous: expected_asynchronous,
                corrected: expected_corrected,
                fatal: expected_fatal,
            }),
        ) if record == 3 => {
            let asynchronous = raw[200] == 1;
            if raw_u64(raw, 168).map_err(invalid)? != *expected_esr
                || raw_u64(raw, 176).map_err(invalid)? != expected_far.unwrap_or(0)
                || raw_u64(raw, 184).map_err(invalid)? != expected_disr.unwrap_or(0)
                || raw[200] != u8::from(*expected_asynchronous)
                || raw[201] != u8::from(*expected_corrected)
                || raw[202] != u8::from(expected_far.is_some())
                || raw[203] != u8::from(expected_disr.is_some())
                || raw[204] != u8::from(*expected_fatal)
                || *expected_fatal != (row.error_class == FaultHardwareErrorClassV1::Fatal)
                || raw[50] != u8::from(row.maskable)
                || (*expected_corrected
                    && (raw_u64(raw, 64).map_err(invalid)? != 0
                        || raw_u32(raw, 72).map_err(invalid)? != 0
                        || raw[76] != 0
                        || raw_u64(raw, 80).map_err(invalid)? != 0
                        || raw_u64(raw, 88).map_err(invalid)? != 0))
                || (!*expected_corrected
                    && (raw_u32(raw, 72).map_err(invalid)? != expectation.vector
                        || raw[76] != u8::from(expectation.fault_address.is_some())
                        || raw_u64(raw, 80).map_err(invalid)? != expectation.syndrome
                        || raw_u64(raw, 88).map_err(invalid)?
                            != expectation.fault_address.unwrap_or(0)))
                || (asynchronous
                    && raw_u64(raw, AFTER_STATE + 104).map_err(invalid)?
                        != raw_u64(raw, 184).map_err(invalid)?)
                || (!asynchronous
                    && (raw_u64(raw, AFTER_STATE + 72).map_err(invalid)?
                        != raw_u64(raw, 168).map_err(invalid)?
                        || raw_u64(raw, AFTER_STATE + 80).map_err(invalid)?
                            != raw_u64(raw, 176).map_err(invalid)?))
            {
                return Err(FaultCommandBridgeError::HardwareErrorEvidence);
            }
        }
        _ => return Err(FaultCommandBridgeError::HardwareErrorEvidence),
    }
    Ok(raw.to_vec())
}

pub(super) fn translate_hardware_ecc_evidence(
    raw: &[u8],
    manifest_payload: &[u8],
    event: &QemuFaultEvent,
    expectation: &MemoryEccCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    const BEFORE_CPU: usize = 416;
    const QUEUED_CPU: usize = 544;
    const AFTER_CPU: usize = 672;
    const BEFORE_GHES: usize = 800;
    const QUEUED_GHES: usize = 992;
    const AFTER_GHES: usize = 1184;
    let invalid = |_| FaultCommandBridgeError::HardwareErrorEvidence;
    if raw.len() != 1376
        || raw[..8] != *b"CRUCHWE1"
        || raw_u16(raw, 8).map_err(invalid)? != 1
        || event.command_kind != FaultCommandKind::MemoryEccEvent as u16
        || event.outcome != FaultEventOutcomeV1::Applied as u16
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.target_kind != NodeFaultTargetKindV1::Memory as u16
        || raw_u64(raw, 16).map_err(invalid)? != event.observed_icount
        || raw_u64(raw, 40).map_err(invalid)? != event.rule_command_sequence
        || raw_u64(raw, 24).map_err(invalid)? != expectation.address
        || raw_u64(raw, 32).map_err(invalid)? != expectation.syndrome
        || raw_u32(raw, 52).map_err(invalid)? != expectation.target_vcpu
        || sha2::Sha256::digest(raw).as_slice() != event.opportunity_hash
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let manifest = FaultHardwareErrorCapabilityManifestV1::decode(manifest_payload)
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
    let row_index = usize::try_from(raw_u32(raw, 12).map_err(invalid)?)
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
    let row = manifest
        .rows
        .get(row_index)
        .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
    if row.record_kind != FaultHardwareErrorRecordKindV1::MemoryEcc
        || raw_u16(raw, 10).map_err(invalid)? != manifest.architecture as u16
        || raw[64..96] != crucible_shmem::fault_object_id_hash_v1(&row.id)
        || raw[96..128] != crucible_shmem::fault_object_id_hash_v1(&row.bank)
        || raw[128..160] != crucible_shmem::fault_object_id_hash_v1(&row.channel)
        || raw[160..192] != crucible_shmem::fault_object_id_hash_v1(&row.rank)
        || &raw[320..352] != sha2::Sha256::digest(manifest_payload).as_slice()
        || raw[352..384] != crucible_shmem::fault_object_id_hash_v1(&row.firmware)
        || raw[384..416] != crucible_shmem::fault_object_id_hash_v1(&row.state)
        || raw[96..128] != expectation.bank
        || raw[128..160] != expectation.channel
        || raw[160..192] != expectation.rank
        || raw[49..52].iter().any(|byte| *byte != 0)
        || raw[56..64].iter().any(|byte| *byte != 0)
        || raw[288..320].iter().any(|byte| *byte != 0)
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    let address = raw_u64(raw, 24).map_err(invalid)?;
    let visibility = expectation
        .visibility
        .as_object()
        .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
    let visibility_kind = visibility
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
    if (expectation.kind == 1
        && (visibility.len() != 1 || visibility_kind != "telemetry_only" || raw[48] != 1))
        || (expectation.kind == 2
            && (visibility.len() != 2 || visibility_kind != "exception" || raw[48] != 2))
        || !matches!(expectation.kind, 1 | 2)
        || row.corrected != (expectation.kind == 1)
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    if expectation.kind == 2 {
        let exception = visibility
            .get("parameters")
            .and_then(serde_json::Value::as_object)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let record = exception
            .get("record")
            .and_then(serde_json::Value::as_object)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let record_parameters = record
            .get("parameters")
            .and_then(serde_json::Value::as_object)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let architecture = exception
            .get("architecture")
            .and_then(serde_json::Value::as_str)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let record_kind = record
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let vector = u32::try_from(
            json_u64(exception.get("vector"))
                .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?,
        )
        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
        let exception_syndrome = json_u64(exception.get("syndrome"))
            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
        let fault_address = json_u64(exception.get("fault_address"))
            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
        let before_instruction = exception
            .get("before_instruction")
            .and_then(serde_json::Value::as_bool)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let maskable = exception
            .get("maskable")
            .and_then(serde_json::Value::as_bool)
            .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?;
        let flags = raw_u32(raw, 256).map_err(invalid)?;
        if exception.len() != 7
            || record.len() != 2
            || raw_u32(raw, 196).map_err(invalid)? != vector
            || raw_u64(raw, 200).map_err(invalid)? != exception_syndrome
            || raw_u64(raw, 208).map_err(invalid)? != fault_address
            || flags & 1 == 0
            || ((flags >> 1) & 1) != u32::from(before_instruction)
            || ((flags >> 2) & 1) != u32::from(maskable)
        {
            return Err(FaultCommandBridgeError::HardwareErrorEvidence);
        }
        match (architecture, record_kind) {
            ("x86_64", "x86_machine_check") => {
                let address = json_u64(record_parameters.get("address"))
                    .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?;
                let misc = match record_parameters.get("misc") {
                    Some(serde_json::Value::Null) => None,
                    value => Some(
                        json_u64(value)
                            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?,
                    ),
                };
                if record_parameters.len() != 7
                    || raw_u16(raw, 192).map_err(invalid)? != 2
                    || raw_u32(raw, 216).map_err(invalid)?
                        != u32::try_from(
                            json_u64(record_parameters.get("bank")).map_err(|_source| {
                                FaultCommandBridgeError::HardwareErrorEvidence
                            })?,
                        )
                        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?
                    || raw_u64(raw, 224).map_err(invalid)?
                        != json_u64(record_parameters.get("status"))
                            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?
                    || raw_u64(raw, 232).map_err(invalid)?
                        != json_u64(record_parameters.get("global_status"))
                            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?
                    || raw_u64(raw, 240).map_err(invalid)? != address
                    || raw_u64(raw, 248).map_err(invalid)? != misc.unwrap_or(0)
                    || ((flags >> 3) & 1)
                        != u32::from(
                            record_parameters
                                .get("corrected")
                                .and_then(serde_json::Value::as_bool)
                                .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                        )
                    || ((flags >> 4) & 1) != 1
                    || ((flags >> 5) & 1) != u32::from(misc.is_some())
                    || flags & !0x3f != 0
                {
                    return Err(FaultCommandBridgeError::HardwareErrorEvidence);
                }
            }
            ("aarch64", "aarch64_ras") => {
                let optional = |name| match record_parameters.get(name) {
                    Some(serde_json::Value::Null) => Ok(None),
                    value => json_u64(value)
                        .map(Some)
                        .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence),
                };
                let far = optional("far")?;
                let disr = optional("disr")?;
                if record_parameters.len() != 6
                    || raw_u16(raw, 192).map_err(invalid)? != 3
                    || raw_u64(raw, 264).map_err(invalid)?
                        != json_u64(record_parameters.get("esr"))
                            .map_err(|_source| FaultCommandBridgeError::HardwareErrorEvidence)?
                    || raw_u64(raw, 272).map_err(invalid)? != far.unwrap_or(0)
                    || raw_u64(raw, 280).map_err(invalid)? != disr.unwrap_or(0)
                    || ((flags >> 3) & 1)
                        != u32::from(
                            record_parameters
                                .get("asynchronous")
                                .and_then(serde_json::Value::as_bool)
                                .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                        )
                    || ((flags >> 4) & 1)
                        != u32::from(
                            record_parameters
                                .get("corrected")
                                .and_then(serde_json::Value::as_bool)
                                .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                        )
                    || ((flags >> 5) & 1)
                        != u32::from(
                            record_parameters
                                .get("fatal")
                                .and_then(serde_json::Value::as_bool)
                                .ok_or(FaultCommandBridgeError::HardwareErrorEvidence)?,
                        )
                    || ((flags >> 6) & 1) != u32::from(far.is_some())
                    || ((flags >> 7) & 1) != u32::from(disr.is_some())
                    || flags & !0xff != 0
                {
                    return Err(FaultCommandBridgeError::HardwareErrorEvidence);
                }
            }
            _ => return Err(FaultCommandBridgeError::HardwareErrorEvidence),
        }
    } else if raw_u16(raw, 192).map_err(invalid)? != 0
        && row.mechanism == FaultHardwareErrorMechanismV1::AcpiGhes
    {
        return Err(FaultCommandBridgeError::HardwareErrorEvidence);
    }
    match row.mechanism {
        FaultHardwareErrorMechanismV1::X86Mca => {
            for offset in [BEFORE_CPU, QUEUED_CPU, AFTER_CPU] {
                if raw[offset..offset + 8] != *b"CRUCHCS1"
                    || raw_u32(raw, offset + 8).map_err(invalid)?
                        != FaultCapabilityScope::X86_64 as u32
                    || raw_u32(raw, offset + 16).map_err(invalid)? != row.bank_number
                {
                    return Err(FaultCommandBridgeError::HardwareErrorEvidence);
                }
            }
            let status = raw_u64(raw, 224).map_err(invalid)?;
            let before_status = raw_u64(raw, BEFORE_CPU + 40).map_err(invalid)?;
            let preserves_uncorrectable = row.corrected
                && before_status & ((1_u64 << 63) | (1_u64 << 61))
                    == ((1_u64 << 63) | (1_u64 << 61));
            let expected_status = if preserves_uncorrectable {
                before_status | (1_u64 << 62)
            } else if before_status & (1_u64 << 63) != 0 {
                status | (1_u64 << 62)
            } else {
                status
            };
            if status & row.status_required != row.status_required
                || status & !row.status_allowed != 0
                || raw_u64(raw, QUEUED_CPU + 40).map_err(invalid)? != expected_status
                || raw_u64(raw, AFTER_CPU + 40).map_err(invalid)? != expected_status
                || (!preserves_uncorrectable
                    && raw_u64(raw, AFTER_CPU + 48).map_err(invalid)? != address)
            {
                return Err(FaultCommandBridgeError::HardwareErrorEvidence);
            }
        }
        FaultHardwareErrorMechanismV1::AcpiGhes => {
            for offset in [BEFORE_GHES, QUEUED_GHES, AFTER_GHES] {
                if raw[offset..offset + 8] != *b"CRUCGHS1"
                    || raw_u32(raw, offset + 16).map_err(invalid)? != 172
                {
                    return Err(FaultCommandBridgeError::HardwareErrorEvidence);
                }
            }
            if raw_u64(raw, BEFORE_GHES + 8).map_err(invalid)? == 0
                || !validate_ghes_memory_record(raw, QUEUED_GHES, row.corrected, address)?
                || raw[QUEUED_GHES..QUEUED_GHES + 192] != raw[AFTER_GHES..AFTER_GHES + 192]
            {
                return Err(FaultCommandBridgeError::HardwareErrorEvidence);
            }
        }
        FaultHardwareErrorMechanismV1::Aarch64Ras => {
            return Err(FaultCommandBridgeError::HardwareErrorEvidence);
        }
    }
    Ok(raw.to_vec())
}

pub(super) fn validate_ghes_memory_record(
    raw: &[u8],
    state_offset: usize,
    corrected: bool,
    address: u64,
) -> Result<bool, FaultCommandBridgeError> {
    const MEMORY_SECTION_GUID: [u8; 16] = [
        0x14, 0x11, 0xbc, 0xa5, 0x64, 0x6f, 0xde, 0x4e, 0xb8, 0x63, 0x3e, 0x83, 0xed, 0x7c, 0x83,
        0xb1,
    ];
    const MEMORY_VALIDATION_BITS: u64 =
        (1_u64 << 14) | (1_u64 << 15) | (1_u64 << 6) | (1_u64 << 4) | (1_u64 << 1);
    let invalid = |_| FaultCommandBridgeError::HardwareErrorEvidence;
    let record = state_offset + 20;
    let block_status = if corrected { 0x12 } else { 0x11 };
    let severity = if corrected { 2 } else { 0 };

    Ok(raw_u64(raw, state_offset + 8).map_err(invalid)? == 0
        && raw_u32(raw, state_offset + 16).map_err(invalid)? == 172
        && raw_u32(raw, record).map_err(invalid)? == block_status
        && raw[record + 4..record + 12].iter().all(|byte| *byte == 0)
        && raw_u32(raw, record + 12).map_err(invalid)? == 152
        && raw_u32(raw, record + 16).map_err(invalid)? == severity
        && raw[record + 20..record + 36] == MEMORY_SECTION_GUID
        && raw_u32(raw, record + 36).map_err(invalid)? == severity
        && raw_u16(raw, record + 40).map_err(invalid)? == 0x300
        && raw[record + 42..record + 44].iter().all(|byte| *byte == 0)
        && raw_u32(raw, record + 44).map_err(invalid)? == 80
        && raw[record + 48..record + 92].iter().all(|byte| *byte == 0)
        && raw_u64(raw, record + 92).map_err(invalid)? == MEMORY_VALIDATION_BITS
        && raw_u64(raw, record + 100).map_err(invalid)? == 0
        && raw_u64(raw, record + 108).map_err(invalid)? == address
        && raw[record + 116..record + 172]
            .iter()
            .all(|byte| *byte == 0))
}

pub(super) fn instruction_system_digest(
    cpu_sha256: [u8; 32],
    ram_sha256: [u8; 32],
    device_sha256: [u8; 32],
    ram_bytes: u64,
    device_bytes: u64,
) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    digest.update(b"crucible.instruction-state.v1\0");
    digest.update(cpu_sha256);
    digest.update(ram_sha256);
    digest.update(device_sha256);
    digest.update(ram_bytes.to_le_bytes());
    digest.update(device_bytes.to_le_bytes());
    digest.finalize().into()
}
