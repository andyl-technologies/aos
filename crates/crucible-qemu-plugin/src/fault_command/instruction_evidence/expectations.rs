//! Command expectations for register and instruction evidence.

use super::*;

pub(in crate::fault_command) fn register_command_expectation(
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

pub(in crate::fault_command) fn instruction_command_expectation(
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

pub(in crate::fault_command) fn exception_command_expectation(
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

pub(in crate::fault_command) fn memory_ecc_command_expectation(
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

pub(in crate::fault_command) fn clock_command_expectation(
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
        source_ids: value.as_chunks::<32>().0.to_vec(),
        parameters,
    })
}

pub(in crate::fault_command) fn accelerator_command_expectation(
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

pub(in crate::fault_command) fn result_register_expectation(
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
            if !row.width_bits.is_multiple_of(8) {
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

pub(in crate::fault_command) fn policy_json(
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

pub(in crate::fault_command) fn json_u64(
    value: Option<&serde_json::Value>,
) -> Result<u64, FaultCommandBridgeError> {
    value
        .and_then(serde_json::Value::as_u64)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)
}

pub(in crate::fault_command) fn hex_json(
    value: Option<&serde_json::Value>,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    value
        .and_then(serde_json::Value::as_str)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)
        .and_then(hex_bytes)
}

pub(in crate::fault_command) fn hex_bytes(value: &str) -> Result<Vec<u8>, FaultCommandBridgeError> {
    if !value.len().is_multiple_of(2) {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
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
