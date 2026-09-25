//! Register and instruction evidence translation.

use super::*;

pub(in crate::fault_command) struct RegisterEvidenceObservation<'a> {
    pub(in crate::fault_command) identity: &'a RegisterEvidenceIdentity,
    pub(in crate::fault_command) logical_icount_offset: u64,
    pub(in crate::fault_command) expected_raw_icount: u64,
    pub(in crate::fault_command) expected_model_phase: Option<u16>,
    pub(in crate::fault_command) expected_before: [u8; 32],
    pub(in crate::fault_command) expected_after: [u8; 32],
}

pub(in crate::fault_command) fn translate_register_evidence(
    raw: &[u8],
    observation: RegisterEvidenceObservation<'_>,
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
    if architecture != observation.identity.architecture {
        return Err(FaultCommandBridgeError::RegisterEvidence);
    }
    let model_phase = raw_u16(raw, 12)?;
    if observation
        .expected_model_phase
        .is_some_and(|expected| expected != model_phase)
        || model_phase != expectation.model_phase
        || raw_u64(raw, 56)? != observation.expected_raw_icount
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
    let observed_icount =
        raw_to_logical_tick(raw_u64(raw, 56)?, observation.logical_icount_offset)?;
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
    let row = observation
        .identity
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
        || (observation.expected_model_phase.is_none()
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
        || (observation.expected_model_phase.is_none()
            && baseline_fingerprint == execution_fingerprint)
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
        manifest_digest: observation.identity.manifest_digest,
        cpu_model_digest: observation.identity.cpu_model_digest,
        before_sha256: observation.expected_before,
        after_sha256: observation.expected_after,
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
pub(in crate::fault_command) fn translate_terminal_instruction_evidence(
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

pub(in crate::fault_command) fn translate_instruction_evidence(
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
                RegisterEvidenceObservation {
                    identity: register_identity,
                    logical_icount_offset,
                    expected_raw_icount: event.observed_icount,
                    expected_model_phase: Some(12),
                    expected_before: event.before_hash,
                    expected_after: event.after_hash,
                },
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
    let observed_icount = raw_to_logical_tick(event.observed_icount, logical_icount_offset)?;
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

pub(in crate::fault_command) fn translate_exception_evidence(
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
        command_icount: raw_to_logical_tick(
            raw_u64(raw, 40).map_err(invalid)?,
            logical_icount_offset,
        )?,
        delivered_icount: raw_to_logical_tick(event.observed_icount, logical_icount_offset)?,
        entry_pc: raw_u64(raw, 64).map_err(invalid)?,
        before_sha256: event.before_hash,
        after_sha256: event.after_hash,
    };
    evidence
        .encode()
        .map_err(|_source| FaultCommandBridgeError::ExceptionEvidence)
}
