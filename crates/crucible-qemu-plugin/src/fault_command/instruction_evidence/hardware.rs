//! Hardware exception and error evidence translation.

use super::*;

pub(in crate::fault_command) fn translate_hardware_exception_evidence(
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

pub(in crate::fault_command) fn translate_hardware_ecc_evidence(
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

pub(in crate::fault_command) fn validate_ghes_memory_record(
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

pub(in crate::fault_command) fn instruction_system_digest(
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
