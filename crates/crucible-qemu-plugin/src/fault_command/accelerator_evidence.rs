//! Accelerator command and evidence validation.

use super::*;
pub(super) fn translate_accelerator_evidence(
    raw: &[u8],
    event: &QemuFaultEvent,
    manifest_payload: &[u8],
    expectation: &AcceleratorCommandExpectation,
) -> Result<Vec<u8>, FaultCommandBridgeError> {
    use node_fault_field::*;

    if raw.len() != 256
        || event.command_kind != expectation.command_kind
        || event.binding_hash != expectation.binding_hash
        || event.generation != expectation.generation
        || event.action_hash != expectation.action_hash
        || event.target_hash != expectation.target_hash
        || event.model_phase != expectation.model_phase
        || event.outcome != FaultEventOutcomeV1::Applied as u16
    {
        return Err(FaultCommandBridgeError::AcceleratorEvidence);
    }
    let manifest = FaultAcceleratorCapabilityManifestV1::decode(manifest_payload)
        .map_err(|_| FaultCommandBridgeError::AcceleratorEvidence)?;
    let device = accelerator_field(expectation, T1)?;
    let row = manifest
        .rows
        .iter()
        .find(|row| fault_object_id_hash_v1(&row.id).as_slice() == device)
        .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?;
    let common = |before_at: usize, after_at: usize, binding_at: usize| {
        if raw.get(before_at..before_at + 32) != Some(event.before_hash.as_slice())
            || raw.get(after_at..after_at + 32) != Some(event.after_hash.as_slice())
            || raw.get(binding_at..binding_at + 32) != Some(expectation.binding_hash.as_slice())
        {
            Err(FaultCommandBridgeError::AcceleratorEvidence)
        } else {
            Ok(())
        }
    };
    match raw.get(..8) {
        Some(b"CRUCALE1")
            if expectation.command_kind == FaultCommandKind::AcceleratorLifecycle as u16 =>
        {
            if raw_u32(raw, 16)? != accelerator_u32(expectation, P2)?
                || raw_u32(raw, 20)? != accelerator_u32(expectation, P3)?
                || raw_u32(raw, 24)? != accelerator_u32(expectation, P4)?
                || raw.get(64..96) != Some(device)
            {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
            common(96, 128, 200)?;
        }
        Some(b"CRUCAMI1")
            if expectation.command_kind == FaultCommandKind::AcceleratorMemoryEvent as u16 =>
        {
            let transform = accelerator_field(expectation, P8)?;
            if raw_u64(raw, 16)? != accelerator_u64(expectation, P1)?
                || raw_u64(raw, 24)? != accelerator_u64(expectation, P2)?
                || raw_u32(raw, 32)? != accelerator_u32(expectation, P4)?
                || raw_u32(raw, 36)? != u32::from(accelerator_bool(expectation, P5)?)
                || raw_u64(raw, 40)? != accelerator_u64(expectation, P6)?
                || raw.get(168..200) != Some(sha2::Sha256::digest(transform).as_slice())
            {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
            common(72, 104, 136)?;
        }
        Some(b"CRUCAME1")
            if expectation.command_kind == FaultCommandKind::AcceleratorMemoryEvent as u16 =>
        {
            let transform = accelerator_field(expectation, P8)?;
            if raw_u64(raw, 24)? != accelerator_u64(expectation, P1)?
                || raw_u64(raw, 32)? != accelerator_u64(expectation, P2)?
                || raw_u32(raw, 40)? != accelerator_u32(expectation, P4)?
                || raw_u32(raw, 44)? != u32::from(accelerator_bool(expectation, P5)?)
                || raw_u64(raw, 48)? != accelerator_u64(expectation, P6)?
                || raw.get(168..200) != Some(sha2::Sha256::digest(transform).as_slice())
            {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
            common(104, 136, 200)?;
        }
        Some(b"CRUCARE1")
            if expectation.command_kind == FaultCommandKind::AcceleratorResultTransform as u16 =>
        {
            let selector = policy_json(accelerator_field(expectation, P1)?, true)?;
            let mutation = policy_json(accelerator_field(expectation, P2)?, true)?;
            let offset = mutation
                .get("offset")
                .and_then(serde_json::Value::as_u64)
                .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?;
            let mask = mutation
                .get("mask")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| hex::decode(value).ok())
                .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?;
            let value = mutation
                .get("value")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| hex::decode(value).ok())
                .ok_or(FaultCommandBridgeError::AcceleratorEvidence)?;
            let class_id = raw_u16(raw, 8)?;
            let expected_job = match class_id {
                1 if row.class_mask & 1 != 0 => "vector-add",
                2 if row.class_mask & 2 != 0 => "matrix-multiply",
                3 if row.class_mask & 4 != 0 => "lookup-table",
                _ => return Err(FaultCommandBridgeError::AcceleratorEvidence),
            };
            let queue_id = u64::from(raw_u16(raw, 12)?);
            if raw_u64(raw, 24)? != offset
                || raw_u64(raw, 32)? != mask.len() as u64
                || selector.get("job_kind").and_then(serde_json::Value::as_str)
                    != Some(expected_job)
                || selector
                    .get("queue")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|queue| queue != queue_id)
                || queue_id < u64::from(row.queue_start)
                || queue_id > u64::from(row.queue_end)
                || raw_u64(raw, 40)? > u64::from(row.maximum_output_bytes)
                || raw.get(112..144) != Some(sha2::Sha256::digest(&mask).as_slice())
                || raw.get(144..176) != Some(sha2::Sha256::digest(&value).as_slice())
            {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
            common(48, 80, 200)?;
        }
        Some(b"CRUCASE1")
            if expectation.command_kind == FaultCommandKind::AcceleratorService as u16 =>
        {
            let class_id = raw_u16(raw, 8)?;
            let ratio = accelerator_field(expectation, P1)?;
            let thermal = policy_json(accelerator_field(expectation, P6)?, true)?;
            if !(1..=3).contains(&class_id)
                || row.class_mask & (1 << (class_id - 1)) == 0
                || raw_u16(raw, 12)? < row.queue_start
                || raw_u16(raw, 12)? > row.queue_end
                || raw_u64(raw, 152)? > u64::from(row.maximum_input_bytes)
                || raw_u64(raw, 160)? > u64::from(row.maximum_output_bytes)
                || raw.get(40..56) != Some(ratio)
                || raw_u64(raw, 56)?
                    != if accelerator_bool(expectation, P2)? {
                        accelerator_u64(expectation, P3)?
                    } else {
                        u64::MAX
                    }
                || raw_u64(raw, 64)?
                    != if accelerator_bool(expectation, P4)? {
                        accelerator_u64(expectation, P5)?
                    } else {
                        u64::MAX
                    }
                || thermal
                    .get("temperature_millikelvin")
                    .and_then(serde_json::Value::as_u64)
                    != Some(raw_u64(raw, 136)?)
                || thermal
                    .get("power_milliwatts")
                    .and_then(serde_json::Value::as_u64)
                    != Some(raw_u64(raw, 144)?)
            {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
            common_hashes(raw, event, 88, 168)?;
            if raw.get(168..200) != Some(expectation.binding_hash.as_slice()) {
                return Err(FaultCommandBridgeError::AcceleratorEvidence);
            }
        }
        _ => return Err(FaultCommandBridgeError::AcceleratorEvidence),
    }
    Ok(raw.to_vec())
}

pub(super) fn common_hashes(
    raw: &[u8],
    event: &QemuFaultEvent,
    before_len: usize,
    after_len: usize,
) -> Result<(), FaultCommandBridgeError> {
    if sha2::Sha256::digest(&raw[..before_len]).as_slice() != event.before_hash
        || sha2::Sha256::digest(&raw[..after_len]).as_slice() != event.after_hash
    {
        return Err(FaultCommandBridgeError::AcceleratorEvidence);
    }
    Ok(())
}

pub(super) fn boundary_phase(value: u16) -> Result<FaultBoundaryPhase, FaultCommandBridgeError> {
    match value {
        1 => Ok(FaultBoundaryPhase::NodeBoundary),
        2 => Ok(FaultBoundaryPhase::BeforeInstruction),
        3 => Ok(FaultBoundaryPhase::AfterInstruction),
        4 => Ok(FaultBoundaryPhase::BeforeMemoryAccess),
        5 => Ok(FaultBoundaryPhase::AfterMemoryAccess),
        6 => Ok(FaultBoundaryPhase::Interrupt),
        7 => Ok(FaultBoundaryPhase::Device),
        _ => Err(FaultCommandBridgeError::QemuPhase { value }),
    }
}

pub(super) fn result_status(value: u16) -> Result<FaultResultStatus, FaultCommandBridgeError> {
    match value {
        1 => Ok(FaultResultStatus::Applied),
        2 => Ok(FaultResultStatus::NotApplicable),
        3 => Ok(FaultResultStatus::PreconditionMismatch),
        4 => Ok(FaultResultStatus::InvalidTarget),
        5 => Ok(FaultResultStatus::InvalidPhase),
        6 => Ok(FaultResultStatus::UnsupportedCapability),
        7 => Ok(FaultResultStatus::PastBoundary),
        8 => Ok(FaultResultStatus::ResourceLimit),
        9 => Ok(FaultResultStatus::GuestRejected),
        10 => Ok(FaultResultStatus::InternalError),
        11 => Ok(FaultResultStatus::MalformedCommand),
        12 => Ok(FaultResultStatus::DuplicateSequence),
        13 => Ok(FaultResultStatus::AuthenticationFailed),
        14 => Ok(FaultResultStatus::Prepared),
        _ => Err(FaultCommandBridgeError::QemuStatus { value }),
    }
}

pub(super) fn event_outcome(value: u16) -> Result<FaultEventOutcomeV1, FaultCommandBridgeError> {
    match value {
        1 => Ok(FaultEventOutcomeV1::Applied),
        2 => Ok(FaultEventOutcomeV1::Suppressed),
        3 => Ok(FaultEventOutcomeV1::Corrected),
        4 => Ok(FaultEventOutcomeV1::Error),
        5 => Ok(FaultEventOutcomeV1::Passed),
        6 => Ok(FaultEventOutcomeV1::Recovered),
        _ => Err(FaultCommandBridgeError::QemuEventOutcome { value }),
    }
}

pub(super) fn rejection_status(error: FaultAbiError) -> FaultResultStatus {
    match error {
        FaultAbiError::PayloadDigest => FaultResultStatus::AuthenticationFailed,
        _ => FaultResultStatus::MalformedCommand,
    }
}
