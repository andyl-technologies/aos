//! Canonical operator-recovery record encodings and pure replay comparisons.
//!
//! Records use big-endian integer fields and exact canonical protobuf payloads:
//!
//! ```text
//! Issued: AOSORI1\0 | principal[32] | binding[32] | effect[32]
//!         | attempt:u32 | ambiguity_queries:u32 | state:u32 | action:i32
//!         | generation:u64 | request_len:u32 | current_len:u32 | request | current
//! Complete: AOSORC1\0 | issued_len:u32 | issued | result_len:u32 | result
//! Current: kind:u8 | actions:u8 | version_len:u32 | version | generation:u64
//!          | observation_sequence:u64 | transition_seconds:i64 | transition_nanos:u32
//! ```
//!
//! These helpers interpret owned DATA only. They never borrow the protected
//! writer or create authorization, effect handoffs, or signed receipts.

use aos_proto::aos::sandbox::v1::OperatorRecoveryAction;
use aos_sandbox_core::ObjectDigest;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{
    DormantOperatorRecoveryDurableStateV1, DormantOperatorRecoveryIssuedStateV1,
    DormantOperatorRecoveryReservationV1, MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1,
    MAXIMUM_OPERATOR_RECOVERY_EFFECT_ATTEMPTS_V1, RecoveryCurrentHeadV1,
};
use crate::cli_model::{InvalidObservationClientAdapter, OperatorRecoveryRequestV1};

const RECOVERY_ISSUED_MAGIC: &[u8; 8] = b"AOSORI1\0";
const RECOVERY_COMPLETE_MAGIC: &[u8; 8] = b"AOSORC1\0";
const MAXIMUM_OPERATOR_RECOVERY_RECORD_BYTES_V1: usize = 128 * 1024;

pub(in crate::controller) fn recovery_current_key(resource_id: [u8; 16]) -> Vec<u8> {
    [b"current/".as_slice(), resource_id.as_slice()].concat()
}

pub(super) fn recovery_reservation_key(principal: &[u8; 32], idempotency_key: &[u8]) -> Vec<u8> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.operator-recovery-idempotency.v1\0")
        .chain_update(principal)
        .chain_update((idempotency_key.len() as u64).to_be_bytes())
        .chain_update(idempotency_key)
        .finalize()
        .into();
    [b"idempotency/".as_slice(), digest.as_slice()].concat()
}

pub(super) fn recovery_transition_key(resource_id: [u8; 16], next_version: &[u8]) -> Vec<u8> {
    let version_digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.operator-recovery-version-key.v1\0")
        .chain_update((next_version.len() as u64).to_be_bytes())
        .chain_update(next_version)
        .finalize()
        .into();
    [
        b"transition/".as_slice(),
        resource_id.as_slice(),
        b"/".as_slice(),
        version_digest.as_slice(),
    ]
    .concat()
}

pub(super) fn recovery_effect_id(
    principal: ObjectDigest,
    request: &OperatorRecoveryRequestV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.operator-recovery-effect.v1\0")
            .chain_update(principal.as_bytes())
            .chain_update(request.authority_binding().as_bytes())
            .finalize()
            .into(),
    )
}

pub(super) fn recovery_issued_commit_id(
    issued: &DormantOperatorRecoveryIssuedStateV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.operator-recovery-issued-commit.v1\0")
            .chain_update(issued.effect_id.as_bytes())
            .chain_update(issued.attempt.to_be_bytes())
            .chain_update(issued.ambiguity_queries.to_be_bytes())
            .finalize()
            .into(),
    )
}

pub(super) fn recovery_terminal_commit_id(
    issued: &DormantOperatorRecoveryIssuedStateV1,
    result: &aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.operator-recovery-terminal-commit.v1\0")
            .chain_update(issued.effect_id.as_bytes())
            .chain_update(issued.attempt.to_be_bytes())
            .chain_update((result.resource_version.len() as u64).to_be_bytes())
            .chain_update(&result.resource_version)
            .finalize()
            .into(),
    )
}

pub(super) fn encode_issued_recovery_reservation(
    issued: &DormantOperatorRecoveryIssuedStateV1,
) -> Result<Vec<u8>, InvalidObservationClientAdapter> {
    let request = issued.request.to_proto().encode_to_vec();
    let request_length = u32::try_from(request.len())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let current_length = u32::try_from(issued.current.len())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let current_head = decode_recovery_current(&issued.current)?;
    if issued.binding != issued.request.authority_binding()
        || issued.effect_id != recovery_effect_id(issued.principal, &issued.request)
        || issued.current_generation != current_head.desired_generation
        || issued.attempt == 0
        || issued.attempt > MAXIMUM_OPERATOR_RECOVERY_EFFECT_ATTEMPTS_V1
        || issued.ambiguity_queries > MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1
        || !matches!(
            (
                issued.recovery_state,
                issued.attempt,
                issued.ambiguity_queries
            ),
            (DormantOperatorRecoveryDurableStateV1::InitialIssue, 1, 0)
                | (
                    DormantOperatorRecoveryDurableStateV1::ReissuedAfterAbsence,
                    2..=MAXIMUM_OPERATOR_RECOVERY_EFFECT_ATTEMPTS_V1,
                    0
                )
                | (
                    DormantOperatorRecoveryDurableStateV1::ObservationUnknown,
                    _,
                    1..=MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1
                )
        )
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    validate_recovery_current(&issued.request, &issued.current)?;
    let encoded_length = 136_usize
        .checked_add(request.len())
        .and_then(|length| length.checked_add(issued.current.len()))
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if encoded_length > MAXIMUM_OPERATOR_RECOVERY_RECORD_BYTES_V1 {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let mut encoded = Vec::with_capacity(encoded_length);
    encoded.extend_from_slice(RECOVERY_ISSUED_MAGIC);
    encoded.extend_from_slice(issued.principal.as_bytes());
    encoded.extend_from_slice(issued.binding.as_bytes());
    encoded.extend_from_slice(issued.effect_id.as_bytes());
    encoded.extend_from_slice(&issued.attempt.to_be_bytes());
    encoded.extend_from_slice(&issued.ambiguity_queries.to_be_bytes());
    encoded.extend_from_slice(&issued.recovery_state.to_wire().to_be_bytes());
    encoded.extend_from_slice(&issued.request.action().to_be_bytes());
    encoded.extend_from_slice(&issued.current_generation.to_be_bytes());
    encoded.extend_from_slice(&request_length.to_be_bytes());
    encoded.extend_from_slice(&current_length.to_be_bytes());
    encoded.extend_from_slice(&request);
    encoded.extend_from_slice(&issued.current);
    Ok(encoded)
}

fn encode_completed_recovery_reservation(
    issued: &DormantOperatorRecoveryIssuedStateV1,
    result: &aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
) -> Result<Vec<u8>, InvalidObservationClientAdapter> {
    validate_recovery_terminal(&issued.request, result)?;
    let issued = encode_issued_recovery_reservation(issued)?;
    let result = result.encode_to_vec();
    let issued_length = u32::try_from(issued.len())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let result_length = u32::try_from(result.len())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let encoded_length = 16_usize
        .checked_add(issued.len())
        .and_then(|length| length.checked_add(result.len()))
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if encoded_length > MAXIMUM_OPERATOR_RECOVERY_RECORD_BYTES_V1 {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let mut encoded = Vec::with_capacity(encoded_length);
    encoded.extend_from_slice(RECOVERY_COMPLETE_MAGIC);
    encoded.extend_from_slice(&issued_length.to_be_bytes());
    encoded.extend_from_slice(&issued);
    encoded.extend_from_slice(&result_length.to_be_bytes());
    encoded.extend_from_slice(&result);
    Ok(encoded)
}

pub(super) fn decode_recovery_reservation(
    encoded: &[u8],
) -> Result<DormantOperatorRecoveryReservationV1, InvalidObservationClientAdapter> {
    if encoded.len() > MAXIMUM_OPERATOR_RECOVERY_RECORD_BYTES_V1 {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    if encoded.get(..8) == Some(RECOVERY_ISSUED_MAGIC.as_slice()) {
        return decode_issued_recovery_reservation(encoded)
            .map(DormantOperatorRecoveryReservationV1::Issued);
    }
    if encoded.len() < 16 || encoded.get(..8) != Some(RECOVERY_COMPLETE_MAGIC.as_slice()) {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let issued_length = u32::from_be_bytes(
        encoded[8..12]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ) as usize;
    let issued_end = 12_usize
        .checked_add(issued_length)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let result_length_end = issued_end
        .checked_add(4)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if encoded.len() < result_length_end {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let result_length = u32::from_be_bytes(
        encoded[issued_end..result_length_end]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ) as usize;
    let result_end = result_length_end
        .checked_add(result_length)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if result_end != encoded.len() {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let issued = decode_issued_recovery_reservation(&encoded[12..issued_end])?;
    let result = aos_proto::aos::sandbox::v1::OperatorRecoveryResult::decode_from_slice(
        &encoded[result_length_end..result_end],
    )
    .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if result.encode_to_vec() != encoded[result_length_end..result_end] {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    validate_recovery_terminal(&issued.request, &result)?;
    Ok(DormantOperatorRecoveryReservationV1::Complete { issued, result })
}

fn decode_issued_recovery_reservation(
    encoded: &[u8],
) -> Result<DormantOperatorRecoveryIssuedStateV1, InvalidObservationClientAdapter> {
    if encoded.len() < 136 || encoded.get(..8) != Some(RECOVERY_ISSUED_MAGIC.as_slice()) {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let principal = ObjectDigest::from_bytes(
        encoded[8..40]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let binding = ObjectDigest::from_bytes(
        encoded[40..72]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let effect_id = ObjectDigest::from_bytes(
        encoded[72..104]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let attempt = u32::from_be_bytes(
        encoded[104..108]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let ambiguity_queries = u32::from_be_bytes(
        encoded[108..112]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let recovery_state = DormantOperatorRecoveryDurableStateV1::from_wire(u32::from_be_bytes(
        encoded[112..116]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ))
    .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let action = i32::from_be_bytes(
        encoded[116..120]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let current_generation = u64::from_be_bytes(
        encoded[120..128]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let request_length = u32::from_be_bytes(
        encoded[128..132]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ) as usize;
    let current_length = u32::from_be_bytes(
        encoded[132..136]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ) as usize;
    let request_end = 136_usize
        .checked_add(request_length)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let current_end = request_end
        .checked_add(current_length)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if current_end != encoded.len() {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let request_proto = aos_proto::aos::sandbox::v1::OperatorRecoveryRequest::decode_from_slice(
        &encoded[136..request_end],
    )
    .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if request_proto.encode_to_vec() != encoded[136..request_end] {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let request = OperatorRecoveryRequestV1::try_from(request_proto)?;
    let issued = DormantOperatorRecoveryIssuedStateV1 {
        principal,
        binding,
        effect_id,
        request,
        current: encoded[request_end..current_end].to_vec(),
        current_generation,
        attempt,
        ambiguity_queries,
        recovery_state,
    };
    if action != issued.request.action() || encode_issued_recovery_reservation(&issued)? != encoded
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    Ok(issued)
}

pub(super) fn validate_recovery_reservation_key(
    issued: &DormantOperatorRecoveryIssuedStateV1,
    key: &[u8],
) -> Result<(), InvalidObservationClientAdapter> {
    if key
        != recovery_reservation_key(
            issued.principal.as_bytes(),
            issued.request.idempotency_key(),
        )
    {
        Err(InvalidObservationClientAdapter::InvalidOperatorRecovery)
    } else {
        Ok(())
    }
}

pub(super) fn validate_recovery_replay(
    issued: &DormantOperatorRecoveryIssuedStateV1,
    principal: ObjectDigest,
    binding: ObjectDigest,
    effect_id: ObjectDigest,
    request: &OperatorRecoveryRequestV1,
    reservation_key: &[u8],
) -> Result<(), InvalidObservationClientAdapter> {
    validate_recovery_reservation_key(issued, reservation_key)?;
    if issued.principal != principal
        || issued.binding != binding
        || issued.effect_id != effect_id
        || &issued.request != request
    {
        Err(InvalidObservationClientAdapter::InvalidOperatorRecovery)
    } else {
        Ok(())
    }
}

pub(super) fn latest_recovery_transition(
    conditions: &[crate::controller_query::CheckedConditionV1],
    fallback: Option<(i64, u32)>,
) -> Result<(i64, u32), InvalidObservationClientAdapter> {
    conditions
        .iter()
        .map(crate::controller_query::CheckedConditionV1::transition)
        .chain(fallback)
        .max()
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)
}

pub(super) fn encode_recovery_current(
    kind: u8,
    allowed_actions: u8,
    version: &[u8],
    desired_generation: u64,
    observation_sequence: u64,
    transition: (i64, u32),
) -> Result<Vec<u8>, InvalidObservationClientAdapter> {
    if !matches!(kind, 1 | 2)
        || version.is_empty()
        || desired_generation == 0
        || observation_sequence == 0
        || transition.1 >= 1_000_000_000
        || !(-62_135_596_800..=253_402_300_799).contains(&transition.0)
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let version_len = u32::try_from(version.len())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let mut value = Vec::with_capacity(34 + version.len());
    value.extend_from_slice(&[kind, allowed_actions]);
    value.extend_from_slice(&version_len.to_be_bytes());
    value.extend_from_slice(version);
    value.extend_from_slice(&desired_generation.to_be_bytes());
    value.extend_from_slice(&observation_sequence.to_be_bytes());
    value.extend_from_slice(&transition.0.to_be_bytes());
    value.extend_from_slice(&transition.1.to_be_bytes());
    Ok(value)
}

pub(in crate::controller) fn decode_recovery_current(
    current: &[u8],
) -> Result<RecoveryCurrentHeadV1, InvalidObservationClientAdapter> {
    if current.len() < 35 {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let version_len = u32::from_be_bytes(
        current[2..6]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    ) as usize;
    let version_end = 6_usize
        .checked_add(version_len)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if current.len() != version_end + 28 {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let desired_generation = u64::from_be_bytes(
        current[version_end..version_end + 8]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let observation_sequence = u64::from_be_bytes(
        current[version_end + 8..version_end + 16]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let seconds = i64::from_be_bytes(
        current[version_end + 16..version_end + 24]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    let nanoseconds = u32::from_be_bytes(
        current[version_end + 24..version_end + 28]
            .try_into()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
    );
    encode_recovery_current(
        current[0],
        current[1],
        &current[6..version_end],
        desired_generation,
        observation_sequence,
        (seconds, nanoseconds),
    )?;
    Ok(RecoveryCurrentHeadV1 {
        kind: current[0],
        allowed_actions: current[1],
        version: current[6..version_end].to_vec(),
        desired_generation,
        observation_sequence,
        transition: (seconds, nanoseconds),
    })
}

pub(super) fn recovery_current_evidence(
    resource_id: [u8; 16],
    current: &[u8],
) -> aos_proto::aos::sandbox::v1::ObjectDescriptor {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.operator-recovery-current-evidence.v1\0")
        .chain_update(resource_id)
        .chain_update((current.len() as u64).to_be_bytes())
        .chain_update(current)
        .finalize()
        .into();
    aos_proto::aos::sandbox::v1::ObjectDescriptor {
        media_type: "application/vnd.aos.sandbox.operator-recovery-evidence.v1".into(),
        sha256: digest.to_vec(),
        encoded_size: (16 + current.len()) as u64,
        ..Default::default()
    }
}

pub(in crate::controller) fn validate_recovery_current(
    request: &OperatorRecoveryRequestV1,
    current: &[u8],
) -> Result<(), InvalidObservationClientAdapter> {
    let head = decode_recovery_current(current)?;
    if head.version.as_slice() != request.expected_resource_version()
        || head.allowed_actions & (1_u8 << (request.action() - 1)) == 0
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let evidence = request.evidence();
    let expected = recovery_current_evidence(request.resource_id(), current);
    // Compare only the established evidence fields; unrelated protobuf DATA
    // is not part of this current-head binding.
    if evidence.media_type != expected.media_type
        || evidence.sha256 != expected.sha256
        || evidence.encoded_size != expected.encoded_size
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    Ok(())
}

pub(super) fn validate_recovery_terminal(
    request: &OperatorRecoveryRequestV1,
    result: &aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
) -> Result<(), InvalidObservationClientAdapter> {
    if requires_physical_recovery_receipt(request.action())
        || result.resource_id.as_slice() != request.resource_id()
        || result.action.to_i32() != request.action()
        || result.resource_version.is_empty()
        || result.resource_version.len() > crate::cli_model::MAXIMUM_CLI_OPAQUE_BYTES
        || result.resource_version == request.expected_resource_version()
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    crate::cli_model::CheckedOperatorRecoveryResultV1::try_from(result.clone())
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    Ok(())
}

pub(super) fn requires_physical_recovery_receipt(action: i32) -> bool {
    action == OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RECONCILE as i32
        || action == OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR as i32
}

pub(super) fn recovery_terminal_records(
    issued: &DormantOperatorRecoveryIssuedStateV1,
    result: &aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
) -> Result<(Vec<u8>, Vec<u8>), InvalidObservationClientAdapter> {
    validate_recovery_terminal(&issued.request, result)?;
    let current_head = decode_recovery_current(&issued.current)?;
    let desired_generation = result
        .conditions
        .iter()
        .map(|condition| condition.desired_generation)
        .max()
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let observation_sequence = result
        .conditions
        .iter()
        .map(|condition| condition.observation_sequence)
        .max()
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let transition = result
        .conditions
        .iter()
        .filter_map(|condition| condition.transition_time.as_option())
        .map(|timestamp| (timestamp.seconds, timestamp.nanoseconds))
        .max()
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if result.resource_version == current_head.version
        || desired_generation < current_head.desired_generation
        || observation_sequence <= current_head.observation_sequence
        || transition < current_head.transition
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let next_current = encode_recovery_current(
        current_head.kind,
        0,
        &result.resource_version,
        desired_generation,
        observation_sequence,
        transition,
    )?;
    let completed = encode_completed_recovery_reservation(issued, result)?;
    Ok((next_current, completed))
}
