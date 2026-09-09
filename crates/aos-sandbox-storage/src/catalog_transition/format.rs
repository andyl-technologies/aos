//! Authenticated catalog-transition record encoding and chain validation.
//!
//! The journal stores canonical JSON envelopes with a key identity and an
//! HMAC over the nested payload. Payloads are typed as a reservation, a
//! physical-state transition, or the single catalog head:
//!
//! ```text
//! AuthenticatedRecord {
//!   payload: ReservationPayload | TransitionPayload | HeadPayload,
//!   key_id: [u8; 16],
//!   mac: HMAC-SHA256(record-domain || canonical-payload),
//! }
//! ```
//!
//! Recovery authenticates and canonicalizes every envelope, validates each
//! payload independently, then requires one connected reservation/transition
//! chain ending at the authenticated head. A reservation without a transition
//! is permitted only at the current head and represents the pre-effect crash
//! boundary.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::ObjectDigest;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    AuthenticatedRecord, CatalogRecordFormatV1, CatalogReservation, EXECUTION_FORMAT_VERSION,
    EXECUTION_SNAPSHOT_VARIABLE_ARRAY_BYTES, EXECUTION_TRANSITION_DIGEST_DOMAIN, HEAD_MAGIC,
    HeadPayload, HeadPayloadV1, HeadPayloadV2, LEGACY_FORMAT_VERSION, MAXIMUM_JSON_BYTE_EXPANSION,
    MAXIMUM_RECORD_BYTES, PhysicalCatalogState, PhysicalStateFormatV1, RECORD_MAC_DOMAIN,
    RESERVATION_MAGIC, ReservationPayload, ReservationPayloadV1, ReservationPayloadV2,
    TRANSITION_DIGEST_DOMAIN, TRANSITION_MAGIC, TransitionPayload, TransitionPayloadV1,
    TransitionPayloadV2, VARIABLE_TRANSITION_ARRAY_BYTES, capture_guid,
    maximum_snapshot_root_metadata_wire,
};
use crate::{CatalogPlanV1, ResolvedCatalogCommitmentV1, StorageStateError};

type HmacSha256 = Hmac<Sha256>;

pub(super) fn transition_payload(
    operation_id: [u8; 16],
    mutation_digest: ObjectDigest,
    catalog: &ResolvedCatalogCommitmentV1,
    predecessor: &PhysicalCatalogState,
    result_state: &PhysicalCatalogState,
    object_guid: Option<u64>,
    observation_digest: ObjectDigest,
) -> Result<TransitionPayload, StorageStateError> {
    Ok(TransitionPayload {
        format: match result_state.format {
            PhysicalStateFormatV1::LegacyV1 => CatalogRecordFormatV1::LegacyV1,
            PhysicalStateFormatV1::ExecutionV2 => CatalogRecordFormatV1::ExecutionV2,
        },
        operation_id,
        mutation_digest: *mutation_digest.as_bytes(),
        catalog: catalog.binding().into(),
        predecessor: predecessor.binding.into(),
        result: result_state.binding.into(),
        observation_digest: *observation_digest.as_bytes(),
        object_guid,
        result_state: result_state.clone(),
    })
}

pub(super) fn encode_transition_payload(
    payload: &TransitionPayload,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<Vec<u8>, StorageStateError> {
    match payload.format {
        CatalogRecordFormatV1::LegacyV1 => {
            if payload.result_state.format != PhysicalStateFormatV1::LegacyV1 {
                return Err(StorageStateError::InvalidValue);
            }
            encode_authenticated(&transition_wire_v1(payload)?, key_id, secret)
        }
        CatalogRecordFormatV1::ExecutionV2 => {
            if payload.result_state.format != PhysicalStateFormatV1::ExecutionV2 {
                return Err(StorageStateError::InvalidValue);
            }
            encode_authenticated(&transition_wire_v2(payload)?, key_id, secret)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encoded_transition_size(
    operation_id: [u8; 16],
    mutation_digest: ObjectDigest,
    catalog: &ResolvedCatalogCommitmentV1,
    predecessor: &PhysicalCatalogState,
    result_state: &PhysicalCatalogState,
    object_guid: Option<u64>,
    observation_digest: ObjectDigest,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<usize, StorageStateError> {
    let payload = transition_payload(
        operation_id,
        mutation_digest,
        catalog,
        predecessor,
        result_state,
        object_guid,
        observation_digest,
    )?;
    encode_transition_payload(&payload, key_id, secret)?
        .len()
        .checked_add(transition_variable_array_bytes(catalog) * MAXIMUM_JSON_BYTE_EXPANSION)
        .ok_or(StorageStateError::InvalidValue)
}

pub(super) fn transition_variable_array_bytes(catalog: &ResolvedCatalogCommitmentV1) -> usize {
    let snapshot_metadata_digest_bytes = usize::from(
        catalog.format_version() == 3 && matches!(catalog.plan(), CatalogPlanV1::Snapshot { .. }),
    ) * EXECUTION_SNAPSHOT_VARIABLE_ARRAY_BYTES;

    VARIABLE_TRANSITION_ARRAY_BYTES + snapshot_metadata_digest_bytes
}

pub(super) fn validate_reserved_transition_bound(
    reservation: &CatalogReservation,
    catalog: &ResolvedCatalogCommitmentV1,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<(), StorageStateError> {
    let worst_case_guid = capture_guid(catalog.plan()).then_some(u64::MAX);
    let worst_case_state = reservation.predecessor.apply_with_snapshot_metadata(
        reservation.payload.operation_id,
        catalog,
        worst_case_guid,
        worst_case_guid
            .map(|guid| maximum_snapshot_root_metadata_wire(catalog, guid))
            .transpose()?
            .flatten(),
    )?;
    let expected = encoded_transition_size(
        reservation.payload.operation_id,
        ObjectDigest::from_bytes(reservation.payload.mutation_digest),
        catalog,
        &reservation.predecessor,
        &worst_case_state,
        worst_case_guid,
        ObjectDigest::from_bytes([u8::MAX; 32]),
        key_id,
        secret,
    )?;
    if usize::try_from(reservation.payload.maximum_transition_bytes)
        .map_err(|_| StorageStateError::CorruptRecord)?
        != expected
    {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(())
}

pub(super) fn transition_digest(
    payload: &TransitionPayload,
) -> Result<ObjectDigest, StorageStateError> {
    let bytes = match payload.format {
        CatalogRecordFormatV1::LegacyV1 => serde_json::to_vec(&transition_wire_v1(payload)?)
            .map_err(|_| StorageStateError::CorruptRecord)?,
        CatalogRecordFormatV1::ExecutionV2 => serde_json::to_vec(&transition_wire_v2(payload)?)
            .map_err(|_| StorageStateError::CorruptRecord)?,
    };
    let mut hash = Sha256::new();
    hash.update(match payload.format {
        CatalogRecordFormatV1::LegacyV1 => TRANSITION_DIGEST_DOMAIN,
        CatalogRecordFormatV1::ExecutionV2 => EXECUTION_TRANSITION_DIGEST_DOMAIN,
    });
    hash.update(bytes);
    Ok(ObjectDigest::from_bytes(hash.finalize().into()))
}

pub(super) fn validate_reservation_payload(
    payload: &ReservationPayload,
) -> Result<(), StorageStateError> {
    let catalog = payload.catalog.binding()?;
    let predecessor = payload.predecessor.binding()?;
    if payload.operation_id == [0; 16]
        || payload.request_digest == [0; 32]
        || payload.mutation_digest == [0; 32]
        || payload.catalog_bytes_digest == [0; 32]
        || payload.maximum_transition_bytes == 0
        || payload.maximum_transition_bytes as usize > MAXIMUM_RECORD_BYTES
        || predecessor.generation().checked_add(1) != Some(catalog.generation())
    {
        Err(StorageStateError::CorruptRecord)
    } else {
        Ok(())
    }
}

pub(super) fn validate_transition_payload(
    payload: &TransitionPayload,
) -> Result<(), StorageStateError> {
    if payload.operation_id == [0; 16]
        || payload.mutation_digest == [0; 32]
        || payload.observation_digest == [0; 32]
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let predecessor = payload.predecessor.binding()?;
    if payload.result_state.binding != payload.result.binding()?
        || payload.result_state.wire.predecessor_state != Some(predecessor.into())
        || payload.result_state.wire.resolution != Some(payload.catalog)
        || payload.catalog.generation.checked_add(1)
            != Some(payload.result_state.binding.generation())
        || matches!(
            (payload.format, payload.result_state.format),
            (
                CatalogRecordFormatV1::LegacyV1,
                PhysicalStateFormatV1::ExecutionV2
            ) | (
                CatalogRecordFormatV1::ExecutionV2,
                PhysicalStateFormatV1::LegacyV1
            )
        )
    {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(())
}

pub(super) fn validate_head(
    head: &HeadPayload,
    transitions: &BTreeMap<[u8; 16], TransitionPayload>,
) -> Result<(), StorageStateError> {
    match (
        head.genesis_state.as_ref(),
        head.operation_id,
        head.transition_digest,
    ) {
        (Some(state), None, None) if transitions.is_empty() => {
            if state.binding != head.binding.binding()?
                || !record_format_matches_state(head.format, state.format)
            {
                return Err(StorageStateError::CorruptRecord);
            }
        }
        (None, Some(operation_id), Some(digest)) => {
            let transition = transitions
                .get(&operation_id)
                .ok_or(StorageStateError::CorruptRecord)?;
            if head.binding != transition.result
                || digest != *transition_digest(transition)?.as_bytes()
                || head.format != transition.format
                || transitions
                    .values()
                    .any(|candidate| candidate.result.generation > head.binding.generation)
            {
                return Err(StorageStateError::CorruptRecord);
            }
        }
        _ => return Err(StorageStateError::CorruptRecord),
    }
    Ok(())
}

pub(super) fn validate_catalog_chain(
    head_payload: Option<&HeadPayload>,
    head: Option<&PhysicalCatalogState>,
    reservations: &BTreeMap<[u8; 16], CatalogReservation>,
    transitions: &BTreeMap<[u8; 16], TransitionPayload>,
) -> Result<(), StorageStateError> {
    let (Some(head_payload), Some(head)) = (head_payload, head) else {
        return if reservations.is_empty() && transitions.is_empty() {
            Ok(())
        } else {
            Err(StorageStateError::CorruptRecord)
        };
    };

    if transitions
        .keys()
        .any(|operation_id| !reservations.contains_key(operation_id))
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let pending = reservations
        .iter()
        .filter(|(operation_id, _)| !transitions.contains_key(*operation_id))
        .collect::<Vec<_>>();
    if pending.len() > 1 {
        return Err(StorageStateError::CorruptRecord);
    }

    if transitions.is_empty() {
        if head.wire.predecessor_state.is_some()
            || head.wire.resolution.is_some()
            || !record_format_matches_state(head_payload.format, head.format)
            || pending
                .first()
                .is_some_and(|(_, reservation)| reservation.predecessor != *head)
        {
            return Err(StorageStateError::CorruptRecord);
        }
        return Ok(());
    }

    let result_bindings = transitions
        .values()
        .map(|transition| transition.result)
        .collect::<BTreeSet<_>>();
    let roots = transitions
        .iter()
        .filter(|(operation_id, _)| {
            reservations.get(*operation_id).is_some_and(|reservation| {
                !result_bindings.contains(&reservation.payload.predecessor)
            })
        })
        .collect::<Vec<_>>();
    let [(first_operation, _)] = roots.as_slice() else {
        return Err(StorageStateError::CorruptRecord);
    };
    let mut current = reservations
        .get(*first_operation)
        .ok_or(StorageStateError::CorruptRecord)?
        .predecessor
        .clone();
    if current.wire.predecessor_state.is_some() || current.wire.resolution.is_some() {
        return Err(StorageStateError::CorruptRecord);
    }

    let mut visited = BTreeSet::new();
    let mut last_operation = None;
    loop {
        let matching = transitions
            .iter()
            .filter(|(operation_id, _)| {
                !visited.contains(*operation_id)
                    && reservations.get(*operation_id).is_some_and(|reservation| {
                        reservation.predecessor.binding == current.binding
                    })
            })
            .collect::<Vec<_>>();
        if matching.is_empty() {
            break;
        }
        let [(operation_id, transition)] = matching.as_slice() else {
            return Err(StorageStateError::CorruptRecord);
        };
        let reservation = reservations
            .get(*operation_id)
            .ok_or(StorageStateError::CorruptRecord)?;
        let result = transition.result_state.clone();
        if reservation.predecessor != current
            || reservation.payload.format != transition.format
            || matches!(
                (current.format, transition.format),
                (
                    PhysicalStateFormatV1::ExecutionV2,
                    CatalogRecordFormatV1::LegacyV1
                )
            )
            || transition.operation_id != **operation_id
            || transition.mutation_digest != reservation.payload.mutation_digest
            || transition.catalog != reservation.payload.catalog
            || transition.predecessor != reservation.payload.predecessor
            || transition.result != result.binding.into()
        {
            return Err(StorageStateError::CorruptRecord);
        }
        visited.insert(**operation_id);
        last_operation = Some(**operation_id);
        current = result;
    }

    if visited.len() != transitions.len()
        || current != *head
        || !record_format_matches_state(head_payload.format, head.format)
        || head_payload.operation_id != last_operation
        || pending
            .first()
            .is_some_and(|(_, reservation)| reservation.predecessor != current)
    {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(())
}

#[derive(Deserialize)]
struct AuthenticatedRecordVersionProbe {
    payload: PayloadVersionProbe,
}

#[derive(Deserialize)]
struct PayloadVersionProbe {
    version: u16,
}

pub(super) fn payload_version(bytes: &[u8]) -> Result<u16, StorageStateError> {
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(StorageStateError::CorruptRecord);
    }
    serde_json::from_slice::<AuthenticatedRecordVersionProbe>(bytes)
        .map(|record| record.payload.version)
        .map_err(|_| StorageStateError::CorruptRecord)
}

pub(super) fn decode_reservation_payload(
    bytes: &[u8],
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<(ReservationPayload, PhysicalCatalogState), StorageStateError> {
    let (payload, predecessor) = match payload_version(bytes)? {
        LEGACY_FORMAT_VERSION => {
            let wire: ReservationPayloadV1 = decode_authenticated(bytes, key_id, secret)?;
            if wire.magic != RESERVATION_MAGIC || wire.version != LEGACY_FORMAT_VERSION {
                return Err(StorageStateError::CorruptRecord);
            }
            let predecessor = PhysicalCatalogState::from_legacy_wire(wire.predecessor_state)?;
            (
                ReservationPayload {
                    format: CatalogRecordFormatV1::LegacyV1,
                    operation_id: wire.operation_id,
                    request_digest: wire.request_digest,
                    mutation_digest: wire.mutation_digest,
                    catalog: wire.catalog,
                    catalog_bytes_digest: wire.catalog_bytes_digest,
                    predecessor: wire.predecessor,
                    maximum_transition_bytes: wire.maximum_transition_bytes,
                },
                predecessor,
            )
        }
        EXECUTION_FORMAT_VERSION => {
            let wire: ReservationPayloadV2 = decode_authenticated(bytes, key_id, secret)?;
            if wire.magic != RESERVATION_MAGIC || wire.version != EXECUTION_FORMAT_VERSION {
                return Err(StorageStateError::CorruptRecord);
            }
            let predecessor = PhysicalCatalogState::from_envelope(wire.predecessor_state)?;
            (
                ReservationPayload {
                    format: CatalogRecordFormatV1::ExecutionV2,
                    operation_id: wire.operation_id,
                    request_digest: wire.request_digest,
                    mutation_digest: wire.mutation_digest,
                    catalog: wire.catalog,
                    catalog_bytes_digest: wire.catalog_bytes_digest,
                    predecessor: wire.predecessor,
                    maximum_transition_bytes: wire.maximum_transition_bytes,
                },
                predecessor,
            )
        }
        _ => return Err(StorageStateError::CorruptRecord),
    };
    validate_reservation_payload(&payload)?;
    if predecessor.binding != payload.predecessor.binding()?
        || matches!(
            (predecessor.format, payload.format),
            (
                PhysicalStateFormatV1::ExecutionV2,
                CatalogRecordFormatV1::LegacyV1
            )
        )
    {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok((payload, predecessor))
}

pub(super) fn encode_reservation_payload(
    payload: &ReservationPayload,
    predecessor: &PhysicalCatalogState,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<Vec<u8>, StorageStateError> {
    match payload.format {
        CatalogRecordFormatV1::LegacyV1 => {
            if predecessor.format != PhysicalStateFormatV1::LegacyV1 {
                return Err(StorageStateError::InvalidTransition);
            }
            encode_authenticated(
                &ReservationPayloadV1 {
                    magic: RESERVATION_MAGIC.to_owned(),
                    version: LEGACY_FORMAT_VERSION,
                    operation_id: payload.operation_id,
                    request_digest: payload.request_digest,
                    mutation_digest: payload.mutation_digest,
                    catalog: payload.catalog,
                    catalog_bytes_digest: payload.catalog_bytes_digest,
                    predecessor: payload.predecessor,
                    predecessor_state: predecessor.wire.clone(),
                    maximum_transition_bytes: payload.maximum_transition_bytes,
                },
                key_id,
                secret,
            )
        }
        CatalogRecordFormatV1::ExecutionV2 => encode_authenticated(
            &ReservationPayloadV2 {
                magic: RESERVATION_MAGIC.to_owned(),
                version: EXECUTION_FORMAT_VERSION,
                operation_id: payload.operation_id,
                request_digest: payload.request_digest,
                mutation_digest: payload.mutation_digest,
                catalog: payload.catalog,
                catalog_bytes_digest: payload.catalog_bytes_digest,
                predecessor: payload.predecessor,
                predecessor_state: predecessor.envelope()?,
                maximum_transition_bytes: payload.maximum_transition_bytes,
            },
            key_id,
            secret,
        ),
    }
}

pub(super) fn decode_transition_payload(
    bytes: &[u8],
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<TransitionPayload, StorageStateError> {
    let payload = match payload_version(bytes)? {
        LEGACY_FORMAT_VERSION => {
            let wire: TransitionPayloadV1 = decode_authenticated(bytes, key_id, secret)?;
            if wire.magic != TRANSITION_MAGIC || wire.version != LEGACY_FORMAT_VERSION {
                return Err(StorageStateError::CorruptRecord);
            }
            TransitionPayload {
                format: CatalogRecordFormatV1::LegacyV1,
                operation_id: wire.operation_id,
                mutation_digest: wire.mutation_digest,
                catalog: wire.catalog,
                predecessor: wire.predecessor,
                result: wire.result,
                observation_digest: wire.observation_digest,
                object_guid: wire.object_guid,
                result_state: PhysicalCatalogState::from_legacy_wire(wire.result_state)?,
            }
        }
        EXECUTION_FORMAT_VERSION => {
            let wire: TransitionPayloadV2 = decode_authenticated(bytes, key_id, secret)?;
            if wire.magic != TRANSITION_MAGIC || wire.version != EXECUTION_FORMAT_VERSION {
                return Err(StorageStateError::CorruptRecord);
            }
            TransitionPayload {
                format: CatalogRecordFormatV1::ExecutionV2,
                operation_id: wire.operation_id,
                mutation_digest: wire.mutation_digest,
                catalog: wire.catalog,
                predecessor: wire.predecessor,
                result: wire.result,
                observation_digest: wire.observation_digest,
                object_guid: wire.object_guid,
                result_state: PhysicalCatalogState::from_execution_wire(wire.result_state)?,
            }
        }
        _ => return Err(StorageStateError::CorruptRecord),
    };
    validate_transition_payload(&payload)?;
    Ok(payload)
}

fn transition_wire_v1(
    payload: &TransitionPayload,
) -> Result<TransitionPayloadV1, StorageStateError> {
    if payload.format != CatalogRecordFormatV1::LegacyV1
        || payload.result_state.format != PhysicalStateFormatV1::LegacyV1
    {
        return Err(StorageStateError::InvalidTransition);
    }
    Ok(TransitionPayloadV1 {
        magic: TRANSITION_MAGIC.to_owned(),
        version: LEGACY_FORMAT_VERSION,
        operation_id: payload.operation_id,
        mutation_digest: payload.mutation_digest,
        catalog: payload.catalog,
        predecessor: payload.predecessor,
        result: payload.result,
        observation_digest: payload.observation_digest,
        object_guid: payload.object_guid,
        result_state: payload.result_state.wire.clone(),
    })
}

fn transition_wire_v2(
    payload: &TransitionPayload,
) -> Result<TransitionPayloadV2, StorageStateError> {
    if payload.format != CatalogRecordFormatV1::ExecutionV2
        || payload.result_state.format != PhysicalStateFormatV1::ExecutionV2
    {
        return Err(StorageStateError::InvalidTransition);
    }
    Ok(TransitionPayloadV2 {
        magic: TRANSITION_MAGIC.to_owned(),
        version: EXECUTION_FORMAT_VERSION,
        operation_id: payload.operation_id,
        mutation_digest: payload.mutation_digest,
        catalog: payload.catalog,
        predecessor: payload.predecessor,
        result: payload.result,
        observation_digest: payload.observation_digest,
        object_guid: payload.object_guid,
        result_state: payload.result_state.execution_wire()?,
    })
}

pub(super) fn decode_head_payload(
    bytes: &[u8],
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<HeadPayload, StorageStateError> {
    match payload_version(bytes)? {
        LEGACY_FORMAT_VERSION => {
            let wire: HeadPayloadV1 = decode_authenticated(bytes, key_id, secret)?;
            if wire.magic != HEAD_MAGIC || wire.version != LEGACY_FORMAT_VERSION {
                return Err(StorageStateError::CorruptRecord);
            }
            Ok(HeadPayload {
                format: CatalogRecordFormatV1::LegacyV1,
                binding: wire.binding,
                operation_id: wire.operation_id,
                transition_digest: wire.transition_digest,
                genesis_state: wire
                    .genesis_state
                    .map(PhysicalCatalogState::from_legacy_wire)
                    .transpose()?,
            })
        }
        EXECUTION_FORMAT_VERSION => {
            let wire: HeadPayloadV2 = decode_authenticated(bytes, key_id, secret)?;
            if wire.magic != HEAD_MAGIC || wire.version != EXECUTION_FORMAT_VERSION {
                return Err(StorageStateError::CorruptRecord);
            }
            Ok(HeadPayload {
                format: CatalogRecordFormatV1::ExecutionV2,
                binding: wire.binding,
                operation_id: wire.operation_id,
                transition_digest: wire.transition_digest,
                genesis_state: wire
                    .genesis_state
                    .map(PhysicalCatalogState::from_envelope)
                    .transpose()?,
            })
        }
        _ => Err(StorageStateError::CorruptRecord),
    }
}

pub(super) fn encode_head_payload(
    payload: &HeadPayload,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<Vec<u8>, StorageStateError> {
    match payload.format {
        CatalogRecordFormatV1::LegacyV1 => {
            if payload
                .genesis_state
                .as_ref()
                .is_some_and(|state| state.format != PhysicalStateFormatV1::LegacyV1)
            {
                return Err(StorageStateError::InvalidTransition);
            }
            encode_authenticated(
                &HeadPayloadV1 {
                    magic: HEAD_MAGIC.to_owned(),
                    version: LEGACY_FORMAT_VERSION,
                    binding: payload.binding,
                    operation_id: payload.operation_id,
                    transition_digest: payload.transition_digest,
                    genesis_state: payload
                        .genesis_state
                        .as_ref()
                        .map(|state| state.wire.clone()),
                },
                key_id,
                secret,
            )
        }
        CatalogRecordFormatV1::ExecutionV2 => encode_authenticated(
            &HeadPayloadV2 {
                magic: HEAD_MAGIC.to_owned(),
                version: EXECUTION_FORMAT_VERSION,
                binding: payload.binding,
                operation_id: payload.operation_id,
                transition_digest: payload.transition_digest,
                genesis_state: payload
                    .genesis_state
                    .as_ref()
                    .map(PhysicalCatalogState::envelope)
                    .transpose()?,
            },
            key_id,
            secret,
        ),
    }
}

fn record_format_matches_state(
    record: CatalogRecordFormatV1,
    state: PhysicalStateFormatV1,
) -> bool {
    matches!(
        (record, state),
        (
            CatalogRecordFormatV1::LegacyV1,
            PhysicalStateFormatV1::LegacyV1
        ) | (
            CatalogRecordFormatV1::ExecutionV2,
            PhysicalStateFormatV1::ExecutionV2
        )
    )
}

pub(super) fn encode_authenticated<T: Serialize>(
    payload: &T,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<Vec<u8>, StorageStateError> {
    let payload_bytes = serde_json::to_vec(payload).map_err(|_| StorageStateError::InvalidValue)?;
    let mac = record_mac(secret, &payload_bytes)?;
    let value = AuthenticatedRecord {
        payload,
        key_id,
        mac,
    };
    let bytes = serde_json::to_vec(&value).map_err(|_| StorageStateError::InvalidValue)?;
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(StorageStateError::InvalidValue);
    }
    Ok(bytes)
}

pub(super) fn decode_authenticated<T>(
    bytes: &[u8],
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<T, StorageStateError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(StorageStateError::CorruptRecord);
    }
    let envelope: AuthenticatedRecord<T> =
        serde_json::from_slice(bytes).map_err(|_| StorageStateError::CorruptRecord)?;
    let canonical = serde_json::to_vec(&envelope).map_err(|_| StorageStateError::CorruptRecord)?;
    let payload_bytes =
        serde_json::to_vec(&envelope.payload).map_err(|_| StorageStateError::CorruptRecord)?;
    if canonical != bytes
        || envelope.key_id != key_id
        || record_mac(secret, &payload_bytes)? != envelope.mac
    {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(envelope.payload)
}

pub(super) fn record_mac(secret: &[u8; 32], bytes: &[u8]) -> Result<[u8; 32], StorageStateError> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(RECORD_MAC_DOMAIN);
    mac.update(bytes);
    Ok(mac.finalize().into_bytes().into())
}

pub(super) fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
