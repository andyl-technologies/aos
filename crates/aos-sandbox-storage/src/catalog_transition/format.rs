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
    AuthenticatedRecord, CatalogReservation, FORMAT_VERSION, HEAD_MAGIC, HeadPayload,
    MAXIMUM_JSON_BYTE_EXPANSION, MAXIMUM_RECORD_BYTES, PhysicalCatalogState, RECORD_MAC_DOMAIN,
    RESERVATION_MAGIC, ReservationPayload, TRANSITION_DIGEST_DOMAIN, TRANSITION_MAGIC,
    TransitionPayload, VARIABLE_TRANSITION_ARRAY_BYTES, capture_guid,
};
use crate::{ResolvedCatalogCommitmentV1, StorageStateError};

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
        magic: TRANSITION_MAGIC.to_owned(),
        version: FORMAT_VERSION,
        operation_id,
        mutation_digest: *mutation_digest.as_bytes(),
        catalog: catalog.binding().into(),
        predecessor: predecessor.binding.into(),
        result: result_state.binding.into(),
        observation_digest: *observation_digest.as_bytes(),
        object_guid,
        result_state: result_state.wire.clone(),
    })
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
    encode_authenticated(&payload, key_id, secret)?
        .len()
        .checked_add(VARIABLE_TRANSITION_ARRAY_BYTES * MAXIMUM_JSON_BYTE_EXPANSION)
        .ok_or(StorageStateError::InvalidValue)
}

pub(super) fn validate_reserved_transition_bound(
    reservation: &CatalogReservation,
    catalog: &ResolvedCatalogCommitmentV1,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<(), StorageStateError> {
    let worst_case_guid = capture_guid(catalog.plan()).then_some(u64::MAX);
    let worst_case_state = reservation.predecessor.apply(
        reservation.payload.operation_id,
        catalog,
        worst_case_guid,
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
    let bytes = serde_json::to_vec(payload).map_err(|_| StorageStateError::CorruptRecord)?;
    let mut hash = Sha256::new();
    hash.update(TRANSITION_DIGEST_DOMAIN);
    hash.update(bytes);
    Ok(ObjectDigest::from_bytes(hash.finalize().into()))
}

pub(super) fn validate_reservation_payload(
    payload: &ReservationPayload,
) -> Result<(), StorageStateError> {
    let catalog = payload.catalog.binding()?;
    let predecessor = payload.predecessor.binding()?;
    if payload.magic != RESERVATION_MAGIC
        || payload.version != FORMAT_VERSION
        || payload.operation_id == [0; 16]
        || payload.request_digest == [0; 32]
        || payload.mutation_digest == [0; 32]
        || payload.catalog_bytes_digest == [0; 32]
        || payload.maximum_transition_bytes == 0
        || payload.maximum_transition_bytes as usize > MAXIMUM_RECORD_BYTES
        || catalog.generation() != predecessor.generation().saturating_add(1)
    {
        Err(StorageStateError::CorruptRecord)
    } else {
        Ok(())
    }
}

pub(super) fn validate_transition_payload(
    payload: &TransitionPayload,
) -> Result<(), StorageStateError> {
    if payload.magic != TRANSITION_MAGIC
        || payload.version != FORMAT_VERSION
        || payload.operation_id == [0; 16]
        || payload.mutation_digest == [0; 32]
        || payload.observation_digest == [0; 32]
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let predecessor = payload.predecessor.binding()?;
    let result = PhysicalCatalogState::from_wire(payload.result_state.clone())?;
    if result.binding != payload.result.binding()?
        || result.wire.predecessor_state != Some(predecessor.into())
        || result.wire.resolution != Some(payload.catalog)
        || result.binding.generation() != payload.catalog.generation.saturating_add(1)
    {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(())
}

pub(super) fn validate_head(
    head: &HeadPayload,
    transitions: &BTreeMap<[u8; 16], TransitionPayload>,
) -> Result<(), StorageStateError> {
    if head.magic != HEAD_MAGIC || head.version != FORMAT_VERSION {
        return Err(StorageStateError::CorruptRecord);
    }
    match (
        head.genesis_state.as_ref(),
        head.operation_id,
        head.transition_digest,
    ) {
        (Some(wire), None, None) if transitions.is_empty() => {
            if PhysicalCatalogState::from_wire(wire.clone())?.binding != head.binding.binding()? {
                return Err(StorageStateError::CorruptRecord);
            }
        }
        (None, Some(operation_id), Some(digest)) => {
            let transition = transitions
                .get(&operation_id)
                .ok_or(StorageStateError::CorruptRecord)?;
            if head.binding != transition.result
                || digest != *transition_digest(transition)?.as_bytes()
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
        let result = PhysicalCatalogState::from_wire(transition.result_state.clone())?;
        if reservation.predecessor != current
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
        || head_payload.operation_id != last_operation
        || pending
            .first()
            .is_some_and(|(_, reservation)| reservation.predecessor != current)
    {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(())
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
