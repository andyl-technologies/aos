//! Current protected-state fencing for physical Cache pin effects.

use aos_sandbox_core::OperationId;

use crate::cache_residency::pin::valid_logical_renewal;
use crate::cache_residency::{CachePinV1, CacheRecordKindV1, decode_atomic_object_record};
use crate::lifecycle::protected_journal_adapter::decode_reducer_payload_with_validator;

use super::{
    CacheResidencyProtectedJournalEnvelopeV1, CacheResidencyProtectedJournalErrorV1,
    CacheResidencyProtectedJournalSchemaV1, CacheResidencyProtectedRecordKindV1,
    CacheResidencyReplayValidatorV1, CacheResidencyTransactionKindV1, PARTITION_DESCRIPTOR_BYTES,
    decode_partition_descriptor, reconstruct_cache_history,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CurrentPhysicalPinActionV1 {
    Acquire,
    Release,
    Retain,
}

pub(super) struct CurrentPhysicalPinEffectV1 {
    pub(super) action: CurrentPhysicalPinActionV1,
    pub(super) operation: OperationId,
    pub(super) pin: CachePinV1,
}

/// Selects the transaction's one physical pin change only while it remains current.
///
/// # Errors
///
/// Returns an error if the Pin envelope, authority binding, or protected
/// replayed history is malformed.
pub(super) fn current_physical_pin_effect(
    kind: CacheResidencyTransactionKindV1,
    transaction: &[CacheResidencyProtectedJournalEnvelopeV1],
    history: &[CacheResidencyProtectedJournalEnvelopeV1],
    validator: &CacheResidencyReplayValidatorV1,
) -> Result<Option<CurrentPhysicalPinEffectV1>, CacheResidencyProtectedJournalErrorV1> {
    if kind != CacheResidencyTransactionKindV1::PinChange {
        return Ok(None);
    }
    let mut pin_records = transaction
        .iter()
        .filter(|record| record.key().kind() == CacheResidencyProtectedRecordKindV1::Pin);
    let record = pin_records
        .next()
        .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
    if pin_records.next().is_some() {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }

    let reducer = decode_reducer_payload_with_validator::<CacheResidencyProtectedJournalSchemaV1>(
        record.key(),
        record.payload(),
        validator,
    )?;
    let descriptor_end = 8 + PARTITION_DESCRIPTOR_BYTES;
    let body = reducer.body();
    let partition = decode_partition_descriptor(
        body.get(8..descriptor_end)
            .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
    )
    .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
    let payload = decode_atomic_object_record(
        partition,
        body.get(descriptor_end..)
            .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?,
        validator.limits,
    )
    .map_err(|_| CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
    if payload.record.kind != CacheRecordKindV1::Pin {
        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
    }

    let (action, pin) = match payload.record.state {
        1 => {
            let mut candidates = payload
                .pins
                .iter()
                .filter(|pin| pin.evidence == payload.record.authority);
            let pin = candidates
                .next()
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
            if candidates.next().is_some() {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
            (CurrentPhysicalPinActionV1::Acquire, pin.clone())
        }
        2 => {
            let mut candidates = payload
                .released_pins
                .iter()
                .filter(|released| released.drain.digest() == payload.record.authority);
            let released = candidates
                .next()
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
            if candidates.next().is_some() {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
            (CurrentPhysicalPinActionV1::Release, released.pin.clone())
        }
        3 => {
            let mut candidates = payload
                .pins
                .iter()
                .filter(|pin| pin.evidence == payload.record.authority);
            let pin = candidates
                .next()
                .ok_or(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord)?;
            if candidates.next().is_some() {
                return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
            }
            (CurrentPhysicalPinActionV1::Retain, pin.clone())
        }
        _ => return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord),
    };

    let current = reconstruct_cache_history(history, validator)?
        .into_iter()
        .find(|inventory| inventory.global.node_quota.partition == partition)
        .and_then(|inventory| {
            inventory
                .reconstructed
                .into_iter()
                .find(|latest| latest.record.subject == payload.record.subject)
        });
    let still_retained = current.is_some_and(|latest| match action {
        // Renewal changes the lease authority, not the physical obligation.
        CurrentPhysicalPinActionV1::Acquire => latest
            .pins
            .iter()
            .any(|active| active == &pin || valid_logical_renewal(&pin, active)),
        CurrentPhysicalPinActionV1::Retain => latest
            .pins
            .iter()
            .any(|active| active == &pin || valid_logical_renewal(&pin, active)),
        CurrentPhysicalPinActionV1::Release => latest.released_pins.iter().any(|released| {
            released.pin == pin && released.drain.digest() == payload.record.authority
        }),
    });
    Ok(still_retained.then_some(CurrentPhysicalPinEffectV1 {
        action,
        operation: payload.record.operation,
        pin,
    }))
}
