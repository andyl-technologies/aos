//! Owns every canonical capacity family, accounting and full-state selection.
//!
//! V1/V2 legacy records share their established codec in [`super::capacity`].
//! Native3, Ordinary4, OriginalRoot5, OriginalSource5 and Query6 retain distinct
//! closed codecs. Every state selection validates all capacity rows first.
//! These records and conservative budgets confer no protected writer scope,
//! capacity grant, currentness, signer custody or installed-owner authority.

use super::JournalTransactionDataError;
use super::capacity::take;
use super::capacity::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1,
    MAXIMUM_FUTURE_TRANSACTIONS, decode_reservation, reservation_id, reservation_key,
    valid_future_transactions,
};
use super::transaction::{JournalLimits, JournalRecord};
use aos_sandbox_model::RecordNamespace;

pub mod family;
mod fixed300;
pub mod native_held;
pub mod ordinary;
pub mod query;

use family::{CanonicalCapacityFamily, canonical_reservations};
use ordinary::{
    OrdinaryCapacityDataV4, OrdinaryCapacityKindV4, OrdinaryCapacityProfileV4,
    OrdinaryCapacityRecordV4,
};

/// Reports canonical capacity DATA failures without any Native journal cause.
#[derive(Debug, thiserror::Error)]
pub enum CapacityDataError {
    /// A complete family record or binding is malformed.
    #[error("malformed journal record: {0}")]
    MalformedRecord(&'static str),
    /// A configured size or count bound was exceeded.
    #[error("journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Aggregate encoded bytes exceed their representation.
    #[error("journal exceeds the configured replay byte bound")]
    JournalTooLarge,
    /// A deletion or invalid transaction cannot supply capacity DATA.
    #[error("transaction identity must be nonzero and records must be nonempty")]
    InvalidTransaction,
    /// A supplied record belongs to another namespace.
    #[error("protected authority journal contains a foreign namespace")]
    ForeignAuthorityNamespace,
    /// A closed legacy DATA selection encountered another family.
    #[error("protected journal storage boundary is invalid")]
    ProtectedBoundary,
    /// Canonical transaction DATA framing failed with its existing cause.
    #[error(transparent)]
    Transaction(#[from] JournalTransactionDataError),
}

/// Projects a canonical floor into conservative nonauthorizing accounting DATA.
#[derive(Clone, Copy)]
pub struct DecodedCapacityReservationV1 {
    /// Canonical self-binding reservation identity.
    pub reservation_id: [u8; 32],
    /// Maximum retained records promised by the remaining floor.
    pub maximum_records: usize,
    /// Maximum bytes promised by the remaining floor.
    pub maximum_bytes: u64,
    /// Maximum remaining transaction count.
    pub maximum_transactions: usize,
}

/// Decodes one canonical legacy capacity request as nonauthorizing data.
///
/// The returned tuple contains the request, admission transaction ID and
/// reservation ID. This checks only the supplied record, not the complete floor
/// snapshot, an owner graph or journal currentness. Callers must validate every
/// retained floor before selecting a record. These values cannot construct a
/// protected reservation or settlement grant.
///
/// # Errors
///
/// Rejects another namespace, deletion, malformed or unknown framing, a changed
/// key or identity, and valid native or ordinary records from other families.
pub fn decode_capacity_reservation_request_v1(
    record: &JournalRecord,
) -> Result<(GlobalCapacityReservationRequestV1, [u8; 16], [u8; 32]), CapacityDataError> {
    if record.namespace() != RecordNamespace::GlobalCapacityReservation {
        return Err(CapacityDataError::ForeignAuthorityNamespace);
    }
    let value = record
        .value()
        .ok_or(CapacityDataError::InvalidTransaction)?;
    CanonicalCapacityFamily::decode(record.key(), value)?.require_legacy()
}

/// Validates a touched capacity row before selecting one legacy purpose.
///
/// # Errors
///
/// Rejects a foreign namespace, deletion, or malformed/unknown family. Valid
/// native and ordinary DATA rows return false without becoming legacy grants.
pub fn capacity_record_has_legacy_purpose(
    record: &JournalRecord,
    purpose: GlobalCapacityReservationPurposeV1,
) -> Result<bool, CapacityDataError> {
    if record.namespace() != RecordNamespace::GlobalCapacityReservation {
        return Err(CapacityDataError::ForeignAuthorityNamespace);
    }
    let value = record
        .value()
        .ok_or(CapacityDataError::InvalidTransaction)?;
    let family = CanonicalCapacityFamily::decode(record.key(), value)?;
    Ok(family
        .legacy()
        .is_some_and(|(request, _, _)| request.purpose == purpose))
}

/// Checks ownership only after validating every canonical retained floor.
///
/// # Errors
///
/// Rejects malformed, unknown or duplicate capacity rows anywhere in the snapshot.
pub fn all_reservations_owned_by(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    namespace: RecordNamespace,
) -> Result<bool, CapacityDataError> {
    let families = canonical_reservations(state)?;
    Ok(families
        .iter()
        .all(|family| family.owner_namespace() == namespace))
}

/// Selects legacy identities only after validating every retained family.
///
/// # Errors
///
/// Rejects malformed, unknown or duplicate capacity rows before purpose selection.
pub fn legacy_capacity_ids_for_purpose(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    purpose: GlobalCapacityReservationPurposeV1,
) -> Result<Vec<[u8; 32]>, CapacityDataError> {
    let families = canonical_reservations(state)?;
    Ok(families
        .iter()
        .filter_map(|family| {
            let (request, _, identity) = family.legacy()?;
            (request.purpose == purpose).then_some(identity)
        })
        .collect())
}

/// Checks complete legacy request DATA against the supplied journal limits.
///
/// # Errors
///
/// Rejects invalid owner bindings, closed counts or budgets beyond the supplied limits.
pub fn validate_request_with_limits(
    request: &GlobalCapacityReservationRequestV1,
    limits: JournalLimits,
) -> Result<(), CapacityDataError> {
    let records = request.terminal_records.max(request.poison_records);
    let bytes = request.terminal_bytes.max(request.poison_bytes);
    if request.owner_namespace != request.purpose.owner_namespace()
        || request.owner_id == [0; 32]
        || request.owner_digest == [0; 32]
        || request.operation_id == [0; 16]
        || request.artifact_digest == [0; 32]
        || request.checkpoint_digest == [0; 32]
        || request.chain_head_digest == [0; 32]
        || request.future_transactions == 0
        || request.future_transactions > MAXIMUM_FUTURE_TRANSACTIONS
        || !valid_future_transactions(request.purpose, request.future_transactions)
        || request.terminal_records == 0
        || request.poison_records == 0
        || request.terminal_bytes == 0
        || request.poison_bytes == 0
        || usize::try_from(records).ok().is_none_or(|value| {
            value > limits.maximum_records_per_transaction
                || value > limits.maximum_materialized_records
        })
        || bytes
            > limits
                .maximum_journal_bytes
                .min(limits.maximum_transaction_bytes as u64)
    {
        return Err(CapacityDataError::LimitExceeded(
            "invalid global capacity reservation",
        ));
    }
    Ok(())
}

/// Validates every canonical floor in a complete DATA snapshot before selection.
///
/// The caller supplies the complete journal snapshot, including every namespace46
/// row. This performs no owner graph check and proves neither currentness nor a
/// protected scope. Valid native/ordinary DATA never becomes a legacy grant.
///
/// # Errors
///
/// Rejects unknown/malformed families, noncanonical self-bound keys or duplicate
/// floor identities anywhere in the supplied snapshot, including foreign owners.
pub fn validate_capacity_snapshot_data_v2(
    records: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), CapacityDataError> {
    family::canonical_reservations(records)?;
    Ok(())
}
