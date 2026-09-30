//! Canonical capacity-family dispatch, accounting, and closed legacy gates.
//!
//! Known versions are DATA variants, never interchangeable protected grants.
//! Every full-state traversal validates all rows before selecting an owner or
//! purpose. In particular, a foreign valid row cannot hide a later malformed row.

use std::collections::{BTreeMap, BTreeSet};

use super::super::{JournalError, JournalTransaction, RecordNamespace};
use super::native_held::{
    NativeHeldCapacityRecordV3, OriginalRootCapacityRecordV5, OriginalSourceCapacityRecordV5,
};
use super::ordinary::OrdinaryCapacityRecordV4;
use super::query::QueryCapacityRecordV6;
use super::{
    DecodedCapacityReservationV1, GlobalCapacityReservationRequestV1, decode_reservation,
    reservation_id, reservation_key,
};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type LegacyData = (GlobalCapacityReservationRequestV1, [u8; 16], [u8; 32]);

/// Keeps canonical family classification separate from any legacy authority.
pub(in crate::journal) enum CanonicalCapacityFamily {
    Legacy1(LegacyData),
    Legacy2(LegacyData),
    Native3(NativeHeldCapacityRecordV3),
    Ordinary4(OrdinaryCapacityRecordV4),
    OriginalRoot5(OriginalRootCapacityRecordV5),
    OriginalSource5(OriginalSourceCapacityRecordV5),
    Query6(QueryCapacityRecordV6),
}

impl CanonicalCapacityFamily {
    /// Validates one exact family encoding and its self-bound key.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions or any selected codec/key/identity violation.
    pub(in crate::journal) fn decode(key: &[u8], value: &[u8]) -> Result<Self, JournalError> {
        let version = value
            .get(8..10)
            .ok_or(JournalError::MalformedRecord("capacity family header"))?;
        match version {
            [0, 1] | [0, 2] => {
                let legacy @ (request, admission, identifier) = decode_reservation(value)?;
                if key != reservation_key(identifier).as_slice()
                    || reservation_id(&request, admission) != identifier
                    || request.owner_namespace != request.purpose.owner_namespace()
                {
                    return Err(JournalError::MalformedRecord(
                        "capacity reservation key or digest is invalid",
                    ));
                }
                if version == [0, 1] {
                    Ok(Self::Legacy1(legacy))
                } else {
                    Ok(Self::Legacy2(legacy))
                }
            }
            [0, 3] => Ok(Self::Native3(NativeHeldCapacityRecordV3::decode(
                key, value,
            )?)),
            [0, 4] => Ok(Self::Ordinary4(OrdinaryCapacityRecordV4::decode(
                key, value,
            )?)),
            [0, 5] => match value.get(8..14) {
                Some([0, 5, 40, 8, 0, 0]) => Ok(Self::OriginalRoot5(
                    OriginalRootCapacityRecordV5::decode(key, value)?,
                )),
                Some([0, 5, 41, 11, 0, 0]) => Ok(Self::OriginalSource5(
                    OriginalSourceCapacityRecordV5::decode(key, value)?,
                )),
                _ => Err(JournalError::MalformedRecord(
                    "unknown original capacity family tuple",
                )),
            },
            [0, 6] => Ok(Self::Query6(QueryCapacityRecordV6::decode(key, value)?)),
            _ => Err(JournalError::MalformedRecord(
                "unknown capacity family version",
            )),
        }
    }

    /// Selects legacy DATA only after full canonical family validation.
    pub(super) fn legacy(&self) -> Option<LegacyData> {
        match self {
            Self::Legacy1(data) | Self::Legacy2(data) => Some(*data),
            Self::Native3(_)
            | Self::Ordinary4(_)
            | Self::OriginalRoot5(_)
            | Self::OriginalSource5(_)
            | Self::Query6(_) => None,
        }
    }

    /// Keeps the strict legacy request interface closed to other families.
    ///
    /// # Errors
    ///
    /// Rejects native and ordinary families with the protected boundary error.
    pub(super) fn require_legacy(&self) -> Result<LegacyData, JournalError> {
        self.legacy().ok_or(JournalError::ProtectedBoundary)
    }

    /// Returns the DATA owner without granting a journal scope.
    pub(super) fn owner_namespace(&self) -> RecordNamespace {
        match self {
            Self::Legacy1((request, _, _)) | Self::Legacy2((request, _, _)) => {
                request.owner_namespace
            }
            Self::Native3(record) => record.request().purpose.owner_namespace(),
            Self::Ordinary4(_) | Self::OriginalRoot5(_) | Self::Query6(_) => {
                RecordNamespace::MountSourceAcquisition
            }
            Self::OriginalSource5(_) => RecordNamespace::SourceProviderAuthority,
        }
    }

    fn identity(&self) -> [u8; 32] {
        match self {
            Self::Legacy1((_, _, identity)) | Self::Legacy2((_, _, identity)) => *identity,
            Self::Native3(record) => record.reservation_id(),
            Self::Ordinary4(record) => record.reservation_id(),
            Self::OriginalRoot5(record) => record.reservation_id(),
            Self::OriginalSource5(record) => record.reservation_id(),
            Self::Query6(record) => record.reservation_id(),
        }
    }

    /// Projects the full remaining floor into conservative shared accounting.
    ///
    /// # Errors
    ///
    /// Rejects counts that cannot be represented on this host.
    pub(super) fn accounting(&self) -> Result<DecodedCapacityReservationV1, JournalError> {
        let (records, bytes, transactions) = match self {
            Self::Legacy1((request, _, _)) | Self::Legacy2((request, _, _)) => (
                request.terminal_records.max(request.poison_records),
                request.terminal_bytes.max(request.poison_bytes),
                request.future_transactions,
            ),
            Self::Native3(record) => {
                let request = record.request();
                (
                    request.terminal_records.max(request.poison_records),
                    request.terminal_bytes.max(request.poison_bytes),
                    request.future_transactions,
                )
            }
            Self::OriginalRoot5(record) => {
                let request = record.request();
                (
                    request.terminal_records.max(request.poison_records),
                    request.terminal_bytes.max(request.poison_bytes),
                    request.future_transactions,
                )
            }
            Self::OriginalSource5(record) => {
                let request = record.request();
                (
                    request.terminal_records.max(request.poison_records),
                    request.terminal_bytes.max(request.poison_bytes),
                    request.future_transactions,
                )
            }
            Self::Ordinary4(record) => {
                let data = record.data();
                (
                    data.remaining_record_frames
                        .max(data.maximum_retained_growth_entries),
                    data.remaining_append_bytes
                        .max(data.maximum_retained_growth_bytes),
                    data.remaining_transactions,
                )
            }
            Self::Query6(record) => {
                let data = record.data();
                (
                    data.remaining_record_frames.max(data.maximum_retained_growth_entries),
                    data.remaining_append_bytes.max(data.maximum_retained_growth_bytes),
                    data.remaining_transactions,
                )
            }
        };
        Ok(DecodedCapacityReservationV1 {
            reservation_id: self.identity(),
            maximum_records: usize::try_from(records)
                .map_err(|_| JournalError::LimitExceeded("reserved record count"))?,
            maximum_bytes: bytes,
            maximum_transactions: usize::try_from(transactions)
                .map_err(|_| JournalError::LimitExceeded("reserved transaction count"))?,
        })
    }
}

/// Validates every retained floor before any owner or purpose selection.
///
/// # Errors
///
/// Rejects any malformed/unknown row or duplicate canonical identity.
pub(in crate::journal) fn canonical_reservations(
    state: &State,
) -> Result<Vec<CanonicalCapacityFamily>, JournalError> {
    let mut families = Vec::new();
    let mut identities = BTreeSet::new();
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::GlobalCapacityReservation {
            continue;
        }

        let family = CanonicalCapacityFamily::decode(key, value)?;
        if !identities.insert(family.identity()) {
            return Err(JournalError::MalformedRecord(
                "duplicate global capacity reservation",
            ));
        }
        families.push(family);
    }
    Ok(families)
}

/// Projects every canonical family before any purpose-specific mutation.
pub(in crate::journal) fn accounting_reservations(
    state: &State,
) -> Result<BTreeMap<[u8; 32], DecodedCapacityReservationV1>, JournalError> {
    canonical_reservations(state)?
        .into_iter()
        .map(|family| {
            let accounting = family.accounting()?;
            Ok((accounting.reservation_id, accounting))
        })
        .collect()
}

/// Projects one already-selected canonical floor without producing a grant.
pub(in crate::journal) fn accounting_reservation(
    key: &[u8],
    value: &[u8],
) -> Result<DecodedCapacityReservationV1, JournalError> {
    CanonicalCapacityFamily::decode(key, value)?.accounting()
}

/// Preserves the old whole-journal legacy claim refusal for other families.
///
/// # Errors
///
/// Rejects malformed state and every retained native or ordinary floor.
pub(in crate::journal) fn require_legacy_reservations(state: &State) -> Result<(), JournalError> {
    let families = canonical_reservations(state)?;
    if families.iter().any(|family| family.legacy().is_none()) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Keeps fixed generic owners closed while their native or ordinary floor exists.
///
/// # Errors
///
/// Rejects malformed state or a nonlegacy floor owned by this namespace.
pub(in crate::journal) fn require_legacy_owner(
    state: &State,
    namespace: RecordNamespace,
) -> Result<(), JournalError> {
    let families = canonical_reservations(state)?;
    if families
        .iter()
        .any(|family| family.legacy().is_none() && family.owner_namespace() == namespace)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Refuses generic nonlegacy floor changes and their protected owner mutations.
///
/// # Errors
///
/// Rejects malformed retained/touched capacity rows, nonlegacy floor writes or
/// deletion/overwrite, and writes in the corresponding nonlegacy owner namespace.
pub(in crate::journal) fn require_legacy_transaction(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    let families = canonical_reservations(state)?;
    let changed_namespaces: BTreeSet<_> = transaction
        .records()
        .iter()
        .map(|record| record.namespace())
        .collect();
    let mut nonlegacy_capacity_write = false;
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            continue;
        }

        if let Some(value) = record.value() {
            nonlegacy_capacity_write |= CanonicalCapacityFamily::decode(record.key(), value)?
                .legacy()
                .is_none();
        }
        if let Some(value) = state.get(&(record.namespace(), record.key().to_vec())) {
            nonlegacy_capacity_write |= CanonicalCapacityFamily::decode(record.key(), value)?
                .legacy()
                .is_none();
        }
    }
    if nonlegacy_capacity_write
        || families.iter().any(|family| {
            family.legacy().is_none() && changed_namespaces.contains(&family.owner_namespace())
        })
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}
