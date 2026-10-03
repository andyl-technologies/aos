//! Bounded full held8 readback alongside unchanged legacy owner recovery.
//!
//! This private representation is structural DATA. Archive signer eligibility,
//! original admission and intermediate complete remaining geometry are unresolved;
//! it must never enter a Ready ledger or produce signing/effect/backend custody.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1, JournalRecord,
    SourceProviderHeldReadOnlyJournalAuthorityV1, decode_capacity_reservation_request_v1,
    journal::native_held::{
        NativeHeldCapacityPurposeV3, NativeHeldCapacityRecordV3, OriginalSourceCapacityRecordV5,
        validate_capacity_snapshot_data_v2,
    },
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::{
    collect_bounded_records,
    ledger::native_held_completion::{
        SourceNativeHeldCompletionRecordV1, validate_native_held_records_v1,
    },
};
use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldControlKindV1;
use sha2::{Digest as _, Sha256};

use crate::{
    ProviderLedgerError, model::RecoveredProviderLedgerV1, state::ProtectedProviderConfigurationV1,
};

/// Records missing proofs explicitly rather than promoting a canonical claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnresolvedNativeProofV1 {
    Unresolved,
}

pub(crate) struct RecoveredNativeProfileV1 {
    pub(crate) records: BTreeMap<Vec<u8>, Vec<u8>>,
    // Retains every checked current/original legacy companion without exposing
    // a mutable ledger or flattening held rows into the old native map.
    _owners: RecoveredProviderLedgerV1,
    pub(crate) held: BTreeMap<ObjectDigest, SourceNativeHeldCompletionRecordV1>,
    pub(crate) floor_ids: BTreeSet<[u8; 32]>,
    pub(crate) archive_eligibility: UnresolvedNativeProofV1,
    pub(crate) remaining_geometry: UnresolvedNativeProofV1,
}

pub(crate) fn is_held(bytes: &[u8]) -> bool {
    bytes.get(8..10) == Some(&8_u16.to_be_bytes())
}

pub(crate) fn recover(
    journal: &SourceProviderHeldReadOnlyJournalAuthorityV1<'_>,
    configuration: &ProtectedProviderConfigurationV1,
) -> Result<RecoveredNativeProfileV1, ProviderLedgerError> {
    let records = collect_bounded_records(journal.security_view()?.records()?)
        .map_err(crate::transaction::map_pure_ledger_error)?;
    validate_native_held_records_v1(
        records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let mut held = BTreeMap::new();
    for (key, value) in records.iter().filter(|(_, value)| is_held(value)) {
        let record = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(key, value)
            .map_err(crate::transaction::map_pure_ledger_error)?;
        if held
            .insert(record.original().acquisition_id, record)
            .is_some()
        {
            return Err(ProviderLedgerError::Corrupt("duplicate held acquisition"));
        }
    }
    if held.is_empty() {
        return Err(ProviderLedgerError::InvalidTransition(
            "held readback has no held profile",
        ));
    }
    let owners = super::recover_records_with_held(
        records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        configuration,
        &held,
    )?;
    let floors = Floors::collect(journal.capacity_records()?)?;
    let mut floor_ids = BTreeSet::new();
    let obligations = aos_sandbox_source_provider_ledger::ledger::source_capacity::derive_source_capacity_owner_data_v1(
        records.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
        &[],
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    for binding in obligations.ordinary_bindings() {
        let request = aos_sandbox::journal::source_native_ordinary_capacity_request_v1(binding);
        if !floor_ids.insert(floors.exact_legacy(request)?) {
            return Err(ProviderLedgerError::Equivocation);
        }
    }
    for record in held.values() {
        let identifier = floors.exact_held(record, &owners)?;
        if !floor_ids.insert(identifier) {
            return Err(ProviderLedgerError::Equivocation);
        }
    }
    if floor_ids != floors.identities() {
        return Err(ProviderLedgerError::Corrupt(
            "mixed capacity union differs from complete owners",
        ));
    }
    Ok(RecoveredNativeProfileV1 {
        records,
        _owners: owners,
        held,
        floor_ids,
        archive_eligibility: UnresolvedNativeProofV1::Unresolved,
        remaining_geometry: UnresolvedNativeProofV1::Unresolved,
    })
}

pub(super) enum Floor {
    Legacy(GlobalCapacityReservationRequestV1),
    Held(NativeHeldCapacityRecordV3),
    OriginalSource(OriginalSourceCapacityRecordV5),
}

pub(super) struct FloorEntry {
    pub(super) floor: Floor,
    pub(super) row: JournalRecord,
    pub(super) admission_transaction_id: [u8; 16],
}

pub(super) struct Floors(pub(super) BTreeMap<[u8; 32], FloorEntry>);

enum InventoryKind {
    StrictHeldReadback,
    OriginalSourceComparison,
}

impl Floors {
    fn collect(records: Vec<JournalRecord>) -> Result<Self, ProviderLedgerError> {
        Self::collect_for(records, InventoryKind::StrictHeldReadback)
    }

    /// Admits Source5 only to the private original comparison, never readback.
    pub(super) fn collect_original_source_comparison(
        records: Vec<JournalRecord>,
    ) -> Result<Self, ProviderLedgerError> {
        Self::collect_for(records, InventoryKind::OriginalSourceComparison)
    }

    fn collect_for(
        records: Vec<JournalRecord>,
        kind: InventoryKind,
    ) -> Result<Self, ProviderLedgerError> {
        let complete = records
            .iter()
            .map(|row| {
                row.value()
                    .map(|value| ((row.namespace(), row.key().to_vec()), value.to_vec()))
                    .ok_or(ProviderLedgerError::Corrupt("capacity observation DELETE"))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        validate_capacity_snapshot_data_v2(&complete)?;
        let mut floors = BTreeMap::new();
        for row in records {
            let value = row
                .value()
                .ok_or(ProviderLedgerError::Corrupt("capacity observation DELETE"))?;
            let (identifier, admission_transaction_id, floor) = if value.get(8..10)
                == Some(&3_u16.to_be_bytes())
            {
                let native = NativeHeldCapacityRecordV3::from_journal_record(&row)?;
                if matches!(kind, InventoryKind::OriginalSourceComparison)
                    && native.request().purpose != NativeHeldCapacityPurposeV3::Provider
                {
                    return Err(ProviderLedgerError::Corrupt("foreign native floor family"));
                }
                (
                    native.reservation_id(),
                    native.admission_transaction_id(),
                    Floor::Held(native),
                )
            } else if matches!(kind, InventoryKind::OriginalSourceComparison)
                && value.get(8..10) == Some(&5_u16.to_be_bytes())
            {
                let original = OriginalSourceCapacityRecordV5::from_journal_record(&row)?;
                (
                    original.reservation_id(),
                    original.admission_transaction_id(),
                    Floor::OriginalSource(original),
                )
            } else {
                if matches!(kind, InventoryKind::OriginalSourceComparison)
                    && value.get(8..10) != Some(&1_u16.to_be_bytes())
                {
                    // Query6 and all other families remain unsupported here,
                    // even if the shared syntax gate learns their codecs.
                    return Err(ProviderLedgerError::Corrupt(
                        "unsupported Source floor family",
                    ));
                }
                let (request, admission, identifier) =
                    decode_capacity_reservation_request_v1(&row)?;
                if matches!(kind, InventoryKind::OriginalSourceComparison)
                    && request.purpose
                        != GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal
                {
                    return Err(ProviderLedgerError::Corrupt(
                        "unsupported Source floor family",
                    ));
                }
                (identifier, admission, Floor::Legacy(request))
            };
            let entry = FloorEntry {
                floor,
                row,
                admission_transaction_id,
            };
            if floors.insert(identifier, entry).is_some() {
                return Err(ProviderLedgerError::Corrupt("duplicate physical floor"));
            }
        }
        Ok(Self(floors))
    }

    pub(super) fn identities(&self) -> BTreeSet<[u8; 32]> {
        self.0.keys().copied().collect()
    }

    pub(super) fn exact_legacy(
        &self,
        expected: GlobalCapacityReservationRequestV1,
    ) -> Result<[u8; 32], ProviderLedgerError> {
        let matches = self
            .0
            .iter()
            .filter_map(|(identifier, row)| {
                matches!(&row.floor, Floor::Legacy(actual) if *actual == expected)
                    .then_some(*identifier)
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [identifier] => Ok(*identifier),
            _ => Err(ProviderLedgerError::Corrupt(
                "mixed legacy obligation is missing or ambiguous",
            )),
        }
    }

    pub(super) fn exact_held(
        &self,
        held: &SourceNativeHeldCompletionRecordV1,
        owners: &RecoveredProviderLedgerV1,
    ) -> Result<[u8; 32], ProviderLedgerError> {
        let original = held.original();
        let acquisition = owners
            .acquisitions
            .values()
            .find(|row| row.acquisition_id == original.acquisition_id)
            .ok_or(ProviderLedgerError::Corrupt("held floor acquisition"))?;
        let native = original
            .canonical_request
            .as_ref()
            .ok_or(ProviderLedgerError::Corrupt("held floor native request"))?;
        let checkpoint = held
            .suffix()
            .control(NativeHeldControlKindV1::RootPrepared)
            .ok_or(ProviderLedgerError::Corrupt("held floor Root preparation"))?
            .digest();
        let mut owner = Sha256::new();
        owner.update(b"aos.sandbox.source-provider.native-dispatch-capacity-owner.v2\0");
        owner.update(original.provider_id);
        owner.update(original.holder_id);
        owner.update(original.acquisition_id.as_bytes());
        let owner_id: [u8; 32] = owner.finalize().into();
        let owner_digest =
            original
                .reservation_acquisition_digest
                .ok_or(ProviderLedgerError::Corrupt(
                    "held floor original reservation",
                ))?;
        let catalog = native.request().claims().catalog().digest();
        let matches = self
            .0
            .iter()
            .filter_map(|(identifier, row)| {
                let Floor::Held(row) = &row.floor else {
                    return None;
                };
                let request = row.request();
                (request.purpose == NativeHeldCapacityPurposeV3::Provider
                    && request.owner_id == owner_id
                    && request.owner_digest == *owner_digest.as_bytes()
                    && request.operation_id == acquisition.effect_id
                    && request.artifact_digest == *original.native_request_digest.as_bytes()
                    && request.checkpoint_digest == *checkpoint.as_bytes()
                    && request.chain_head_digest == *catalog.as_bytes()
                    && (held.suffix().phase() != 0 || request.future_transactions == 19)
                    && (held.suffix().phase() != 10 || request.future_transactions == 1))
                    .then_some(*identifier)
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [identifier] => Ok(*identifier),
            _ => Err(ProviderLedgerError::Corrupt(
                "held floor binding is missing or ambiguous",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Canonical floor DATA vectors, not a qualified mixed runtime fixture.

    use aos_sandbox::journal::native_held::NativeHeldCapacityRequestV3;
    use aos_sandbox::{
        GlobalCapacityReservationPurposeV1, Journal, JournalLimits, RecordNamespace,
    };
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn legacy_request() -> GlobalCapacityReservationRequestV1 {
        GlobalCapacityReservationRequestV1 {
            purpose: GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
            owner_namespace: RecordNamespace::SourceProviderAuthority,
            owner_id: [1; 32],
            owner_digest: [2; 32],
            operation_id: [3; 16],
            artifact_digest: [4; 32],
            checkpoint_digest: [5; 32],
            chain_head_digest: [6; 32],
            future_transactions: 1,
            terminal_records: 3,
            terminal_bytes: 4096,
            poison_records: 3,
            poison_bytes: 4096,
        }
    }

    fn legacy_record(admission: u8) -> JournalRecord {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "provider.journal",
            JournalLimits::default(),
            rustix::process::geteuid().as_raw(),
        )
        .unwrap();
        let owner = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        owner
            .prepare_global_capacity_reservation_v1(legacy_request(), [admission; 16])
            .unwrap()
            .record()
            .clone()
    }

    fn native_record() -> JournalRecord {
        NativeHeldCapacityRecordV3::new(
            NativeHeldCapacityRequestV3 {
                purpose: NativeHeldCapacityPurposeV3::Provider,
                owner_id: [11; 32],
                owner_digest: [12; 32],
                operation_id: [13; 16],
                artifact_digest: [14; 32],
                checkpoint_digest: [15; 32],
                chain_head_digest: [16; 32],
                future_transactions: 19,
                terminal_records: 7,
                terminal_bytes: 4096,
                poison_records: 7,
                poison_bytes: 4096,
            },
            [17; 16],
        )
        .unwrap()
        .to_journal_record()
    }

    #[test]
    fn full_floor_data_traversal_precedes_selected_legacy_match() {
        let legacy = legacy_record(21);
        let native = native_record();
        let floors = Floors::collect(vec![legacy.clone(), native.clone()]).unwrap();
        assert_eq!(floors.identities().len(), 2);
        assert!(floors.exact_legacy(legacy_request()).is_ok());

        let mut corrupt = native.value().unwrap().to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        let corrupt = JournalRecord::put(native.namespace(), native.key().to_vec(), corrupt);
        assert!(Floors::collect(vec![legacy, corrupt]).is_err());
    }

    #[test]
    fn associated_floor_data_rejects_duplicate_and_ambiguous_legacy_rows() {
        let first = legacy_record(22);
        assert!(Floors::collect(vec![first.clone(), first.clone()]).is_err());
        let floors = Floors::collect(vec![first, legacy_record(23)]).unwrap();
        assert!(floors.exact_legacy(legacy_request()).is_err());
        assert!(
            Floors::collect(vec![JournalRecord::delete(
                RecordNamespace::GlobalCapacityReservation,
                vec![1],
            )])
            .is_err()
        );
    }

    #[test]
    fn legacy_floor_selection_never_ignores_any_binding_or_geometry_field() {
        let floors = Floors::collect(vec![legacy_record(24)]).unwrap();
        let original = legacy_request();
        let mut changed = original;
        changed.owner_digest[0] ^= 1;
        assert!(floors.exact_legacy(changed).is_err());
        let mut changed = original;
        changed.terminal_bytes += 1;
        assert!(floors.exact_legacy(changed).is_err());
        let mut changed = original;
        changed.checkpoint_digest[0] ^= 1;
        assert!(floors.exact_legacy(changed).is_err());
    }
}
