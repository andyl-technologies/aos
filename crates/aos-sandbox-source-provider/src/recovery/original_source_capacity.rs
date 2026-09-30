//! Exact original Source mixed-floor transaction comparisons, exclusively DATA.
//!
//! Complete inventories and borrowed transactions are checked before retention.
//! No result establishes physical admission membership, configuration origin,
//! archive eligibility or whole-journal funding, or enters a Ready ledger.
//! Unsupported foreign families and later original Source prefixes fail closed.
//!
//! ```text
//! Applying: Attempt | Acquisition | Holder | History | Source5 PUT
//! Requested: held8 PUT | Source5 DELETE | count19 Source5 PUT
//! Closed: Attempt | Acquisition | Holder | History | cold9 | DELETE | count2 PUT
//! StoreZ: cold9 PUT | Source5 DELETE | count1 Source5 PUT
//! ACK: cold9 PUT | Source5 DELETE
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox::{
    JournalRecord, JournalTransaction, RecordNamespace,
    journal::native_held::{
        ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5, OriginalSourceCapacityRecordV5,
        validate_capacity_snapshot_data_v2,
    },
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::{
    collect_bounded_records,
    ledger::native_completion::{
        OriginalSourceOwnerDataV5, OriginalSourceOwnerPrefixV5, SourcePreRequestedColdArchiveV1,
        SourcePreRequestedColdPhaseV1,
        classify_original_source_owner_v5, classify_original_source_pre_requested_cold_v1,
        native_completion_key_v2, propose_original_source_applying_v5,
        propose_original_source_pre_requested_closed_v1,
        propose_original_source_pre_requested_closure_stored_v1,
        propose_original_source_pre_requested_root_acknowledged_v1,
        propose_original_source_requested_v5,
    },
    ledger::native_held_completion::{
        SourceNativeHeldCompletionRecordV1, SourceNativeHeldMutationV1,
        native_held_release_status_binding_v1, validate_native_held_records_v1,
    },
    limits::{MAXIMUM_LEDGER_GRAPH_BYTES, MAXIMUM_LEDGER_RECORDS, MAXIMUM_TRANSACTION_BYTES},
};
use sha2::{Digest as _, Sha256};

use super::{
    CanonicalNativeProfile,
    native_profile::{Floor, Floors, UnresolvedNativeProofV1},
};
use crate::{ProviderLedgerError, state::ProtectedProviderConfigurationV1};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

/// Borrows real retained comparison inputs; matching DATA is not a receipt.
struct OriginalAdmissionComparisonV5<'a> {
    original_before: &'a State,
    applying_transaction: &'a JournalTransaction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OriginalSourceFloorEdgeV5 {
    Applying,
    FirstRequested,
    ColdClosedPrepared,
    ColdClosureStored,
    ColdRootAcknowledged,
}

impl OriginalSourceFloorEdgeV5 {
    fn shape(self) -> (usize, usize, Option<u32>, Option<u32>) {
        match self {
            Self::Applying => (5, 4, None, Some(20)),
            Self::FirstRequested => (3, 1, Some(20), Some(19)),
            Self::ColdClosedPrepared => (7, 5, Some(20), Some(2)),
            Self::ColdClosureStored => (3, 1, Some(2), Some(1)),
            Self::ColdRootAcknowledged => (2, 1, Some(1), None),
        }
    }
}

/// Retains full compared bytes without any live or settlement authority.
struct OriginalSourceFloorDeltaDataV5 {
    before: State,
    after: State,
    transaction: JournalTransaction,
    original_before: State,
    applying_transaction: JournalTransaction,
    before_floors: Floors,
    after_floors: Floors,
    original_physical_membership: UnresolvedNativeProofV1,
    configuration_origin: UnresolvedNativeProofV1,
    archive_eligibility: UnresolvedNativeProofV1,
    whole_journal_funding: UnresolvedNativeProofV1,
}

struct ValidatedAdmission {
    after: State,
    initial_floor: OriginalSourceCapacityRecordV5,
    owner: OriginalSourceOwnerDataV5,
}

/// Checks five closed edges against every actual ordinary capacity obligation.
///
/// Both the current TX and original Applying TX remain caller-owned on error.
/// Cold replay without genuine retained original-before/TX inputs is unsupported;
/// even supplied matching inputs do not prove their physical lifetime membership.
fn compare_original_source_floor_union_transaction_v5(
    before: &State,
    after: &State,
    transaction: &JournalTransaction,
    original: OriginalAdmissionComparisonV5<'_>,
    configuration: &ProtectedProviderConfigurationV1,
    edge: OriginalSourceFloorEdgeV5,
) -> Result<OriginalSourceFloorDeltaDataV5, ProviderLedgerError> {
    bound_state(original.original_before)?;
    bound_state(before)?;
    bound_state(after)?;
    bound_transaction(transaction, edge.shape().0)?;
    validate_capacity_snapshot_data_v2(original.original_before)?;
    validate_capacity_snapshot_data_v2(before)?;
    validate_capacity_snapshot_data_v2(after)?;

    let admission =
        validate_original_admission(original.original_before, original.applying_transaction)?;

    // Validate the original complete union too: replayed five-record DATA must
    // not hide any already-outstanding ordinary obligation at admission.
    associate_cut(original.original_before, &admission, configuration)?;
    associate_cut(&admission.after, &admission, configuration)?;
    let before_floors = associate_cut(before, &admission, configuration)?;
    let after_floors = associate_cut(after, &admission, configuration)?;

    let reapplied = apply_transaction(before, transaction)?;
    if &reapplied != after {
        return Err(corrupt("original Source full after differs from ordered TX"));
    }
    validate_edge(before, after, transaction, &admission, edge)?;
    preserve_other_floors(&before_floors, &after_floors, &admission)?;
    if edge == OriginalSourceFloorEdgeV5::Applying
        && (before != original.original_before || transaction != original.applying_transaction)
    {
        return Err(corrupt("Applying differs from retained original transaction"));
    }
    if edge != OriginalSourceFloorEdgeV5::Applying
        && transaction.id() == original.applying_transaction.id()
    {
        return Err(corrupt("original Source repeated admission transaction identity"));
    }

    Ok(OriginalSourceFloorDeltaDataV5 {
        before: before.clone(),
        after: after.clone(),
        transaction: transaction.clone(),
        original_before: original.original_before.clone(),
        applying_transaction: original.applying_transaction.clone(),
        before_floors,
        after_floors,
        original_physical_membership: UnresolvedNativeProofV1::Unresolved,
        configuration_origin: UnresolvedNativeProofV1::Unresolved,
        archive_eligibility: UnresolvedNativeProofV1::Unresolved,
        whole_journal_funding: UnresolvedNativeProofV1::Unresolved,
    })
}

fn validate_original_admission(
    before: &State,
    transaction: &JournalTransaction,
) -> Result<ValidatedAdmission, ProviderLedgerError> {
    bound_state(before)?;
    validate_capacity_snapshot_data_v2(before)?;
    bound_transaction(transaction, 5)?;
    let records = transaction.records();
    let floor = OriginalSourceCapacityRecordV5::from_journal_record(&records[4])?;
    if floor.request().future_transactions != 20
        || floor.admission_transaction_id() != *transaction.id()
        || floor.origin_reservation_id()? != floor.reservation_id()
    {
        return Err(corrupt("original Source initial admission floor"));
    }
    original_owner_order(&records[..4], &floor)?;
    let proposed = propose_original_source_applying_v5(
        owner_views(before),
        changes(&records[..4]),
        floor.original_provenance(),
        floor.original_provenance().claims().configuration,
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    require_mutations(before, &records[..4], proposed.mutations())?;
    require_owner_binding(&floor, proposed.data())?;

    let after = apply_transaction(before, transaction)?;
    validate_capacity_snapshot_data_v2(&after)?;
    Ok(ValidatedAdmission {
        after,
        initial_floor: floor,
        owner: proposed.data().clone(),
    })
}

fn validate_edge(
    before: &State,
    after: &State,
    transaction: &JournalTransaction,
    admission: &ValidatedAdmission,
    edge: OriginalSourceFloorEdgeV5,
) -> Result<(), ProviderLedgerError> {
    let (record_count, owner_count, old_count, next_count) = edge.shape();
    bound_transaction(transaction, record_count)?;
    let records = transaction.records();
    let floor = &admission.initial_floor;
    let provenance = floor.original_provenance();
    let configuration = provenance.claims().configuration;
    let old = selected_floor(before, admission)?;
    let next = selected_floor(after, admission)?;

    if old.as_ref().map(|row| row.request().future_transactions) != old_count
        || next.as_ref().map(|row| row.request().future_transactions) != next_count
    {
        return Err(corrupt("original Source edge exact counts"));
    }
    if let Some(old) = old.as_ref() {
        require_retained_floor(old, floor)?;
        let expected = JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation,
            old.to_journal_record()?.key().to_vec(),
        );
        if records[owner_count] != expected {
            return Err(corrupt("original Source ordered floor DELETE"));
        }
    }
    if let Some(next) = next.as_ref() {
        require_retained_floor(next, floor)?;
        if records[record_count - 1] != next.to_journal_record()? {
            return Err(corrupt("original Source ordered floor PUT"));
        }
        if let Some(old) = old.as_ref() {
            require_no_budget_growth(old, next)?;
        }
    }

    let mutations = match edge {
        OriginalSourceFloorEdgeV5::Applying => {
            original_owner_order(&records[..4], floor)?;
            let proposed = propose_original_source_applying_v5(
                owner_views(before),
                changes(&records[..4]),
                provenance,
                configuration,
            )
            .map_err(crate::transaction::map_pure_ledger_error)?;
            proposed.mutations().to_vec()
        }
        OriginalSourceFloorEdgeV5::FirstRequested => {
            let proposed = propose_original_source_requested_v5(
                owner_views(before),
                changes(&records[..1]),
                provenance,
                configuration,
            )
            .map_err(crate::transaction::map_pure_ledger_error)?;
            if let Some(next) = next.as_ref() {
                require_owner_binding(next, proposed.data())?;
            }
            proposed.mutations().to_vec()
        }
        OriginalSourceFloorEdgeV5::ColdClosedPrepared => {
            original_owner_order(&records[..4], floor)?;
            require_native_put(&records[4], admission.owner.acquisition_id)?;
            let proposed = propose_original_source_pre_requested_closed_v1(
                owner_views(before),
                changes(&records[..5]),
                provenance,
                configuration,
            )
            .map_err(crate::transaction::map_pure_ledger_error)?;
            if proposed.archive().prepared().claims().first_cold_transaction != *transaction.id() {
                return Err(corrupt("cold first transaction DATA differs"));
            }
            proposed.mutations().to_vec()
        }
        OriginalSourceFloorEdgeV5::ColdClosureStored => {
            require_native_put(&records[0], admission.owner.acquisition_id)?;
            let proposed = propose_original_source_pre_requested_closure_stored_v1(
                owner_views(before),
                changes(&records[..1]),
                admission.owner.acquisition_id,
            )
            .map_err(crate::transaction::map_pure_ledger_error)?;
            proposed.mutations().to_vec()
        }
        OriginalSourceFloorEdgeV5::ColdRootAcknowledged => {
            require_native_put(&records[0], admission.owner.acquisition_id)?;
            let proposed = propose_original_source_pre_requested_root_acknowledged_v1(
                owner_views(before),
                changes(&records[..1]),
                admission.owner.acquisition_id,
            )
            .map_err(crate::transaction::map_pure_ledger_error)?;
            proposed.mutations().to_vec()
        }
    };
    require_mutations(before, &records[..owner_count], &mutations)
}

fn associate_cut(
    state: &State,
    admission: &ValidatedAdmission,
    configuration: &ProtectedProviderConfigurationV1,
) -> Result<Floors, ProviderLedgerError> {
    bound_state(state)?;
    validate_capacity_snapshot_data_v2(state)?;
    let records = collect_bounded_records(owner_views(state))
        .map_err(crate::transaction::map_pure_ledger_error)?;
    validate_native_held_records_v1(
        records.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let profiles = typed_profiles(&records)?;
    let owners = super::recover_records_with_profiles(
        records.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
        configuration,
        &profiles,
    )?;
    let floors = Floors::collect_original_source_comparison(capacity_rows(state))?;
    let mut expected = BTreeSet::new();
    let mut original_acquisitions = BTreeSet::new();

    // Select no owner until all families and the complete owner graph passed.
    for (identifier, entry) in &floors.0 {
        let Floor::OriginalSource(floor) = &entry.floor else {
            continue;
        };
        let acquisition = floor.original_provenance().claims().claims.provider_acquisition().1;
        let selected = acquisition == admission.owner.acquisition_id;
        let count = match profiles.get(&acquisition) {
            Some(CanonicalNativeProfile::Cold(archive)) if selected => {
                require_cold_origin(archive, admission)?;
                match archive.phase() {
                    SourcePreRequestedColdPhaseV1::ClosedPrepared => 2,
                    SourcePreRequestedColdPhaseV1::ClosureStored => 1,
                    SourcePreRequestedColdPhaseV1::RootAcknowledged => {
                        return Err(corrupt("acknowledged cold retains original floor"));
                    }
                }
            }
            _ => {
                let owner = classify_original_source_owner_v5(
                    owner_views(state),
                    floor.original_provenance(),
                    floor.original_provenance().claims().configuration,
                )
                .map_err(crate::transaction::map_pure_ledger_error)?;
                require_owner_binding(floor, &owner)?;
                match owner.prefix {
                    OriginalSourceOwnerPrefixV5::Applying => 20,
                    OriginalSourceOwnerPrefixV5::Requested => 19,
                }
            }
        };
        if floor.request().future_transactions != count
            || !original_acquisitions.insert(acquisition)
            || !expected.insert(*identifier)
        {
            return Err(corrupt("original Source association count or duplicate"));
        }
        if selected {
            require_retained_floor(floor, &admission.initial_floor)?;
        }
    }

    for (acquisition, profile) in &profiles {
        match profile {
            CanonicalNativeProfile::Cold(archive) => {
                if *acquisition != admission.owner.acquisition_id {
                    return Err(corrupt("unsupported independent cold archive"));
                }
                require_cold_origin(archive, admission)?;
                if archive.phase() == SourcePreRequestedColdPhaseV1::RootAcknowledged {
                    if !original_acquisitions.insert(*acquisition) {
                        return Err(corrupt("cold ACK has a floor"));
                    }
                } else if !original_acquisitions.contains(acquisition) {
                    return Err(corrupt("cold archive lacks original floor"));
                }
            }
            CanonicalNativeProfile::Held(held) if !original_acquisitions.contains(acquisition) => {
                let identifier = floors.exact_held(held, &owners)?;
                if !expected.insert(identifier) {
                    return Err(ProviderLedgerError::Equivocation);
                }
            }
            CanonicalNativeProfile::Held(_) => {}
        }
    }
    crate::native_no_dispatch_capacity::add_expected(
        &owners,
        owners.acquisitions.values().filter(|row| {
            !original_acquisitions.contains(&row.acquisition_id)
                && !profiles.contains_key(&row.acquisition_id)
        }),
        &mut expected,
        |request| floors.exact_legacy(request),
    )?;
    crate::native_release_capacity::add_expected_with(
        &owners,
        &mut expected,
        |acquisition| match profiles.get(&acquisition) {
            Some(CanonicalNativeProfile::Held(_)) => {
                native_held_release_status_binding_v1(owner_views(state), acquisition)
                    .map_err(crate::transaction::map_pure_ledger_error)
            }
            Some(CanonicalNativeProfile::Cold(_)) => {
                Err(corrupt("cold archive cannot bind ordinary Release"))
            }
            None => crate::native_release_capacity::binding(&owners, acquisition),
        },
        |request| floors.exact_legacy(request),
    )?;
    if expected != floors.identities() {
        return Err(corrupt("original Source full floor union differs from owners"));
    }
    Ok(floors)
}

fn typed_profiles(
    records: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<BTreeMap<ObjectDigest, CanonicalNativeProfile>, ProviderLedgerError> {
    let mut profiles = BTreeMap::new();
    for (key, value) in records {
        let profile = match value.get(8..10) {
            Some(version) if version == 8_u16.to_be_bytes() => {
                CanonicalNativeProfile::Held(
                    SourceNativeHeldCompletionRecordV1::from_canonical_bytes(key, value)
                        .map_err(crate::transaction::map_pure_ledger_error)?,
                )
            }
            Some(version) if version == 9_u16.to_be_bytes() => {
                let decoded = SourcePreRequestedColdArchiveV1::from_canonical_bytes(key, value)
                    .map_err(crate::transaction::map_pure_ledger_error)?;
                let archive = classify_original_source_pre_requested_cold_v1(
                    records.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
                    decoded.prepared().claims().acquisition_id,
                )
                .map_err(crate::transaction::map_pure_ledger_error)?;
                CanonicalNativeProfile::Cold(archive)
            }
            _ => continue,
        };
        if profiles.insert(profile.acquisition_id(), profile).is_some() {
            return Err(corrupt("duplicate canonical native profile"));
        }
    }
    Ok(profiles)
}

fn require_cold_origin(
    archive: &SourcePreRequestedColdArchiveV1,
    admission: &ValidatedAdmission,
) -> Result<(), ProviderLedgerError> {
    let initial = &admission.initial_floor;
    let row = initial.to_journal_record()?;
    let claims = archive.prepared().claims();
    let owner = &admission.owner;
    let staged = initial.original_provenance().claims().claims.to_canonical_bytes();
    let staged_digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos-source-provider-pre-requested-staged-claims.v1\0")
            .chain_update((staged.len() as u32).to_be_bytes())
            .chain_update(staged)
            .finalize()
            .into(),
    );
    if archive.initial_source_floor_bytes() != row.value().ok_or(corrupt("initial floor DELETE"))?
        || claims.original_source_floor.as_bytes() != &initial.reservation_id()
        || claims.admission_transaction != initial.admission_transaction_id()
        || claims.acquisition_id != owner.acquisition_id
        || claims.provider_id != owner.provider.authority_id()
        || claims.holder_id != owner.holder.authority_id()
        || claims.original_session != owner.session_binding
        || claims.original_signed_request != owner.root_request_digest
        || claims.original_attempt != owner.attempt_digest
        || claims.original_root_prepared != owner.root_prepared_digest
        || claims.original_applying != owner.reservation_acquisition_digest
        || claims.staged_claims != staged_digest
        || claims.challenge_absence.key().get(8..)
            != Some(initial.original_provenance().claims().claims.attempt().0.as_slice())
    {
        return Err(corrupt("cold archive differs from retained original admission DATA"));
    }
    Ok(())
}

fn require_retained_floor(
    current: &OriginalSourceCapacityRecordV5,
    original: &OriginalSourceCapacityRecordV5,
) -> Result<(), ProviderLedgerError> {
    let mut bindings = current.request();
    let initial = original.request();
    bindings.future_transactions = initial.future_transactions;
    bindings.terminal_records = initial.terminal_records;
    bindings.terminal_bytes = initial.terminal_bytes;
    bindings.poison_records = initial.poison_records;
    bindings.poison_bytes = initial.poison_bytes;
    if bindings != initial
        || current.admission_transaction_id() != original.admission_transaction_id()
        || current.origin_budgets() != original.origin_budgets()
        || current.original_provenance() != original.original_provenance()
        || current.origin_reservation_id()? != original.reservation_id()
    {
        return Err(corrupt("original Source retained floor bindings"));
    }
    Ok(())
}

fn require_no_budget_growth(
    old: &OriginalSourceCapacityRecordV5,
    next: &OriginalSourceCapacityRecordV5,
) -> Result<(), ProviderLedgerError> {
    let old = old.request();
    let next = next.request();
    if next.terminal_records > old.terminal_records
        || next.terminal_bytes > old.terminal_bytes
        || next.poison_records > old.poison_records
        || next.poison_bytes > old.poison_bytes
    {
        return Err(corrupt("original Source successor budget grows"));
    }
    Ok(())
}

fn require_owner_binding(
    floor: &OriginalSourceCapacityRecordV5,
    owner: &OriginalSourceOwnerDataV5,
) -> Result<(), ProviderLedgerError> {
    let request = floor.request();
    if request.owner_digest != *owner.reservation_acquisition_digest.as_bytes()
        || request.operation_id != owner.operation_id
        || request.artifact_digest != *owner.attempt_digest.as_bytes()
        || request.checkpoint_digest != *owner.root_request_digest.as_bytes()
        || request.chain_head_digest != *owner.session_binding.as_bytes()
    {
        return Err(corrupt("original Source actual owner binding"));
    }
    Ok(())
}

fn selected_floor(
    state: &State,
    admission: &ValidatedAdmission,
) -> Result<Option<OriginalSourceCapacityRecordV5>, ProviderLedgerError> {
    let floors = Floors::collect_original_source_comparison(capacity_rows(state))?;
    let mut selected = None;
    for entry in floors.0.values() {
        let Floor::OriginalSource(floor) = &entry.floor else {
            continue;
        };
        if floor.request().owner_id != admission.initial_floor.request().owner_id {
            continue;
        }
        if selected.replace(floor.clone()).is_some() {
            return Err(corrupt("duplicate selected Source floor"));
        }
    }
    Ok(selected)
}

fn preserve_other_floors(
    before: &Floors,
    after: &Floors,
    admission: &ValidatedAdmission,
) -> Result<(), ProviderLedgerError> {
    let is_independent = |entry: &&super::native_profile::FloorEntry| {
        !matches!(&entry.floor, Floor::OriginalSource(floor)
            if floor.request().owner_id == admission.initial_floor.request().owner_id)
    };
    let before_rows = before.0.values()
        .filter(is_independent)
        .map(|entry| (&entry.row, entry.admission_transaction_id));
    let after_rows = after.0.values()
        .filter(is_independent)
        .map(|entry| (&entry.row, entry.admission_transaction_id));
    if !before_rows.eq(after_rows) {
        return Err(corrupt("independent Source floor bytes changed"));
    }
    Ok(())
}

fn original_owner_order(
    records: &[JournalRecord],
    floor: &OriginalSourceCapacityRecordV5,
) -> Result<(), ProviderLedgerError> {
    let witnesses = &floor.original_provenance().claims().records;
    if records.len() != 4 || records.iter().zip(witnesses).any(|(row, witness)| {
        row.namespace() != RecordNamespace::SourceProviderAuthority
            || row.key() != witness.key()
            || row.value().is_none()
    }) {
        return Err(corrupt("original Source semantic owner order"));
    }
    Ok(())
}

fn require_native_put(row: &JournalRecord, acquisition: ObjectDigest) -> Result<(), ProviderLedgerError> {
    if row.namespace() != RecordNamespace::SourceProviderAuthority
        || row.key() != native_completion_key_v2(acquisition)
        || row.value().is_none()
    {
        return Err(corrupt("original Source native archive PUT"));
    }
    Ok(())
}

fn require_mutations(
    before: &State,
    records: &[JournalRecord],
    mutations: &[SourceNativeHeldMutationV1],
) -> Result<(), ProviderLedgerError> {
    if records.len() != mutations.len() || mutations.iter().any(|mutation| {
        !records.iter().any(|row| {
            row.namespace() == RecordNamespace::SourceProviderAuthority
                && row.key() == mutation.key()
                && row.value() == Some(mutation.after())
                && before.get(&(row.namespace(), row.key().to_vec())).map(Vec::as_slice)
                    == mutation.before()
        })
    }) {
        return Err(corrupt("original Source exact owner mutation bytes"));
    }
    Ok(())
}

fn owner_views(state: &State) -> impl Iterator<Item = (&[u8], &[u8])> {
    state.iter().filter_map(|((namespace, key), value)| {
        (*namespace == RecordNamespace::SourceProviderAuthority)
            .then_some((key.as_slice(), value.as_slice()))
    })
}

fn capacity_rows(state: &State) -> Vec<JournalRecord> {
    state.iter()
        .filter(|((namespace, _), _)| *namespace == RecordNamespace::GlobalCapacityReservation)
        .map(|((namespace, key), value)| JournalRecord::put(*namespace, key.clone(), value.clone()))
        .collect()
}

fn changes(records: &[JournalRecord]) -> impl Iterator<Item = (&[u8], Option<&[u8]>)> {
    records.iter().map(|row| (row.key(), row.value()))
}

// This conservative allocation ceiling counts 8+key+value for owners AND floors.
// It is stricter than the physical journal's key+value materialized limit, not
// an exact opened-limit model, historical64 suffix estimate or funding scalar.
// Both inventories and the prospective union are bounded before any clone.
fn bound_state(state: &State) -> Result<(), ProviderLedgerError> {
    bound_inventory(state.iter().map(|((namespace, key), value)| {
        (*namespace, key.as_slice(), value.as_slice())
    }))
}

fn bound_inventory<'a>(
    rows: impl Iterator<Item = (RecordNamespace, &'a [u8], &'a [u8])>,
) -> Result<(), ProviderLedgerError> {
    let mut owners = 0_usize;
    let mut floors = 0_usize;
    let mut bytes = 0_usize;
    for (namespace, key, value) in rows {
        match namespace {
            RecordNamespace::SourceProviderAuthority => owners += 1,
            RecordNamespace::GlobalCapacityReservation => {
                floors += 1;
                if key.len() != 75 || value.len() > ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5 {
                    return Err(corrupt("original Source floor width"));
                }
            }
            _ => return Err(corrupt("foreign Source inventory namespace")),
        }
        bytes = bytes
            .checked_add(8)
            .and_then(|total| total.checked_add(key.len()))
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(ProviderLedgerError::LimitExceeded("original Source inventory bytes"))?;
        if owners > MAXIMUM_LEDGER_RECORDS
            || floors > MAXIMUM_LEDGER_RECORDS
            || bytes > MAXIMUM_LEDGER_GRAPH_BYTES
        {
            return Err(ProviderLedgerError::LimitExceeded("original Source complete inventory bounds"));
        }
    }
    Ok(())
}

fn bound_transaction(transaction: &JournalTransaction, count: usize) -> Result<(), ProviderLedgerError> {
    if transaction.records().len() != count {
        return Err(corrupt("original Source exact coupled count"));
    }
    let mut bytes = 0_usize;
    let mut keys = BTreeSet::new();
    for row in transaction.records() {
        if !matches!(
            row.namespace(),
            RecordNamespace::SourceProviderAuthority | RecordNamespace::GlobalCapacityReservation
        ) || !keys.insert((row.namespace(), row.key()))
        {
            return Err(corrupt("foreign or duplicate original Source TX record"));
        }
        bytes = bytes
            .checked_add(8)
            .and_then(|total| total.checked_add(row.key().len()))
            .and_then(|total| total.checked_add(row.value().map_or(0, <[u8]>::len)))
            .ok_or(ProviderLedgerError::LimitExceeded("original Source TX bytes"))?;
        if bytes > MAXIMUM_TRANSACTION_BYTES {
            return Err(ProviderLedgerError::LimitExceeded("original Source TX bytes"));
        }
    }
    Ok(())
}

fn apply_transaction(
    before: &State,
    transaction: &JournalTransaction,
) -> Result<State, ProviderLedgerError> {
    bound_state(before)?;
    bound_transaction(transaction, transaction.records().len())?;
    // Reject noops/missing DELETEs before cloning the complete caller state.
    for row in transaction.records() {
        let previous = before.get(&(row.namespace(), row.key().to_vec()));
        if row.value() == previous.map(Vec::as_slice) {
            return Err(corrupt("original Source TX noop or missing DELETE"));
        }
    }
    let unchanged = before.iter()
        .filter(|((namespace, key), _)| {
            !transaction.records().iter().any(|row| {
                row.namespace() == *namespace && row.key() == key.as_slice()
            })
        })
        .map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice()));
    let replacements = transaction.records().iter().filter_map(|row| {
        row.value().map(|value| (row.namespace(), row.key(), value))
    });
    bound_inventory(unchanged.chain(replacements))?;

    let mut after = before.clone();
    for row in transaction.records() {
        let key = (row.namespace(), row.key().to_vec());
        match row.value() {
            Some(value) => {
                after.insert(key, value.to_vec());
            }
            None => {
                after.remove(&key);
            }
        }
    }
    bound_state(&after)?;
    Ok(after)
}

fn corrupt(message: &'static str) -> ProviderLedgerError {
    ProviderLedgerError::Corrupt(message)
}

#[cfg(test)]
mod tests;
