//! Exact original Source mixed-floor transaction comparisons, exclusively DATA.
//!
//! Complete inventories and borrowed transactions are checked before retention.
//! No result establishes physical admission membership, configuration origin,
//! archive eligibility or whole-journal funding, or enters a Ready ledger.
//! The shared Sandbox union covers reducer-derived later prefixes. Foreign
//! families and unsupported Native3 intermediates remain explicit refusals.
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
        SourcePreRequestedColdArchiveV1, SourcePreRequestedColdPhaseV1,
        classify_original_source_pre_requested_cold_v1,
    },
    ledger::native_held_completion::SourceNativeHeldCompletionRecordV1,
    ledger::source_capacity::{
        OriginalSourceChallengeDataV5, SourceCapacityOwnerEdgeKindV5 as OwnerEdgeKind,
    },
    limits::{MAXIMUM_LEDGER_GRAPH_BYTES, MAXIMUM_LEDGER_RECORDS, MAXIMUM_TRANSACTION_BYTES},
};
#[cfg(test)]
use aos_sandbox_source_provider_ledger::ledger::{
    native_completion::{
        OriginalSourceOwnerDataV5, OriginalSourceOwnerPrefixV5,
        classify_original_source_owner_v5,
        native_completion_key_v2, propose_original_source_applying_v5,
        propose_original_source_pre_requested_closed_v1,
        propose_original_source_pre_requested_closure_stored_v1,
        propose_original_source_pre_requested_root_acknowledged_v1,
        propose_original_source_requested_v5,
    },
    native_held_completion::{
        SourceNativeHeldMutationV1,
        native_held_release_status_binding_v1, validate_native_held_records_v1,
    },
};
#[cfg(test)]
use sha2::{Digest as _, Sha256};

use super::{
    CanonicalNativeProfile,
    native_profile::{Floor, Floors, UnresolvedNativeProofV1},
};
use crate::{ProviderLedgerError, state::ProtectedProviderConfigurationV1};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

/// Retains current protected authentication alongside still-unresolved DATA.
///
/// Authentication under today's configuration is not evidence of the archived
/// original deployment, original floor custody or physical transaction history.
pub(super) struct AuthenticatedSourceCapacityUnionDataV5 {
    /// Retains canonical comparison DATA with no Ready/writer conversion.
    pub(super) comparison: aos_sandbox::journal::SourceCapacityUnionComparisonDataV5,
    configuration_origin: UnresolvedNativeProofV1,
    original_physical_membership: UnresolvedNativeProofV1,
    archive_eligibility: UnresolvedNativeProofV1,
    whole_journal_funding: UnresolvedNativeProofV1,
}

/// Authenticates complete current/historical cuts without promoting DATA to Ready.
///
/// The pure Sandbox comparator derives all owner/floor eligibility below Source.
/// Source alone checks real protected current configuration, retained histories
/// and signatures. There is no callback into Source from Sandbox or new writer.
///
/// # Errors
///
/// Rejects incomplete union/edge DATA, foreign current deployment configuration,
/// or current/historical owner authentication and retained-signature failures.
pub(super) fn compare_authenticated_source_capacity_union_data_v5(
    before: &aos_sandbox::journal::SourceCapacityStateV5,
    transaction: Option<&JournalTransaction>,
    origins: &[aos_sandbox::journal::SourceOriginalAdmissionDataV5],
    challenges: &[OriginalSourceChallengeDataV5<'_>],
    configuration: &ProtectedProviderConfigurationV1,
    limits: aos_sandbox::JournalLimits,
) -> Result<AuthenticatedSourceCapacityUnionDataV5, ProviderLedgerError> {
    let comparison = aos_sandbox::journal::compare_source_capacity_union_data_v5(
        before,
        transaction,
        origins,
        challenges,
        limits,
    )?;

    authenticate_complete_cut(comparison.before(), configuration)?;
    authenticate_complete_cut(comparison.after(), configuration)?;
    for origin in origins {
        if origin.admission_comparison().original().configuration_digest
            != configuration.deployment_digest()
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        authenticate_complete_cut(origin.original_before(), configuration)?;
        authenticate_complete_cut(origin.applying_after(), configuration)?;
    }

    Ok(AuthenticatedSourceCapacityUnionDataV5 {
        comparison,
        configuration_origin: UnresolvedNativeProofV1::Unresolved,
        original_physical_membership: UnresolvedNativeProofV1::Unresolved,
        archive_eligibility: UnresolvedNativeProofV1::Unresolved,
        whole_journal_funding: UnresolvedNativeProofV1::Unresolved,
    })
}

fn authenticate_complete_cut(
    state: &State,
    configuration: &ProtectedProviderConfigurationV1,
) -> Result<(), ProviderLedgerError> {
    let records = collect_bounded_records(owner_views(state))
        .map_err(crate::transaction::map_pure_ledger_error)?;
    let profiles = typed_profiles(&records)?;

    super::recover_records_with_profiles(
        records.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
        configuration,
        &profiles,
    )?;
    Ok(())
}

/// Authenticates one real complete cut under archived equality and current eligibility.
///
/// Neither input can replace the other: archived deployment owns durable head
/// equality; freshly protected current configuration owns issuance/revocation.
pub(crate) fn authenticate_archived_complete_cut_v5(
    state: &State,
    archived: &aos_sandbox_source_provider_security::ProtectedOriginalDeploymentV5,
    current: &ProtectedProviderConfigurationV1,
) -> Result<crate::model::RecoveredProviderLedgerV1, ProviderLedgerError> {
    let configuration = ProtectedProviderConfigurationV1::from_original_archive_v5(archived)?;
    let records = collect_bounded_records(owner_views(state))
        .map_err(crate::transaction::map_pure_ledger_error)?;
    let profiles = typed_profiles(&records)?;

    // This unchanged recovery pass enforces exact durable heads, catalog floor,
    // canonical graph, Session/history joins and signatures against archived A.
    let recovered = super::recover_records_with_profiles(
        records.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
        &configuration,
        &profiles,
    )?;

    // Only key/issuance/revocation eligibility is overlaid. In particular,
    // today's catalog floor is not applied to the unchanged historical cut.
    super::validate_historical_signatures(
        current,
        &recovered.authority,
        &recovered.catalog_history,
        &recovered.session_history,
        &recovered.attempts,
        &recovered.acquisitions,
        &recovered.releases,
    )?;
    for catalog in recovered.catalog_history.values() {
        let trusted = current.historical_key_projection_for(&catalog.publisher_signer)
            .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
        aos_sandbox_source_provider_security::verify_retained_catalog_publication(
            current.trust_history(), trusted, &catalog.canonical_publication,
        )?;
    }
    Ok(recovered)
}

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

#[cfg(test)]
struct ValidatedAdmission {
    after: State,
    initial_floor: OriginalSourceCapacityRecordV5,
    owner: OriginalSourceOwnerDataV5,
}

/// Delegates the five legacy comparison shapes to the complete all-prefix union.
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

    let limits = aos_sandbox::JournalLimits::default();
    let admission = aos_sandbox::journal::compare_source_original_admission_data_v5(
        aos_sandbox::journal::SourceOriginalAdmissionInputV5 {
            original_before: original.original_before,
            original_applying: original.applying_transaction,
        },
        limits,
    )?;
    let compared = compare_authenticated_source_capacity_union_data_v5(
        before,
        Some(transaction),
        &[admission],
        &[],
        configuration,
        limits,
    )?;
    if compared.comparison.after() != after {
        return Err(corrupt("original Source full after differs from ordered TX"));
    }
    let expected = match edge {
        OriginalSourceFloorEdgeV5::Applying => OwnerEdgeKind::Applying,
        OriginalSourceFloorEdgeV5::FirstRequested => OwnerEdgeKind::Held(
            aos_sandbox_source_provider_ledger::ledger::native_held_completion::SourceNativeHeldStepV1::Requested,
        ),
        OriginalSourceFloorEdgeV5::ColdClosedPrepared => {
            OwnerEdgeKind::PreRequestedCold(SourcePreRequestedColdPhaseV1::ClosedPrepared)
        }
        OriginalSourceFloorEdgeV5::ColdClosureStored => {
            OwnerEdgeKind::PreRequestedCold(SourcePreRequestedColdPhaseV1::ClosureStored)
        }
        OriginalSourceFloorEdgeV5::ColdRootAcknowledged => {
            OwnerEdgeKind::PreRequestedCold(SourcePreRequestedColdPhaseV1::RootAcknowledged)
        }
    };
    if compared.comparison.owner_edge().map(|edge| edge.kind()) != Some(expected) {
        return Err(corrupt("original Source compatibility edge differs from actual reducer"));
    }
    drop(compared);

    let before_floors = Floors::collect_original_source_comparison(capacity_rows(before))?;
    let after_floors = Floors::collect_original_source_comparison(capacity_rows(after))?;

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

#[cfg(test)]
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

#[cfg(test)]
fn validate_edge(
    before: &State,
    transaction: &JournalTransaction,
    before_floors: &Floors,
    after_floors: &Floors,
    admission: &ValidatedAdmission,
    edge: OriginalSourceFloorEdgeV5,
) -> Result<(), ProviderLedgerError> {
    let (record_count, owner_count, old_count, next_count) = edge.shape();
    bound_transaction(transaction, record_count)?;
    let records = transaction.records();
    let floor = &admission.initial_floor;
    let provenance = floor.original_provenance();
    let configuration = provenance.claims().configuration;
    let old = selected_floor(before_floors, admission)?;
    let next = selected_floor(after_floors, admission)?;

    if old.map(|row| row.request().future_transactions) != old_count
        || next.map(|row| row.request().future_transactions) != next_count
    {
        return Err(corrupt("original Source edge exact counts"));
    }
    if let Some(old) = old {
        require_retained_floor(old, floor)?;
        let expected = JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation,
            old.to_journal_record()?.key().to_vec(),
        );
        if records[owner_count] != expected {
            return Err(corrupt("original Source ordered floor DELETE"));
        }
    }
    if let Some(next) = next {
        require_retained_floor(next, floor)?;
        if records[record_count - 1] != next.to_journal_record()? {
            return Err(corrupt("original Source ordered floor PUT"));
        }
        if let Some(old) = old {
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
            if let Some(next) = next {
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

// The comparison passes inventories already checked for complete families,
// owner/configuration and the exact union. Selection never reconstructs a cut.
#[cfg(test)]
fn selected_floor<'floor>(
    floors: &'floor Floors,
    admission: &ValidatedAdmission,
) -> Result<Option<&'floor OriginalSourceCapacityRecordV5>, ProviderLedgerError> {
    let mut selected = None;
    for entry in floors.0.values() {
        let Floor::OriginalSource(floor) = &entry.floor else {
            continue;
        };
        if floor.request().owner_id != admission.initial_floor.request().owner_id {
            continue;
        }
        if selected.replace(floor).is_some() {
            return Err(corrupt("duplicate selected Source floor"));
        }
    }
    Ok(selected)
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
fn require_native_put(row: &JournalRecord, acquisition: ObjectDigest) -> Result<(), ProviderLedgerError> {
    if row.namespace() != RecordNamespace::SourceProviderAuthority
        || row.key() != native_completion_key_v2(acquisition)
        || row.value().is_none()
    {
        return Err(corrupt("original Source native archive PUT"));
    }
    Ok(())
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
