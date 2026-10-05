//! Same-writer original Root native admission, retained provenance and readback.
//!
//! Only exact rederived namespace40 owner edges plus their namespace46 original
//! floor pass this scope. Physical readback does not establish live Security
//! custody or Mount's actual table installation; those owners must compare the
//! same retained originals before private signing or carrier IO.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::{
    RootNativeCutKindV1, RootNativeCutV1, RootNativeHeldGraphV2, RootNativeHeldSidecarV2,
    RootNativeTransitionKindV2 as Kind, has_original_pending_closed_cut_v5,
    native_root_sidecar_key_v2, original_root_remaining_v5,
    validate_native_root_graph_v2, validate_original_root_transition_v5,
};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1, NativeHeldOwnerV1,
    frame::{PreparedNativeHeldControlV1, SignedNativeHeldControlV1},
    suffix::NativeHeldCompletionSuffixV1,
};
use sha2::{Digest as _, Sha256};

use super::capacity_reservation::{
    OrdinaryCapacityKindV4, OrdinaryCapacityProfileV4, OrdinaryCapacityRecordV4,
};
use super::capacity_reservation::family::{CanonicalCapacityFamily, canonical_reservations};
use super::native_held::OriginalRootCapacityRecordV5;
use super::{
    CacheMutationGateV1, CommitResult, Journal, JournalError, JournalLimits, JournalRecord,
    JournalTransaction, ProtectedAuthorityScope, ProtectedJournalAuthority,
    ProtectedJournalSnapshot, RecordNamespace, RootOwnerEdge, RootSourceGenesisTransitionV1,
    SourceProjectAdmissionTransition, authority_preflight_digest, controller_source_genesis,
    source_tree_genesis, validate_transaction,
};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

mod pending_v5;
mod root_closed_v5;
mod custody;

#[cfg(test)]
pub(super) use root_closed_v5::phase11_funded_data;

fn invalid() -> JournalError {
    JournalError::MalformedRecord("invalid original Root native owner edge")
}

fn graph(state: &State) -> Result<RootNativeHeldGraphV2, JournalError> {
    validate_native_root_graph_v2(state.iter().filter_map(|((namespace, key), value)| {
        (*namespace == RecordNamespace::MountSourceAcquisition)
            .then_some((key.as_slice(), value.as_slice()))
    }))
    .map_err(|_| invalid())
}

fn require_named_funding(state: &State, limits: JournalLimits) -> Result<(), JournalError> {
    // Query coexistence is a complete metadata join, never a generic allowance.
    super::root_original_inventory::pending(state, limits)?;
    let mut families = canonical_reservations(state)?;
    if families.iter().any(is_original_release_floor) {
        validate_original_release_floors(state, &families)?;
        families.retain(|family| !is_original_release_floor(family));
    }
    require_supported_funding_families(&families)
}

fn is_original_release_floor(family: &CanonicalCapacityFamily) -> bool {
    matches!(family, CanonicalCapacityFamily::Ordinary4(floor)
        if floor.data().kind == OrdinaryCapacityKindV4::ReleaseRequest)
}

fn validate_original_release_floors(
    state: &State,
    families: &[CanonicalCapacityFamily],
) -> Result<(), JournalError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        ProviderAttemptStateV2, ProviderMethodV2, ProviderQueryOwnerV2,
        SourceAcquisitionPhaseV2,
    };

    let checked = graph(state)?;
    let mut owners = BTreeSet::new();
    for family in families {
        let CanonicalCapacityFamily::Ordinary4(floor) = family else { continue };
        let data = floor.data();
        if data.kind != OrdinaryCapacityKindV4::ReleaseRequest { continue; }
        if !owners.insert(data.owner_id)
            || !matches!(data.profile, OrdinaryCapacityProfileV4::ReleaseOutcomeAndNegativeCustody
                | OrdinaryCapacityProfileV4::ReleaseNegativeCustody)
        {
            return Err(invalid());
        }
        let query = checked.legacy().provider_attempts.get(&data.owner_id)
            .ok_or_else(invalid)?;
        let ProviderQueryOwnerV2::Release { acquisition_id } = query.owner else {
            return Err(invalid());
        };
        let row = checked.legacy().acquisitions.get(&acquisition_id).ok_or_else(invalid)?;
        let root = row.acquire_lineage.root.id;
        let sidecar = checked.sidecars().get(&root).ok_or_else(invalid)?;
        let head = checked.legacy().provider_heads
            .get(&(row.scope.holder_authority_id, row.scope.provider_authority_id))
            .ok_or_else(invalid)?;
        if sidecar.suffix().phase() != 7
            || original_root_remaining_v5(&checked, root).map_err(|_| invalid())? != 0
            || query.method != ProviderMethodV2::Release
            || !match data.profile {
                OrdinaryCapacityProfileV4::ReleaseOutcomeAndNegativeCustody =>
                    query.state == ProviderAttemptStateV2::Reserved,
                OrdinaryCapacityProfileV4::ReleaseNegativeCustody => matches!(query.state,
                    ProviderAttemptStateV2::DispositionConsumed {
                        status: aos_sandbox_protocol::mount_source_acquisition_state::ProviderStatusV2::Pending, ..
                    }),
                _ => false,
            }
            || row.phase != SourceAcquisitionPhaseV2::Releasing
            || row.release_lineage.as_ref().is_none_or(|lineage| {
                lineage.root.id != data.owner_id || lineage.tail.id != data.owner_id
            })
            || !match data.profile {
                OrdinaryCapacityProfileV4::ReleaseOutcomeAndNegativeCustody =>
                    head.pending_attempt.as_ref().is_some_and(|pending| pending.id == data.owner_id),
                OrdinaryCapacityProfileV4::ReleaseNegativeCustody => head.pending_attempt.is_none(),
                _ => false,
            }
            || query.signed_request_digest != data.original_artifact_digest
            || query.request_id != data.operation_id
        {
            return Err(invalid());
        }
        let puts = original_release_current_puts(&checked, data.owner_id)?;
        if OriginalRootCapacityRecordV5::release_owner_digest_v1(&puts)?
            != data.admission_owner_mutation_digest
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn original_release_current_puts(
    checked: &RootNativeHeldGraphV2,
    release: [u8; 32],
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, JournalError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        ProviderQueryOwnerV2, StoredRecordV2, encode_mount_source_state_record_v2,
    };

    let query = checked.legacy().provider_attempts.get(&release).ok_or_else(invalid)?;
    let ProviderQueryOwnerV2::Release { acquisition_id } = query.owner else {
        return Err(invalid());
    };
    let row = checked.legacy().acquisitions.get(&acquisition_id).ok_or_else(invalid)?;
    let head = checked.legacy().provider_heads
        .get(&(row.scope.holder_authority_id, row.scope.provider_authority_id))
        .ok_or_else(invalid)?;
    [
        StoredRecordV2::ProviderQueryAttempt { value: query.clone() },
        StoredRecordV2::Acquisition { value: row.clone() },
        StoredRecordV2::ProviderHead { value: head.clone() },
    ].iter().map(|record| encode_mount_source_state_record_v2(record)
        .map_err(|_| invalid())).collect()
}

fn derive_original_release(
    state: &State,
    owners: &JournalTransaction,
    root: [u8; 32],
    release: [u8; 32],
    limits: JournalLimits,
) -> Result<(JournalTransaction, OrdinaryCapacityRecordV4), JournalError> {
    require_named_funding(state, limits)?;
    if canonical_reservations(state)?.iter().any(is_original_release_floor) {
        return Err(JournalError::ProtectedBoundary);
    }
    super::root_local_recovery::require_fences(state, owners)?;
    let before = graph(state)?;
    let after = graph(&apply(state, owners.records())?)?;
    let proposal = aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::
        validate_original_release_transition_v1(&before, &after, root, release, *owners.id())
        .map_err(|_| invalid())?;
    require_exact_owner_puts(owners, &proposal.puts, None)?;
    let floor = OriginalRootCapacityRecordV5::release_floor_v1(
        &before, &after, root, release, *owners.id(), state, limits,
    )?;
    let mut records = owners.records().to_vec();
    records.push(floor.to_journal_record());
    let transaction = JournalTransaction::new(*owners.id(), records)?;
    validate_transaction(&transaction, limits)?;
    Ok((transaction, floor))
}

fn validate_original_release_edge(
    state: &State,
    transaction: &JournalTransaction,
    root: [u8; 32],
    limits: JournalLimits,
) -> Result<(), JournalError> {
    // This bounded prefix selects only the new Pending disposition. The sole
    // family decoder below still authenticates its complete bytes. Existing
    // profile3 inputs retain their original DELETE/error/collection order.
    let pending = transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::GlobalCapacityReservation
            && record.value().is_some_and(|bytes| {
                bytes.get(8..14) == Some(&[0, 4, 40, 10, 12, 4])
            })
    });
    let floors = transaction.records().iter()
        .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
        .filter(|record| !pending || record.value().is_some())
        .map(OrdinaryCapacityRecordV4::from_journal_record)
        .collect::<Result<Vec<_>, _>>()?;
    let [floor] = floors.as_slice() else { return Err(invalid()) };
    if floor.data().kind != OrdinaryCapacityKindV4::ReleaseRequest {
        return Err(invalid());
    }
    let owners = JournalTransaction::new(*transaction.id(), transaction.records().iter()
        .filter(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
        .cloned().collect())?;
    let (derived, _) = match floor.data().profile {
        OrdinaryCapacityProfileV4::ReleaseOutcomeAndNegativeCustody =>
            derive_original_release(state, &owners, root, floor.data().owner_id, limits)?,
        OrdinaryCapacityProfileV4::ReleaseNegativeCustody =>
            derive_original_release_status(state, &owners, root, floor.data().owner_id, limits)?,
        _ => return Err(invalid()),
    };
    if derived != *transaction { return Err(invalid()); }
    Ok(())
}

fn derive_original_release_status(
    state: &State,
    owners: &JournalTransaction,
    root: [u8; 32],
    release: [u8; 32],
    limits: JournalLimits,
) -> Result<(JournalTransaction, OrdinaryCapacityRecordV4), JournalError> {
    require_named_funding(state, limits)?;
    super::root_local_recovery::require_fences(state, owners)?;
    let families = canonical_reservations(state)?;
    let old = families.iter().find_map(|family| match family {
        CanonicalCapacityFamily::Ordinary4(floor) if is_original_release_floor(family)
            && floor.data().owner_id == release => Some(floor),
        _ => None,
    }).ok_or_else(invalid)?;
    let before = graph(state)?;
    let after = graph(&apply(state, owners.records())?)?;
    let proposal = aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::
        validate_original_release_status_transition_v1(&before, &after, root, release, *owners.id())
        .map_err(|_| invalid())?;
    require_exact_owner_puts(owners, &proposal.puts, None)?;
    let next = OriginalRootCapacityRecordV5::release_status_floor_v1(
        &before, &after, old, root, release, *owners.id(), limits,
    )?;
    let previous = old.to_journal_record();
    let mut records = owners.records().to_vec();
    records.push(JournalRecord::delete(previous.namespace(), previous.key().to_vec()));
    records.push(next.to_journal_record());
    let transaction = JournalTransaction::new(*owners.id(), records)?;
    validate_transaction(&transaction, limits)?;
    let charged = super::encoded_transaction_append_bytes(&transaction)?
        .checked_add(next.data().remaining_append_bytes).ok_or(JournalError::SequenceExhausted)?;
    if old.data().remaining_transactions != next.data().remaining_transactions + 1
        || u64::from(old.data().remaining_record_frames)
            < transaction.records().len() as u64 + u64::from(next.data().remaining_record_frames)
        || old.data().remaining_append_bytes < charged
    {
        return Err(JournalError::LimitExceeded("original Release Pending transferred debt"));
    }
    Ok((transaction, next))
}

/// Shares only the closed family policy after complete canonical traversal.
///
/// # Errors
/// Rejects unsupported Source5, Mount Native3 and non-kind2/kind5 Ordinary4.
pub(super) fn require_supported_funding_families(
    families: &[CanonicalCapacityFamily],
) -> Result<(), JournalError> {
    for family in families {
        match family {
            // Source5 is pure DATA only until its own named writer is implemented.
            CanonicalCapacityFamily::OriginalSource5(_) => {
                return Err(JournalError::ProtectedBoundary);
            }
            CanonicalCapacityFamily::Native3(floor)
                if floor.request().purpose.owner_namespace()
                    == RecordNamespace::MountSourceAcquisition =>
            {
                return Err(JournalError::ProtectedBoundary);
            }
            CanonicalCapacityFamily::Ordinary4(floor)
                if !matches!(
                    floor.data().kind,
                    OrdinaryCapacityKindV4::BarrierIdleReplacement
                        | OrdinaryCapacityKindV4::DeadReplacement
                ) =>
            {
                return Err(JournalError::ProtectedBoundary);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Rejoins unchanged native5 originals after the caller's exact ordinary reducer.
pub(super) fn preserve_local_owner(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    let families = canonical_reservations(state)?;
    let floors: Vec<_> = families
        .into_iter()
        .filter_map(|family| match family {
            CanonicalCapacityFamily::OriginalRoot5(floor) => Some(floor),
            _ => None,
        })
        .collect();
    if floors.is_empty() {
        return Ok(());
    }
    let before = graph(state)?;
    let owners: Vec<_> = transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
        .cloned()
        .collect();
    let after = graph(&apply(state, &owners)?)?;
    if before.sidecars() != after.sidecars() || before.v1_sidecars() != after.v1_sidecars() {
        return Err(invalid());
    }
    for floor in floors {
        let record = floor.to_journal_record()?;
        if transaction.records().iter().any(|changed| {
            changed.namespace() == record.namespace() && changed.key() == record.key()
        }) {
            return Err(invalid());
        }
        floor.validate_preserved_graph(&before)?;
        floor.validate_preserved_graph(&after)?;
    }
    Ok(())
}

pub(super) fn require_funded_original_owner(
    state: &State,
    checked: &RootNativeHeldGraphV2,
) -> Result<(), JournalError> {
    let families = canonical_reservations(state)?;
    if !checked.v1_sidecars().is_empty() {
        return Err(JournalError::ProtectedBoundary);
    }
    for sidecar in checked.sidecars().values() {
        let attempt = *sidecar.original_scope().mount_attempt.as_bytes();
        if original_root_remaining_v5(checked, attempt).map_err(|_| invalid())? == 0 {
            if families.iter().any(|family| matches!(family,
                CanonicalCapacityFamily::OriginalRoot5(floor) if floor.request().owner_id == attempt))
            { return Err(invalid()); }
            // The complete graph validates the genuine terminal ACK or exact
            // no-interest marker. Floor absence is NOT a new grant or P factory.
            continue;
        }
        let floor = families
            .iter()
            .find_map(|family| match family {
                CanonicalCapacityFamily::OriginalRoot5(floor)
                    if floor.request().owner_id == attempt =>
                {
                    Some(floor)
                }
                _ => None,
            })
            .ok_or(JournalError::ProtectedBoundary)?;
        floor.validate_preserved_graph(checked)?;
    }
    Ok(())
}

/// Rejoins every selected original floor only after validating ALL families.
pub(super) fn pending(
    state: &State,
    limits: JournalLimits,
) -> Result<Vec<OriginalRootCapacityRecordV5>, JournalError> {
    let floors: Vec<_> = canonical_reservations(state)?
        .into_iter()
        .filter_map(|family| match family {
            CanonicalCapacityFamily::OriginalRoot5(floor) => Some(floor),
            _ => None,
        })
        .collect();
    let mut owners = BTreeSet::new();
    if floors
        .iter()
        .any(|floor| !owners.insert(floor.request().owner_id))
    {
        return Err(invalid());
    }
    let archives = state.keys().any(|(namespace, key)| {
        *namespace == RecordNamespace::MountSourceAcquisition
            && key.starts_with(b"aos.mount.native-held-completion.")
    });
    if floors.is_empty() && !archives {
        return Ok(floors);
    }
    let checked = graph(state)?;
    for floor in &floors {
        floor.validate_graph(&checked, limits)?;
    }
    require_funded_original_owner(state, &checked)?;
    Ok(floors)
}

pub(super) fn require_generic_transaction(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    let archives = state.keys().any(|(namespace, key)| {
        *namespace == RecordNamespace::MountSourceAcquisition
            && key.starts_with(b"aos.mount.native-held-completion.")
    });
    if archives {
        let checked = graph(state)?;
        require_funded_original_owner(state, &checked)?;
        if transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    Ok(())
}

fn apply(state: &State, records: &[JournalRecord]) -> Result<State, JournalError> {
    let mut after = state.clone();
    for record in records {
        if record.namespace() != RecordNamespace::MountSourceAcquisition || record.value().is_none()
        {
            return Err(invalid());
        }
        after.insert(
            (record.namespace(), record.key().to_vec()),
            record.value().ok_or_else(invalid)?.to_vec(),
        );
    }
    Ok(after)
}

fn require_exact_owner_puts(
    owners: &JournalTransaction,
    puts: &BTreeMap<Vec<u8>, Vec<u8>>,
    generated: Option<(&[u8], &[u8])>,
) -> Result<(), JournalError> {
    let expected_count = owners
        .records()
        .len()
        .checked_add(usize::from(generated.is_some()))
        .ok_or_else(invalid)?;
    if puts.len() != expected_count {
        return Err(invalid());
    }
    if let Some((key, value)) = generated {
        if puts.get(key).map(Vec::as_slice) != Some(value) {
            return Err(invalid());
        }
    }

    let mut seen = BTreeSet::new();
    for record in owners.records() {
        if record.namespace() != RecordNamespace::MountSourceAcquisition
            || record.value().is_none()
            || generated.is_some_and(|(key, _)| record.key() == key)
            || !seen.insert(record.key())
            || puts.get(record.key()).map(Vec::as_slice) != record.value()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn admission(
    state: &State,
    owners: &JournalTransaction,
    prepared: PreparedNativeHeldControlV1,
    limits: JournalLimits,
) -> Result<(JournalTransaction, OriginalRootCapacityRecordV5), JournalError> {
    let (transaction, floor) = derive_admission(state, owners, prepared, limits)?;
    validate_transaction(&transaction, limits)?;
    Ok((transaction, floor))
}

fn derive_admission(
    state: &State,
    owners: &JournalTransaction,
    prepared: PreparedNativeHeldControlV1,
    limits: JournalLimits,
) -> Result<(JournalTransaction, OriginalRootCapacityRecordV5), JournalError> {
    require_named_funding(state, limits)?;
    let before = graph(state)?;
    pending(state, limits)?;
    super::root_local_recovery::require_fences(state, owners)?;
    let attempt = *prepared.scope().mount_attempt.as_bytes();
    let mut after = apply(state, owners.records())?;
    let reserved = graph(&after)?;
    let cut = RootNativeCutV1::capture(
        RootNativeCutKindV1::Admission,
        *owners.id(),
        reserved.legacy(),
        attempt,
    )
    .map_err(|_| invalid())?;
    let suffix = NativeHeldCompletionSuffixV1::new(
        NativeHeldOwnerV1::Root,
        0,
        prepared.scope().flight,
        Some(prepared.clone()),
        Vec::new(),
    )
    .map_err(|_| invalid())?;
    let sidecar = RootNativeHeldSidecarV2::new(
        *prepared.scope(),
        [0; 16],
        None,
        None,
        None,
        suffix,
        cut.clone(),
        None,
        None,
    )
    .map_err(|_| invalid())?;
    let key = native_root_sidecar_key_v2(attempt).map_err(|_| invalid())?;
    let value = sidecar.to_canonical_bytes().map_err(|_| invalid())?;
    if after
        .insert(
            (RecordNamespace::MountSourceAcquisition, key.clone()),
            value.clone(),
        )
        .is_some()
    {
        return Err(invalid());
    }
    let after_graph = graph(&after)?;
    let proposal =
        validate_original_root_transition_v5(&before, &after_graph, attempt, *owners.id())
            .map_err(|_| invalid())?;
    if proposal.kind != Kind::PreparedAssertionRecorded
        || proposal.admission_binding.is_none()
        || !(5..=6).contains(&proposal.puts.len())
    {
        return Err(invalid());
    }
    require_exact_owner_puts(owners, &proposal.puts, Some((&key, &value)))?;
    let floor = OriginalRootCapacityRecordV5::for_graph(&after_graph, prepared, cut, limits)?;
    let mut records = owners.records().to_vec();
    records.push(JournalRecord::put(
        RecordNamespace::MountSourceAcquisition,
        key,
        value,
    ));
    records.push(floor.to_journal_record()?);
    let transaction = JournalTransaction::new(*owners.id(), records)?;
    Ok((transaction, floor))
}

fn continuation(
    state: &State,
    owners: &JournalTransaction,
    attempt: [u8; 32],
    limits: JournalLimits,
) -> Result<
    (
        JournalTransaction,
        Option<OriginalRootCapacityRecordV5>,
        [u8; 32],
    ),
    JournalError,
> {
    let (transaction, next, old) = derive_continuation(state, owners, attempt, limits)?;
    validate_transfer(&transaction, &old, next.as_ref(), limits)?;
    Ok((transaction, next, old.reservation_id()))
}

fn derive_continuation(
    state: &State,
    owners: &JournalTransaction,
    attempt: [u8; 32],
    limits: JournalLimits,
) -> Result<
    (
        JournalTransaction,
        Option<OriginalRootCapacityRecordV5>,
        OriginalRootCapacityRecordV5,
    ),
    JournalError,
> {
    require_named_funding(state, limits)?;
    let old = pending(state, limits)?
        .into_iter()
        .find(|floor| floor.request().owner_id == attempt)
        .ok_or_else(invalid)?;
    super::root_local_recovery::require_fences(state, owners)?;
    let before = graph(state)?;
    let after = graph(&apply(state, owners.records())?)?;
    let proposal = validate_original_root_transition_v5(&before, &after, attempt, *owners.id())
        .map_err(|_| invalid())?;
    if matches!(
        proposal.kind,
        Kind::PreparedAssertionRecorded | Kind::Duplicate
    ) {
        return Err(invalid());
    }
    require_exact_owner_puts(owners, &proposal.puts, None)?;
    let next = if proposal.maximum_remaining_transactions == 0 {
        if !matches!(
            proposal.kind,
            Kind::TerminalAckStored | Kind::NativeNoInterestCleanup
        ) {
            return Err(invalid());
        }
        if proposal.kind == Kind::NativeNoInterestCleanup {
            let marker = after
                .sidecars()
                .get(&attempt)
                .and_then(|r| r.no_interest_terminal())
                .ok_or_else(invalid)?;
            let bytes = old.to_journal_record()?;
            if marker.retired_capacity()
                != (
                    old.reservation_id(),
                    super::capacity_reservation::digest_bytes(bytes.value().ok_or_else(invalid)?),
                )
            {
                return Err(invalid());
            }
        }
        None
    } else {
        Some(OriginalRootCapacityRecordV5::for_graph(
            &after,
            old.original_prepared().clone(),
            old.admission_cut().clone(),
            limits,
        )?)
    };
    let mut records = owners.records().to_vec();
    records.push(JournalRecord::delete(
        RecordNamespace::GlobalCapacityReservation,
        old.to_journal_record()?.key().to_vec(),
    ));
    if let Some(floor) = &next {
        records.push(floor.to_journal_record()?);
    }
    let transaction = JournalTransaction::new(*owners.id(), records)?;
    Ok((transaction, next, old))
}

fn validate_transfer(
    transaction: &JournalTransaction,
    old: &OriginalRootCapacityRecordV5,
    next: Option<&OriginalRootCapacityRecordV5>,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    super::native_held::check_transfer(
        transaction,
        old.request(),
        next.map(OriginalRootCapacityRecordV5::request),
        limits,
        (
            "original Root consumed records",
            "original Root complete transferred suffix",
        ),
    )
}

pub(super) fn validate_edge(
    state: &State,
    transaction: &JournalTransaction,
    attempt: [u8; 32],
    limits: JournalLimits,
) -> Result<Option<[u8; 32]>, JournalError> {
    if transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::GlobalCapacityReservation
            && record.value().is_some_and(|bytes| bytes.get(8..13) == Some(&[0, 4, 40, 10, 12]))
    }) {
        validate_original_release_edge(state, transaction, attempt, limits)?;
        return Ok(None);
    }
    let owners: Vec<_> = transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
        .cloned()
        .collect();
    if pending(state, limits)?
        .iter()
        .any(|floor| floor.request().owner_id == attempt)
    {
        let owner_tx = JournalTransaction::new(*transaction.id(), owners)?;
        let (derived, _, old) = continuation(state, &owner_tx, attempt, limits)?;
        if derived != *transaction {
            return Err(invalid());
        }
        return Ok(Some(old));
    }
    let floor = transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
        .map(OriginalRootCapacityRecordV5::from_journal_record)
        .collect::<Result<Vec<_>, _>>()?;
    let [floor] = floor.as_slice() else {
        return Err(invalid());
    };
    if floor.request().owner_id != attempt {
        return Err(invalid());
    }
    let sidecar_key = native_root_sidecar_key_v2(attempt).map_err(|_| invalid())?;
    let owners = owners
        .into_iter()
        .filter(|record| record.key() != sidecar_key)
        .collect();
    let owner_tx = JournalTransaction::new(*transaction.id(), owners)?;
    let (derived, _) = admission(state, &owner_tx, floor.original_prepared().clone(), limits)?;
    if derived != *transaction {
        return Err(invalid());
    }
    Ok(None)
}

pub(super) fn validate_replayed_transaction(
    state: &State,
    transaction: &JournalTransaction,
    limits: JournalLimits,
    successor_sequence: u64,
) -> Result<bool, JournalError> {
    if let Some(floor) = transaction.records().iter().find(|record| {
        record.namespace() == RecordNamespace::GlobalCapacityReservation
            && record.value().is_some_and(|bytes| bytes.get(8..13) == Some(&[0, 4, 40, 10, 12]))
    }) {
        let floor = OrdinaryCapacityRecordV4::from_journal_record(floor)?;
        let after = graph(&apply(state, &transaction.records().iter()
            .filter(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
            .cloned().collect::<Vec<_>>())?)?;
        let query = after.legacy().provider_attempts.get(&floor.data().owner_id)
            .ok_or_else(invalid)?;
        let row = after.legacy().acquisitions.get(&query.owner.owner_id()).ok_or_else(invalid)?;
        validate_original_release_edge(state, transaction, row.acquire_lineage.root.id, limits)?;
        return Ok(true);
    }
    let mut selected = None;
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        let bytes = record.value().or_else(|| {
            state
                .get(&(record.namespace(), record.key().to_vec()))
                .map(Vec::as_slice)
        });
        let Some(bytes) = bytes else {
            continue;
        };
        // Dispatch the complete canonical family, not version5 alone. Future
        // distinct namespace/purpose tuples must have their own strict codec.
        let floor = match CanonicalCapacityFamily::decode(record.key(), bytes)? {
            CanonicalCapacityFamily::OriginalRoot5(floor) => floor,
            // No producer or protected replay edge admits Source5 in this leaf.
            CanonicalCapacityFamily::OriginalSource5(_) => {
                return Err(JournalError::ProtectedBoundary);
            }
            _ => continue,
        };
        let attempt = floor.request().owner_id;
        if selected.is_some_and(|old| old != attempt) {
            return Err(invalid());
        }
        selected = Some(attempt);
    }
    if let Some(attempt) = selected {
        validate_edge(state, transaction, attempt, limits)?;
        pending_v5::validate_pending_sequence(state, transaction, attempt, successor_sequence)?;
        return Ok(true);
    }
    let owns_native_archive = state.keys().any(|(namespace, key)| {
        *namespace == RecordNamespace::MountSourceAcquisition
            && key.starts_with(b"aos.mount.native-held-completion.")
    });
    if owns_native_archive
        && transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
    {
        // Only the already named local2/5 validator may derive an ordinary edge
        // here. Owner-only TXs cannot temporarily corrupt and later restore R.
        let local = transaction.records().iter().any(|record| {
            record.namespace() == RecordNamespace::GlobalCapacityReservation
                && record.value().is_some_and(|bytes| {
                    bytes.get(8..14) == Some(&[0, 4, 40, 10, 2, 1])
                        || bytes.get(8..14) == Some(&[0, 4, 40, 10, 5, 1])
                })
        });
        if !local {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    Ok(false)
}

/// Borrows the same fixed held writer for original Root-only native owner edges.
pub struct MountOriginalNativeJournalAuthorityV5<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
}

/// Retains exact attempted bytes across every preflight/commit/readback error.
#[must_use]
pub struct PreparedOriginalRootAppendV5 {
    transaction: JournalTransaction,
    snapshot: ProtectedJournalSnapshot,
    attempt: [u8; 32],
    digest: [u8; 32],
    floor: Option<OriginalRootCapacityRecordV5>,
    preflight_complete: bool,
    failed: core::cell::Cell<bool>,
    attempted: core::cell::Cell<bool>,
    actual: Option<custody::ActualOriginalRootAppendV5>,
}

/// Binds exact original rows/floor to a physical current writer and sequence.
#[must_use]
pub struct OriginalRootProtectedReadbackV5 {
    snapshot: ProtectedJournalSnapshot,
    graph: RootNativeHeldGraphV2,
    floor: Option<OriginalRootCapacityRecordV5>,
    attempt: [u8; 32],
}

impl<'journal> MountOriginalNativeJournalAuthorityV5<'journal> {
    /// Returns the eight immutable ceilings opened by this SAME held Journal.
    ///
    /// These are configuration DATA, not currentness, residency funding or an
    /// append/signing permit. This projection performs no observation.
    #[must_use]
    pub fn configured_limits(&self) -> JournalLimits {
        self.authority.journal.configured_limits()
    }

    pub(crate) fn claim(journal: &'journal mut Journal) -> Result<Self, JournalError> {
        journal.ensure_protected_authority()?;
        let writer = Self {
            authority: ProtectedJournalAuthority {
                journal,
                namespace: RecordNamespace::MountSourceAcquisition,
                scope: ProtectedAuthorityScope::RootOriginalNativeV5,
            },
        };
        writer.require_current()?;
        writer.authority.validate_root_local_startup_replay_v4()?;
        writer.current_graph()?;
        Ok(writer)
    }

    fn require_current(&self) -> Result<(), JournalError> {
        self.authority.journal.ensure_protected_authority()?;
        self.authority.validate_held_root_owned_at(
            Path::new("/var/lib/aos/sandbox-mount"),
            "mount.journal",
        )?;
        if self.authority.scope != ProtectedAuthorityScope::RootOriginalNativeV5 {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }

    /// Returns the complete checked current native graph without hot authority.
    ///
    /// # Errors
    /// Rejects stale physical names, unknown owner funding or invalid full graphs.
    pub fn current_graph(&self) -> Result<RootNativeHeldGraphV2, JournalError> {
        self.require_current()?;
        require_named_funding(&self.authority.journal.state, self.authority.journal.limits)?;
        pending(&self.authority.journal.state, self.authority.journal.limits)?;
        if self.authority.journal.state.iter().any(|((namespace, _), value)| {
            *namespace == RecordNamespace::GlobalCapacityReservation
                && value.get(8..13) == Some(&[0, 4, 40, 10, 12])
        }) {
            for family in canonical_reservations(&self.authority.journal.state)? {
                if let CanonicalCapacityFamily::Ordinary4(floor) = family {
                    if floor.data().kind == OrdinaryCapacityKindV4::ReleaseRequest
                        && !self.authority.journal.transaction_ids
                            .contains(&floor.data().admission_transaction)
                    {
                        // A compacted scalar floor cannot replace actual original
                        // Release admission provenance on this selected hot route.
                        return Err(JournalError::StaleAuthoritySnapshot);
                    }
                }
            }
        }
        graph(&self.authority.journal.state)
    }

    /// Returns an opaque current snapshot for this named physical scope only.
    ///
    /// # Errors
    /// Rejects unavailable physical currentness or malformed original funding.
    pub fn snapshot(&self) -> Result<ProtectedJournalSnapshot, JournalError> {
        self.current_graph()?;
        self.authority.snapshot()
    }

    /// Checks this named scope's exact physical snapshot without a generic grant.
    ///
    /// # Errors
    /// Rejects a different instance/scope/sequence or changed original state.
    pub fn validate_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.current_graph()?;
        self.authority
            .validate_mount_source_acquisition_snapshot(snapshot)
    }

    /// Rechecks the retained original legacy planning token before first append.
    ///
    /// This narrow handover validates the SAME opaque instance/sequence and
    /// fixed legacy scope. It never relabels or updates a historical token.
    ///
    /// # Errors
    /// Rejects stale or nonfixed planning custody and existing original debt.
    pub fn validate_original_planning_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.current_graph()?;
        if snapshot.scope != ProtectedAuthorityScope::FixedMountSourceAcquisition
            || snapshot.namespace != RecordNamespace::MountSourceAcquisition
            || !std::sync::Arc::ptr_eq(
                &snapshot.instance,
                &self.authority.journal.authority_instance,
            )
            || snapshot.sequence != self.authority.journal.snapshot_sequence()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Borrows one actual current namespace40 value after full native validation.
    ///
    /// # Errors
    /// Rejects unavailable currentness or any malformed retained original floor.
    pub fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, JournalError> {
        self.current_graph()?;
        self.authority.mount_source_acquisition_get(key)
    }

    /// Prepares exact original owner reservation, R/cut and its native7 floor.
    ///
    /// # Errors
    /// Rejects nonoriginal owners, changed cut/witness, fences or all-floor limits.
    pub fn prepare_admission(
        &self,
        owners: &JournalTransaction,
        prepared: PreparedNativeHeldControlV1,
    ) -> Result<PreparedOriginalRootAppendV5, JournalError> {
        let mut retained = None;
        self.prepare_admission_retaining_v5(owners, &prepared, &mut retained)?;
        retained.ok_or_else(invalid)
    }

    /// Reconstructs exact prospective companions for unsigned original DATA.
    ///
    /// This supplies no signing/append grant; original owner validation is
    /// rederived by prepare_admission before the actual coupled commit.
    ///
    /// # Errors
    /// Rejects currentness, owner graph/cut errors or exhausted frame sequence.
    pub fn prospective_original_admission_cut(&self, owners: &JournalTransaction, attempt: [u8; 32])
        -> Result<(RootNativeCutV1, aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::RootNativeReconstructedCutV1, u64), JournalError>
    {
        self.current_graph()?;
        let successor = graph(&apply(&self.authority.journal.state, owners.records())?)?;
        let cut = RootNativeCutV1::capture(
            RootNativeCutKindV1::Admission,
            *owners.id(),
            successor.legacy(),
            attempt,
        )
        .map_err(|_| invalid())?;
        let captured = cut
            .reconstruct(successor.legacy(), attempt)
            .map_err(|_| invalid())?;
        let sequence = self
            .authority
            .journal
            .snapshot_sequence()
            .checked_add(
                u64::try_from(owners.records().len())
                    .map_err(|_| JournalError::SequenceExhausted)?
                    + 4,
            )
            .ok_or(JournalError::SequenceExhausted)?;
        Ok((cut, captured, sequence))
    }

    /// Prepares an exact native-only continuation under the retained originals.
    ///
    /// # Errors
    /// Rejects stutters, foreign owners, missing originals or unchanged limits.
    pub fn prepare_transition(
        &self,
        owners: &JournalTransaction,
        attempt: [u8; 32],
    ) -> Result<PreparedOriginalRootAppendV5, JournalError> {
        let mut retained = None;
        self.prepare_transition_retaining_v5(owners, attempt, &mut retained)?;
        retained.ok_or_else(invalid)
    }

    /// Parks an independently funded Release beside the same phase7 original.
    ///
    /// The returned candidate uses the existing one-shot preflight, commit and
    /// physical capture engine. It never spends or remints the original native
    /// floor and cannot authorize physical release or retirement.
    ///
    /// # Errors
    ///
    /// Retains failed candidate custody for occupied slots, changed originals,
    /// a nonfresh Release, another capacity debt or any opened ceiling failure.
    #[doc(hidden)]
    pub fn prepare_original_release_retaining_v1(
        &self,
        owners: &JournalTransaction,
        root: [u8; 32],
        release: [u8; 32],
        slot: &mut Option<PreparedOriginalRootAppendV5>,
    ) -> Result<(), JournalError> {
        custody::PreparationBoundaryV5::new(slot).run(|slot| {
            if slot.is_some() {
                return Err(invalid());
            }
            *slot = Some(self.initial_candidate_v5(owners, root));
            self.current_graph()?;
            let (transaction, _) = derive_original_release(
                &self.authority.journal.state, owners, root, release,
                self.authority.journal.limits,
            )?;
            let candidate = slot.as_mut().ok_or_else(invalid)?;
            candidate.transaction = transaction;
            self.finish_preparation_v5(candidate)
        })
    }

    /// Parks the exact consumed-Pending owner edge and surviving cleanup floor.
    ///
    /// # Errors
    ///
    /// Retains a failed candidate on stale physical names, non-exact canonical
    /// owners, missing profile3 debt or any whole opened-limit/NEXT refusal.
    #[doc(hidden)]
    pub fn prepare_original_release_status_retaining_v1(
        &self,
        owners: &JournalTransaction,
        root: [u8; 32],
        release: [u8; 32],
        slot: &mut Option<PreparedOriginalRootAppendV5>,
    ) -> Result<(), JournalError> {
        custody::PreparationBoundaryV5::new(slot).run(|slot| {
            if slot.is_some() { return Err(invalid()); }
            *slot = Some(self.initial_candidate_v5(owners, root));
            self.current_graph()?;
            let (transaction, _) = derive_original_release_status(
                &self.authority.journal.state, owners, root, release,
                self.authority.journal.limits,
            )?;
            let candidate = slot.as_mut().ok_or_else(invalid)?;
            candidate.transaction = transaction;
            self.finish_preparation_v5(candidate)
        })
    }

    /// Prepares exact signed Root1 storage before either original carrier send.
    ///
    /// # Errors
    /// Rejects stale physical admission/readback, a different signature input,
    /// already advanced original phase or an unfunded continuation.
    pub fn prepare_root1_store(
        &self,
        admission: &OriginalRootProtectedReadbackV5,
        signed: &SignedNativeHeldControlV1,
    ) -> Result<PreparedOriginalRootAppendV5, JournalError> {
        let mut retained = None;
        self.prepare_root1_store_retaining_v5(admission, signed, &mut retained)?;
        retained.ok_or_else(invalid)
    }

    fn original_root1_store_owners(
        &self,
        admission: &OriginalRootProtectedReadbackV5,
        signed: &SignedNativeHeldControlV1,
    ) -> Result<JournalTransaction, JournalError> {
        self.validate_readback(admission)?;
        let floor = admission.floor.as_ref().ok_or_else(invalid)?;
        let old = admission
            .graph
            .sidecars()
            .get(&admission.attempt)
            .ok_or_else(invalid)?;
        if old.suffix().phase() != 0
            || signed.kind() != NativeHeldControlKindV1::RootPrepared
            || signed.prepared() != floor.original_prepared()
        {
            return Err(invalid());
        }
        let suffix = NativeHeldCompletionSuffixV1::new(
            NativeHeldOwnerV1::Root,
            1,
            old.suffix().flight(),
            None,
            vec![signed.clone()],
        )
        .map_err(|_| invalid())?;
        let sidecar = RootNativeHeldSidecarV2::new(
            *old.original_scope(),
            old.response_transaction(),
            old.disposition().cloned(),
            old.settlement().cloned(),
            old.terminal_verifier().cloned(),
            suffix,
            old.admission_cut().clone(),
            old.disposition_cut().cloned(),
            old.no_interest_terminal().cloned(),
        )
        .map_err(|_| invalid())?;
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.mount.original-root1-store-tx.v5\0");
        digest.update(floor.admission_transaction_id());
        digest.update(signed.to_canonical_bytes());
        let hash: [u8; 32] = digest.finalize().into();
        let mut tx = [0; 16];
        tx.copy_from_slice(&hash[..16]);
        let owners = JournalTransaction::new(
            tx,
            vec![JournalRecord::put(
                RecordNamespace::MountSourceAcquisition,
                native_root_sidecar_key_v2(admission.attempt).map_err(|_| invalid())?,
                sidecar.to_canonical_bytes().map_err(|_| invalid())?,
            )],
        )?;
        Ok(owners)
    }

    fn preflight(
        &self,
        transaction: &JournalTransaction,
        attempt: [u8; 32],
    ) -> Result<(), JournalError> {
        self.authority.journal.preflight_with_cache_gate(
            std::slice::from_ref(transaction),
            None,
            true,
            false,
            None,
            None,
            None,
            Some(RootOwnerEdge::OriginalNative(attempt)),
            CacheMutationGateV1::Ordinary,
        )
    }

    /// Appends and reads back while borrowing, never consuming attempted custody.
    ///
    /// # Errors
    /// Rejects stale preflight/snapshot/bytes. Ambiguous durability or readback
    /// poisons the writer while the caller retains the same prepared container.
    pub fn commit_prepared(
        &mut self,
        prepared: &PreparedOriginalRootAppendV5,
    ) -> Result<OriginalRootProtectedReadbackV5, JournalError> {
        let mut actual = None;
        self.commit_original_input_v5(custody::OriginalAppendInputV5::borrow(prepared), &mut actual)?;
        actual.and_then(|capture| capture.complete).ok_or_else(invalid)
    }

    /// Reconstructs protected metadata for one existing original Root terminal.
    ///
    /// This permits readback after restart without a retained append container.
    /// It requires actual retained admission transaction provenance and either
    /// the current no-interest marker's cleanup transaction or a stored terminal
    /// ACK in the fully validated graph. It provides no original hot flight,
    /// positive FD or time authority, current signer, or new ACK authority.
    ///
    /// # Errors
    /// Rejects an absent or nonterminal original v2 sidecar, a remaining original
    /// floor for the attempt, missing retained transaction provenance, invalid
    /// graph/funding, or unavailable physical currentness. A compacted generation
    /// without the original transaction identities cannot supply this readback.
    pub fn terminal_readback(
        &self,
        attempt: [u8; 32],
    ) -> Result<OriginalRootProtectedReadbackV5, JournalError> {
        let checked = self.current_graph()?;
        let sidecar = checked.sidecars().get(&attempt).ok_or_else(invalid)?;
        if original_root_remaining_v5(&checked, attempt).map_err(|_| invalid())? != 0 {
            return Err(invalid());
        }

        let families = canonical_reservations(&self.authority.journal.state)?;
        if families.iter().any(|family| {
            matches!(family, CanonicalCapacityFamily::OriginalRoot5(floor)
                if floor.request().owner_id == attempt)
        }) {
            return Err(invalid());
        }

        let transactions = &self.authority.journal.transaction_ids;
        if !transactions.contains(&sidecar.admission_cut().capture_transaction()) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        if let Some(marker) = sidecar.no_interest_terminal() {
            if !transactions.contains(&marker.cleanup_transaction()) {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
        } else if !sidecar.suffix().controls().last().is_some_and(|control| {
            matches!(
                control.kind(),
                NativeHeldControlKindV1::RootTerminalRecorded
                    | NativeHeldControlKindV1::RootRecoveryQuery
            )
        }) {
            return Err(invalid());
        }

        let readback = OriginalRootProtectedReadbackV5 {
            snapshot: self.snapshot()?,
            graph: checked,
            floor: None,
            attempt,
        };
        self.validate_readback(&readback)?;
        Ok(readback)
    }

    /// Rechecks exact physical readback at its actual current-use boundary.
    ///
    /// # Errors
    /// Rejects stale readback, changed full graph, missing P/C or substituted floor.
    pub fn validate_readback(
        &self,
        readback: &OriginalRootProtectedReadbackV5,
    ) -> Result<(), JournalError> {
        self.validate_snapshot(&readback.snapshot)?;
        let checked = self.current_graph()?;
        if checked.canonical_records() != readback.graph.canonical_records() {
            return Err(invalid());
        }
        if let Some(floor) = &readback.floor {
            floor.validate_graph(&checked, self.authority.journal.limits)?;
            let record = floor.to_journal_record()?;
            if self.authority.journal.get(record.namespace(), record.key()) != record.value() {
                return Err(invalid());
            }
        } else if original_root_remaining_v5(&checked, readback.attempt).map_err(|_| invalid())?
            != 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Checks historical origin without weakening any current V5 snapshot method.
///
/// # Errors
/// Rejects replaced instances, wrong historical scope/phase, changed original
/// rows or Root5 bytes, and malformed current Query or original metadata.
pub(super) fn require_original_root_closed_origin_v6(
    origin: &OriginalRootProtectedReadbackV5,
    journal: &Journal,
) -> Result<(), JournalError> {
    if !std::sync::Arc::ptr_eq(&origin.snapshot.instance, &journal.authority_instance)
        || origin.snapshot.namespace != RecordNamespace::MountSourceAcquisition
        || origin.snapshot.scope != ProtectedAuthorityScope::RootOriginalNativeV5
        || origin.snapshot.sequence > journal.snapshot_sequence()
    {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    let floor = origin.floor.as_ref().ok_or_else(invalid)?;
    let sidecar = origin.graph.sidecars().get(&origin.attempt).ok_or_else(invalid)?;
    if floor.request().owner_id != origin.attempt
        || floor.request().future_transactions != 2
        || sidecar.suffix().phase() != 11
        || sidecar.suffix().prepared().is_some()
        || sidecar.suffix().control(NativeHeldControlKindV1::RootClosed).is_none()
        || sidecar.suffix().control(NativeHeldControlKindV1::ProviderHeld).is_some()
        || sidecar.suffix().control(NativeHeldControlKindV1::RootAccepted).is_some()
        || sidecar.settlement().is_some()
        || sidecar.terminal_verifier().is_some()
        || sidecar.no_interest_terminal().is_some()
        || !has_original_pending_closed_cut_v5(&origin.graph, sidecar).map_err(|_| invalid())?
        || original_root_remaining_v5(&origin.graph, origin.attempt).map_err(|_| invalid())? != 2
    {
        return Err(invalid());
    }
    floor.validate_graph(&origin.graph, journal.limits)?;
    let current = graph(&journal.state)?;
    pending(&journal.state, journal.limits)?;
    super::root_original_inventory::pending(&journal.state, journal.limits)?;
    floor.validate_graph(&current, journal.limits)?;
    let floor_record = floor.to_journal_record()?;
    let sidecar_key = native_root_sidecar_key_v2(origin.attempt).map_err(|_| invalid())?;
    if journal.get(floor_record.namespace(), floor_record.key()) != floor_record.value()
        || current.canonical_records().get(&sidecar_key)
            != origin.graph.canonical_records().get(&sidecar_key)
    {
        return Err(invalid());
    }

    let cut = sidecar.disposition_cut().ok_or_else(invalid)?;
    let captured = cut.reconstruct(origin.graph.legacy(), origin.attempt)
        .map_err(|_| invalid())?;
    let scope = origin.graph.legacy().provider_attempts.get(&origin.attempt)
        .ok_or_else(invalid)?.scope;
    let head_key = aos_sandbox_protocol::mount_source_acquisition_state::provider_head_key(
        scope.holder_authority_id, scope.provider_authority_id,
    );
    if captured.canonical_records().len() != 4 {
        return Err(invalid());
    }
    for (key, bytes) in captured.canonical_records() {
        if origin.graph.canonical_records().get(key) != Some(bytes)
            || (*key != head_key && current.canonical_records().get(key) != Some(bytes))
        {
            return Err(invalid());
        }
    }
    // Captured H/R/W remain historical. Current H has its independent complete
    // Query graph/rejoin check above, at the named writer's bracketed cut.
    Ok(())
}

impl OriginalRootProtectedReadbackV5 {
    /// Borrows actual checked current records for trusted private installation.
    #[must_use]
    pub const fn graph(&self) -> &RootNativeHeldGraphV2 {
        &self.graph
    }

    /// Borrows retained exact original provenance, never a signing grant.
    #[must_use]
    pub const fn floor(&self) -> Option<&OriginalRootCapacityRecordV5> {
        self.floor.as_ref()
    }

    /// Returns the immutable original Mount attempt identity.
    #[must_use]
    pub const fn attempt(&self) -> [u8; 32] {
        self.attempt
    }

    /// Returns the physical sequence for diagnostic comparison only.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.snapshot.sequence()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_owner_puts_match_only_exact_reducer_changes() {
        let namespace = RecordNamespace::MountSourceAcquisition;
        let owner = JournalRecord::put(namespace, b"owner".to_vec(), b"changed".to_vec());
        let owners = JournalTransaction::new([1; 16], vec![owner.clone()]).unwrap();
        let puts = BTreeMap::from([
            (b"owner".to_vec(), b"changed".to_vec()),
            (b"sidecar".to_vec(), b"generated".to_vec()),
        ]);

        assert!(require_exact_owner_puts(&owners, &puts, Some((b"sidecar", b"generated"))).is_ok());
        let redundant = JournalRecord::put(namespace, b"unchanged".to_vec(), b"same".to_vec());
        let extra = JournalTransaction::new([1; 16], vec![owner.clone(), redundant]).unwrap();
        assert!(require_exact_owner_puts(&extra, &puts, Some((b"sidecar", b"generated"))).is_err());

        let duplicate = JournalTransaction::new([1; 16], vec![owner.clone(), owner]).unwrap();
        let duplicate_puts = BTreeMap::from([(b"owner".to_vec(), b"changed".to_vec())]);
        assert!(require_exact_owner_puts(&duplicate, &duplicate_puts, None).is_err());
    }

    #[test]
    fn continuation_owner_puts_require_exact_namespace_and_put_value() {
        let puts = BTreeMap::from([(b"owner".to_vec(), b"changed".to_vec())]);
        let foreign = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                RecordNamespace::GlobalCapacityReservation,
                b"owner".to_vec(),
                b"changed".to_vec(),
            )],
        )
        .unwrap();
        assert!(require_exact_owner_puts(&foreign, &puts, None).is_err());

        let delete = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::delete(
                RecordNamespace::MountSourceAcquisition,
                b"owner".to_vec(),
            )],
        )
        .unwrap();
        assert!(require_exact_owner_puts(&delete, &puts, None).is_err());
    }
}
