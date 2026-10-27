//! Same-writer original Root native admission, retained provenance and readback.
//!
//! Only exact rederived namespace40 owner edges plus their namespace46 original
//! floor pass this scope. Physical readback does not establish live Security
//! custody or Mount's actual table installation; those owners must compare the
//! same retained originals before private signing or carrier IO.

use aos_sandbox_protocol::domain_ledger::capacity_family::family::{
    CanonicalCapacityFamily, canonical_reservations,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::OriginalRootCapacityRecordV5;
use aos_sandbox_protocol::domain_ledger::capacity_family::ordinary::{
    OrdinaryCapacityKindV4, OrdinaryCapacityProfileV4, OrdinaryCapacityRecordV4,
};


use std::collections::{BTreeMap, BTreeSet};

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

use super::{JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace, validate_transaction};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

/// Compares saved Pending sequence and original witness fields.
#[doc(hidden)]
pub mod pending_v5;

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
pub fn invalid() -> JournalError {
    JournalError::MalformedRecord("invalid original Root native owner edge")
}

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn graph(state: &State) -> Result<RootNativeHeldGraphV2, JournalError> {
    validate_native_root_graph_v2(state.iter().filter_map(|((namespace, key), value)| {
        (*namespace == RecordNamespace::MountSourceAcquisition)
            .then_some((key.as_slice(), value.as_slice()))
    }))
    .map_err(|_| invalid())
}

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn require_named_funding(state: &State, limits: JournalLimits) -> Result<(), JournalError> {
    // Query coexistence is a complete metadata join, never a generic allowance.
    super::root_original_inventory::pending(state, limits)?;
    let mut families = canonical_reservations(state)?;
    if families.iter().any(is_original_release_floor) {
        validate_original_release_floors(state, &families)?;
        families.retain(|family| !is_original_release_floor(family));
    }
    require_supported_funding_families(&families)
}

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
pub fn is_original_release_floor(family: &CanonicalCapacityFamily) -> bool {
    matches!(family, CanonicalCapacityFamily::Ordinary4(floor)
        if floor.data().kind == OrdinaryCapacityKindV4::ReleaseRequest)
}

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn validate_original_release_floors(
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn original_release_current_puts(
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn derive_original_release(
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn validate_original_release_edge(
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
        .map(|record| {
            OrdinaryCapacityRecordV4::from_journal_record(record).map_err(JournalError::from)
        })
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn derive_original_release_status(
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
#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn require_supported_funding_families(
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
#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn preserve_local_owner(
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn require_funded_original_owner(
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
#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn pending(
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn require_generic_transaction(
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn apply(state: &State, records: &[JournalRecord]) -> Result<State, JournalError> {
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn require_exact_owner_puts(
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn admission(
    state: &State,
    owners: &JournalTransaction,
    prepared: PreparedNativeHeldControlV1,
    limits: JournalLimits,
) -> Result<(JournalTransaction, OriginalRootCapacityRecordV5), JournalError> {
    let (transaction, floor) = derive_admission(state, owners, prepared, limits)?;
    validate_transaction(&transaction, limits)?;
    Ok((transaction, floor))
}

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn derive_admission(
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn continuation(
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn derive_continuation(
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
                    super::digest_bytes(bytes.value().ok_or_else(invalid)?),
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn validate_transfer(
    transaction: &JournalTransaction,
    old: &OriginalRootCapacityRecordV5,
    next: Option<&OriginalRootCapacityRecordV5>,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    super::native_transfer::check_transfer(
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn validate_edge(
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
        .map(|record| {
            OriginalRootCapacityRecordV5::from_journal_record(record).map_err(JournalError::from)
        })
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

#[doc(hidden)]
/// Runs the canonical saved-state comparison without granting a live owner.
///
/// # Errors
/// Returns the original historical DATA classification on an invalid join.
pub fn validate_replayed_transaction(
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
