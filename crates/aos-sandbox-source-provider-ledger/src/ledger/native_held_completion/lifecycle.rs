//! Exact retained-held lifecycle comparisons, with explicit unresolved custody.
//!
//! These proposals contain canonical DATA. A future protected producer must
//! independently establish current Release authorization, original native
//! custody closure, free headroom and exact writer/readback before effects.

use std::collections::BTreeSet;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::SourceProviderMethod;
use sha2::{Digest as _, Sha256};

use super::{
    SourceNativeHeldCompletionRecordV1 as Record, corrupt,
    graph::{self, Records},
    transition,
};
use crate::ledger::{
    LedgerFormatErrorV1, completion, format,
    model::*,
    native_completion::{
        self, NativeAcquireCompletionStateV2 as Outer,
        release_fence::{self, NativeReleaseStatusCapacityBindingV1},
    },
};

/// Names an exact pure lifecycle comparison for one retained held lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceNativeHeldLifecycleV1 {
    /// Adds only the original cleanup marker; actual owner custody remains required.
    OriginalCustodyMarked,
    /// Marks an unleased cold terminal original without retiring Storage interest.
    ColdTerminalCleanupMarked,
    /// Reserves a fresh Release through either exact native predecessor shape.
    ReleaseAdmitted,
    /// Completes only descriptor-free Pending or Unavailable Release status.
    ReleaseStatusCompleted,
    /// Applies genuine ordinary signed Release or receipt-only recovery reducers.
    ReleaseCompleted,
    /// Compacts duplicate Released lease fields while retaining full Complete.
    ReleasedArtifactsCompacted,
    /// Advances other current owners while retaining this terminal lineage.
    CurrentOwnersAdvanced,
}

/// Contains an exact lifecycle DATA proposal and its separate capacity joins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceNativeHeldLifecycleTransactionV1 {
    lifecycle: SourceNativeHeldLifecycleV1,
    mutations: Vec<super::SourceNativeHeldMutationV1>,
    status: Option<NativeReleaseStatusCapacityBindingV1>,
    original_custody_required: Option<Vec<u8>>,
}

impl SourceNativeHeldLifecycleTransactionV1 {
    /// Returns the precise compared lifecycle operation.
    #[must_use]
    pub const fn lifecycle(&self) -> SourceNativeHeldLifecycleV1 {
        self.lifecycle
    }

    /// Borrows the actual changed owner PUTs, excluding separately owned floors.
    #[must_use]
    pub fn mutations(&self) -> &[super::SourceNativeHeldMutationV1] {
        &self.mutations
    }

    /// Returns status provenance bound to the actual envelope8 carrier.
    #[must_use]
    pub const fn status_binding(&self) -> Option<&NativeReleaseStatusCapacityBindingV1> {
        self.status.as_ref()
    }

    /// Borrows the original carrier whose actual custody closure is still required.
    ///
    /// Presence describes an unresolved producer prerequisite. This DATA is not
    /// a successful custody check, a live guard or a public guard constructor.
    #[must_use]
    pub fn original_custody_required(&self) -> Option<&[u8]> {
        self.original_custody_required.as_deref()
    }
}

/// Binds retained Release status DATA to its actual held carrier and session history.
///
/// The complete canonical graph and terminal held archive are validated before
/// returning the existing six-field association for Reserved or immutable
/// Pending/Unavailable status. Completed status remains associated after genuine
/// Release and later current-owner advances, without proving an outstanding floor.
///
/// This DATA proves neither current authorization, original custody closure nor
/// committed capacity admission. Those remain protected producer obligations.
///
/// # Errors
///
/// Rejects incomplete, duplicate or noncanonical graphs, nonterminal or legacy
/// carriers, missing or compacted Release associations, foreign session history
/// and outcomes other than Reserved or immutable Pending/Unavailable.
pub fn native_held_release_status_binding_v1<'records>(
    records: impl IntoIterator<Item = (&'records [u8], &'records [u8])>,
    acquisition: ObjectDigest,
) -> Result<NativeReleaseStatusCapacityBindingV1, LedgerFormatErrorV1> {
    let records = graph::collect(records)?;
    graph::validate(&records)?;

    let key = native_completion::native_completion_key_v2(acquisition);
    let bytes = records
        .get(&key)
        .ok_or(corrupt("held status retained carrier"))?;
    let held = Record::from_canonical_bytes(&key, bytes)?;
    graph::TerminalHeldArchive::read(&held)?;
    status_binding(&records, &held)
}

/// Compares complete current graphs for one narrowly named held lifecycle.
///
/// Release admission requires a terminal archive and the full original Complete
/// artifacts. The returned custody requirement must be discharged by the actual
/// original owner; Root ACK, marker DATA and this proposal do not discharge it.
///
/// # Errors
///
/// Rejects missing historical dependencies, unrelated or invented changes,
/// stale current-session pairing and any substituted Release/status/cleanup.
pub fn propose_native_held_lifecycle_v1<'before, 'after>(
    before: impl IntoIterator<Item = (&'before [u8], &'before [u8])>,
    after: impl IntoIterator<Item = (&'after [u8], &'after [u8])>,
    acquisition: ObjectDigest,
    lifecycle: SourceNativeHeldLifecycleV1,
) -> Result<SourceNativeHeldLifecycleTransactionV1, LedgerFormatErrorV1> {
    let before = graph::collect(before)?;
    let after = graph::collect(after)?;
    graph::validate(&before)?;
    graph::validate(&after)?;
    crate::validate_transition_structure(&before, &after)?;

    let key = native_completion::native_completion_key_v2(acquisition);
    let old_bytes = before
        .get(&key)
        .ok_or(corrupt("held lifecycle original carrier"))?;
    let new_bytes = after
        .get(&key)
        .ok_or(corrupt("held lifecycle retained carrier"))?;
    let old = Record::from_canonical_bytes(&key, old_bytes)?;
    let new = Record::from_canonical_bytes(&key, new_bytes)?;
    let rows = graph::Companions::read(&before, &old)?;
    let mut status = None;
    let mut custody = None;
    let mut release_shape = None;

    match lifecycle {
        SourceNativeHeldLifecycleV1::OriginalCustodyMarked => {
            if old.original.state != Outer::Active
                || old.suffix != new.suffix
                || old.original.advance(Outer::CleanupRequired)? != new.original
            {
                return Err(corrupt("held exact custody marker"));
            }
            transition::exact_mutations(&before, &after, &BTreeSet::from([key.clone()]))?;
            custody = Some(old_bytes.clone());
        }
        SourceNativeHeldLifecycleV1::ColdTerminalCleanupMarked => {
            graph::TerminalHeldArchive::read(&old)?;
            if !matches!(old.original.state, Outer::Requested | Outer::Prepared)
                || graph::cold_unleased_original(&old, &rows)?.is_none()
                || old.suffix != new.suffix
                || old.original.advance(Outer::CleanupRequired)? != new.original
            {
                return Err(corrupt("held exact cold terminal cleanup marker"));
            }
            transition::exact_mutations(&before, &after, &BTreeSet::from([key.clone()]))?;
            custody = Some(old_bytes.clone());
        }
        SourceNativeHeldLifecycleV1::ReleaseAdmitted => {
            graph::TerminalHeldArchive::read(&old)?;
            if old.suffix != new.suffix
                || rows.acquisition.state != ProviderAcquisitionStateV1::Active
            {
                return Err(corrupt("held fresh Release terminal predecessor"));
            }
            match old.original.state {
                Outer::Active if old.original.advance(Outer::CleanupRequired)? == new.original => {}
                Outer::CleanupRequired if old_bytes == new_bytes => {}
                _ => return Err(corrupt("held two exact Release predecessor shapes")),
            }
            status = Some(release_fence::validate_release_admission_rows(
                &before,
                &after,
                &new.original,
                new_bytes,
            )?);
            validate_current_release_reservation(
                &before,
                &after,
                &rows,
                status
                    .as_ref()
                    .ok_or(corrupt("held Release status binding"))?,
            )?;
            custody = Some(old_bytes.clone());
        }
        SourceNativeHeldLifecycleV1::ReleaseStatusCompleted
        | SourceNativeHeldLifecycleV1::ReleaseCompleted => {
            graph::TerminalHeldArchive::read(&old)?;
            if old_bytes != new_bytes || old.original.state != Outer::CleanupRequired {
                return Err(corrupt("held Release preserved native carrier"));
            }
            release_shape = Some(completion::validate_native_held_release(
                &before,
                &after,
                if lifecycle == SourceNativeHeldLifecycleV1::ReleaseStatusCompleted {
                    completion::HeldReleaseCompletion::StatusOnly
                } else {
                    completion::HeldReleaseCompletion::Released
                },
                &old,
            )?);
            if lifecycle == SourceNativeHeldLifecycleV1::ReleaseStatusCompleted {
                status = Some(status_binding(&after, &new)?);
            }
        }
        SourceNativeHeldLifecycleV1::ReleasedArtifactsCompacted => {
            graph::TerminalHeldArchive::read(&old)?;
            if old_bytes != new_bytes
                || rows.acquisition.state != ProviderAcquisitionStateV1::Released
            {
                return Err(corrupt("held compaction Released predecessor"));
            }
            let mut expected = before.clone();
            let mut acquisition = rows.acquisition.clone();
            acquisition.revision = increment(acquisition.revision)?;
            acquisition.lease_history.clear();
            acquisition.signed_lease.clear();
            acquisition.reopen_identity = None;
            let bytes = format::encode_acquisition(&acquisition);
            let release_key = format::release_key(&ReleaseKeyV1 {
                provider_id: old.original.provider_id,
                holder_id: old.original.holder_id,
                acquisition_id: acquisition.acquisition_id,
            });
            let DecodedRecordV1::Release(mut release) = format::decode_record(
                &release_key,
                before
                    .get(&release_key)
                    .ok_or(corrupt("held compaction Release"))?,
            )?
            else {
                return Err(corrupt("held compaction Release type"));
            };
            if release.state != ProviderReleaseStateV1::Tombstone {
                return Err(corrupt("held compaction actual Tombstone"));
            }
            release.revision = increment(release.revision)?;
            release.acquisition_record_digest = format::record_digest(&bytes)?;
            expected.insert(rows.keys[2].clone(), bytes);
            expected.insert(release_key, format::encode_release(&release));
            if expected != after {
                return Err(corrupt("held exact Released artifact compaction"));
            }
        }
        SourceNativeHeldLifecycleV1::CurrentOwnersAdvanced => {
            graph::TerminalHeldArchive::read(&old)?;
            if old_bytes != new_bytes || before.get(&rows.keys[2]) != after.get(&rows.keys[2]) {
                return Err(corrupt("held current work rewrote original acquisition"));
            }
        }
    }

    let changed = before
        .keys()
        .chain(after.keys())
        .filter(|key| before.get(*key) != after.get(*key))
        .cloned()
        .collect::<BTreeSet<_>>();
    let maximum = if lifecycle == SourceNativeHeldLifecycleV1::ReleaseAdmitted
        && old.original.state == Outer::Active
    {
        7
    } else {
        6
    };
    if changed.is_empty() || changed.len() > maximum {
        return Err(corrupt("held lifecycle owner bounds"));
    }
    if let Some(shape) = cleanup_key_widths(lifecycle, release_shape)
        && (changed.len() > shape.len() || changed.iter().any(|key| !shape.contains(&key.len())))
    {
        return Err(corrupt("held lifecycle exact reducer family shape"));
    }
    let mutations = transition::exact_mutations(&before, &after, &changed)?;
    Ok(SourceNativeHeldLifecycleTransactionV1 {
        lifecycle,
        mutations,
        status,
        original_custody_required: custody,
    })
}

// These are owner families emitted by the existing lifecycle comparators and
// completion materializers. Independent admission/current-work never consumes
// the Source final slot, even when its row count happens to be small enough.
pub(super) fn cleanup_key_widths(
    lifecycle: SourceNativeHeldLifecycleV1,
    release: Option<completion::HeldReleaseMutationShape>,
) -> Option<&'static [usize]> {
    use SourceNativeHeldLifecycleV1 as Lifecycle;
    match lifecycle {
        Lifecycle::OriginalCustodyMarked | Lifecycle::ColdTerminalCleanupMarked => Some(&[40]),
        Lifecycle::ReleaseStatusCompleted => {
            Some(completion::HeldReleaseMutationShape::StatusOnly.key_widths())
        }
        Lifecycle::ReleaseCompleted => release.map(|shape| shape.key_widths()),
        Lifecycle::ReleasedArtifactsCompacted => Some(&[95, 99]),
        Lifecycle::ReleaseAdmitted | Lifecycle::CurrentOwnersAdvanced => None,
    }
}

fn validate_current_release_reservation(
    before: &Records,
    after: &Records,
    rows: &graph::Companions,
    binding: &NativeReleaseStatusCapacityBindingV1,
) -> Result<(), LedgerFormatErrorV1> {
    let attempt = after
        .iter()
        .find_map(
            |(key, bytes)| match format::decode_record(key, bytes).ok()? {
                DecodedRecordV1::Attempt(attempt)
                    if attempt.attempt_digest == binding.artifact_digest =>
                {
                    Some(attempt)
                }
                _ => None,
            },
        )
        .ok_or(corrupt("held fresh Release Attempt"))?;
    let holder = &rows.holder;
    if holder.pending_attempt_digest.is_some()
        || attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.method != SourceProviderMethod::Release
        || attempt.status.is_some()
        || attempt.revision != 1
        || attempt.session_binding != holder.session_binding
        || attempt.request_sequence != holder.next_request_sequence
        || attempt.provider != rows.authority.provider
        || attempt.holder != holder.holder
        || attempt.root_record_signer != holder.signers[1]
        || attempt.signer_set_commitment != holder.signer_set_commitment
        || attempt.provider_process_instance != holder.provider_process_instance
        || attempt.root_process_instance != holder.root_process_instance
        || attempt.proof_class_capabilities != rows.authority.proof_class_capabilities
        || attempt.supports_recursive != rows.authority.supports_recursive
        || attempt.supports_kernel_coupled != rows.authority.supports_kernel_coupled
        || rows.authority.state == ProviderAuthorityStateV1::Retired
    {
        return Err(corrupt("held independently current Release reservation"));
    }
    let mut expected_holder = holder.clone();
    expected_holder.revision = increment(holder.revision)?;
    expected_holder.next_request_sequence = increment(holder.next_request_sequence)?;
    expected_holder.pending_attempt_digest = Some(attempt.attempt_digest);
    let current_history = format::session_history_key(
        holder.provider.authority_id(),
        holder.holder.authority_id(),
        holder.session_binding,
    );
    if after.get(&rows.keys[3]) != Some(&format::encode_session(&expected_holder))
        || after.get(&current_history) != Some(&format::encode_session_history(&expected_holder))
    {
        return Err(corrupt("held exact current Release Holder/history patch"));
    }
    let mut expected_authority = rows.authority.clone();
    expected_authority.revision = increment(expected_authority.revision)?;
    expected_authority.inventory_generation = increment(expected_authority.inventory_generation)?;
    expected_authority.last_release_generation =
        increment(expected_authority.last_release_generation)?;
    let acquisition_bytes = after
        .get(&rows.keys[2])
        .ok_or(corrupt("held Release acquisition bytes"))?;
    let release_key = format::release_key(&ReleaseKeyV1 {
        provider_id: rows.acquisition.provider.authority_id(),
        holder_id: rows.acquisition.holder.authority_id(),
        acquisition_id: rows.acquisition.acquisition_id,
    });
    let release = ReleaseRecordV1 {
        revision: 1,
        state: ProviderReleaseStateV1::Intent,
        provider: rows.acquisition.provider.clone(),
        holder: rows.acquisition.holder.clone(),
        acquisition_id: rows.acquisition.acquisition_id,
        acquisition_sequence: rows.acquisition.acquisition_sequence,
        lease_id: rows
            .acquisition
            .lease_id
            .ok_or(corrupt("held Release original lease ID"))?,
        lease_digest: rows
            .acquisition
            .lease_digest
            .ok_or(corrupt("held Release original lease digest"))?,
        effect_id: binding.operation_id,
        release_generation: expected_authority.last_release_generation,
        effect_attempt_digest: attempt.attempt_digest,
        attempt_digest: attempt.attempt_digest,
        backend_id: rows.acquisition.backend_id,
        backend_lineage_digest: release_lineage(&rows.acquisition, &attempt, binding.operation_id)?,
        backend_evidence: None,
        release_observation_digest: None,
        released_seconds: None,
        receipt_digest: None,
        signed_receipt: Vec::new(),
        acquisition_record_digest: format::record_digest(acquisition_bytes)?,
    };
    if after.get(&release_key) != Some(&format::encode_release(&release)) {
        return Err(corrupt("held exact ordinary Release Intent"));
    }
    let (digest, count) = crate::ledger::reducer::inventory_state_digest(
        expected_authority.provider.authority_id(),
        expected_authority.catalog_generation,
        expected_authority.catalog_digest,
        after
            .iter()
            .filter(|(_, value)| !graph::is_held(value))
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        crate::limits::MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER,
    )?;
    expected_authority.inventory_state_digest = digest;
    expected_authority.active_lease_count = count;
    if after.get(&rows.keys[0]) != Some(&format::encode_authority(&expected_authority))
        || before.contains_key(&format::attempt_key(&AttemptKeyV1 {
            provider_id: attempt.provider.authority_id(),
            holder_id: attempt.holder.authority_id(),
            root_record_key_id: attempt.root_record_signer.key_id(),
            method: SourceProviderMethod::Release as u8,
            request_id: attempt.request_id,
        }))
    {
        return Err(corrupt("held exact fresh Release authority patch"));
    }
    Ok(())
}

fn status_binding(
    records: &Records,
    held: &Record,
) -> Result<NativeReleaseStatusCapacityBindingV1, LedgerFormatErrorV1> {
    let rows = graph::Companions::read(records, held)?;
    let key = format::release_key(&ReleaseKeyV1 {
        provider_id: held.original.provider_id,
        holder_id: held.original.holder_id,
        acquisition_id: held.original.acquisition_id,
    });
    let DecodedRecordV1::Release(release) = format::decode_record(
        &key,
        records
            .get(&key)
            .ok_or(corrupt("held status retained Release"))?,
    )?
    else {
        return Err(corrupt("held status Release kind"));
    };
    let attempt = records
        .iter()
        .find_map(
            |(key, bytes)| match format::decode_record(key, bytes).ok()? {
                DecodedRecordV1::Attempt(attempt)
                    if attempt.attempt_digest == release.attempt_digest =>
                {
                    Some(attempt)
                }
                _ => None,
            },
        )
        .ok_or(corrupt("held status retained Release Attempt"))?;

    // The current Holder can advance independently of this retained Release.
    // Neither it nor the original Acquire history identifies the Release session.
    let history_key = format::session_history_key(
        attempt.provider.authority_id(),
        attempt.holder.authority_id(),
        attempt.session_binding,
    );
    let DecodedRecordV1::SessionHistory(history) = format::decode_record(
        &history_key,
        records
            .get(&history_key)
            .ok_or(corrupt("held status retained Release history"))?,
    )?
    else {
        return Err(corrupt("held status Release history kind"));
    };
    release_fence::release_status_binding(
        &rows.acquisition,
        &held.original,
        &rows.attempt,
        &release,
        &attempt,
        &history,
        &held.to_canonical_bytes()?,
    )
}

fn release_lineage(
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
    effect: [u8; 16],
) -> Result<ObjectDigest, LedgerFormatErrorV1> {
    Ok(ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.release-lineage.v1\0")
            .chain_update(acquisition.provider.authority_id())
            .chain_update(acquisition.holder.authority_id())
            .chain_update(attempt.session_binding.as_bytes())
            .chain_update(attempt.attempt_digest.as_bytes())
            .chain_update(acquisition.acquisition_id.as_bytes())
            .chain_update(effect)
            .chain_update(
                acquisition
                    .lease_id
                    .ok_or(corrupt("held Release lineage lease ID"))?,
            )
            .chain_update(
                acquisition
                    .lease_digest
                    .ok_or(corrupt("held Release lineage lease digest"))?
                    .as_bytes(),
            )
            .chain_update(acquisition.backend_id)
            .finalize()
            .into(),
    ))
}

fn increment(value: u64) -> Result<u64, LedgerFormatErrorV1> {
    value
        .checked_add(1)
        .ok_or(corrupt("held lifecycle sequence exhausted"))
}
