//! Pure AOSSPL01 state-shape, transition, and inventory validation.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    InventoryLeaseStateV1, SignedSourceExportLeaseV1, SignedSourceReleaseReceiptV1,
    SourceProviderAuthorityV1, SourceProviderInventoryV1, SourceProviderMethod,
    digest_provider_proof, digest_signed_export_lease, digest_signed_release_receipt,
};
use sha2::{Digest as _, Sha256};

use super::LedgerFormatErrorV1;
use super::model::{
    AcquisitionRecordV1, AttemptRecordV1, ProviderAcquisitionStateV1, ProviderAttemptStateV1,
    ProviderReleaseStateV1, ReleaseRecordV1,
};

const INVENTORY_STATE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.inventory-state.v1\0";

/// Returns whether an attempt owns the exact holder lineage it is completing.
///
/// A strict successor holder may touch a predecessor acquisition only through
/// an explicitly retained recovery bridge. Cryptographic ancestry and the
/// predecessor attempt/session joins are validated by the whole graph.
pub(crate) fn attempt_owns_holder_lineage(
    lineage_holder: &SourceProviderAuthorityV1,
    attempt: &AttemptRecordV1,
) -> bool {
    lineage_holder == &attempt.holder
        || (attempt.method == SourceProviderMethod::Release
            && lineage_holder.authority_id() == attempt.holder.authority_id()
            && attempt.holder.authority_generation() > lineage_holder.authority_generation()
            && attempt.holder.authority_digest() != lineage_holder.authority_digest()
            && attempt.recovery_predecessor_attempt_digest.is_some()
            && attempt.recovery_predecessor_session_binding.is_some()
            && attempt.recovery_fence_digest.is_some()
            && (1..=3).contains(&attempt.recovery_fence_class)
            && attempt.recovery_revocation_generation > 0
            && attempt.recovery_revocation_digest.as_bytes() != &[0; 32])
}

/// Validates the exact bidirectional shape of an acquisition and its attempt.
pub fn validate_acquisition_join(
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
) -> Result<(), LedgerFormatErrorV1> {
    let common = acquisition.provider == attempt.provider
        && attempt_owns_holder_lineage(&acquisition.holder, attempt)
        && acquisition.current_attempt_digest == attempt.attempt_digest
        && acquisition.acquisition_id == acquisition.normalized_intent.acquisition_id()
        && acquisition.acquisition_sequence == acquisition.normalized_intent.acquisition_sequence()
        && acquisition.acquisition_sequence == attempt.acquisition_sequence;
    let shaped = match acquisition.state {
        ProviderAcquisitionStateV1::Applying => {
            attempt.state == ProviderAttemptStateV1::Reserved
                && acquisition.effect_attempt_digest == attempt.attempt_digest
                && acquisition.normalized_intent.digest() == attempt.operation_intent_digest
                && attempt.status.is_none()
                && acquisition.lease_id.is_none()
                && acquisition.backend_evidence.is_none()
        }
        ProviderAcquisitionStateV1::Pending => {
            attempt.state == ProviderAttemptStateV1::Completed
                && acquisition.effect_attempt_digest == attempt.attempt_digest
                && acquisition.normalized_intent.digest() == attempt.operation_intent_digest
                && attempt.status
                    == Some(aos_sandbox_source_provider_protocol::SourceProviderStatus::Pending)
                && acquisition.lease_id.is_none()
        }
        ProviderAcquisitionStateV1::Active => {
            attempt.state == ProviderAttemptStateV1::Completed
                && acquisition.normalized_intent.digest() == attempt.operation_intent_digest
                && attempt.status
                    == Some(aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete)
                && acquisition.lease_id.is_some()
                && acquisition.lease_digest.is_some()
                && acquisition.backend_evidence.is_some()
                && acquisition.reopen_identity.is_some()
                && acquisition.source_root.is_some()
                && !acquisition.signed_lease.is_empty()
                && validate_retained_lease(acquisition, attempt).is_ok()
        }
        ProviderAcquisitionStateV1::Releasing | ProviderAcquisitionStateV1::Released => true,
        ProviderAcquisitionStateV1::Faulted => {
            (acquisition.lease_id.is_none()
                && acquisition.lease_digest.is_none()
                && acquisition.signed_lease.is_empty())
                || (acquisition.lease_id.is_some()
                    && acquisition.lease_digest.is_some()
                    && !acquisition.signed_lease.is_empty())
        }
    };
    if common && shaped {
        Ok(())
    } else {
        Err(LedgerFormatErrorV1::Corrupt(
            "acquisition/attempt state shape",
        ))
    }
}

/// Validates one retained signed lease and its complete durable selection lineage.
pub fn validate_retained_lease(
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
) -> Result<(), LedgerFormatErrorV1> {
    let signed_lease = SignedSourceExportLeaseV1::from_canonical_bytes(&acquisition.signed_lease)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("active signed lease"))?;
    let lease = signed_lease.subject();
    let resource = lease.resource();
    let evidence = acquisition
        .backend_evidence
        .as_ref()
        .ok_or(LedgerFormatErrorV1::Corrupt("active backend evidence"))?;
    let reopen = acquisition
        .reopen_identity
        .as_ref()
        .ok_or(LedgerFormatErrorV1::Corrupt("active reopen identity"))?;
    let lease_duration = lease
        .expires_seconds()
        .checked_sub(lease.issued_seconds())
        .and_then(|seconds| u64::try_from(seconds).ok());
    let lineage = acquisition
        .lease_history
        .last()
        .ok_or(LedgerFormatErrorV1::Corrupt("active lease lineage"))?;
    let expected_proof_class = lease.proof().capability_bit().trailing_zeros() as u8 + 1;
    if acquisition.lease_attempt_digest != Some(attempt.attempt_digest)
        || acquisition.lease_issue_generation == 0
        || acquisition.lease_id != Some(lease.lease_id())
        || acquisition.lease_digest != Some(digest_signed_export_lease(&signed_lease))
        || lineage.issue_generation != acquisition.lease_issue_generation
        || lineage.lease_id != lease.lease_id()
        || lineage.lease_digest != digest_signed_export_lease(&signed_lease)
        || lineage.attempt_digest != attempt.attempt_digest
        || lease.request_id() != attempt.request_id
        || lease.request_digest() != attempt.typed_request_digest
        || lease.provider() != &acquisition.provider
        || signed_lease.signer().authority_id() != acquisition.provider.authority_id()
        || signed_lease.signer().authority_generation()
            != acquisition.provider.authority_generation()
        || signed_lease.signer().authority_digest() != acquisition.provider.authority_digest()
        || lease.holder_authority_id() != acquisition.holder.authority_id()
        || lease.holder_generation() != acquisition.holder.authority_generation()
        || lease.holder_authority_digest() != acquisition.holder.authority_digest()
        || lease.binding_digest() != acquisition.normalized_intent.binding_digest()
        || lease.revocation_digest() != acquisition.normalized_intent.holder_revocation_digest()
        || lease_duration.is_none_or(|duration| {
            duration == 0 || duration > acquisition.normalized_intent.requested_lease_seconds()
        })
        || lease.issued_seconds() < attempt.verified_at_seconds
        || lease.issued_seconds() >= attempt.current_valid_until_seconds
        || lease.expires_seconds() > attempt.deadline_seconds
        || lease.expires_seconds() > attempt.current_valid_until_seconds
        || resource.resource_namespace_digest() != acquisition.resource_namespace_digest
        || resource.resource_id() != acquisition.resource_id
        || resource.resource_generation() != acquisition.resource_generation
        || resource.resource_digest() != acquisition.resource_digest
        || resource.catalog_generation() != acquisition.catalog_generation
        || resource.catalog_digest() != acquisition.catalog_digest
        || resource.selection_generation() != acquisition.selection_generation
        || resource.selection_digest() != acquisition.selection_digest
        || acquisition.proof_class != expected_proof_class
        || acquisition.proof_digest != digest_provider_proof(lease.proof())
        || reopen.class() != evidence.class()
        || reopen.backend_id() != acquisition.backend_id
        || reopen.backend_generation() != evidence.backend_generation()
        || reopen.backend_digest() != evidence.backend_digest()
        || reopen.resource_id() != acquisition.resource_id
        || reopen.resource_generation() != acquisition.resource_generation
        || reopen.resource_digest() != acquisition.resource_digest
        || !reopen.matches_proof(lease.proof())
        || evidence.state() != super::evidence::BackendEvidenceStateV1::Acquired
        || acquisition.release_effect_id.is_some()
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "active acquisition artifact lineage",
        ));
    }
    Ok(())
}

/// Validates the exact bidirectional shape of one release lineage.
pub fn validate_release_join(
    acquisition: &AcquisitionRecordV1,
    release: &ReleaseRecordV1,
    attempt: &AttemptRecordV1,
) -> Result<(), LedgerFormatErrorV1> {
    let common = acquisition.provider == release.provider
        && acquisition.holder == release.holder
        && acquisition.acquisition_id == release.acquisition_id
        && acquisition.release_effect_id == Some(release.effect_id)
        && release.attempt_digest == attempt.attempt_digest
        && acquisition.current_attempt_digest == attempt.attempt_digest
        && release.provider == attempt.provider
        && attempt_owns_holder_lineage(&release.holder, attempt)
        && release.acquisition_sequence == acquisition.acquisition_sequence
        && attempt.acquisition_sequence == acquisition.acquisition_sequence;
    let shaped = match release.state {
        ProviderReleaseStateV1::Intent => {
            matches!(
                acquisition.state,
                ProviderAcquisitionStateV1::Releasing | ProviderAcquisitionStateV1::Faulted
            )
                && (attempt.state == ProviderAttemptStateV1::Reserved
                    || (attempt.state == ProviderAttemptStateV1::Completed
                        && matches!(
                            attempt.status,
                            Some(
                                aos_sandbox_source_provider_protocol::SourceProviderStatus::Pending
                                    | aos_sandbox_source_provider_protocol::SourceProviderStatus::Unavailable
                            )
                        )))
                && release.backend_evidence.is_none()
                && release.receipt_digest.is_none()
                && release.signed_receipt.is_empty()
        }
        ProviderReleaseStateV1::Tombstone => {
            acquisition.state == ProviderAcquisitionStateV1::Released
                && attempt.state == ProviderAttemptStateV1::Completed
                && matches!(
                    attempt.status,
                    Some(
                        aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                            | aos_sandbox_source_provider_protocol::SourceProviderStatus::Pending
                            | aos_sandbox_source_provider_protocol::SourceProviderStatus::Unavailable
                    )
                )
                && release.backend_evidence.is_some()
                && release.receipt_digest.is_some()
                && !release.signed_receipt.is_empty()
                && validate_release_tombstone(acquisition, release, attempt).is_ok()
        }
    };
    if common && shaped {
        Ok(())
    } else {
        Err(LedgerFormatErrorV1::Corrupt(
            "release/acquisition/attempt state shape",
        ))
    }
}

fn validate_release_tombstone(
    acquisition: &AcquisitionRecordV1,
    release: &ReleaseRecordV1,
    attempt: &AttemptRecordV1,
) -> Result<(), LedgerFormatErrorV1> {
    let acquired = acquisition
        .backend_evidence
        .as_ref()
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "released acquisition evidence",
        ))?;
    let released = release
        .backend_evidence
        .as_ref()
        .ok_or(LedgerFormatErrorV1::Corrupt("release evidence"))?;
    let signed_receipt =
        SignedSourceReleaseReceiptV1::from_canonical_bytes(&release.signed_receipt)
            .map_err(|_| LedgerFormatErrorV1::Corrupt("signed Release receipt"))?;
    let receipt = signed_receipt.subject();
    if release.backend_id != acquisition.backend_id
        || released.state() != super::evidence::BackendEvidenceStateV1::Released
        || released.class() != acquired.class()
        || released.backend_authority_id() != acquired.backend_authority_id()
        || released.backend_generation() != acquired.backend_generation()
        || released.backend_digest() != acquired.backend_digest()
        || released.predecessor_observation_generation()? != acquired.observation_generation()
        || released.predecessor_observation_digest()? != acquired.observation_digest()
        || release.release_observation_digest != Some(released.observation_digest())
        || release.receipt_digest != Some(digest_signed_release_receipt(&signed_receipt))
        || signed_receipt.signer().authority_id() != release.provider.authority_id()
        || signed_receipt.signer().authority_generation() != release.provider.authority_generation()
        || signed_receipt.signer().authority_digest() != release.provider.authority_digest()
        || receipt.provider() != &release.provider
        || receipt.request_id() != attempt.request_id
        || receipt.request_digest() != attempt.typed_request_digest
        || receipt.lease_id() != release.lease_id
        || receipt.lease_digest() != release.lease_digest
        || receipt.release_generation() != release.release_generation
        || receipt.provider_process_instance() != attempt.provider_process_instance
        || release.released_seconds != Some(receipt.released_seconds())
    {
        return Err(LedgerFormatErrorV1::Corrupt("Release tombstone lineage"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum InventoryStateV1 {
    Active = 1,
    Reaping = 2,
    Released = 3,
}

struct InventoryEntryV1 {
    provider_id: [u8; 16],
    holder_id: [u8; 16],
    lease_id: [u8; 16],
    lease_digest: ObjectDigest,
    acquisition_id: ObjectDigest,
    state: InventoryStateV1,
    resource_namespace_digest: ObjectDigest,
    resource_id: [u8; 32],
    resource_generation: u64,
    resource_digest: ObjectDigest,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    selection_generation: u64,
    selection_digest: ObjectDigest,
    proof_class: u8,
    proof_digest: ObjectDigest,
    resource_commitment: ObjectDigest,
    release_generation: u64,
}

/// Recomputes the stable sorted inventory projection from canonical records.
pub fn inventory_state_digest<'record>(
    provider_id: [u8; 16],
    current_catalog_generation: u64,
    current_catalog_digest: ObjectDigest,
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    maximum_tombstones_per_holder: usize,
) -> Result<(ObjectDigest, u64), LedgerFormatErrorV1> {
    use super::format::decode_record;
    use super::model::DecodedRecordV1;

    let mut acquisitions = BTreeMap::new();
    let mut releases = BTreeMap::new();
    for (key, value) in records {
        match decode_record(key, value)? {
            DecodedRecordV1::Acquisition(value) => {
                acquisitions.insert(
                    (
                        value.provider.authority_id(),
                        value.holder.authority_id(),
                        value.acquisition_id,
                    ),
                    value,
                );
            }
            DecodedRecordV1::Release(value) => {
                releases.insert(
                    (
                        value.provider.authority_id(),
                        value.holder.authority_id(),
                        value.acquisition_id,
                    ),
                    value,
                );
            }
            _ => {}
        }
    }

    let mut newest_released = BTreeMap::<([u8; 16], [u8; 16]), Vec<_>>::new();
    let mut entries = Vec::new();
    for acquisition in acquisitions.values() {
        match acquisition.state {
            ProviderAcquisitionStateV1::Active | ProviderAcquisitionStateV1::Releasing => {
                entries.push(inventory_entry(acquisition, &releases)?);
            }
            ProviderAcquisitionStateV1::Released => {
                newest_released
                    .entry((
                        acquisition.provider.authority_id(),
                        acquisition.holder.authority_id(),
                    ))
                    .or_default()
                    .push(acquisition);
            }
            ProviderAcquisitionStateV1::Applying
            | ProviderAcquisitionStateV1::Pending
            | ProviderAcquisitionStateV1::Faulted => {}
        }
    }
    for tombstones in newest_released.values_mut() {
        tombstones.sort_by_key(|acquisition| {
            std::cmp::Reverse(
                releases
                    .get(&(
                        acquisition.provider.authority_id(),
                        acquisition.holder.authority_id(),
                        acquisition.acquisition_id,
                    ))
                    .map_or(0, |release| release.release_generation),
            )
        });
        for acquisition in tombstones.iter().take(maximum_tombstones_per_holder) {
            entries.push(inventory_entry(acquisition, &releases)?);
        }
    }
    entries.sort_by_key(|entry| entry.lease_id);
    let mut leases = BTreeSet::new();
    let mut acquisition_ids = BTreeSet::new();
    if entries.iter().any(|entry| {
        !leases.insert(entry.lease_id) || !acquisition_ids.insert(entry.acquisition_id)
    }) {
        return Err(LedgerFormatErrorV1::Corrupt("duplicate inventory identity"));
    }

    let mut hasher = Sha256::new();
    hasher.update(INVENTORY_STATE_DOMAIN);
    hasher.update(provider_id);
    hasher.update(current_catalog_generation.to_be_bytes());
    hasher.update(current_catalog_digest.as_bytes());
    hasher.update((entries.len() as u32).to_be_bytes());
    for entry in &entries {
        hasher.update(entry.provider_id);
        hasher.update(entry.holder_id);
        hasher.update(entry.lease_id);
        hasher.update(entry.lease_digest.as_bytes());
        hasher.update(entry.acquisition_id.as_bytes());
        hasher.update([entry.state as u8]);
        hasher.update([0; 7]);
        hasher.update(entry.resource_namespace_digest.as_bytes());
        hasher.update(entry.resource_id);
        hasher.update(entry.resource_generation.to_be_bytes());
        hasher.update(entry.resource_digest.as_bytes());
        hasher.update(entry.catalog_generation.to_be_bytes());
        hasher.update(entry.catalog_digest.as_bytes());
        hasher.update(entry.selection_generation.to_be_bytes());
        hasher.update(entry.selection_digest.as_bytes());
        hasher.update([entry.proof_class]);
        hasher.update([0; 7]);
        hasher.update(entry.proof_digest.as_bytes());
        hasher.update(entry.resource_commitment.as_bytes());
        hasher.update(entry.release_generation.to_be_bytes());
    }
    let active_count = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.state,
                InventoryStateV1::Active | InventoryStateV1::Reaping
            )
        })
        .count() as u64;
    Ok((
        ObjectDigest::from_bytes(hasher.finalize().into()),
        active_count,
    ))
}

/// Validates one holder inventory against the exact canonical graph projection.
pub fn validate_inventory_subject<'record>(
    inventory: &SourceProviderInventoryV1,
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    maximum_tombstones_per_holder: usize,
    maximum_entries: usize,
) -> Result<(), LedgerFormatErrorV1> {
    use super::format::decode_record;
    use super::model::DecodedRecordV1;

    let mut authority = None;
    let mut acquisitions = BTreeMap::new();
    let mut releases = BTreeMap::new();
    for (key, value) in records {
        match decode_record(key, value)? {
            DecodedRecordV1::Authority(value) => authority = Some(value),
            DecodedRecordV1::Acquisition(value) => {
                acquisitions.insert(
                    (
                        value.provider.authority_id(),
                        value.holder.authority_id(),
                        value.acquisition_id,
                    ),
                    value,
                );
            }
            DecodedRecordV1::Release(value) => {
                releases.insert(
                    (
                        value.provider.authority_id(),
                        value.holder.authority_id(),
                        value.acquisition_id,
                    ),
                    value,
                );
            }
            _ => {}
        }
    }
    let authority = authority.ok_or(LedgerFormatErrorV1::Corrupt("Inventory authority"))?;
    if inventory.provider() != &authority.provider
        || inventory.catalog_generation() != authority.catalog_generation
        || inventory.catalog_digest() != authority.catalog_digest
        || inventory.inventory_generation() != authority.inventory_generation
    {
        return Err(LedgerFormatErrorV1::Corrupt("Inventory authority head"));
    }
    let mut newest_released = BTreeMap::<([u8; 16], [u8; 16]), Vec<_>>::new();
    let mut expected = Vec::new();
    for acquisition in acquisitions.values() {
        match acquisition.state {
            ProviderAcquisitionStateV1::Active | ProviderAcquisitionStateV1::Releasing => {
                expected.push(inventory_entry(acquisition, &releases)?);
            }
            ProviderAcquisitionStateV1::Released => newest_released
                .entry((
                    acquisition.provider.authority_id(),
                    acquisition.holder.authority_id(),
                ))
                .or_default()
                .push(acquisition),
            ProviderAcquisitionStateV1::Applying
            | ProviderAcquisitionStateV1::Pending
            | ProviderAcquisitionStateV1::Faulted => {}
        }
    }
    for tombstones in newest_released.values_mut() {
        tombstones.sort_by_key(|acquisition| {
            std::cmp::Reverse(
                releases
                    .get(&(
                        acquisition.provider.authority_id(),
                        acquisition.holder.authority_id(),
                        acquisition.acquisition_id,
                    ))
                    .map_or(0, |release| release.release_generation),
            )
        });
        for acquisition in tombstones.iter().take(maximum_tombstones_per_holder) {
            expected.push(inventory_entry(acquisition, &releases)?);
        }
    }
    expected.retain(|entry| entry.holder_id == inventory.holder_authority_id());
    expected.sort_by_key(|entry| entry.lease_id);
    if expected.len() > maximum_entries || expected.len() != inventory.entries().len() {
        return Err(LedgerFormatErrorV1::Corrupt("Inventory entry count"));
    }
    for (entry, actual) in expected.iter().zip(inventory.entries()) {
        let state = match entry.state {
            InventoryStateV1::Active => InventoryLeaseStateV1::Active,
            InventoryStateV1::Reaping => InventoryLeaseStateV1::Reaping,
            InventoryStateV1::Released => InventoryLeaseStateV1::Released,
        };
        let resource = actual.resource();
        if actual.lease_id() != entry.lease_id
            || actual.lease_digest() != entry.lease_digest
            || actual.acquisition_id() != entry.acquisition_id
            || actual.state() != state
            || resource.resource_namespace_digest() != entry.resource_namespace_digest
            || resource.resource_id() != entry.resource_id
            || resource.resource_generation() != entry.resource_generation
            || resource.resource_digest() != entry.resource_digest
            || resource.catalog_generation() != entry.catalog_generation
            || resource.catalog_digest() != entry.catalog_digest
            || resource.selection_generation() != entry.selection_generation
            || resource.selection_digest() != entry.selection_digest
            || actual.proof_class() != entry.proof_class
            || actual.proof_digest() != entry.proof_digest
            || actual.resource_commitment() != entry.resource_commitment
        {
            return Err(LedgerFormatErrorV1::Corrupt("Inventory entry projection"));
        }
    }
    Ok(())
}

fn inventory_entry(
    acquisition: &AcquisitionRecordV1,
    releases: &BTreeMap<([u8; 16], [u8; 16], ObjectDigest), ReleaseRecordV1>,
) -> Result<InventoryEntryV1, LedgerFormatErrorV1> {
    let lease_id = acquisition
        .lease_id
        .ok_or(LedgerFormatErrorV1::Corrupt("inventoried lease"))?;
    let lease_digest = acquisition
        .lease_digest
        .ok_or(LedgerFormatErrorV1::Corrupt("inventoried lease digest"))?;
    let state = match acquisition.state {
        ProviderAcquisitionStateV1::Active => InventoryStateV1::Active,
        ProviderAcquisitionStateV1::Releasing => InventoryStateV1::Reaping,
        ProviderAcquisitionStateV1::Released => InventoryStateV1::Released,
        _ => return Err(LedgerFormatErrorV1::Corrupt("inventory state")),
    };
    let release_generation = if state == InventoryStateV1::Active {
        0
    } else {
        releases
            .get(&(
                acquisition.provider.authority_id(),
                acquisition.holder.authority_id(),
                acquisition.acquisition_id,
            ))
            .ok_or(LedgerFormatErrorV1::Corrupt("inventory Release"))?
            .release_generation
    };
    Ok(InventoryEntryV1 {
        provider_id: acquisition.provider.authority_id(),
        holder_id: acquisition.holder.authority_id(),
        lease_id,
        lease_digest,
        acquisition_id: acquisition.acquisition_id,
        state,
        resource_namespace_digest: acquisition.resource_namespace_digest,
        resource_id: acquisition.resource_id,
        resource_generation: acquisition.resource_generation,
        resource_digest: acquisition.resource_digest,
        catalog_generation: acquisition.catalog_generation,
        catalog_digest: acquisition.catalog_digest,
        selection_generation: acquisition.selection_generation,
        selection_digest: acquisition.selection_digest,
        proof_class: acquisition.proof_class,
        proof_digest: acquisition.proof_digest,
        resource_commitment: acquisition.resource_commitment,
        release_generation,
    })
}
