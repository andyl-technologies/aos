//! Actual held-profile completion and retained original artifact comparisons.
//!
//! These private adapters reuse the common completion materializers and artifact
//! joins. They compare full canonical graphs and confer no live custody.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedSourceExportLeaseV1, SignedSourceReleaseReceiptV1, SourceProviderMethod,
    SourceProviderStatus, decode_acquire_response, digest_signed_export_lease,
    provider_resource_commitment_v1, provider_response_artifact_digest_v1,
};

use crate::ledger::{
    LedgerFormatErrorV1,
    format::{acquisition_key, decode_record},
    model::{
        AcquisitionKeyV1, AcquisitionRecordV1, AttemptRecordV1, DecodedRecordV1, LeaseLineageV1,
        ProviderAcquisitionStateV1, ProviderAttemptStateV1, ReleaseKeyV1,
    },
    native_completion::{NativeAcquireCompletionRecordV2, NativeAcquireCompletionStateV2},
    reopen::ReopenIdentityV1,
};

use super::{
    AcquireCompletionPatchV1, AcquireCompletionPlanV1, FinalizedCompletionV1,
    ReleaseCompletionPatchV1, ReleaseCompletionPlanV1, ReleaseRecoveryCompletionPlanV1,
    ReleaseStatusCompletionPlanV1, decode_attempt_from, materialize_release_recovery,
    materialize_response_completion, response_acquire_receipt, validate_acquire_artifact_join,
};

// Replays the same pure six-row reducers against exact proposed artifacts. This
// comparison path returns no sealed outcome, signature or live commit permit.
pub(crate) fn finalize_native_held_complete(
    before: &BTreeMap<Vec<u8>, Vec<u8>>,
    plan: AcquireCompletionPlanV1,
    next: &crate::ledger::native_held_completion::SourceNativeHeldCompletionRecordV1,
    response: Vec<u8>,
    lease: SignedSourceExportLeaseV1,
    completed_at_seconds: i64,
) -> Result<FinalizedCompletionV1, LedgerFormatErrorV1> {
    materialize_response_completion(
        before.clone(),
        plan.0,
        response,
        Some(lease),
        completed_at_seconds,
        Some(next),
    )
}

pub(crate) fn validate_native_held_complete(
    before: &BTreeMap<Vec<u8>, Vec<u8>>,
    after: &BTreeMap<Vec<u8>, Vec<u8>>,
    keys: &[Vec<u8>; 6],
) -> Result<(), LedgerFormatErrorV1> {
    let attempt = decode_attempt_from(after, &keys[1])?;
    let DecodedRecordV1::Acquisition(acquisition) = decode_record(
        &keys[2],
        after
            .get(&keys[2])
            .ok_or(LedgerFormatErrorV1::Corrupt("held Complete acquisition"))?,
    )?
    else {
        return Err(LedgerFormatErrorV1::Corrupt(
            "held Complete acquisition kind",
        ));
    };
    let held =
        crate::ledger::native_held_completion::SourceNativeHeldCompletionRecordV1::from_canonical_bytes(
            &keys[5],
            after
                .get(&keys[5])
                .ok_or(LedgerFormatErrorV1::Corrupt("held Complete native"))?,
        )?;
    let native = held.original().clone();
    let lease = SignedSourceExportLeaseV1::from_canonical_bytes(&acquisition.signed_lease)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("held Complete lease"))?;
    let patch = AcquireCompletionPatchV1::new(
        keys[2].clone(),
        attempt.attempt_digest,
        acquisition.lease_issue_generation,
        acquisition.proof_digest,
        acquisition.resource_commitment,
        acquisition
            .backend_evidence
            .as_ref()
            .map(|value| value.encode()),
        acquisition
            .reopen_identity
            .as_ref()
            .map(|value| value.encode().to_vec()),
        native.original_root,
    )?;
    let plan = AcquireCompletionPlanV1::new(
        keys[1].clone(),
        patch,
        crate::limits::MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER,
    )?
    .with_native_completion(native)?;
    let finalized = finalize_native_held_complete(
        before,
        plan,
        &held,
        attempt.completed_response.clone(),
        lease,
        attempt
            .completed_at_seconds
            .ok_or(LedgerFormatErrorV1::Corrupt("held Complete time"))?,
    )?;
    let mut expected = before.clone();
    for (key, value) in finalized.mutations {
        let value = value.ok_or(LedgerFormatErrorV1::Corrupt("held Complete deleted row"))?;
        expected.insert(key, value);
    }
    if expected != *after {
        return Err(LedgerFormatErrorV1::Corrupt(
            "held Complete exact reducer bytes",
        ));
    }
    Ok(())
}

/// Selects the exact private reducer comparison, not a validation exemption.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum HeldReleaseCompletion {
    StatusOnly,
    Released,
}

/// Shares the materializer's actual cleanup families with bounded projections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeldReleaseMutationShape {
    StatusOnly,
    OrdinaryComplete,
    ReceiptOnlyRecovery,
}

impl HeldReleaseMutationShape {
    pub(crate) const fn key_widths(self) -> &'static [usize] {
        match self {
            Self::StatusOnly => &[63, 96, 103],
            Self::OrdinaryComplete => &[49, 63, 95, 96, 99, 103],
            Self::ReceiptOnlyRecovery => &[49, 95, 99],
        }
    }
}

fn held_release_mutation_shape(
    completion: HeldReleaseCompletion,
    attempt_unchanged: bool,
) -> HeldReleaseMutationShape {
    if completion == HeldReleaseCompletion::StatusOnly {
        HeldReleaseMutationShape::StatusOnly
    } else if attempt_unchanged {
        HeldReleaseMutationShape::ReceiptOnlyRecovery
    } else {
        HeldReleaseMutationShape::OrdinaryComplete
    }
}

pub(crate) fn validate_native_held_release(
    before: &BTreeMap<Vec<u8>, Vec<u8>>,
    after: &BTreeMap<Vec<u8>, Vec<u8>>,
    completion: HeldReleaseCompletion,
    held: &crate::ledger::native_held_completion::SourceNativeHeldCompletionRecordV1,
) -> Result<HeldReleaseMutationShape, LedgerFormatErrorV1> {
    let native = held.original();
    let release_key = crate::ledger::format::release_key(&ReleaseKeyV1 {
        provider_id: native.provider_id,
        holder_id: native.holder_id,
        acquisition_id: native.acquisition_id,
    });
    let DecodedRecordV1::Release(release) = decode_record(
        &release_key,
        after.get(&release_key).ok_or(LedgerFormatErrorV1::Corrupt(
            "held Release completion intent",
        ))?,
    )?
    else {
        return Err(LedgerFormatErrorV1::Corrupt("held Release completion kind"));
    };
    let (attempt_key, attempt) = after
        .iter()
        .find_map(|(key, bytes)| match decode_record(key, bytes).ok()? {
            DecodedRecordV1::Attempt(attempt)
                if attempt.attempt_digest == release.attempt_digest =>
            {
                Some((key.clone(), attempt))
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "held Release completion Attempt",
        ))?;
    let shape = held_release_mutation_shape(
        completion,
        before.get(&attempt_key) == after.get(&attempt_key),
    );
    let finalized = if shape == HeldReleaseMutationShape::StatusOnly {
        if !crate::ledger::native_completion::release_fence::native_release_status_is_completed_v1(
            &attempt,
        ) {
            return Err(LedgerFormatErrorV1::Corrupt(
                "held Release Pending/Unavailable only",
            ));
        }
        materialize_response_completion(
            before.clone(),
            ReleaseStatusCompletionPlanV1::new(attempt_key)?.0,
            attempt.completed_response.clone(),
            None,
            attempt
                .completed_at_seconds
                .ok_or(LedgerFormatErrorV1::Corrupt("held Release status time"))?,
            None,
        )?
    } else {
        let patch = ReleaseCompletionPatchV1::new(
            release_key,
            release
                .backend_evidence
                .as_ref()
                .ok_or(LedgerFormatErrorV1::Corrupt(
                    "held actual Released evidence",
                ))?
                .encode(),
            release
                .release_observation_digest
                .ok_or(LedgerFormatErrorV1::Corrupt("held Released observation"))?,
            release
                .released_seconds
                .ok_or(LedgerFormatErrorV1::Corrupt("held Released time"))?,
        )?;
        if shape == HeldReleaseMutationShape::ReceiptOnlyRecovery {
            let signed_receipt =
                SignedSourceReleaseReceiptV1::from_canonical_bytes(&release.signed_receipt)
                    .map_err(|_| LedgerFormatErrorV1::Corrupt("held Release recovery receipt"))?;
            materialize_release_recovery(
                before.clone(),
                ReleaseRecoveryCompletionPlanV1::new(
                    patch,
                    crate::limits::MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER,
                )?
                .0,
                signed_receipt,
            )?
        } else {
            if attempt.status != Some(SourceProviderStatus::Complete) {
                return Err(LedgerFormatErrorV1::Corrupt(
                    "held ordinary Released Complete",
                ));
            }
            materialize_response_completion(
                before.clone(),
                ReleaseCompletionPlanV1::new(
                    attempt_key,
                    patch,
                    crate::limits::MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER,
                )?
                .0,
                attempt.completed_response.clone(),
                None,
                attempt
                    .completed_at_seconds
                    .ok_or(LedgerFormatErrorV1::Corrupt("held Release Complete time"))?,
                None,
            )?
        }
    };
    let mut expected = before.clone();
    for (key, value) in finalized.mutations {
        expected.insert(
            key,
            value.ok_or(LedgerFormatErrorV1::Corrupt("held Release deleted owner"))?,
        );
    }
    if expected != *after {
        return Err(LedgerFormatErrorV1::Corrupt(
            "held exact Release reducer bytes",
        ));
    }
    Ok(shape)
}

// Derives historical Complete evidence from the retained full signed artifacts.
// Restored duplicate lease/reopen DATA never becomes an Applying before image,
// a live observation, or a new permission to Complete or export.
pub(crate) fn original_native_complete_artifact(
    native: &NativeAcquireCompletionRecordV2,
    attempt: &AttemptRecordV1,
    acquisition: &AcquisitionRecordV1,
) -> Result<ObjectDigest, LedgerFormatErrorV1> {
    if matches!(
        attempt.state,
        ProviderAttemptStateV1::Reserved | ProviderAttemptStateV1::Retired
    ) && attempt.status.is_none()
        && attempt.completed_response.is_empty()
        && matches!(
            native.state,
            NativeAcquireCompletionStateV2::Requested | NativeAcquireCompletionStateV2::Prepared
        )
    {
        return Ok(ObjectDigest::from_bytes([0; 32]));
    }
    if attempt.state != ProviderAttemptStateV1::Completed
        || attempt.method != SourceProviderMethod::Acquire
        || attempt.status != Some(SourceProviderStatus::Complete)
        || !matches!(
            native.state,
            NativeAcquireCompletionStateV2::Active
                | NativeAcquireCompletionStateV2::CleanupRequired
        )
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "held genuine original Complete",
        ));
    }
    crate::ledger::artifact::validate_completed_response(attempt)?;
    let receipt = response_acquire_receipt(&attempt.completed_response)?;
    let lease =
        SignedSourceExportLeaseV1::from_canonical_bytes(receipt.subject().signed_export_lease())
            .map_err(|_| LedgerFormatErrorV1::Corrupt("held original Complete signed lease"))?;
    let patch = AcquireCompletionPatchV1::new(
        acquisition_key(&AcquisitionKeyV1 {
            provider_id: native.provider_id,
            holder_id: native.holder_id,
            acquisition_id: native.acquisition_id,
        }),
        attempt.attempt_digest,
        acquisition.lease_issue_generation,
        acquisition.proof_digest,
        acquisition.resource_commitment,
        None,
        None,
        native.original_root,
    )?;
    validate_acquire_artifact_join(acquisition, &patch, attempt, &lease, &receipt)?;
    let response = decode_acquire_response(&attempt.completed_response)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("held original Complete response"))?;
    let reply = native
        .accepted_reply
        .as_ref()
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "held original Complete acceptance",
        ))?;
    let aos_sandbox_source_provider_protocol::SourceProviderProofV1::ZfsHeldSnapshot {
        proof,
        topology,
    } = lease.subject().proof()
    else {
        return Err(LedgerFormatErrorV1::Corrupt(
            "held original Complete proof class",
        ));
    };
    if proof != reply.receipt().receipt().snapshot()
        || topology != reply.acceptance().acceptance().topology()
        || lease.subject().resource() != reply.receipt().receipt().resource()
        || acquisition.resource_commitment
            != provider_resource_commitment_v1(lease.subject().resource(), acquisition.proof_digest)
        || attempt.descriptor_commitment != native.descriptor_commitment
        || response.signed_status().subject().descriptor_commitment()
            != native.descriptor_commitment
        || acquisition.source_root != Some(native.original_root)
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "held full original Complete proof/descriptor",
        ));
    }
    let compacted = acquisition.signed_lease.is_empty();
    let mut artifacts = acquisition.clone();
    if compacted {
        if acquisition.state != ProviderAcquisitionStateV1::Released
            || !acquisition.lease_history.is_empty()
            || acquisition.reopen_identity.is_some()
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "held original Complete compaction shape",
            ));
        }
        let evidence =
            acquisition
                .backend_evidence
                .as_ref()
                .ok_or(LedgerFormatErrorV1::Corrupt(
                    "held original Complete backend evidence",
                ))?;
        artifacts.signed_lease = lease.to_canonical_bytes();
        artifacts.lease_history = vec![LeaseLineageV1 {
            issue_generation: acquisition.lease_issue_generation,
            lease_id: lease.subject().lease_id(),
            lease_digest: digest_signed_export_lease(&lease),
            attempt_digest: attempt.attempt_digest,
        }];
        artifacts.reopen_identity = Some(ReopenIdentityV1::new(
            evidence.class(),
            acquisition.backend_id,
            evidence.backend_generation(),
            evidence.backend_digest(),
            acquisition.resource_id,
            acquisition.resource_generation,
            acquisition.resource_digest,
            proof.storage_handle(),
            proof.storage_version(),
            proof.active_hold_digest(),
        )?);
    } else if acquisition.signed_lease != lease.to_canonical_bytes() {
        return Err(LedgerFormatErrorV1::Corrupt(
            "held original Complete lease substitution",
        ));
    }
    crate::ledger::reducer::validate_retained_lease_artifacts(&artifacts, attempt)?;
    Ok(provider_response_artifact_digest_v1(
        attempt.method,
        &attempt.completed_response,
    ))
}
