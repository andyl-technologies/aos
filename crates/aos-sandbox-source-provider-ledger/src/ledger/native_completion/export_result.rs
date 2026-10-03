//! Pure native export-fence result joins over the existing protected graph.
//!
//! The cut commits the unchanged native carrier, exact Release-status binding,
//! reservation admission identity and pre-result sequence. Signature/custody
//! authority remains exclusively with the protected security owner.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    NativeExportFenceAcquireV1, NativeExportFenceCutV1, NativeExportFenceReleaseV1,
    ReleaseSourceResponseProfileV2, SourceProviderNativeExportFenceV1,
};
use sha2::{Digest as _, Sha256};

use crate::ledger::LedgerFormatErrorV1;
use crate::ledger::format::{decode_record, encode_native_completion_v2};
use crate::ledger::model::DecodedRecordV1;

// The fixed 1,488-byte response fits the existing full-size Attempt response
// slot. Status4 already budgets that maximum Attempt plus both session rows;
// neither the original native carrier nor either reservation is enlarged.
const _: () = assert!(
    aos_sandbox_source_provider_protocol::MAXIMUM_NATIVE_RELEASE_RESPONSE_BYTES_V2
        <= crate::limits::MAXIMUM_SIGNED_REQUEST_OR_RESPONSE_BYTES
);

/// Derives exact nonauthorizing claims from the whole caller-validated graph.
///
/// Cut scalars grant no journal authority. The sealed owner independently
/// requires Reserved/Releasing and recovers exact capacity at its snapshot.
///
/// # Errors
///
/// Rejects missing or conflicting native, Release, original Acquire/session,
/// lease, acceptance, descriptor or protected-capacity lineage.
pub fn native_export_fence_subject_v1(
    records: &[(Vec<u8>, Vec<u8>)],
    attempt_digest: ObjectDigest,
    sequence: u64,
    admission_transaction_id: [u8; 16],
    reservation_id: [u8; 32],
) -> Result<SourceProviderNativeExportFenceV1, LedgerFormatErrorV1> {
    let decoded = records
        .iter()
        .map(|(key, value)| decode_record(key, value))
        .collect::<Result<Vec<_>, _>>()?;
    subject_from_decoded(
        &decoded,
        attempt_digest,
        sequence,
        admission_transaction_id,
        reservation_id,
        None,
    )
}

fn subject_from_decoded(
    decoded: &[DecodedRecordV1],
    attempt_digest: ObjectDigest,
    sequence: u64,
    admission_transaction_id: [u8; 16],
    reservation_id: [u8; 32],
    held: Option<&crate::ledger::native_held_completion::SourceNativeHeldCompletionRecordV1>,
) -> Result<SourceProviderNativeExportFenceV1, LedgerFormatErrorV1> {
    let attempt = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::Attempt(value) if value.attempt_digest == attempt_digest => {
                Some(value)
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt("native fence Release attempt"))?;
    let acquisition = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::Acquisition(value)
                if value.current_attempt_digest == attempt_digest =>
            {
                Some(value)
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt("native fence acquisition"))?;
    let native = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::NativeCompletion(value)
                if value.acquisition_id == acquisition.acquisition_id =>
            {
                Some(value)
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "native fence original carrier",
        ))?;
    let original = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::Attempt(value) if value.attempt_digest == native.attempt_digest => {
                Some(value)
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "native fence original Acquire",
        ))?;
    let release = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::Release(value) if value.attempt_digest == attempt_digest => {
                Some(value)
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt("native fence Release intent"))?;
    let session = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::SessionHistory(value)
                if value.session_binding == attempt.session_binding
                    && value.provider == attempt.provider
                    && value.holder == attempt.holder =>
            {
                Some(value)
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "native fence Release session history",
        ))?;
    subject_from_join(
        acquisition,
        native,
        original,
        release,
        attempt,
        session,
        sequence,
        admission_transaction_id,
        reservation_id,
        &match held {
            Some(held) if held.original() == native => held.to_canonical_bytes()?,
            Some(_) => {
                return Err(LedgerFormatErrorV1::Corrupt(
                    "held fence original carrier mismatch",
                ));
            }
            None => encode_native_completion_v2(native),
        },
    )
}

/// Derives claims from exact typed owner rows after the caller validates its graph.
///
/// # Errors
///
/// Rejects any conflicting original Acquire, current Release/session, accepted
/// artifact, lease or protected status-capacity binding. This grants no authority.
pub fn native_export_fence_subject_from_join_v1(
    acquisition: &crate::ledger::model::AcquisitionRecordV1,
    native: &super::NativeAcquireCompletionRecordV2,
    original: &crate::ledger::model::AttemptRecordV1,
    release: &crate::ledger::model::ReleaseRecordV1,
    attempt: &crate::ledger::model::AttemptRecordV1,
    session: &crate::ledger::model::HolderSessionHeadRecordV1,
    sequence: u64,
    admission_transaction_id: [u8; 16],
    reservation_id: [u8; 32],
) -> Result<SourceProviderNativeExportFenceV1, LedgerFormatErrorV1> {
    subject_from_join(
        acquisition,
        native,
        original,
        release,
        attempt,
        session,
        sequence,
        admission_transaction_id,
        reservation_id,
        &encode_native_completion_v2(native),
    )
}

fn subject_from_join(
    acquisition: &crate::ledger::model::AcquisitionRecordV1,
    native: &super::NativeAcquireCompletionRecordV2,
    original: &crate::ledger::model::AttemptRecordV1,
    release: &crate::ledger::model::ReleaseRecordV1,
    attempt: &crate::ledger::model::AttemptRecordV1,
    session: &crate::ledger::model::HolderSessionHeadRecordV1,
    sequence: u64,
    admission_transaction_id: [u8; 16],
    reservation_id: [u8; 32],
    carrier: &[u8],
) -> Result<SourceProviderNativeExportFenceV1, LedgerFormatErrorV1> {
    let binding = super::release_fence::release_status_binding(
        acquisition,
        native,
        original,
        release,
        attempt,
        session,
        carrier,
    )?;
    let accepted = native
        .accepted_reply
        .as_ref()
        .ok_or(LedgerFormatErrorV1::Corrupt("native fence acceptance"))?;
    let acceptance = accepted.acceptance().acceptance().clone();
    if acceptance.digest() != native.acceptance_payload_digest
        || acceptance.issuance_id() != native.issuance_id
        || accepted.acceptance().digest() != native.acceptance_digest
        || accepted.receipt().digest() != native.receipt_digest
        || acceptance.descriptor_commitment() != native.descriptor_commitment
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native fence exact accepted artifacts",
        ));
    }

    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.source-provider.native-export-fence-cut.v1\0");
    hash.update(sequence.to_be_bytes());
    hash.update(admission_transaction_id);
    hash.update(reservation_id);
    hash.update((carrier.len() as u32).to_be_bytes());
    hash.update(carrier);
    hash.update(binding.owner_id);
    hash.update(binding.owner_digest.as_bytes());
    hash.update(binding.operation_id);
    hash.update(binding.artifact_digest.as_bytes());
    hash.update(binding.checkpoint_digest.as_bytes());
    hash.update(binding.chain_head_digest.as_bytes());
    let cut = NativeExportFenceCutV1 {
        sequence,
        admission_transaction_id,
        reservation_id,
        fence_digest: ObjectDigest::from_bytes(hash.finalize().into()),
    };
    SourceProviderNativeExportFenceV1::new(
        NativeExportFenceReleaseV1 {
            provider: attempt.provider.clone(),
            holder: attempt.holder.clone(),
            request_id: attempt.request_id,
            signed_request_digest: attempt.signed_request_digest,
            typed_request_digest: attempt.typed_request_digest,
            attempt_digest: attempt.attempt_digest,
            session_binding: attempt.session_binding,
            request_sequence: attempt.request_sequence,
            response_sequence: attempt
                .response_sequence
                .unwrap_or(session.next_response_sequence),
            provider_process_instance: attempt.provider_process_instance,
        },
        NativeExportFenceAcquireV1 {
            acquisition_id: acquisition.acquisition_id,
            acquisition_sequence: acquisition.acquisition_sequence,
            root_request_digest: native.root_request_digest,
            attempt_digest: native.attempt_digest,
            session_binding: native.session_binding,
            backend_id: acquisition.backend_id,
            lease_id: release.lease_id,
            lease_digest: release.lease_digest,
        },
        native.native_request_digest,
        native.acceptance_digest,
        acceptance,
        cut,
    )
    .map_err(|_| LedgerFormatErrorV1::Corrupt("native fence subject"))
}

/// Checks an immutable completed native result against every retained owner join.
///
/// # Errors
///
/// Rejects a changed native/current Release artifact or a non-fenced graph.
/// Generic V1 responses retain their existing separate validation rules.
pub fn validate_native_export_fence_result_v1(
    records: &[(Vec<u8>, Vec<u8>)],
    attempt_digest: ObjectDigest,
    response: &[u8],
) -> Result<(), LedgerFormatErrorV1> {
    let decoded = records
        .iter()
        .map(|(key, value)| decode_record(key, value))
        .collect::<Result<Vec<_>, _>>()?;
    validate_native_export_fence_result_decoded(&decoded, attempt_digest, response)
}

pub(crate) fn validate_native_export_fence_result_decoded(
    decoded: &[DecodedRecordV1],
    attempt_digest: ObjectDigest,
    response: &[u8],
) -> Result<(), LedgerFormatErrorV1> {
    validate_result(decoded, attempt_digest, response, None)
}

pub(crate) fn validate_native_export_fence_result_current(
    decoded: &[DecodedRecordV1],
    canonical: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    attempt_digest: ObjectDigest,
    response: &[u8],
) -> Result<(), LedgerFormatErrorV1> {
    let held = decoded.iter().find_map(|row| match row {
        DecodedRecordV1::Acquisition(acquisition) if acquisition.current_attempt_digest == attempt_digest => {
            let key = super::native_completion_key_v2(acquisition.acquisition_id);
            canonical.get(&key).filter(|bytes| crate::ledger::native_held_completion::graph::is_held(bytes)).map(|bytes|
                crate::ledger::native_held_completion::SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, bytes))
        }
        _ => None,
    }).transpose()?;
    validate_result(decoded, attempt_digest, response, held.as_ref())
}

fn validate_result(
    decoded: &[DecodedRecordV1],
    attempt_digest: ObjectDigest,
    response: &[u8],
    held: Option<&crate::ledger::native_held_completion::SourceNativeHeldCompletionRecordV1>,
) -> Result<(), LedgerFormatErrorV1> {
    let profile = ReleaseSourceResponseProfileV2::from_canonical_bytes(response)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("native fence response profile"))?;
    let Some(fence) = profile.native_fence() else {
        return Ok(());
    };
    let cut = fence.subject().cut();
    let expected = subject_from_decoded(
        decoded,
        attempt_digest,
        cut.sequence,
        cut.admission_transaction_id,
        cut.reservation_id,
        held,
    )?;
    if fence.subject() != &expected {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native fence retained graph mismatch",
        ));
    }
    let session = decoded
        .iter()
        .find_map(|row| match row {
            DecodedRecordV1::SessionHistory(value)
                if value.provider == expected.release().provider
                    && value.holder == expected.release().holder
                    && value.session_binding == expected.release().session_binding =>
            {
                Some(value)
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt("native fence signer history"))?;
    if fence.signer() != &session.signers[3] {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native fence exact historical signer",
        ));
    }
    Ok(())
}
