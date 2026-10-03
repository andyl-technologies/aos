//! Nonterminal native fence joins over existing immutable Release attempts.
//!
//! The signed result lives in the consumed Pending attempt; no new row family
//! or terminal `release_proof` is introduced. Pure validation creates no Root
//! custody/absence authority and never changes Inventory terminal semantics.
//!
//! Root did not retain the original signed native Storage request/receipt or
//! issuance acceptance. Those identities remain Provider-asserted historical
//! lineage. The original signed Provider lease retained the native topology
//! commitment: recomputing it joins the claimed request/receipt/descriptor to
//! original content/counts/authority/cut, not independent Storage currentness.

use super::format::state_error;
use super::model::*;
use super::validation::{exact_attempt, exact_session};
use super::{Result, SourceAcquisitionTableV2};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::native_export_fence::native_dispatch_backend_identity_v2;
use aos_sandbox_source_provider_protocol::{
    SignedSourceExportLeaseV1, SignedSourceProviderNativeExportFenceV1,
    SignedSourceProviderReceiptV1, SignedSourceProviderRequestV1, SourceProviderMethod,
    SourceProviderProofV1, decode_release_request, digest_release_request,
    source_provider_request_attempt_digest_v1,
};

/// Validates native fence lineage without interpreting it as physical Release.
///
/// # Errors
///
/// Rejects changed current Release/request/session, original Acquire/lease/
/// backend, native acceptance/descriptor/topology, or terminal-proof substitution.
pub fn validate_native_export_fence_v1(
    row: &SourceAcquisitionRowV2,
    attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<Option<SignedSourceProviderNativeExportFenceV1>> {
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Pending,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Ok(None);
    };
    if attempt.method != ProviderMethodV2::Release || signed_result.is_empty() {
        return Ok(None);
    }
    let fence = SignedSourceProviderNativeExportFenceV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("native fence Pending result is invalid"))?;
    let current = fence.subject().release();
    let original = fence.subject().acquire();
    let acceptance = fence.subject().acceptance();
    let evidence = row
        .evidence
        .as_ref()
        .ok_or_else(|| state_error("native fence original Acquire evidence absent"))?;
    let acquire = exact_attempt(table, evidence.acquire_attempt)?;
    let original_signed =
        SignedSourceProviderRequestV1::from_canonical_bytes(&acquire.signed_request)
            .map_err(|_| state_error("native fence original signed Acquire invalid"))?;
    let original_attempt = source_provider_request_attempt_digest_v1(
        original_signed.signer(),
        SourceProviderMethod::Acquire,
        acquire.request_id,
    );
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
        .map_err(|_| state_error("native fence signed Release invalid"))?;
    let request = decode_release_request(signed.subject())
        .map_err(|_| state_error("native fence Release subject invalid"))?;
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let normalized = acquire
        .normalized_acquire_intent
        .as_ref()
        .ok_or_else(|| state_error("native fence normalized Acquire absent"))?;
    let backend = native_dispatch_backend_identity_v2(
        ObjectDigest::from_bytes(normalized.digest),
        evidence.provider_catalog_generation,
        ObjectDigest::from_bytes(evidence.provider_catalog_digest),
        original_attempt,
    );
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result: original_result,
        ..
    } = &acquire.state
    else {
        return Err(state_error("native fence original Acquire is not Complete"));
    };
    let receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(original_result)
        .map_err(|_| state_error("native fence original receipt invalid"))?;
    let lease =
        SignedSourceExportLeaseV1::from_canonical_bytes(receipt.subject().signed_export_lease())
            .map_err(|_| state_error("native fence original lease invalid"))?;
    let SourceProviderProofV1::ZfsHeldSnapshot { proof, topology } = lease.subject().proof() else {
        return Err(state_error("native fence original lease is not native ZFS"));
    };
    aos_sandbox_source_provider_protocol::validate_storage_native_topology_commitments_v1(
        topology,
        fence.subject().native_request_digest(),
        acceptance.receipt_digest(),
        acceptance.descriptor_commitment(),
        proof.read_only_content_digest(),
    )
    .map_err(|_| state_error("native fence original topology crosslink mismatch"))?;
    if acceptance.topology() != topology
        || current.provider.authority_id() != session.scope.provider_authority_id
        || current.provider.authority_generation() != session.provider_authority_generation
        || current.provider.authority_digest().as_bytes() != &session.provider_authority_digest
        || current.holder.authority_id() != session.scope.holder_authority_id
        || current.holder.authority_generation() != session.root_mount_authority_generation
        || current.holder.authority_digest().as_bytes() != &session.root_mount_authority_digest
        || current.request_id != attempt.request_id
        || current.signed_request_digest.as_bytes() != &attempt.signed_request_digest
        || current.typed_request_digest != digest_release_request(&request)
        || current.attempt_digest
            != source_provider_request_attempt_digest_v1(
                signed.signer(),
                SourceProviderMethod::Release,
                attempt.request_id,
            )
        || current.session_binding.as_bytes() != &session.session_binding
        || current.request_sequence != attempt.request_sequence
        || current.response_sequence != attempt.request_sequence
        || current.provider_process_instance != session.provider_process_instance
        || original.acquisition_id.as_bytes() != &row.provider_acquisition.acquisition_id
        || original.acquisition_sequence != row.provider_acquisition.acquisition_sequence
        || original.root_request_digest.as_bytes() != &acquire.signed_request_digest
        || original.attempt_digest != original_attempt
        || original.session_binding
            != aos_sandbox_source_provider_protocol::decode_acquire_request(
                original_signed.subject(),
            )
            .map_err(|_| state_error("native fence original subject invalid"))?
            .session_binding()
        || original.backend_id != backend
        || original.lease_id != evidence.lease_id
        || original.lease_digest.as_bytes() != &evidence.signed_lease_digest
        || acceptance.descriptor().kernel_boot_id() != evidence.source_kernel_boot_id
        || acceptance.descriptor().device() != evidence.source_device
        || acceptance.descriptor().inode() != evidence.source_inode
        || acceptance.descriptor().unique_mount_id() != evidence.source_unique_mount_id
        || acceptance.descriptor_commitment().as_bytes() != &evidence.descriptor_commitment
        || request.acquisition_id() != original.acquisition_id
        || request.lease_id() != original.lease_id
        || request.lease_digest() != original.lease_digest
        || row.release_lineage.as_ref().is_none_or(|lineage| {
            lineage.tail.id != attempt.attempt_id
                || lineage.tail.record_digest != attempt.record_digest
                || lineage.tail.revision != attempt.revision
        })
        || row.release_proof.is_some()
        || row.negative_custody_digest.is_some()
        || (row.phase != SourceAcquisitionPhaseV2::Releasing
            && !(row.phase == SourceAcquisitionPhaseV2::Faulted
                && row.faulted_from == Some(SourceAcquisitionPhaseV2::Releasing)))
    {
        return Err(state_error("native export-fence graph mismatch"));
    }
    Ok(Some(fence))
}
