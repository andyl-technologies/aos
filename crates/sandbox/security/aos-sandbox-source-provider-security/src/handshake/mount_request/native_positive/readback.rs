//! Root comparison of the genuine readonly Source selected/deployment files.
//!
//! The existing Archive5 engine owns both fixed files, bounded preimages and
//! native failures. Source signatures delegate their assertions; these reads
//! do not reproduce Source admission, its Applying transaction or its floor.

use aos_sandbox_source_provider_protocol::{
    StorageNativeAcquireReplyV3,
    native_held_completion::witness::ProviderNativeHeldWitnessV1,
    storage_zfs_hold_receipt::{
        STORAGE_ZFS_HOLD_ENROLLMENT_BYTES_V1, decode_storage_zfs_hold_enrollment_v1,
    },
};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::configuration::original_archive::FixedSourcePublicArchiveReadbackV1;

pub(super) fn capture(
    archive: &mut FixedSourcePublicArchiveReadbackV1,
    witness: &ProviderNativeHeldWitnessV1,
) -> Result<(), SourceProviderSecurityError> {
    archive.open_fixed()
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    archive.read_selected(witness.selected_manifest)
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    let (deployment, _, _, _, _) = archive.selected_references()
        .ok_or(SourceProviderSecurityError::Currentness)?;
    archive.read_deployment(deployment)
        .map_err(|_| SourceProviderSecurityError::Currentness)
}

// Each argument is the actual retained original, not a reconstructed authority
// envelope. The comparison intentionally exposes no file/opener selector.
#[allow(clippy::too_many_arguments)]
pub(super) fn compare(
    archive: &mut FixedSourcePublicArchiveReadbackV1,
    authorization: &AuthorizedMountProviderOutcomeV2,
    original: &native_catalog::NativeAcquireOutcomeCustodyV3,
    held: &SignedNativeHeldControlV1,
    storage: &SignedNativeHeldControlV1,
    reply: &StorageNativeAcquireReplyV3,
    root1: &SignedNativeHeldControlV1,
    witness: &ProviderNativeHeldWitnessV1,
    trust: &aos_sandbox_source_provider_protocol::SourceProviderTrustSetV1,
) -> Result<(), SourceProviderSecurityError> {
    archive.revalidate()
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    let (request, publication, catalog, resource, snapshot) = original.original_selection_v5()?;
    let frame = archive.selected_frame()
        .ok_or(SourceProviderSecurityError::Currentness)?;
    let fields = frame.fields();
    let (deployment, configuration, origin, applying, ordered) = archive.selected_references()
        .ok_or(SourceProviderSecurityError::Currentness)?;
    let (archived_configuration, _, projection, archived_publication) = archive.deployment_data()
        .ok_or(SourceProviderSecurityError::Currentness)?;
    let (catalog_bytes, backend, dedicated) = archive.selected_preimages()
        .ok_or(SourceProviderSecurityError::Currentness)?;
    let native = request.native_catalog()
        .ok_or(SourceProviderSecurityError::Currentness)?;

    // Header origin references remain historical claims. Exact file custody
    // and Source's signature are not Root's observation of Source membership.
    // The shared frame codec validates all Source-plan fields structurally;
    // effect/normalized-intent/backend remain Source-local signed assertions,
    // not replacements for Root's independent Mount plan or execution evidence.
    if deployment == ObjectDigest::from_bytes([0; 32])
        || configuration == ObjectDigest::from_bytes([0; 32])
        || origin == ObjectDigest::from_bytes([0; 32])
        || applying == [0; 16]
        || ordered == [0; 32]
        || archived_configuration != configuration
        || frame.digest() != witness.selected_manifest
        || fields.scope != *held.scope()
        || fields.provider_id != authorization.provider.authority_id()
        || fields.holder_id != authorization.holder.authority_id()
        || fields.session_binding != authorization.session_binding
        || fields.attempt_digest != held.scope().provider_attempt
        || Some(fields.acquisition_id) != authorization.acquisition_id
        || fields.root_prepared != root1.digest()
        || fields.publication != witness.publication
        || fields.catalog != catalog.digest()
        || fields.binding != request.binding_digest()
        || fields.backend_enrollment != witness.backend_manifest
        || fields.dedicated_enrollment != witness.verifier_manifest
        || catalog_bytes != catalog.to_canonical_bytes()
        || backend.len() != 928
        || dedicated.len() != STORAGE_ZFS_HOLD_ENROLLMENT_BYTES_V1
        || ObjectDigest::from_bytes(Sha256::digest(backend).into()) != witness.backend_manifest
        || ObjectDigest::from_bytes(Sha256::digest(dedicated).into()) != witness.verifier_manifest
        || witness.authority != authorization.provider
        || witness.native_namespace != native.resource_namespace_digest()
        || (witness.catalog_head.generation, witness.catalog_head.digest) != native.head()
        || (witness.catalog_floor.generation, witness.catalog_floor.digest) != native.floor()
        || witness.head_commitment != native.current_head_commitment()
        || witness.publication != ObjectDigest::from_bytes(
            Sha256::digest(publication.canonical_publication()).into(),
        )
        || archived_publication.canonical_publication() != publication.canonical_publication()
        || projection.provider() != &authorization.provider
        || projection.provider_outcome_signer() != &authorization.provider_outcome_signer
        || reply.receipt().receipt().resource() != resource
        || reply.receipt().receipt().snapshot() != snapshot
        || reply.receipt().receipt().binding_digest() != request.binding_digest()
        || reply.receipt().receipt().attempt().1 != held.scope().provider_attempt
        || reply.acceptance().acceptance().request_digest() != held.scope().original_native_request
    {
        return Err(SourceProviderSecurityError::Currentness);
    }

    // Parse the SAME authenticated enrollment, never a self-pin from a frame.
    // The shared decoder supplies crypto DATA, not rotated-key currentness.
    let dedicated: &[u8; STORAGE_ZFS_HOLD_ENROLLMENT_BYTES_V1] = dedicated.try_into()
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    let verifier = decode_storage_zfs_hold_enrollment_v1(dedicated)
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    let (signer, key) = verifier.projection();
    storage.verify_signature_claim(&NativeHeldSignerV1::Storage(signer), &key)
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    verifier.verify_retained_signature_claim(reply.receipt())
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    reply.acceptance().verify(verifier)
        .map_err(|_| SourceProviderSecurityError::Currentness)?;

    // No independent historical-key rotation proof is reconstructed here.
    // Current issuance eligibility is checked by the genuine Root Session;
    // this archived role must equal that exact admitted Source role.
    let (trust_generation, trust_digest, revocation_generation, revocation_digest) = (
        trust.trust_generation(),
        trust.trust_digest(),
        trust.revocation_generation(),
        trust.revocation_digest(),
    );
    if projection.trust_head() != (trust_generation, trust_digest)
        || projection.revocation_head() != (revocation_generation, revocation_digest)
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    archive.revalidate()
        .map_err(|_| SourceProviderSecurityError::Currentness)
}
