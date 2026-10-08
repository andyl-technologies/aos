//! Purpose-restricted signing for the same-original V5 native request.
//!
//! The protected Applying readback and genuine Root carrier remain borrowed.
//! Shared reserved-row checks also serve original completion; the retired V2
//! facade no longer provides a parallel signing recipe.

use super::*;

use aos_sandbox_source_provider_ledger::ledger::format::decode_record;
use aos_sandbox_source_provider_ledger::ledger::model::{
    DecodedRecordV1, ProviderAcquisitionStateV1, ProviderAttemptStateV1,
};
use aos_sandbox_source_provider_protocol::{
    SignedStorageNativeAcquireRequestV2, StorageNativeAcquireRequestV2,
};

/// Preserves the physical or Security cause of original native signing failure.
#[derive(thiserror::Error)]
pub enum OriginalNativeSigningErrorV5 {
    /// Retains the actual scoped writer's physical/readback failure.
    #[error("original native signing journal boundary failed")]
    Journal(#[from] aos_sandbox::JournalError),
    /// Retains the actual current custody or signing-purpose failure.
    #[error("original native signing security boundary failed")]
    Security(#[from] SourceProviderSecurityError),
    /// Retains the actual purpose-specific native signing/format failure.
    #[error("original native request signing failed")]
    Native(#[from] aos_sandbox_source_provider_protocol::StorageNativeAcquireErrorV2),
}

impl core::fmt::Debug for OriginalNativeSigningErrorV5 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("OriginalNativeSigningErrorV5([retained cause])")
    }
}

impl CurrentProviderIngressSessionV1 {
    /// Signs only the original V3 request joined to an actual Applying readback.
    ///
    /// The same genuine Root carrier and verified Acquire remain borrowed. The
    /// readback owns the one-shot purpose latch; the caller's resident slot owns
    /// the signature before any postcheck. This method neither sends nor
    /// authenticates a historical graph as a live original.
    ///
    /// # Errors
    ///
    /// Preserves a typed physical, custody or signing failure and closes this Session.
    /// Existing signed custody is never replaced after failure.
    #[doc(hidden)]
    pub fn sign_original_storage_native_request_v5(
        &mut self,
        journal: &aos_sandbox::journal::SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &aos_sandbox::journal::OriginalSourceProtectedReadbackV5,
        root: &super::CurrentRootPreparedCarrierV1,
        acquire: &super::CurrentProviderRequestV1,
        request: &StorageNativeAcquireRequestV2,
        signed: &mut Option<SignedStorageNativeAcquireRequestV2>,
    ) -> Result<(), OriginalNativeSigningErrorV5> {
        let checked = (|| {
            if signed.is_some() {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            }
            self.revalidate_root_prepared_carrier_v1(root)?;
            let now = current_unix_seconds()?;
            let aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(verified)
                = acquire.verified() else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            let original = verified.request();
            let projection = verified.ingress_projection();
            let peer = self.current_projection()?;
            let execution = self.custody.inner().execution().baseline();
            let origin = journal.original_signing_basis_v5(readback, original.acquisition_id())?;
            let provenance = origin.initial_floor().original_provenance().claims();
            let claims = request.claims();
            if original.acquisition_version()
                    != aos_sandbox_source_provider_protocol::ACQUIRE_SOURCE_REQUEST_VERSION_V3
                || original.kernel_coupled()
                || !matches!(verified.sequence(),
                    aos_sandbox_source_provider_protocol::VerifiedProviderRequestSequenceV1::Fresh(_))
                || projection.proof_class_capabilities() & 1 == 0
                || peer.provider() != projection.provider_authority()
                || peer.holder() != projection.root_mount_authority()
                || peer.session_binding() != projection.session_binding()
                || peer.root_process_instance() != projection.root_mount_process_instance()
                || peer.provider_process_instance() != projection.provider_process_instance()
                || acquire.provider_execution_identity() != (execution.pid, execution.start_time_ticks)
                || request.signed_root_request().to_canonical_bytes()
                    != verified.attempt().canonical_signed_request()
                || request.signed_root_request().signer()
                    != self.custody.inner().root_authority().traffic_signer()
                || root.control() != &provenance.root_prepared
                || claims != &provenance.claims
                || now < claims.validity().0
                || now >= claims.validity().1
                || claims.validity().1 > projection.current_valid_until_seconds()
                || claims.validity().1 > original.deadline_seconds()
            {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            }

            let catalog_claims = original.native_catalog()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let mut catalog = None;
            for ((namespace, key), value) in readback.rows() {
                if *namespace == aos_sandbox::RecordNamespace::SourceProviderAuthority
                    && let Ok(DecodedRecordV1::Catalog(value)) = decode_record(key, value)
                {
                    if catalog.replace(value).is_some() {
                        return Err(SourceProviderSecurityError::SessionContinuity.into());
                    }
                }
            }
            let catalog = catalog.ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let configuration = self.revalidated_provider_configuration()?;
            let publication = crate::verify_catalog_publication(
                &configuration, &catalog.canonical_publication,
            )?;
            let current = crate::catalog::current_catalog_projection(&catalog);
            use sha2::Digest as _;
            let publication_digest = aos_sandbox_core::ObjectDigest::from_bytes(
                sha2::Sha256::digest(&catalog.canonical_publication).into(),
            );
            if !crate::catalog::publication_matches_catalog(&publication, &catalog)
                || catalog_claims.head() != current.catalog_head()
                || catalog_claims.floor() != current.floor()
                || catalog_claims.resource_namespace_digest() != current.scope().1
                || catalog_claims.current_head_commitment() != current.head_commitment()
                || catalog_claims.canonical_publication_digest() != publication_digest
                || claims.selection().1 != current.head_commitment()
            {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            }
            let (resource, _) = claims.catalog().select_under_head(
                catalog.catalog_generation,
                catalog.catalog_digest,
                catalog.resource_namespace_digest,
                original.binding_digest(),
            ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            let witness = &provenance.records;
            let decode = |key: &[u8]| {
                readback.rows().get(&(
                    aos_sandbox::RecordNamespace::SourceProviderAuthority, key.to_vec(),
                )).and_then(|bytes| decode_record(key, bytes).ok())
            };
            let Some(DecodedRecordV1::Attempt(attempt)) = decode(witness[0].key()) else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            let Some(DecodedRecordV1::Acquisition(acquisition)) = decode(witness[1].key()) else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            let scope = NativeSigningScope {
                provider: projection.provider_authority(),
                holder: projection.root_mount_authority(),
                attempt: verified.attempt().attempt_digest(),
                session: projection.session_binding(),
                intent: origin.admission_comparison().original().normalized_intent_digest,
            };
            require_native_reserved_rows(&acquisition, &attempt, scope, request, &resource)?;
            journal.claim_original_native_signing_v5(readback, original.acquisition_id())?;

            let inner = self.custody.inner();
            *signed = Some(SignedStorageNativeAcquireRequestV2::sign(
                request.clone(),
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )?);

            journal.original_signing_basis_v5(readback, original.acquisition_id())?;
            self.revalidate_root_prepared_carrier_v1(root)?;
            self.revalidate()?;
            Ok(())
        })();
        if checked.is_err() {
            poison_and_close(
                &mut self.custody, &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            );
        }
        checked
    }
}

/// Borrows the original signer's or completion's authenticated bindings.
pub(super) struct NativeSigningScope<'a> {
    pub(super) provider: &'a aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1,
    pub(super) holder: &'a aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1,
    pub(super) attempt: aos_sandbox_core::ObjectDigest,
    pub(super) session: aos_sandbox_core::ObjectDigest,
    pub(super) intent: aos_sandbox_core::ObjectDigest,
}

pub(super) fn require_native_reserved_rows(
    acquisition: &aos_sandbox_source_provider_ledger::ledger::model::AcquisitionRecordV1,
    attempt: &aos_sandbox_source_provider_ledger::ledger::model::AttemptRecordV1,
    scope: NativeSigningScope<'_>,
    request: &StorageNativeAcquireRequestV2,
    resource: &aos_sandbox_source_provider_protocol::SourceResourceV1,
) -> Result<(), SourceProviderSecurityError> {
    let dispatch_id = aos_sandbox_source_provider_ledger::identity::acquire_native_dispatch_id_v2(
        acquisition.normalized_intent.digest(),
        acquisition.catalog_generation,
        acquisition.catalog_digest,
        scope.attempt,
    );
    if acquisition.state != ProviderAcquisitionStateV1::Applying
        || &acquisition.provider != scope.provider
        || &acquisition.holder != scope.holder
        || acquisition.current_attempt_digest != scope.attempt
        || acquisition.effect_attempt_digest != scope.attempt
        || acquisition.normalized_intent.digest() != scope.intent
        || acquisition.normalized_intent.kernel_coupled()
        || acquisition.backend_id != dispatch_id
        || acquisition.proof_class != 0
        || acquisition.lease_id.is_some()
        || acquisition.backend_evidence.is_some()
        || acquisition.source_root.is_some()
        || acquisition.resource_id != resource.resource_id()
        || acquisition.resource_generation != resource.resource_generation()
        || acquisition.resource_digest != resource.resource_digest()
        || acquisition.catalog_generation != resource.catalog_generation()
        || acquisition.catalog_digest != resource.catalog_digest()
        || acquisition.selection_generation != resource.selection_generation()
        || acquisition.selection_digest != resource.selection_digest()
        || attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.status.is_some()
        || attempt.response_sequence.is_some()
        || attempt.attempt_digest != scope.attempt
        || attempt.session_binding != scope.session
        || attempt.operation_intent_digest != scope.intent
        || attempt.signed_request != request.signed_root_request().to_canonical_bytes()
        || request.claims().validity().0 < attempt.verified_at_seconds
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}
