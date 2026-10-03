//! Purpose-restricted Provider signing for an exact protected native reservation.
//!
//! The Provider owner retains the challenge in its separate protected journal.
//! This facade joins the exact request, current catalog, and namespace-41
//! attempt; it cannot create a lease, sign generic backend evidence, or send.

use super::*;

use aos_sandbox_source_provider_ledger::ledger::format::{
    acquisition_key, attempt_key, decode_record,
};
use aos_sandbox_source_provider_ledger::ledger::model::{
    AcquisitionKeyV1, AttemptKeyV1, DecodedRecordV1, ProviderAcquisitionStateV1,
    ProviderAttemptStateV1,
};
use aos_sandbox_source_provider_protocol::{
    SignedStorageNativeAcquireRequestV2, StorageNativeAcquireRequestV2, decode_acquire_request,
    digest_signed_request,
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

impl<'session, 'journal, 'authority, 'authorization>
    ProviderOwnerSecurityFacadeV1<'session, 'journal, 'authority, 'authorization>
{
    /// Signs the original native request under exact current reservation custody.
    ///
    /// The caller must durably retain and read back the returned canonical
    /// bytes before Storage dispatch. Signing is deterministic and restricted
    /// to one purpose per authorization; stale journal snapshots are rejected.
    ///
    /// # Errors
    ///
    /// Closes custody for a changed selected row, request, native identity,
    /// attempt, signer, validity interval, or protected journal snapshot.
    pub fn sign_current_storage_native_request_v2(
        &mut self,
        selected: &crate::ProtectedProviderHeldSnapshotSelectionV1<'_>,
        request: StorageNativeAcquireRequestV2,
    ) -> Result<SignedStorageNativeAcquireRequestV2, SourceProviderSecurityError> {
        self.session.revalidate()?;
        let now = current_unix_seconds().map_err(|error| {
            poison_and_close(&mut self.session.custody, &mut self.session.carrier, error)
        })?;
        let root_signer = self
            .session
            .custody
            .inner()
            .root_authority()
            .traffic_signer();
        if request.signed_root_request().signer() != root_signer
            || validate_native_signing_basis(
                self.journal,
                self.authorization,
                selected,
                &request,
                now,
            )
            .is_err()
        {
            return Err(poison_and_close(
                &mut self.session.custody,
                &mut self.session.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        self.authorization.claim_purpose(1 << 7)?;
        let signed = {
            let inner = self.session.custody.inner();
            SignedStorageNativeAcquireRequestV2::sign(
                request,
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
        }
        .map_err(|_| {
            poison_and_close(
                &mut self.session.custody,
                &mut self.session.carrier,
                SourceProviderSecurityError::SessionContinuity,
            )
        })?;
        self.session.revalidate()?;
        Ok(signed)
    }
}

fn validate_native_signing_basis(
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    authorization: &ProviderOutcomeAuthorizationV1,
    selected: &crate::ProtectedProviderHeldSnapshotSelectionV1<'_>,
    request: &StorageNativeAcquireRequestV2,
    now: i64,
) -> Result<(), SourceProviderSecurityError> {
    validate_authorization_journal(journal, authorization)?;
    let claims = request.claims();
    let root = decode_acquire_request(request.signed_root_request().subject())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let (resource, snapshot) = selected.selected();
    let catalog = claims.catalog();
    let claimed_selection = catalog.select_under_head(
        catalog.generation(),
        catalog.digest(),
        catalog.namespace_digest(),
        root.binding_digest(),
    );
    if authorization.method != SourceProviderMethod::Acquire
        || !selected.is_current(journal)
        || claimed_selection.ok().as_ref() != Some(&(resource.clone(), snapshot.clone()))
        || claims.provider_acquisition()
            != (authorization.provider.authority_id(), root.acquisition_id())
        || claims.holder_session()
            != (
                authorization.holder.authority_id(),
                authorization.session_binding,
            )
        || claims.attempt().1 != authorization.attempt_digest
        || claims.selection()
            != (
                root.binding_digest(),
                selected.publication_head_commitment(),
            )
        || authorization.acquisition_id != Some(root.acquisition_id())
        || digest_signed_request(request.signed_root_request())
            != authorization.signed_request_digest
        || now < claims.validity().0
        || now >= claims.validity().1
        || claims.validity().1 > authorization.current_valid_until_seconds
        || claims.validity().1 > authorization.request_deadline_seconds
        || !authorization_authority_is_current(authorization, now)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }

    let acquisition_key = acquisition_key(&AcquisitionKeyV1 {
        provider_id: authorization.provider.authority_id(),
        holder_id: authorization.holder.authority_id(),
        acquisition_id: root.acquisition_id(),
    });
    let attempt_key = attempt_key(&AttemptKeyV1 {
        provider_id: authorization.provider.authority_id(),
        holder_id: authorization.holder.authority_id(),
        root_record_key_id: request.signed_root_request().signer().key_id(),
        method: SourceProviderMethod::Acquire as u8,
        request_id: authorization.request_id,
    });
    let acquisition = match journal
        .get(&acquisition_key)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        .and_then(|bytes| decode_record(&acquisition_key, bytes).ok())
    {
        Some(DecodedRecordV1::Acquisition(value)) => value,
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let attempt = match journal
        .get(&attempt_key)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        .and_then(|bytes| decode_record(&attempt_key, bytes).ok())
    {
        Some(DecodedRecordV1::Attempt(value)) => value,
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let scope = NativeSigningScope {
        provider: &authorization.provider,
        holder: &authorization.holder,
        attempt: authorization.attempt_digest,
        session: authorization.session_binding,
        intent: authorization.operation_intent_digest,
    };
    require_native_reserved_rows(&acquisition, &attempt, scope, request, &resource)?;
    if !selected.is_current(journal) {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

/// Borrows either closed caller's already authenticated signing bindings.
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
