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
    let dispatch_id = aos_sandbox_source_provider_ledger::identity::acquire_native_dispatch_id_v2(
        acquisition.normalized_intent.digest(),
        acquisition.catalog_generation,
        acquisition.catalog_digest,
        authorization.attempt_digest,
    );
    if acquisition.state != ProviderAcquisitionStateV1::Applying
        || acquisition.provider != authorization.provider
        || acquisition.holder != authorization.holder
        || acquisition.current_attempt_digest != authorization.attempt_digest
        || acquisition.effect_attempt_digest != authorization.attempt_digest
        || acquisition.normalized_intent.digest() != authorization.operation_intent_digest
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
        || attempt.attempt_digest != authorization.attempt_digest
        || attempt.session_binding != authorization.session_binding
        || attempt.operation_intent_digest != authorization.operation_intent_digest
        || attempt.signed_request != request.signed_root_request().to_canonical_bytes()
        || claims.validity().0 < attempt.verified_at_seconds
        || !selected.is_current(journal)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}
