//! One-shot Provider outcome signing for a selected, effect-free Storage plan.

use super::*;

use aos_sandbox_source_provider_ledger::ledger::format::{
    acquisition_key, attempt_key, decode_record, session_key,
};
use aos_sandbox_source_provider_ledger::ledger::model::{
    AcquisitionKeyV1, AttemptKeyV1, DecodedRecordV1, ProviderAcquisitionStateV1,
    ProviderAttemptStateV1,
};
use aos_sandbox_source_provider_protocol::{decode_acquire_request, digest_signed_request};

impl<'session, 'journal, 'authority, 'authorization>
    ProviderOwnerSecurityFacadeV1<'session, 'journal, 'authority, 'authorization>
{
    /// Signs only the current protected LocalLive row and reserved attempt.
    ///
    /// This grants Storage a verifiable request, not an export, lease, kernel
    /// clone, or RootMount response. A fresh authorization may reproduce the
    /// same deterministic bytes after an exact retry; one authorization cannot
    /// sign competing plans.
    ///
    /// # Errors
    ///
    /// Closes the live session if custody, journal, attempt, selected row,
    /// interval, or one-shot signing purpose has changed.
    pub fn sign_current_storage_export_request(
        &mut self,
        selected: &crate::ProtectedProviderCatalogSelectionV1<'_>,
        request: StorageLiveExportRequestV1,
    ) -> Result<SignedStorageLiveExportRequestV1, SourceProviderSecurityError> {
        self.session.revalidate()?;
        let now_seconds = current_unix_seconds().map_err(|error| {
            poison_and_close(&mut self.session.custody, &mut self.session.carrier, error)
        })?;
        if validate_signed_storage_plan_basis(
            self.journal,
            self.authorization,
            selected,
            &request,
            now_seconds,
        )
        .is_err()
        {
            return Err(poison_and_close(
                &mut self.session.custody,
                &mut self.session.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        self.authorization.claim_purpose(1 << 6)?;
        let signed = {
            let inner = self.session.custody.inner();
            SignedStorageLiveExportRequestV1::sign(
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

impl CurrentProviderIngressSessionV1 {
    /// Re-signs only an unchanged, protected pre-effect Storage plan.
    ///
    /// Ed25519 signing is deterministic. The historical Provider signer,
    /// retained RootMount request, effect ID, row, and interval must all still
    /// be exact, so a retry cannot fork Storage's `(authority, plan_id)` replay
    /// identity. The fresh carrier is authenticated custody, not a new Acquire.
    ///
    /// # Errors
    ///
    /// Closes the session for changed custody, signer, journal reservation,
    /// selected row, request, or validity interval.
    pub fn sign_recovered_storage_export_request(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        selected: &crate::ProtectedProviderCatalogSelectionV1<'_>,
        request: StorageLiveExportRequestV1,
    ) -> Result<SignedStorageLiveExportRequestV1, SourceProviderSecurityError> {
        self.revalidate()?;
        let now_seconds = current_unix_seconds()
            .map_err(|error| poison_and_close(&mut self.custody, &mut self.carrier, error))?;
        if validate_recovered_storage_plan(self, journal, selected, &request, now_seconds).is_err()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let signed = {
            let inner = self.custody.inner();
            SignedStorageLiveExportRequestV1::sign(
                request,
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
        }
        .map_err(|_| {
            poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            )
        })?;
        self.revalidate()?;
        Ok(signed)
    }
}

fn validate_recovered_storage_plan(
    session: &CurrentProviderIngressSessionV1,
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    selected: &crate::ProtectedProviderCatalogSelectionV1<'_>,
    request: &StorageLiveExportRequestV1,
    now_seconds: i64,
) -> Result<(), SourceProviderSecurityError> {
    let inner = session.custody.inner();
    let root_request = decode_acquire_request(request.signed_root_request().subject())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let (resource, selector) = selected.selected();
    if !selected.is_current(journal)
        || request.resource() != resource
        || request.selector() != selector
        || !root_request.kernel_coupled()
        || request.plan_id() != request.effect_id()
        || request.signed_root_request().signer() != inner.root_authority().traffic_signer()
        || now_seconds < request.issued_seconds()
        || now_seconds >= request.expires_seconds()
        || now_seconds >= root_request.deadline_seconds()
        || inner.provider_authority().validate_at(now_seconds).is_err()
        || inner.root_authority().validate_at(now_seconds).is_err()
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let provider = inner.provider_authority().authority();
    let holder = inner.root_authority().authority();
    let acquisition_key = acquisition_key(&AcquisitionKeyV1 {
        provider_id: provider.authority_id(),
        holder_id: holder.authority_id(),
        acquisition_id: root_request.acquisition_id(),
    });
    let acquisition = match journal
        .get(&acquisition_key)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        .and_then(|bytes| decode_record(&acquisition_key, bytes).ok())
    {
        Some(DecodedRecordV1::Acquisition(value)) => value,
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let attempt_key = attempt_key(&AttemptKeyV1 {
        provider_id: provider.authority_id(),
        holder_id: holder.authority_id(),
        root_record_key_id: request.signed_root_request().signer().key_id(),
        method: SourceProviderMethod::Acquire as u8,
        request_id: root_request.request_id(),
    });
    let attempt = match journal
        .get(&attempt_key)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        .and_then(|bytes| decode_record(&attempt_key, bytes).ok())
    {
        Some(DecodedRecordV1::Attempt(value)) => value,
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let holder_key = session_key(provider.authority_id(), holder.authority_id());
    let holder_head = match journal
        .get(&holder_key)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        .and_then(|bytes| decode_record(&holder_key, bytes).ok())
    {
        Some(DecodedRecordV1::Session(value)) => value,
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let lease_end = attempt
        .verified_at_seconds
        .saturating_add(i64::try_from(root_request.requested_lease_seconds()).unwrap_or(i64::MAX));
    let expected_expiry = lease_end
        .min(attempt.current_valid_until_seconds)
        .min(root_request.deadline_seconds());
    let row_matches = acquisition.resource_namespace_digest == resource.resource_namespace_digest()
        && acquisition.resource_id == resource.resource_id()
        && acquisition.resource_generation == resource.resource_generation()
        && acquisition.resource_digest == resource.resource_digest()
        && acquisition.catalog_generation == resource.catalog_generation()
        && acquisition.catalog_digest == resource.catalog_digest()
        && acquisition.selection_generation == resource.selection_generation()
        && acquisition.selection_digest == resource.selection_digest();
    if acquisition.state != ProviderAcquisitionStateV1::Applying
        || acquisition.provider != *provider
        || acquisition.holder != *holder
        || acquisition.acquisition_id != root_request.acquisition_id()
        || acquisition.acquisition_sequence != root_request.acquisition_sequence()
        || acquisition.normalized_intent.binding_digest() != root_request.binding_digest()
        || !acquisition.normalized_intent.kernel_coupled()
        || !row_matches
        || acquisition.current_attempt_digest != attempt.attempt_digest
        || acquisition.effect_attempt_digest != attempt.attempt_digest
        || acquisition.effect_id != request.effect_id()
        || acquisition.backend_id != *request.backend_id().as_bytes()
        || acquisition.normalized_intent.digest() != request.normalized_intent_digest()
        || attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.method != SourceProviderMethod::Acquire
        || attempt.provider != *provider
        || attempt.holder != *holder
        || attempt.request_id != root_request.request_id()
        || attempt.root_record_signer != *request.signed_root_request().signer()
        || attempt.status.is_some()
        || attempt.response_sequence.is_some()
        || attempt.attempt_digest != request.protected_attempt_digest()
        || attempt.signed_request != request.signed_root_request().to_canonical_bytes()
        || attempt.signed_request_digest != digest_signed_request(request.signed_root_request())
        || attempt.operation_intent_digest != request.normalized_intent_digest()
        || attempt.session_binding != root_request.session_binding()
        || attempt.request_sequence != root_request.sequence()
        || holder_head.session_binding != attempt.session_binding
        || holder_head.pending_attempt_digest != Some(attempt.attempt_digest)
        || attempt.request_sequence.checked_add(1) != Some(holder_head.next_request_sequence)
        || holder_head.signers[1] != attempt.root_record_signer
        || holder_head.signers[3] != *inner.provider_authority().traffic_signer()
        || request.issued_seconds() != attempt.verified_at_seconds
        || request.expires_seconds() != expected_expiry
        || !selected.is_current(journal)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

fn validate_signed_storage_plan_basis(
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    authorization: &ProviderOutcomeAuthorizationV1,
    selected: &crate::ProtectedProviderCatalogSelectionV1<'_>,
    request: &StorageLiveExportRequestV1,
    now_seconds: i64,
) -> Result<(), SourceProviderSecurityError> {
    validate_authorization_journal(journal, authorization)?;
    let (resource, selector) = selected.selected();
    if authorization.method != SourceProviderMethod::Acquire
        || !selected.is_current(journal)
        || request.resource() != resource
        || request.selector() != selector
        || request.protected_attempt_digest() != authorization.attempt_digest
        || request.normalized_intent_digest() != authorization.operation_intent_digest
        || digest_signed_request(request.signed_root_request())
            != authorization.signed_request_digest
        || now_seconds < request.issued_seconds()
        || now_seconds >= request.expires_seconds()
        || now_seconds >= authorization.request_deadline_seconds
        || !authorization_authority_is_current(authorization, now_seconds)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let acquisition_id = authorization
        .acquisition_id
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let acquisition_key = acquisition_key(&AcquisitionKeyV1 {
        provider_id: authorization.provider.authority_id(),
        holder_id: authorization.holder.authority_id(),
        acquisition_id,
    });
    let acquisition = match journal
        .get(&acquisition_key)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        .and_then(|bytes| decode_record(&acquisition_key, bytes).ok())
    {
        Some(DecodedRecordV1::Acquisition(value)) => value,
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let attempt_key = attempt_key(&AttemptKeyV1 {
        provider_id: authorization.provider.authority_id(),
        holder_id: authorization.holder.authority_id(),
        root_record_key_id: request.signed_root_request().signer().key_id(),
        method: SourceProviderMethod::Acquire as u8,
        request_id: authorization.request_id,
    });
    let attempt = match journal
        .get(&attempt_key)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        .and_then(|bytes| decode_record(&attempt_key, bytes).ok())
    {
        Some(DecodedRecordV1::Attempt(value)) => value,
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let root_request = decode_acquire_request(request.signed_root_request().subject())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let lease_end = attempt
        .verified_at_seconds
        .saturating_add(i64::try_from(root_request.requested_lease_seconds()).unwrap_or(i64::MAX));
    let expected_expiry = lease_end
        .min(attempt.current_valid_until_seconds)
        .min(root_request.deadline_seconds());
    let row_matches = acquisition.resource_namespace_digest == resource.resource_namespace_digest()
        && acquisition.resource_id == resource.resource_id()
        && acquisition.resource_generation == resource.resource_generation()
        && acquisition.resource_digest == resource.resource_digest()
        && acquisition.catalog_generation == resource.catalog_generation()
        && acquisition.catalog_digest == resource.catalog_digest()
        && acquisition.selection_generation == resource.selection_generation()
        && acquisition.selection_digest == resource.selection_digest();
    if acquisition.state != ProviderAcquisitionStateV1::Applying
        || acquisition.provider != authorization.provider
        || acquisition.holder != authorization.holder
        || acquisition.acquisition_id != acquisition_id
        || acquisition.current_attempt_digest != authorization.attempt_digest
        || acquisition.effect_attempt_digest != authorization.attempt_digest
        || acquisition.normalized_intent.digest() != authorization.operation_intent_digest
        || !acquisition.normalized_intent.kernel_coupled()
        || !row_matches
        || request.plan_id() != acquisition.effect_id
        || request.effect_id() != acquisition.effect_id
        || request.backend_id().as_bytes() != &acquisition.backend_id
        || attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.status.is_some()
        || attempt.response_sequence.is_some()
        || attempt.attempt_digest != authorization.attempt_digest
        || attempt.operation_intent_digest != authorization.operation_intent_digest
        || attempt.session_binding != authorization.session_binding
        || attempt.signed_request != request.signed_root_request().to_canonical_bytes()
        || attempt.current_valid_until_seconds != authorization.current_valid_until_seconds
        || request.issued_seconds() != attempt.verified_at_seconds
        || request.expires_seconds() != expected_expiry
        || !selected.is_current(journal)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}
