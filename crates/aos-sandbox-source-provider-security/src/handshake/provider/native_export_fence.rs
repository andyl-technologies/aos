//! Sealed native export-fence result production from exact protected custody.
//!
//! No public scalar-to-authority factory exists. The same three-row status
//! completion consumes only its own status4 reserve, preserving original
//! native7 and FD custody. Signing precedes the result append to avoid a cycle.

use super::*;
use aos_sandbox_source_provider_ledger::ledger::native_completion::export_result::native_export_fence_subject_v1;

fn original_pending_fence_subject_v1(
    writer: &aos_sandbox::SourceOriginalNativeJournalAuthorityV5<'_, '_>,
    readback: &aos_sandbox::OriginalSourceProtectedReadbackV5,
    authorization: &super::ProviderOutcomeAuthorizationV1,
    records: &[(Vec<u8>, Vec<u8>)],
) -> Result<aos_sandbox_source_provider_protocol::SourceProviderNativeExportFenceV1, super::OriginalNativeSigningErrorV5> {
    writer.validate_original_release_status_snapshot_v1(readback, &authorization.journal_snapshot)?;
    let acquisition = authorization.acquisition_id
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    if authorization.method != SourceProviderMethod::Release
        || records.len() != readback.rows().keys().filter(|(namespace, _)| {
            *namespace == aos_sandbox::RecordNamespace::SourceProviderAuthority
        }).count()
        || records.iter().any(|(key, value)| {
            readback.rows().get(&(aos_sandbox::RecordNamespace::SourceProviderAuthority, key.clone()))
                != Some(value)
        })
    {
        return Err(SourceProviderSecurityError::SessionContinuity.into());
    }
    let (snapshot, capacity) = writer.original_release_status_basis_v1(readback, acquisition)?;
    aos_sandbox_source_provider_ledger::ledger::native_completion::export_result::native_held_export_fence_subject_v1(
        records, acquisition, authorization.attempt_digest, snapshot.sequence(),
        capacity.admission_transaction_id(), capacity.reservation_id(),
    ).map_err(|_| SourceProviderSecurityError::SessionContinuity.into())
}

impl CurrentProviderIngressSessionV1 {
    /// Prepares the fixed original Pending fence before the final signing cut.
    ///
    /// # Errors
    ///
    /// Rejects changed custody, graph, reservation, purpose or signer identity.
    #[doc(hidden)]
    pub fn prepare_original_native_release_fence_v1(
        &mut self,
        writer: &aos_sandbox::SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &aos_sandbox::OriginalSourceProtectedReadbackV5,
        authorization: &super::ProviderOutcomeAuthorizationV1,
        records: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<aos_sandbox_source_provider_protocol::PreparedNativeExportFenceDataV1, super::OriginalNativeSigningErrorV5> {
        self.revalidate()?;
        authorization.claim_purpose(1 << 2)?;
        let subject = original_pending_fence_subject_v1(writer, readback, authorization, records)?;
        let inner = self.custody.inner();
        aos_sandbox_source_provider_protocol::PreparedNativeExportFenceDataV1::prepare(
            subject, inner.provider_authority().traffic_signer().clone(),
            &inner.outcome_key().signing_key().verifying_key().to_bytes(),
        ).map_err(|_| SourceProviderSecurityError::SessionContinuity.into())
    }

    /// Lends only this exact prepared original fence and the actual outcome key.
    ///
    /// The caller finishes its independent owner observations before obtaining
    /// the loan, samples its original Release clock last, and parks `.sign()`'s
    /// whole result immediately. The consumed purpose cannot be retried.
    ///
    /// # Errors
    ///
    /// Rejects an altered current graph, prepared subject, signer or spent purpose.
    #[doc(hidden)]
    pub fn borrow_original_native_release_fence_v1<'data, 'key>(
        &'key mut self,
        writer: &aos_sandbox::SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &aos_sandbox::OriginalSourceProtectedReadbackV5,
        authorization: &super::ProviderOutcomeAuthorizationV1,
        records: &[(Vec<u8>, Vec<u8>)],
        physical: &crate::ProviderSourceRootHandoffV1,
        prepared: &'data aos_sandbox_source_provider_protocol::PreparedNativeExportFenceDataV1,
    ) -> Result<aos_sandbox_source_provider_protocol::NativeExportFenceSigningLoanV1<'data, 'key>, super::OriginalNativeSigningErrorV5> {
        let expected = original_pending_fence_subject_v1(writer, readback, authorization, records)?;
        if prepared.subject() != &expected {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        authorization.claim_purpose(1 << 4)?;
        self.revalidate_original_held_mount_v5(physical)?;
        let now = current_unix_seconds()?;
        if !authorization_authority_is_current(authorization, now)
            || now >= authorization.request_deadline_seconds
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        prepared.signing_loan(self.custody.inner().outcome_key().signing_key())
            .map_err(|_| SourceProviderSecurityError::SessionContinuity.into())
    }

    /// Prepares the dependent Pending status using the same canonical encoder.
    ///
    /// # Errors
    ///
    /// Rejects changed original rows, custody, signed fence or expired authority.
    #[doc(hidden)]
    pub fn prepare_original_pending_release_status_v1(
        &mut self,
        writer: &aos_sandbox::SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &aos_sandbox::OriginalSourceProtectedReadbackV5,
        authorization: &super::ProviderOutcomeAuthorizationV1,
        records: &[(Vec<u8>, Vec<u8>)],
        fence: &aos_sandbox_source_provider_protocol::SignedSourceProviderNativeExportFenceV1,
    ) -> Result<aos_sandbox_source_provider_protocol::PreparedSourceProviderStatusDataV5, super::OriginalNativeSigningErrorV5> {
        self.revalidate()?;
        let expected = original_pending_fence_subject_v1(writer, readback, authorization, records)?;
        let inner = self.custody.inner();
        let now = current_unix_seconds()?;
        if fence.subject() != &expected
            || fence.signer() != inner.provider_authority().traffic_signer()
            || !authorization_authority_is_current(authorization, now)
            || now >= authorization.request_deadline_seconds
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        fence.verify(&inner.outcome_key().signing_key().verifying_key().to_bytes())
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let status = super::completion::completion_status_subject(
            authorization, SourceProviderStatus::Pending,
            response_result_digest_v1(SourceProviderMethod::Release, SourceProviderStatus::Pending,
                Some(&fence.to_canonical_bytes())),
            empty_descriptor_set_commitment_v1(),
        )?;
        aos_sandbox_source_provider_protocol::PreparedSourceProviderStatusDataV5::prepare(
            status, inner.provider_authority().traffic_signer().clone(),
            &inner.outcome_key().signing_key().verifying_key().to_bytes(),
        ).map_err(|_| SourceProviderSecurityError::SessionContinuity.into())
    }

    /// Lends the exact dependent Pending status to its authentic outcome key.
    ///
    /// # Errors
    ///
    /// Rejects an altered status binding or a previously consumed signing purpose.
    #[doc(hidden)]
    pub fn borrow_original_pending_release_status_v1<'data, 'key>(
        &'key mut self,
        writer: &aos_sandbox::SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &aos_sandbox::OriginalSourceProtectedReadbackV5,
        authorization: &super::ProviderOutcomeAuthorizationV1,
        records: &[(Vec<u8>, Vec<u8>)],
        physical: &crate::ProviderSourceRootHandoffV1,
        fence: &aos_sandbox_source_provider_protocol::SignedSourceProviderNativeExportFenceV1,
        prepared: &'data aos_sandbox_source_provider_protocol::PreparedSourceProviderStatusDataV5,
    ) -> Result<aos_sandbox_source_provider_protocol::PendingReleaseStatusSigningLoanV1<'data, 'key>, super::OriginalNativeSigningErrorV5> {
        let expected_fence = original_pending_fence_subject_v1(writer, readback, authorization, records)?;
        let expected_status = super::completion::completion_status_subject(
            authorization, SourceProviderStatus::Pending,
            response_result_digest_v1(SourceProviderMethod::Release, SourceProviderStatus::Pending,
                Some(&fence.to_canonical_bytes())),
            empty_descriptor_set_commitment_v1(),
        )?;
        if fence.subject() != &expected_fence
            || prepared.subject() != &expected_status
            || !super::completion::status_matches_authorization(authorization, prepared.subject())
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        authorization.claim_purpose(1 << 5)?;
        self.revalidate_original_held_mount_v5(physical)?;
        let now = current_unix_seconds()?;
        if !authorization_authority_is_current(authorization, now)
            || now >= authorization.request_deadline_seconds
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        prepared.pending_release_signing_loan(self.custody.inner().outcome_key().signing_key())
            .map_err(|_| SourceProviderSecurityError::SessionContinuity.into())
    }
}

impl<'session, 'journal, 'authority, 'authorization>
    ProviderOwnerSecurityFacadeV1<'session, 'journal, 'authority, 'authorization>
{
    /// Seals exact Pending no-future-Provider-exports evidence and its status suffix.
    ///
    /// # Errors
    ///
    /// Rejects another method, stale custody/snapshot/request, non-Releasing
    /// native graph, foreign capacity or artifacts, signing or preflight failure.
    pub fn prepare_native_export_fence_completion(
        self,
        plan: aos_sandbox_source_provider_ledger::ReleaseStatusCompletionPlanV1,
    ) -> Result<ProviderCompletionBuilderV1, SourceProviderSecurityError> {
        use aos_sandbox_source_provider_protocol::{
            ReleaseSourceResponseV2, SignedSourceProviderNativeExportFenceV1,
        };
        if self.authorization.method != SourceProviderMethod::Release {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        validate_authorization_journal(self.journal, self.authorization)?;
        self.session.revalidate()?;
        let current = super::completion::collect_bounded_current_records(self.journal)?;
        let capacity = super::native_release_status::exact_reservation(
            self.journal,
            &current,
            self.authorization,
        )?;
        let subject = native_export_fence_subject_v1(
            &current,
            self.authorization.attempt_digest,
            self.authorization.journal_snapshot.sequence(),
            capacity.admission_transaction_id(),
            capacity.reservation_id(),
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        self.authorization
            .claim_purpose((1 << 2) | (1 << 4) | (1 << 5))?;
        let signed = {
            let inner = self.session.custody.inner();
            SignedSourceProviderNativeExportFenceV1::sign(
                subject,
                inner.provider_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
        }
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        self.session.revalidate()?;
        let status_subject = super::completion::completion_status_subject(
            self.authorization,
            SourceProviderStatus::Pending,
            response_result_digest_v1(
                SourceProviderMethod::Release,
                SourceProviderStatus::Pending,
                Some(&signed.to_canonical_bytes()),
            ),
            empty_descriptor_set_commitment_v1(),
        )?;
        let (status, completed_at) = self.session.sign_current_response_status(
            self.journal,
            self.authorization,
            status_subject,
        )?;
        let response = ReleaseSourceResponseV2::new(status, signed)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
            .to_canonical_bytes();
        super::completion::completion_records_for_plan(
            self.journal,
            self.authorization,
            plan.attempt_key(),
            &response,
        )?;
        let finalized = plan
            .finalize(
                current
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                response,
                None,
                completed_at,
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        super::completion::prepare_finalized_builder_with_native_status_capacity(
            self.session,
            self.journal,
            self.authorization,
            finalized,
            Some(capacity),
        )
    }
}
