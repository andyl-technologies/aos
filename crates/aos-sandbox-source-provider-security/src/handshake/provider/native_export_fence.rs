//! Sealed native export-fence result production from exact protected custody.
//!
//! No public scalar-to-authority factory exists. The same three-row status
//! completion consumes only its own status4 reserve, preserving original
//! native7 and FD custody. Signing precedes the result append to avoid a cycle.

use super::*;
use aos_sandbox_source_provider_ledger::ledger::native_completion::export_result::native_export_fence_subject_v1;

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
