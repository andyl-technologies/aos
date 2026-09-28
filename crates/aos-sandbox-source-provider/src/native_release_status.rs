//! Exact originally reauthenticated native Release status-only recovery.
//!
//! This runtime caller consumes the separate status suffix after a durable
//! export fence. It never observes or executes a backend, completes physical
//! Release, drops original FD custody, or rebinds a historical reservation.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::SourceProviderStatus;

use crate::ProviderLedgerError;
use crate::backend::{DurableProviderReplyV1, DurableReleaseEffectPermitV1, ReleasePlanV1};
use crate::model::ProviderAttemptStateV1;
use crate::state::ProviderLedgerV1;

impl ProviderLedgerV1<'_> {
    /// Completes only an exactly reauthenticated reserved native Release status.
    ///
    /// No backend is observed or executed. Cold exact replay may consume the
    /// original status suffix only while the original Release session remains
    /// current; successor-session recovery does not rebind that reservation.
    ///
    /// # Errors
    ///
    /// Rejects another request/session, a non-Releasing graph, absent current
    /// authorization or suffix capacity, signing failure, or failed sync.
    pub(crate) fn complete_native_release_status_from_original(
        &mut self,
        acquisition_id: ObjectDigest,
        effect_id: [u8; 16],
        original: &aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        let acquisition = self
            .recovered
            .acquisitions
            .values()
            .find(|row| row.acquisition_id == acquisition_id)
            .cloned()
            .ok_or(ProviderLedgerError::Unavailable)?;
        let release = self
            .recovered
            .releases
            .values()
            .find(|row| row.acquisition_id == acquisition_id)
            .cloned()
            .ok_or(ProviderLedgerError::Unavailable)?;
        let attempt = self
            .recovered
            .attempts
            .values()
            .find(|row| row.attempt_digest == release.attempt_digest)
            .cloned()
            .ok_or(ProviderLedgerError::Unavailable)?;
        if !crate::native_completion::is_native_dispatch_acquisition(&acquisition)
            || acquisition.state != crate::ProviderAcquisitionStateV1::Releasing
            || release.effect_id != effect_id
            || attempt.state != ProviderAttemptStateV1::Reserved
            || attempt.signed_request != original.to_canonical_bytes()
            || attempt.signed_request_digest
                != aos_sandbox_source_provider_protocol::digest_signed_request(original)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        crate::native_no_dispatch_capacity::validate_set(&self.journal, &self.recovered)?;
        crate::native_release_capacity::exact_reservation(
            &self.journal,
            &self.recovered,
            acquisition_id,
        )?;
        let plan = ReleasePlanV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            session_binding: attempt.session_binding,
            attempt_digest: attempt.attempt_digest,
            acquisition_id,
            effect_id,
            lease_id: release.lease_id,
            lease_digest: release.lease_digest,
            backend_id: acquisition.backend_id,
            acquired_evidence: crate::backend::acquired_evidence(&acquisition)?,
        };
        if !plan.matches_effect_release(&acquisition, &release) {
            return Err(ProviderLedgerError::Equivocation);
        }
        let signing_authorization = self
            .recovery_authorizations
            .remove(&attempt.attempt_digest)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let permit = DurableReleaseEffectPermitV1 {
            plan,
            completion_session_binding: attempt.session_binding,
            completion_attempt_digest: attempt.attempt_digest,
            reservation_digest: release.backend_lineage_digest,
            journal_snapshot: self.journal.snapshot()?,
            completion_capacity: crate::transaction::CompletionCapacityV1::NativeReleaseStatus,
            signing_authorization,
        };
        self.complete_release_disposition(permit, SourceProviderStatus::Pending)
    }
}
