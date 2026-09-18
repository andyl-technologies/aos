//! Live-only terminalization of durable Pending acquisition progress.
//!
//! A cached Pending response remains immutable. This module may observe the
//! already-retained backend operation only while the original runtime remains
//! alive; hostile recovery describes the work but recreates no effect,
//! observation, signing, descriptor, or send authority.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::SourceProviderStatus;

use crate::ProviderLedgerError;
use crate::backend::{
    AcquireObservationV1, AcquirePlanV1, BackendEvidenceStateV1, ObservedBackendAcquisitionV1,
    SourceProviderBackendV1,
};
use crate::model::{ProviderAcquisitionStateV1, ProviderAttemptStateV1};
use crate::state::ProviderLedgerV1;
use crate::transaction::preflight_completion_capacity;

pub(crate) struct LivePendingAcquisitionV1 {
    pub(crate) plan: AcquirePlanV1,
    pub(crate) completion_session_binding: ObjectDigest,
    pub(crate) completion_attempt_digest: ObjectDigest,
    pub(crate) reservation_digest: ObjectDigest,
}

impl ProviderLedgerV1<'_> {
    /// Observes one live Pending acquisition without silently activating it.
    ///
    /// This path can observe an already-retained backend operation but cannot
    /// execute it. The original cached Pending response remains byte-identical;
    /// successful observation advances only the separate acquisition and
    /// inventory state. Recovery never recreates this live observation token.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when the live Pending token is absent or
    /// stale, custody changed, the operation remains unavailable, backend facts
    /// conflict, signing fails, or the terminal transaction cannot synchronize.
    pub fn observe_pending_acquire<B: SourceProviderBackendV1>(
        &mut self,
        acquisition_id: ObjectDigest,
        backend: &mut B,
    ) -> Result<(), ProviderLedgerError> {
        self.ensure_open()?;
        let progress = self.pending_acquisitions.remove(&acquisition_id).ok_or(
            ProviderLedgerError::InvalidTransition("no live Pending observation token"),
        )?;
        let current_snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&current_snapshot)?;
        let completion_capacity = preflight_completion_capacity(
            &self.journal,
            b"observe-pending-acquire",
            progress.reservation_digest,
            crate::limits::MAXIMUM_ACQUIRE_COMPLETION_BYTES,
        )?;
        completion_capacity.validate(&self.journal)?;

        let holder_id = progress.plan.holder_id;
        let current = self
            .current_sessions
            .get_mut(&holder_id)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "missing current Pending session",
            ))?
            .session
            .current_projection()?;
        if current.session_binding() != progress.completion_session_binding {
            return Err(ProviderLedgerError::Equivocation);
        }

        let observation = backend.observe_acquire(&progress.plan);
        let observed = match self.poison_backend_result(acquisition_id, observation) {
            Ok(AcquireObservationV1::Applied(observed)) => observed,
            Ok(AcquireObservationV1::NotApplied) => {
                self.pending_acquisitions.insert(acquisition_id, progress);
                return Err(ProviderLedgerError::Unavailable);
            }
            Ok(AcquireObservationV1::Conflict) => {
                self.record_backend_conflict(acquisition_id)?;
                return Err(ProviderLedgerError::BackendConflict);
            }
            Err(error) => {
                self.pending_acquisitions.insert(acquisition_id, progress);
                return Err(error);
            }
        };
        let result = validate_pending_acquire_observation(self, &progress, &observed);
        if matches!(&result, Err(ProviderLedgerError::BackendConflict)) {
            self.record_backend_conflict(acquisition_id)?;
        }
        result?;
        self.poison_backend_result(acquisition_id, observed.revalidate_physical())?;

        // The cached Pending response carried no descriptor. Even a terminal
        // backend observation therefore cannot silently activate a lease.
        // Dispose of this transient descriptor and retain the observe-only
        // continuation for a later authenticated rebind.
        drop(observed);
        self.pending_acquisitions.insert(acquisition_id, progress);
        Ok(())
    }
}

fn validate_pending_acquire_observation(
    ledger: &ProviderLedgerV1<'_>,
    progress: &LivePendingAcquisitionV1,
    observed: &ObservedBackendAcquisitionV1,
) -> Result<(), ProviderLedgerError> {
    let acquisition_key_value = ledger
        .recovered
        .acquisitions
        .keys()
        .find(|key| key.acquisition_id == progress.plan.acquisition_id)
        .cloned()
        .ok_or(ProviderLedgerError::InvalidTransition(
            "unknown Pending acquisition",
        ))?;
    let acquisition = ledger
        .recovered
        .acquisitions
        .get(&acquisition_key_value)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt("missing Pending acquisition"))?;
    if acquisition.state != ProviderAcquisitionStateV1::Pending
        || !progress.plan.matches_effect_acquisition(&acquisition)
        || observed.backend_id != progress.plan.backend_id
        || observed.lineage_digest != progress.plan.lineage_digest()
        || observed.evidence.state() != BackendEvidenceStateV1::Acquired
    {
        return Err(ProviderLedgerError::BackendConflict);
    }
    let attempt = ledger
        .recovered
        .attempts
        .values()
        .find(|attempt| attempt.attempt_digest == acquisition.current_attempt_digest)
        .cloned()
        .ok_or(ProviderLedgerError::Corrupt(
            "missing Pending Acquire attempt",
        ))?;
    if attempt.state != ProviderAttemptStateV1::Completed
        || attempt.status != Some(SourceProviderStatus::Pending)
        || attempt.session_binding != progress.completion_session_binding
        || attempt.attempt_digest != progress.completion_attempt_digest
    {
        return Err(ProviderLedgerError::Corrupt(
            "Pending Acquire disposition graph",
        ));
    }
    crate::acquire::validate_backend_selection(ledger, &acquisition, &attempt, observed)
}
