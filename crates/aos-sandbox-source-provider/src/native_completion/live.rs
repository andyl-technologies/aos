//! Retained legacy native observation checks and a closed dispatch frontier.
//!
//! The uninstalled V2 producer is retired, while the opaque observation and
//! custody checks remain intact. The old entry checks openness and exact reply
//! reservation before consuming its permit at the same unavailable cut. The
//! selected V5 original owner retains its separate live Storage custody.

use std::sync::Arc;

use aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1;
use aos_sandbox_source_provider_security::ReceivedStorageNativeAcquireV3;

use super::*;
use crate::backend_verifier::ProtectedBackendVerifierV1;
use crate::zfs_hold_challenge::{ProtectedZfsHoldChallengesV1, current_seconds};
use crate::zfs_hold_verifier::ProtectedStorageZfsHoldVerifierV1;
use crate::{DurableAcquireEffectPermitV1, DurableProviderReplyV1, SourceProviderBackendV1};

/// Keeps live endpoint origin and the exact spent-challenge completion together.
///
/// The retired V2 producer no longer constructs this token. Its fields and
/// validators remain private; signed DATA alone cannot reconstruct the original
/// endpoint, verifier or clock custody.
pub(crate) struct NativeAcquireLiveObservationV3 {
    active: NativeAcquireCompletionRecordV2,
    origin: ReceivedStorageNativeAcquireV3,
    manifest: ProtectedStorageZfsHoldVerifierV1,
    clock: Arc<NativeAcquireClockGuardV1>,
}

impl core::fmt::Debug for NativeAcquireLiveObservationV3 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NativeAcquireLiveObservationV3([protected origin])")
    }
}

impl NativeAcquireLiveObservationV3 {
    pub(crate) fn reply_identity(&self) -> NativeReplyIdentity {
        NativeReplyIdentity {
            acquisition: self.active.acquisition_id,
            attempt: self.active.attempt_digest,
            session: self.active.session_binding,
            signed_request: self.active.root_request_digest,
        }
    }

    pub(crate) fn revalidate(
        &self,
        descriptor: &aos_sandbox_source_provider_protocol::SourceRootObservationV1,
    ) -> Result<(), ProviderLedgerError> {
        self.origin
            .revalidate()
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        self.manifest.revalidate()?;
        self.clock
            .revalidate(Some(self.origin.reply().receipt().receipt().validity().1))?;
        let now = current_seconds()?;
        let (issued, expires) = self.origin.reply().receipt().receipt().validity();
        if self.origin.reply().acceptance().acceptance().descriptor() != descriptor
            || self.origin.reply().receipt().digest() != self.active.receipt_digest
            || now < issued
            || now < self.active.challenge_issued_seconds
            || now >= expires
            || now >= self.active.challenge_valid_until_seconds
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn completion_record(
        &self,
        ledger: &ProviderLedgerV1<'_>,
        permit: &DurableAcquireEffectPermitV1,
    ) -> Result<NativeAcquireCompletionRecordV2, ProviderLedgerError> {
        if ledger.qualified_native_bridge.is_none()
            || self.active.state != NativeAcquireCompletionStateV2::Active
            || self.active.acquisition_id != permit.plan.acquisition_id()
            || self.active.attempt_digest != permit.completion_attempt_digest
            || self.active.session_binding != permit.completion_session_binding
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        let current = ledger
            .recovered
            .native_completions
            .get(&self.active.acquisition_id)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = ledger
            .recovered
            .acquisitions
            .values()
            .find(|row| row.acquisition_id == current.acquisition_id)
            .ok_or(ProviderLedgerError::Unavailable)?;
        crate::ledger::native_completion::validate_native_export_open_v1(
            acquisition,
            Some(current),
        )
        .map_err(crate::transaction::map_pure_ledger_error)?;
        if current.state != NativeAcquireCompletionStateV2::Prepared {
            return Err(ProviderLedgerError::Equivocation);
        }
        current
            .validate_successor(&self.active)
            .map_err(crate::transaction::map_pure_ledger_error)?;
        Ok(self.active.clone())
    }
}

impl ProviderLedgerV1<'_> {
    /// Retains the exact closed legacy entry without enabling native dispatch.
    pub(crate) fn execute_native_acquire_v3(
        &mut self,
        challenges: &mut ProtectedZfsHoldChallengesV1,
        permit: DurableAcquireEffectPermitV1,
        original: &SignedSourceProviderRequestV1,
        current_catalog: (&[u8], &[u8]),
        _backend: &mut impl SourceProviderBackendV1,
        _backend_verifier: Arc<ProtectedBackendVerifierV1>,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        let identity =
            NativeReplyIdentity::for_request(original, permit.completion_attempt_digest)?;
        self.native_reply_custody.require_reserved(identity)?;
        self.prepare_native_acquire_request_v2(challenges, permit, original, current_catalog)
    }
}
