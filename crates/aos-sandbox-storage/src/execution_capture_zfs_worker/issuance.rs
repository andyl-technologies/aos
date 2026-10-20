//! Binds the physical create recipe to the actual fresh same-ledger issuer.
//!
//! Only the noncopyable freshly committed424 owner can enter this constructor.
//! The actual signed admission remains beside the created private attempt.
//! Historical receipt/query DATA has no conversion into this owner. Dispatch
//! still requires the same genuine occupied F and authenticated worker channel.

use super::*;
use crate::execution_output::FreshCaptureCreateCommitV3;

/// Retains the genuine issuer and its sole private native create preparation.
pub(crate) struct NativeCaptureCreateOriginalV3 {
    fresh: FreshCaptureCreateCommitV3,
    state_pending: crate::state::CaptureStatePendingOriginalV3,
    retired: bool,
}

impl NativeCaptureCreateOriginalV3 {
    pub(crate) fn from_fresh_v3(fresh: FreshCaptureCreateCommitV3) -> Self {
        Self { fresh, state_pending: crate::state::CaptureStatePendingOriginalV3::new(), retired: false }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.state_pending.failure()
    }

    // This exact Native owner retains both genuine issuers across the State
    // append. No parsed reservation or completed Controller response can enter.
    pub(crate) fn prepare_state_pending_once_v3(
        &mut self,
        store: &mut crate::StorageTransactionStore,
        authority: &crate::authorization::StorageAuthorityV1,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), crate::StorageStateError> {
        self.state_pending.begin_once_v3(store, authority, &self.fresh, receiving)
    }

    pub(crate) fn worker_dispatch_inputs_v3(&self) -> Option<(
        &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2,
        &[u8; 424], &CaptureDatasetRequirementV1,
        crate::execution_capture_policy::CaptureAllocationV1,
    )> {
        if !self.state_pending.completed_v3()
        { return None; }
        let (_, _, _, _, _, _, _, requirement, policy) = self.fresh.native_parts_v3();
        Some((self.fresh.admitted_v3().source_v3(), self.fresh.record_bytes_v3(), requirement, policy))
    }

    pub(crate) fn catalog_resolution_v3(&self)
        -> Option<&crate::catalog_transition::CaptureCatalogResolutionV3>
    { self.state_pending.resolution_v3() }

    pub(crate) fn worker_result_identity_v3(&self) -> super::CaptureWorkerResultIdentityDataV3 {
        let (attempt, controller, host, durable, _, _, _, _, _) = self.fresh.native_parts_v3();
        super::CaptureWorkerResultIdentityDataV3 { attempt, controller, host, durable }
    }

    pub(crate) fn durable_attempt_digest_v3(&self) -> ObjectDigest {
        self.fresh.native_parts_v3().3
    }

    pub(crate) fn admission_v3(&self) -> &crate::authorization::VerifiedCaptureReserveOngoingAdmissionV3 {
        self.fresh.admitted_v3()
    }
}

impl Drop for NativeCaptureCreateOriginalV3 {
    fn drop(&mut self) {
        // Neither a completed Controller response nor an ambiguous create is
        // physical completion. Only the actual later native terminal can retire
        // this same owner; failure must not unwind through native field drops.
        if !self.retired { std::process::abort(); }
    }
}


impl NativeCaptureCreateOriginalV3 {
    pub(crate) fn retire_after_complete_disposal_v3(&mut self,
        disposal: &mut aos_sandbox::StorageCaptureWorkerDisposalV2<'_, '_, '_>,
        record: &aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordDataV2)
        -> Result<(), ZfsWorkerError> {
        disposal.require_capture_original_v3(self.admission_v3().lifetime_v3())
            .map_err(|_| ZfsWorkerError::Authority)?;
        record.verify_original_ongoing_v2(self.admission_v3().source_v3(),
            self.worker_result_identity_v3().attempt, self.durable_attempt_digest_v3())
            .map_err(|_| ZfsWorkerError::Authority)?;
        self.retired = true;
        Ok(())
    }
}
