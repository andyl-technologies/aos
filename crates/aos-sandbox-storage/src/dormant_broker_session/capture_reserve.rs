//! Keeps the actual Capture60 request, prelude and occupied physical owner.
//!
//! The existing concrete Domain entry pays the inert representation before
//! construction. The actual same-F loan is always supplied by the Session;
//! no vector, UID, Source DTO or response constructs a new financial original.
//! A successful reserve response leaves this owner and its physical F occupied.

use super::*;
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::{AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerMethodOutcomeV1};
use crate::execution_output_credential::StorageExecutionOutputCustodyV1;
use crate::runtime::original_capture::OriginalStorageCaptureReserveV3;

impl DormantStorageApplyCompositionV1 {
    /// Retains fresh Capture60 inputs and builds its exact parked Host45 body.
    ///
    /// Unit return does not indicate success. The caller borrows the body only
    /// after this owner's currentness, payment and independently owed posts.
    /// Host45 must use that body on the same already-held Host Session.
    pub fn prepare_original_capture_ongoing_v3(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        host_header: &aos_proto::aos::sandbox::local::v1::RequestHeader,
        output: &mut StorageExecutionOutputCustodyV1,
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        if self.capture_reserve_entered || self.capture_reserve.is_some() { return; }
        self.capture_reserve_entered = true;
        // This is the same mechanical Domain constructor-entry recipe used by
        // the adjacent logical output owner, not a logical effect/loan cast.
        let demand = std::mem::size_of::<OriginalStorageCaptureReserveV3>().checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .map(|bytes| ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })
            .map_err(crate::execution_output_credential::logical_receiving::LogicalOutputFundingErrorV1::from);
        let entered = self.capture_reserve_entry.prepare(lifecycle, session, socket, demand);
        if entered { self.capture_reserve = Some(Box::new(OriginalStorageCaptureReserveV3::new())); }
        self.capture_reserve_entry.finish(lifecycle, session, socket);
        if !entered || self.capture_reserve_entry.failure().is_some() { return; }
        let Some(original) = self.capture_reserve.as_deref_mut() else { std::process::abort(); };
        self.runtime.prepare_original_capture_ongoing_v3(request, host_header, output, lifecycle, session, socket, original);
    }

    /// Borrows the exact Host45 body after every paid prelude/post succeeds.
    #[must_use]
    pub fn original_capture_host_body_v3(&self) -> Option<&[u8]> {
        if self.capture_reserve_entry.failure().is_some() { return None; }
        self.capture_reserve.as_deref()?.host_body_v3()
    }

    /// Continues only with the actual committed Host45 outcome on the same F.
    ///
    /// The real native original remains resident after a response. Neither the
    /// Session Outcome nor a transport ACK completes its worker, pipe streams,
    /// durable capture or independently owed physical disposal obligations.
    pub fn finish_original_capture_with_host_ongoing_v3(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        host: &AuthenticatedBrokerMethodOutcomeV1,
        output: &mut StorageExecutionOutputCustodyV1,
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        if self.capture_reserve_entry.failure().is_some() { return; }
        let Some(original) = self.capture_reserve.as_deref_mut() else { return; };
        self.runtime.finish_original_capture_with_host_ongoing_v3(request, host, output, lifecycle, session, socket, original);
    }

    /// Borrows the canonical effect-possible response after actual native posts.
    ///
    /// This response locates the attempt and conveys no physical pipe proof.
    #[must_use]
    pub fn original_capture_reserve_response_v3(&self) -> Option<&[u8]> {
        if self.capture_reserve_entry.failure().is_some() { return None; }
        self.capture_reserve.as_deref()?.response_v3()
    }

    /// Checks the actual completed reserve without retiring its physical worker.
    ///
    /// The same native State interval must have completed. Its genuine reserve
    /// response already requires mounted-pipe verification and the independently
    /// prepaid State, service and Output posts. The occupied Capture owner stays
    /// resident until the separate physical terminal/disposal continuation.
    ///
    /// # Errors
    /// Refuses an incomplete reserve, failed constructor or another native State
    /// interval. This comparison performs no new I/O or physical disposition.
    pub fn require_original_capture_response_disposal_v3(
        &self,
        native: &aos_sandbox::StorageLifecyclePositiveDisposalV1<'_, '_, '_>,
    ) -> Result<(), aos_sandbox::StorageReceivingClosedV1> {
        if self.original_capture_reserve_response_v3().is_none() {
            return Err(aos_sandbox::StorageReceivingClosedV1);
        }
        native.require_state_reconciliation_disposal_v1(self.runtime.lifecycle_state_journal_v1())
    }

    /// Checks a completed Output-only operation's unused State interval.
    ///
    /// # Errors
    /// Refuses another native State writer or any entered State encoder. The
    /// caller retains its genuine domain original and response through disposal.
    pub fn require_original_output_response_disposal_v2(
        &self,
        native: &aos_sandbox::StorageLifecyclePositiveDisposalV1<'_, '_, '_>,
    ) -> Result<(), aos_sandbox::StorageReceivingClosedV1> {
        native.require_unused_state_disposal_v2(self.runtime.lifecycle_state_journal_v1())
    }

    /// Borrows the same paid actual request retained through this continuation.
    #[must_use]
    pub fn original_capture_reserve_request_v3(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        self.capture_reserve.as_deref()?.request_v3()
    }

    /// Borrows the first retained native/domain cause without disposing custody.
    #[must_use]
    pub fn original_capture_reserve_failure_v3<'cause>(&'cause self, output: &'cause StorageExecutionOutputCustodyV1)
        -> Option<&'cause (dyn std::error::Error + 'static)>
    {
        self.capture_reserve_entry.failure()
            .or_else(|| self.capture_reserve.as_deref()?.failure_v3(output))
    }
}


impl DormantStorageApplyCompositionV1 {
    /// Reports whether the actual completed60 owns its still-resident worker.
    ///
    /// This borrowed status cannot construct funding, a proof or a native loan.
    #[must_use]
    pub fn has_original_capture_resident_v3(&self) -> bool {
        self.capture_reserve.as_deref().is_some_and(OriginalStorageCaptureReserveV3::has_resident_capture_v3)
    }

    /// Reports whether the same physical owner still awaits its initial Begin.
    #[must_use]
    pub fn awaiting_original_capture_begin_v3(&self) -> bool {
        self.capture_reserve.as_deref().is_some_and(OriginalStorageCaptureReserveV3::awaiting_capture_begin_v3)
    }

    /// Adds only the resident authenticated Host socket to the daemon poll set.
    ///
    /// This borrowed readiness entry cannot construct a socket or native loan.
    /// Its descriptor remains owned by the same occupied physical original.
    #[must_use]
    pub fn push_original_capture_terminal_poll_v3<'fd>(&'fd self,
        polls: &mut Vec<rustix::event::PollFd<'fd>>) -> Option<usize> {
        self.capture_reserve.as_deref()?.push_capture_terminal_poll_v3(polls)
    }

    /// Reports full native completion and every independently owed physical post.
    #[must_use]
    pub fn original_capture_physical_completed_v3(&self) -> bool {
        self.capture_reserve.as_deref().is_some_and(OriginalStorageCaptureReserveV3::completed_physical_capture_v3)
    }

    /// Serves the actual Host physical hold on this same original Storage F.
    ///
    /// The parent continuously lends its actual startup original. This does
    /// not reconstruct the expired60 Session or derive a grant from the Begin.
    /// Unit return conveys no success; failures remain on the actual owner.
    pub fn serve_original_capture_held_v3(&mut self,
        listener: &mut aos_sandbox_linux::seqpacket::RecordSubjectListener,
        output: &mut StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>) {
        let Some(original) = self.capture_reserve.as_deref_mut() else { return; };
        self.runtime.serve_original_capture_held_v3(original, listener, output, receiving);
    }

    /// Disposes only the fully completed physical owner after all native posts.
    ///
    /// The full676 remains on the same MAC Output history for fresh Query61;
    /// no ledger capacity, traffic, Source lifetime or effect is renewed.
    /// This pure positive transfer performs no I/O and returns no native owner.
    ///
    /// # Errors
    /// Retains an incomplete, negative or still-resident physical original.
    pub fn retire_completed_original_capture_v3(&mut self) -> Result<(), crate::StorageRuntimeError> {
        if !self.capture_reserve.as_deref().is_some_and(OriginalStorageCaptureReserveV3::completed_physical_capture_v3) {
            return Err(crate::StorageRuntimeError::Receiving);
        }
        drop(self.capture_reserve.take());
        self.capture_reserve_entered = false;
        self.capture_reserve_entry = crate::execution_output_credential::logical_receiving::LogicalOutputEntryV1::new();
        Ok(())
    }
}

impl DormantStorageApplyCompositionV1 {
    /// Reports the same original's unused, prepaid fresh Stop control slot.
    ///
    /// Historical Capture failures do not create permission or erase this slot.
    /// Actual fresh signed Stop is checked independently on native reception.
    #[must_use]
    pub fn can_receive_original_capture_stop_v4(&self) -> bool {
        self.capture_reserve
            .as_deref()
            .is_some_and(OriginalStorageCaptureReserveV3::can_receive_stop_cleanup_v4)
    }

    /// Waits on the actual listener while keeping the original F continuously lent.
    ///
    /// # Errors
    /// Retains a missing/repeated slot or actual readiness failure. No expired
    /// positive effect gate is reentered and no request lifetime is renewed.
    pub fn wait_original_capture_stop_v4(
        &mut self,
        listener: &aos_sandbox_linux::seqpacket::RecordSubjectListener,
    ) -> Result<(), crate::ZfsWorkerError> {
        self.capture_reserve
            .as_deref_mut()
            .and_then(|original| original.physical_for_stop_v4())
            .ok_or(crate::ZfsWorkerError::Authority)?
            .wait_stop_cleanup_once_v4(listener)
    }

    /// Receives one freshly authorized cancellation on this occupied original.
    ///
    /// The unit return cannot prove cleanup. Borrowed receipt/failure access
    /// remains tied to actual native reception, containment and all owed posts;
    /// this call never drops the incomplete Capture or returns its old F.
    pub fn serve_original_capture_stop_v4(
        &mut self,
        listener: &mut aos_sandbox_linux::seqpacket::RecordSubjectListener,
        output: &StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) {
        let Some(original) = self.capture_reserve.as_deref_mut() else {
            return;
        };
        self.runtime
            .serve_original_capture_stop_v4(original, listener, output, receiving);
    }

    /// Borrows the negative branch's selected error beside the old Capture cause.
    #[must_use]
    pub fn original_capture_stop_failure_v4<'cause>(
        &'cause self,
        receiving: &'cause aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        self.capture_reserve.as_deref()?.stop_failure_v4(receiving)
    }

    /// Reports only actual negative receipt delivery and its independent posts.
    ///
    /// The incomplete dataset, original errors and F remain occupied for
    /// authenticated Recovery. This is never a Complete676 disposition.
    #[must_use]
    pub fn original_capture_stopped_with_residual_v4(&self) -> bool {
        self.capture_reserve
            .as_deref()
            .is_some_and(|original| original.stopped_with_residual_v4())
    }
}
