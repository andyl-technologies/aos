//! Keeps actual Query61 custody through its authenticated successor.
//!
//! This concrete Composition entry is funded by the actual Storage lifecycle;
//! it exposes only a completed historical response or a borrowed original cause.
//! A worker, admission lifetime or physical permit cannot be extracted.

use super::*;
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use crate::runtime::capture_query::OriginalStorageCaptureQueryV3;
use crate::execution_output_credential::StorageExecutionOutputCustodyV1;

#[derive(Clone, Copy)]
enum First { Arm, Demand, Payment, Post }

pub(super) struct QueryEntryOriginalV3 {
    arm: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    demand: Option<Result<ResourceVector, AccountingError>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    post: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    first: Option<First>,
    entered: bool,
}

impl QueryEntryOriginalV3 {
    pub(super) const fn new() -> Self {
        Self { arm: None, demand: None, payment: None, post: None, first: None, entered: false }
    }

    pub(super) const fn is_entered_v3(&self) -> bool { self.entered }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Arm => self.arm.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Demand => self.demand.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Payment => self.payment.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Post => self.post.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}

impl DormantStorageApplyCompositionV1 {
    /// Observes the actual freshly signed Query61 under the same Storage F.
    ///
    /// This entry parks all lower results. Unit return never establishes
    /// success; the caller borrows the response only after every owed post and
    /// retains the actual Session until its independent terminal disposition.
    pub fn query_original_capture_ongoing_v3(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        output: &mut StorageExecutionOutputCustodyV1,
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        if self.capture_query_entry.entered || self.capture_query.is_some() { return; }
        let entry = &mut self.capture_query_entry;
        entry.entered = true;
        entry.arm = Some(lifecycle.arm_operation_observation_post_v1(session, socket));
        if !matches!(entry.arm, Some(Ok(()))) { entry.first = Some(First::Arm); return; }
        entry.demand = Some(std::mem::size_of::<OriginalStorageCaptureQueryV3>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .map(|bytes| ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes }));
        if let Some(Ok(demand)) = entry.demand.as_ref() {
            entry.payment = Some(lifecycle.reserve_domain_additional_v1(session, socket, *demand));
            if !matches!(entry.payment, Some(Ok(()))) { entry.first = Some(First::Payment); }
        } else { entry.first = Some(First::Demand); }
        if entry.first.is_none() {
            self.capture_query = Some(OriginalStorageCaptureQueryV3::new());
        }
        // The constructor representation and any financial refusal remain
        // resident before the independent actual F post; no nested Output
        // sampler is entered until this interval has completed positively.
        entry.post = Some(lifecycle.finish_operation_observation_post_v1(session, socket));
        if !matches!(entry.post, Some(Ok(()))) { entry.first.get_or_insert(First::Post); }
        if entry.first.is_some() { return; }
        let Some(original) = self.capture_query.as_mut() else { std::process::abort(); };
        self.runtime.query_original_capture_ongoing_v3(request, output, lifecycle, session, socket, original);
    }

    /// Borrows the canonical historical query only after all real lower posts.
    #[must_use]
    pub fn original_capture_query_response_v3(&self) -> Option<&[u8]> {
        if self.capture_query_entry.first.is_some() { return None; }
        self.capture_query.as_ref()?.response_v3()
    }

    /// Borrows the same actual query request retained after genuine prepayment.
    #[must_use]
    pub fn original_capture_query_request_v3(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        self.capture_query.as_ref()?.request_v3()
    }

    /// Borrows the first query cause without moving its native originals.
    #[must_use]
    pub fn original_capture_query_failure_v3<'cause>(&'cause self, output: &'cause StorageExecutionOutputCustodyV1)
        -> Option<&'cause (dyn std::error::Error + 'static)>
    {
        self.capture_query_entry.failure()
            .or_else(|| self.capture_query.as_ref()?.failure_v3(output))
    }

    /// Retires this positive historical query after a real authenticated successor.
    ///
    /// The Session caller must already have admitted the successor's signed
    /// predecessor link against its own current writer. This comparison creates
    /// no response or work permission and never resets a failed owner/account.
    ///
    /// # Errors
    /// Refuses an absent/failed original or a foreign Session/sequence/direction.
    pub fn retire_original_capture_query_v3(
        &mut self,
        successor: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), DormantStorageBrokerCallErrorV1> {
        let original = self.capture_query.as_ref().ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
        let previous = original.request_v3().ok_or(DormantStorageBrokerCallErrorV1::StaleKernel)?;
        if self.capture_query_entry.first.is_some() || original.response_v3().is_none()
            || successor.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || successor.session_binding() != previous.session_binding()
            || previous.client_sequence().checked_add(1) != Some(successor.client_sequence())
        { return Err(DormantStorageBrokerCallErrorV1::StaleKernel); }
        drop(self.capture_query.take());
        self.capture_query_entry = QueryEntryOriginalV3::new();
        Ok(())
    }
}
