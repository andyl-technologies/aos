//! Same-owner authenticated Storage connections after positive retirement.
//!
//! The existing listener, HELLO reducer, floor and Native writer remain shared.
//! The resident native identity spans the connection; short exclusive guards
//! cover each actual operation and end only after positive carrier disposal. No startup stage, role key or journal lock is reopened here.

use super::*;
mod execution_availability;
pub(crate) use execution_availability::ProductionStorageExecutionAvailabilityOriginalV2;
use aos_sandbox::{StorageLifecycleSessionLoanV1, StoragePrepareReceivingLoanV1};
use crate::production_activation::StorageRetainedSocketAcceptanceV1;
use crate::handshake::retained_storage_session::StorageRetainedSessionHandshakeV1;

use super::storage_prepare::{Cause, StorageSessionChecks, StorageSessionRetirementV1, RetirementCause};
use crate::{
    DormantBrokerExecutionFailureV1, DormantBrokerResponseSendProgressV1,
    DormantBrokerSessionHandshakeErrorV1, ProductionStorageBrokerDispatchErrorV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerOutcomeCommittedAdvancementV1,
};

type Dispatch = Result<ProtectedBrokerOutcomeCommitResultV1,
    DormantBrokerExecutionFailureV1<ProductionStorageBrokerDispatchErrorV1>>;
type Send = Result<DormantBrokerResponseSendProgressV1, DormantBrokerSessionHandshakeErrorV1>;
type ReplaySend = Result<crate::DormantBrokerTerminalReplaySendProgressV1, DormantBrokerSessionHandshakeErrorV1>;

// These variants retain the actual existing opaque sender results. They add no
// response/advancement constructor and share one transport/post/disposal loop.
enum TerminalSendV1 {
    Advancement(Send),
    Replay(ReplaySend),
}

enum PendingTerminalV1 {
    Advancement(ProtectedBrokerOutcomeCommittedAdvancementV1),
    Replay(crate::DormantBrokerTerminalReplayV1),
}

impl TerminalSendV1 {
    fn send_once(
        session: &mut DormantAuthenticatedBrokerSessionV1,
        pending: PendingTerminalV1,
        attempt: &mut Option<crate::handshake::StorageResponseSendAttemptV1>,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Self {
        match pending {
            PendingTerminalV1::Advancement(terminal) =>
                Self::Advancement(session.send_storage_response_receiving_v3(terminal, attempt, receiving)),
            PendingTerminalV1::Replay(replay) =>
                Self::Replay(session.send_storage_terminal_replay_receiving_v3(replay, attempt, receiving)),
        }
    }

    fn is_sent(&self) -> bool {
        matches!(self, Self::Advancement(Ok(DormantBrokerResponseSendProgressV1::Sent(_)))
            | Self::Replay(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::Sent(_))))
    }

    fn is_pending(&self) -> bool {
        matches!(self, Self::Advancement(Ok(DormantBrokerResponseSendProgressV1::Pending(_)))
            | Self::Replay(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::Pending(_))))
    }

    fn into_pending(self) -> PendingTerminalV1 {
        match self {
            Self::Advancement(Ok(DormantBrokerResponseSendProgressV1::Pending(terminal))) =>
                PendingTerminalV1::Advancement(terminal),
            Self::Replay(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::Pending(replay))) =>
                PendingTerminalV1::Replay(replay),
            _ => std::process::abort(),
        }
    }

    fn compare_terminal(&self, session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>)
        -> Result<(), crate::BrokerSessionSecurityError>
    {
        match self {
            Self::Advancement(Ok(DormantBrokerResponseSendProgressV1::Sent(terminal))) =>
                session.compare_storage_terminal_receiving_v3(terminal, receiving),
            Self::Replay(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::Sent(replay))) =>
                session.compare_storage_replay_receiving_v3(replay, receiving),
            _ => std::process::abort(),
        }
    }

    fn into_terminal(self) -> crate::recovery::RetainedStorageTerminalV1 {
        match self {
            Self::Advancement(Ok(DormantBrokerResponseSendProgressV1::Sent(terminal))) =>
                terminal.into_retained_storage_terminal_v1(),
            Self::Replay(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::Sent(replay))) =>
                replay.into_retained_storage_terminal_v1(),
            _ => std::process::abort(),
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Advancement(Err(cause)) | Self::Replay(Err(cause)) => Some(cause),
            Self::Advancement(Ok(DormantBrokerResponseSendProgressV1::RecoveryRequired { error, .. })) => Some(error),
            Self::Replay(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::RecoveryRequired { error, .. })) => Some(error),
            _ => None,
        }
    }
}

/// Reports a refused continuation while its original owners remain resident.
#[derive(Debug, thiserror::Error)]
#[error("the original Storage Session continuation is closed")]
pub struct StorageSessionContinuationClosedV1;

/// Holds the authenticated Session between short genuine-payer borrows.
///
/// The Session cannot be extracted or substituted. Multiple completed operations
/// may use the same socket; only a positive per-operation disposition permits
/// another request, and only actual shutdown permits a different connection.
#[must_use = "retain the real Session and payer through actual positive disposition"]
pub struct ProductionOriginalStorageLifecycleSessionV1 {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    availability: ProductionStorageExecutionAvailabilityOriginalV2,
    request: Option<crate::handshake::storage_lifecycle_request::StorageLifecycleRequestOriginalV1>,
    event: Option<crate::ProductionBrokerRequestEventV1>,
    dispatch: Option<Dispatch>,
    send: Option<TerminalSendV1>,
    replay_reservation: Option<Result<(), crate::BrokerSessionSecurityError>>,
    event_refusal: Option<crate::ProductionBrokerResponseErrorV1>,
    native_admission: Option<aos_sandbox::StorageReceivingClosedV1>,
    native_replay: Option<aos_sandbox::StorageReceivingClosedV1>,
    send_attempt: Option<crate::handshake::StorageResponseSendAttemptV1>,
    latest_terminal: Option<crate::recovery::RetainedStorageTerminalV1>,
    terminal_check: Option<Result<(), crate::BrokerSessionSecurityError>>,
    query_retirement: Option<Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>,
    candidate_retirement: Option<Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>,
    candidate_before_send: Option<Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>,
    candidate_after_send: Option<Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>,
    candidate_after_primary: bool,
    logical: super::storage_output::StorageOutputLifecycleOriginalV1,
    logical_retirement: Option<Result<(), super::storage_output::OriginalStorageOutputClosedV1>>,
    readiness: Option<Result<(), DormantBrokerSessionHandshakeErrorV1>>,
    raw_current: Option<bool>,
    disposal_error: Option<aos_sandbox::StorageLifecycleDisposalErrorV1>,
    domain_disposal: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    retirement: Option<StorageSessionRetirementV1>,
    checks: StorageSessionChecks,
    first: Option<Cause>,
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Parks the actual full-method Session before its first Native interval.
    #[must_use]
    pub fn begin_original_storage_lifecycle_cycle_v1(self) -> ProductionOriginalStorageLifecycleSessionV1 {
        ProductionOriginalStorageLifecycleSessionV1 {
            session: Some(self), availability: ProductionStorageExecutionAvailabilityOriginalV2::new(),
            request: None, event: None, dispatch: None, send: None, replay_reservation: None, event_refusal: None, native_admission: None, native_replay: None,
            send_attempt: None, latest_terminal: None, terminal_check: None, query_retirement: None, candidate_retirement: None,
            candidate_before_send: None, candidate_after_send: None, candidate_after_primary: false,
            logical: super::storage_output::StorageOutputLifecycleOriginalV1::new(), logical_retirement: None,
            readiness: None, raw_current: None, disposal_error: None,
            domain_disposal: None, retirement: None, checks: StorageSessionChecks::empty(), first: None,
        }
    }
}

impl Drop for ProductionOriginalStorageLifecycleSessionV1 {
    fn drop(&mut self) {
        if self.session.is_some() {
            std::process::abort();
        }
    }
}

impl ProductionOriginalStorageLifecycleSessionV1 {
    /// Joins the same positively disposed initial HELLO to full-method service.
    ///
    /// # Errors
    /// Refuses another initial socket/writer or any prior native failure. The
    /// real Session stays resident in this owner on every refusal.
    pub fn initialize_initial_v1(
        &mut self,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), StorageSessionContinuationClosedV1> {
        let Some(session) = self.session.as_ref() else { return Err(StorageSessionContinuationClosedV1); };
        match session.begin_initial_storage_lifecycle_v1(receiving) {
            Ok(guard) => {
                guard.park_between_operations_v1();
                Ok(())
            }
            Err(_) => {
                self.first.get_or_insert(Cause::Closed);
                Err(StorageSessionContinuationClosedV1)
            }
        }
    }

    /// Retires the actual completed full-method transport into the same owner.
    ///
    /// # Errors
    /// Refuses outstanding request carriers, an absent terminal or any actual
    /// end/terminal/floor/service failure. The whole Session stays resident.
    pub fn retire_session_v1(
        &mut self,
        original: &mut StoragePrepareReceivingLoanV1<'_>,
        deadline: u64,
    ) -> Result<ProductionStorageSessionContinuationV1, StorageSessionContinuationClosedV1> {
        self.availability.require_retirement_v2().map_err(|_| StorageSessionContinuationClosedV1)?;
        if self.first.is_some() || self.request.is_some() || self.event.is_some()
            || self.dispatch.is_some() || self.send.is_some() || self.retirement.is_some()
        {
            return Err(StorageSessionContinuationClosedV1);
        }
        self.retirement = Some(StorageSessionRetirementV1::new());
        let Some(session) = self.session.as_mut() else { return Err(StorageSessionContinuationClosedV1); };
        let Some(terminal) = self.latest_terminal.as_ref() else { return Err(StorageSessionContinuationClosedV1); };
        let Some(retirement) = self.retirement.as_mut() else { std::process::abort(); };
        let mut native = match session.resume_storage_lifecycle_v1(original) {
            Ok(native) => native,
            Err(error) => {
                retirement.entry_error = Some(error);
                retirement.first = Some(RetirementCause::Entry);
                retirement.observe_terminal_owner_v1(session, terminal, None, 1, deadline);
                return Err(StorageSessionContinuationClosedV1);
            }
        };
        retirement.observe_terminal_owner_v1(session, terminal, Some(&mut native), 0, deadline);
        if retirement.first.is_some() {
            return Err(StorageSessionContinuationClosedV1);
        }
        retirement.end = Some(session.end_storage_session_transport_v1());
        let Some(ended) = retirement.end.take() else { std::process::abort(); };
        let mut positive = match session.prepare_storage_transport_disposal_v1(&mut native, ended) {
            Ok(positive) => positive,
            Err(error) => {
                retirement.native_error = Some(error);
                retirement.first.get_or_insert(RetirementCause::Native);
                retirement.observe_terminal_owner_v1(session, terminal, None, 1, deadline);
                return Err(StorageSessionContinuationClosedV1);
            }
        };
        match positive.borrow_transport_post_receiving_v3() {
            Ok(source) => retirement.observe_terminal_owner_v1(session, terminal, Some(source), 1, deadline),
            Err(cause) => {
                retirement.entry_error = Some(cause);
                retirement.first.get_or_insert(RetirementCause::Entry);
            }
        }
        if retirement.first.is_some() {
            return Err(StorageSessionContinuationClosedV1);
        }

        let session = match self.session.take() { Some(session) => session, None => std::process::abort() };
        let terminal = match self.latest_terminal.take() { Some(terminal) => terminal, None => std::process::abort() };
        let owner = session.into_retained_storage_terminal_owner_v1(terminal);
        self.retirement = None;
        positive.complete_after_disposal_v1();
        Ok(ProductionStorageSessionContinuationV1 { owner: Some(owner), acceptance: None, handshake: None })
    }

    /// Borrows the same authenticated transport for readiness polling.
    ///
    /// # Errors
    /// Refuses a completed or unusable carrier; this grants no dispatch authority.
    pub fn as_fd(&self) -> Result<std::os::fd::BorrowedFd<'_>, crate::DormantBrokerSessionHandshakeErrorV1> {
        match self.session.as_ref() {
            Some(session) => session.as_fd(),
            None => Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole),
        }
    }

    /// Borrows the genuine original payer's first actual refusal.
    #[must_use]
    pub fn receiving_failure<'owner>(
        &self,
        receiving: &'owner StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        receiving.failure()
    }

    /// Borrows the actual request reducer's retained first returned refusal.
    ///
    /// Native original causes remain separately available through
    /// `receiving_failure`; existing coarse Security projections are preserved.
    #[must_use]
    pub fn request_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.request.as_ref().and_then(|request| request.failure())
    }

    /// Receives and retains the next funded request on this actual Session.
    ///
    /// The same raw/admission/initial-or-successor CAS engine serves ordinary
    /// Storage. This entry keeps its event private until the corresponding
    /// funded domain consumer and positive operation disposition are connected.
    /// It cannot be called again while that actual operation remains resident.
    ///
    /// # Errors
    /// Keeps the real Session, payer, raw record, first cause and exact CAS
    /// recovery target on payment, admission, currentness or cutoff refusal.
    fn receive_next_request_v1(
        &mut self,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        deadline: u64,
    ) -> Result<(), StorageSessionContinuationClosedV1> {
        if self.first.is_some() || self.request.is_some() || self.event.is_some() {
            return Err(StorageSessionContinuationClosedV1);
        }
        if let Some(terminal) = &self.latest_terminal {
            let Some(session) = self.session.as_mut() else {
                return Err(StorageSessionContinuationClosedV1);
            };
            self.terminal_check = Some(session.compare_storage_terminal_owner_receiving_v3(terminal, receiving));
            if !matches!(self.terminal_check, Some(Ok(()))) {
                self.first = Some(Cause::Closed);
                return Err(StorageSessionContinuationClosedV1);
            }
        }
        self.request = Some(crate::handshake::storage_lifecycle_request::StorageLifecycleRequestOriginalV1::new());
        let Some(session) = self.session.as_mut() else {
            return Err(StorageSessionContinuationClosedV1);
        };
        let Some(original) = self.request.as_mut() else { std::process::abort(); };
        self.event = session.receive_original_storage_lifecycle_request_v1(
            original, receiving, deadline, self.latest_terminal.as_ref(),
        );
        if self.event.is_some() {
            Ok(())
        } else {
            self.first = Some(Cause::Receive);
            Err(StorageSessionContinuationClosedV1)
        }
    }
    fn bookend_v1(&mut self, receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>, index: usize, deadline: u64) -> bool {
        let Some(session) = self.session.as_mut() else { return false; };
        let current = session.require_storage_lifecycle_current_v1(receiving);
        if let Some(cause) = self.checks.observe(session, current, receiving, index, deadline) {
            self.first.get_or_insert(cause);
        }
        self.first.is_none()
    }

    /// Completes one authenticated finite method on the same resident paid Session.
    ///
    /// The original receipt remains resident through shared admission/effects,
    /// real terminal CAS, actual Sent, raw-subject checks and independent posts.
    /// Only their joint positive disposition permits the next same-socket
    /// operation; shutdown is a separate transport retirement.
    ///
    /// # Errors
    /// Retains real raw/native/effect/commit/send/recovery owners on any refusal.
    /// Each method uses its existing purpose-closed domain and native payer.
    pub fn serve_original_storage_apply_request_v1(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: Option<&mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1>,
        original: &mut StoragePrepareReceivingLoanV1<'_>,
        deadline: u64,
    ) -> Result<(), StorageSessionContinuationClosedV1> {
        let Some(session) = self.session.as_ref() else {
            return Err(StorageSessionContinuationClosedV1);
        };
        let mut receiving = match session.resume_storage_lifecycle_v1(original) {
            Ok(receiving) => receiving,
            Err(_) => {
                self.first.get_or_insert(Cause::Closed);
                return Err(StorageSessionContinuationClosedV1);
            }
        };
        self.serve_apply_inner_v1(storage, output, &mut receiving, deadline)?;
        receiving.park_between_operations_v1();
        Ok(())
    }

    fn serve_apply_inner_v1(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        mut output: Option<&mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1>,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        deadline: u64,
    ) -> Result<(), StorageSessionContinuationClosedV1> {
        if self.first.is_some() || self.dispatch.is_some() || self.send.is_some() {
            return Err(StorageSessionContinuationClosedV1);
        }
        if self.availability.require_method_v2(
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2,
        ).is_err() {
            self.first = Some(Cause::Closed);
            return Err(StorageSessionContinuationClosedV1);
        }
        if self.request.is_none() {
            self.receive_next_request_v1(receiving, deadline)?;
        }
        if matches!(self.event, Some(crate::ProductionBrokerRequestEventV1::InFlightReplay(_))) {
            let replay = match self.event.take() {
                Some(crate::ProductionBrokerRequestEventV1::InFlightReplay(replay)) => replay,
                _ => std::process::abort(),
            };
            match replay.into_unobserved_request() {
                Ok(request) => self.event = Some(crate::ProductionBrokerRequestEventV1::Request(request)),
                Err(replay) => {
                    self.event = Some(crate::ProductionBrokerRequestEventV1::InFlightReplay(replay));
                    self.event_refusal = Some(crate::ProductionBrokerResponseErrorV1::OutcomeRecovery);
                    self.first = Some(Cause::Closed);
                    return Err(StorageSessionContinuationClosedV1);
                }
            }
        }
        if matches!(self.event, Some(crate::ProductionBrokerRequestEventV1::TerminalReplay(_))) {
            return self.serve_terminal_replay_v1(storage, output, receiving, deadline);
        }
        let Some(crate::ProductionBrokerRequestEventV1::Request(request)) = self.event.as_ref() else {
            self.first = Some(Cause::Closed);
            return Err(StorageSessionContinuationClosedV1);
        };
        if self.logical.request().is_some() {
            let Some(session) = self.session.as_ref() else { std::process::abort(); };
            self.logical_retirement = Some(self.logical.retire_on_successor_v1(request, session));
            if !matches!(self.logical_retirement, Some(Ok(()))) {
                self.first = Some(Cause::Closed);
                return Err(StorageSessionContinuationClosedV1);
            }
        }
        if storage.original_capture_candidate_request().is_some() {
            self.candidate_retirement = Some(request.retire_original_storage_capture_candidate(storage));
            if !matches!(self.candidate_retirement, Some(Ok(()))) {
                self.first = Some(Cause::Closed);
                return Err(StorageSessionContinuationClosedV1);
            }
        }
        if storage.original_capture_query_request_v3().is_some() {
            self.query_retirement = Some(request.retire_original_storage_capture_query_v3(storage));
            if !matches!(self.query_retirement, Some(Ok(()))) {
                self.first = Some(Cause::Closed);
                return Err(StorageSessionContinuationClosedV1);
            }
        }
        use aos_proto::aos::sandbox::local::v1::BrokerMethod;
        // The authenticated method chooses only an existing same-F engine.
        // Signed admission, TPM floors, Host45 and domain posts remain inside
        // their canonical method owners; this roster creates no readiness.
        let method = request.method();
        if self.availability.require_method_v2(method).is_err() {
            self.first = Some(Cause::Closed);
            return Err(StorageSessionContinuationClosedV1);
        }
        if !matches!(method,
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY
                | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
                | BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT
                | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
                | BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
                | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
                | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1)
                && method != BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2
        {
            self.first = Some(Cause::Closed);
            return Err(StorageSessionContinuationClosedV1);
        }
        let deadline = deadline.min(request.original_storage_prepare_deadline());
        if !self.bookend_v1(receiving, 0, deadline) {
            return Err(StorageSessionContinuationClosedV1);
        }
        let Some(crate::ProductionBrokerRequestEventV1::Request(request)) = self.event.take() else {
            std::process::abort();
        };
        let Some(session) = self.session.as_mut() else { std::process::abort(); };
        self.dispatch = Some(session.dispatch_storage_lifecycle_request_and_commit_v1(
            request, storage, output.as_deref_mut(), &mut self.logical, &mut self.availability,
            receiving, &mut self.native_admission,
        ));
        if !matches!(self.dispatch, Some(Ok(ProtectedBrokerOutcomeCommitResultV1::Committed(_)))) {
            self.first = Some(Cause::Dispatch);
        }
        if !self.bookend_v1(receiving, 1, deadline) {
            return Err(StorageSessionContinuationClosedV1);
        }
        let committed = match self.dispatch.take() {
            Some(Ok(ProtectedBrokerOutcomeCommitResultV1::Committed(committed))) => committed,
            _ => std::process::abort(),
        };
        self.send_to_completion_v1(storage, output, receiving, deadline, PendingTerminalV1::Advancement(committed))?;
        if self.availability.require_method_v2(method).is_err() {
            self.first = Some(Cause::Closed);
            return Err(StorageSessionContinuationClosedV1);
        }
        self.prepare_positive_controls_v1(receiving, deadline)?;
        let sent = self.take_native_sent_v1()?;
        let Some(session) = self.session.as_ref() else { std::process::abort(); };
        let native = match session.prepare_storage_operation_disposal_v1(receiving, sent) {
            Ok(native) => native,
            Err(error) => {
                self.disposal_error = Some(error);
                self.first = Some(Cause::Closed);
                return Err(StorageSessionContinuationClosedV1);
            }
        };
        match method {
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2 => {
                // Only this request's completed wire controls retire. The
                // actual Session/F/floor and availability capsule stay resident
                // across the preaccept response and accepted-source binding.
                self.dispose_positive_controls_v1();
                native.complete_after_disposal_v1();
            }
            BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
            | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1 => {
                // These actual domain engines intentionally never enter State
                // encoding. Their completed originals remain resident until an
                // authenticated successor retires them; only controls end here.
                self.domain_disposal = Some(storage.require_original_output_response_disposal_v2(&native));
                if !matches!(self.domain_disposal, Some(Ok(()))) {
                    self.first = Some(Cause::Closed);
                    return Err(StorageSessionContinuationClosedV1);
                }
                self.dispose_positive_controls_v1();
                native.complete_after_disposal_v1();
            }
            BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1 => {
                self.domain_disposal = Some(storage.require_original_capture_response_disposal_v3(&native));
                if !matches!(self.domain_disposal, Some(Ok(()))) {
                    self.first = Some(Cause::Closed);
                    return Err(StorageSessionContinuationClosedV1);
                }
                // Capture's mounted worker/F remains occupied after this60
                // response. Only its676 continuation can retire that owner.
                self.dispose_positive_controls_v1();
                native.complete_after_disposal_v1();
            }
            _ => {
                let positive = match storage.prepare_lifecycle_reconciliation_disposal_v1(native) {
                    Ok(positive) => positive,
                    Err(_) => {
                        self.first = Some(Cause::Closed);
                        return Err(StorageSessionContinuationClosedV1);
                    }
                };
                self.dispose_positive_controls_v1();
                positive.complete_after_disposal_v1();
            }
        }
        Ok(())
    }

    fn serve_terminal_replay_v1(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: Option<&mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1>,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        deadline: u64,
    ) -> Result<(), StorageSessionContinuationClosedV1> {
        if !self.bookend_v1(receiving, 0, deadline) {
            return Err(StorageSessionContinuationClosedV1);
        }
        let Some(session) = self.session.as_ref() else { std::process::abort(); };
        let Some(crate::ProductionBrokerRequestEventV1::TerminalReplay(replay)) = self.event.as_ref() else {
            std::process::abort();
        };
        if let Err(cause) = session.arm_storage_request_post_v1(receiving) {
            self.native_replay = Some(cause);
            self.first = Some(Cause::Closed);
            return Err(StorageSessionContinuationClosedV1);
        }
        self.replay_reservation = Some(session.reserve_storage_lifecycle_replay_v1(
            replay, receiving, &mut self.native_replay,
        ));
        let post = session.finish_storage_operation_post_v1(receiving);
        if !matches!(self.replay_reservation, Some(Ok(()))) {
            self.first = Some(Cause::Closed);
        } else if let Err(cause) = post {
            self.native_replay = Some(cause);
            self.first = Some(Cause::Closed);
        }
        if !self.bookend_v1(receiving, 1, deadline) {
            return Err(StorageSessionContinuationClosedV1);
        }
        let replay = match self.event.take() {
            Some(crate::ProductionBrokerRequestEventV1::TerminalReplay(replay)) => replay,
            _ => std::process::abort(),
        };
        self.send_to_completion_v1(storage, output, receiving, deadline, PendingTerminalV1::Replay(replay))?;
        self.prepare_positive_controls_v1(receiving, deadline)?;
        let sent = self.take_native_sent_v1()?;
        let Some(session) = self.session.as_ref() else { std::process::abort(); };
        let native = match session.prepare_storage_operation_disposal_v1(receiving, sent) {
            Ok(native) => native,
            Err(error) => {
                self.disposal_error = Some(error);
                self.first = Some(Cause::Closed);
                return Err(StorageSessionContinuationClosedV1);
            }
        };
        // Exact terminal replay creates no State interval or domain mutation.
        // Its SAME actual Sent/currentness/Native proof permits only disposal
        // of this operation's successful transport/control copies.
        self.dispose_positive_controls_v1();
        native.complete_after_disposal_v1();
        Ok(())
    }

    fn send_to_completion_v1(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        mut output: Option<&mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1>,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        deadline: u64,
        mut pending: PendingTerminalV1,
    ) -> Result<(), StorageSessionContinuationClosedV1> {
        loop {
            let Some(session) = self.session.as_mut() else { std::process::abort(); };
            let candidate = storage.original_capture_candidate_request().is_some();
            if candidate {
                self.candidate_before_send = Some(match output.as_deref_mut() {
                    Some(output) => session.prepare_storage_capture_candidate_delivery_v1(storage, output, receiving),
                    None => Err(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel),
                });
                if !matches!(self.candidate_before_send, Some(Ok(()))) {
                    // No send has occurred; the actual terminal remains held.
                    self.send = Some(match pending {
                        PendingTerminalV1::Advancement(terminal) => TerminalSendV1::Advancement(Ok(DormantBrokerResponseSendProgressV1::Pending(terminal))),
                        PendingTerminalV1::Replay(replay) => TerminalSendV1::Replay(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::Pending(replay))),
                    });
                    self.first = Some(Cause::Closed);
                    return Err(StorageSessionContinuationClosedV1);
                }
            }
            if session.arm_storage_operation_post_v1(receiving).is_err() {
                // No send occurred. Keep the same actual protected terminal.
                self.send = Some(match pending {
                    PendingTerminalV1::Advancement(terminal) =>
                        TerminalSendV1::Advancement(Ok(DormantBrokerResponseSendProgressV1::Pending(terminal))),
                    PendingTerminalV1::Replay(replay) =>
                        TerminalSendV1::Replay(Ok(crate::DormantBrokerTerminalReplaySendProgressV1::Pending(replay))),
                });
                if candidate {
                    self.candidate_after_send = Some(match output.as_deref_mut() {
                        Some(output) => session.finish_storage_capture_candidate_delivery_v1(storage, output, receiving),
                        None => Err(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel),
                    });
                }
                self.first = Some(Cause::Closed);
                return Err(StorageSessionContinuationClosedV1);
            }
            self.send = Some(TerminalSendV1::send_once(session, pending, &mut self.send_attempt, receiving));
            // The full candidate source after is already prepaid/prearmed.
            // Run it for both actual send success and native transport failure,
            // before the sender's independently owed common service post.
            if candidate {
                self.candidate_after_send = Some(match output.as_deref_mut() {
                    Some(output) => session.finish_storage_capture_candidate_delivery_v1(storage, output, receiving),
                    None => Err(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel),
                });
            }
            let post = session.finish_storage_operation_post_v1(receiving);
            let native_refused = self.send_attempt.as_ref()
                .is_some_and(crate::handshake::StorageResponseSendAttemptV1::refuses_terminal_progress_v1);
            if native_refused || !self.send.as_ref().is_some_and(|sent| sent.is_sent() || sent.is_pending()) {
                self.first = Some(Cause::Send);
            }
            if candidate && !matches!(self.candidate_after_send, Some(Ok(()))) && self.first.is_none() {
                self.candidate_after_primary = true;
                self.first = Some(Cause::Closed);
            }
            if post.is_err() {
                self.first.get_or_insert(Cause::Closed);
            }
            if !self.bookend_v1(receiving, 2, deadline) {
                return Err(StorageSessionContinuationClosedV1);
            }
            if self.send.as_ref().is_some_and(TerminalSendV1::is_sent) {
                return Ok(());
            }
            let Some(session) = self.session.as_ref() else { std::process::abort(); };
            self.readiness = Some(super::wait_output_original(session, true, deadline));
            if !matches!(self.readiness, Some(Ok(()))) {
                self.first = Some(Cause::Readiness);
                return Err(StorageSessionContinuationClosedV1);
            }
            if !self.bookend_v1(receiving, 2, deadline) {
                return Err(StorageSessionContinuationClosedV1);
            }
            pending = match self.send.take() {
                Some(sent) => sent.into_pending(),
                None => std::process::abort(),
            };
        }
    }

    fn prepare_positive_controls_v1(
        &mut self,
        receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>,
        deadline: u64,
    ) -> Result<(), StorageSessionContinuationClosedV1> {
        let Some(session) = self.session.as_mut() else { std::process::abort(); };
        let Some(sent) = self.send.as_ref() else { std::process::abort(); };
        self.terminal_check = Some(sent.compare_terminal(session, receiving));
        let raw = match self.request.as_mut().and_then(|original| original.completed_receipt()) {
            Some(receipt) => session.recheck_storage_prepare_replay_transport_v1(receipt),
            None => false,
        };
        self.raw_current = Some(raw);
        if !matches!(self.terminal_check, Some(Ok(()))) || !raw {
            self.first = Some(Cause::Closed);
            return Err(StorageSessionContinuationClosedV1);
        }
        if self.bookend_v1(receiving, 2, deadline) { Ok(()) } else { Err(StorageSessionContinuationClosedV1) }
    }

    fn take_native_sent_v1(&mut self)
        -> Result<aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1, StorageSessionContinuationClosedV1>
    {
        match self.send_attempt.as_mut().and_then(|attempt| attempt.take_native_sent_v1()) {
            Some(sent) => Ok(sent),
            None => {
                self.first = Some(Cause::Send);
                Err(StorageSessionContinuationClosedV1)
            }
        }
    }

    fn dispose_positive_controls_v1(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.dispose_storage_positive_replays_v3();
        }
        let terminal = match self.send.take() {
            Some(sent) => sent.into_terminal(),
            None => std::process::abort(),
        };
        // All fallible checks ran with both old/new terminal and raw/control
        // owners resident. No observation or admission follows these drops.
        drop(self.latest_terminal.replace(terminal));
        drop(self.request.take());
        drop(self.event.take());
        drop(self.dispatch.take());
        drop(self.send_attempt.take());
        self.replay_reservation = None;
        self.native_admission = None;
        self.native_replay = None;
        self.terminal_check = None;
        self.domain_disposal = None;
        self.query_retirement = None;
        self.candidate_retirement = None;
        self.candidate_before_send = None;
        self.candidate_after_send = None;
        self.candidate_after_primary = false;
        self.logical_retirement = None;
        self.readiness = None;
        self.raw_current = None;
        self.checks = StorageSessionChecks::empty();
    }

    /// Resolves only genuine receiving projections through their resident owner.
    ///
    /// Concrete earlier IO/decoder/semantic errors retain priority over a later
    /// independent original post. No native error is cloned or reconstructed.
    #[must_use]
    pub fn operation_failure_with_storage<'owner>(
        &'owner self,
        storage: &'owner aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &'owner StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        let cause = self.operation_failure()?;
        let native_projection = (self.first == Some(Cause::Dispatch) && self.native_admission.is_some())
            || (self.first == Some(Cause::Closed) && self.native_replay.is_some());
        if native_projection {
            return Some(receiving.failure().unwrap_or(cause));
        }
        let domain_projection = matches!(self.dispatch.as_ref(),
            Some(Err(DormantBrokerExecutionFailureV1::OutcomeUnknown {
                error: crate::DormantBrokerExecutionErrorV1::Domain(
                    ProductionStorageBrokerDispatchErrorV1::Operation(
                        aos_sandbox_storage::DormantStorageBrokerCallErrorV1::Runtime(
                            aos_sandbox_storage::StorageRuntimeError::Receiving,
                        ),
                    ) | ProductionStorageBrokerDispatchErrorV1::Inventory(
                        aos_sandbox_storage::StorageRuntimeError::Receiving,
                    ),
                ), ..
            })));
        let cause = if self.first == Some(Cause::Dispatch) && domain_projection {
            storage.lifecycle_apply_failure_v1().unwrap_or(cause)
        } else {
            cause
        };
        let projection = cause.is::<aos_sandbox::StorageReceivingClosedV1>()
            || cause.is::<StorageSessionContinuationClosedV1>()
            || matches!(cause.downcast_ref::<aos_sandbox_storage::StorageRuntimeError>(),
                Some(aos_sandbox_storage::StorageRuntimeError::Receiving))
            || matches!(cause.downcast_ref::<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>(),
                Some(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::Runtime(
                    aos_sandbox_storage::StorageRuntimeError::Receiving,
                )));
        Some(if projection { self.receiving_failure(receiving).unwrap_or(cause) } else { cause })
    }

    pub fn operation_failure_with_output_v3<'owner>(
        &'owner self,
        storage: &'owner aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: Option<&'owner aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1>,
        receiving: &'owner StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        let cause = self.operation_failure_with_storage(storage, receiving)?;
        let candidate_source = (self.first == Some(Cause::Dispatch)
            && storage.original_capture_candidate_request().is_some())
            || (self.first == Some(Cause::Closed)
                && (matches!(self.candidate_before_send, Some(Err(_)))
                    || self.candidate_after_primary));
        if candidate_source {
            if let Some(original) = output.and_then(|output| storage.original_capture_candidate_receiving_failure_v1(output)) {
                return Some(if original.is::<aos_sandbox::StorageReceivingClosedV1>() {
                    receiving.failure().unwrap_or(original)
                } else { original });
            }
        }

        let query_domain = self.first == Some(Cause::Dispatch) && matches!(self.dispatch.as_ref(),
            Some(Err(DormantBrokerExecutionFailureV1::OutcomeUnknown {
                error: crate::DormantBrokerExecutionErrorV1::Domain(
                    ProductionStorageBrokerDispatchErrorV1::Operation(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)
                ), ..
            })));
        if query_domain {
            if let Some(original) = self.logical.failure(self.session.as_ref()) {
                let capture_projection = self.logical.request().is_some_and(|request|
                    request.method() == aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1)
                    && matches!(original.downcast_ref::<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>(),
                        Some(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel));
                if capture_projection {
                    if let Some(cause) = output.and_then(|output| storage.original_capture_reserve_failure_v3(output)) {
                        return Some(if cause.is::<aos_sandbox::StorageReceivingClosedV1>() { receiving.failure().unwrap_or(cause) } else { cause });
                    }
                }
                let projection = original.is::<aos_sandbox::StorageReceivingClosedV1>()
                    || self.logical.financial_projection_selected_v1();
                return Some(if projection { receiving.failure().unwrap_or(original) } else { original });
            }
        }
        if query_domain {
            if let Some(original) = output.and_then(|output| storage.original_capture_query_failure_v3(output)) {
                return Some(if original.is::<aos_sandbox::StorageReceivingClosedV1>() {
                    receiving.failure().unwrap_or(original)
                } else { original });
            }
        }
        Some(cause)
    }

    /// Borrows the exact selected operation cause while all its owners remain.
    #[must_use]
    pub fn operation_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if matches!(self.first, Some(Cause::Dispatch | Cause::Closed)) {
            if let Some(cause) = self.availability.failure() { return Some(cause); }
        }
        if let Some(retirement) = &self.retirement {
            if let Some(cause) = retirement.failure() {
                return Some(cause);
            }
        }
        match self.first? {
            Cause::Receive => self.request_failure(),
            Cause::Dispatch => match self.dispatch.as_ref()? {
                Err(DormantBrokerExecutionFailureV1::BeforeEffect { error, .. }) => Some(error),
                Err(DormantBrokerExecutionFailureV1::OutcomeUnknown { error, .. }) => Some(error),
                Ok(ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. }) => Some(error),
                _ => Some(&StorageSessionContinuationClosedV1),
            },
            Cause::Send => self.send_attempt.as_ref().and_then(|attempt| attempt.failure())
                .or_else(|| self.send.as_ref().and_then(TerminalSendV1::failure)),
            Cause::Readiness => self.readiness.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Cause::Clock(_) | Cause::Receiving(_) | Cause::Current(_) => self.checks.failure(self.first?),
            _ => self.candidate_retirement.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error)
                .or_else(|| self.query_retirement.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
                .or_else(|| self.request.as_ref().filter(|_| self.raw_current == Some(false))
                .and_then(|request| request.transport_post_failure()))
                .or_else(|| self.event_refusal.as_ref().map(|cause| cause as &dyn std::error::Error))
                .or_else(|| self.native_replay.as_ref().map(|cause| cause as &dyn std::error::Error))
                .or_else(|| self.replay_reservation.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error))
                .or_else(|| self.disposal_error.as_ref().map(|cause| cause as &dyn std::error::Error))
                .or_else(|| self.domain_disposal.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error))
                .or_else(|| self.terminal_check.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error))
                .or(Some(&StorageSessionContinuationClosedV1)),
        }
    }

}

impl ProductionStorageSessionContinuationV1 {
    /// Borrows an actual retained acceptance or HELLO refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.acceptance.as_ref().and_then(StorageRetainedSocketAcceptanceV1::failure)
            .or_else(|| self.handshake.as_ref().and_then(StorageRetainedSessionHandshakeV1::failure))
    }

    /// Accepts the next fixed Storage connection using the same original writer.
    ///
    /// A genuine native poll zero with no adopted socket and positive Journal,
    /// service and listener posts returns `None`. Those actual no-acquisition
    /// observations are disposed before a later finite accept interval. Every
    /// admitted or ambiguous failure remains owned and cannot be retried.
    /// Native opening, floor attachment and request initialization do not run.
    ///
    /// # Errors
    /// Retains acceptance, original service/name, HELLO, endpoint/floor or cutoff
    /// refusals. Native causes remain on the continuously borrowed original.
    pub fn accept_lifecycle_session_v1<'cut, 'original>(
        &mut self,
        activation: &mut crate::ProductionBrokerSessionActivationV1,
        receiving: &'cut mut StoragePrepareReceivingLoanV1<'original>,
        deadline: u64,
    ) -> Result<Option<ProductionOriginalStorageLifecycleSessionV1>, StorageSessionContinuationClosedV1> {
        if self.acceptance.is_some() || self.handshake.is_some() || self.owner.is_none() {
            return Err(StorageSessionContinuationClosedV1);
        }
        self.acceptance = Some(StorageRetainedSocketAcceptanceV1::new());
        let owner = match self.owner.as_mut() { Some(owner) => owner, None => std::process::abort() };
        let accepted = match self.acceptance.as_mut() { Some(accepted) => accepted, None => std::process::abort() };
        accepted.observe_owner(owner, receiving, 0);
        if accepted.failure().is_none() {
            let journal = owner.retained_storage_journal_v1()
                .map_err(|_| StorageSessionContinuationClosedV1)?;
            activation.accept_storage_continuation_socket_v1(journal, receiving, deadline, accepted);
        }
        accepted.observe_owner(owner, receiving, 1);
        if accepted.failure().is_some() { return Err(StorageSessionContinuationClosedV1); }
        if accepted.is_idle() {
            // No new transport/HELLO exists. Real required PID1-currentness
            // flights are separately paid/settled by their actual Native lane;
            // this clears only the successful no-acquisition accept evidence.
            self.acceptance = None;
            return Ok(None);
        }
        let socket = match accepted.take_socket() { Some(socket) => socket, None => return Err(StorageSessionContinuationClosedV1) };
        let owner = match self.owner.take() { Some(owner) => owner, None => std::process::abort() };
        self.handshake = Some(StorageRetainedSessionHandshakeV1::new(
            owner, socket, crate::handshake::OriginalBrokerColdDeadlineV1::storage_accept(deadline),
        ));
        // The initial whole owner now contains the accepted socket. Dispose
        // only successful acceptance metadata, never a transport/failed result.
        self.acceptance = None;
        let handshake = match self.handshake.as_mut() { Some(handshake) => handshake, None => std::process::abort() };
        let (session, receiving) = handshake.finish(receiving).map_err(|_| StorageSessionContinuationClosedV1)?;
        let session = crate::DormantAuthenticatedBrokerSessionV1::from_retained_storage_inner_v1(session);
        // HELLO's actual Sent, posts and control disposal already completed.
        // End only its Rust borrow; the same native wire debt/identity survives.
        receiving.park_between_operations_v1();
        self.handshake = None;
        Ok(Some(session.begin_original_storage_lifecycle_cycle_v1()))
    }
}

/// Keeps the actual selected Storage connection between daemon poll turns.
///
/// The empty owner supplies no authority. Every I/O turn borrows the genuine
/// original for its closed purpose, while positive turns return that same
/// original to Runtime so the daemon can service its other listeners.
#[must_use]
pub struct ProductionOriginalStorageConnectionV1 {
    preparation: Option<super::ProductionOriginalStoragePrepareCycleV1>,
    lifecycle: Option<ProductionOriginalStorageLifecycleSessionV1>,
    continuation: Option<ProductionStorageSessionContinuationV1>,
    started: bool,
}

impl ProductionOriginalStorageConnectionV1 {
    /// Creates an inert destination for the actual selected connection.
    #[must_use]
    pub const fn new() -> Self {
        Self { preparation: None, lifecycle: None, continuation: None, started: false }
    }

    /// Reports an actual retained socket rather than a listener to poll.
    #[must_use]
    pub fn has_active_session(&self) -> bool {
        self.preparation.is_some() || self.lifecycle.is_some()
    }

    /// Borrows the actual connected socket while its whole Session stays held.
    ///
    /// # Errors
    /// Refuses an absent or unusable active Session.
    pub fn as_fd(&self) -> Result<std::os::fd::BorrowedFd<'_>, DormantBrokerSessionHandshakeErrorV1> {
        if let Some(cycle) = &self.preparation {
            return cycle.as_fd();
        }
        if let Some(cycle) = &self.lifecycle {
            return cycle.as_fd();
        }
        Err(DormantBrokerSessionHandshakeErrorV1::EndpointRole)
    }

    /// Advances one actual listener/request turn under the same original.
    ///
    /// The signed verified required-method set chooses Preparation; argv and
    /// the full server advertisement never narrow an authenticated Session.
    /// A positive turn ends its Rust borrow only, without reopening a writer,
    /// resetting wire consumption or reclaiming any persistent history.
    ///
    /// # Errors
    /// Retains actual activation, Session, request, native and effect owners on
    /// refusal. Selected failures cannot fall through to the ordinary route.
    pub fn serve_once_v1(
        &mut self,
        activation: &mut crate::ProductionBrokerSessionActivationV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: Option<&mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1>,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
        deadline: u64,
    ) -> Result<(), StorageSessionContinuationClosedV1> {
        if let Some(cycle) = &mut self.preparation {
            return cycle.serve_production_storage_prepare_request_v1(storage, receiving, deadline)
                .map_err(|_| StorageSessionContinuationClosedV1);
        }
        if let Some(cycle) = &mut self.lifecycle {
            return cycle.serve_original_storage_apply_request_v1(storage, output, receiving, deadline);
        }
        if let Some(continuation) = &mut self.continuation {
            match continuation.accept_lifecycle_session_v1(activation, receiving, deadline)? {
                Some(session) => {
                    self.lifecycle = Some(session);
                    self.continuation = None;
                }
                None => {}
            }
            return Ok(());
        }
        if self.started {
            return Err(StorageSessionContinuationClosedV1);
        }
        self.started = true;
        let session = activation.accept_authenticated_storage_prepare_v1(deadline, receiving)
            .map_err(|_| StorageSessionContinuationClosedV1)?;
        if session.is_original_storage_preparation_profile_v1() {
            self.preparation = Some(session.begin_original_storage_prepare_cycle());
            Ok(())
        } else {
            // Park before the fallible initial-purpose join. A refusal keeps
            // the actual Session, socket and held writer on this resident owner.
            self.lifecycle = Some(session.begin_original_storage_lifecycle_cycle_v1());
            match self.lifecycle.as_mut() {
                Some(cycle) => cycle.initialize_initial_v1(receiving),
                None => std::process::abort(),
            }
        }
    }

    /// Retires the actual socket after its positive terminal and real shutdown.
    ///
    /// # Errors
    /// Refuses missing terminal/unfinished work or actual native/upper posts;
    /// the original active cycle remains resident on every negative result.
    pub fn retire_once_v1(
        &mut self,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
        deadline: u64,
    ) -> Result<(), StorageSessionContinuationClosedV1> {
        let continuation = if let Some(cycle) = &mut self.preparation {
            cycle.retire_prepared_session_v1(receiving, deadline)
                .map_err(|_| StorageSessionContinuationClosedV1)?
        } else if let Some(cycle) = &mut self.lifecycle {
            cycle.retire_session_v1(receiving, deadline)?
        } else {
            return Err(StorageSessionContinuationClosedV1);
        };
        self.continuation = Some(continuation);
        self.preparation = None;
        self.lifecycle = None;
        Ok(())
    }

    /// Borrows the chronological primary from its actual retained destination.
    #[must_use]
    pub fn failure_with_storage<'owner>(
        &'owner self,
        storage: &'owner aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receiving: &'owner StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        if let Some(cycle) = &self.preparation {
            let cause = cycle.failure_with_storage_v1(storage, receiving)
                .or_else(|| cycle.postcheck_debt())?;
            return Some(if cause.is::<aos_sandbox::StorageReceivingClosedV1>() {
                receiving.failure().unwrap_or(cause)
            } else { cause });
        }
        self.lifecycle.as_ref().and_then(|cycle| cycle.operation_failure_with_storage(storage, receiving))
            .or_else(|| self.continuation.as_ref().and_then(ProductionStorageSessionContinuationV1::failure)
                .map(|cause| if cause.is::<aos_sandbox::StorageReceivingClosedV1>() {
                    receiving.failure().unwrap_or(cause)
                } else { cause }))
    }
}

impl Default for ProductionOriginalStorageConnectionV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ProductionOriginalStorageConnectionV1 {
    /// Borrows a precise query-domain cause through the same actual Output owner.
    #[must_use]
    pub fn failure_with_storage_output_v3<'owner>(
        &'owner self,
        storage: &'owner aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: Option<&'owner aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1>,
        receiving: &'owner StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        if let Some(cycle) = &self.lifecycle {
            return cycle.operation_failure_with_output_v3(storage, output, receiving);
        }
        self.failure_with_storage(storage, receiving)
    }
}
