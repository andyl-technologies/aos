//! Complete resident Storage output and capture request cycles.

use crate::{DormantAuthenticatedBrokerSessionV1, ProductionBrokerResponseErrorV1};

use super::{ProductionBrokerDeadlineErrorV1, wait_output_original};

mod host;
mod logical;
pub(crate) use logical::{StorageOutputRequestOriginalV1, StorageOutputLifecycleOriginalV1};
use host::StorageOutputHostOriginalV1;

impl DormantAuthenticatedBrokerSessionV1 {
    /// Parks this genuine Storage session before receiving selected output work.
    ///
    /// The returned cycle retains every returned request, Host flight and
    /// terminal result. Its legacy receive/handshake engines still own their
    /// unreturned prefixes; this constructor is not whole-prefix retention,
    /// physical output capture, admission, or terminal drain.
    #[must_use]
    pub fn begin_original_storage_output_cycle(
        self,
    ) -> ProductionOriginalStorageOutputCycleV1 {
        ProductionOriginalStorageOutputCycleV1::begin(self)
    }
}

/// Retains one request's original Storage/Host carriers and returned results.
///
/// Local terminal transmission does not release the pending original. Only a
/// genuine authenticated successor admitted by the same journal can retire a
/// successful predecessor. A failed request is never replaced or retried.
/// Blank deployment, floor provisioning and physical capture remain distinct
/// prerequisites; this owner does not change method-46's installed floor gate.
/// Dropping failed custody or a selected request before its authenticated
/// successor aborts the process before those original fields are destroyed.
#[must_use = "retain selected custody until an authenticated successor retires it"]
pub struct ProductionOriginalStorageOutputCycleV1 {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    receipt: Option<crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1>,
    event: Option<crate::ProductionBrokerRequestEventV1>,
    ordinary: Option<Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerResponseErrorV1>>,
    selected: Option<OriginalStorageOutputRequestV1>,
    capture_candidate: Option<OriginalStorageCaptureRequestV1>,
    receive_deadline: Option<Result<u64, ProductionBrokerDeadlineErrorV1>>,
    poll_failure: Option<rustix::io::Errno>,
    deadline: u64,
    started: bool,
    ended: bool,
}

impl Drop for ProductionOriginalStorageOutputCycleV1 {
    fn drop(&mut self) {
        // The daemon uses explicit exit for a reported first cause. Unwind or
        // premature disposal must not release its original writers/carriers.
        if self.selected.is_some() || self.capture_candidate.is_some() || self.failure().is_some() || self.postcheck_debt().is_some() {
            std::process::abort();
        }
    }
}

struct OriginalStorageOutputRequestV1 {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    receipt: crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
    logical: StorageOutputRequestOriginalV1,
    terminal: crate::handshake::output_registration_continuation::OriginalOutputServerTerminalV1,
    deadline: u64,
    attempted: bool,
    ended: bool,
}

struct OriginalStorageCaptureRequestV1 {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    receipt: crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
    dispatch: Option<Result<
        crate::ProtectedBrokerOutcomeCommitResultV1,
        crate::DormantBrokerExecutionFailureV1<crate::ProductionStorageBrokerDispatchErrorV1>,
    >>,
    retirement: Option<Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>,
    dispatch_postcheck: Option<Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>,
    terminal: crate::production_response::OriginalCaptureCandidateResponseV1,
    deadline: u64,
    attempted: bool,
}

impl OriginalStorageCaptureRequestV1 {
    fn begin(
        session: DormantAuthenticatedBrokerSessionV1,
        receipt: crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
        deadline: u64,
    ) -> Self {
        Self {
            session: Some(session),
            receipt,
            dispatch: None,
            retirement: None,
            dispatch_postcheck: None,
            terminal: crate::production_response::OriginalCaptureCandidateResponseV1::empty(),
            deadline,
            attempted: false,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.receipt.failure() { return Some(error); }
        match &self.dispatch {
            Some(Err(crate::DormantBrokerExecutionFailureV1::BeforeEffect { error, .. })) => return Some(error),
            Some(Err(crate::DormantBrokerExecutionFailureV1::OutcomeUnknown { error, .. })) => {
                return match error {
                    crate::DormantBrokerExecutionErrorV1::Domain(crate::ProductionStorageBrokerDispatchErrorV1::Operation(
                        aos_sandbox_storage::DormantStorageBrokerCallErrorV1::CaptureCandidate(custody),
                    )) => custody.original_cause().or_else(|| custody.postcheck_debt()),
                    error => Some(error),
                };
            }
            Some(Ok(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. })) => return Some(error),
            _ => {}
        }
        if let Some(error) = self.terminal.failure() { return Some(error); }
        if let Some(Err(error)) = &self.dispatch_postcheck {
            return match error {
                aos_sandbox_storage::DormantStorageBrokerCallErrorV1::CaptureCandidate(custody) =>
                    custody.original_cause().or_else(|| custody.postcheck_debt()),
                error => Some(error),
            };
        }
        if let Some(Err(error)) = &self.retirement { return Some(error); }
        None
    }

    fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.receipt.postcheck_debt() { return Some(error); }
        if let Some(Err(error)) = &self.dispatch_postcheck {
            return match error {
                aos_sandbox_storage::DormantStorageBrokerCallErrorV1::CaptureCandidate(custody) =>
                    custody.original_cause().or_else(|| custody.postcheck_debt()),
                error => Some(error),
            };
        }
        if let Some(Err(crate::DormantBrokerExecutionFailureV1::OutcomeUnknown {
            error: crate::DormantBrokerExecutionErrorV1::Domain(crate::ProductionStorageBrokerDispatchErrorV1::Operation(
                aos_sandbox_storage::DormantStorageBrokerCallErrorV1::CaptureCandidate(custody),
            )), ..
        })) = &self.dispatch {
            if let Some(error) = custody.postcheck_debt() { return Some(error); }
        }
        self.terminal.postcheck_debt()
    }

    fn advance(
        &mut self,
        request: crate::DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) {
        if self.attempted { return; }
        self.attempted = true;
        let Some(session) = &mut self.session else { return; };
        self.dispatch = Some(session.dispatch_storage_capture_candidate_and_commit_v1(request, storage, output));
        // A terminal/currentness failure owns chronological priority. Still
        // compare the actual source after that native signing/commit boundary;
        // an already failed domain recipe is not reopened or retried.
        if matches!(&self.dispatch,
            Some(Ok(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { .. }))
            | Some(Err(crate::DormantBrokerExecutionFailureV1::OutcomeUnknown {
                error: crate::DormantBrokerExecutionErrorV1::Currentness(_), ..
            }))
        ) {
            self.dispatch_postcheck = Some(storage.recheck_original_capture_candidate_v1(output, false));
        }
        let committed = match self.dispatch.take() {
            Some(Ok(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(committed))) => committed,
            retained => {
                self.dispatch = retained;
                return;
            }
        };
        self.terminal.send_once(session, committed, storage, output, self.deadline);
    }
}

#[derive(Debug, thiserror::Error)]
#[error("original Storage output request is closed with its returned custody resident")]
pub(crate) struct OriginalStorageOutputClosedV1;

impl ProductionOriginalStorageOutputCycleV1 {
    fn begin(session: DormantAuthenticatedBrokerSessionV1) -> Self {
        Self {
            session: Some(session),
            receipt: None,
            event: None,
            ordinary: None,
            selected: None,
            capture_candidate: None,
            receive_deadline: None,
            poll_failure: None,
            deadline: 0,
            started: false,
            ended: false,
        }
    }

    /// Borrows the actual same-session descriptor for the existing daemon poll.
    ///
    /// # Errors
    /// Rejects a closed cycle or an unavailable original carrier.
    pub fn as_fd(&self) -> Result<std::os::fd::BorrowedFd<'_>, crate::DormantBrokerSessionHandshakeErrorV1> {
        if self.ended {
            return Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole);
        }
        if let Some(capture) = &self.capture_candidate {
            if let Some(session) = &capture.session { return session.as_fd(); }
        }
        if let Some(selected) = &self.selected {
            return selected.session.as_ref().ok_or(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)?.as_fd();
        }
        if let Some(Ok(session)) = &self.ordinary {
            return session.as_fd();
        }
        if let Some(session) = &self.session {
            return session.as_fd();
        }
        Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)
    }

    /// Borrows the genuine first returned cause, never an erased replacement.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = &self.poll_failure { return Some(error); }
        if let Some(Err(error)) = &self.receive_deadline { return Some(error); }
        if let Some(receipt) = &self.receipt {
            if let Some(error) = receipt.failure() { return Some(error); }
        }
        if let Some(Err(error)) = &self.ordinary { return Some(error); }
        if let Some(capture) = &self.capture_candidate {
            if let Some(error) = capture.failure() { return Some(error); }
            if capture.postcheck_debt().is_some() { return None; }
        }
        if let Some(selected) = &self.selected {
            if let Some(error) = selected.failure() { return Some(error); }
            if self.postcheck_debt().is_some() { return None; }
        }
        self.ended.then_some(&OriginalStorageOutputClosedV1 as &dyn std::error::Error)
    }

    /// Borrows later currentness debt independently of an earlier action error.
    #[must_use]
    pub fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(receipt) = &self.receipt {
            if let Some(error) = receipt.postcheck_debt() { return Some(error); }
        }
        if let Some(capture) = &self.capture_candidate {
            if let Some(error) = capture.postcheck_debt() { return Some(error); }
        }
        let selected = self.selected.as_ref()?;
        if let Some(error) = selected.receipt.postcheck_debt() { return Some(error); }
        if let Some(error) = selected.logical.postcheck_debt(selected.session.as_ref()) { return Some(error); }
        selected.terminal.postcheck_debt().map(|error| error as &dyn std::error::Error)
    }

    /// Parks the daemon's actual poll error before any later bookend or return.
    pub fn close_on_poll_failure(&mut self, error: rustix::io::Errno) {
        self.ended = true;
        if self.poll_failure.is_none() {
            self.poll_failure = Some(error);
        }
    }

    /// Drives the same request engines without replacing a failed attempt.
    /// Unit return is not success; diagnostics and original results stay owned.
    pub fn advance(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        next_receive_deadline: Result<u64, ProductionBrokerDeadlineErrorV1>,
    ) {
        if self.ended {
            return;
        }
        // The real Session was parked before the daemon's clock call. A new
        // receive cut is only for a subsequent authenticated request; it never
        // replaces the predecessor's resident request deadline or ambiguity.
        self.receive_deadline = Some(next_receive_deadline);
        let Some(Ok(next_receive_deadline)) = &self.receive_deadline else {
            self.ended = true;
            return;
        };
        let next_receive_deadline = *next_receive_deadline;
        if self.started {
            // The predecessor remains resident while the sole authenticated
            // receiver admits its signed successor against the terminal head.
            if let Some(capture) = self.capture_candidate.as_mut() {
                if !capture.terminal.locally_sent() || capture.failure().is_some() || capture.postcheck_debt().is_some() {
                    self.ended = true;
                    return;
                }
                self.session = capture.session.take();
            } else if let Some(selected) = self.selected.as_mut() {
                if !selected.terminal.locally_sent() {
                    self.ended = true;
                    return;
                }
                self.session = selected.session.take();
            } else if matches!(&self.ordinary, Some(Ok(_))) {
                let Some(Ok(session)) = self.ordinary.take() else {
                    self.ended = true;
                    return;
                };
                self.session = Some(session);
            } else {
                self.ended = true;
                return;
            }
            self.deadline = next_receive_deadline;
        }
        if !self.started {
            self.deadline = next_receive_deadline;
        }
        self.started = true;
        // The actual Session remains resident through the borrowed receiver.
        // This native record and admission use the sole parser/CAS engine.
        self.ended = true;
        self.receipt = Some(crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1::empty());
        let Some(session) = &mut self.session else { return; };
        let Some(receipt) = &mut self.receipt else { return; };
        self.event = session.receive_original_output_request(receipt, self.deadline);
        if self.event.is_none() { return; }
        // A selected repeat stays resident and closed. It cannot enter the
        // ordinary resend/recovery adapter or mint another signing attempt.
        if self.event.as_ref().is_some_and(|event| event.is_original_output_replay()) {
            return;
        }
        if self.event.as_ref().is_some_and(|event| event.is_original_capture_candidate_replay()) {
            return;
        }

        if let Some(capture) = &mut self.capture_candidate {
            let Some(crate::ProductionBrokerRequestEventV1::Request(successor)) = &self.event else { return; };
            let Some(original) = storage.original_capture_candidate_request() else { return; };
            if !successor.is_original_output_successor(original) { return; }
            capture.retirement = Some(successor.retire_original_storage_capture_candidate(storage));
            if !matches!(&capture.retirement, Some(Ok(()))) { return; }
            // The real receipt has authenticated the signed predecessor. Both
            // successful source and terminal custody may now retire together.
            self.capture_candidate = None;
        }

        if let Some(predecessor) = &self.selected {
            let original = predecessor.logical.request();
            let Some(crate::ProductionBrokerRequestEventV1::Request(successor)) = &self.event else { return; };
            if !successor.is_original_output_successor(original) { return; }
            // A current signed successor, not local send success, is the
            // coordination point that retires the previous successful attempt.
        }
        let Some(event) = self.event.take() else { return; };
        let Some(session) = self.session.take() else { return; };
        match event {
            crate::ProductionBrokerRequestEventV1::Request(request)
                if request.method() == aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE =>
            {
                let deadline = self.deadline.min(request.original_capture_candidate_deadline());
                let Some(receipt) = self.receipt.take() else { return; };
                self.selected = None;
                self.capture_candidate = Some(OriginalStorageCaptureRequestV1::begin(session, receipt, deadline));
                let Some(capture) = &mut self.capture_candidate else { return; };
                capture.advance(request, storage, output);
                self.ended = !capture.terminal.locally_sent() || capture.failure().is_some() || capture.postcheck_debt().is_some();
            }
            crate::ProductionBrokerRequestEventV1::Request(request)
                if matches!(request.method(),
                    aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                    | aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT) =>
            {
                let registration = request.into_original_output_registration(storage);
                let deadline = self.deadline.min(registration.original_request().deadline_boottime_nanoseconds());
                let Some(receipt) = self.receipt.take() else { return; };
                self.selected = Some(OriginalStorageOutputRequestV1::begin(session, receipt, registration, deadline));
                let Some(selected) = self.selected.as_mut() else { return; };
                selected.advance(storage, output);
                self.ended = selected.failure().is_some() || self.postcheck_debt().is_some();
            }
            ordinary => {
                self.selected = None;
                // The ordinary consuming completion engine and its errors are
                // unchanged. Only its returned whole result is additionally held.
                self.ordinary = Some(session.complete_storage_request_event(ordinary, storage, self.deadline));
                self.ended = !matches!(&self.ordinary, Some(Ok(_)));
            }
        }
    }
}

impl OriginalStorageOutputRequestV1 {
    fn begin(
        session: DormantAuthenticatedBrokerSessionV1,
        receipt: crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
        registration: aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        deadline: u64,
    ) -> Self {
        Self {
            session: Some(session),
            receipt,
            logical: StorageOutputRequestOriginalV1::new(registration),
            terminal: crate::handshake::output_registration_continuation::OriginalOutputServerTerminalV1::empty(),
            deadline,
            attempted: false,
            ended: false,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.receipt.failure() { return Some(error); }
        if let Some(error) = self.logical.failure(self.session.as_ref()) { return Some(error); }
        if let Some(error) = self.terminal.failure() { return Some(error); }
        let witness_debt = self.logical.host.session.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(DormantAuthenticatedBrokerSessionV1::output_terminal_witness_debt).is_some();
        (self.ended && !witness_debt && !self.logical.host.flight.has_postcheck_debt() && !self.logical.preparation.has_postcheck_debt())
            .then_some(&OriginalStorageOutputClosedV1 as &dyn std::error::Error)
    }

    fn advance(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) {
        if self.attempted { self.ended = true; return; }
        self.attempted = true;
        self.ended = true;
        let Some(session) = self.session.as_mut() else { return; };
        if !self.logical.advance(session, storage, output, logical::LogicalOutputReceivingV1::Ordinary, self.deadline) { return; }
        self.logical.finish_logical_terminal_v1(session, &mut self.terminal, self.deadline);
        self.ended = !self.terminal.locally_sent();
    }
}

fn finish_original_output_terminal(
    session: &mut DormantAuthenticatedBrokerSessionV1,
    registration: &aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
    terminal: &mut crate::handshake::output_registration_continuation::OriginalOutputServerTerminalV1,
    readiness: &mut Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    deadline: u64,
) {
    let Some(body) = registration.response() else { return; };
    session.commit_original_output_server_terminal(registration.original_request(), body, terminal);
    if terminal.failure().is_some() { return; }
    *readiness = Some(wait_output_original(session, true, deadline));
    if !matches!(readiness, Some(Ok(()))) { return; }
    session.send_original_output_server_terminal(terminal);
}

