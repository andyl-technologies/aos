//! Complete resident Storage output and capture request cycles.

use crate::{DormantAuthenticatedBrokerSessionV1, ProductionBrokerResponseErrorV1};

use super::{ProductionBrokerDeadlineErrorV1, wait_output_original};

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
    registration: aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
    original: Option<Result<aos_sandbox::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptV1, aos_sandbox::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptErrorV1>>,
    host_custody: Option<Result<crate::ProtectedBrokerSessionFixedCustodyV1, crate::BrokerSessionSecurityError>>,
    host_session: Option<Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1>>,
    host: crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1,
    preparation: crate::handshake::output_registration_continuation::OutputPreparationCustodyV1,
    nomination: Option<aos_proto::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1>,
    host_body: Option<Result<Vec<u8>, aos_sandbox::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptErrorV1>>,
    host_checks: [Option<Result<(), crate::BrokerSessionSecurityError>>; 2],
    readiness: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 5],
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
struct OriginalStorageOutputClosedV1;

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
        if let Some(session) = &selected.session {
            if let Some(error) = session.output_preparation_postcheck_debt(&selected.preparation) { return Some(error); }
        }
        if let Some(Ok(session)) = &selected.host_session {
            if let Some(error) = session.output_client_flight_postcheck_debt(&selected.host) { return Some(error); }
        }
        if let Some(error) = selected.registration.postcheck_debt() { return Some(error); }
        if selected.host_checks[1].is_some() {
            if let Some(Ok(session)) = &selected.host_session {
                if let Some(witness) = session.output_terminal_witness_debt_before_protected() { return Some(witness); }
            }
        }
        if let Some(Err(error)) = &selected.host_checks[1] {
            return Some(error);
        }
        if let Some(Ok(session)) = &selected.host_session {
            if let Some(witness) = session.output_terminal_witness_debt() { return Some(witness); }
        }
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
            let original = predecessor.registration.original_request();
            let Some(crate::ProductionBrokerRequestEventV1::Request(successor)) = &self.event else { return; };
            if !successor.is_original_output_successor(original) { return; }
            // A current signed successor, not local send success, is the
            // coordination point that retires the previous successful attempt.
        }
        let Some(event) = self.event.take() else { return; };
        let Some(session) = self.session.take() else { return; };
        match event {
            crate::ProductionBrokerRequestEventV1::Request(request)
                if request.method() == aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE =>
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
                    aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                    | aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT) =>
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
            registration,
            original: None,
            host_custody: None,
            host_session: None,
            host: crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1::empty(),
            preparation: crate::handshake::output_registration_continuation::OutputPreparationCustodyV1::empty(),
            nomination: None,
            host_body: None,
            host_checks: std::array::from_fn(|_| None),
            readiness: std::array::from_fn(|_| None),
            terminal: crate::handshake::output_registration_continuation::OriginalOutputServerTerminalV1::empty(),
            deadline,
            attempted: false,
            ended: false,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.receipt.failure() { return Some(error); }
        if let Some(Err(error)) = &self.original { return Some(error); }
        if let Some(Err(error)) = &self.host_custody { return Some(error); }
        if let Some(Err(error)) = &self.host_session { return Some(error); }
        let host_failure = match &self.host_session {
            Some(Ok(session)) => session.output_client_flight_failure(&self.host),
            _ => self.host.failure(),
        };
        if let Some(error) = host_failure { return Some(error); }
        if let Some(Err(error)) = &self.host_body { return Some(error); }
        let preparation_failure = match &self.session {
            Some(session) => session.output_preparation_failure(&self.preparation),
            None => self.preparation.failure(),
        };
        if let Some(error) = preparation_failure { return Some(error); }
        for result in self.readiness.iter().flatten() {
            if let Err(error) = result { return Some(error); }
        }
        if self.host_checks[0].is_some() {
            if let Some(Ok(session)) = &self.host_session {
                if let Some(witness) = session.output_terminal_witness_failure() { return Some(witness); }
            }
        }
        if let Some(Err(error)) = &self.host_checks[0] {
            return Some(error);
        }
        if let Some(error) = self.registration.failure() { return Some(error); }
        if let Some(error) = self.terminal.failure() { return Some(error); }
        let witness_debt = self.host_session.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(DormantAuthenticatedBrokerSessionV1::output_terminal_witness_debt).is_some();
        (self.ended && !witness_debt && !self.host.has_postcheck_debt() && !self.preparation.has_postcheck_debt())
            .then_some(&OriginalStorageOutputClosedV1 as &dyn std::error::Error)
    }

    fn advance(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) {
        if self.attempted {
            self.ended = true;
            return;
        }
        self.attempted = true;
        self.ended = true;
        if self.registration.original_request().method()
            == aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
        {
            if let Some(session) = &mut self.session {
                {
                    let mut transport = session.output_registration_transport(
                        self.registration.original_request(), &mut self.preparation,
                    );
                    if transport.recheck(self.registration.original_request()).is_err() { return; }
                    storage.query_original_execution_output(output, &mut self.registration);
                    if transport.finish_action_turn(self.registration.original_request()).is_err() { return; }
                }
                finish_original_output_terminal(
                    session, &self.registration, &mut self.terminal,
                    &mut self.readiness[4], self.deadline,
                );
            }
            self.ended = !self.terminal.locally_sent();
            return;
        }
        self.original = Some(aos_sandbox::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptV1::from_authenticated_captured_request(
            self.registration.original_request(),
        ));
        if !matches!(&self.original, Some(Ok(_))) { return; }
        self.host_custody = Some(crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
            crate::ProtectedBrokerSessionFixedEndpointV1::StorageHostClient,
        ));
        if !matches!(&self.host_custody, Some(Ok(_))) { return; }
        let Some(Ok(custody)) = self.host_custody.take() else { return; };
        self.host_session = Some(custody.connect_output_client_session(self.deadline));
        let Some(Ok(host_session)) = &mut self.host_session else { return; };
        host_session.park_output_client_coordinates(
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT,
            self.deadline, &mut self.host,
        );
        let Some(Ok(coordinates)) = &self.host.coordinates else { return; };
        let Some(Ok(original)) = &self.original else { return; };
        self.host_body = Some(original.captured_host_readback_body(coordinates.request_header()));
        let Some(Ok(body)) = &self.host_body else { return; };
        let Some(session) = &mut self.session else { return; };
        let request = self.registration.original_request();
        let mut transport = session.output_registration_transport(request, &mut self.preparation);
        let Ok(head) = transport.original_head(request) else { return; };
        self.nomination = Some(aos_proto::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1 {
            version: 1, stage: 1,
            original_storage_request_id: request.request_id().to_vec(),
            original_storage_session_binding: request.session_binding().to_vec(),
            original_signed_request_digest: request.signed_request_digest().to_vec(),
            original_semantic_request_digest: request.semantic_commitment().to_vec(),
            storage_pending_head: head.to_vec(),
            canonical_host_readback_request: body.clone(),
            ..Default::default()
        });
        if transport.finish_turn(request).is_err() { return; }
        self.readiness[0] = Some(wait_output_original(session, true, self.deadline));
        if !matches!(&self.readiness[0], Some(Ok(()))) { return; }
        let Some(nomination) = &self.nomination else { return; };
        let mut transport = session.output_registration_transport(request, &mut self.preparation);
        if transport.send(request, nomination).is_err() || transport.finish_turn(request).is_err() { return; }
        self.readiness[1] = Some(wait_output_original(session, false, self.deadline));
        if !matches!(&self.readiness[1], Some(Ok(()))) { return; }
        let mut transport = session.output_registration_transport(request, &mut self.preparation);
        if transport.receive(request, 2).is_err() || transport.finish_turn(request).is_err() { return; }
        let Some(authorization) = self.preparation.record(2) else { return; };
        if !aos_sandbox_protocol::storage_output_reserve::continuation::matches_nomination_v1(authorization, nomination) { return; }
        let message = aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope {
            method: aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT.into(),
            body: body.clone(),
            authorization: authorization.host_authorization.clone(),
            ..Default::default()
        };
        if !host_session.park_output_client_request(&mut self.host, message) { return; }
        self.readiness[2] = Some(wait_output_original(host_session, true, self.deadline));
        if !matches!(&self.readiness[2], Some(Ok(())))
            || !host_session.send_original_output_client_request(&mut self.host)
        { return; }
        self.readiness[3] = Some(wait_output_original(host_session, false, self.deadline));
        if !matches!(&self.readiness[3], Some(Ok(())))
            || !host_session.receive_original_output_client_terminal(&mut self.host)
        { return; }
        let Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) = &self.host.committed else { return; };
        {
            let mut transport = session.output_registration_transport(
                request, &mut self.preparation,
            );
            if transport.recheck(request).is_err() { return; }
            host_session.register_original_storage_output_with_host(
                committed, storage, output, &mut self.registration, &mut self.host_checks,
            );
            if transport.finish_action_turn(self.registration.original_request()).is_err() { return; }
        }
        if !matches!(&self.host_checks[0], Some(Ok(())))
            || !matches!(&self.host_checks[1], Some(Ok(())))
            || host_session.output_terminal_witness_failure().is_some()
            || host_session.output_terminal_witness_debt().is_some()
        { return; }
        finish_original_output_terminal(
            session, &self.registration, &mut self.terminal,
            &mut self.readiness[4], self.deadline,
        );
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

