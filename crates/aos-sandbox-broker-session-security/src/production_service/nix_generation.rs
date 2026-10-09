//! Complete resident Nix-generation request cycles.

use crate::{DormantAuthenticatedBrokerSessionV1, ProductionBrokerResponseErrorV1};

use super::{ProductionBrokerDeadlineErrorV1, wait_output_original};

impl DormantAuthenticatedBrokerSessionV1 {
    /// Parks the original selected Storage Session before any receive or clock.
    ///
    /// The fixed daemon mode supplies this Session through its genuine retained
    /// HELLO. This custody adds no readiness, physical mutation or Drain claim.
    #[must_use]
    pub fn begin_original_nix_generation_cycle(self) -> ProductionOriginalNixGenerationCycleV1 {
        ProductionOriginalNixGenerationCycleV1::begin(self)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NixGenerationCycleCauseV1 {
    Receive,
    Dispatch,
    Send,
    Readiness,
    Clock(usize),
    Session(usize),
    LateClock(usize),
    Poll,
    Closed,
}

/// Retains one installed selected request, its actual Session and returned results.
///
/// Ordinary methods keep the existing consuming completion engine. Method57
/// uses a short mutable Session loan and retains native domain and response
/// results before its independent original-cutoff/currentness bookends. No
/// failed request is replaced, and successful Prepared still remains pending.
/// Lower consuming pre-return prefixes and allocation funding remain distinct.
#[must_use = "retain the selected original until its later genuine handoff"]
pub struct ProductionOriginalNixGenerationCycleV1 {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    receipt: Option<crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1>,
    previous_receipt: Option<crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1>,
    event: Option<crate::ProductionBrokerRequestEventV1>,
    ordinary: Option<Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerResponseErrorV1>>,
    dispatch: Option<Result<
        crate::ProtectedBrokerOutcomeCommitResultV1,
        crate::DormantBrokerExecutionFailureV1<crate::ProductionStorageBrokerDispatchErrorV1>,
    >>,
    send: Option<Result<
        crate::DormantBrokerResponseSendProgressV1,
        crate::DormantBrokerSessionHandshakeErrorV1,
    >>,
    readiness: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    receive_deadline: Option<Result<u64, ProductionBrokerDeadlineErrorV1>>,
    clock: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 3],
    late_clock: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 3],
    current: [Option<Result<(), crate::BrokerSessionSecurityError>>; 3],
    poll_error: Option<rustix::io::Errno>,
    first: Option<NixGenerationCycleCauseV1>,
    deadline: u64,
    selected: bool,
    ended: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("original Nix generation cycle is closed with its custody resident")]
struct NixGenerationCycleClosedV1;

impl Drop for ProductionOriginalNixGenerationCycleV1 {
    fn drop(&mut self) {
        if self.selected || self.first.is_some() || self.postcheck_debt().is_some() {
            // A local send cannot dispose of a pending generation or an
            // ambiguous original. Abort before this parent's fields drop.
            std::process::abort();
        }
    }
}

impl ProductionOriginalNixGenerationCycleV1 {
    fn begin(session: DormantAuthenticatedBrokerSessionV1) -> Self {
        Self {
            session: Some(session),
            receipt: None,
            previous_receipt: None,
            event: None,
            ordinary: None,
            dispatch: None,
            send: None,
            readiness: None,
            receive_deadline: None,
            clock: [None, None, None],
            late_clock: [None, None, None],
            current: [None, None, None],
            poll_error: None,
            first: None,
            deadline: 0,
            selected: false,
            ended: false,
        }
    }

    /// Borrows the same carrier for the existing daemon poll without extracting it.
    ///
    /// # Errors
    /// Rejects a missing original; an ended request cannot accept another frame.
    pub fn as_fd(&self) -> Result<std::os::fd::BorrowedFd<'_>, crate::DormantBrokerSessionHandshakeErrorV1> {
        if self.ended {
            return Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole);
        }
        if let Some(session) = &self.session {
            return session.as_fd();
        }
        if let Some(Ok(session)) = &self.ordinary {
            return session.as_fd();
        }
        Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)
    }

    /// Borrows the chronological returned cause without moving retained custody.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            NixGenerationCycleCauseV1::Receive => {
                if let Some(Err(error)) = &self.receive_deadline { return Some(error); }
                self.receipt.as_ref()?.failure()
            }
            NixGenerationCycleCauseV1::Dispatch => match self.dispatch.as_ref()? {
                Err(crate::DormantBrokerExecutionFailureV1::BeforeEffect { error, .. }) => Some(error),
                Err(crate::DormantBrokerExecutionFailureV1::OutcomeUnknown { error, .. }) => Some(error),
                Ok(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. }) => Some(error),
                _ => Some(&NixGenerationCycleClosedV1),
            },
            NixGenerationCycleCauseV1::Send => match self.send.as_ref()? {
                Err(error) => Some(error),
                Ok(crate::DormantBrokerResponseSendProgressV1::RecoveryRequired { error, .. }) => Some(error),
                _ => Some(&NixGenerationCycleClosedV1),
            },
            NixGenerationCycleCauseV1::Readiness => self.readiness.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            NixGenerationCycleCauseV1::Clock(index) => self.clock[index].as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            NixGenerationCycleCauseV1::Session(index) => self.current[index].as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            NixGenerationCycleCauseV1::LateClock(index) => self.late_clock[index].as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            NixGenerationCycleCauseV1::Poll => self.poll_error.as_ref()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            NixGenerationCycleCauseV1::Closed => {
                if let Some(Err(error)) = &self.ordinary { return Some(error); }
                Some(&NixGenerationCycleClosedV1)
            }
        }
    }

    /// Borrows final comparison debt independently of an earlier action error.
    #[must_use]
    pub fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.receipt.as_ref().and_then(|receipt| receipt.postcheck_debt()) {
            return Some(error);
        }
        for index in 1..3 {
            if self.first != Some(NixGenerationCycleCauseV1::Clock(index)) {
                if let Some(Err(error)) = &self.clock[index] { return Some(error); }
            }
            if self.first != Some(NixGenerationCycleCauseV1::Session(index)) {
                if let Some(Err(error)) = &self.current[index] { return Some(error); }
            }
            if self.first != Some(NixGenerationCycleCauseV1::LateClock(index)) {
                if let Some(Err(error)) = &self.late_clock[index] { return Some(error); }
            }
        }
        None
    }

    /// Parks a genuine daemon poll error and permanently fences the same request.
    pub fn close_on_poll_failure(&mut self, error: rustix::io::Errno) {
        self.poll_error.get_or_insert(error);
        self.first.get_or_insert(NixGenerationCycleCauseV1::Poll);
        self.ended = true;
    }

    /// Reports only a locally sent Prepared whose original owners remain pending.
    ///
    /// This diagnostic is not completion, a release permission or physical Drain.
    #[must_use]
    pub fn has_prepared_pending(&self) -> bool {
        self.selected && self.first.is_none() && self.postcheck_debt().is_none()
            && matches!(self.send, Some(Ok(crate::DormantBrokerResponseSendProgressV1::Sent(_))))
    }

    fn bookend(&mut self, index: usize) -> bool {
        self.clock[index] = Some(crate::dormant_handshake::check_production_deadline(self.deadline));
        if self.clock[index].as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(NixGenerationCycleCauseV1::Clock(index));
            if index == 0 {
                return false;
            }
        }
        let Some(session) = self.session.as_mut() else {
            return false;
        };
        self.current[index] = Some(session.recheck_original_nix_generation_session());
        if self.current[index].as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(NixGenerationCycleCauseV1::Session(index));
        }
        // A slow named/native comparison may cross the original cutoff.
        let late = crate::dormant_handshake::check_production_deadline(self.deadline);
        if index == 0 {
            if late.is_err() {
                self.clock[index] = Some(late);
                self.first.get_or_insert(NixGenerationCycleCauseV1::Clock(index));
            }
        } else {
            // Post-action observations are independent. Keep the first clock
            // result even on failure, and retain the final sample separately.
            self.late_clock[index] = Some(late);
            if self.late_clock[index].as_ref().is_some_and(Result::is_err) {
                self.first.get_or_insert(NixGenerationCycleCauseV1::LateClock(index));
            }
        }
        self.first.is_none()
    }

    /// Drives one actual request without replacing its original Session or deadline.
    ///
    /// A unit return is not Prepared. Original results and errors remain owned;
    /// the installed caller terminates before dropping failed or selected custody.
    pub fn advance(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receive_deadline: Result<u64, ProductionBrokerDeadlineErrorV1>,
    ) {
        if self.ended || self.selected {
            return;
        }
        if let Some(ordinary) = self.ordinary.take() {
            match ordinary {
                Ok(session) => self.session = Some(session),
                Err(error) => {
                    self.ordinary = Some(Err(error));
                    self.first = Some(NixGenerationCycleCauseV1::Closed);
                    self.ended = true;
                    return;
                }
            }
        }
        self.receive_deadline = Some(receive_deadline);
        let Some(Ok(deadline)) = &self.receive_deadline else {
            self.first = Some(NixGenerationCycleCauseV1::Receive);
            self.ended = true;
            return;
        };
        self.deadline = *deadline;
        self.previous_receipt = self.receipt.take();
        self.receipt = Some(crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1::empty());
        self.ended = true;
        let (Some(session), Some(receipt)) = (self.session.as_mut(), self.receipt.as_mut()) else {
            return;
        };
        // The existing receipt engine checks fixed Storage/NodeController
        // originals; it is not an Output-operation authority constructor.
        self.event = session.receive_original_output_request(receipt, self.deadline);
        if self.event.is_none() {
            self.first = Some(NixGenerationCycleCauseV1::Receive);
            return;
        }
        // The same parser authenticated the current predecessor before the
        // prior successful ordinary receipt can be disposed of.
        self.previous_receipt = None;
        if !self.event.as_ref().is_some_and(|event| event.is_nix_generation()) {
            let (Some(event), Some(session)) = (self.event.take(), self.session.take()) else {
                return;
            };
            self.ordinary = Some(session.complete_storage_request_event(event, storage, self.deadline));
            self.ended = !matches!(self.ordinary, Some(Ok(_)));
            if self.ended {
                self.first = Some(NixGenerationCycleCauseV1::Closed);
            }
            return;
        }

        self.selected = true;
        // A terminal or ambiguous repeat remains resident and closed. No new
        // effect, receipt or replacement dispatch is inferred from replay.
        let Some(crate::ProductionBrokerRequestEventV1::Request(request)) = self.event.as_ref() else {
            self.first = Some(NixGenerationCycleCauseV1::Closed);
            return;
        };
        self.deadline = self.deadline.min(request.original_nix_generation_deadline());
        if !self.bookend(0) {
            return;
        }
        let Some(crate::ProductionBrokerRequestEventV1::Request(request)) = self.event.take() else {
            return;
        };
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.dispatch = Some(session.dispatch_storage_request_and_commit(request, storage));
        if matches!(
            self.dispatch.as_ref(),
            Some(Err(_))
                | Some(Ok(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { .. }))
        ) {
            self.first = Some(NixGenerationCycleCauseV1::Dispatch);
        }
        if !self.bookend(1) {
            return;
        }
        let committed = match self.dispatch.take() {
            Some(Ok(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(committed))) => committed,
            retained => {
                self.dispatch = retained;
                self.first.get_or_insert(NixGenerationCycleCauseV1::Dispatch);
                return;
            }
        };
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.send = Some(session.send_authenticated_response(committed));
        if matches!(self.send, Some(Err(_)) | Some(Ok(crate::DormantBrokerResponseSendProgressV1::RecoveryRequired { .. }))) {
            self.first = Some(NixGenerationCycleCauseV1::Send);
        }
        if !self.bookend(2) {
            return;
        }
        while matches!(self.send, Some(Ok(crate::DormantBrokerResponseSendProgressV1::Pending(_)))) {
            let Some(session) = self.session.as_ref() else {
                return;
            };
            self.readiness = Some(wait_output_original(session, true, self.deadline));
            if self.readiness.as_ref().is_some_and(Result::is_err) {
                self.first = Some(NixGenerationCycleCauseV1::Readiness);
            }
            if !self.bookend(2) {
                return;
            }
            let pending = match self.send.take() {
                Some(Ok(crate::DormantBrokerResponseSendProgressV1::Pending(pending))) => pending,
                retained => {
                    self.send = retained;
                    return;
                }
            };
            let Some(session) = self.session.as_mut() else {
                return;
            };
            self.send = Some(session.send_authenticated_response(pending));
            if matches!(self.send, Some(Err(_)) | Some(Ok(crate::DormantBrokerResponseSendProgressV1::RecoveryRequired { .. }))) {
                self.first = Some(NixGenerationCycleCauseV1::Send);
            }
            if !self.bookend(2) {
                return;
            }
        }
    }
}

