//! Whole retained Storage HELLO ownership on the existing three-flight reducer.
//!
//! The sole writer, floor and endpoint stay together. Native opening and its
//! original cold cutoff never restart; a fresh finite transport cutoff bounds
//! this connection's HELLO. No request initialization or effect occurs here.

use super::*;
use aos_sandbox_controller_domain::{StorageLifecycleSessionLoanV1, StoragePrepareReceivingLoanV1, StorageReceivingClosedV1};
use aos_sandbox_model::ResourceVector;

use super::storage_broker_start::StorageBrokerHandshakeStartV1 as Start;

#[derive(Clone, Copy)]
enum Failure {
    Native,
    Demand,
    Deadline,
    Handshake,
    Readiness,
    Protected,
    Start,
}

/// Retains every reached startup/HELLO result before the same owning handoff.
pub(crate) struct StorageRetainedSessionHandshakeV1 {
    start: Option<Start>,
    pending: Option<DormantBrokerEndpointHandshakeV1>,
    cold: Option<RetainedStorageColdOpenV1>,
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    deadline: OriginalBrokerColdDeadlineV1,
    demand: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    native: Option<Result<(), StorageReceivingClosedV1>>,
    wire: Option<Result<(), StorageReceivingClosedV1>>,
    wire_demand: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    cutoff: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    readiness: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    poll: Option<Result<usize, rustix::io::Errno>>,
    handshake: Option<crate::DormantBrokerSessionHandshakeErrorV1>,
    protected: Option<Result<(), BrokerSessionSecurityError>>,
    first: Option<Failure>,
    entered: bool,
}

impl StorageRetainedSessionHandshakeV1 {
    pub(crate) fn new(owner: ProtectedBrokerSessionOwnerV1, socket: SeqpacketSocket, deadline: OriginalBrokerColdDeadlineV1) -> Self {
        Self {
            start: Some(Start::new(
                ProtectedBrokerSessionOwnerV1::retained_storage_root_v1(),
                BrokerHandshakeCustodyV1::RetainedStorage(owner), socket,
            )),
            pending: None, cold: None, session: None, deadline,
            demand: None, native: None, wire: None, wire_demand: None, cutoff: None, readiness: None,
            poll: None, handshake: None, protected: None, first: None,
            entered: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Native => self.native.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn std::error::Error)
                .or_else(|| self.wire.as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error)),
            Failure::Demand => self.demand.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn std::error::Error)
                .or_else(|| self.wire_demand.as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error)),
            Failure::Start => self.start.as_ref()?.failure(),
            Failure::Deadline => self.cutoff.as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error),
            Failure::Handshake => self.handshake.as_ref().map(|error| error as &dyn std::error::Error),
            Failure::Readiness => self.poll.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn std::error::Error)
                .or_else(|| self.readiness.as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error)),
            Failure::Protected => self.protected.as_ref()?.as_ref().err().map(|error| error as &dyn std::error::Error),
        }
    }

    fn parts(&self) -> Result<(&aos_sandbox_controller_domain::Journal, &SeqpacketSocket), BrokerSessionSecurityError> {
        if let Some(start) = &self.start {
            return start.retained_parts();
        }
        if let Some(pending) = &self.pending {
            let (custody, carrier) = match &pending.state {
                DormantBrokerHandshakeStateV1::SendPublication(stage) => (&stage.custody, &stage.carrier),
                DormantBrokerHandshakeStateV1::AwaitClientHello(stage) => (&stage.custody, &stage.carrier),
                DormantBrokerHandshakeStateV1::SendHello(stage) => (&stage.custody, &stage.carrier),
            };
            let BrokerHandshakeCustodyV1::RetainedStorage(owner) = custody else {
                return Err(BrokerSessionSecurityError::Currentness);
            };
            let HandshakeTransport::Ordinary(socket) = &carrier.transport else {
                return Err(BrokerSessionSecurityError::Currentness);
            };
            return Ok((owner.retained_storage_journal_v1()?, socket));
        }
        if let Some(crate::DormantBrokerSessionHandshakeErrorV1::StoragePreparation(failure)) = &self.handshake {
            let (custody, carrier) = match &failure._owner {
                SelectedBrokerFailureOwnerV1::Publication(stage) => (&stage.custody, &stage.carrier),
                SelectedBrokerFailureOwnerV1::ClientHello { stage, .. } => (&stage.custody, &stage.carrier),
                SelectedBrokerFailureOwnerV1::ServerHello(stage) => (&stage.custody, &stage.carrier),
                // This owner admits only Broker startup. A retained Client
                // failure remains in its original Client disposition.
                SelectedBrokerFailureOwnerV1::ClientPublication { .. }
                | SelectedBrokerFailureOwnerV1::ClientSend(_)
                | SelectedBrokerFailureOwnerV1::ClientBrokerHello { .. } => {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
            };
            let BrokerHandshakeCustodyV1::RetainedStorage(owner) = custody else {
                return Err(BrokerSessionSecurityError::Currentness);
            };
            let HandshakeTransport::Ordinary(socket) = &carrier.transport else {
                return Err(BrokerSessionSecurityError::Currentness);
            };
            return Ok((owner.retained_storage_journal_v1()?, socket));
        }
        if let Some(session) = &self.session {
            return Ok((session.owner.retained_storage_journal_v1()?, &session.socket));
        }
        self.cold.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.retained_storage_parts_v1()
    }

    fn observe(&mut self, receiving: &mut StorageLifecycleSessionLoanV1<'_, '_>) {
        // No negative observation can be replaced: every caller exits once
        // first is set. Successful transport-only samples can be reused.
        self.cutoff = Some(self.deadline.check());
        if matches!(self.cutoff, Some(Err(_))) {
            self.first.get_or_insert(Failure::Deadline);
        }
        self.native = Some(match self.parts() {
            Ok((journal, socket)) => receiving.require_current_v1(journal, socket),
            Err(error) => {
                self.protected = Some(Err(error));
                self.first.get_or_insert(Failure::Protected);
                Err(StorageReceivingClosedV1)
            }
        });
        if matches!(self.native, Some(Err(_))) {
            self.first.get_or_insert(Failure::Native);
        }
    }

    fn initialize(&mut self) {
        let Some(start) = self.start.as_mut() else { std::process::abort() };
        start.initialize_once();
        if start.failure().is_some() {
            self.first = Some(Failure::Start);
            return;
        }
        let Some(pending) = start.take_ready() else {
            std::process::abort()
        };
        self.pending = Some(pending);
        self.start = None;
    }

    pub(crate) fn finish<'cut, 'original>(
        &mut self,
        receiving: &'cut mut StoragePrepareReceivingLoanV1<'original>,
    ) -> Result<(DormantAuthenticatedBrokerSessionV1, StorageLifecycleSessionLoanV1<'cut, 'original>), crate::DormantBrokerSessionHandshakeErrorV1> {
        if self.entered {
            return Err(BrokerSessionSecurityError::Currentness.into());
        }
        self.entered = true;
        let parts = self.parts().map_err(crate::DormantBrokerSessionHandshakeErrorV1::from)?;
        let mut receiving = match receiving.borrow_lifecycle_session_v1(parts.0, parts.1) {
            Ok(receiving) => receiving,
            Err(error) => {
                self.native = Some(Err(error));
                self.first = Some(Failure::Native);
                return Err(BrokerSessionSecurityError::Currentness.into());
            }
        };
        self.demand = Some(crate::recovery::BrokerMainOpenV1::retained_storage_handshake_demand_v1());
        let Some(Ok(demand)) = self.demand.as_ref() else {
            self.first = Some(Failure::Demand);
            return Err(BrokerSessionSecurityError::Currentness.into());
        };
        let demand = *demand;
        self.wire_demand = Some(crate::recovery::BrokerMainOpenV1::storage_hello_flight_demand_v1());
        let Some(Ok(wire_demand)) = self.wire_demand.as_ref() else {
            self.first = Some(Failure::Demand);
            return Err(BrokerSessionSecurityError::Currentness.into());
        };
        let wire_result = {
            let (journal, socket) = self.parts()
                .map_err(crate::DormantBrokerSessionHandshakeErrorV1::from)?;
            receiving.reserve_handshake_flight_v1(journal, socket, *wire_demand)
        };
        self.wire = Some(wire_result);
        if !matches!(self.wire, Some(Ok(()))) {
            self.first = Some(Failure::Native);
            return Err(BrokerSessionSecurityError::Currentness.into());
        }
        let native_result = {
            let (journal, socket) = self.parts()
                .map_err(crate::DormantBrokerSessionHandshakeErrorV1::from)?;
            receiving.reserve_handshake_v1(journal, socket, demand)
        };
        self.native = Some(native_result);
        if !matches!(self.native, Some(Ok(()))) {
            self.first = Some(Failure::Native);
            return Err(BrokerSessionSecurityError::Currentness.into());
        }
        self.observe(&mut receiving);
        if self.first.is_some() { return Err(BrokerSessionSecurityError::Currentness.into()); }
        self.initialize();
        // Initial peer/publication failures still owe the independent original
        // Native observation while their whole owner/socket remain resident.
        self.observe(&mut receiving);
        if self.first.is_some() { return Err(BrokerSessionSecurityError::Currentness.into()); }

        loop {
            self.observe(&mut receiving);
            if self.first.is_some() { return Err(BrokerSessionSecurityError::Currentness.into()); }
            let pending = match self.pending.take() { Some(pending) => pending, None => std::process::abort() };
            match pending.advance_retaining_storage() {
                Err(error) => {
                    self.handshake = Some(error.into());
                    self.first = Some(Failure::Handshake);
                    self.observe(&mut receiving);
                    return Err(BrokerSessionSecurityError::Currentness.into());
                }
                Ok(ColdBrokerHandshakeProgressV1::Pending(pending)) => {
                    self.pending = Some(pending);
                    let pending = match self.pending.as_ref() { Some(pending) => pending, None => std::process::abort() };
                    self.readiness = Some(match pending.as_fd() {
                        Ok(fd) => crate::dormant_handshake::wait_for_handshake_readiness_retaining_v1(
                            fd, pending.wants_write(), self.deadline.value(), &mut self.poll,
                        ),
                        Err(error) => Err(error.into()),
                    });
                    if !matches!(self.readiness, Some(Ok(()))) {
                        self.first = Some(Failure::Readiness);
                    }
                    self.observe(&mut receiving);
                    if self.first.is_some() { return Err(BrokerSessionSecurityError::Currentness.into()); }
                }
                Ok(ColdBrokerHandshakeProgressV1::Verified(verified)) => {
                    self.cold = Some(RetainedStorageColdOpenV1::retain(verified, self.deadline));
                    let cold = match self.cold.as_mut() { Some(cold) => cold, None => std::process::abort() };
                    match cold.finish_retained_storage_session_v1(&mut receiving) {
                        Ok(session) => self.session = Some(session),
                        Err(error) => {
                            self.handshake = Some(error);
                            self.first = Some(Failure::Handshake);
                            self.observe(&mut receiving);
                            return Err(BrokerSessionSecurityError::Currentness.into());
                        }
                    }
                    self.observe(&mut receiving);
                    if self.first.is_some() { return Err(BrokerSessionSecurityError::Currentness.into()); }
                    let session = match self.session.as_mut() { Some(session) => session, None => std::process::abort() };
                    self.protected = Some(session.owner.require_original_storage_output_server(&session.transcript, session.socket.peer()));
                    if !matches!(self.protected, Some(Ok(()))) {
                        self.first = Some(Failure::Protected);
                    }
                    self.cutoff = Some(self.deadline.check());
                    if !matches!(self.cutoff, Some(Ok(()))) { self.first.get_or_insert(Failure::Deadline); }
                    if self.first.is_some() { return Err(BrokerSessionSecurityError::Currentness.into()); }

                    let cold = match self.cold.take() { Some(cold) => cold, None => std::process::abort() };
                    if let Err(cold) = cold.dispose_retained_storage_hello_v1(session, &mut receiving) {
                        self.cold = Some(cold);
                        self.first = Some(Failure::Native);
                        return Err(BrokerSessionSecurityError::Currentness.into());
                    }
                    // Only infallible owning handoff follows actual control
                    // disposal and completion of the same paid HELLO operation.
                    let session = match self.session.take() { Some(session) => session, None => std::process::abort() };
                    return Ok((session, receiving));
                }
                Ok(ColdBrokerHandshakeProgressV1::Complete(_)) => std::process::abort(),
            }
        }
    }
}
