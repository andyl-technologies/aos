//! Controller-owned durable sequence-one Network Inventory traffic.
//!
//! A locally finalized request is consumed into exact evidence and reserved in
//! the protected controller journal before its packet can reach the transport.
//! The matching outcome is authenticated and durably resolved before the
//! traffic-proved channel exists.

use aos_sandbox::resource_inventory::{
    ControllerNetworkInventoryCheckpointOwnerV1, ControllerNetworkInventoryReservationV1,
};
use aos_sandbox_broker_session_protocol::ProtectedBrokerSessionVerificationContextV1;
use aos_sandbox_protocol::{
    MAXIMUM_RESPONSE_BYTES,
    authenticated_session::{
        AuthenticatedBrokerSessionStateV1, AuthenticatedNetworkInventoryOutcomeAdmissionV1,
        AuthenticatedNetworkInventoryRequestV1,
        checkpoint::{
            NetworkInventoryOutcomeCheckpointDraftV1, NetworkInventoryRequestCheckpointDraftV1,
        },
    },
};

use super::{
    HandshakeError, InertProvisionalClientSession, RemotePeerExpectation, RetainedSubject,
    SeqpacketError, TrafficProofError, TrafficTransition, boottime_nanoseconds,
    channel::ClientHeads2ChannelV1,
};
use crate::ProtectedBrokerSessionClientV1;

/// Owns the exact reserved request packet until its one atomic send succeeds.
pub(super) struct ClientDurableReservedRequestV1 {
    custody: ProtectedBrokerSessionClientV1,
    carrier: super::HandshakeCarrier,
    publication_packet: Vec<u8>,
    client_packet: Vec<u8>,
    broker_packet: Vec<u8>,
    publication_subject: RetainedSubject,
    broker_subject: RetainedSubject,
    broker_process: [u8; 16],
    expectation: RemotePeerExpectation,
    request_packet: Vec<u8>,
    request: AuthenticatedNetworkInventoryRequestV1,
    state: AuthenticatedBrokerSessionStateV1,
    checkpoint_owner: ControllerNetworkInventoryCheckpointOwnerV1,
    reservation: ControllerNetworkInventoryReservationV1,
}

/// Retains the sent request and its live durable reservation while receiving.
pub(super) struct ClientDurableAwaitOutcomeV1 {
    custody: ProtectedBrokerSessionClientV1,
    carrier: super::HandshakeCarrier,
    publication_packet: Vec<u8>,
    client_packet: Vec<u8>,
    broker_packet: Vec<u8>,
    publication_subject: RetainedSubject,
    broker_subject: RetainedSubject,
    broker_process: [u8; 16],
    expectation: RemotePeerExpectation,
    request_packet: Vec<u8>,
    request: AuthenticatedNetworkInventoryRequestV1,
    state: AuthenticatedBrokerSessionStateV1,
    checkpoint_owner: ControllerNetworkInventoryCheckpointOwnerV1,
    reservation: ControllerNetworkInventoryReservationV1,
}

impl InertProvisionalClientSession {
    /// Finalizes and durably reserves the exact sequence-one request.
    pub(super) fn prepare_durable_initial_inventory(
        self,
        expectation: RemotePeerExpectation,
        mut checkpoint_owner: ControllerNetworkInventoryCheckpointOwnerV1,
    ) -> Result<ClientDurableReservedRequestV1, TrafficProofError> {
        let InertProvisionalClientSession {
            mut _custody,
            mut _carrier,
            _publication_packet,
            _client_packet,
            _broker_packet,
            _publication_subject,
            _broker_subject,
            _transcript,
        } = self;
        let broker_process = _transcript.broker_process();
        let result = (|| {
            _custody
                .revalidate_handshake_custody()
                .map_err(|_| TrafficProofError::Local)?;
            _carrier
                .validate_peer()
                .map_err(|_| TrafficProofError::RemoteInvalid)?;
            _carrier.validate_remote_expectation(expectation)?;
            _publication_subject
                .validate()
                .map_err(|_| TrafficProofError::RemoteInvalid)?;
            _broker_subject
                .validate()
                .map_err(|_| TrafficProofError::RemoteInvalid)?;
            if !_publication_subject.same_execution(&_broker_subject) {
                return Err(TrafficProofError::RemoteInvalid);
            }

            let context = _custody
                .context_for_handshake(broker_process)
                .map_err(|_| TrafficProofError::Local)?;
            let state = AuthenticatedBrokerSessionStateV1::from_hello_packets(
                &_client_packet,
                &_broker_packet,
                &context,
            )
            .map_err(|_| TrafficProofError::Local)?;
            let now = boottime_nanoseconds()?;
            let deadline = now
                .checked_add(super::FIRST_REQUEST_LIFETIME_NANOSECONDS)
                .ok_or(TrafficProofError::Local)?;
            let maximum_response_bytes = _transcript
                .negotiated_maximum_response_bytes()
                .min(MAXIMUM_RESPONSE_BYTES);
            let prepared = _custody
                .finalize_initial_client_record(
                    state,
                    broker_process,
                    deadline,
                    maximum_response_bytes,
                    expectation.credentials,
                    expectation.policy,
                    now,
                )
                .map_err(|_| TrafficProofError::Local)?;
            if prepared.is_expired() {
                return Err(TrafficProofError::Local);
            }
            let (request_packet, request, state) = prepared.into_parts();
            let request_draft = NetworkInventoryRequestCheckpointDraftV1::derive(&request)
                .map_err(|_| TrafficProofError::Local)?;
            let reservation = checkpoint_owner
                .reserve_live_request(request_draft)
                .map_err(|_| TrafficProofError::Local)?;
            validate_client_context(
                &mut _custody,
                &_carrier,
                expectation,
                &_publication_subject,
                &_broker_subject,
                None,
                broker_process,
                &state,
            )?;

            Ok((request_packet, request, *state, reservation))
        })();
        let (request_packet, request, state, reservation) = match result {
            Ok(value) => value,
            Err(error) => {
                _carrier.close();
                return Err(error);
            }
        };

        Ok(ClientDurableReservedRequestV1 {
            custody: _custody,
            carrier: _carrier,
            publication_packet: _publication_packet,
            client_packet: _client_packet,
            broker_packet: _broker_packet,
            publication_subject: _publication_subject,
            broker_subject: _broker_subject,
            broker_process,
            expectation,
            request_packet,
            request,
            state,
            checkpoint_owner,
            reservation,
        })
    }
}

impl ClientDurableReservedRequestV1 {
    /// Sends only the exact packet whose protected reservation this value owns.
    pub(super) fn send(
        mut self,
    ) -> TrafficTransition<ClientDurableAwaitOutcomeV1, ClientDurableReservedRequestV1> {
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        let result = self.carrier.send(&self.request_packet);
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        match result {
            Ok(()) => TrafficTransition::Complete(ClientDurableAwaitOutcomeV1 {
                custody: self.custody,
                carrier: self.carrier,
                publication_packet: self.publication_packet,
                client_packet: self.client_packet,
                broker_packet: self.broker_packet,
                publication_subject: self.publication_subject,
                broker_subject: self.broker_subject,
                broker_process: self.broker_process,
                expectation: self.expectation,
                request_packet: self.request_packet,
                request: self.request,
                state: self.state,
                checkpoint_owner: self.checkpoint_owner,
                reservation: self.reservation,
            }),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                TrafficTransition::Retry(self)
            }
            Err(_) => {
                self.carrier.close();
                TrafficTransition::Failed(TrafficProofError::Transport)
            }
        }
    }

    fn precheck(&mut self) -> Result<(), TrafficProofError> {
        validate_client_context(
            &mut self.custody,
            &self.carrier,
            self.expectation,
            &self.publication_subject,
            &self.broker_subject,
            None,
            self.broker_process,
            &self.state,
        )
    }
}

impl ClientDurableAwaitOutcomeV1 {
    /// Receives, authenticates, and durably resolves the sequence-one outcome.
    pub(super) fn receive(
        mut self,
    ) -> TrafficTransition<ClientHeads2ChannelV1, ClientDurableAwaitOutcomeV1> {
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        let maximum = match self.state.maximum_outcome_receive_bytes() {
            Some(value) => value,
            None => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::Local);
            }
        };
        let received = self.carrier.receive(maximum);
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        let flight = match received {
            Ok(value) => value,
            Err(HandshakeError::Transport) => return TrafficTransition::Retry(self),
            Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::RemoteInvalid);
            }
        };
        if flight.subject.validate().is_err()
            || !self.broker_subject.same_execution(&flight.subject)
        {
            self.carrier.close();
            return TrafficTransition::Failed(TrafficProofError::RemoteInvalid);
        }
        let context = match self.context() {
            Ok(value) => value,
            Err(error) => {
                self.carrier.close();
                return TrafficTransition::Failed(error);
            }
        };
        let (outcome, state) =
            match self
                .state
                .admit_network_inventory_outcome(&flight.payload, 0, &context)
            {
                Ok(AuthenticatedNetworkInventoryOutcomeAdmissionV1::New {
                    outcome,
                    next_state,
                }) if next_state.has_initial_traffic_proof() => (outcome, *next_state),
                _ => {
                    self.carrier.close();
                    return TrafficTransition::Failed(TrafficProofError::RemoteInvalid);
                }
            };
        if self.precheck().is_err() {
            self.carrier.close();
            return TrafficTransition::Failed(TrafficProofError::Local);
        }
        let outcome_draft = match NetworkInventoryOutcomeCheckpointDraftV1::derive(&outcome) {
            Ok(value) => value,
            Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::Local);
            }
        };
        let committed_result = match self
            .checkpoint_owner
            .complete_live_outcome(self.reservation, outcome_draft)
        {
            Ok(value) => value,
            Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::Local);
            }
        };
        if !state.has_initial_traffic_proof()
            || validate_client_context(
                &mut self.custody,
                &self.carrier,
                self.expectation,
                &self.publication_subject,
                &self.broker_subject,
                Some(&flight.subject),
                self.broker_process,
                &state,
            )
            .is_err()
        {
            self.carrier.close();
            return TrafficTransition::Failed(TrafficProofError::Local);
        }

        TrafficTransition::Complete(ClientHeads2ChannelV1 {
            _custody: self.custody,
            _carrier: self.carrier,
            _publication_packet: self.publication_packet,
            _client_packet: self.client_packet,
            _broker_packet: self.broker_packet,
            _publication_subject: self.publication_subject,
            _broker_subject: self.broker_subject,
            _outcome_subject: flight.subject,
            _broker_process: self.broker_process,
            _expectation: self.expectation,
            _request_packet: self.request_packet,
            _outcome_packet: flight.payload,
            _state: state,
            _request: self.request,
            _outcome: outcome,
            _checkpoint_owner: self.checkpoint_owner,
            _committed_result: committed_result,
        })
    }

    fn precheck(&mut self) -> Result<(), TrafficProofError> {
        validate_client_context(
            &mut self.custody,
            &self.carrier,
            self.expectation,
            &self.publication_subject,
            &self.broker_subject,
            None,
            self.broker_process,
            &self.state,
        )
    }

    fn context(&self) -> Result<ProtectedBrokerSessionVerificationContextV1, TrafficProofError> {
        self.custody
            .context_for_handshake(self.broker_process)
            .map_err(|_| TrafficProofError::Local)
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_client_context(
    custody: &mut ProtectedBrokerSessionClientV1,
    carrier: &super::HandshakeCarrier,
    expectation: RemotePeerExpectation,
    publication_subject: &RetainedSubject,
    broker_subject: &RetainedSubject,
    outcome_subject: Option<&RetainedSubject>,
    broker_process: [u8; 16],
    state: &AuthenticatedBrokerSessionStateV1,
) -> Result<(), TrafficProofError> {
    custody
        .revalidate_handshake_custody()
        .map_err(|_| TrafficProofError::Local)?;
    carrier
        .validate_peer()
        .map_err(|_| TrafficProofError::RemoteInvalid)?;
    carrier.validate_remote_expectation(expectation)?;
    publication_subject
        .validate()
        .map_err(|_| TrafficProofError::RemoteInvalid)?;
    broker_subject
        .validate()
        .map_err(|_| TrafficProofError::RemoteInvalid)?;
    if !publication_subject.same_execution(broker_subject) {
        return Err(TrafficProofError::RemoteInvalid);
    }
    if let Some(subject) = outcome_subject {
        subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        if !broker_subject.same_execution(subject) {
            return Err(TrafficProofError::RemoteInvalid);
        }
    }
    let context = custody
        .context_for_handshake(broker_process)
        .map_err(|_| TrafficProofError::Local)?;
    state
        .require_current_context(&context)
        .map_err(|_| TrafficProofError::Local)
}
