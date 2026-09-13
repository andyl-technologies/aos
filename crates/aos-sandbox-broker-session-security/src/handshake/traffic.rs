//! Sealed sequence-one Network Inventory traffic-key proof.
//!
//! This private typestate retains the hello socket and kernel evidence while a
//! mandatory ClientRecord and BrokerOutcome prove the two traffic keys. It
//! authorizes no peer, observes no catalog, dispatches no work, and has no
//! production constructor until protected peer and MAC policy exists.

use super::*;
use aos_sandbox_broker_session_protocol::ProtectedBrokerSessionVerificationContextV1;
use aos_sandbox_protocol::authenticated_session::{
    AuthenticatedBrokerSessionStateV1, AuthenticatedNetworkInventoryOutcomeAdmissionV1,
    AuthenticatedNetworkInventoryOutcomeV1, AuthenticatedNetworkInventoryRequestV1,
    AuthenticatedNetworkInventoryTerminalErrorV1, PreparedAuthenticatedNetworkInventoryOutcomeV1,
    PreparedAuthenticatedNetworkInventoryRequestV1,
    SealedInitialNetworkInventoryTrafficProofAdmissionV1,
    checkpoint::{
        NetworkInventoryOutcomeCheckpointDraftV1, NetworkInventoryRequestCheckpointDraftV1,
    },
};
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};

const FIRST_RESPONSE_BOUND: u32 = 4_096;
const FIRST_REQUEST_LIFETIME_NANOSECONDS: u64 = 5_000_000_000;

/// Pins the test-only peer-policy expectation independently of received values.
#[derive(Clone, Copy)]
pub(super) struct RemotePeerExpectation {
    credentials: PeerCredentials,
    policy: PeerPolicy,
}

impl RemotePeerExpectation {
    #[cfg(test)]
    pub(super) const fn for_test(credentials: PeerCredentials, policy: PeerPolicy) -> Self {
        Self {
            credentials,
            policy,
        }
    }
}

impl HandshakeCarrier {
    fn validate_remote_expectation(
        &self,
        expectation: RemotePeerExpectation,
    ) -> Result<(), TrafficProofError> {
        let credentials = expectation.credentials;
        if credentials.uid != self.peer.effective_user_id
            || credentials.gid != self.peer.effective_group_id
            || credentials.pid.is_some_and(|pid| pid != self.peer.process_id)
            || expectation.policy.uid != credentials.uid
            || expectation.policy.gid.is_some_and(|gid| gid != credentials.gid)
            || expectation.policy.audience
                != aos_sandbox_broker_session_protocol::hello_message::Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(TrafficProofError::RemoteInvalid);
        }
        Ok(())
    }
}

/// Collapses private traffic-proof failures without granting authority details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TrafficProofError {
    Local,
    RemoteInvalid,
    Transport,
}

/// Models one consuming I/O transition with exact-byte retry ownership.
pub(super) enum TrafficTransition<Complete, Retry> {
    Complete(Complete),
    Retry(Retry),
    Failed(TrafficProofError),
}

/// Owns the locally admitted exact ClientRecord until one atomic send succeeds.
pub(super) struct ClientPreparedRequest {
    custody: ProtectedBrokerSessionClientV1,
    carrier: HandshakeCarrier,
    publication_packet: Vec<u8>,
    client_packet: Vec<u8>,
    broker_packet: Vec<u8>,
    publication_subject: RetainedSubject,
    broker_subject: RetainedSubject,
    broker_process: [u8; 16],
    expectation: RemotePeerExpectation,
    prepared: PreparedAuthenticatedNetworkInventoryRequestV1,
}

/// Retains the sent ClientRecord and its outstanding semantic state.
pub(super) struct ClientAwaitOutcome {
    custody: ProtectedBrokerSessionClientV1,
    carrier: HandshakeCarrier,
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
}

/// Owns the broker's provisional state while awaiting the mandatory ClientRecord.
pub(super) struct BrokerAwaitRequest {
    custody: ProtectedBrokerSessionBrokerV1,
    carrier: HandshakeCarrier,
    publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    client_packet: Vec<u8>,
    client_subject: RetainedSubject,
    broker_packet: Vec<u8>,
    client_process: [u8; 16],
    expectation: RemotePeerExpectation,
    state: AuthenticatedBrokerSessionStateV1,
}

/// Retains one authenticated request before closed outcome selection.
pub(super) struct BrokerAdmittedRequest {
    custody: ProtectedBrokerSessionBrokerV1,
    carrier: HandshakeCarrier,
    publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    client_packet: Vec<u8>,
    client_subject: RetainedSubject,
    request_subject: RetainedSubject,
    broker_packet: Vec<u8>,
    client_process: [u8; 16],
    expectation: RemotePeerExpectation,
    request_packet: Vec<u8>,
    request: AuthenticatedNetworkInventoryRequestV1,
    state: AuthenticatedBrokerSessionStateV1,
    expired: bool,
}

/// Owns the locally admitted exact BrokerOutcome until one atomic send succeeds.
pub(super) struct BrokerPreparedOutcome {
    custody: ProtectedBrokerSessionBrokerV1,
    carrier: HandshakeCarrier,
    publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    client_packet: Vec<u8>,
    client_subject: RetainedSubject,
    request_subject: RetainedSubject,
    broker_packet: Vec<u8>,
    client_process: [u8; 16],
    expectation: RemotePeerExpectation,
    request_packet: Vec<u8>,
    request: AuthenticatedNetworkInventoryRequestV1,
    prepared: PreparedAuthenticatedNetworkInventoryOutcomeV1,
}

/// Retains client-side checkpoint inputs without exposing authority or further I/O.
pub(super) struct ClientNetworkInventoryCheckpointPending {
    _custody: ProtectedBrokerSessionClientV1,
    _carrier: HandshakeCarrier,
    _publication_packet: Vec<u8>,
    _client_packet: Vec<u8>,
    _broker_packet: Vec<u8>,
    _publication_subject: RetainedSubject,
    _broker_subject: RetainedSubject,
    _outcome_subject: RetainedSubject,
    _broker_process: [u8; 16],
    _expectation: RemotePeerExpectation,
    _request_packet: Vec<u8>,
    _outcome_packet: Vec<u8>,
    _state: AuthenticatedBrokerSessionStateV1,
    _request: AuthenticatedNetworkInventoryRequestV1,
    _outcome: AuthenticatedNetworkInventoryOutcomeV1,
    _request_draft: NetworkInventoryRequestCheckpointDraftV1,
    _outcome_draft: NetworkInventoryOutcomeCheckpointDraftV1,
}

/// Retains broker-side checkpoint inputs without exposing authority or further I/O.
pub(super) struct BrokerNetworkInventoryCheckpointPending {
    _custody: ProtectedBrokerSessionBrokerV1,
    _carrier: HandshakeCarrier,
    _publication_packet: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    _client_packet: Vec<u8>,
    _broker_packet: Vec<u8>,
    _client_subject: RetainedSubject,
    _request_subject: RetainedSubject,
    _client_process: [u8; 16],
    _expectation: RemotePeerExpectation,
    _request_packet: Vec<u8>,
    _outcome_packet: Vec<u8>,
    _state: AuthenticatedBrokerSessionStateV1,
    _request: AuthenticatedNetworkInventoryRequestV1,
    _outcome: AuthenticatedNetworkInventoryOutcomeV1,
    _request_draft: NetworkInventoryRequestCheckpointDraftV1,
    _outcome_draft: NetworkInventoryOutcomeCheckpointDraftV1,
}

#[cfg(test)]
impl ClientNetworkInventoryCheckpointPending {
    pub(super) fn has_exact_initial_proof(&self) -> bool {
        self._state.has_initial_traffic_proof()
    }

    pub(super) fn outcome_packet_len_for_test(&self) -> usize {
        self._outcome_packet.len()
    }
}

#[cfg(test)]
impl BrokerNetworkInventoryCheckpointPending {
    pub(super) fn has_exact_initial_proof(&self) -> bool {
        self._state.has_initial_traffic_proof()
    }

    pub(super) fn outcome_packet_len_for_test(&self) -> usize {
        self._outcome_packet.len()
    }
}

impl InertProvisionalClientSession {
    pub(super) fn prepare_traffic_proof(
        self,
        expectation: RemotePeerExpectation,
    ) -> Result<ClientPreparedRequest, TrafficProofError> {
        self.prepare_traffic_proof_inner(expectation, None)
    }

    #[cfg(test)]
    pub(super) fn prepare_expiring_traffic_proof_for_test(
        self,
        expectation: RemotePeerExpectation,
    ) -> Result<ClientPreparedRequest, TrafficProofError> {
        self.prepare_traffic_proof_inner(expectation, Some((0, 1)))
    }

    fn prepare_traffic_proof_inner(
        self,
        expectation: RemotePeerExpectation,
        fixed_times: Option<(u64, u64)>,
    ) -> Result<ClientPreparedRequest, TrafficProofError> {
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
                .context_for_handshake(_transcript.broker_process())
                .map_err(|_| TrafficProofError::Local)?;
            let state = AuthenticatedBrokerSessionStateV1::from_hello_packets(
                &_client_packet,
                &_broker_packet,
                &context,
            )
            .map_err(|_| TrafficProofError::Local)?;
            let (now, deadline) = match fixed_times {
                Some(times) => times,
                None => {
                    let now = boottime_nanoseconds()?;
                    let deadline = now
                        .checked_add(FIRST_REQUEST_LIFETIME_NANOSECONDS)
                        .ok_or(TrafficProofError::Local)?;
                    (now, deadline)
                }
            };
            let prepared = _custody
                .finalize_initial_client_record(
                    state,
                    _transcript.broker_process(),
                    deadline,
                    FIRST_RESPONSE_BOUND,
                    expectation.credentials,
                    expectation.policy,
                    now,
                )
                .map_err(|_| TrafficProofError::Local)?;
            if prepared.is_expired() {
                return Err(TrafficProofError::Local);
            }
            Ok(prepared)
        })();
        let prepared = match result {
            Ok(prepared) => prepared,
            Err(error) => {
                _carrier.close();
                return Err(error);
            }
        };
        Ok(ClientPreparedRequest {
            custody: _custody,
            carrier: _carrier,
            publication_packet: _publication_packet,
            client_packet: _client_packet,
            broker_packet: _broker_packet,
            publication_subject: _publication_subject,
            broker_subject: _broker_subject,
            broker_process: _transcript.broker_process(),
            expectation,
            prepared,
        })
    }
}

impl ClientPreparedRequest {
    pub(super) fn send(mut self) -> TrafficTransition<ClientAwaitOutcome, Self> {
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        let result = self.carrier.send(self.prepared.packet());
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        match result {
            Ok(()) => {}
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                return TrafficTransition::Retry(self);
            }
            Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::Transport);
            }
        }
        let (request_packet, request, state) = self.prepared.into_parts();
        TrafficTransition::Complete(ClientAwaitOutcome {
            custody: self.custody,
            carrier: self.carrier,
            publication_packet: self.publication_packet,
            client_packet: self.client_packet,
            broker_packet: self.broker_packet,
            publication_subject: self.publication_subject,
            broker_subject: self.broker_subject,
            broker_process: self.broker_process,
            expectation: self.expectation,
            request_packet,
            request,
            state: *state,
        })
    }

    fn precheck(&mut self) -> Result<(), TrafficProofError> {
        self.custody
            .revalidate_handshake_custody()
            .map_err(|_| TrafficProofError::Local)?;
        self.carrier
            .validate_peer()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        self.carrier.validate_remote_expectation(self.expectation)?;
        self.publication_subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        self.broker_subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        let context = self.context()?;
        self.prepared
            .require_current_context(&context)
            .map_err(|_| TrafficProofError::Local)
    }

    fn context(&self) -> Result<ProtectedBrokerSessionVerificationContextV1, TrafficProofError> {
        self.custody
            .context_for_handshake(self.broker_process)
            .map_err(|_| TrafficProofError::Local)
    }

    #[cfg(test)]
    pub(super) fn would_block_next_send(&mut self) {
        self.carrier.would_block_next_send();
    }

    #[cfg(test)]
    pub(super) fn packet_for_test(&self) -> &[u8] {
        self.prepared.packet()
    }

    #[cfg(test)]
    pub(super) fn corrupt_peer_after_next_send(&mut self) {
        self.carrier.corrupt_peer_after_next_send();
    }

    #[cfg(test)]
    pub(super) fn send_with_unexpected_descriptor(
        &mut self,
        descriptor: std::os::fd::BorrowedFd<'_>,
    ) -> Result<(), TrafficProofError> {
        self.precheck()?;
        match &mut self.carrier.transport {
            HandshakeTransport::Descriptor(socket) => socket
                .send_with_descriptors(self.prepared.packet(), &[descriptor])
                .map_err(|_| TrafficProofError::Transport),
            HandshakeTransport::Ordinary(_) => Err(TrafficProofError::Transport),
        }
    }
}

impl ClientAwaitOutcome {
    pub(super) fn receive(
        mut self,
    ) -> TrafficTransition<ClientNetworkInventoryCheckpointPending, Self> {
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        let maximum = match self.state.maximum_outcome_receive_bytes() {
            Some(maximum) => maximum,
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
            Ok(flight) => flight,
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
            Ok(context) => context,
            Err(error) => {
                self.carrier.close();
                return TrafficTransition::Failed(error);
            }
        };
        let admission = self
            .state
            .admit_network_inventory_outcome(&flight.payload, 0, &context);
        let (outcome, state) = match admission {
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
        let request_draft = match NetworkInventoryRequestCheckpointDraftV1::derive(&self.request) {
            Ok(draft) => draft,
            Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::Local);
            }
        };
        let outcome_draft = match NetworkInventoryOutcomeCheckpointDraftV1::derive(&outcome) {
            Ok(draft) => draft,
            Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::Local);
            }
        };

        TrafficTransition::Complete(ClientNetworkInventoryCheckpointPending {
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
            _request_draft: request_draft,
            _outcome_draft: outcome_draft,
        })
    }

    fn precheck(&mut self) -> Result<(), TrafficProofError> {
        self.custody
            .revalidate_handshake_custody()
            .map_err(|_| TrafficProofError::Local)?;
        self.carrier
            .validate_peer()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        self.carrier.validate_remote_expectation(self.expectation)?;
        self.publication_subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        self.broker_subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        let context = self.context()?;
        self.state
            .require_current_context(&context)
            .map_err(|_| TrafficProofError::Local)
    }

    fn context(&self) -> Result<ProtectedBrokerSessionVerificationContextV1, TrafficProofError> {
        self.custody
            .context_for_handshake(self.broker_process)
            .map_err(|_| TrafficProofError::Local)
    }

    #[cfg(test)]
    pub(super) fn would_block_next_receive(&mut self) {
        self.carrier.would_block_next_receive();
    }
}

impl InertProvisionalBrokerSession {
    pub(super) fn await_traffic_proof(
        self,
        expectation: RemotePeerExpectation,
    ) -> Result<BrokerAwaitRequest, TrafficProofError> {
        let InertProvisionalBrokerSession {
            mut _custody,
            mut _carrier,
            _publication,
            _client_packet,
            _client_subject,
            _broker_packet,
            _transcript,
        } = self;
        _custody
            .revalidate_handshake_custody()
            .map_err(|_| TrafficProofError::Local)?;
        _carrier
            .validate_peer()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        _carrier.validate_remote_expectation(expectation)?;
        _client_subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        let context = _custody
            .context_for_handshake(_transcript.client_process())
            .map_err(|_| TrafficProofError::Local)?;
        let state = AuthenticatedBrokerSessionStateV1::from_hello_packets(
            &_client_packet,
            &_broker_packet,
            &context,
        )
        .map_err(|_| TrafficProofError::Local)?;
        Ok(BrokerAwaitRequest {
            custody: _custody,
            carrier: _carrier,
            publication: _publication,
            client_packet: _client_packet,
            client_subject: _client_subject,
            broker_packet: _broker_packet,
            client_process: _transcript.client_process(),
            expectation,
            state,
        })
    }
}

impl BrokerAwaitRequest {
    #[cfg(test)]
    pub(super) fn corrupt_client_subject_for_test(&mut self) {
        self.client_subject.evidence.process_id ^= 1;
    }

    pub(super) fn receive(mut self) -> TrafficTransition<BrokerAdmittedRequest, Self> {
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        let received = self
            .carrier
            .receive(self.state.maximum_request_receive_bytes());
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        let flight = match received {
            Ok(flight) => flight,
            Err(HandshakeError::Transport) => return TrafficTransition::Retry(self),
            Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::RemoteInvalid);
            }
        };
        if flight.subject.validate().is_err()
            || !self.client_subject.same_execution(&flight.subject)
        {
            self.carrier.close();
            return TrafficTransition::Failed(TrafficProofError::RemoteInvalid);
        }
        let context = match self.context() {
            Ok(context) => context,
            Err(error) => {
                self.carrier.close();
                return TrafficTransition::Failed(error);
            }
        };
        let now = match boottime_nanoseconds() {
            Ok(now) => now,
            Err(error) => {
                self.carrier.close();
                return TrafficTransition::Failed(error);
            }
        };
        let admission = self
            .state
            .admit_initial_network_inventory_traffic_proof_request(
                &flight.payload,
                0,
                self.expectation.credentials,
                self.expectation.policy,
                now,
                &context,
            );
        let (request, state, expired) = match admission {
            Ok(SealedInitialNetworkInventoryTrafficProofAdmissionV1::Fresh {
                request,
                next_state,
            }) => (request, *next_state, false),
            Ok(SealedInitialNetworkInventoryTrafficProofAdmissionV1::AuthenticatedExpired {
                request,
                next_state,
            }) => (request, *next_state, true),
            _ => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::RemoteInvalid);
            }
        };
        TrafficTransition::Complete(BrokerAdmittedRequest {
            custody: self.custody,
            carrier: self.carrier,
            publication: self.publication,
            client_packet: self.client_packet,
            client_subject: self.client_subject,
            request_subject: flight.subject,
            broker_packet: self.broker_packet,
            client_process: self.client_process,
            expectation: self.expectation,
            request_packet: flight.payload,
            request,
            state,
            expired,
        })
    }

    fn precheck(&mut self) -> Result<(), TrafficProofError> {
        self.custody
            .revalidate_handshake_custody()
            .map_err(|_| TrafficProofError::Local)?;
        self.carrier
            .validate_peer()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        self.carrier.validate_remote_expectation(self.expectation)?;
        self.client_subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        let context = self.context()?;
        self.state
            .require_current_context(&context)
            .map_err(|_| TrafficProofError::Local)
    }

    fn context(&self) -> Result<ProtectedBrokerSessionVerificationContextV1, TrafficProofError> {
        self.custody
            .context_for_handshake(self.client_process)
            .map_err(|_| TrafficProofError::Local)
    }

    #[cfg(test)]
    pub(super) fn interrupt_next_receive(&mut self) {
        self.carrier.interrupt_next_receive();
    }
}

impl BrokerAdmittedRequest {
    #[cfg(test)]
    pub(super) const fn is_expired_for_test(&self) -> bool {
        self.expired
    }

    pub(super) fn prepare_success(
        mut self,
        inventory_body: Vec<u8>,
    ) -> Result<BrokerPreparedOutcome, TrafficProofError> {
        if self.expired {
            self.carrier.close();
            return Err(TrafficProofError::RemoteInvalid);
        }
        self.prepare(|state, context| {
            state.into_network_inventory_success_outcome_plan(inventory_body, context)
        })
    }

    pub(super) fn prepare_terminal_error(
        mut self,
        error: AuthenticatedNetworkInventoryTerminalErrorV1,
    ) -> Result<BrokerPreparedOutcome, TrafficProofError> {
        if self.expired && error != AuthenticatedNetworkInventoryTerminalErrorV1::DeadlineExpired {
            self.carrier.close();
            return Err(TrafficProofError::RemoteInvalid);
        }
        self.prepare(|state, context| {
            state.into_network_inventory_terminal_outcome_plan(error, context)
        })
    }

    fn prepare<F>(mut self, build: F) -> Result<BrokerPreparedOutcome, TrafficProofError>
    where
        F: FnOnce(
            AuthenticatedBrokerSessionStateV1,
            &ProtectedBrokerSessionVerificationContextV1,
        ) -> Result<
            aos_sandbox_protocol::authenticated_session::AuthenticatedNetworkInventoryOutcomeSigningPlanV1,
            aos_sandbox_protocol::AuthenticatedBrokerSessionError,
        >,
    {
        self.custody
            .revalidate_handshake_custody()
            .map_err(|_| TrafficProofError::Local)?;
        self.carrier
            .validate_peer()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        self.carrier.validate_remote_expectation(self.expectation)?;
        self.client_subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        self.request_subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        if !self.client_subject.same_execution(&self.request_subject) {
            return Err(TrafficProofError::RemoteInvalid);
        }
        let context = self
            .custody
            .context_for_handshake(self.client_process)
            .map_err(|_| TrafficProofError::Local)?;
        self.state
            .require_current_context(&context)
            .map_err(|_| TrafficProofError::Local)?;
        let plan = build(self.state, &context).map_err(|_| TrafficProofError::Local)?;
        let prepared = self
            .custody
            .finalize_initial_broker_outcome(plan, self.client_process)
            .map_err(|_| TrafficProofError::Local)?;
        Ok(BrokerPreparedOutcome {
            custody: self.custody,
            carrier: self.carrier,
            publication: self.publication,
            client_packet: self.client_packet,
            client_subject: self.client_subject,
            request_subject: self.request_subject,
            broker_packet: self.broker_packet,
            client_process: self.client_process,
            expectation: self.expectation,
            request_packet: self.request_packet,
            request: self.request,
            prepared,
        })
    }
}

impl BrokerPreparedOutcome {
    pub(super) fn send(
        mut self,
    ) -> TrafficTransition<BrokerNetworkInventoryCheckpointPending, Self> {
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        let result = self.carrier.send(self.prepared.packet());
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        match result {
            Ok(()) => {}
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                return TrafficTransition::Retry(self);
            }
            Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::Transport);
            }
        }
        let (outcome_packet, outcome, state) = self.prepared.into_parts();
        if !state.has_initial_traffic_proof() {
            self.carrier.close();
            return TrafficTransition::Failed(TrafficProofError::Local);
        }
        let request_draft = match NetworkInventoryRequestCheckpointDraftV1::derive(&self.request) {
            Ok(draft) => draft,
            Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::Local);
            }
        };
        let outcome_draft = match NetworkInventoryOutcomeCheckpointDraftV1::derive(&outcome) {
            Ok(draft) => draft,
            Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::Local);
            }
        };

        TrafficTransition::Complete(BrokerNetworkInventoryCheckpointPending {
            _custody: self.custody,
            _carrier: self.carrier,
            _publication_packet: self.publication,
            _client_packet: self.client_packet,
            _broker_packet: self.broker_packet,
            _client_subject: self.client_subject,
            _request_subject: self.request_subject,
            _client_process: self.client_process,
            _expectation: self.expectation,
            _request_packet: self.request_packet,
            _outcome_packet: outcome_packet,
            _state: *state,
            _request: self.request,
            _outcome: outcome,
            _request_draft: request_draft,
            _outcome_draft: outcome_draft,
        })
    }

    fn precheck(&mut self) -> Result<(), TrafficProofError> {
        self.custody
            .revalidate_handshake_custody()
            .map_err(|_| TrafficProofError::Local)?;
        self.carrier
            .validate_peer()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        self.carrier.validate_remote_expectation(self.expectation)?;
        self.client_subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        self.request_subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        if !self.client_subject.same_execution(&self.request_subject) {
            return Err(TrafficProofError::RemoteInvalid);
        }
        let context = self
            .custody
            .context_for_handshake(self.client_process)
            .map_err(|_| TrafficProofError::Local)?;
        self.prepared
            .require_current_context(&context)
            .map_err(|_| TrafficProofError::Local)
    }

    #[cfg(test)]
    pub(super) fn interrupt_next_send(&mut self) {
        self.carrier.interrupt_next_send();
    }

    #[cfg(test)]
    pub(super) fn packet_for_test(&self) -> &[u8] {
        self.prepared.packet()
    }
}

fn boottime_nanoseconds() -> Result<u64, TrafficProofError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| TrafficProofError::Local)?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| TrafficProofError::Local)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(TrafficProofError::Local)
}
