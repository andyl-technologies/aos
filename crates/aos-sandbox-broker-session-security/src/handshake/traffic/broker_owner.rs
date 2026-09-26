//! Broker-owned durable sequence-one Network Inventory traffic.
//!
//! The authenticated request is durably reserved before catalog observation.
//! Outcome selection is closed over owner-produced observation tokens, and the
//! exact signed outcome is committed and rechecked before its packet can reach
//! the transport.

use aos_sandbox_broker_session_protocol::ProtectedBrokerSessionVerificationContextV1;
use aos_sandbox_network::namespace_catalog::{
    BrokerNetworkInventoryObservationDispositionV1, BrokerNetworkInventoryOutcomeCauseV1,
    BrokerNetworkInventoryOutcomeReceiptV1, BrokerNetworkInventoryReservationDispositionV1,
    BrokerNetworkInventoryReservationV1, NetworkNamespaceCatalogV1,
};
use aos_sandbox_protocol::authenticated_session::{
    AuthenticatedBrokerSessionStateV1, AuthenticatedNetworkInventoryOutcomeV1,
    AuthenticatedNetworkInventoryRequestV1, AuthenticatedNetworkInventoryTerminalErrorV1,
    SealedInitialNetworkInventoryTrafficProofAdmissionV1,
    checkpoint::{
        NetworkInventoryOutcomeCheckpointDraftV1, NetworkInventoryRequestCheckpointDraftV1,
    },
};

use super::{
    BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES, HandshakeError, InertProvisionalBrokerSession,
    RemotePeerExpectation, RetainedSubject, SeqpacketError, TrafficProofError, TrafficTransition,
    boottime_nanoseconds, channel::BrokerHeads2ChannelV1,
};
use crate::ProtectedBrokerSessionBrokerV1;

/// Owns provisional broker state while awaiting the sequence-one request.
pub(super) struct BrokerDurableAwaitRequestV1 {
    custody: ProtectedBrokerSessionBrokerV1,
    carrier: super::HandshakeCarrier,
    publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    client_packet: Vec<u8>,
    client_subject: RetainedSubject,
    broker_packet: Vec<u8>,
    client_process: [u8; 16],
    expectation: RemotePeerExpectation,
    state: AuthenticatedBrokerSessionStateV1,
    catalog_owner: NetworkNamespaceCatalogV1,
}

/// Retains an authenticated request and its unique catalog reservation.
pub(super) struct BrokerDurableReservedRequestV1 {
    custody: ProtectedBrokerSessionBrokerV1,
    carrier: super::HandshakeCarrier,
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
    catalog_owner: NetworkNamespaceCatalogV1,
    reservation: BrokerNetworkInventoryReservationV1,
}

/// Owns one durably committed exact outcome until its atomic send succeeds.
pub(super) struct BrokerDurableCommittedOutcomeV1 {
    custody: ProtectedBrokerSessionBrokerV1,
    carrier: super::HandshakeCarrier,
    publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    client_packet: Vec<u8>,
    client_subject: RetainedSubject,
    request_subject: RetainedSubject,
    broker_packet: Vec<u8>,
    client_process: [u8; 16],
    expectation: RemotePeerExpectation,
    request_packet: Vec<u8>,
    outcome_packet: Vec<u8>,
    request: AuthenticatedNetworkInventoryRequestV1,
    outcome: AuthenticatedNetworkInventoryOutcomeV1,
    state: AuthenticatedBrokerSessionStateV1,
    catalog_owner: NetworkNamespaceCatalogV1,
    receipt: BrokerNetworkInventoryOutcomeReceiptV1,
}

impl InertProvisionalBrokerSession {
    /// Adopts the protected catalog owner before receiving durable traffic.
    pub(super) fn await_durable_initial_inventory(
        self,
        expectation: RemotePeerExpectation,
        catalog_owner: NetworkNamespaceCatalogV1,
    ) -> Result<BrokerDurableAwaitRequestV1, TrafficProofError> {
        let InertProvisionalBrokerSession {
            mut _custody,
            mut _carrier,
            _publication,
            _client_packet,
            _client_subject,
            _broker_packet,
            _transcript,
        } = self;
        let client_process = _transcript.client_process();
        let result = (|| {
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
                .context_for_handshake(client_process)
                .map_err(|_| TrafficProofError::Local)?;
            AuthenticatedBrokerSessionStateV1::from_hello_packets(
                &_client_packet,
                &_broker_packet,
                &context,
            )
            .map_err(|_| TrafficProofError::Local)
        })();
        let state = match result {
            Ok(value) => value,
            Err(error) => {
                _carrier.close();
                return Err(error);
            }
        };

        Ok(BrokerDurableAwaitRequestV1 {
            custody: _custody,
            carrier: _carrier,
            publication: _publication,
            client_packet: _client_packet,
            client_subject: _client_subject,
            broker_packet: _broker_packet,
            client_process,
            expectation,
            state,
            catalog_owner,
        })
    }
}

impl BrokerDurableAwaitRequestV1 {
    /// Receives, authenticates, and reserves the exact initial request.
    pub(super) fn receive(
        mut self,
    ) -> TrafficTransition<BrokerDurableReservedRequestV1, BrokerDurableAwaitRequestV1> {
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
            Ok(value) => value,
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
            Ok(value) => value,
            Err(error) => {
                self.carrier.close();
                return TrafficTransition::Failed(error);
            }
        };
        let now = match boottime_nanoseconds() {
            Ok(value) => value,
            Err(error) => {
                self.carrier.close();
                return TrafficTransition::Failed(error);
            }
        };
        let (request, state, expired) = match self
            .state
            .admit_initial_network_inventory_traffic_proof_request(
                &flight.payload,
                0,
                self.expectation.credentials,
                self.expectation.policy,
                now,
                &context,
            ) {
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
        let request_draft = match NetworkInventoryRequestCheckpointDraftV1::derive(&request) {
            Ok(value) => value,
            Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::Local);
            }
        };
        let reservation = match self
            .catalog_owner
            .reserve_initial_authenticated_inventory_request(request_draft)
        {
            Ok(BrokerNetworkInventoryReservationDispositionV1::Reserved(value)) => value,
            Ok(
                BrokerNetworkInventoryReservationDispositionV1::Pending
                | BrokerNetworkInventoryReservationDispositionV1::ExactCompleted,
            )
            | Err(_) => {
                self.carrier.close();
                return TrafficTransition::Failed(TrafficProofError::Local);
            }
        };
        if let Err(error) = validate_broker_context(
            &mut self.custody,
            &self.carrier,
            self.expectation,
            &self.client_subject,
            Some(&flight.subject),
            self.client_process,
            &state,
        ) {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }

        TrafficTransition::Complete(BrokerDurableReservedRequestV1 {
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
            catalog_owner: self.catalog_owner,
            reservation,
        })
    }

    fn precheck(&mut self) -> Result<(), TrafficProofError> {
        validate_broker_context(
            &mut self.custody,
            &self.carrier,
            self.expectation,
            &self.client_subject,
            None,
            self.client_process,
            &self.state,
        )
    }

    fn context(&self) -> Result<ProtectedBrokerSessionVerificationContextV1, TrafficProofError> {
        self.custody
            .context_for_handshake(self.client_process)
            .map_err(|_| TrafficProofError::Local)
    }
}

impl BrokerDurableReservedRequestV1 {
    /// Selects, signs, commits, and rechecks the sole causal initial outcome.
    pub(super) fn prepare(mut self) -> Result<BrokerDurableCommittedOutcomeV1, TrafficProofError> {
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return Err(error);
        }
        let BrokerDurableReservedRequestV1 {
            mut custody,
            mut carrier,
            publication,
            client_packet,
            client_subject,
            request_subject,
            broker_packet,
            client_process,
            expectation,
            request_packet,
            request,
            state,
            expired,
            mut catalog_owner,
            reservation,
        } = self;

        let prepared = (|| {
            let context = custody
                .context_for_handshake(client_process)
                .map_err(|_| TrafficProofError::Local)?;
            let (cause, plan) = if expired {
                let cause = BrokerNetworkInventoryOutcomeCauseV1::deadline_expired(reservation);
                let plan = state
                    .into_network_inventory_terminal_outcome_plan(
                        AuthenticatedNetworkInventoryTerminalErrorV1::DeadlineExpired,
                        &context,
                    )
                    .map_err(|_| TrafficProofError::Local)?;
                (cause, plan)
            } else {
                match catalog_owner
                    .observe_reserved_inventory(reservation)
                    .map_err(|_| TrafficProofError::Local)?
                {
                    BrokerNetworkInventoryObservationDispositionV1::Available(observation) => {
                        let body = observation
                            .canonical_body_with_broker_instance_id(
                                custody.process_execution_id_bytes(),
                            )
                            .map_err(|_| TrafficProofError::Local)?;
                        let cause = BrokerNetworkInventoryOutcomeCauseV1::Available(observation);
                        let plan = state
                            .into_network_inventory_success_outcome_plan(body, &context)
                            .map_err(|_| TrafficProofError::Local)?;
                        (cause, plan)
                    }
                    BrokerNetworkInventoryObservationDispositionV1::Unavailable(observation) => {
                        let cause = BrokerNetworkInventoryOutcomeCauseV1::Unavailable(observation);
                        let plan = state
                            .into_network_inventory_terminal_outcome_plan(
                                AuthenticatedNetworkInventoryTerminalErrorV1::IntegrityFailure,
                                &context,
                            )
                            .map_err(|_| TrafficProofError::Local)?;
                        (cause, plan)
                    }
                }
            };
            let prepared = custody
                .finalize_initial_broker_outcome(plan, client_process)
                .map_err(|_| TrafficProofError::Local)?;
            let (outcome_packet, outcome, state) = prepared.into_parts();
            if !state.has_initial_traffic_proof() {
                return Err(TrafficProofError::Local);
            }
            let outcome_draft = NetworkInventoryOutcomeCheckpointDraftV1::derive(&outcome)
                .map_err(|_| TrafficProofError::Local)?;
            let receipt = catalog_owner
                .commit_initial_authenticated_inventory_outcome(cause, outcome_draft)
                .map_err(|_| TrafficProofError::Local)?;
            catalog_owner
                .recheck_initial_authenticated_inventory_outcome(&receipt)
                .map_err(|_| TrafficProofError::Local)?;

            Ok((outcome_packet, outcome, *state, receipt))
        })();
        let (outcome_packet, outcome, state, receipt) = match prepared {
            Ok(value) => value,
            Err(error) => {
                carrier.close();
                return Err(error);
            }
        };
        if validate_broker_context(
            &mut custody,
            &carrier,
            expectation,
            &client_subject,
            Some(&request_subject),
            client_process,
            &state,
        )
        .is_err()
            || catalog_owner
                .recheck_initial_authenticated_inventory_outcome(&receipt)
                .is_err()
        {
            carrier.close();
            return Err(TrafficProofError::Local);
        }

        Ok(BrokerDurableCommittedOutcomeV1 {
            custody,
            carrier,
            publication,
            client_packet,
            client_subject,
            request_subject,
            broker_packet,
            client_process,
            expectation,
            request_packet,
            outcome_packet,
            request,
            outcome,
            state,
            catalog_owner,
            receipt,
        })
    }

    fn precheck(&mut self) -> Result<(), TrafficProofError> {
        validate_broker_context(
            &mut self.custody,
            &self.carrier,
            self.expectation,
            &self.client_subject,
            Some(&self.request_subject),
            self.client_process,
            &self.state,
        )
    }
}

impl BrokerDurableCommittedOutcomeV1 {
    /// Sends only the exact outcome whose Completed receipt remains current.
    pub(super) fn send(
        mut self,
    ) -> TrafficTransition<BrokerHeads2ChannelV1, BrokerDurableCommittedOutcomeV1> {
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        let result = self.carrier.send(&self.outcome_packet);
        if let Err(error) = self.precheck() {
            self.carrier.close();
            return TrafficTransition::Failed(error);
        }
        match result {
            Ok(()) if self.state.has_initial_traffic_proof() => {
                TrafficTransition::Complete(BrokerHeads2ChannelV1 {
                    _custody: self.custody,
                    _carrier: self.carrier,
                    _publication: self.publication,
                    _client_packet: self.client_packet,
                    _client_subject: self.client_subject,
                    _request_subject: self.request_subject,
                    _broker_packet: self.broker_packet,
                    _client_process: self.client_process,
                    _expectation: self.expectation,
                    _request_packet: self.request_packet,
                    _outcome_packet: self.outcome_packet,
                    _state: self.state,
                    _request: self.request,
                    _outcome: self.outcome,
                    _catalog_owner: self.catalog_owner,
                    _outcome_receipt: self.receipt,
                })
            }
            Ok(()) => {
                self.carrier.close();
                TrafficTransition::Failed(TrafficProofError::Local)
            }
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
        validate_broker_context(
            &mut self.custody,
            &self.carrier,
            self.expectation,
            &self.client_subject,
            Some(&self.request_subject),
            self.client_process,
            &self.state,
        )?;
        self.catalog_owner
            .recheck_initial_authenticated_inventory_outcome(&self.receipt)
            .map_err(|_| TrafficProofError::Local)
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_broker_context(
    custody: &mut ProtectedBrokerSessionBrokerV1,
    carrier: &super::HandshakeCarrier,
    expectation: RemotePeerExpectation,
    client_subject: &RetainedSubject,
    request_subject: Option<&RetainedSubject>,
    client_process: [u8; 16],
    state: &AuthenticatedBrokerSessionStateV1,
) -> Result<(), TrafficProofError> {
    custody
        .revalidate_handshake_custody()
        .map_err(|_| TrafficProofError::Local)?;
    carrier
        .validate_peer()
        .map_err(|_| TrafficProofError::RemoteInvalid)?;
    carrier.validate_remote_expectation(expectation)?;
    client_subject
        .validate()
        .map_err(|_| TrafficProofError::RemoteInvalid)?;
    if let Some(subject) = request_subject {
        subject
            .validate()
            .map_err(|_| TrafficProofError::RemoteInvalid)?;
        if !client_subject.same_execution(subject) {
            return Err(TrafficProofError::RemoteInvalid);
        }
    }
    let context = custody
        .context_for_handshake(client_process)
        .map_err(|_| TrafficProofError::Local)?;
    state
        .require_current_context(&context)
        .map_err(|_| TrafficProofError::Local)
}
