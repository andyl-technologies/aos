//! Authenticated broker traffic composed with complete method semantics.
//!
//! This module owns the transport-neutral boundary between Broker Session
//! Authentication 1.0 and the existing closed broker message validators. The
//! cryptographic crate remains projection-only: this module withholds every
//! candidate traffic state until the selected method body, error shape, and
//! descriptor contract have all validated.
//!
//! The first supported method is Network 1.0 `InventoryResources`. Its request
//! body defines only the common header. It has no catalog, effect, portable
//! semantic, or durable-owner digest, so this module deliberately invents none.
//! Retained evidence consists of the canonical envelope packet, the exact
//! signed and semantically validated nested body bytes, a domain-separated
//! packet digest, the signed ClientRecord bytes and digest, request/session/
//! sequence/response-bound links, and the exact empty descriptor-role table.

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerDescriptorRole, BrokerMethod};
use aos_sandbox_broker_session_protocol::{
    AUTHENTICATED_RESPONSE_MAXIMUM_BYTES, BrokerOutcomeAdmissionV1, BrokerRequestAdmissionV1,
    BrokerSessionProjectionError, BrokerSessionProtocolV1, BrokerSessionReplayEvidenceV1,
    BrokerSessionSequenceError, BrokerSessionTrafficStateV1, BrokerSessionTranscriptError,
    ProtectedBrokerSessionVerificationContextV1, decode_canonical_client_hello_v1,
    decode_canonical_request_v1, decode_canonical_response_v1, decode_canonical_server_hello_v1,
    verify_broker_session_transcript_v1,
};
use sha2::{Digest as _, Sha256};

use crate::network_inventory::{
    ValidatedNetworkInventory, decode_network_resource_inventory_request_static,
    decode_network_resource_inventory_response,
};
use crate::session::{
    ValidatedBrokerError, validate_decoded_request_envelope, validate_decoded_response_envelope,
};
use crate::{PeerCredentials, PeerPolicy, ProtocolValidationError, validate_request_deadline};

const NETWORK_INVENTORY_REQUEST_PACKET_DOMAIN: &[u8] =
    b"aos-sandbox-authenticated-network-inventory-request-packet-v1\0";
const NETWORK_INVENTORY_OUTCOME_PACKET_DOMAIN: &[u8] =
    b"aos-sandbox-authenticated-network-inventory-outcome-packet-v1\0";
const EMPTY_DESCRIPTOR_ROLES: [BrokerDescriptorRole; 0] = [];

/// Reports a failed authenticated handshake, traffic check, or method semantic.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthenticatedBrokerSessionError {
    /// Canonical Broker Session Authentication protobuf validation failed.
    #[error("invalid canonical authenticated broker packet: {0}")]
    Projection(#[from] BrokerSessionProjectionError),
    /// Mutual hello verification or authenticated negotiation failed.
    #[error("authenticated broker transcript failed: {0}")]
    Transcript(#[from] BrokerSessionTranscriptError),
    /// Pure cryptographic traffic sequencing or continuity failed.
    #[error("authenticated broker traffic failed: {0}")]
    Traffic(#[from] BrokerSessionSequenceError),
    /// The selected method's complete legacy semantics failed.
    #[error("authenticated broker method semantics failed: {0}")]
    Semantics(#[from] ProtocolValidationError),
    /// The authenticated transcript is not the exact supported method profile.
    #[error("authenticated broker transcript does not support Network Inventory 1.0")]
    UnsupportedProfile,
    /// A cryptographic replay did not reproduce the retained semantic packet.
    #[error("authenticated broker semantic replay differs from retained packet")]
    SemanticEquivocation,
    /// Internal retained method state is inconsistent with cryptographic state.
    #[error("authenticated broker semantic state is inconsistent")]
    InconsistentState,
}

/// Retains a completely validated Network Inventory request without authority.
///
/// This value is evidence for a future caller-owned atomic transaction. It is
/// not a dispatch permit, descriptor-use permit, journal reservation, protected
/// provenance proof, or authorization claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedNetworkInventoryRequestV1 {
    canonical_packet_bytes: Vec<u8>,
    canonical_packet_digest: [u8; 32],
    exact_body_bytes: Vec<u8>,
    request_id: [u8; 16],
    maximum_response_bytes: u32,
    deadline_boottime_nanoseconds: u64,
    session_binding: [u8; 32],
    client_sequence: u64,
    signed_request_bytes: Vec<u8>,
    signed_request_digest: [u8; 32],
}

impl AuthenticatedNetworkInventoryRequestV1 {
    /// Returns the sole closed method/verb represented by this evidence.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
    }

    /// Returns the exact canonical authenticated request packet.
    #[must_use]
    pub fn canonical_packet_bytes(&self) -> &[u8] {
        &self.canonical_packet_bytes
    }

    /// Returns the domain-separated digest of the complete canonical packet.
    #[must_use]
    pub const fn canonical_packet_digest(&self) -> [u8; 32] {
        self.canonical_packet_digest
    }

    /// Returns the exact signed, semantically validated request body bytes.
    ///
    /// The containing envelope is canonical. The nested Network protobuf is
    /// retained exactly as signed and is not independently re-encoded.
    #[must_use]
    pub fn exact_body_bytes(&self) -> &[u8] {
        &self.exact_body_bytes
    }

    /// Returns the request ID derived only from the validated method body.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the response ceiling derived only from the validated body.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the validated absolute `CLOCK_BOOTTIME` deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the exact client-then-broker session binding.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the authenticated client-to-broker sequence.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }

    /// Returns the complete canonical signed ClientRecord artifact bytes.
    #[must_use]
    pub fn signed_request_bytes(&self) -> &[u8] {
        &self.signed_request_bytes
    }

    /// Returns the signed ClientRecord digest cross-linked by the outcome.
    #[must_use]
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.signed_request_digest
    }

    /// Returns the exact signed descriptor-role table, which is empty here.
    #[must_use]
    pub const fn descriptor_roles(&self) -> &[BrokerDescriptorRole] {
        &EMPTY_DESCRIPTOR_ROLES
    }
}

/// Carries the fully validated semantic result of one signed Network outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticatedNetworkInventoryResultV1 {
    /// The complete authoritative Network inventory decoded successfully.
    Success(ValidatedNetworkInventory),
    /// The broker returned one completely validated signed terminal error.
    Error(ValidatedBrokerError),
}

/// Retains one complete authenticated Network Inventory outcome.
///
/// The result is non-authorizing and non-committing. In particular, successful
/// inventory bytes do not prove protected catalog provenance or install a
/// controller snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedNetworkInventoryOutcomeV1 {
    canonical_packet_bytes: Vec<u8>,
    canonical_packet_digest: [u8; 32],
    signed_outcome_bytes: Vec<u8>,
    request: AuthenticatedNetworkInventoryRequestV1,
    broker_sequence: u64,
    result: AuthenticatedNetworkInventoryResultV1,
}

impl AuthenticatedNetworkInventoryOutcomeV1 {
    /// Returns the exact canonical authenticated response packet.
    #[must_use]
    pub fn canonical_packet_bytes(&self) -> &[u8] {
        &self.canonical_packet_bytes
    }

    /// Returns the domain-separated digest of the complete response packet.
    #[must_use]
    pub const fn canonical_packet_digest(&self) -> [u8; 32] {
        self.canonical_packet_digest
    }

    /// Returns the complete canonical signed BrokerOutcome artifact bytes.
    #[must_use]
    pub fn signed_outcome_bytes(&self) -> &[u8] {
        &self.signed_outcome_bytes
    }

    /// Returns the complete request evidence cross-linked by this outcome.
    #[must_use]
    pub const fn request(&self) -> &AuthenticatedNetworkInventoryRequestV1 {
        &self.request
    }

    /// Returns the request ID correlated through the retained request.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request.request_id()
    }

    /// Returns the authenticated broker-to-client sequence.
    #[must_use]
    pub const fn broker_sequence(&self) -> u64 {
        self.broker_sequence
    }

    /// Returns the fully validated success inventory or terminal error.
    #[must_use]
    pub const fn result(&self) -> &AuthenticatedNetworkInventoryResultV1 {
        &self.result
    }

    /// Returns the exact response descriptor-role table, which is empty here.
    #[must_use]
    pub const fn descriptor_roles(&self) -> &[BrokerDescriptorRole] {
        &EMPTY_DESCRIPTOR_ROLES
    }
}

/// Classifies a new semantic request or byte-identical retained replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticatedNetworkInventoryRequestAdmissionV1 {
    /// A new request and candidate next composite state.
    New {
        /// Complete non-authorizing semantic request evidence.
        request: AuthenticatedNetworkInventoryRequestV1,
        /// Candidate state; the caller still owns any durable reservation.
        next_state: Box<AuthenticatedBrokerSessionStateV1>,
    },
    /// A byte-identical outstanding or latest-completed request replay.
    ExactReplay {
        /// Complete retained semantic request evidence.
        request: AuthenticatedNetworkInventoryRequestV1,
        /// Pure cryptographic no-write replay evidence.
        replay: BrokerSessionReplayEvidenceV1,
    },
}

/// Classifies a new semantic outcome or byte-identical retained replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticatedNetworkInventoryOutcomeAdmissionV1 {
    /// A new terminal result and candidate next composite state.
    New {
        /// Complete non-authorizing semantic outcome evidence.
        outcome: AuthenticatedNetworkInventoryOutcomeV1,
        /// Candidate state; no catalog or journal is installed by this module.
        next_state: Box<AuthenticatedBrokerSessionStateV1>,
    },
    /// A byte-identical replay of the latest completed outcome.
    ExactReplay {
        /// Complete retained semantic outcome evidence.
        outcome: AuthenticatedNetworkInventoryOutcomeV1,
        /// Pure cryptographic no-write replay evidence.
        replay: BrokerSessionReplayEvidenceV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompletedNetworkInventoryV1 {
    outcome: AuthenticatedNetworkInventoryOutcomeV1,
}

/// Owns authenticated traffic state plus retained complete method semantics.
///
/// Construction requires canonical mutual hellos and exact transcript
/// verification. Fields remain opaque so callers cannot install semantic state
/// or bypass the provisional first-request proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedBrokerSessionStateV1 {
    traffic: BrokerSessionTrafficStateV1,
    outstanding_network_inventory: Option<AuthenticatedNetworkInventoryRequestV1>,
    completed_network_inventory: Option<CompletedNetworkInventoryV1>,
}

impl AuthenticatedBrokerSessionStateV1 {
    /// Verifies canonical hello packets and creates provisional composite state.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] for malformed or
    /// noncanonical hellos, failed negotiation/cryptography, or a transcript
    /// that cannot initialize provisional traffic state.
    pub fn from_hello_packets(
        client_hello_bytes: &[u8],
        broker_hello_bytes: &[u8],
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<Self, AuthenticatedBrokerSessionError> {
        let client = decode_canonical_client_hello_v1(client_hello_bytes)?;
        let broker = decode_canonical_server_hello_v1(broker_hello_bytes)?;
        let transcript = verify_broker_session_transcript_v1(&client, &broker, context)?;
        let traffic = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript)?;

        Ok(Self {
            traffic,
            outstanding_network_inventory: None,
            completed_network_inventory: None,
        })
    }

    /// Returns the state-derived raw request receive ceiling.
    #[must_use]
    pub const fn maximum_request_receive_bytes(&self) -> usize {
        self.traffic.transcript().negotiated_maximum_request_bytes()
    }

    /// Returns the state-derived raw outcome receive ceiling, when one exists.
    #[must_use]
    pub fn maximum_outcome_receive_bytes(&self) -> Option<usize> {
        let outstanding = self
            .outstanding_network_inventory
            .as_ref()
            .map(AuthenticatedNetworkInventoryRequestV1::maximum_response_bytes);
        let completed = self
            .completed_network_inventory
            .as_ref()
            .map(|exchange| exchange.outcome.request().maximum_response_bytes());
        let retained = match (outstanding, completed) {
            (Some(left), Some(right)) => left.max(right),
            (Some(bound), None) | (None, Some(bound)) => bound,
            (None, None) => return None,
        };
        let bound = retained
            .min(
                self.traffic
                    .transcript()
                    .negotiated_maximum_response_bytes(),
            )
            .min(u32::try_from(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES).unwrap_or(u32::MAX));
        usize::try_from(bound).ok()
    }

    /// Admits a complete authenticated Network Inventory request.
    ///
    /// `peer`, `policy`, and `now_boottime_nanoseconds` are observations from
    /// the caller's transport/protected environment. `actual_descriptor_count`
    /// must be the count on this exact packet and is required to be zero.
    /// Request ID, method, and response budget are derived only after the body
    /// has passed its existing closed validator. Deadline freshness applies to
    /// new work; exact no-write replay still rechecks peer policy, protected
    /// context, cryptography, and retained complete packet identity without
    /// expiring at the original deadline.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] for an unsupported
    /// transcript, nonzero actual descriptors, malformed or invalid method
    /// semantics, failed cryptography/currentness, or traffic-state failure.
    pub fn admit_network_inventory_request(
        &self,
        bytes: &[u8],
        actual_descriptor_count: usize,
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<AuthenticatedNetworkInventoryRequestAdmissionV1, AuthenticatedBrokerSessionError>
    {
        self.require_network_inventory_profile()?;
        if actual_descriptor_count != 0 {
            return Err(ProtocolValidationError::DescriptorTableMismatch.into());
        }
        if bytes.len() > self.maximum_request_receive_bytes() {
            return Err(ProtocolValidationError::RequestTooLarge.into());
        }

        let canonical = decode_canonical_request_v1(bytes)?;
        let envelope = validate_decoded_request_envelope(
            canonical.message().clone(),
            aos_sandbox_core::ProtocolId::NetworkBroker,
            actual_descriptor_count,
        )?;
        if envelope.method() != BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
            || envelope.authorization().is_some()
            || !envelope.descriptors().is_empty()
        {
            return Err(ProtocolValidationError::MethodMismatch.into());
        }
        let header =
            decode_network_resource_inventory_request_static(envelope.body(), peer, policy)?;
        let transcript = self.traffic.transcript();
        if header.protocol_version() != aos_sandbox_core::ProtocolVersion::new(1, 0)
            || header.audience() != transcript.audience()
        {
            return Err(ProtocolValidationError::MethodMismatch.into());
        }

        let request_id = *header.request_id();
        let response_bound = header.maximum_response_bytes();
        let admission =
            self.traffic
                .admit_request(&canonical, request_id, response_bound, context)?;
        match admission {
            BrokerRequestAdmissionV1::New {
                request,
                next_state,
            } => {
                validate_request_deadline(&header, now_boottime_nanoseconds)?;
                let evidence = AuthenticatedNetworkInventoryRequestV1 {
                    canonical_packet_bytes: bytes.to_vec(),
                    canonical_packet_digest: packet_digest(
                        NETWORK_INVENTORY_REQUEST_PACKET_DOMAIN,
                        bytes,
                    )?,
                    exact_body_bytes: envelope.body().to_vec(),
                    request_id,
                    maximum_response_bytes: response_bound,
                    deadline_boottime_nanoseconds: header.deadline_boottime_nanoseconds(),
                    session_binding: transcript.session_binding(),
                    client_sequence: request.sequence(),
                    signed_request_bytes: canonical.signed_artifact().to_canonical_bytes(),
                    signed_request_digest: request.signed_request_digest(),
                };
                let mut state = self.clone();
                state.traffic = *next_state;
                state.outstanding_network_inventory = Some(evidence.clone());

                Ok(AuthenticatedNetworkInventoryRequestAdmissionV1::New {
                    request: evidence,
                    next_state: Box::new(state),
                })
            }
            BrokerRequestAdmissionV1::ExactReplay(replay) => {
                let retained = self.retained_request(&replay)?;
                if retained.canonical_packet_bytes() != bytes {
                    return Err(AuthenticatedBrokerSessionError::SemanticEquivocation);
                }
                Ok(
                    AuthenticatedNetworkInventoryRequestAdmissionV1::ExactReplay {
                        request: retained.clone(),
                        replay,
                    },
                )
            }
        }
    }

    /// Admits a complete signed Network Inventory success or error outcome.
    ///
    /// The state-derived bound is checked by the underlying raw traffic entry
    /// point before protobuf allocation. The candidate cryptographic state is
    /// discarded unless full response/error/descriptor semantics and, on
    /// success, the complete Network inventory all validate.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] for absent retained bounds,
    /// nonzero actual descriptors, failed cryptography/currentness, correlation
    /// mismatch, malformed error/body shape, or invalid inventory semantics.
    pub fn admit_network_inventory_outcome(
        &self,
        bytes: &[u8],
        actual_descriptor_count: usize,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<AuthenticatedNetworkInventoryOutcomeAdmissionV1, AuthenticatedBrokerSessionError>
    {
        self.require_network_inventory_profile()?;
        if actual_descriptor_count != 0 {
            return Err(ProtocolValidationError::DescriptorTableMismatch.into());
        }
        let admission = self.traffic.decode_and_admit_outcome(bytes, context)?;
        let canonical = decode_canonical_response_v1(bytes)?;

        match admission {
            BrokerOutcomeAdmissionV1::New {
                outcome,
                next_state,
            } => {
                let request = self
                    .outstanding_network_inventory
                    .as_ref()
                    .ok_or(AuthenticatedBrokerSessionError::InconsistentState)?;
                let semantic = self.validate_network_inventory_outcome(
                    bytes,
                    &canonical,
                    request,
                    actual_descriptor_count,
                    context,
                    outcome.sequence(),
                )?;
                let completed = CompletedNetworkInventoryV1 {
                    outcome: semantic.clone(),
                };
                let mut state = self.clone();
                state.traffic = *next_state;
                state.outstanding_network_inventory = None;
                state.completed_network_inventory = Some(completed);

                Ok(AuthenticatedNetworkInventoryOutcomeAdmissionV1::New {
                    outcome: semantic,
                    next_state: Box::new(state),
                })
            }
            BrokerOutcomeAdmissionV1::ExactReplay(replay) => {
                let completed = self
                    .completed_network_inventory
                    .as_ref()
                    .ok_or(AuthenticatedBrokerSessionError::InconsistentState)?;
                if completed.outcome.canonical_packet_bytes() != bytes {
                    return Err(AuthenticatedBrokerSessionError::SemanticEquivocation);
                }
                self.validate_network_inventory_outcome(
                    bytes,
                    &canonical,
                    completed.outcome.request(),
                    actual_descriptor_count,
                    context,
                    replay.sequence(),
                )?;

                Ok(
                    AuthenticatedNetworkInventoryOutcomeAdmissionV1::ExactReplay {
                        outcome: completed.outcome.clone(),
                        replay,
                    },
                )
            }
        }
    }

    fn require_network_inventory_profile(&self) -> Result<(), AuthenticatedBrokerSessionError> {
        let transcript = self.traffic.transcript();
        if transcript.protocol() != BrokerSessionProtocolV1::Network
            || transcript.protocol_version() != (1, 0)
            || transcript.audience() != Audience::AUDIENCE_NODE_CONTROLLER
            || !transcript
                .negotiated_methods()
                .contains(&BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES)
        {
            return Err(AuthenticatedBrokerSessionError::UnsupportedProfile);
        }
        Ok(())
    }

    fn retained_request(
        &self,
        replay: &BrokerSessionReplayEvidenceV1,
    ) -> Result<&AuthenticatedNetworkInventoryRequestV1, AuthenticatedBrokerSessionError> {
        self.outstanding_network_inventory
            .as_ref()
            .filter(|request| {
                request.request_id() == replay.request_id()
                    && request.client_sequence() == replay.sequence()
            })
            .or_else(|| {
                self.completed_network_inventory
                    .as_ref()
                    .map(|exchange| exchange.outcome.request())
                    .filter(|request| {
                        request.request_id() == replay.request_id()
                            && request.client_sequence() == replay.sequence()
                    })
            })
            .ok_or(AuthenticatedBrokerSessionError::InconsistentState)
    }

    fn validate_network_inventory_outcome(
        &self,
        bytes: &[u8],
        canonical: &aos_sandbox_broker_session_protocol::CanonicalBrokerResponseEnvelopeV1,
        request: &AuthenticatedNetworkInventoryRequestV1,
        actual_descriptor_count: usize,
        context: &ProtectedBrokerSessionVerificationContextV1,
        broker_sequence: u64,
    ) -> Result<AuthenticatedNetworkInventoryOutcomeV1, AuthenticatedBrokerSessionError> {
        let envelope = validate_decoded_response_envelope(
            canonical.message().clone(),
            &request.request_id(),
            request.method(),
            &[],
            actual_descriptor_count,
        )?;
        if !envelope.descriptors().is_empty()
            || !envelope.request_descriptor_dispositions().is_empty()
        {
            return Err(ProtocolValidationError::DescriptorTableMismatch.into());
        }
        let result = if let Some(error) = envelope.error() {
            AuthenticatedNetworkInventoryResultV1::Error(error.clone())
        } else {
            let inventory = decode_network_resource_inventory_response(
                envelope.body(),
                request.maximum_response_bytes(),
            )?;
            if inventory.kernel_boot_id() != &context.boot_id()
                || inventory.broker_instance_id() != &context.broker_process()
            {
                return Err(ProtocolValidationError::InvalidField(
                    "authenticated Network inventory identity",
                )
                .into());
            }
            AuthenticatedNetworkInventoryResultV1::Success(inventory)
        };

        Ok(AuthenticatedNetworkInventoryOutcomeV1 {
            canonical_packet_bytes: bytes.to_vec(),
            canonical_packet_digest: packet_digest(NETWORK_INVENTORY_OUTCOME_PACKET_DOMAIN, bytes)?,
            signed_outcome_bytes: canonical.signed_artifact().to_canonical_bytes(),
            request: request.clone(),
            broker_sequence,
            result,
        })
    }
}

fn packet_digest(domain: &[u8], bytes: &[u8]) -> Result<[u8; 32], AuthenticatedBrokerSessionError> {
    let length =
        u32::try_from(bytes.len()).map_err(|_| ProtocolValidationError::ResponseTooLarge)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(length.to_be_bytes());
    digest.update(bytes);
    Ok(digest.finalize().into())
}
