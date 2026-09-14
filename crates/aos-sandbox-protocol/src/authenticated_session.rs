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

/// Holds production-inert checkpoint companion drafts for sealed composition.
#[doc(hidden)]
pub mod checkpoint;

use aos_proto::aos::sandbox::local::v1::{
    BrokerDescriptorRole, BrokerErrorCode, BrokerMethod, BrokerRequestEnvelope,
    BrokerResponseEnvelope, InventoryNetworksRequest, RequestHeader,
};
use aos_sandbox_broker_session_protocol::{
    AUTHENTICATED_RESPONSE_MAXIMUM_BYTES, BrokerOutcomeAdmissionV1, BrokerOutcomeSubjectV1,
    BrokerRequestAdmissionV1, BrokerRequestSubjectV1, BrokerSessionAuthorizationPresenceV1,
    BrokerSessionMethodProfileV1, BrokerSessionProjectionError, BrokerSessionProtocolV1,
    BrokerSessionReplayEvidenceV1, BrokerSessionSequenceError, BrokerSessionSuccessBodyPresenceV1,
    BrokerSessionTrafficStateV1, BrokerSessionTranscriptError,
    ProtectedBrokerSessionVerificationContextV1, SignedBrokerOutcomeV1, SignedBrokerRequestV1,
    authenticated_broker_method_profile_v1, authenticated_response_cleared_budget_v1,
    decode_canonical_client_hello_v1, decode_canonical_request_v1, decode_canonical_response_v1,
    decode_canonical_server_hello_v1, encode_signed_request_packet_v1,
    encode_signed_response_packet_v1, outcome_fields_digest_v1, request_fields_digest_v1,
    verify_broker_session_transcript_v1,
};
use aos_sandbox_core::{FeatureRef, ProtocolId};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::network_inventory::{
    ValidatedNetworkInventory, decode_network_resource_inventory_request_static,
    decode_network_resource_inventory_response,
};
use crate::session::{
    ValidatedBrokerError, ValidatedBrokerRequestEnvelope,
    encode_authenticated_error_response_envelope, encode_authenticated_success_response_envelope,
    validate_decoded_request_envelope, validate_decoded_response_envelope,
};
use crate::{PeerCredentials, PeerPolicy, ProtocolValidationError, validate_request_deadline};

const NETWORK_INVENTORY_REQUEST_PACKET_DOMAIN: &[u8] =
    b"aos-sandbox-authenticated-network-inventory-request-packet-v1\0";
const NETWORK_INVENTORY_OUTCOME_PACKET_DOMAIN: &[u8] =
    b"aos-sandbox-authenticated-network-inventory-outcome-packet-v1\0";

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
    first_traffic_key_proof: bool,
    expired_on_first_admission: bool,
    validated_envelope: ValidatedBrokerRequestEnvelope,
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

    /// Reports whether this request is the mandatory sequence-one traffic-key proof.
    #[must_use]
    pub const fn first_traffic_key_proof(&self) -> bool {
        self.first_traffic_key_proof
    }

    /// Reports whether first admission found the authenticated deadline expired.
    #[must_use]
    pub const fn expired_on_first_admission(&self) -> bool {
        self.expired_on_first_admission
    }

    /// Returns the exact signed descriptor-role table, which is empty here.
    #[must_use]
    pub fn descriptor_roles(&self) -> &[BrokerDescriptorRole] {
        match authenticated_broker_method_profile_v1(self.method()) {
            Some(profile) => profile.request_descriptor_roles(),
            None => &[],
        }
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
    pub fn descriptor_roles(&self) -> &[BrokerDescriptorRole] {
        match authenticated_broker_method_profile_v1(self.request.method()) {
            Some(profile) => profile.success_response_descriptor_roles(),
            None => &[],
        }
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

/// Carries the sealed sequence-one traffic proof's deadline classification.
///
/// This doc-hidden integration result exists solely for the production-inert
/// broker-session security composition. Its evidence remains non-authorizing,
/// and it exposes no signing key, verification context, socket, or descriptor.
#[doc(hidden)]
pub enum SealedInitialNetworkInventoryTrafficProofAdmissionV1 {
    /// The authenticated sequence-one request is fresh enough for work.
    Fresh {
        /// Complete non-authorizing semantic request evidence.
        request: AuthenticatedNetworkInventoryRequestV1,
        /// Candidate outstanding state retained before any outcome is planned.
        next_state: Box<AuthenticatedBrokerSessionStateV1>,
    },
    /// The authenticated sequence-one request was expired on first admission.
    AuthenticatedExpired {
        /// Complete non-authorizing semantic request evidence.
        request: AuthenticatedNetworkInventoryRequestV1,
        /// Candidate outstanding state that permits only fixed DeadlineExpired.
        next_state: Box<AuthenticatedBrokerSessionStateV1>,
    },
}

/// Selects one closed terminal result that may be signed without dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedNetworkInventoryTerminalErrorV1 {
    /// The completely authenticated request was already past its deadline.
    DeadlineExpired,
    /// A valid authoritative inventory exceeded the admitted response ceiling.
    ResourceExhausted,
    /// The authoritative Network inventory is unavailable or lacks integrity.
    IntegrityFailure,
}

/// Holds one unsigned, non-authorizing sequence-one ClientRecord plan.
///
/// The plan owns the provisional state and can only be completed with an exact
/// purpose-specific signed artifact. It is deliberately non-cloneable.
pub struct AuthenticatedNetworkInventoryRequestSigningPlanV1 {
    state: AuthenticatedBrokerSessionStateV1,
    message: BrokerRequestEnvelope,
    subject: BrokerRequestSubjectV1,
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
}

impl AuthenticatedNetworkInventoryRequestSigningPlanV1 {
    /// Returns the exact ClientRecord subject to sign with the dedicated key.
    #[must_use]
    pub const fn signing_subject(&self) -> &BrokerRequestSubjectV1 {
        &self.subject
    }

    /// Attaches and locally admits the exact purpose-specific signature.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] unless the signature and
    /// complete packet match this plan and yield a fresh new admission.
    pub fn finalize(
        self,
        signed: &SignedBrokerRequestV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<PreparedAuthenticatedNetworkInventoryRequestV1, AuthenticatedBrokerSessionError>
    {
        let packet = encode_signed_request_packet_v1(self.message, signed)?;
        let admission = self.state.admit_network_inventory_request(
            &packet,
            0,
            self.peer,
            self.policy,
            self.now_boottime_nanoseconds,
            context,
        )?;
        match admission {
            AuthenticatedNetworkInventoryRequestAdmissionV1::New {
                request,
                next_state,
            } => Ok(PreparedAuthenticatedNetworkInventoryRequestV1 {
                packet,
                expired: request.expired_on_first_admission(),
                request,
                next_state,
            }),
            AuthenticatedNetworkInventoryRequestAdmissionV1::ExactReplay { .. } => {
                Err(AuthenticatedBrokerSessionError::InconsistentState)
            }
        }
    }
}

/// Retains an exact locally admitted request and its candidate next state.
pub struct PreparedAuthenticatedNetworkInventoryRequestV1 {
    packet: Vec<u8>,
    request: AuthenticatedNetworkInventoryRequestV1,
    next_state: Box<AuthenticatedBrokerSessionStateV1>,
    expired: bool,
}

impl PreparedAuthenticatedNetworkInventoryRequestV1 {
    /// Returns the exact packet that must be retained across transport retry.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Reports whether only the fixed deadline-expired outcome is permitted.
    #[must_use]
    pub const fn is_expired(&self) -> bool {
        self.expired
    }

    /// Rechecks the retained candidate state's protected context.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] after any context change.
    pub fn require_current_context(
        &self,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<(), AuthenticatedBrokerSessionError> {
        self.next_state.require_current_context(context)
    }

    /// Consumes the plan into its request evidence and candidate state.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<u8>,
        AuthenticatedNetworkInventoryRequestV1,
        Box<AuthenticatedBrokerSessionStateV1>,
    ) {
        (self.packet, self.request, self.next_state)
    }
}

/// Holds one unsigned, closed BrokerOutcome plan for the outstanding request.
pub struct AuthenticatedNetworkInventoryOutcomeSigningPlanV1 {
    state: AuthenticatedBrokerSessionStateV1,
    message: BrokerResponseEnvelope,
    subject: BrokerOutcomeSubjectV1,
    maximum_total_bytes: u32,
}

impl AuthenticatedNetworkInventoryOutcomeSigningPlanV1 {
    /// Returns the exact BrokerOutcome subject to sign with the dedicated key.
    #[must_use]
    pub const fn signing_subject(&self) -> &BrokerOutcomeSubjectV1 {
        &self.subject
    }

    /// Attaches and locally admits the exact purpose-specific signature.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] unless the signature and
    /// complete response match this plan and complete the outstanding request.
    pub fn finalize(
        self,
        signed: &SignedBrokerOutcomeV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<PreparedAuthenticatedNetworkInventoryOutcomeV1, AuthenticatedBrokerSessionError>
    {
        let packet = encode_signed_response_packet_v1(self.message, signed)?;
        if packet.len()
            > usize::try_from(self.maximum_total_bytes)
                .map_err(|_| AuthenticatedBrokerSessionError::InconsistentState)?
        {
            return Err(ProtocolValidationError::ResponseTooLarge.into());
        }
        let admission = self
            .state
            .admit_network_inventory_outcome(&packet, 0, context)?;
        match admission {
            AuthenticatedNetworkInventoryOutcomeAdmissionV1::New {
                outcome,
                next_state,
            } => Ok(PreparedAuthenticatedNetworkInventoryOutcomeV1 {
                packet,
                outcome,
                next_state,
            }),
            AuthenticatedNetworkInventoryOutcomeAdmissionV1::ExactReplay { .. } => {
                Err(AuthenticatedBrokerSessionError::InconsistentState)
            }
        }
    }
}

/// Retains an exact locally admitted outcome and its traffic-proved state.
pub struct PreparedAuthenticatedNetworkInventoryOutcomeV1 {
    packet: Vec<u8>,
    outcome: AuthenticatedNetworkInventoryOutcomeV1,
    next_state: Box<AuthenticatedBrokerSessionStateV1>,
}

impl PreparedAuthenticatedNetworkInventoryOutcomeV1 {
    /// Returns the exact packet that must be retained across transport retry.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Rechecks the completed candidate state's protected context.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] after any context change.
    pub fn require_current_context(
        &self,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<(), AuthenticatedBrokerSessionError> {
        self.next_state.require_current_context(context)
    }

    /// Consumes the prepared outcome into evidence and completed state.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<u8>,
        AuthenticatedNetworkInventoryOutcomeV1,
        Box<AuthenticatedBrokerSessionStateV1>,
    ) {
        (self.packet, self.outcome, self.next_state)
    }
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

    /// Rechecks the exact retained protected context before transport I/O.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] after any context, key, or
    /// currentness substitution. Admission performs the same check again.
    pub fn require_current_context(
        &self,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<(), AuthenticatedBrokerSessionError> {
        self.traffic.require_current_context(context)?;
        Ok(())
    }

    /// Reports whether exactly the mandatory first request/outcome pair completed.
    #[must_use]
    pub fn has_initial_traffic_proof(&self) -> bool {
        self.traffic.next_client_sequence() == 2
            && self.traffic.next_broker_sequence() == 2
            && !self.traffic.has_outstanding_request()
            && self.outstanding_network_inventory.is_none()
            && self.completed_network_inventory.is_some()
    }

    /// Consumes a provisional state into the mandatory sequence-one request plan.
    ///
    /// The request ID must come from protected kernel entropy in the composing
    /// custody layer. This pure method neither signs nor sends the request.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] unless every static Network
    /// Inventory semantic, negotiated bound, context, and sequence invariant holds.
    #[allow(clippy::too_many_arguments)]
    pub fn into_initial_network_inventory_request_plan(
        self,
        request_id: [u8; 16],
        deadline_boottime_nanoseconds: u64,
        maximum_response_bytes: u32,
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<AuthenticatedNetworkInventoryRequestSigningPlanV1, AuthenticatedBrokerSessionError>
    {
        let profile = self.require_network_inventory_profile()?;
        self.require_current_context(context)?;
        self.require_initial_traffic_state()?;
        let (protocol_major, protocol_minor) = profile.version();

        let body = InventoryNetworksRequest {
            header: Some(RequestHeader {
                protocol_major: u32::from(protocol_major),
                protocol_minor: u32::from(protocol_minor),
                request_id: request_id.to_vec(),
                audience: profile.audience().into(),
                deadline_boottime_nanoseconds,
                maximum_response_bytes,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
        .encode_to_vec();
        let message = BrokerRequestEnvelope {
            method: profile.method().into(),
            body,
            ..Default::default()
        };
        let envelope = validate_decoded_request_envelope(
            message.clone(),
            protocol_id_for_profile(profile.protocol()),
            profile.request_descriptor_roles().len(),
        )?;
        validate_request_against_profile(&envelope, &profile)?;
        let header =
            decode_network_resource_inventory_request_static(envelope.body(), peer, policy)?;
        if *header.request_id() != request_id
            || header.maximum_response_bytes() != maximum_response_bytes
            || header.deadline_boottime_nanoseconds() != deadline_boottime_nanoseconds
        {
            return Err(AuthenticatedBrokerSessionError::InconsistentState);
        }
        let fields = request_fields_digest_v1(&message)?;
        let subject = BrokerRequestSubjectV1::new(
            self.traffic.transcript().session_binding(),
            self.traffic.transcript().client_process(),
            1,
            request_id,
            fields,
        )
        .map_err(|_| AuthenticatedBrokerSessionError::InconsistentState)?;

        Ok(AuthenticatedNetworkInventoryRequestSigningPlanV1 {
            state: self,
            message,
            subject,
            peer,
            policy,
            now_boottime_nanoseconds,
        })
    }

    /// Consumes an outstanding state into a validated success outcome plan.
    ///
    /// An otherwise-valid inventory that cannot fit its effective signed packet
    /// ceiling is deterministically converted to the fixed ResourceExhausted error.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] for malformed inventory,
    /// identity mismatch, absent sequence-one request, or context change.
    pub fn into_network_inventory_success_outcome_plan(
        self,
        body: Vec<u8>,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<AuthenticatedNetworkInventoryOutcomeSigningPlanV1, AuthenticatedBrokerSessionError>
    {
        let profile = self.require_network_inventory_profile()?;
        self.require_current_context(context)?;
        validate_success_body_against_profile(&body, &profile)?;
        let inventory = decode_network_resource_inventory_response(
            &body,
            u32::try_from(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES).unwrap_or(u32::MAX),
        )?;
        if inventory.kernel_boot_id() != &context.boot_id()
            || inventory.broker_instance_id() != &context.broker_process()
        {
            return Err(ProtocolValidationError::InvalidField(
                "authenticated Network inventory identity",
            )
            .into());
        }
        let request = self.initial_outstanding_request()?;
        if request.expired_on_first_admission() {
            return Err(AuthenticatedBrokerSessionError::InconsistentState);
        }
        let cleared_budget =
            authenticated_response_cleared_budget_v1(request.maximum_response_bytes())?;
        let cleared_minimum = authenticated_response_cleared_budget_v1(4_096)?;
        match encode_authenticated_success_response_envelope(
            &request.request_id(),
            &request.validated_envelope,
            body,
            profile.success_response_descriptor_roles(),
            profile.request_descriptor_dispositions(),
            cleared_minimum,
            cleared_budget,
        ) {
            Ok(bytes) => self.outcome_plan_from_cleared_packet(bytes, context),
            Err(ProtocolValidationError::ResponseTooLarge) => self
                .into_network_inventory_terminal_outcome_plan(
                    AuthenticatedNetworkInventoryTerminalErrorV1::ResourceExhausted,
                    context,
                ),
            Err(error) => Err(error.into()),
        }
    }

    /// Consumes an outstanding state into one fixed signed terminal-error plan.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] unless the error is permitted
    /// for the retained request and all context/sequence invariants remain current.
    pub fn into_network_inventory_terminal_outcome_plan(
        self,
        error: AuthenticatedNetworkInventoryTerminalErrorV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<AuthenticatedNetworkInventoryOutcomeSigningPlanV1, AuthenticatedBrokerSessionError>
    {
        let profile = self.require_network_inventory_profile()?;
        self.require_current_context(context)?;
        let request = self.initial_outstanding_request()?;
        let cleared_budget =
            authenticated_response_cleared_budget_v1(request.maximum_response_bytes())?;
        let cleared_minimum = authenticated_response_cleared_budget_v1(4_096)?;
        let (code, message, retryable) = match error {
            AuthenticatedNetworkInventoryTerminalErrorV1::DeadlineExpired => {
                if !request.expired_on_first_admission() {
                    return Err(AuthenticatedBrokerSessionError::InconsistentState);
                }
                (
                    BrokerErrorCode::BROKER_ERROR_CODE_DEADLINE_EXPIRED,
                    "request deadline expired",
                    true,
                )
            }
            AuthenticatedNetworkInventoryTerminalErrorV1::ResourceExhausted => (
                BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED,
                "authoritative Network inventory exceeds response bound",
                true,
            ),
            AuthenticatedNetworkInventoryTerminalErrorV1::IntegrityFailure => (
                BrokerErrorCode::BROKER_ERROR_CODE_INTEGRITY_FAILURE,
                "authoritative Network inventory is unavailable",
                false,
            ),
        };
        if request.expired_on_first_admission()
            && error != AuthenticatedNetworkInventoryTerminalErrorV1::DeadlineExpired
        {
            return Err(AuthenticatedBrokerSessionError::InconsistentState);
        }
        let bytes = encode_authenticated_error_response_envelope(
            &request.request_id(),
            &request.validated_envelope,
            code,
            message,
            retryable,
            None,
            profile.request_descriptor_dispositions(),
            cleared_minimum,
            cleared_budget,
        )?;
        self.outcome_plan_from_cleared_packet(bytes, context)
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
    /// semantics, first-seen expiry, failed cryptography/currentness, or
    /// traffic-state failure.
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
        let admission = self.admit_network_inventory_request_preserving_expiry(
            bytes,
            actual_descriptor_count,
            peer,
            policy,
            now_boottime_nanoseconds,
            context,
        )?;
        match admission {
            AuthenticatedNetworkInventoryRequestAdmissionV1::New { request, .. }
                if request.expired_on_first_admission() =>
            {
                Err(ProtocolValidationError::DeadlineExpired.into())
            }
            admission => Ok(admission),
        }
    }

    /// Admits the mandatory sequence-one traffic proof, retaining signed expiry.
    ///
    /// This integration seam is solely for the sealed, production-inert
    /// broker-session security typestate. Ordinary callers must use
    /// [`Self::admit_network_inventory_request`], which rejects first-seen
    /// expiry. The returned evidence grants no dispatch or authority.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedBrokerSessionError`] unless the state is exactly
    /// provisional and the request passes every static, cryptographic, context,
    /// sequence, peer-policy, and descriptor check.
    #[doc(hidden)]
    pub fn admit_initial_network_inventory_traffic_proof_request(
        &self,
        bytes: &[u8],
        actual_descriptor_count: usize,
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<SealedInitialNetworkInventoryTrafficProofAdmissionV1, AuthenticatedBrokerSessionError>
    {
        self.require_initial_traffic_state()?;
        let admission = self.admit_network_inventory_request_preserving_expiry(
            bytes,
            actual_descriptor_count,
            peer,
            policy,
            now_boottime_nanoseconds,
            context,
        )?;
        match admission {
            AuthenticatedNetworkInventoryRequestAdmissionV1::New {
                request,
                next_state,
            } if request.expired_on_first_admission() => Ok(
                SealedInitialNetworkInventoryTrafficProofAdmissionV1::AuthenticatedExpired {
                    request,
                    next_state,
                },
            ),
            AuthenticatedNetworkInventoryRequestAdmissionV1::New {
                request,
                next_state,
            } => Ok(
                SealedInitialNetworkInventoryTrafficProofAdmissionV1::Fresh {
                    request,
                    next_state,
                },
            ),
            AuthenticatedNetworkInventoryRequestAdmissionV1::ExactReplay { .. } => {
                Err(AuthenticatedBrokerSessionError::InconsistentState)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_network_inventory_request_preserving_expiry(
        &self,
        bytes: &[u8],
        actual_descriptor_count: usize,
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<AuthenticatedNetworkInventoryRequestAdmissionV1, AuthenticatedBrokerSessionError>
    {
        let profile = self.require_network_inventory_profile()?;
        if actual_descriptor_count != profile.request_descriptor_roles().len() {
            return Err(ProtocolValidationError::DescriptorTableMismatch.into());
        }
        if bytes.len() > self.maximum_request_receive_bytes()
            || bytes.len() > profile.total_request_maximum_bytes()
        {
            return Err(ProtocolValidationError::RequestTooLarge.into());
        }

        let canonical = decode_canonical_request_v1(bytes)?;
        let envelope = validate_decoded_request_envelope(
            canonical.message().clone(),
            protocol_id_for_profile(profile.protocol()),
            actual_descriptor_count,
        )?;
        validate_request_against_profile(&envelope, &profile)?;
        let header =
            decode_network_resource_inventory_request_static(envelope.body(), peer, policy)?;
        let transcript = self.traffic.transcript();
        if (
            header.protocol_version().major(),
            header.protocol_version().minor(),
        ) != profile.version()
            || header.audience() != profile.audience()
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
                let expired = match validate_request_deadline(&header, now_boottime_nanoseconds) {
                    Ok(()) => false,
                    Err(ProtocolValidationError::DeadlineExpired) => true,
                    Err(error) => return Err(error.into()),
                };
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
                    first_traffic_key_proof: request.is_first_traffic_key_proof(),
                    expired_on_first_admission: expired,
                    validated_envelope: envelope,
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
        let profile = self.require_network_inventory_profile()?;
        if actual_descriptor_count != profile.success_response_descriptor_roles().len() {
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
                    &profile,
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
                    &profile,
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

    fn require_network_inventory_profile(
        &self,
    ) -> Result<BrokerSessionMethodProfileV1, AuthenticatedBrokerSessionError> {
        let profile = authenticated_broker_method_profile_v1(
            BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        )
        .ok_or(AuthenticatedBrokerSessionError::UnsupportedProfile)?;
        let transcript = self.traffic.transcript();
        if transcript.protocol() != profile.protocol()
            || transcript.protocol_version() != profile.version()
            || transcript.audience() != profile.audience()
            || !transcript.negotiated_methods().contains(&profile.method())
            || transcript.negotiated_maximum_request_bytes() > profile.total_request_maximum_bytes()
            || !profile_features_are_negotiated(&profile, transcript.required_features())
        {
            return Err(AuthenticatedBrokerSessionError::UnsupportedProfile);
        }
        Ok(profile)
    }

    fn require_initial_traffic_state(&self) -> Result<(), AuthenticatedBrokerSessionError> {
        if self.traffic.next_client_sequence() != 1
            || self.traffic.next_broker_sequence() != 1
            || self.traffic.has_outstanding_request()
            || self.outstanding_network_inventory.is_some()
            || self.completed_network_inventory.is_some()
        {
            return Err(AuthenticatedBrokerSessionError::InconsistentState);
        }
        Ok(())
    }

    fn initial_outstanding_request(
        &self,
    ) -> Result<&AuthenticatedNetworkInventoryRequestV1, AuthenticatedBrokerSessionError> {
        let request = self
            .outstanding_network_inventory
            .as_ref()
            .ok_or(AuthenticatedBrokerSessionError::InconsistentState)?;
        if request.client_sequence() != 1
            || !request.first_traffic_key_proof()
            || self.traffic.next_client_sequence() != 1
            || self.traffic.next_broker_sequence() != 1
            || !self.traffic.has_outstanding_request()
        {
            return Err(AuthenticatedBrokerSessionError::InconsistentState);
        }
        Ok(request)
    }

    fn outcome_plan_from_cleared_packet(
        self,
        bytes: Vec<u8>,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<AuthenticatedNetworkInventoryOutcomeSigningPlanV1, AuthenticatedBrokerSessionError>
    {
        self.require_current_context(context)?;
        let request = self.initial_outstanding_request()?;
        let maximum_total_bytes = request.maximum_response_bytes();
        let message = BrokerResponseEnvelope::decode_from_slice(&bytes)
            .map_err(|error| BrokerSessionProjectionError::Malformed(error.to_string()))?;
        if !message.signed_session_outcome.is_empty() {
            return Err(AuthenticatedBrokerSessionError::InconsistentState);
        }
        let fields = outcome_fields_digest_v1(&message)?;
        let subject = BrokerOutcomeSubjectV1::new(
            self.traffic.transcript().session_binding(),
            self.traffic.transcript().broker_process(),
            1,
            request.request_id(),
            request.signed_request_digest(),
            fields,
        )
        .map_err(|_| AuthenticatedBrokerSessionError::InconsistentState)?;

        Ok(AuthenticatedNetworkInventoryOutcomeSigningPlanV1 {
            state: self,
            message,
            subject,
            maximum_total_bytes,
        })
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
        profile: &BrokerSessionMethodProfileV1,
    ) -> Result<AuthenticatedNetworkInventoryOutcomeV1, AuthenticatedBrokerSessionError> {
        let envelope = validate_decoded_response_envelope(
            canonical.message().clone(),
            &request.request_id(),
            profile.method(),
            request.validated_envelope.descriptors(),
            actual_descriptor_count,
        )?;
        validate_outcome_against_profile(&envelope, profile)?;
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

fn protocol_id_for_profile(protocol: BrokerSessionProtocolV1) -> ProtocolId {
    match protocol {
        BrokerSessionProtocolV1::Host => ProtocolId::HostBroker,
        BrokerSessionProtocolV1::Storage => ProtocolId::StorageBroker,
        BrokerSessionProtocolV1::Mount => ProtocolId::MountBroker,
        BrokerSessionProtocolV1::Network => ProtocolId::NetworkBroker,
    }
}

fn profile_features_are_negotiated(
    profile: &BrokerSessionMethodProfileV1,
    features: &[FeatureRef],
) -> bool {
    profile.required_features().iter().all(|required| {
        let (major, minor) = required.version();
        features.iter().any(|feature| {
            feature.namespace() == required.namespace()
                && feature.major() == u32::from(major)
                && feature.minor() == u32::from(minor)
        })
    })
}

fn validate_request_against_profile(
    request: &ValidatedBrokerRequestEnvelope,
    profile: &BrokerSessionMethodProfileV1,
) -> Result<(), ProtocolValidationError> {
    let authorization_matches = match profile.authorization() {
        BrokerSessionAuthorizationPresenceV1::Required => request.authorization().is_some(),
        BrokerSessionAuthorizationPresenceV1::Forbidden => request.authorization().is_none(),
    };
    if request.method() != profile.method() || !authorization_matches {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    if request.descriptors().len() != profile.request_descriptor_roles().len()
        || request
            .descriptors()
            .iter()
            .zip(profile.request_descriptor_roles())
            .any(|(actual, expected)| actual.role() != *expected)
    {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }
    Ok(())
}

fn validate_success_body_against_profile(
    body: &[u8],
    profile: &BrokerSessionMethodProfileV1,
) -> Result<(), ProtocolValidationError> {
    if matches!(
        profile.success_body(),
        BrokerSessionSuccessBodyPresenceV1::Required
    ) && body.is_empty()
    {
        return Err(ProtocolValidationError::InvalidField(
            "authenticated response body profile",
        ));
    }
    Ok(())
}

fn validate_outcome_against_profile(
    outcome: &crate::session::ValidatedBrokerResponseEnvelope,
    profile: &BrokerSessionMethodProfileV1,
) -> Result<(), ProtocolValidationError> {
    let expected_response_roles = if outcome.error().is_some() {
        profile.error_response_descriptor_roles()
    } else {
        validate_success_body_against_profile(outcome.body(), profile)?;
        profile.success_response_descriptor_roles()
    };
    if outcome.descriptors().len() != expected_response_roles.len()
        || outcome
            .descriptors()
            .iter()
            .zip(expected_response_roles)
            .any(|(actual, expected)| actual.role() != *expected)
    {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }

    let expected_request_roles = profile.request_descriptor_roles();
    let expected_dispositions = profile.request_descriptor_dispositions();
    if expected_request_roles.len() != expected_dispositions.len()
        || outcome.request_descriptor_dispositions().len() != expected_dispositions.len()
        || outcome
            .request_descriptor_dispositions()
            .iter()
            .zip(expected_request_roles.iter().zip(expected_dispositions))
            .any(|(actual, (role, disposition))| {
                actual.role() != *role || actual.disposition() != *disposition
            })
    {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }
    Ok(())
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
