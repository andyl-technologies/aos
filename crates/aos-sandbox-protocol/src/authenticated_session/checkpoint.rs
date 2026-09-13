//! Network Inventory checkpoint companion values and semantic drafts.
//!
//! A live draft can be derived only from the parent module's opaque, fully
//! authenticated Network Inventory evidence. Recovery deliberately produces a
//! separate hostile-byte view: decoding durable bytes does not recreate live
//! authentication, send authority, catalog authority, or a commit permit.

use aos_sandbox_broker_session_protocol::{
    BROKER_SESSION_OUTCOME_COMPANION_BYTES, BROKER_SESSION_REQUEST_COMPANION_BYTES,
    BrokerSessionCheckpointError, BrokerSessionOutcomeCompanionV1, BrokerSessionProjectionError,
    BrokerSessionProtocolV1, BrokerSessionRequestCompanionV1, SIGNED_BROKER_OUTCOME_BYTES,
    SIGNED_BROKER_REQUEST_BYTES, SignedBrokerOutcomeV1, SignedBrokerRequestV1,
    authenticated_response_cleared_budget_v1, complete_signed_request_digest_v1,
    decode_canonical_request_v1, decode_canonical_response_v1,
};
use aos_sandbox_core::ProtocolId;
use buffa::Message as _;

use super::{
    Audience, AuthenticatedNetworkInventoryOutcomeV1, AuthenticatedNetworkInventoryRequestV1,
    AuthenticatedNetworkInventoryResultV1, BrokerErrorCode, BrokerMethod, InventoryNetworksRequest,
    NETWORK_INVENTORY_OUTCOME_PACKET_DOMAIN, NETWORK_INVENTORY_REQUEST_PACKET_DOMAIN,
    ProtocolValidationError, ValidatedBrokerError, decode_network_resource_inventory_response,
    encode_authenticated_success_response_envelope, packet_digest,
    validate_decoded_request_envelope, validate_decoded_response_envelope,
};

/// Maximum exact request owner value: companion plus canonical request packet.
pub const NETWORK_INVENTORY_REQUEST_RECORD_MAXIMUM_BYTES: usize = 1_048_912;
/// Maximum exact outcome owner value: companion plus canonical outcome packet.
pub const NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES: usize = 15_729_056;
/// Exact maximum canonical packet bytes for the fixed Inventory request shape.
pub const NETWORK_INVENTORY_CHECKPOINT_REQUEST_PACKET_MAXIMUM_BYTES: usize = 355;
/// Exact maximum owner-value bytes for the fixed Inventory request shape.
pub const NETWORK_INVENTORY_CHECKPOINT_REQUEST_VALUE_MAXIMUM_BYTES: usize = 691;
/// Exact maximum canonical packet bytes for a fixed terminal Inventory outcome.
pub const NETWORK_INVENTORY_CHECKPOINT_TERMINAL_PACKET_MAXIMUM_BYTES: usize = 425;
/// Exact maximum owner-value bytes for a fixed terminal Inventory outcome.
pub const NETWORK_INVENTORY_CHECKPOINT_TERMINAL_VALUE_MAXIMUM_BYTES: usize = 841;

const PROTOBUF_AUTHENTICATION_FIELD_PREFIX_BYTES: usize = 3;
const NETWORK_INVENTORY_REQUEST_CLEARED_PACKET_MAXIMUM_BYTES: usize = 44;
const NETWORK_INVENTORY_TERMINAL_CLEARED_PACKET_MAXIMUM_BYTES: usize = 82;
const NETWORK_INVENTORY_REQUEST_PACKET_MAXIMUM_BYTES: usize =
    NETWORK_INVENTORY_REQUEST_RECORD_MAXIMUM_BYTES - BROKER_SESSION_REQUEST_COMPANION_BYTES;
const NETWORK_INVENTORY_OUTCOME_PACKET_MAXIMUM_BYTES: usize =
    NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES - BROKER_SESSION_OUTCOME_COMPANION_BYTES;

const _: () = assert!(BROKER_SESSION_REQUEST_COMPANION_BYTES == 336);
const _: () = assert!(BROKER_SESSION_OUTCOME_COMPANION_BYTES == 416);
const _: () = assert!(NETWORK_INVENTORY_REQUEST_PACKET_MAXIMUM_BYTES == 1_048_576);
const _: () = assert!(NETWORK_INVENTORY_OUTCOME_PACKET_MAXIMUM_BYTES == 15_728_640);
const _: () = assert!(
    NETWORK_INVENTORY_CHECKPOINT_REQUEST_PACKET_MAXIMUM_BYTES
        == NETWORK_INVENTORY_REQUEST_CLEARED_PACKET_MAXIMUM_BYTES
            + PROTOBUF_AUTHENTICATION_FIELD_PREFIX_BYTES
            + SIGNED_BROKER_REQUEST_BYTES
);
const _: () = assert!(
    NETWORK_INVENTORY_CHECKPOINT_TERMINAL_PACKET_MAXIMUM_BYTES
        == NETWORK_INVENTORY_TERMINAL_CLEARED_PACKET_MAXIMUM_BYTES
            + PROTOBUF_AUTHENTICATION_FIELD_PREFIX_BYTES
            + SIGNED_BROKER_OUTCOME_BYTES
);
const _: () = assert!(
    NETWORK_INVENTORY_CHECKPOINT_REQUEST_VALUE_MAXIMUM_BYTES
        == BROKER_SESSION_REQUEST_COMPANION_BYTES
            + NETWORK_INVENTORY_CHECKPOINT_REQUEST_PACKET_MAXIMUM_BYTES
);
const _: () = assert!(
    NETWORK_INVENTORY_CHECKPOINT_TERMINAL_VALUE_MAXIMUM_BYTES
        == BROKER_SESSION_OUTCOME_COMPANION_BYTES
            + NETWORK_INVENTORY_CHECKPOINT_TERMINAL_PACKET_MAXIMUM_BYTES
);

/// Reports an inconsistency while deriving or decoding a Network checkpoint value.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NetworkInventoryCheckpointDraftError {
    /// The retained containing protobuf packet is not canonical.
    #[error("invalid canonical Network checkpoint packet")]
    Projection(#[from] BrokerSessionProjectionError),
    /// The fixed companion record rejected a retained field or artifact.
    #[error("invalid Network checkpoint companion")]
    Companion(#[from] BrokerSessionCheckpointError),
    /// Retained semantic evidence and its reparsed signed artifact disagree.
    #[error("Network checkpoint evidence cross-link mismatch")]
    CrossLink,
}

/// Holds a non-authorizing request companion before caller-owned persistence.
#[doc(hidden)]
pub struct NetworkInventoryRequestCheckpointDraftV1 {
    value: Vec<u8>,
    session_binding: [u8; 32],
    request_id: [u8; 16],
    client_sequence: u64,
}

impl NetworkInventoryRequestCheckpointDraftV1 {
    /// Derives a draft only from complete authenticated Network request evidence.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkInventoryCheckpointDraftError`] if the retained packet,
    /// signed artifact, or any request/session/sequence cross-link disagrees.
    pub fn derive(
        request: &AuthenticatedNetworkInventoryRequestV1,
    ) -> Result<Self, NetworkInventoryCheckpointDraftError> {
        let signed_request = validate_exact_request_evidence(request)?;
        let companion = BrokerSessionRequestCompanionV1::try_from_parts(
            BrokerSessionProtocolV1::Network,
            request.method(),
            request.deadline_boottime_nanoseconds(),
            request.maximum_response_bytes(),
            signed_request,
        )?;
        let value = concatenate_record_value(
            &companion.encode(),
            request.canonical_packet_bytes(),
            NETWORK_INVENTORY_REQUEST_RECORD_MAXIMUM_BYTES,
        )?;

        Ok(Self {
            value,
            session_binding: request.session_binding(),
            request_id: request.request_id(),
            client_sequence: request.client_sequence(),
        })
    }

    /// Returns the exact journal-neutral request owner value.
    #[must_use]
    pub fn exact_value(&self) -> &[u8] {
        &self.value
    }

    /// Returns the authenticated session binding retained by the live request.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the authenticated request ID retained by the live request.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the authenticated client sequence retained by the live request.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }
}

/// Holds a live, non-authorizing outcome companion before owner persistence.
#[doc(hidden)]
pub struct NetworkInventoryOutcomeCheckpointDraftV1 {
    request_value: Vec<u8>,
    outcome_value: Vec<u8>,
    recovered: RecoveredNetworkInventoryCheckpointViewV1,
    expired_on_first_admission: bool,
}

impl NetworkInventoryOutcomeCheckpointDraftV1 {
    /// Derives a draft only from complete authenticated Network outcome evidence.
    ///
    /// Both fully validated success and fully validated closed terminal-error
    /// outcomes are accepted. Neither result is installed or committed here.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkInventoryCheckpointDraftError`] if the retained packet,
    /// signed artifact, request tuple, digest, session, or sequence disagrees.
    pub fn derive(
        outcome: &AuthenticatedNetworkInventoryOutcomeV1,
    ) -> Result<Self, NetworkInventoryCheckpointDraftError> {
        let request = outcome.request();
        let request_draft = NetworkInventoryRequestCheckpointDraftV1::derive(request)?;
        let signed_outcome = validate_exact_outcome_evidence(outcome)?;
        let companion = BrokerSessionOutcomeCompanionV1::try_from_parts(
            BrokerSessionProtocolV1::Network,
            request.method(),
            request.request_id(),
            request.client_sequence(),
            request.maximum_response_bytes(),
            request.signed_request_digest(),
            signed_outcome,
        )?;
        let outcome_value = concatenate_record_value(
            &companion.encode(),
            outcome.canonical_packet_bytes(),
            NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES,
        )?;
        let recovered = decode_recovered_network_inventory_checkpoint_values_v1(
            request_draft.exact_value(),
            &outcome_value,
        )?;
        if recovered.result != *outcome.result() {
            return Err(NetworkInventoryCheckpointDraftError::CrossLink);
        }

        Ok(Self {
            request_value: request_draft.value,
            outcome_value,
            recovered,
            expired_on_first_admission: request.expired_on_first_admission(),
        })
    }

    /// Returns the exact request owner value paired with this live outcome.
    #[must_use]
    pub fn exact_request_value(&self) -> &[u8] {
        &self.request_value
    }

    /// Returns the exact outcome owner value paired with this live outcome.
    #[must_use]
    pub fn exact_outcome_value(&self) -> &[u8] {
        &self.outcome_value
    }

    /// Returns the authenticated session binding retained by the live evidence.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.recovered.session_binding
    }

    /// Returns the authenticated request ID retained by the live evidence.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.recovered.request_id
    }

    /// Returns the authenticated client sequence retained by the live evidence.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.recovered.client_sequence
    }

    /// Returns the authenticated total response ceiling retained by the request.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.recovered.maximum_response_bytes
    }

    /// Reports whether the live request was expired on its first admission.
    #[must_use]
    pub const fn expired_on_first_admission(&self) -> bool {
        self.expired_on_first_admission
    }

    /// Returns the exact response body retained by the complete live outcome.
    #[must_use]
    pub fn exact_outcome_body(&self) -> &[u8] {
        &self.recovered.exact_outcome_body
    }

    /// Returns the fully validated live success inventory or signed error.
    #[must_use]
    pub const fn result(&self) -> &AuthenticatedNetworkInventoryResultV1 {
        &self.recovered.result
    }

    /// Returns the exact closed terminal tuple, or `None` for success.
    #[must_use]
    pub fn terminal_error(&self) -> Option<NetworkInventoryCheckpointTerminalErrorV1> {
        match self.result() {
            AuthenticatedNetworkInventoryResultV1::Success(_) => None,
            AuthenticatedNetworkInventoryResultV1::Error(error) => exact_terminal_error(error),
        }
    }

    /// Determines whether an otherwise-valid success exceeds its signed ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkInventoryCheckpointDraftError`] if the retained request
    /// or proposed success cannot reproduce the authenticated response projection.
    pub fn success_exceeds_response_ceiling(
        &self,
        body: &[u8],
    ) -> Result<bool, NetworkInventoryCheckpointDraftError> {
        let (_, request_packet) = self
            .request_value
            .split_at_checked(BROKER_SESSION_REQUEST_COMPANION_BYTES)
            .ok_or(NetworkInventoryCheckpointDraftError::CrossLink)?;
        let canonical = decode_canonical_request_v1(request_packet)?;
        let request = validate_decoded_request_envelope(
            canonical.message().clone(),
            ProtocolId::NetworkBroker,
            0,
        )
        .map_err(map_semantics)?;
        let minimum = authenticated_response_cleared_budget_v1(4_096)?;
        let maximum = authenticated_response_cleared_budget_v1(self.maximum_response_bytes())?;
        match encode_authenticated_success_response_envelope(
            &self.request_id(),
            &request,
            body.to_vec(),
            &[],
            &[],
            minimum,
            maximum,
        ) {
            Ok(_) => Ok(false),
            Err(ProtocolValidationError::ResponseTooLarge) => Ok(true),
            Err(_) => Err(NetworkInventoryCheckpointDraftError::CrossLink),
        }
    }
}

/// Holds a hostile-byte decoded checkpoint view without recreating live authority.
#[doc(hidden)]
pub struct RecoveredNetworkInventoryCheckpointViewV1 {
    session_binding: [u8; 32],
    request_id: [u8; 16],
    client_sequence: u64,
    maximum_response_bytes: u32,
    exact_outcome_packet: Vec<u8>,
    exact_outcome_body: Vec<u8>,
    result: AuthenticatedNetworkInventoryResultV1,
}

impl RecoveredNetworkInventoryCheckpointViewV1 {
    /// Returns the structurally cross-checked session binding from durable bytes.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the structurally cross-checked request ID from durable bytes.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the structurally cross-checked client sequence from durable bytes.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }

    /// Returns the structurally cross-checked response ceiling from durable bytes.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the exact canonical outcome packet as non-authorizing recovered bytes.
    #[must_use]
    pub fn exact_outcome_packet(&self) -> &[u8] {
        &self.exact_outcome_packet
    }

    /// Returns the completely decoded but non-authorizing semantic result.
    #[must_use]
    pub const fn result(&self) -> &AuthenticatedNetworkInventoryResultV1 {
        &self.result
    }
}

/// Holds one hostile-byte decoded request owner value without live authority.
#[doc(hidden)]
pub struct RecoveredNetworkInventoryRequestCheckpointViewV1 {
    session_binding: [u8; 32],
    request_id: [u8; 16],
    client_sequence: u64,
    deadline_boottime_nanoseconds: u64,
    maximum_response_bytes: u32,
    signed_request_digest: [u8; 32],
}

impl RecoveredNetworkInventoryRequestCheckpointViewV1 {
    /// Returns the structurally cross-checked session binding.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the structurally cross-checked request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the structurally cross-checked client sequence.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }

    /// Returns the structurally cross-checked request deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the structurally cross-checked total response ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the complete signed ClientRecord digest.
    #[must_use]
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.signed_request_digest
    }
}

/// Decodes one request owner value without recreating authentication authority.
///
/// # Errors
///
/// Returns [`NetworkInventoryCheckpointDraftError`] for any bound, canonicality,
/// semantic, companion, or signed-artifact cross-link failure.
#[doc(hidden)]
pub fn decode_recovered_network_inventory_request_checkpoint_value_v1(
    request_value: &[u8],
) -> Result<RecoveredNetworkInventoryRequestCheckpointViewV1, NetworkInventoryCheckpointDraftError>
{
    if request_value.len() <= BROKER_SESSION_REQUEST_COMPANION_BYTES
        || request_value.len() > NETWORK_INVENTORY_CHECKPOINT_REQUEST_VALUE_MAXIMUM_BYTES
    {
        return Err(NetworkInventoryCheckpointDraftError::CrossLink);
    }
    let (companion_bytes, request_packet) =
        request_value.split_at(BROKER_SESSION_REQUEST_COMPANION_BYTES);
    if request_packet.len() > NETWORK_INVENTORY_CHECKPOINT_REQUEST_PACKET_MAXIMUM_BYTES {
        return Err(NetworkInventoryCheckpointDraftError::CrossLink);
    }
    let companion = BrokerSessionRequestCompanionV1::decode(companion_bytes)?;
    require_network_inventory_pair(companion.protocol(), companion.method())?;
    let canonical = decode_canonical_request_v1(request_packet)?;
    let envelope = validate_decoded_request_envelope(
        canonical.message().clone(),
        ProtocolId::NetworkBroker,
        0,
    )
    .map_err(map_semantics)?;
    let body = InventoryNetworksRequest::decode_from_slice(envelope.body())
        .map_err(|_| NetworkInventoryCheckpointDraftError::CrossLink)?;
    let header = body
        .header
        .as_option()
        .ok_or(NetworkInventoryCheckpointDraftError::CrossLink)?;
    let signed = companion.signed_request();
    let subject = signed.subject();
    if !body.__buffa_unknown_fields.is_empty()
        || !header.__buffa_unknown_fields.is_empty()
        || envelope.method() != BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
        || !envelope.descriptors().is_empty()
        || envelope.authorization().is_some()
        || header.protocol_major != 1
        || header.protocol_minor != 0
        || header.audience.as_known() != Some(Audience::AUDIENCE_NODE_CONTROLLER)
        || header.request_id.as_slice() != subject.request_id().as_slice()
        || header.maximum_response_bytes < crate::MINIMUM_RESPONSE_BYTES
        || header.deadline_boottime_nanoseconds != companion.deadline_boottime_nanoseconds()
        || header.maximum_response_bytes != companion.maximum_response_bytes()
        || canonical.signed_artifact().to_canonical_bytes() != signed.to_canonical_bytes()
        || signed.method() != companion.method()
        || subject.sequence() == 0
        || subject.sequence() == u64::MAX
        || subject.cleared_fields_digest() != canonical.cleared_fields_digest()
    {
        return Err(NetworkInventoryCheckpointDraftError::CrossLink);
    }

    Ok(RecoveredNetworkInventoryRequestCheckpointViewV1 {
        session_binding: subject.session_binding(),
        request_id: subject.request_id(),
        client_sequence: subject.sequence(),
        deadline_boottime_nanoseconds: companion.deadline_boottime_nanoseconds(),
        maximum_response_bytes: companion.maximum_response_bytes(),
        signed_request_digest: complete_signed_request_digest_v1(signed),
    })
}

/// Decodes paired durable owner values into a non-authorizing hostile-byte view.
///
/// This function validates structure, canonical packets, all signed-artifact
/// cross-links, and complete Network success/error semantics. It does not
/// verify signatures, protected context, journal provenance, or currentness,
/// and its result cannot be converted into a live draft.
///
/// # Errors
///
/// Returns [`NetworkInventoryCheckpointDraftError`] for any bound, codec,
/// canonicality, semantic, or cross-link failure.
#[doc(hidden)]
pub fn decode_recovered_network_inventory_checkpoint_values_v1(
    request_value: &[u8],
    outcome_value: &[u8],
) -> Result<RecoveredNetworkInventoryCheckpointViewV1, NetworkInventoryCheckpointDraftError> {
    if request_value.len() > NETWORK_INVENTORY_REQUEST_RECORD_MAXIMUM_BYTES
        || outcome_value.len() <= BROKER_SESSION_OUTCOME_COMPANION_BYTES
        || outcome_value.len() > NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES
    {
        return Err(NetworkInventoryCheckpointDraftError::CrossLink);
    }

    let request = decode_recovered_network_inventory_request_checkpoint_value_v1(request_value)?;
    let request_id = request.request_id();
    let session_binding = request.session_binding();
    let client_sequence = request.client_sequence();
    let maximum_response_bytes = request.maximum_response_bytes();
    let signed_request_digest = request.signed_request_digest();

    let (outcome_companion_bytes, outcome_packet) =
        outcome_value.split_at(BROKER_SESSION_OUTCOME_COMPANION_BYTES);
    let outcome_companion = BrokerSessionOutcomeCompanionV1::decode(outcome_companion_bytes)?;
    require_network_inventory_pair(outcome_companion.protocol(), outcome_companion.method())?;
    let canonical_outcome = decode_canonical_response_v1(outcome_packet)?;
    let outcome_message = canonical_outcome.message();
    let outcome_envelope = validate_decoded_response_envelope(
        outcome_message.clone(),
        &request_id,
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        &[],
        0,
    )
    .map_err(map_semantics)?;
    let signed_outcome = outcome_companion.signed_outcome();
    let outcome_subject = signed_outcome.subject();
    if outcome_packet.len()
        > usize::try_from(maximum_response_bytes)
            .map_err(|_| NetworkInventoryCheckpointDraftError::CrossLink)?
        || !outcome_envelope.descriptors().is_empty()
        || !outcome_envelope
            .request_descriptor_dispositions()
            .is_empty()
        || outcome_companion.request_id() != request_id
        || outcome_companion.client_sequence() != client_sequence
        || outcome_companion.maximum_response_bytes() != maximum_response_bytes
        || outcome_companion.signed_request_digest() != signed_request_digest
        || canonical_outcome.signed_artifact().to_canonical_bytes()
            != signed_outcome.to_canonical_bytes()
        || outcome_message.request_id.as_slice() != request_id.as_slice()
        || signed_outcome.method() != BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
        || outcome_subject.request_id() != request_id
        || outcome_subject.sequence() != client_sequence
        || outcome_subject.session_binding() != session_binding
        || outcome_subject.signed_request_digest() != signed_request_digest
        || outcome_subject.cleared_fields_digest() != canonical_outcome.cleared_fields_digest()
    {
        return Err(NetworkInventoryCheckpointDraftError::CrossLink);
    }

    let exact_outcome_body = outcome_envelope.body().to_vec();
    let result = match outcome_envelope.error() {
        Some(error) if exact_terminal_error(error).is_some() => {
            AuthenticatedNetworkInventoryResultV1::Error(error.clone())
        }
        Some(_) => return Err(NetworkInventoryCheckpointDraftError::CrossLink),
        None => AuthenticatedNetworkInventoryResultV1::Success(
            decode_network_resource_inventory_response(
                outcome_envelope.body(),
                maximum_response_bytes,
            )
            .map_err(map_semantics)?,
        ),
    };

    Ok(RecoveredNetworkInventoryCheckpointViewV1 {
        session_binding,
        request_id,
        client_sequence,
        maximum_response_bytes,
        exact_outcome_packet: outcome_packet.to_vec(),
        exact_outcome_body,
        result,
    })
}

/// Revalidates every exact request field shared by both live drafts.
fn validate_exact_request_evidence(
    request: &AuthenticatedNetworkInventoryRequestV1,
) -> Result<SignedBrokerRequestV1, NetworkInventoryCheckpointDraftError> {
    let canonical = decode_canonical_request_v1(request.canonical_packet_bytes())?;
    let signed_request =
        SignedBrokerRequestV1::from_canonical_bytes(request.signed_request_bytes())
            .map_err(|_| NetworkInventoryCheckpointDraftError::CrossLink)?;
    let body = InventoryNetworksRequest::decode_from_slice(request.exact_body_bytes())
        .map_err(|_| NetworkInventoryCheckpointDraftError::CrossLink)?;
    let header = body
        .header
        .as_option()
        .ok_or(NetworkInventoryCheckpointDraftError::CrossLink)?;
    let subject = signed_request.subject();
    let packet_digest = packet_digest(
        NETWORK_INVENTORY_REQUEST_PACKET_DOMAIN,
        request.canonical_packet_bytes(),
    )
    .map_err(|_| NetworkInventoryCheckpointDraftError::CrossLink)?;

    if canonical.message().body.as_slice() != request.exact_body_bytes()
        || request.validated_envelope.body() != request.exact_body_bytes()
        || request.validated_envelope.method() != request.method()
        || !request.validated_envelope.descriptors().is_empty()
        || request.validated_envelope.authorization().is_some()
        || !body.__buffa_unknown_fields.is_empty()
        || !header.__buffa_unknown_fields.is_empty()
        || header.protocol_major != 1
        || header.protocol_minor != 0
        || header.audience.as_known() != Some(Audience::AUDIENCE_NODE_CONTROLLER)
        || header.request_id.as_slice() != request.request_id().as_slice()
        || header.deadline_boottime_nanoseconds != request.deadline_boottime_nanoseconds()
        || header.maximum_response_bytes != request.maximum_response_bytes()
        || packet_digest != request.canonical_packet_digest()
        || canonical.signed_artifact().to_canonical_bytes() != request.signed_request_bytes()
        || signed_request.method() != request.method()
        || subject.request_id() != request.request_id()
        || subject.sequence() != request.client_sequence()
        || request.first_traffic_key_proof() != (subject.sequence() == 1)
        || subject.session_binding() != request.session_binding()
        || subject.cleared_fields_digest() != canonical.cleared_fields_digest()
        || complete_signed_request_digest_v1(&signed_request) != request.signed_request_digest()
        || !request.descriptor_roles().is_empty()
        || request.method() != BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
    {
        return Err(NetworkInventoryCheckpointDraftError::CrossLink);
    }

    Ok(signed_request)
}

fn validate_exact_outcome_evidence(
    outcome: &AuthenticatedNetworkInventoryOutcomeV1,
) -> Result<SignedBrokerOutcomeV1, NetworkInventoryCheckpointDraftError> {
    let request = outcome.request();
    validate_exact_request_evidence(request)?;
    let canonical = decode_canonical_response_v1(outcome.canonical_packet_bytes())?;
    let signed_outcome =
        SignedBrokerOutcomeV1::from_canonical_bytes(outcome.signed_outcome_bytes())
            .map_err(|_| NetworkInventoryCheckpointDraftError::CrossLink)?;
    let subject = signed_outcome.subject();
    let digest = packet_digest(
        NETWORK_INVENTORY_OUTCOME_PACKET_DOMAIN,
        outcome.canonical_packet_bytes(),
    )
    .map_err(|_| NetworkInventoryCheckpointDraftError::CrossLink)?;

    if canonical.signed_artifact().to_canonical_bytes() != outcome.signed_outcome_bytes()
        || canonical.message().request_id.as_slice() != request.request_id().as_slice()
        || digest != outcome.canonical_packet_digest()
        || signed_outcome.method() != request.method()
        || subject.request_id() != request.request_id()
        || subject.sequence() != outcome.broker_sequence()
        || subject.session_binding() != request.session_binding()
        || subject.cleared_fields_digest() != canonical.cleared_fields_digest()
        || subject.signed_request_digest() != request.signed_request_digest()
        || request.method() != BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
    {
        return Err(NetworkInventoryCheckpointDraftError::CrossLink);
    }

    Ok(signed_outcome)
}

fn concatenate_record_value(
    companion: &[u8],
    packet: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, NetworkInventoryCheckpointDraftError> {
    let length = companion
        .len()
        .checked_add(packet.len())
        .ok_or(NetworkInventoryCheckpointDraftError::CrossLink)?;
    if length > maximum {
        return Err(NetworkInventoryCheckpointDraftError::CrossLink);
    }
    let mut value = Vec::with_capacity(length);
    value.extend_from_slice(companion);
    value.extend_from_slice(packet);
    Ok(value)
}

fn require_network_inventory_pair(
    protocol: BrokerSessionProtocolV1,
    method: BrokerMethod,
) -> Result<(), NetworkInventoryCheckpointDraftError> {
    if protocol != BrokerSessionProtocolV1::Network
        || method != BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
    {
        Err(NetworkInventoryCheckpointDraftError::CrossLink)
    } else {
        Ok(())
    }
}

fn map_semantics(_: ProtocolValidationError) -> NetworkInventoryCheckpointDraftError {
    NetworkInventoryCheckpointDraftError::CrossLink
}

/// Identifies one exact purpose-specific terminal tuple in a live draft.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkInventoryCheckpointTerminalErrorV1 {
    /// The request was expired when first admitted.
    DeadlineExpired,
    /// The otherwise-valid inventory exceeded the authenticated ceiling.
    ResourceExhausted,
    /// The authoritative inventory could not be observed safely.
    IntegrityFailure,
}

fn exact_terminal_error(
    error: &ValidatedBrokerError,
) -> Option<NetworkInventoryCheckpointTerminalErrorV1> {
    if error.missing_feature().is_some() {
        return None;
    }
    match (error.code(), error.safe_message(), error.retryable()) {
        (BrokerErrorCode::BROKER_ERROR_CODE_DEADLINE_EXPIRED, "request deadline expired", true) => {
            Some(NetworkInventoryCheckpointTerminalErrorV1::DeadlineExpired)
        }
        (
            BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED,
            "authoritative Network inventory exceeds response bound",
            true,
        ) => Some(NetworkInventoryCheckpointTerminalErrorV1::ResourceExhausted),
        (
            BrokerErrorCode::BROKER_ERROR_CODE_INTEGRITY_FAILURE,
            "authoritative Network inventory is unavailable",
            false,
        ) => Some(NetworkInventoryCheckpointTerminalErrorV1::IntegrityFailure),
        _ => None,
    }
}
