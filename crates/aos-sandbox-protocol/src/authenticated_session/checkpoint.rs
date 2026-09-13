//! Network Inventory checkpoint companion drafts.
//!
//! Drafts in this module can be derived only from the parent module's opaque,
//! fully authenticated Network Inventory evidence. Derivation reparses the
//! retained canonical packet and signed artifact and checks every retained
//! cross-link before constructing the lower structural companion. A draft is
//! not a journal write, commit record, effect permit, catalog installation, or
//! authority claim.

use aos_sandbox_broker_session_protocol::{
    BrokerSessionCheckpointError, BrokerSessionOutcomeCompanionV1, BrokerSessionProjectionError,
    BrokerSessionProtocolV1, BrokerSessionRequestCompanionV1, SignedBrokerOutcomeV1,
    SignedBrokerRequestV1, complete_signed_request_digest_v1, decode_canonical_request_v1,
    decode_canonical_response_v1,
};
use buffa::{Enumeration as _, Message as _};

use super::{
    Audience, AuthenticatedNetworkInventoryOutcomeV1, AuthenticatedNetworkInventoryRequestV1,
    BrokerMethod, InventoryNetworksRequest, NETWORK_INVENTORY_OUTCOME_PACKET_DOMAIN,
    NETWORK_INVENTORY_REQUEST_PACKET_DOMAIN, packet_digest,
};

/// Reports an inconsistency while deriving a Network checkpoint draft.
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
    _companion: BrokerSessionRequestCompanionV1,
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

        Ok(Self {
            _companion: companion,
        })
    }
}

/// Holds a non-authorizing outcome companion before caller-owned persistence.
#[doc(hidden)]
pub struct NetworkInventoryOutcomeCheckpointDraftV1 {
    _companion: BrokerSessionOutcomeCompanionV1,
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
        validate_exact_request_evidence(request)?;
        let canonical = decode_canonical_response_v1(outcome.canonical_packet_bytes())?;
        let signed_outcome =
            SignedBrokerOutcomeV1::from_canonical_bytes(outcome.signed_outcome_bytes())
                .map_err(|_| NetworkInventoryCheckpointDraftError::CrossLink)?;
        let subject = signed_outcome.subject();
        let packet_digest = packet_digest(
            NETWORK_INVENTORY_OUTCOME_PACKET_DOMAIN,
            outcome.canonical_packet_bytes(),
        )
        .map_err(|_| NetworkInventoryCheckpointDraftError::CrossLink)?;

        if canonical.signed_artifact().to_canonical_bytes() != outcome.signed_outcome_bytes()
            || canonical.message().request_id.as_slice() != request.request_id().as_slice()
            || packet_digest != outcome.canonical_packet_digest()
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

        let companion = BrokerSessionOutcomeCompanionV1::try_from_parts(
            BrokerSessionProtocolV1::Network,
            request.method(),
            request.request_id(),
            request.client_sequence(),
            request.maximum_response_bytes(),
            request.signed_request_digest(),
            signed_outcome,
        )?;

        Ok(Self {
            _companion: companion,
        })
    }
}

/// Revalidates every exact request field shared by both checkpoint drafts.
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
