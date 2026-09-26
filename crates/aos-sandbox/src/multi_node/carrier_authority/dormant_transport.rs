//! Dormant authenticated coordinator/node byte-transport adapter.
//!
//! This module constructs authenticated sessions and exact request/response
//! exchanges, but owns no socket, listener, retry loop, service registration,
//! or readiness advertisement. Callers must provide and move response bytes.

use aos_proto::aos::sandbox::coordinator::v1 as wire;
use aos_sandbox_core::{NodeId, ObjectDigest, OperationId, ProtocolVersion};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::multi_node::protocol::{
    CanonicalNodeSemanticCodecV1, NodeRequestBodyV1, NodeRequestEnvelopeV1, NodeResponseBodyV1,
    NodeResponseEnvelopeV1, validate_response_body,
};

/// Selects the exact semantic and carrier representation authenticated by a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantCoordinatorNodeEncodingV1 {
    /// Uses generated `CoordinatorNodeRequest` and `CoordinatorNodeResponse` carriers.
    Protobuf = 1,
    /// Uses the retired `AOSNODE1` carrier around canonical JSON semantics.
    LegacyJson = 2,
}

/// Describes one canonical carrier handshake awaiting detached authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DormantTransportHandshakeV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    channel_binding: [u8; 32],
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    version: ProtocolVersion,
    maximum_request_bytes: u32,
    maximum_response_bytes: u32,
    replay_fence: ObjectDigest,
    encoding: DormantCoordinatorNodeEncodingV1,
    canonical_bytes: Vec<u8>,
}

impl DormantTransportHandshakeV1 {
    /// Constructs exact, bounded handshake bytes for an external signer.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for sentinel identity, invalid
    /// validity, unsupported protocol semantics, or excessive frame limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node: NodeId,
        lineage: NodeBootLineageV1,
        channel_binding: [u8; 32],
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        coordinator_epoch: u64,
        authenticated_at_unix_seconds: u64,
        valid_until_unix_seconds: u64,
        version: ProtocolVersion,
        maximum_request_bytes: u32,
        maximum_response_bytes: u32,
        replay_fence: ObjectDigest,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        Self::new_with_encoding(
            node,
            lineage,
            channel_binding,
            audience_digest,
            disclosure_domain_digest,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            version,
            maximum_request_bytes,
            maximum_response_bytes,
            replay_fence,
            DormantCoordinatorNodeEncodingV1::Protobuf,
        )
    }

    /// Constructs an explicitly negotiated legacy JSON handshake.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] under the same validation as [`Self::new`].
    #[allow(clippy::too_many_arguments)]
    pub fn new_legacy_json(
        node: NodeId,
        lineage: NodeBootLineageV1,
        channel_binding: [u8; 32],
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        coordinator_epoch: u64,
        authenticated_at_unix_seconds: u64,
        valid_until_unix_seconds: u64,
        version: ProtocolVersion,
        maximum_request_bytes: u32,
        maximum_response_bytes: u32,
        replay_fence: ObjectDigest,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        Self::new_with_encoding(
            node,
            lineage,
            channel_binding,
            audience_digest,
            disclosure_domain_digest,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            version,
            maximum_request_bytes,
            maximum_response_bytes,
            replay_fence,
            DormantCoordinatorNodeEncodingV1::LegacyJson,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_encoding(
        node: NodeId,
        lineage: NodeBootLineageV1,
        channel_binding: [u8; 32],
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        coordinator_epoch: u64,
        authenticated_at_unix_seconds: u64,
        valid_until_unix_seconds: u64,
        version: ProtocolVersion,
        maximum_request_bytes: u32,
        maximum_response_bytes: u32,
        replay_fence: ObjectDigest,
        encoding: DormantCoordinatorNodeEncodingV1,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let canonical_bytes = handshake_bytes(
            node,
            lineage,
            channel_binding,
            audience_digest,
            disclosure_domain_digest,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            version,
            maximum_request_bytes,
            maximum_response_bytes,
            replay_fence,
            encoding,
        );
        CarrierVerifierSessionV1::from_verified_transport(
            node,
            lineage,
            channel_binding,
            audience_digest,
            disclosure_domain_digest,
            ObjectDigest::from_bytes(Sha256::digest(&canonical_bytes).into()),
            u32::try_from(canonical_bytes.len())
                .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            version,
            maximum_request_bytes,
            maximum_response_bytes,
            replay_fence,
        )?;
        Ok(Self {
            node,
            lineage,
            channel_binding,
            audience_digest,
            disclosure_domain_digest,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            version,
            maximum_request_bytes,
            maximum_response_bytes,
            replay_fence,
            encoding,
            canonical_bytes,
        })
    }

    /// Returns exact domain-separated handshake bytes to sign.
    #[must_use]
    pub fn signing_payload(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(in crate::multi_node) fn authenticate_with_protected_owner(
        self,
        canonical_signature: &[u8],
        canonical_trust_policy: &[u8],
        public_key: &[u8; 32],
        current_unix_seconds: u64,
    ) -> Result<DormantAuthenticatedCoordinatorNodeTransportV1, InvalidMultiNodeProtocol> {
        if self.channel_binding != *public_key
            || current_unix_seconds < self.authenticated_at_unix_seconds
            || current_unix_seconds > self.valid_until_unix_seconds
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        verify_protected_carrier_signature(
            &self.canonical_bytes,
            canonical_signature,
            canonical_trust_policy,
            public_key,
            current_unix_seconds,
        )?;
        let session = CarrierVerifierSessionV1::from_verified_transport(
            self.node,
            self.lineage,
            self.channel_binding,
            self.audience_digest,
            self.disclosure_domain_digest,
            ObjectDigest::from_bytes(Sha256::digest(&self.canonical_bytes).into()),
            u32::try_from(self.canonical_bytes.len())
                .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?,
            self.coordinator_epoch,
            self.authenticated_at_unix_seconds,
            self.valid_until_unix_seconds,
            self.version,
            self.maximum_request_bytes,
            self.maximum_response_bytes,
            self.replay_fence,
        )?
        .into_session_grant();
        Ok(DormantAuthenticatedCoordinatorNodeTransportV1 {
            session: AuthenticatedNodeSessionV1::from_authority_grant(session)?,
            codec: match self.encoding {
                DormantCoordinatorNodeEncodingV1::Protobuf => CanonicalNodeSemanticCodecV1::new(),
                DormantCoordinatorNodeEncodingV1::LegacyJson => {
                    CanonicalNodeSemanticCodecV1::legacy_json()
                }
            },
            encoding: self.encoding,
            protected_trust_policy_digest: ObjectDigest::from_bytes(
                Sha256::digest(canonical_trust_policy).into(),
            ),
        })
    }
}

/// Owns one authenticated, source-only coordinator/node exchange boundary.
pub struct DormantAuthenticatedCoordinatorNodeTransportV1 {
    session: AuthenticatedNodeSessionV1,
    codec: CanonicalNodeSemanticCodecV1,
    encoding: DormantCoordinatorNodeEncodingV1,
    protected_trust_policy_digest: ObjectDigest,
}

impl DormantAuthenticatedCoordinatorNodeTransportV1 {
    pub(in crate::multi_node) fn validate_protected_owner(
        &self,
        canonical_trust_policy: &[u8],
        public_key: &[u8; 32],
    ) -> Result<(), InvalidMultiNodeProtocol> {
        if self.session.binding() != *public_key
            || self.protected_trust_policy_digest
                != ObjectDigest::from_bytes(Sha256::digest(canonical_trust_policy).into())
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        Ok(())
    }

    /// Encodes and validates one request without transmitting it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for stale authentication, invalid
    /// request semantics, or a request exceeding the negotiated ceiling.
    pub(in crate::multi_node) fn prepare_exchange_at_protected_time(
        &self,
        request: OperationId,
        body: &NodeRequestBodyV1,
        coordinator_unix_seconds: u64,
    ) -> Result<DormantOutboundExchangeV1, InvalidMultiNodeProtocol> {
        if !self.session.is_current_at(coordinator_unix_seconds) {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        match self.encoding {
            DormantCoordinatorNodeEncodingV1::Protobuf => {
                let semantic_bytes = self.codec.encode_request(body)?;
                let semantic = wire::SemanticEnvelope::decode_from_slice(semantic_bytes.as_slice())
                    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
                let generated = wire::CoordinatorNodeRequest {
                    request_uid: request.as_bytes().to_vec(),
                    session: Some(session_binding(&self.session, self.encoding)).into(),
                    semantic: Some(semantic).into(),
                    ..Default::default()
                };
                let bytes = generated.encode_to_vec();
                if bytes.is_empty() || bytes.len() > self.session.maximum_request_bytes() as usize {
                    return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
                }
                let (consumed, envelope) =
                    self.consume_generated_request(&bytes, coordinator_unix_seconds)?;
                if envelope.request() != request || envelope.body() != body {
                    return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
                }
                Ok(DormantOutboundExchangeV1 {
                    envelope,
                    bytes,
                    generated: Some(consumed),
                })
            }
            DormantCoordinatorNodeEncodingV1::LegacyJson => {
                let bytes = CanonicalNodeFrameV1::encode_request(
                    body,
                    self.session.version(),
                    self.session.binding_digest(),
                    self.session.audience_digest(),
                    self.session.disclosure_domain_digest(),
                    request,
                    self.session.maximum_request_bytes(),
                    &self.codec,
                )?;
                let frame =
                    CanonicalNodeFrameV1::decode(&bytes, self.session.maximum_request_bytes())?;
                let envelope = NodeRequestEnvelopeV1::from_canonical_frame(
                    &self.session,
                    &frame,
                    coordinator_unix_seconds,
                    &self.codec,
                )?;
                Ok(DormantOutboundExchangeV1 {
                    envelope,
                    bytes,
                    generated: None,
                })
            }
        }
    }

    /// Authenticates and consumes one inbound request without registering a service.
    ///
    /// The protobuf branch treats the exact generated `CoordinatorNodeRequest`
    /// bytes as the request contract. The legacy branch is reachable only from
    /// a session that explicitly negotiated the retired JSON carrier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the request signature,
    /// session binding, correlation identity, canonical encoding, and typed
    /// request semantics all match this authenticated session.
    pub(in crate::multi_node) fn accept_request_with_protected_owner(
        &self,
        request_bytes: &[u8],
        canonical_signature: &[u8],
        canonical_trust_policy: &[u8],
        public_key: &[u8; 32],
        verified_at_unix_seconds: u64,
    ) -> Result<NodeRequestEnvelopeV1, InvalidMultiNodeProtocol> {
        if self.session.binding() != *public_key
            || !self.session.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        verify_protected_carrier_signature(
            request_bytes,
            canonical_signature,
            canonical_trust_policy,
            public_key,
            verified_at_unix_seconds,
        )?;

        match self.encoding {
            DormantCoordinatorNodeEncodingV1::Protobuf => self
                .consume_generated_request(request_bytes, verified_at_unix_seconds)
                .map(|(_, envelope)| envelope),
            DormantCoordinatorNodeEncodingV1::LegacyJson => {
                let frame = CanonicalNodeFrameV1::decode(
                    request_bytes,
                    self.session.maximum_request_bytes(),
                )?;
                NodeRequestEnvelopeV1::from_canonical_frame(
                    &self.session,
                    &frame,
                    verified_at_unix_seconds,
                    &self.codec,
                )
            }
        }
    }

    /// Builds one exact response for an authenticated inbound request.
    ///
    /// This adapter performs no transmission and does not sign the result. A
    /// caller-owned protected signer may authenticate [`DormantOutboundResponseV1::bytes`]
    /// after the typed response has passed the request/session checks here.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] when the request does not belong to
    /// this current session, the response does not answer it, or the selected
    /// generated or legacy carrier exceeds the negotiated response limit.
    pub(in crate::multi_node) fn prepare_response_at_protected_time(
        &self,
        request: &NodeRequestEnvelopeV1,
        body: &NodeResponseBodyV1,
        coordinator_unix_seconds: u64,
    ) -> Result<DormantOutboundResponseV1, InvalidMultiNodeProtocol> {
        if !self.session.is_current_at(coordinator_unix_seconds)
            || request.binding() != &self.session.binding()
            || request.node() != self.session.node()
            || request.audience_digest() != self.session.audience_digest()
            || request.disclosure_domain_digest() != self.session.disclosure_domain_digest()
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        validate_response_body(&self.session, request.body(), body)?;

        match self.encoding {
            DormantCoordinatorNodeEncodingV1::Protobuf => {
                let semantic_bytes = self.codec.encode_response(body)?;
                let semantic = wire::SemanticEnvelope::decode_from_slice(semantic_bytes.as_slice())
                    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
                let generated = wire::CoordinatorNodeResponse {
                    request_uid: request.request().as_bytes().to_vec(),
                    session: Some(session_binding(&self.session, self.encoding)).into(),
                    semantic: Some(semantic).into(),
                    ..Default::default()
                };
                let bytes = generated.encode_to_vec();
                if bytes.is_empty() || bytes.len() > self.session.maximum_response_bytes() as usize
                {
                    return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
                }
                let consumed = wire::CoordinatorNodeResponse::decode_from_slice(bytes.as_slice())
                    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
                if consumed.encode_to_vec() != bytes || consumed != generated {
                    return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
                }
                Ok(DormantOutboundResponseV1 {
                    bytes,
                    generated: Some(consumed),
                })
            }
            DormantCoordinatorNodeEncodingV1::LegacyJson => {
                let bytes = CanonicalNodeFrameV1::encode_response(
                    body,
                    self.session.version(),
                    self.session.binding_digest(),
                    self.session.audience_digest(),
                    self.session.disclosure_domain_digest(),
                    request.request(),
                    self.session.maximum_response_bytes(),
                    &self.codec,
                )?;
                CanonicalNodeFrameV1::decode(&bytes, self.session.maximum_response_bytes())?;
                Ok(DormantOutboundResponseV1 {
                    bytes,
                    generated: None,
                })
            }
        }
    }

    /// Authenticates and decodes one response without opening a carrier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for stale authentication, malformed
    /// protobuf/framing, replay mismatch, or response/request substitution.
    pub(in crate::multi_node) fn accept_response_with_protected_owner(
        self,
        request: &DormantOutboundExchangeV1,
        response_bytes: &[u8],
        canonical_signature: &[u8],
        canonical_trust_policy: &[u8],
        public_key: &[u8; 32],
        verified_at_unix_seconds: u64,
    ) -> Result<NodeResponseEnvelopeV1, InvalidMultiNodeProtocol> {
        if self.session.binding() != *public_key {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        if request.generated.is_some()
            != matches!(self.encoding, DormantCoordinatorNodeEncodingV1::Protobuf)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        verify_protected_carrier_signature(
            response_bytes,
            canonical_signature,
            canonical_trust_policy,
            public_key,
            verified_at_unix_seconds,
        )?;
        match self.encoding {
            DormantCoordinatorNodeEncodingV1::LegacyJson => {
                let frame = CanonicalNodeFrameV1::decode(
                    response_bytes,
                    self.session.maximum_response_bytes(),
                )?;
                let grant = issue_response_once(self.session, &frame, verified_at_unix_seconds)?;
                NodeResponseEnvelopeV1::from_authenticated_carrier(
                    grant,
                    &request.envelope,
                    &frame,
                    verified_at_unix_seconds,
                    &self.codec,
                )
            }
            DormantCoordinatorNodeEncodingV1::Protobuf => {
                if response_bytes.is_empty()
                    || response_bytes.len() > self.session.maximum_response_bytes() as usize
                {
                    return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
                }
                let response = wire::CoordinatorNodeResponse::decode_from_slice(response_bytes)
                    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
                if response.encode_to_vec().as_slice() != response_bytes
                    || response.request_uid.as_slice() != request.envelope.request().as_bytes()
                    || response.session.as_option()
                        != Some(&session_binding(&self.session, self.encoding))
                {
                    return Err(InvalidMultiNodeProtocol::SessionMismatch);
                }
                let semantic = response
                    .semantic
                    .into_option()
                    .ok_or(InvalidMultiNodeProtocol::NonCanonicalFrame)?;
                let semantic_bytes = semantic.encode_to_vec();
                let kind = crate::multi_node::protocol::protobuf_codec_v1::response_frame_kind(
                    semantic.kind.to_i32(),
                )?;
                let carrier_bytes = u32::try_from(response_bytes.len())
                    .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
                let body_digest = ObjectDigest::from_bytes(Sha256::digest(&semantic_bytes).into());
                let carrier_digest =
                    ObjectDigest::from_bytes(Sha256::digest(response_bytes).into());
                let grant = issue_generated_response_once(
                    self.session,
                    kind,
                    body_digest,
                    carrier_digest,
                    carrier_bytes,
                    verified_at_unix_seconds,
                )?;
                let body = crate::multi_node::protocol::protobuf_codec_v1::decode_response(
                    grant.context(),
                    kind,
                    &semantic_bytes,
                    verified_at_unix_seconds,
                    &self.codec,
                )?;
                if self.codec.encode_response(&body)? != semantic_bytes {
                    return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
                }
                NodeResponseEnvelopeV1::from_authenticated_generated_carrier(
                    grant,
                    &request.envelope,
                    body,
                    body_digest,
                    carrier_digest,
                    carrier_bytes,
                    verified_at_unix_seconds,
                )
            }
        }
    }

    fn consume_generated_request(
        &self,
        request_bytes: &[u8],
        verified_at_unix_seconds: u64,
    ) -> Result<(wire::CoordinatorNodeRequest, NodeRequestEnvelopeV1), InvalidMultiNodeProtocol>
    {
        if request_bytes.is_empty()
            || request_bytes.len() > self.session.maximum_request_bytes() as usize
        {
            return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
        }
        let request = wire::CoordinatorNodeRequest::decode_from_slice(request_bytes)
            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        if request.encode_to_vec().as_slice() != request_bytes
            || request.session.as_option() != Some(&session_binding(&self.session, self.encoding))
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let request_uid: [u8; 16] = request
            .request_uid
            .as_slice()
            .try_into()
            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        let operation = OperationId::from_bytes(request_uid);
        let semantic = request
            .semantic
            .as_option()
            .ok_or(InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        let semantic_bytes = semantic.encode_to_vec();
        let kind = crate::multi_node::protocol::protobuf_codec_v1::request_frame_kind(
            semantic.kind.to_i32(),
        )?;
        let body = crate::multi_node::protocol::protobuf_codec_v1::decode_request(
            &self.session,
            kind,
            &semantic_bytes,
            verified_at_unix_seconds,
        )?;
        if self.codec.encode_request(&body)? != semantic_bytes {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
        let envelope = NodeRequestEnvelopeV1::from_generated_carrier(
            &self.session,
            operation,
            body,
            &semantic_bytes,
            request_bytes,
            verified_at_unix_seconds,
        )?;
        Ok((request, envelope))
    }
}

/// Retains exact request bytes and parsed semantics until a response arrives.
pub struct DormantOutboundExchangeV1 {
    envelope: NodeRequestEnvelopeV1,
    bytes: Vec<u8>,
    generated: Option<wire::CoordinatorNodeRequest>,
}

/// Retains exact response bytes after typed dormant-service validation.
pub struct DormantOutboundResponseV1 {
    bytes: Vec<u8>,
    generated: Option<wire::CoordinatorNodeResponse>,
}

impl DormantOutboundResponseV1 {
    /// Returns exact bytes for a caller-owned authenticated carrier.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the generated current-protocol response, or `None` for legacy JSON.
    #[must_use]
    pub const fn generated(&self) -> Option<&wire::CoordinatorNodeResponse> {
        self.generated.as_ref()
    }
}

impl DormantOutboundExchangeV1 {
    /// Returns exact bytes for a caller-owned authenticated carrier.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the validated semantic request.
    #[must_use]
    pub const fn envelope(&self) -> &NodeRequestEnvelopeV1 {
        &self.envelope
    }

    /// Returns the generated request consumed by a dormant service adapter.
    #[must_use]
    pub const fn generated(&self) -> Option<&wire::CoordinatorNodeRequest> {
        self.generated.as_ref()
    }
}

fn session_binding(
    session: &AuthenticatedNodeSessionV1,
    encoding: DormantCoordinatorNodeEncodingV1,
) -> wire::AuthenticatedSessionBinding {
    let lineage = session.lineage();
    wire::AuthenticatedSessionBinding {
        node_uid: session.node().as_bytes().to_vec(),
        node_boot_uid: lineage.boot().as_bytes().to_vec(),
        node_boot_generation: lineage.generation(),
        channel_binding_sha256: session.binding().to_vec(),
        audience_sha256: session.audience_digest().as_bytes().to_vec(),
        disclosure_domain_sha256: session.disclosure_domain_digest().as_bytes().to_vec(),
        coordinator_epoch: session.coordinator_epoch(),
        authenticated_at_unix_seconds: session.authenticated_at_unix_seconds(),
        valid_until_unix_seconds: session.valid_until_unix_seconds(),
        protocol: Some(wire::ProtocolVersion {
            major: u32::from(session.version().major()),
            minor: u32::from(session.version().minor()),
            ..Default::default()
        })
        .into(),
        maximum_request_bytes: session.maximum_request_bytes(),
        maximum_response_bytes: session.maximum_response_bytes(),
        replay_fence_sha256: session.replay_fence().as_bytes().to_vec(),
        lineage_sha256: lineage.digest().as_bytes().to_vec(),
        predecessor_boot_uid: lineage
            .predecessor_boot()
            .map_or_else(Vec::new, |boot| boot.as_bytes().to_vec()),
        predecessor_lineage_sha256: lineage
            .predecessor_digest()
            .map_or_else(Vec::new, |digest| digest.as_bytes().to_vec()),
        semantic_encoding: (encoding as i32).into(),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn handshake_bytes(
    node: NodeId,
    lineage: NodeBootLineageV1,
    channel_binding: [u8; 32],
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    version: ProtocolVersion,
    maximum_request_bytes: u32,
    maximum_response_bytes: u32,
    replay_fence: ObjectDigest,
    encoding: DormantCoordinatorNodeEncodingV1,
) -> Vec<u8> {
    wire::AuthenticatedSessionBinding {
        node_uid: node.as_bytes().to_vec(),
        node_boot_uid: lineage.boot().as_bytes().to_vec(),
        node_boot_generation: lineage.generation(),
        channel_binding_sha256: channel_binding.to_vec(),
        audience_sha256: audience_digest.as_bytes().to_vec(),
        disclosure_domain_sha256: disclosure_domain_digest.as_bytes().to_vec(),
        coordinator_epoch,
        authenticated_at_unix_seconds,
        valid_until_unix_seconds,
        protocol: Some(wire::ProtocolVersion {
            major: u32::from(version.major()),
            minor: u32::from(version.minor()),
            ..Default::default()
        })
        .into(),
        maximum_request_bytes,
        maximum_response_bytes,
        replay_fence_sha256: replay_fence.as_bytes().to_vec(),
        lineage_sha256: lineage.digest().as_bytes().to_vec(),
        predecessor_boot_uid: lineage
            .predecessor_boot()
            .map_or_else(Vec::new, |boot| boot.as_bytes().to_vec()),
        predecessor_lineage_sha256: lineage
            .predecessor_digest()
            .map_or_else(Vec::new, |digest| digest.as_bytes().to_vec()),
        semantic_encoding: (encoding as i32).into(),
        ..Default::default()
    }
    .encode_to_vec()
}
