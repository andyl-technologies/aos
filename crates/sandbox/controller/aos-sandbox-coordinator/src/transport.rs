//! Owns dormant Coordinator packet construction and exchange custody.
//!
//! This implementation installs no listener or worker. The actual local native
//! owner authenticates each turn under its fixed trust and protected clock;
//! packet DATA, a decoded tag or a detached receipt cannot replace that owner.

use aos_sandbox_api::aos::sandbox::coordinator::v1 as shared_wire;
use aos_sandbox_controller_domain::local_inventory::ProtectedMultiNodeAuthorityOwnerV1;
use aos_sandbox_controller_domain::local_inventory::protocol::{
    CanonicalNodeSemanticCodecV1, NodeRequestEnvelopeV1, NodeResponseBodyV1, NodeResponseEnvelopeV1,
};
use aos_sandbox_controller_domain::local_inventory::remote::{
    ProtectedCoordinatorChannelOriginalV1, ProtectedCoordinatorRequestOriginalV1,
    ProtectedMultiNodeUpdateErrorV1,
};
use aos_sandbox_coordinator_protocol::aos::sandbox::coordinator::v1 as wire;
use aos_sandbox_coordinator_protocol::session_binding::{
    CanonicalCoordinatorHandshakeV1, CoordinatorHandshakeDataErrorV1, CoordinatorNodeEncodingV1,
    CoordinatorSessionBindingDataV1,
};
use aos_sandbox_model::NodeRequestBodyV1;
use aos_sandbox_model::{InvalidMultiNodeProtocol, MAX_NODE_REQUEST_BYTES, MAX_NODE_RESPONSE_BYTES};
use aos_sandbox_model::{NodeBootLineageV1, NodeId, ObjectDigest, OperationId, ProtocolVersion};
use buffa::Message as _;

/// Constructs exact canonical handshake DATA for a detached protected signer.
///
/// # Errors
///
/// Returns the original session-shape refusal for sentinels or invalid bounds.
/// No native session is created until the actual owner verifies these bytes.
#[allow(clippy::too_many_arguments)]
pub fn prepare_transport_handshake_v1(
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
) -> Result<CanonicalCoordinatorHandshakeV1, InvalidMultiNodeProtocol> {
    CanonicalCoordinatorHandshakeV1::new(
        CoordinatorSessionBindingDataV1 {
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
            encoding: CoordinatorNodeEncodingV1::Protobuf,
        },
        MAX_NODE_REQUEST_BYTES,
        MAX_NODE_RESPONSE_BYTES,
    )
    .map_err(|error| match error {
        CoordinatorHandshakeDataErrorV1::FrameLengthOverflow => {
            InvalidMultiNodeProtocol::InvalidFrameLimits
        }
        CoordinatorHandshakeDataErrorV1::SessionShape => InvalidMultiNodeProtocol::SessionMismatch,
    })
}

/// Owns packet construction and the singular native-authenticated channel.
pub struct CoordinatorNodeTransportOriginalV1 {
    channel: ProtectedCoordinatorChannelOriginalV1,
    codec: CanonicalNodeSemanticCodecV1,
}

impl CoordinatorNodeTransportOriginalV1 {
    /// Authenticates canonical handshake bytes through the actual local owner.
    ///
    /// # Errors
    ///
    /// Returns the actual fixed-key, native-clock, signature or session refusal.
    pub fn authenticate_once_v1(
        owner: &mut ProtectedMultiNodeAuthorityOwnerV1,
        handshake: CanonicalCoordinatorHandshakeV1,
        canonical_signature: &[u8],
    ) -> Result<Self, ProtectedMultiNodeUpdateErrorV1> {
        let channel =
            owner.authenticate_coordinator_channel_once_v1(handshake, canonical_signature)?;
        Ok(Self {
            channel,
            codec: CanonicalNodeSemanticCodecV1::new(),
        })
    }

    /// Constructs and seals one exact bounded request without transmitting it.
    ///
    /// # Errors
    ///
    /// Returns the original native-currentness, semantic, limit or roundtrip failure.
    pub fn prepare_exchange_once_v1(
        &self,
        owner: &mut ProtectedMultiNodeAuthorityOwnerV1,
        request: OperationId,
        body: &NodeRequestBodyV1,
    ) -> Result<CoordinatorOutboundExchangeOriginalV1, ProtectedMultiNodeUpdateErrorV1> {
        let scope = owner.borrow_coordinator_channel_once_v1(&self.channel)?;
        let session = scope.session_v1();
        let semantic_bytes = self.codec.encode_request(body)?;
        let semantic = shared_wire::SemanticEnvelope::decode_from_slice(semantic_bytes.as_slice())
            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        let generated = wire::CoordinatorNodeRequest {
            request_uid: request.as_bytes().to_vec(),
            session: Some(scope.session_binding_data_v1()).into(),
            semantic: Some(semantic).into(),
            ..Default::default()
        };
        let bytes = generated.encode_to_vec();
        if bytes.is_empty() || bytes.len() > session.maximum_request_bytes() as usize {
            return Err(InvalidMultiNodeProtocol::InvalidFrameLimits.into());
        }
        let (consumed, native) = scope.seal_generated_request_once_v1(&bytes)?;
        if native.envelope_v1().request() != request || native.envelope_v1().body() != body {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame.into());
        }
        Ok(CoordinatorOutboundExchangeOriginalV1 {
            native,
            bytes,
            generated: Some(consumed),
        })
    }

    /// Authenticates one inbound request through its real native owner turn.
    ///
    /// # Errors
    ///
    /// Returns the original native, signature, canonical or semantic refusal.
    pub fn accept_request_once_v1(
        &self,
        owner: &mut ProtectedMultiNodeAuthorityOwnerV1,
        request_bytes: &[u8],
        canonical_signature: &[u8],
    ) -> Result<NodeRequestEnvelopeV1, ProtectedMultiNodeUpdateErrorV1> {
        owner
            .borrow_coordinator_channel_once_v1(&self.channel)?
            .accept_generated_request_once_v1(request_bytes, canonical_signature)
            .map_err(Into::into)
    }

    /// Constructs a response after the native request/body relation passes.
    ///
    /// # Errors
    ///
    /// Returns the original native, correlation, body, limit or roundtrip refusal.
    pub fn prepare_response_once_v1(
        &self,
        owner: &mut ProtectedMultiNodeAuthorityOwnerV1,
        request: &NodeRequestEnvelopeV1,
        body: &NodeResponseBodyV1,
    ) -> Result<CoordinatorOutboundResponseOriginalV1, ProtectedMultiNodeUpdateErrorV1> {
        let scope = owner.borrow_coordinator_channel_once_v1(&self.channel)?;
        scope.require_response_body_v1(request, body)?;
        let session = scope.session_v1();
        let semantic_bytes = self.codec.encode_response(body)?;
        let semantic = shared_wire::SemanticEnvelope::decode_from_slice(semantic_bytes.as_slice())
            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        let generated = wire::CoordinatorNodeResponse {
            request_uid: request.request().as_bytes().to_vec(),
            session: Some(scope.session_binding_data_v1()).into(),
            semantic: Some(semantic).into(),
            ..Default::default()
        };
        let bytes = generated.encode_to_vec();
        if bytes.is_empty() || bytes.len() > session.maximum_response_bytes() as usize {
            return Err(InvalidMultiNodeProtocol::InvalidFrameLimits.into());
        }
        let consumed = wire::CoordinatorNodeResponse::decode_from_slice(bytes.as_slice())
            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        if consumed.encode_to_vec() != bytes || consumed != generated {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame.into());
        }
        drop(scope);
        Ok(CoordinatorOutboundResponseOriginalV1 {
            bytes,
            generated: Some(consumed),
        })
    }

    /// Consumes the singular channel through the actual native response issuer.
    ///
    /// # Errors
    ///
    /// Returns the original native/signature/correlation/canonical/semantic cause.
    pub fn accept_response_once_v1(
        self,
        owner: &mut ProtectedMultiNodeAuthorityOwnerV1,
        request: &CoordinatorOutboundExchangeOriginalV1,
        response_bytes: &[u8],
        canonical_signature: &[u8],
    ) -> Result<NodeResponseEnvelopeV1, ProtectedMultiNodeUpdateErrorV1> {
        owner
            .begin_coordinator_response_once_v1(self.channel)?
            .accept_generated_response_once_v1(&request.native, response_bytes, canonical_signature)
            .map_err(Into::into)
    }
}

/// Retains exact request bytes and its genuine native-sealed request envelope.
pub struct CoordinatorOutboundExchangeOriginalV1 {
    native: ProtectedCoordinatorRequestOriginalV1,
    bytes: Vec<u8>,
    generated: Option<wire::CoordinatorNodeRequest>,
}

impl CoordinatorOutboundExchangeOriginalV1 {
    /// Returns exact bytes for the caller's authenticated carrier.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the actual native-sealed request envelope.
    #[must_use]
    pub fn envelope(&self) -> &NodeRequestEnvelopeV1 {
        self.native.envelope_v1()
    }

    /// Borrows the actual generated request consumed by the native parser.
    #[must_use]
    pub const fn generated(&self) -> Option<&wire::CoordinatorNodeRequest> {
        self.generated.as_ref()
    }
}

/// Retains exact response bytes after current request/body validation.
pub struct CoordinatorOutboundResponseOriginalV1 {
    bytes: Vec<u8>,
    generated: Option<wire::CoordinatorNodeResponse>,
}

impl CoordinatorOutboundResponseOriginalV1 {
    /// Returns exact bytes for the caller's protected signer/carrier.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the actual roundtrip-validated generated response.
    #[must_use]
    pub const fn generated(&self) -> Option<&wire::CoordinatorNodeResponse> {
        self.generated.as_ref()
    }
}
