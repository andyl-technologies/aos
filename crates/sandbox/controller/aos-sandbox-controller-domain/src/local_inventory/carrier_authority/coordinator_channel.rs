//! Native fixed-trust channel and private generated-carrier evidence factories.
//!
//! Packet construction and exchange orchestration belong to the Coordinator.
//! This owner retains the actual singular session, protected-key affinity and
//! private one-shot request/response grants. Only the genuine protected owner
//! can supply native time and fixed trust to these private factory operations.

use aos_sandbox_coordinator_protocol::aos::sandbox::coordinator::v1 as wire;
use aos_sandbox_coordinator_protocol::session_binding::{
    CanonicalCoordinatorHandshakeV1, CoordinatorNodeEncodingV1, CoordinatorSessionBindingDataV1,
    session_binding_v1,
};
use aos_sandbox_model::{ObjectDigest, OperationId};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::local_inventory::protocol::{
    CanonicalNodeSemanticCodecV1, NodeRequestEnvelopeV1, NodeResponseBodyV1,
    NodeResponseEnvelopeV1, validate_response_body,
};

/// Retains the native-authenticated session and exact protected-trust affinity.
///
/// This singular value has no public constructor, clone or raw-part adoption.
/// Every operation additionally borrows the actual protected owner through a
/// native currentness scope; this channel alone cannot refresh its interval.
pub struct ProtectedCoordinatorChannelOriginalV1 {
    session: AuthenticatedNodeSessionV1,
    codec: CanonicalNodeSemanticCodecV1,
    encoding: CoordinatorNodeEncodingV1,
    protected_trust_policy_digest: ObjectDigest,
}

/// Retains a generated request sealed under the actual native channel scope.
///
/// Its private encoding marker is recorded by the canonical native parser,
/// never adopted from a caller's success flag or separately supplied envelope.
pub struct ProtectedCoordinatorRequestOriginalV1 {
    envelope: NodeRequestEnvelopeV1,
    encoding: CoordinatorNodeEncodingV1,
}

impl ProtectedCoordinatorRequestOriginalV1 {
    /// Returns the exact request envelope validated by the native channel.
    #[must_use]
    pub const fn envelope_v1(&self) -> &NodeRequestEnvelopeV1 {
        &self.envelope
    }
}

impl ProtectedCoordinatorChannelOriginalV1 {
    pub(in crate::local_inventory) fn authenticate_handshake_v1(
        handshake: CanonicalCoordinatorHandshakeV1,
        canonical_signature: &[u8],
        canonical_trust_policy: &[u8],
        public_key: &[u8; 32],
        current_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let data = handshake.data_v1();
        if data.channel_binding != *public_key
            || current_unix_seconds < data.authenticated_at_unix_seconds
            || current_unix_seconds > data.valid_until_unix_seconds
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        verify_protected_carrier_signature(
            handshake.signing_payload(),
            canonical_signature,
            canonical_trust_policy,
            public_key,
            current_unix_seconds,
        )?;
        let session = CarrierVerifierSessionV1::from_verified_transport(
            data.node,
            data.lineage,
            data.channel_binding,
            data.audience_digest,
            data.disclosure_domain_digest,
            ObjectDigest::from_bytes(Sha256::digest(handshake.signing_payload()).into()),
            u32::try_from(handshake.signing_payload().len())
                .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?,
            data.coordinator_epoch,
            data.authenticated_at_unix_seconds,
            data.valid_until_unix_seconds,
            data.version,
            data.maximum_request_bytes,
            data.maximum_response_bytes,
            data.replay_fence,
        )?
        .into_session_grant();
        Ok(Self {
            session: AuthenticatedNodeSessionV1::from_authority_grant(session)?,
            codec: CanonicalNodeSemanticCodecV1::new(),
            encoding: data.encoding,
            protected_trust_policy_digest: ObjectDigest::from_bytes(
                Sha256::digest(canonical_trust_policy).into(),
            ),
        })
    }

    pub(in crate::local_inventory) fn validate_protected_owner(
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

    pub(in crate::local_inventory) fn session_v1(&self) -> &AuthenticatedNodeSessionV1 {
        &self.session
    }

    pub(in crate::local_inventory) fn session_binding_data_v1(
        &self,
    ) -> wire::AuthenticatedSessionBinding {
        session_binding(&self.session, self.encoding)
    }

    pub(in crate::local_inventory) fn seal_generated_request_v1(
        &self,
        bytes: &[u8],
        current_unix_seconds: u64,
    ) -> Result<
        (
            wire::CoordinatorNodeRequest,
            ProtectedCoordinatorRequestOriginalV1,
        ),
        InvalidMultiNodeProtocol,
    > {
        let (generated, envelope) = self.consume_generated_request(bytes, current_unix_seconds)?;
        Ok((
            generated,
            ProtectedCoordinatorRequestOriginalV1 {
                envelope,
                encoding: self.encoding,
            },
        ))
    }

    pub(in crate::local_inventory) fn accept_request_with_protected_owner(
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

        self.consume_generated_request(request_bytes, verified_at_unix_seconds)
            .map(|(_, envelope)| envelope)
    }

    pub(in crate::local_inventory) fn require_response_semantics_v1(
        &self,
        request: &NodeRequestEnvelopeV1,
        body: &NodeResponseBodyV1,
        coordinator_unix_seconds: u64,
    ) -> Result<(), InvalidMultiNodeProtocol> {
        if !self.session.is_current_at(coordinator_unix_seconds)
            || request.binding() != &self.session.binding()
            || request.node() != self.session.node()
            || request.audience_digest() != self.session.audience_digest()
            || request.disclosure_domain_digest() != self.session.disclosure_domain_digest()
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        validate_response_body(&self.session, request.body(), body)?;

        Ok(())
    }

    pub(in crate::local_inventory) fn accept_response_with_protected_owner(
        self,
        request: &ProtectedCoordinatorRequestOriginalV1,
        response_bytes: &[u8],
        canonical_signature: &[u8],
        canonical_trust_policy: &[u8],
        public_key: &[u8; 32],
        verified_at_unix_seconds: u64,
    ) -> Result<NodeResponseEnvelopeV1, InvalidMultiNodeProtocol> {
        if self.session.binding() != *public_key {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        if request.encoding != self.encoding {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        verify_protected_carrier_signature(
            response_bytes,
            canonical_signature,
            canonical_trust_policy,
            public_key,
            verified_at_unix_seconds,
        )?;
        if response_bytes.is_empty()
            || response_bytes.len() > self.session.maximum_response_bytes() as usize
        {
            return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
        }
        let response = wire::CoordinatorNodeResponse::decode_from_slice(response_bytes)
            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        if response.encode_to_vec().as_slice() != response_bytes
            || response.request_uid.as_slice() != request.envelope.request().as_bytes()
            || response.session.as_option() != Some(&session_binding(&self.session, self.encoding))
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let semantic = response
            .semantic
            .into_option()
            .ok_or(InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        let semantic_bytes = semantic.encode_to_vec();
        let kind = crate::local_inventory::protocol::protobuf_codec_v1::response_frame_kind(
            semantic.kind.to_i32(),
        )?;
        let carrier_bytes = u32::try_from(response_bytes.len())
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        let body_digest = ObjectDigest::from_bytes(Sha256::digest(&semantic_bytes).into());
        let carrier_digest = ObjectDigest::from_bytes(Sha256::digest(response_bytes).into());
        let grant = issue_generated_response_once(
            self.session,
            kind,
            body_digest,
            carrier_digest,
            carrier_bytes,
            verified_at_unix_seconds,
        )?;
        let body = crate::local_inventory::protocol::protobuf_codec_v1::decode_response(
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
        let kind = crate::local_inventory::protocol::protobuf_codec_v1::request_frame_kind(
            semantic.kind.to_i32(),
        )?;
        let body = crate::local_inventory::protocol::protobuf_codec_v1::decode_request(
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

fn session_binding(
    session: &AuthenticatedNodeSessionV1,
    encoding: CoordinatorNodeEncodingV1,
) -> wire::AuthenticatedSessionBinding {
    let lineage = session.lineage();

    session_binding_v1(CoordinatorSessionBindingDataV1 {
        node: session.node(),
        lineage,
        channel_binding: session.binding(),
        audience_digest: session.audience_digest(),
        disclosure_domain_digest: session.disclosure_domain_digest(),
        coordinator_epoch: session.coordinator_epoch(),
        authenticated_at_unix_seconds: session.authenticated_at_unix_seconds(),
        valid_until_unix_seconds: session.valid_until_unix_seconds(),
        version: session.version(),
        maximum_request_bytes: session.maximum_request_bytes(),
        maximum_response_bytes: session.maximum_response_bytes(),
        replay_fence: session.replay_fence(),
        encoding,
    })
}
