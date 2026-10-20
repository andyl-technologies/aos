//! Canonical coordinator handshake DATA and generated session-field mapping.
//!
//! These values contain no authenticated session, native clock, signature
//! verifier, protected writer or grant. Both the Coordinator and native local
//! verifier use this one mapping; only the latter may authenticate its bytes.

use aos_proto::aos::sandbox::coordinator::v1 as shared_wire;
use aos_sandbox_core::{NodeBootLineageV1, NodeId, ObjectDigest, ProtocolVersion};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::aos::sandbox::coordinator::v1 as wire;

/// Selects the canonical carrier representation encoded by handshake DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorNodeEncodingV1 {
    /// Uses generated coordinator request and response messages.
    Protobuf = 1,
}

/// Describes immutable session fields without authenticating any of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorSessionBindingDataV1 {
    /// Names the observed node without granting it ownership.
    pub node: NodeId,
    /// Carries the immutable node boot lineage.
    pub lineage: NodeBootLineageV1,
    /// Commits the expected public channel key.
    pub channel_binding: [u8; 32],
    /// Commits the intended request audience.
    pub audience_digest: ObjectDigest,
    /// Commits the permitted disclosure domain.
    pub disclosure_domain_digest: ObjectDigest,
    /// Names the immutable coordinator epoch.
    pub coordinator_epoch: u64,
    /// Carries the claimed beginning of the handshake interval.
    pub authenticated_at_unix_seconds: u64,
    /// Carries the immutable end of the handshake interval.
    pub valid_until_unix_seconds: u64,
    /// Names the negotiated protocol semantics.
    pub version: ProtocolVersion,
    /// Bounds a canonical generated request.
    pub maximum_request_bytes: u32,
    /// Bounds a canonical generated response.
    pub maximum_response_bytes: u32,
    /// Commits the original replay fence.
    pub replay_fence: ObjectDigest,
    /// Selects the sole canonical generated representation.
    pub encoding: CoordinatorNodeEncodingV1,
}

/// Reports canonical handshake DATA construction failures without authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorHandshakeDataErrorV1 {
    /// The canonical payload length does not fit the existing u32 frame field.
    FrameLengthOverflow,
    /// Session DATA contains a sentinel, invalid interval or excessive bound.
    SessionShape,
}

impl std::fmt::Display for CoordinatorHandshakeDataErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::FrameLengthOverflow => "coordinator handshake length exceeds the frame field",
            Self::SessionShape => "coordinator handshake session DATA is malformed",
        })
    }
}

impl std::error::Error for CoordinatorHandshakeDataErrorV1 {}

/// Retains one canonical handshake payload as non-authorizing DATA.
///
/// A caller-supplied ceiling affects DATA validation only. The actual protected
/// verifier independently applies its own compiled limits before issuing any
/// session, and verifies this exact payload with its fixed native key and time.
pub struct CanonicalCoordinatorHandshakeV1 {
    data: CoordinatorSessionBindingDataV1,
    canonical_bytes: Vec<u8>,
}

impl CanonicalCoordinatorHandshakeV1 {
    /// Constructs exact handshake bytes within the supplied DATA ceilings.
    ///
    /// This constructor performs no authentication and issues no session grant.
    ///
    /// # Errors
    ///
    /// Returns a frame-length overflow or the original session-shape failure.
    #[must_use]
    pub fn new(
        data: CoordinatorSessionBindingDataV1,
        request_ceiling: u32,
        response_ceiling: u32,
    ) -> Result<Self, CoordinatorHandshakeDataErrorV1> {
        let canonical_bytes = session_binding_v1(data).encode_to_vec();
        let bytes = u32::try_from(canonical_bytes.len())
            .map_err(|_| CoordinatorHandshakeDataErrorV1::FrameLengthOverflow)?;
        if !aos_sandbox_core::node_session_data::node_session_data_is_well_formed_v1(
            data.node,
            data.channel_binding,
            data.audience_digest,
            data.disclosure_domain_digest,
            ObjectDigest::from_bytes(Sha256::digest(&canonical_bytes).into()),
            bytes,
            data.coordinator_epoch,
            data.authenticated_at_unix_seconds,
            data.valid_until_unix_seconds,
            data.maximum_request_bytes,
            data.maximum_response_bytes,
            request_ceiling,
            response_ceiling,
            data.replay_fence,
        ) {
            return Err(CoordinatorHandshakeDataErrorV1::SessionShape);
        }
        Ok(Self {
            data,
            canonical_bytes,
        })
    }

    /// Returns the unchanged session-field DATA.
    #[must_use]
    pub const fn data_v1(&self) -> CoordinatorSessionBindingDataV1 {
        self.data
    }

    /// Returns the exact canonical payload for detached signing.
    #[must_use]
    pub fn signing_payload(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Maps handshake DATA and native authenticated sessions to one field schema.
#[must_use]
pub fn session_binding_v1(
    data: CoordinatorSessionBindingDataV1,
) -> wire::AuthenticatedSessionBinding {
    let CoordinatorSessionBindingDataV1 {
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
    } = data;
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
        protocol: Some(shared_wire::ProtocolVersion {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{NodeBootId, ProtocolId, supported_protocol_version};

    fn binding() -> CoordinatorSessionBindingDataV1 {
        let boot = NodeBootId::new([2; 16]).unwrap();
        let lineage = NodeBootLineageV1::new(
            boot,
            1,
            None,
            None,
            NodeBootLineageV1::canonical_digest_for(boot, 1, None, None),
        )
        .unwrap();
        CoordinatorSessionBindingDataV1 {
            node: NodeId::from_bytes([1; 16]),
            lineage,
            channel_binding: [3; 32],
            audience_digest: ObjectDigest::from_bytes([4; 32]),
            disclosure_domain_digest: ObjectDigest::from_bytes([5; 32]),
            coordinator_epoch: 6,
            authenticated_at_unix_seconds: 100,
            valid_until_unix_seconds: 101,
            version: supported_protocol_version(ProtocolId::CoordinatorNode),
            maximum_request_bytes: 1024,
            maximum_response_bytes: 1024,
            replay_fence: ObjectDigest::from_bytes([7; 32]),
            encoding: CoordinatorNodeEncodingV1::Protobuf,
        }
    }

    #[test]
    fn canonical_signing_payload_preserves_the_generated_session_contract() {
        let data = binding();
        let handshake = CanonicalCoordinatorHandshakeV1::new(data, 1024, 1024).unwrap();
        let decoded =
            wire::AuthenticatedSessionBinding::decode_from_slice(handshake.signing_payload())
                .unwrap();

        assert_eq!(decoded, session_binding_v1(data));
        assert_eq!(decoded.encode_to_vec(), handshake.signing_payload());
        assert_eq!(handshake.data_v1(), data);
    }

    #[test]
    fn canonical_payload_does_not_bypass_the_existing_replay_or_limit_sentinels() {
        let mut data = binding();
        assert!(CanonicalCoordinatorHandshakeV1::new(data, 1024, 1024).is_ok());

        data.replay_fence = ObjectDigest::from_bytes([0; 32]);
        assert!(matches!(
            CanonicalCoordinatorHandshakeV1::new(data, 1024, 1024),
            Err(CoordinatorHandshakeDataErrorV1::SessionShape)
        ));

        data = binding();
        data.maximum_request_bytes = 1025;
        assert!(matches!(
            CanonicalCoordinatorHandshakeV1::new(data, 1024, 1024),
            Err(CoordinatorHandshakeDataErrorV1::SessionShape)
        ));
    }
}
