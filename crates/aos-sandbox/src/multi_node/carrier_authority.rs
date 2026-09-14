//! Private authenticated-carrier authority boundary.
//!
//! Only this module owns constructors for carrier-verifier sessions and
//! one-shot grants. Protocol reducers can consume the resulting opaque values,
//! but no ordinary `multi_node` sibling can implement the verifier, assemble a
//! session from scalar fields, or replay a grant.

use aos_sandbox_core::{NodeId, ObjectDigest, ProtocolVersion};
use sha2::Digest as _;

use super::capability::NodeBootLineageV1;
use super::evidence::{AuthenticatedEvidenceContextV1, InvalidEvidenceContext};
use super::protocol::{
    AuthenticatedNodeSessionV1, CanonicalNodeFrameV1, InvalidMultiNodeProtocol,
    MAX_NODE_REQUEST_BYTES, MAX_NODE_RESPONSE_BYTES,
};

mod sealed {
    pub trait Sealed {}
}

/// Represents the only carrier verifier admitted by this source partition.
///
/// A future transport integration is implemented as a child of this authority
/// module and receives a constructor there after verifying its real channel.
/// The session is singular and intentionally neither `Clone` nor `Copy`.
struct CarrierVerifierSessionV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    binding: [u8; 32],
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    authenticated_frame_digest: ObjectDigest,
    authenticated_frame_bytes: u32,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    version: ProtocolVersion,
    maximum_request_bytes: u32,
    maximum_response_bytes: u32,
    replay_fence: ObjectDigest,
}

impl CarrierVerifierSessionV1 {
    /// Constructs a verifier session only for a child transport integration.
    ///
    /// The child must call this only after authenticating the exact handshake
    /// bytes, peer identity, audience, and fresh replay fence.
    #[allow(clippy::too_many_arguments)]
    fn from_verified_transport(
        node: NodeId,
        lineage: NodeBootLineageV1,
        binding: [u8; 32],
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        authenticated_frame_digest: ObjectDigest,
        authenticated_frame_bytes: u32,
        coordinator_epoch: u64,
        authenticated_at_unix_seconds: u64,
        valid_until_unix_seconds: u64,
        version: ProtocolVersion,
        maximum_request_bytes: u32,
        maximum_response_bytes: u32,
        replay_fence: ObjectDigest,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        if node.as_bytes() == &[0; 16]
            || binding == [0; 32]
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || authenticated_frame_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || authenticated_frame_bytes == 0
            || authenticated_frame_bytes > MAX_NODE_RESPONSE_BYTES
            || coordinator_epoch == 0
            || valid_until_unix_seconds <= authenticated_at_unix_seconds
            || maximum_request_bytes == 0
            || maximum_request_bytes > MAX_NODE_REQUEST_BYTES
            || maximum_response_bytes == 0
            || maximum_response_bytes > MAX_NODE_RESPONSE_BYTES
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        Ok(Self {
            node,
            lineage,
            binding,
            audience_digest,
            disclosure_domain_digest,
            authenticated_frame_digest,
            authenticated_frame_bytes,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            version,
            maximum_request_bytes,
            maximum_response_bytes,
            replay_fence,
        })
    }
}

impl sealed::Sealed for CarrierVerifierSessionV1 {}

/// Marks the private, non-implementable carrier authority interface.
trait CarrierAuthorityV1: sealed::Sealed {
    /// Consumes the verifier session and issues one protocol session grant.
    fn into_session_grant(self) -> CarrierSessionGrantV1;
}

impl CarrierAuthorityV1 for CarrierVerifierSessionV1 {
    fn into_session_grant(self) -> CarrierSessionGrantV1 {
        CarrierSessionGrantV1 {
            node: self.node,
            lineage: self.lineage,
            binding: self.binding,
            audience_digest: self.audience_digest,
            disclosure_domain_digest: self.disclosure_domain_digest,
            authenticated_frame_digest: self.authenticated_frame_digest,
            authenticated_frame_bytes: self.authenticated_frame_bytes,
            coordinator_epoch: self.coordinator_epoch,
            authenticated_at_unix_seconds: self.authenticated_at_unix_seconds,
            valid_until_unix_seconds: self.valid_until_unix_seconds,
            version: self.version,
            maximum_request_bytes: self.maximum_request_bytes,
            maximum_response_bytes: self.maximum_response_bytes,
            replay_fence: self.replay_fence,
        }
    }
}

/// Carries a singular authenticated protocol-session decision.
///
/// Fields and construction remain private to this authority module. Consuming
/// the grant prevents accidental reuse of one verifier response.
pub(super) struct CarrierSessionGrantV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    binding: [u8; 32],
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    authenticated_frame_digest: ObjectDigest,
    authenticated_frame_bytes: u32,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    version: ProtocolVersion,
    maximum_request_bytes: u32,
    maximum_response_bytes: u32,
    replay_fence: ObjectDigest,
}

impl CarrierSessionGrantV1 {
    pub(super) const fn node(&self) -> NodeId {
        self.node
    }
    pub(super) const fn lineage(&self) -> NodeBootLineageV1 {
        self.lineage
    }
    pub(super) const fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub(super) const fn audience_digest(&self) -> ObjectDigest {
        self.audience_digest
    }
    pub(super) const fn disclosure_domain_digest(&self) -> ObjectDigest {
        self.disclosure_domain_digest
    }
    pub(super) const fn authenticated_frame_digest(&self) -> ObjectDigest {
        self.authenticated_frame_digest
    }
    pub(super) const fn authenticated_frame_bytes(&self) -> u32 {
        self.authenticated_frame_bytes
    }
    pub(super) const fn coordinator_epoch(&self) -> u64 {
        self.coordinator_epoch
    }
    pub(super) const fn authenticated_at_unix_seconds(&self) -> u64 {
        self.authenticated_at_unix_seconds
    }
    pub(super) const fn valid_until_unix_seconds(&self) -> u64 {
        self.valid_until_unix_seconds
    }
    pub(super) const fn version(&self) -> ProtocolVersion {
        self.version
    }
    pub(super) const fn maximum_request_bytes(&self) -> u32 {
        self.maximum_request_bytes
    }
    pub(super) const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }
    pub(super) const fn replay_fence(&self) -> ObjectDigest {
        self.replay_fence
    }
}

/// Carries a singular authenticated evidence decision.
pub(super) struct CarrierEvidenceGrantV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    carrier_binding_digest: ObjectDigest,
    canonical_bytes_digest: ObjectDigest,
    canonical_bytes: u32,
    coordinator_epoch: u64,
    verified_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    replay_fence: ObjectDigest,
}

/// Carries one singular exact-frame authentication into protocol decoding.
///
/// Neither the session nor its verifier-issued evidence can be extracted by
/// ordinary siblings except through consuming protocol construction.
pub(super) struct CarrierResponseGrantV1 {
    session: AuthenticatedNodeSessionV1,
    context: AuthenticatedEvidenceContextV1,
    frame_seal: AuthenticatedFrameSealV1,
}

/// Seals the exact authenticated frame kind and semantic body commitment.
///
/// Its fields and constructor remain in this authority module. Reducers can
/// validate against a borrowed seal but cannot synthesize one from digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedFrameSealV1 {
    kind: super::protocol::CanonicalNodeFrameKindV1,
    body_digest: ObjectDigest,
    frame_digest: ObjectDigest,
    frame_bytes: u32,
    replay_fence: ObjectDigest,
}

impl AuthenticatedFrameSealV1 {
    pub(super) fn matches(
        &self,
        kind: super::protocol::CanonicalNodeFrameKindV1,
        body_digest: ObjectDigest,
        context: AuthenticatedEvidenceContextV1,
    ) -> bool {
        self.kind == kind
            && self.body_digest == body_digest
            && self.frame_digest == context.canonical_frame_digest()
            && self.frame_bytes == context.canonical_frame_bytes()
            && self.replay_fence == context.replay_fence()
    }
}

impl CarrierResponseGrantV1 {
    pub(super) fn into_parts(
        self,
    ) -> (
        AuthenticatedNodeSessionV1,
        AuthenticatedEvidenceContextV1,
        AuthenticatedFrameSealV1,
    ) {
        (self.session, self.context, self.frame_seal)
    }
}

impl CarrierEvidenceGrantV1 {
    pub(super) const fn node(&self) -> NodeId {
        self.node
    }
    pub(super) const fn lineage(&self) -> NodeBootLineageV1 {
        self.lineage
    }
    pub(super) const fn audience_digest(&self) -> ObjectDigest {
        self.audience_digest
    }
    pub(super) const fn disclosure_domain_digest(&self) -> ObjectDigest {
        self.disclosure_domain_digest
    }
    pub(super) const fn carrier_binding_digest(&self) -> ObjectDigest {
        self.carrier_binding_digest
    }
    pub(super) const fn canonical_bytes_digest(&self) -> ObjectDigest {
        self.canonical_bytes_digest
    }
    pub(super) const fn canonical_bytes(&self) -> u32 {
        self.canonical_bytes
    }
    pub(super) const fn coordinator_epoch(&self) -> u64 {
        self.coordinator_epoch
    }
    pub(super) const fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }
    pub(super) const fn valid_until_unix_seconds(&self) -> u64 {
        self.valid_until_unix_seconds
    }
    pub(super) const fn replay_fence(&self) -> ObjectDigest {
        self.replay_fence
    }
}

/// Consumes one authenticated carrier session and issues its protocol model.
///
/// # Errors
///
/// Returns [`InvalidMultiNodeProtocol`] when any verified fact is invalid or
/// exceeds a compiled frame ceiling.
fn issue_node_session_once(
    authority: impl CarrierAuthorityV1,
) -> Result<AuthenticatedNodeSessionV1, InvalidMultiNodeProtocol> {
    AuthenticatedNodeSessionV1::from_authority_grant(authority.into_session_grant())
}

/// Issues evidence for exact canonical bytes already authenticated by a session.
///
/// # Errors
///
/// Returns [`InvalidEvidenceContext`] when the byte identity, audience, replay
/// fence, or currentness does not match the authenticated protocol session.
fn issue_evidence_once(
    session: &AuthenticatedNodeSessionV1,
    canonical_bytes_digest: ObjectDigest,
    canonical_bytes: u32,
    verified_at_unix_seconds: u64,
) -> Result<AuthenticatedEvidenceContextV1, InvalidEvidenceContext> {
    if canonical_bytes_digest.as_bytes() == &[0; 32]
        || canonical_bytes == 0
        || canonical_bytes > MAX_NODE_RESPONSE_BYTES
        || canonical_bytes > session.maximum_response_bytes()
        || verified_at_unix_seconds < session.authenticated_at_unix_seconds()
        || !session.is_current_at(verified_at_unix_seconds)
    {
        return Err(InvalidEvidenceContext::Invalid);
    }
    let grant = CarrierEvidenceGrantV1 {
        node: session.node(),
        lineage: session.lineage(),
        audience_digest: session.audience_digest(),
        disclosure_domain_digest: session.disclosure_domain_digest(),
        carrier_binding_digest: session.binding_digest(),
        canonical_bytes_digest,
        canonical_bytes,
        coordinator_epoch: session.coordinator_epoch(),
        verified_at_unix_seconds,
        valid_until_unix_seconds: session.valid_until_unix_seconds(),
        replay_fence: session.replay_fence(),
    };
    AuthenticatedEvidenceContextV1::from_authority_grant(grant)
}

/// Issues a one-shot response grant after authenticating the exact frame.
///
/// This constructor is intentionally private. A future carrier integration is
/// a child module of this authority and calls it only after authenticating the
/// exact byte slice, peer, audience, disclosure domain, and replay fence.
fn issue_response_once(
    session: AuthenticatedNodeSessionV1,
    frame: &CanonicalNodeFrameV1<'_>,
    verified_at_unix_seconds: u64,
) -> Result<CarrierResponseGrantV1, InvalidMultiNodeProtocol> {
    let canonical_bytes = u32::try_from(frame.bytes().len())
        .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
    if frame.frame_digest() != ObjectDigest::from_bytes(sha2::Sha256::digest(frame.bytes()).into())
        || frame.binding_digest() != session.binding_digest()
        || frame.audience_digest() != session.audience_digest()
        || frame.disclosure_domain_digest() != session.disclosure_domain_digest()
        || frame.version() != session.version()
        || canonical_bytes > session.maximum_response_bytes()
    {
        return Err(InvalidMultiNodeProtocol::SessionMismatch);
    }
    let context = issue_evidence_once(
        &session,
        frame.frame_digest(),
        canonical_bytes,
        verified_at_unix_seconds,
    )
    .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
    let replay_fence = session.replay_fence();
    Ok(CarrierResponseGrantV1 {
        session,
        context,
        frame_seal: AuthenticatedFrameSealV1 {
            kind: frame.kind(),
            body_digest: frame.body_digest(),
            frame_digest: frame.frame_digest(),
            frame_bytes: canonical_bytes,
            replay_fence,
        },
    })
}
