//! Private authenticated-carrier authority boundary.
//!
//! Only this module owns constructors for carrier-verifier sessions and
//! one-shot grants. Protocol reducers can consume the resulting opaque values,
//! but no ordinary `multi_node` sibling can implement the verifier, assemble a
//! session from scalar fields, or replay a grant.

use aos_sandbox_core::format::{decode_signature, encode_signature};
use aos_sandbox_core::model::SignaturePurpose;
use aos_sandbox_core::{
    AssignmentEpoch, DecodeLimits, MediaType, NodeId, ObjectDigest, PortableMediaType,
    ProtocolVersion, descriptor_for_bytes, verify_signature,
};
use sha2::{Digest as _, Sha256};

use super::assignment::{AssignmentIntentV1, VerifiedAssignmentAuthorityV1};
use super::capability::NodeBootLineageV1;
use super::evidence::{AuthenticatedEvidenceContextV1, InvalidEvidenceContext};
use super::journal::ProtectedJournalRecordV1;
use super::protocol::{
    AuthenticatedNodeSessionV1, CanonicalNodeFrameV1, InvalidMultiNodeProtocol,
    MAX_NODE_REQUEST_BYTES, MAX_NODE_RESPONSE_BYTES,
};

mod sealed {
    pub trait Sealed {}
}

mod dormant_transport;
pub use dormant_transport::{
    DormantAuthenticatedCoordinatorNodeTransportV1, DormantCoordinatorNodeEncodingV1,
    DormantOutboundExchangeV1, DormantOutboundResponseV1, DormantTransportHandshakeV1,
};

const ASSIGNMENT_CARRIER_DOMAIN: &[u8] = b"aos.sandbox.multi-node.assignment-carrier.v1\0";
const MAXIMUM_ASSIGNMENT_SIGNATURE_BYTES: usize = 64 * 1024;

/// Binds authenticated peer and ownership facts for one assignment store write.
///
/// Construction stays inside this verifier authority. The value is singular,
/// does not contain a signing key or lease capability, and cannot extend the
/// verifier's original currentness interval.
pub(super) struct AuthenticatedAssignmentCarrierContractV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    peer_identity_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    authenticated_frame_digest: ObjectDigest,
    authenticated_frame_bytes: u32,
    coordinator_epoch: u64,
    assignment_epoch: AssignmentEpoch,
    assignment_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    signature_digest: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
    replay_fence: ObjectDigest,
    verified_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    digest: ObjectDigest,
}

/// Carries one exact detached-signature verification result into the carrier.
///
/// Only a verifier child can construct this singular grant. Keeping canonical
/// signature bytes here prevents another sibling from substituting a digest.
pub(super) struct VerifiedAssignmentSignatureGrantV1 {
    assignment_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    canonical_signature: Vec<u8>,
    signature_digest: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
    verified_at_unix_seconds: u64,
}

impl VerifiedAssignmentSignatureGrantV1 {
    /// Seals exact signature bytes after a child cryptographic verifier succeeds.
    fn from_verified_signature(
        assignment_digest: ObjectDigest,
        lease_generation: u64,
        lease_digest: ObjectDigest,
        canonical_signature: Vec<u8>,
        context: AuthenticatedEvidenceContextV1,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        if assignment_digest.as_bytes() == &[0; 32]
            || lease_generation == 0
            || lease_digest.as_bytes() == &[0; 32]
            || canonical_signature.is_empty()
            || canonical_signature.len() > MAXIMUM_ASSIGNMENT_SIGNATURE_BYTES
            || !context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let signature_digest =
            ObjectDigest::from_bytes(Sha256::digest(&canonical_signature).into());
        Ok(Self {
            assignment_digest,
            lease_generation,
            lease_digest,
            canonical_signature,
            signature_digest,
            context,
            verified_at_unix_seconds,
        })
    }
}

impl AuthenticatedAssignmentCarrierContractV1 {
    /// Issues a store contract after exact carrier and owner verification.
    ///
    /// This private constructor is reserved for the verifier authority after it
    /// authenticates the signature grant's exact detached bytes as the signature
    /// associated with `authority`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::SessionMismatch`] when carrier,
    /// assignment, lease, signature, currentness, or replay facts differ.
    pub(super) fn from_verified_assignment(
        session: &AuthenticatedNodeSessionV1,
        intent: &AssignmentIntentV1,
        authority: VerifiedAssignmentAuthorityV1,
        signature: VerifiedAssignmentSignatureGrantV1,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let signature_bytes = u32::try_from(signature.canonical_signature.len())
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        if session.node() != intent.node()
            || session.lineage() != intent.selected_capability_lineage()
            || session.coordinator_epoch()
                != intent.selected_capability_binding().coordinator_epoch()
            || !session.is_current_at(verified_at_unix_seconds)
            || !authority.is_current_for(intent, session.lineage(), verified_at_unix_seconds)
            || authority.audience_digest() != session.audience_digest()
            || authority.carrier_frame_digest() != session.authenticated_frame_digest()
            || authority.context() != signature.context
            || signature.assignment_digest != intent.assignment_digest()
            || signature.lease_generation != authority.lease_generation()
            || signature.lease_digest != authority.lease_digest()
            || signature.verified_at_unix_seconds != verified_at_unix_seconds
            || signature.context.node() != session.node()
            || signature.context.lineage() != session.lineage()
            || signature.context.audience_digest() != session.audience_digest()
            || signature.context.disclosure_domain_digest() != session.disclosure_domain_digest()
            || signature.context.carrier_binding_digest() != session.binding_digest()
            || signature.context.canonical_frame_digest() != session.authenticated_frame_digest()
            || signature.context.canonical_frame_bytes() != session.authenticated_frame_bytes()
            || signature.context.coordinator_epoch() != session.coordinator_epoch()
            || signature.context.replay_fence() != session.replay_fence()
            || !signature.context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let peer_identity_digest = session.binding_digest();
        let valid_until_unix_seconds = session
            .valid_until_unix_seconds()
            .min(authority.valid_until_unix_seconds())
            .min(signature.context.valid_until_unix_seconds());
        let digest = assignment_carrier_digest(
            session.node(),
            session.lineage(),
            peer_identity_digest,
            session.audience_digest(),
            session.disclosure_domain_digest(),
            session.authenticated_frame_digest(),
            session.authenticated_frame_bytes(),
            session.coordinator_epoch(),
            intent.epoch(),
            intent.assignment_digest(),
            authority.lease_generation(),
            authority.lease_digest(),
            signature.signature_digest,
            signature_bytes,
            session.replay_fence(),
            verified_at_unix_seconds,
            valid_until_unix_seconds,
        );
        Ok(Self {
            node: session.node(),
            lineage: session.lineage(),
            peer_identity_digest,
            audience_digest: session.audience_digest(),
            disclosure_domain_digest: session.disclosure_domain_digest(),
            authenticated_frame_digest: session.authenticated_frame_digest(),
            authenticated_frame_bytes: session.authenticated_frame_bytes(),
            coordinator_epoch: session.coordinator_epoch(),
            assignment_epoch: intent.epoch(),
            assignment_digest: intent.assignment_digest(),
            lease_generation: authority.lease_generation(),
            lease_digest: authority.lease_digest(),
            signature_digest: signature.signature_digest,
            context: signature.context,
            replay_fence: session.replay_fence(),
            verified_at_unix_seconds,
            valid_until_unix_seconds,
            digest,
        })
    }

    pub(super) const fn node(&self) -> NodeId {
        self.node
    }

    pub(super) const fn lineage(&self) -> NodeBootLineageV1 {
        self.lineage
    }

    pub(super) const fn peer_identity_digest(&self) -> ObjectDigest {
        self.peer_identity_digest
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

    pub(super) const fn assignment_epoch(&self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    pub(super) const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    pub(super) const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    pub(super) const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    pub(super) const fn signature_digest(&self) -> ObjectDigest {
        self.signature_digest
    }

    pub(super) const fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }

    pub(super) const fn replay_fence(&self) -> ObjectDigest {
        self.replay_fence
    }

    pub(super) const fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }

    pub(super) const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(super) fn is_current_for(
        &self,
        intent: &AssignmentIntentV1,
        coordinator_unix_seconds: u64,
    ) -> bool {
        self.node == intent.node()
            && self.lineage == intent.selected_capability_lineage()
            && self.coordinator_epoch == intent.selected_capability_binding().coordinator_epoch()
            && self.assignment_epoch == intent.epoch()
            && self.assignment_digest == intent.assignment_digest()
            && coordinator_unix_seconds >= self.verified_at_unix_seconds
            && coordinator_unix_seconds <= self.valid_until_unix_seconds
    }

    pub(super) fn matches_assignment_and_lease_of(&self, prior: &Self) -> bool {
        self.node == prior.node
            && self.lineage == prior.lineage
            && self.peer_identity_digest == prior.peer_identity_digest
            && self.audience_digest == prior.audience_digest
            && self.disclosure_domain_digest == prior.disclosure_domain_digest
            && self.coordinator_epoch == prior.coordinator_epoch
            && self.assignment_epoch == prior.assignment_epoch
            && self.assignment_digest == prior.assignment_digest
            && self.lease_generation == prior.lease_generation
            && self.lease_digest == prior.lease_digest
    }
}

#[allow(clippy::too_many_arguments)]
fn assignment_carrier_digest(
    node: NodeId,
    lineage: NodeBootLineageV1,
    peer_identity_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    authenticated_frame_digest: ObjectDigest,
    authenticated_frame_bytes: u32,
    coordinator_epoch: u64,
    assignment_epoch: AssignmentEpoch,
    assignment_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    signature_digest: ObjectDigest,
    signature_bytes: u32,
    replay_fence: ObjectDigest,
    verified_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(ASSIGNMENT_CARRIER_DOMAIN);
    digest.update(node.as_bytes());
    digest.update(lineage.boot().as_bytes());
    digest.update(lineage.generation().to_be_bytes());
    digest.update(peer_identity_digest.as_bytes());
    digest.update(audience_digest.as_bytes());
    digest.update(disclosure_domain_digest.as_bytes());
    digest.update(authenticated_frame_digest.as_bytes());
    digest.update(authenticated_frame_bytes.to_be_bytes());
    digest.update(coordinator_epoch.to_be_bytes());
    digest.update(assignment_epoch.get().to_be_bytes());
    digest.update(assignment_digest.as_bytes());
    digest.update(lease_generation.to_be_bytes());
    digest.update(lease_digest.as_bytes());
    digest.update(signature_digest.as_bytes());
    digest.update(signature_bytes.to_be_bytes());
    digest.update(replay_fence.as_bytes());
    digest.update(verified_at_unix_seconds.to_be_bytes());
    digest.update(valid_until_unix_seconds.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

/// Represents the only carrier verifier admitted by this source partition.
///
/// A transport integration is implemented as a child of this authority module
/// and receives a constructor there after verifying its real channel.
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
    pub(super) const fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }

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

fn issue_generated_response_once(
    session: AuthenticatedNodeSessionV1,
    kind: super::protocol::CanonicalNodeFrameKindV1,
    body_digest: ObjectDigest,
    carrier_digest: ObjectDigest,
    carrier_bytes: u32,
    verified_at_unix_seconds: u64,
) -> Result<CarrierResponseGrantV1, InvalidMultiNodeProtocol> {
    if body_digest.as_bytes() == &[0; 32]
        || carrier_digest.as_bytes() == &[0; 32]
        || carrier_bytes == 0
        || carrier_bytes > session.maximum_response_bytes()
    {
        return Err(InvalidMultiNodeProtocol::SessionMismatch);
    }
    let context = issue_evidence_once(
        &session,
        carrier_digest,
        carrier_bytes,
        verified_at_unix_seconds,
    )
    .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
    let replay_fence = session.replay_fence();
    Ok(CarrierResponseGrantV1 {
        session,
        context,
        frame_seal: AuthenticatedFrameSealV1 {
            kind,
            body_digest,
            frame_digest: carrier_digest,
            frame_bytes: carrier_bytes,
            replay_fence,
        },
    })
}

/// Core-owned dormant transport bridge backed by protected expected identities.
mod protected_integration {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    pub(super) fn issue_context_from_protected_bootstrap(
        node: NodeId,
        lineage: NodeBootLineageV1,
        authenticated_channel_binding: [u8; 32],
        frame: &CanonicalNodeFrameV1<'_>,
        coordinator_epoch: u64,
        authenticated_at_unix_seconds: u64,
        current_unix_seconds: u64,
        valid_until_unix_seconds: u64,
        maximum_request_bytes: u32,
        maximum_response_bytes: u32,
        replay_fence: ObjectDigest,
        signed_bootstrap_payload: &[u8],
        canonical_signature: &[u8],
        canonical_trust_policy: &[u8],
        public_key: &[u8; 32],
    ) -> Result<AuthenticatedEvidenceContextV1, InvalidMultiNodeProtocol> {
        let canonical_frame_bytes = u32::try_from(frame.bytes().len())
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        if protected_carrier_binding_digest(authenticated_channel_binding) != frame.binding_digest()
            || authenticated_channel_binding != *public_key
            || ObjectDigest::from_bytes(Sha256::digest(frame.bytes()).into())
                != frame.frame_digest()
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        verify_protected_carrier_signature(
            signed_bootstrap_payload,
            canonical_signature,
            canonical_trust_policy,
            public_key,
            current_unix_seconds,
        )?;
        let authority = CarrierVerifierSessionV1::from_verified_transport(
            node,
            lineage,
            authenticated_channel_binding,
            frame.audience_digest(),
            frame.disclosure_domain_digest(),
            frame.frame_digest(),
            canonical_frame_bytes,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            frame.version(),
            maximum_request_bytes,
            maximum_response_bytes,
            replay_fence,
        )?;
        let session = issue_node_session_once(authority)?;
        if !session.is_current_at(current_unix_seconds) {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        issue_evidence_once(
            &session,
            frame.frame_digest(),
            canonical_frame_bytes,
            authenticated_at_unix_seconds,
        )
        .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)
    }

    pub(super) fn issue_session_from_protected_channel(
        protected_expected: &ProtectedJournalRecordV1,
        frame: &CanonicalNodeFrameV1<'_>,
        authenticated_channel_binding: [u8; 32],
        maximum_request_bytes: u32,
        maximum_response_bytes: u32,
        verified_at_unix_seconds: u64,
    ) -> Result<AuthenticatedNodeSessionV1, InvalidMultiNodeProtocol> {
        let context = protected_expected.context();
        let canonical_frame_bytes = u32::try_from(frame.bytes().len())
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        if protected_expected.replay_fence() != context.replay_fence()
            || protected_carrier_binding_digest(authenticated_channel_binding)
                != context.carrier_binding_digest()
            || ObjectDigest::from_bytes(Sha256::digest(frame.bytes()).into())
                != frame.frame_digest()
            || frame.frame_digest() != context.canonical_frame_digest()
            || canonical_frame_bytes != context.canonical_frame_bytes()
            || frame.binding_digest() != context.carrier_binding_digest()
            || frame.audience_digest() != context.audience_digest()
            || frame.disclosure_domain_digest() != context.disclosure_domain_digest()
            || !context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let authority = CarrierVerifierSessionV1::from_verified_transport(
            context.node(),
            context.lineage(),
            authenticated_channel_binding,
            context.audience_digest(),
            context.disclosure_domain_digest(),
            context.canonical_frame_digest(),
            context.canonical_frame_bytes(),
            context.coordinator_epoch(),
            context.verified_at_unix_seconds(),
            context.valid_until_unix_seconds(),
            frame.version(),
            maximum_request_bytes,
            maximum_response_bytes,
            context.replay_fence(),
        )?;
        issue_node_session_once(authority)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn verify_assignment_contract_from_protected_channel(
        session: &AuthenticatedNodeSessionV1,
        protected_expected: &ProtectedJournalRecordV1,
        intent: &AssignmentIntentV1,
        authority: VerifiedAssignmentAuthorityV1,
        canonical_signature: &[u8],
        canonical_trust_policy: &[u8],
        public_key: &[u8; 32],
        verified_at_unix_seconds: u64,
    ) -> Result<AuthenticatedAssignmentCarrierContractV1, InvalidMultiNodeProtocol> {
        let context = protected_expected.context();
        let limits = assignment_signature_decode_limits();
        if canonical_signature.is_empty()
            || canonical_signature.len() > MAXIMUM_ASSIGNMENT_SIGNATURE_BYTES
            || canonical_trust_policy.is_empty()
            || canonical_trust_policy.len() > MAXIMUM_ASSIGNMENT_SIGNATURE_BYTES
            || session.binding() != *public_key
            || protected_carrier_binding_digest(*public_key) != context.carrier_binding_digest()
            || session.node() != context.node()
            || session.lineage() != context.lineage()
            || session.audience_digest() != context.audience_digest()
            || session.disclosure_domain_digest() != context.disclosure_domain_digest()
            || session.authenticated_frame_digest() != context.canonical_frame_digest()
            || session.authenticated_frame_bytes() != context.canonical_frame_bytes()
            || !session.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }

        let signature = decode_signature(canonical_signature, limits)
            .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
        if encode_signature(&signature).as_slice() != canonical_signature
            || signature.statement().purpose() != SignaturePurpose::Distribution
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let signed_payload = assignment_signature_payload(session, intent, authority, context);
        let media_type = MediaType::new(PortableMediaType::Content.as_str())
            .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
        let expected_subject = descriptor_for_bytes(media_type, &signed_payload);
        if signature.statement().subject() != &expected_subject {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let verified_at = i64::try_from(verified_at_unix_seconds)
            .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
        let verified = verify_signature(
            &signature,
            canonical_trust_policy,
            public_key,
            verified_at,
            limits,
        )
        .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
        if verified.subject() != &expected_subject {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }

        let signature_grant = VerifiedAssignmentSignatureGrantV1::from_verified_signature(
            intent.assignment_digest(),
            authority.lease_generation(),
            authority.lease_digest(),
            canonical_signature.to_vec(),
            context,
            verified_at_unix_seconds,
        )?;
        AuthenticatedAssignmentCarrierContractV1::from_verified_assignment(
            session,
            intent,
            authority,
            signature_grant,
            verified_at_unix_seconds,
        )
    }

    pub(super) fn issue_response_from_protected_channel(
        session: AuthenticatedNodeSessionV1,
        protected_expected: &ProtectedJournalRecordV1,
        frame: &CanonicalNodeFrameV1<'_>,
        verified_at_unix_seconds: u64,
    ) -> Result<CarrierResponseGrantV1, InvalidMultiNodeProtocol> {
        let context = protected_expected.context();
        if context.node() != session.node()
            || context.lineage() != session.lineage()
            || context.carrier_binding_digest() != session.binding_digest()
            || context.audience_digest() != session.audience_digest()
            || context.disclosure_domain_digest() != session.disclosure_domain_digest()
            || context.coordinator_epoch() != session.coordinator_epoch()
            || context.replay_fence() != session.replay_fence()
            || protected_expected.replay_fence() != session.replay_fence()
            || frame.frame_digest() != context.canonical_frame_digest()
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        issue_response_once(session, frame, verified_at_unix_seconds)
    }
}

pub(super) use protected_integration::{
    issue_context_from_protected_bootstrap, issue_response_from_protected_channel,
    issue_session_from_protected_channel, verify_assignment_contract_from_protected_channel,
};

fn protected_carrier_binding_digest(binding: [u8; 32]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.coordinator-node.carrier-binding.v1\0")
            .chain_update(binding)
            .finalize()
            .into(),
    )
}

fn assignment_signature_decode_limits() -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: MAXIMUM_ASSIGNMENT_SIGNATURE_BYTES,
        maximum_collection_items: 128,
        maximum_total_items: 512,
        maximum_byte_string_bytes: MAXIMUM_ASSIGNMENT_SIGNATURE_BYTES,
        maximum_text_bytes: 1024,
        maximum_depth: 16,
    }
}

fn verify_protected_carrier_signature(
    signed_payload: &[u8],
    canonical_signature: &[u8],
    canonical_trust_policy: &[u8],
    public_key: &[u8; 32],
    verified_at_unix_seconds: u64,
) -> Result<(), InvalidMultiNodeProtocol> {
    let limits = assignment_signature_decode_limits();
    if signed_payload.is_empty()
        || canonical_signature.is_empty()
        || canonical_signature.len() > MAXIMUM_ASSIGNMENT_SIGNATURE_BYTES
        || canonical_trust_policy.is_empty()
        || canonical_trust_policy.len() > MAXIMUM_ASSIGNMENT_SIGNATURE_BYTES
    {
        return Err(InvalidMultiNodeProtocol::SessionMismatch);
    }
    let signature = decode_signature(canonical_signature, limits)
        .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
    let media_type = MediaType::new(PortableMediaType::Content.as_str())
        .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
    let expected_subject = descriptor_for_bytes(media_type, signed_payload);
    if encode_signature(&signature).as_slice() != canonical_signature
        || signature.statement().purpose() != SignaturePurpose::Distribution
        || signature.statement().subject() != &expected_subject
    {
        return Err(InvalidMultiNodeProtocol::SessionMismatch);
    }
    let verified_at = i64::try_from(verified_at_unix_seconds)
        .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
    let verified = verify_signature(
        &signature,
        canonical_trust_policy,
        public_key,
        verified_at,
        limits,
    )
    .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
    if verified.subject() != &expected_subject {
        return Err(InvalidMultiNodeProtocol::SessionMismatch);
    }
    Ok(())
}

fn assignment_signature_payload(
    session: &AuthenticatedNodeSessionV1,
    intent: &AssignmentIntentV1,
    authority: VerifiedAssignmentAuthorityV1,
    context: AuthenticatedEvidenceContextV1,
) -> Vec<u8> {
    let guardian_state = match authority.guardian_state() {
        super::assignment::VerifiedGuardianStateV1::Armed => 1,
        super::assignment::VerifiedGuardianStateV1::Contained => 2,
        super::assignment::VerifiedGuardianStateV1::ExpiredAndContained => 3,
    };
    let mut bytes = Vec::with_capacity(320);
    bytes.extend_from_slice(b"AOSMAS01");
    bytes.extend_from_slice(session.binding().as_slice());
    bytes.extend_from_slice(intent.node().as_bytes());
    bytes.extend_from_slice(intent.selected_capability_lineage().boot().as_bytes());
    bytes.extend_from_slice(
        &intent
            .selected_capability_lineage()
            .generation()
            .to_be_bytes(),
    );
    bytes.extend_from_slice(intent.sandbox().as_bytes());
    bytes.extend_from_slice(intent.incarnation().as_bytes());
    bytes.extend_from_slice(&intent.epoch().get().to_be_bytes());
    bytes.extend_from_slice(&intent.desired_generation().get().to_be_bytes());
    bytes.extend_from_slice(intent.assignment_digest().as_bytes());
    bytes.extend_from_slice(&authority.lease_generation().to_be_bytes());
    bytes.extend_from_slice(authority.lease_digest().as_bytes());
    bytes.extend_from_slice(authority.guardian_digest().as_bytes());
    bytes.push(guardian_state);
    bytes.extend_from_slice(context.audience_digest().as_bytes());
    bytes.extend_from_slice(context.disclosure_domain_digest().as_bytes());
    bytes.extend_from_slice(context.canonical_frame_digest().as_bytes());
    bytes.extend_from_slice(context.replay_fence().as_bytes());
    bytes.extend_from_slice(&context.coordinator_epoch().to_be_bytes());
    bytes.extend_from_slice(&context.verified_at_unix_seconds().to_be_bytes());
    bytes.extend_from_slice(&context.valid_until_unix_seconds().to_be_bytes());
    bytes
}
