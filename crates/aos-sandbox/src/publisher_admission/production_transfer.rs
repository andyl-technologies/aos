//! Signed, role-separated transfer of existing local publisher responses.
//!
//! ```text
//! AOSPLT01 | kind:u8 | scope-digest[32] | local-length:u32be
//!          | canonical AOSPLP02 message | Ed25519 signature[64]
//! ```
//!
//! This is a transport-authentication contract, not a publication or read
//! capability. The receiving process must derive the expected scope from its
//! protected current state, authenticate the inner plan where applicable, and
//! retain the existing ledger, root, and read-grant checks before any effect.

use aos_sandbox_core::format::encode_publisher_admission_request_v1;
use aos_sandbox_core::{
    ChannelBinding, ObjectDigest, PublisherAdmissionRequestV1, PublisherInstanceId,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::{
    PublisherLocalBodyV1, PublisherLocalMessageV1, ReadAuthorityGrantV1, decode_local_message_v1,
    encode_local_message_v1,
};

const MAGIC: &[u8; 8] = b"AOSPLT01";
const HEADER_BYTES: usize = 45;
const SIGNATURE_BYTES: usize = 64;
const MAXIMUM_LOCAL_BYTES: usize = 1024 * 1024 + 64;
const PUBLICATION_SCOPE_DOMAIN: &[u8] = b"aos.sandbox.publisher.transfer-publication.v1\0";
const READ_SCOPE_DOMAIN: &[u8] = b"aos.sandbox.publisher.transfer-read.v1\0";

/// Selects the only authority-bearing AOSPLP02 response roles admitted here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublisherTransferKindV1 {
    /// Returns one exact controller-signed admission plan.
    Admission = 1,
    /// Returns one exact retained completion permit commitment.
    CompletionPermit = 2,
    /// Returns one independently revocable read-grant commitment.
    ReadGrant = 3,
}

impl PublisherTransferKindV1 {
    fn matches(self, body: &PublisherLocalBodyV1) -> bool {
        matches!(
            (self, body),
            (
                Self::Admission,
                PublisherLocalBodyV1::AdmissionResult { .. }
            ) | (
                Self::CompletionPermit,
                PublisherLocalBodyV1::CompletionPermit { .. }
            ) | (
                Self::ReadGrant,
                PublisherLocalBodyV1::ReadGrantResult { .. }
            )
        )
    }
}

/// Binds a transfer to independently rechecked publication or read facts.
///
/// The digest is inert by itself. A receiver must reconstruct it from a fresh
/// authenticated publisher execution and protected holder or read-grant state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherTransferScopeV1 {
    digest: ObjectDigest,
    read_grant: bool,
}

impl PublisherTransferScopeV1 {
    /// Commits the complete challenge-bound request and live publisher channel.
    ///
    /// The canonical request includes project, holder channel, operation,
    /// descriptor, source authorization, reservation, and challenge. The caller
    /// must have obtained it from a current protected two-channel join.
    ///
    /// # Errors
    ///
    /// Rejects an unspecified publisher channel or oversized request.
    pub fn publication(
        request: &PublisherAdmissionRequestV1,
        publisher_channel: ChannelBinding,
    ) -> Result<Self, PublisherTransferErrorV1> {
        if publisher_channel.as_bytes() == &[0; 32] {
            return Err(PublisherTransferErrorV1::Scope);
        }
        let canonical = encode_publisher_admission_request_v1(request);
        if canonical.len() > aos_sandbox_core::publisher::MAXIMUM_PUBLISHER_ADMISSION_REQUEST_BYTES
        {
            return Err(PublisherTransferErrorV1::Scope);
        }
        Ok(Self {
            digest: hash_scope(PUBLICATION_SCOPE_DOMAIN, &canonical, publisher_channel),
            read_grant: false,
        })
    }

    /// Commits one current project read grant and live publisher channel.
    ///
    /// # Errors
    ///
    /// Rejects an unspecified execution, channel, or inactive grant.
    pub fn read_grant(
        grant: &ReadAuthorityGrantV1,
        publisher_instance: PublisherInstanceId,
        publisher_channel: ChannelBinding,
    ) -> Result<Self, PublisherTransferErrorV1> {
        grant
            .validate()
            .map_err(|_| PublisherTransferErrorV1::Scope)?;
        if publisher_instance.as_bytes() == &[0; 16]
            || publisher_channel.as_bytes() == &[0; 32]
            || grant.state != super::ReadGrantStateV1::Active
            || grant.generation != 1
        {
            return Err(PublisherTransferErrorV1::Scope);
        }
        let mut facts = Vec::with_capacity(16 + 16 + 16 + 16 + 32 + 8 + 32);
        facts.extend_from_slice(publisher_instance.as_bytes());
        facts.extend_from_slice(grant.holder.as_bytes());
        facts.extend_from_slice(grant.project.as_bytes());
        facts.extend_from_slice(grant.resource.as_bytes());
        facts.extend_from_slice(grant.domain.domain_id().as_bytes());
        facts.extend_from_slice(grant.policy_digest.as_bytes());
        facts.extend_from_slice(&grant.generation.to_be_bytes());
        facts.extend_from_slice(grant.grant_digest.as_bytes());
        Ok(Self {
            digest: hash_scope(READ_SCOPE_DOMAIN, &facts, publisher_channel),
            read_grant: true,
        })
    }
}

fn hash_scope(domain: &[u8], facts: &[u8], channel: ChannelBinding) -> ObjectDigest {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((facts.len() as u64).to_be_bytes());
    hash.update(facts);
    hash.update(channel.as_bytes());
    ObjectDigest::from_bytes(hash.finalize().into())
}

/// Freezes one bounded response for signing by a protected controller signer.
///
/// Construction does not establish the provenance of `scope` or authorize an
/// effect. Only the receiving process can compare it with fresh protected facts.
pub struct PublisherTransferStatementV1 {
    signing_bytes: Vec<u8>,
}

impl PublisherTransferStatementV1 {
    /// Canonicalizes one descriptor-free AOSPLP02 authority response.
    ///
    /// # Errors
    ///
    /// Rejects a wrong role, malformed body, invalid scope class, or byte bound.
    pub fn new(
        kind: PublisherTransferKindV1,
        scope: PublisherTransferScopeV1,
        request_id: [u8; 16],
        body: &PublisherLocalBodyV1,
    ) -> Result<Self, PublisherTransferErrorV1> {
        if !kind.matches(body) || (kind == PublisherTransferKindV1::ReadGrant) != scope.read_grant {
            return Err(PublisherTransferErrorV1::Role);
        }
        let local = encode_local_message_v1(request_id, body)
            .map_err(|_| PublisherTransferErrorV1::LocalMessage)?;
        if local.len() > MAXIMUM_LOCAL_BYTES {
            return Err(PublisherTransferErrorV1::Bound);
        }
        let length = u32::try_from(local.len()).map_err(|_| PublisherTransferErrorV1::Bound)?;
        let mut signing_bytes = Vec::with_capacity(HEADER_BYTES + local.len());
        signing_bytes.extend_from_slice(MAGIC);
        signing_bytes.push(kind as u8);
        signing_bytes.extend_from_slice(scope.digest.as_bytes());
        signing_bytes.extend_from_slice(&length.to_be_bytes());
        signing_bytes.extend_from_slice(&local);
        Ok(Self { signing_bytes })
    }

    /// Returns the exact domain-separated bytes for a protected Ed25519 signer.
    #[must_use]
    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }

    /// Attaches a detached signature without asserting its provenance.
    #[must_use]
    pub fn attach_signature(mut self, signature: [u8; SIGNATURE_BYTES]) -> Vec<u8> {
        self.signing_bytes.extend_from_slice(&signature);
        self.signing_bytes
    }
}

/// Proves static signature and exact local-response binding only.
///
/// It is deliberately non-cloneable and cannot be converted into a publisher
/// physical-effect capability or an independently current read grant.
pub struct PublisherSignedTransferV1 {
    message: PublisherLocalMessageV1,
}

impl PublisherSignedTransferV1 {
    /// Verifies one transfer against independently reconstructed exact facts.
    ///
    /// `expected_body` must come from the protected decision, permit, or grant,
    /// not from the received message. Admission callers must additionally verify
    /// its nested signed plan with `verify_publisher_domain_plan`.
    ///
    /// # Errors
    ///
    /// Rejects framing, role, scope, local-message, semantic, or signature
    /// substitution before returning the inert authenticated response.
    pub fn verify(
        bytes: &[u8],
        kind: PublisherTransferKindV1,
        scope: PublisherTransferScopeV1,
        expected_request_id: [u8; 16],
        expected_body: &PublisherLocalBodyV1,
        trusted_controller_key: &VerifyingKey,
    ) -> Result<Self, PublisherTransferErrorV1> {
        if bytes.len() < HEADER_BYTES + SIGNATURE_BYTES
            || bytes.len() > HEADER_BYTES + MAXIMUM_LOCAL_BYTES + SIGNATURE_BYTES
            || &bytes[..8] != MAGIC
            || bytes[8] != kind as u8
            || bytes[9..41] != *scope.digest.as_bytes()
            || !kind.matches(expected_body)
            || (kind == PublisherTransferKindV1::ReadGrant) != scope.read_grant
        {
            return Err(PublisherTransferErrorV1::Role);
        }
        let length = u32::from_be_bytes(
            bytes[41..45]
                .try_into()
                .map_err(|_| PublisherTransferErrorV1::Bound)?,
        ) as usize;
        if length > MAXIMUM_LOCAL_BYTES
            || HEADER_BYTES
                .checked_add(length)
                .and_then(|n| n.checked_add(SIGNATURE_BYTES))
                != Some(bytes.len())
        {
            return Err(PublisherTransferErrorV1::Bound);
        }
        let message = decode_local_message_v1(&bytes[HEADER_BYTES..HEADER_BYTES + length], &[])
            .map_err(|_| PublisherTransferErrorV1::LocalMessage)?;
        if message.request_id != expected_request_id
            || message.body != *expected_body
            || !kind.matches(&message.body)
        {
            return Err(PublisherTransferErrorV1::Role);
        }
        let signature = Signature::from_slice(&bytes[HEADER_BYTES + length..])
            .map_err(|_| PublisherTransferErrorV1::Signature)?;
        trusted_controller_key
            .verify_strict(&bytes[..HEADER_BYTES + length], &signature)
            .map_err(|_| PublisherTransferErrorV1::Signature)?;
        Ok(Self { message })
    }

    /// Borrows the exact authenticated local response without granting its effect.
    #[must_use]
    pub const fn message(&self) -> &PublisherLocalMessageV1 {
        &self.message
    }
}

/// Reports an invalid static publisher authority transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublisherTransferErrorV1 {
    /// Protected scope inputs are absent or incompatible.
    #[error("publisher transfer scope is invalid")]
    Scope,
    /// A response method or exact expected semantics differs.
    #[error("publisher transfer response role differs")]
    Role,
    /// Transfer length or allocation bound differs.
    #[error("publisher transfer exceeds its bound")]
    Bound,
    /// Nested AOSPLP02 message is malformed or noncanonical.
    #[error("publisher local response is invalid")]
    LocalMessage,
    /// Detached controller signature is invalid.
    #[error("publisher transfer signature is invalid")]
    Signature,
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::model::{CacheDomain, CacheDomainKind};
    use aos_sandbox_core::{
        CacheDomainId, MediaType, NodeId, ObjectDescriptor, OperationId, PortableMediaType,
        PrincipalId, ProjectId, ProtocolVersion, PublicationReservationId,
        PublisherAdmissionClaimV1, PublisherAdmissionRequestDraftV1, PublisherAuthorityBindings,
        PublisherChallengeV1, PublisherTarget, ResourceId, RevocationScopeId,
    };
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn read_grant() -> ReadAuthorityGrantV1 {
        ReadAuthorityGrantV1::active(
            PrincipalId::from_bytes([1; 16]),
            ProjectId::from_bytes([2; 16]),
            ResourceId::from_bytes([3; 16]),
            CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([4; 16])),
            ObjectDigest::from_bytes([5; 32]),
            1,
        )
        .unwrap()
    }

    fn publication_request(challenge: u8) -> PublisherAdmissionRequestV1 {
        PublisherAdmissionRequestV1::new(PublisherAdmissionRequestDraftV1 {
            capability: aos_sandbox_core::CapabilityId::from_bytes([11; 16]),
            cache_resource: ResourceId::from_bytes([3; 16]),
            challenge: PublisherChallengeV1::from_bytes([challenge; 32]).unwrap(),
            protocol_version: ProtocolVersion::new(1, 0),
            target: PublisherTarget {
                principal: PrincipalId::from_bytes([1; 16]),
                instance: PublisherInstanceId::from_bytes([6; 16]),
                node: NodeId::from_bytes([12; 16]),
                project: ProjectId::from_bytes([2; 16]),
                cache_domain: CacheDomain::new(
                    CacheDomainKind::Project,
                    CacheDomainId::from_bytes([4; 16]),
                ),
                isolation_policy: ObjectDigest::from_bytes([13; 32]),
            },
            claim: PublisherAdmissionClaimV1 {
                holder: PrincipalId::from_bytes([14; 16]),
                channel: ChannelBinding::new([15; 32]),
                operation: OperationId::from_bytes([16; 16]),
                reservation: PublicationReservationId::from_bytes([17; 16]),
                content: ObjectDescriptor::new(
                    MediaType::new(PortableMediaType::Content.as_str().to_owned()).unwrap(),
                    ObjectDigest::from_bytes([18; 32]),
                    64,
                ),
                source_authorization: ObjectDigest::from_bytes([19; 32]),
                maximum_bytes: 64,
            },
            authority: PublisherAuthorityBindings {
                policy: ObjectDigest::from_bytes([20; 32]),
                policy_generation: 1,
                controller_generation: 1,
                revocation_scope: RevocationScopeId::from_bytes([21; 16]),
                revocation_generation: 1,
                root_registry_generation: 1,
            },
            issued_seconds: 10,
            expires_seconds: 20,
            required_features: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn signed_completion_transfer_binds_original_challenge_and_channel() {
        let request = publication_request(22);
        let channel = ChannelBinding::new([23; 32]);
        let scope = PublisherTransferScopeV1::publication(&request, channel).unwrap();
        let body = PublisherLocalBodyV1::CompletionPermit {
            operation: request.plan().fields().request.operation,
            permit: super::super::PublicationPermitId::from_bytes([24; 16]).unwrap(),
            permit_digest: ObjectDigest::from_bytes([24; 32]),
        };
        let statement = PublisherTransferStatementV1::new(
            PublisherTransferKindV1::CompletionPermit,
            scope,
            [25; 16],
            &body,
        )
        .unwrap();
        let signer = SigningKey::from_bytes(&[26; 32]);
        let signature = signer.sign(statement.signing_bytes()).to_bytes();
        let encoded = statement.attach_signature(signature);
        assert!(
            PublisherSignedTransferV1::verify(
                &encoded,
                PublisherTransferKindV1::CompletionPermit,
                scope,
                [25; 16],
                &body,
                &signer.verifying_key(),
            )
            .is_ok()
        );

        let changed_challenge =
            PublisherTransferScopeV1::publication(&publication_request(27), channel).unwrap();
        let changed_channel =
            PublisherTransferScopeV1::publication(&request, ChannelBinding::new([28; 32])).unwrap();
        for changed in [changed_challenge, changed_channel] {
            assert!(matches!(
                PublisherSignedTransferV1::verify(
                    &encoded,
                    PublisherTransferKindV1::CompletionPermit,
                    changed,
                    [25; 16],
                    &body,
                    &signer.verifying_key(),
                ),
                Err(PublisherTransferErrorV1::Role)
            ));
        }
    }

    #[test]
    fn signed_read_grant_transfer_binds_exact_scope_and_body() {
        let grant = read_grant();
        let instance = PublisherInstanceId::from_bytes([6; 16]);
        let channel = ChannelBinding::new([7; 32]);
        let scope = PublisherTransferScopeV1::read_grant(&grant, instance, channel).unwrap();
        let body = PublisherLocalBodyV1::ReadGrantResult {
            publisher_instance: instance,
            grant_digest: grant.grant_digest,
        };
        let statement = PublisherTransferStatementV1::new(
            PublisherTransferKindV1::ReadGrant,
            scope,
            [8; 16],
            &body,
        )
        .unwrap();
        let signer = SigningKey::from_bytes(&[9; 32]);
        let signature = signer.sign(statement.signing_bytes()).to_bytes();
        let encoded = statement.attach_signature(signature);

        let verified = PublisherSignedTransferV1::verify(
            &encoded,
            PublisherTransferKindV1::ReadGrant,
            scope,
            [8; 16],
            &body,
            &signer.verifying_key(),
        )
        .unwrap();
        assert_eq!(verified.message().body, body);

        let changed_channel =
            PublisherTransferScopeV1::read_grant(&grant, instance, ChannelBinding::new([10; 32]))
                .unwrap();
        assert!(matches!(
            PublisherSignedTransferV1::verify(
                &encoded,
                PublisherTransferKindV1::ReadGrant,
                changed_channel,
                [8; 16],
                &body,
                &signer.verifying_key(),
            ),
            Err(PublisherTransferErrorV1::Role)
        ));
        let mut changed_grant = grant.clone();
        changed_grant.state = super::super::ReadGrantStateV1::Revoked;
        assert_eq!(
            PublisherTransferScopeV1::read_grant(&changed_grant, instance, channel),
            Err(PublisherTransferErrorV1::Scope)
        );
    }

    #[test]
    fn transfer_rejects_wrong_role_and_signature_substitution() {
        let grant = read_grant();
        let instance = PublisherInstanceId::from_bytes([6; 16]);
        let scope =
            PublisherTransferScopeV1::read_grant(&grant, instance, ChannelBinding::new([7; 32]))
                .unwrap();
        let body = PublisherLocalBodyV1::ReadGrantResult {
            publisher_instance: instance,
            grant_digest: grant.grant_digest,
        };
        assert!(matches!(
            PublisherTransferStatementV1::new(
                PublisherTransferKindV1::CompletionPermit,
                scope,
                [8; 16],
                &body,
            ),
            Err(PublisherTransferErrorV1::Role)
        ));

        let statement = PublisherTransferStatementV1::new(
            PublisherTransferKindV1::ReadGrant,
            scope,
            [8; 16],
            &body,
        )
        .unwrap();
        let signer = SigningKey::from_bytes(&[9; 32]);
        let signature = signer.sign(statement.signing_bytes()).to_bytes();
        let mut encoded = statement.attach_signature(signature);
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert!(matches!(
            PublisherSignedTransferV1::verify(
                &encoded,
                PublisherTransferKindV1::ReadGrant,
                scope,
                [8; 16],
                &body,
                &signer.verifying_key(),
            ),
            Err(PublisherTransferErrorV1::Signature)
        ));
    }
}
