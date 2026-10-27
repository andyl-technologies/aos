//! Canonical Publisher administrative signatures and public issuer DATA.
//!
//! A privileged administrative signer, distinct from the Controller seed
//! signer, may assert seven initial-tree limits against one current protected
//! publisher head. Packet verification alone does not install credentials,
//! retain the packet, spend an epoch, or authorize a Source journal append.
//!
//! ```text
//! AOSPSC02 | version:u16be | reserved:u16be | signer-generation:u64be |
//! project:16 | publisher-generation:u64be | AOSPOLH1 digest:32 |
//! AOSPOLR1 digest:32 | request-id:16 | issuer-epoch:u64be |
//! seven TreeLimitsV1 ceilings:u32be each | Ed25519 signature:64
//! AOSPSC03 uses the same claims, followed by 22 resource ceilings:u64be
//! in ResourceDimension::ALL order, then the signature (336 + 64 bytes).
//!
//! AOSPAK02 | signer-generation:u64be | Ed25519 public key:32 |
//! SHA-256(key-domain || preceding 48 bytes):32
//! ```

use aos_sandbox_model::source_tree_model::TreeLimitsV1;
use aos_sandbox_model::{ObjectDigest, ProjectId, ResourceDimension, ResourceVector};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::source_project_authorization::{
    PROJECT_AUTHORIZATION_SOURCE_BODY_BYTES_V2 as BODY_BYTES,
    PROJECT_AUTHORIZATION_SOURCE_BODY_BYTES_V3 as BODY_BYTES_V3,
    PROJECT_AUTHORIZATION_SOURCE_BYTES_V3,
    ProjectAuthorizationSourceDataErrorV2, UnverifiedProjectAuthorizationClaimsV2,
    packet_body_bytes, parse_unverified_project_authorization_claims_v2,
};
use crate::role_credential::{
    ROLE_CREDENTIAL_BYTES, decode_role_credential, encode_role_credential,
};

const KEY_MAGIC: &[u8; 8] = b"AOSPAK02";
const KEY_BYTES: usize = ROLE_CREDENTIAL_BYTES;
const SIGNING_DOMAIN: &[u8] =
    b"aos.sandbox.publisher-project-authorization-source.v2\0/var/lib/aos/sandboxd/controller.journal\0";
const SIGNING_DOMAIN_V3: &[u8] =
    b"aos.sandbox.publisher-project-authorization-source.v3\0/var/lib/aos/sandboxd/controller.journal\0";
const KEY_DOMAIN: &[u8] = b"aos.sandbox.publisher-project-authorization-verifier.v2\0";

/// Domain of the canonical Publisher current-head comparison digest.
pub const HEAD_DOMAIN: &[u8] =
    b"aos.sandbox.publisher-project-authorization.current-head.v2\0";

/// Domain of the canonical immutable Publisher revision comparison digest.
pub const REVISION_DOMAIN: &[u8] =
    b"aos.sandbox.publisher-project-authorization.current-revision.v2\0";

/// Reports an invalid or stale portable project authorization signature.
#[derive(Debug, Error)]
pub enum ProjectAuthorizationSignatureErrorV2 {
    /// A source packet, issuer credential, or tree limit is noncanonical.
    #[error("invalid project authorization source")]
    NonCanonical,
    /// The packet names another pinned issuer generation.
    #[error("project authorization source is stale")]
    Stale,
    /// The pinned issuer did not sign these exact source bytes.
    #[error("project authorization source signature is invalid")]
    Signature,
}

impl From<ProjectAuthorizationSourceDataErrorV2> for ProjectAuthorizationSignatureErrorV2 {
    fn from(error: ProjectAuthorizationSourceDataErrorV2) -> Self {
        match error {
            ProjectAuthorizationSourceDataErrorV2::NonCanonical => Self::NonCanonical,
        }
    }
}

/// Holds a public-only, independently provisioned project issuer pin.
///
/// Decoding this credential does not install it as a trust root. Its bytes
/// must come from privileged deployment configuration, never the packet.
pub struct PinnedPublisherProjectAuthorizationIssuerV2 {
    generation: u64,
    key: VerifyingKey,
}

impl PinnedPublisherProjectAuthorizationIssuerV2 {
    /// Decodes the role-specific public verifier credential.
    ///
    /// # Errors
    ///
    /// Rejects a foreign role, malformed key, zero generation, or alteration.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProjectAuthorizationSignatureErrorV2> {
        let (generation, key) = decode_role_credential(bytes, KEY_MAGIC, KEY_DOMAIN)
            .ok_or(ProjectAuthorizationSignatureErrorV2::NonCanonical)?;
        Ok(Self { generation, key })
    }

    /// Returns the externally pinned signer generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the role-specific public key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

/// Encodes a public-only project issuer credential for offline provisioning.
///
/// This does not install an issuer or permit Source-tree creation.
///
/// # Errors
///
/// Rejects generation zero.
pub fn encode_project_authorization_issuer_credential_v2(
    generation: u64,
    key: &VerifyingKey,
) -> Result<[u8; KEY_BYTES], ProjectAuthorizationSignatureErrorV2> {
    encode_role_credential(generation, key, KEY_MAGIC, KEY_DOMAIN)
        .ok_or(ProjectAuthorizationSignatureErrorV2::NonCanonical)
}

/// Describes an offline administrative statement with an explicit full budget.
///
/// These values are DATA until the existing issuer signature and current
/// publisher, epoch and owner joins are verified. No Node ceiling is inherited.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectResourceAuthorizationClaimsV3 {
    /// Identifies the project selected by the administrative signer.
    pub project: ProjectId,
    /// Retains the independent administrative issuer generation.
    pub issuer_generation: u64,
    /// Identifies the existing publisher revision generation.
    pub publisher_generation: u64,
    /// Commits to the exact existing protected publisher pointer.
    pub publisher_head: ObjectDigest,
    /// Commits to the exact existing immutable publisher revision.
    pub publisher_revision: ObjectDigest,
    /// Correlates the administrative request and matching seed.
    pub request_id: [u8; 16],
    /// Carries the administrative epoch, which retention must spend once.
    pub epoch: u64,
    /// Carries the same seven independent initial-tree ceilings as PSC02.
    pub tree_limits: TreeLimitsV1,
    /// Carries explicit ceilings for every registered resource dimension.
    pub resource_envelope: ResourceVector,
}

/// Signs the full administrative resource statement for offline provisioning.
///
/// The signer remains the existing AOSPAK02 role. Signing does not install a
/// credential, retain an epoch, authorize Source mutation or fund a Project.
///
/// # Errors
/// Rejects sentinel claims or tree limits that cannot fit the existing codec.
pub fn sign_project_resource_authorization_source_v3(
    claims: ProjectResourceAuthorizationClaimsV3,
    key: &SigningKey,
) -> Result<[u8; PROJECT_AUTHORIZATION_SOURCE_BYTES_V3], ProjectAuthorizationSignatureErrorV2> {
    let mut packet = [0; PROJECT_AUTHORIZATION_SOURCE_BYTES_V3];
    packet[..8].copy_from_slice(b"AOSPSC03");
    packet[8..10].copy_from_slice(&3_u16.to_be_bytes());
    packet[12..20].copy_from_slice(&claims.issuer_generation.to_be_bytes());
    packet[20..36].copy_from_slice(claims.project.as_bytes());
    packet[36..44].copy_from_slice(&claims.publisher_generation.to_be_bytes());
    packet[44..76].copy_from_slice(claims.publisher_head.as_bytes());
    packet[76..108].copy_from_slice(claims.publisher_revision.as_bytes());
    packet[108..124].copy_from_slice(&claims.request_id);
    packet[124..132].copy_from_slice(&claims.epoch.to_be_bytes());

    for (index, limit) in [
        claims.tree_limits.maximum_project_roots(),
        claims.tree_limits.maximum_project_sandboxes(),
        claims.tree_limits.maximum_project_live_sandboxes(),
        claims.tree_limits.maximum_depth(),
        claims.tree_limits.maximum_children_per_parent(),
        claims.tree_limits.maximum_descendants(),
        claims.tree_limits.maximum_live_descendants(),
    ].into_iter().enumerate() {
        let limit = u32::try_from(limit).map_err(|_| ProjectAuthorizationSignatureErrorV2::NonCanonical)?;
        packet[132 + index * 4..136 + index * 4].copy_from_slice(&limit.to_be_bytes());
    }
    for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
        packet[BODY_BYTES + index * 8..BODY_BYTES + (index + 1) * 8]
            .copy_from_slice(&claims.resource_envelope.get(dimension).to_be_bytes());
    }

    parse_unverified_project_authorization_claims_v2(&packet)?;
    let signature = key.sign(&signing_preimage(&packet[..BODY_BYTES_V3]));
    packet[BODY_BYTES_V3..].copy_from_slice(&signature.to_bytes());
    Ok(packet)
}

/// Checks only the independent role signature; callers separately join owners.
///
/// The returned parsed claims remain DATA, not current policy or Source append
/// authority. Fixed native owners separately check their actual current heads,
/// retained issuer, request and epoch before crossing an effect boundary.
///
/// # Errors
/// Returns the original malformed framing, stale issuer or invalid signature
/// class at the same parser, issuer comparison and verification frontier.
pub fn verify_signed_project_authorization_claims_v2(
    bytes: &[u8],
    issuer: &PinnedPublisherProjectAuthorizationIssuerV2,
) -> Result<UnverifiedProjectAuthorizationClaimsV2, ProjectAuthorizationSignatureErrorV2> {
    let claims = parse_unverified_project_authorization_claims_v2(bytes)?;
    if claims.issuer_generation() != issuer.generation {
        return Err(ProjectAuthorizationSignatureErrorV2::Stale);
    }
    let body_bytes = packet_body_bytes(bytes)?;
    let signature = Signature::from_bytes(&take::<64>(bytes, body_bytes)?);
    issuer
        .key
        .verify_strict(&signing_preimage(&bytes[..body_bytes]), &signature)
        .map_err(|_| ProjectAuthorizationSignatureErrorV2::Signature)?;
    Ok(claims)
}

/// Computes the existing domain-separated canonical comparison digest.
///
/// Supplying bytes or a domain proves no native owner or currentness.
pub fn commitment(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(domain)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn signing_preimage(body: &[u8]) -> Vec<u8> {
    let domain = if body.len() == BODY_BYTES_V3 { SIGNING_DOMAIN_V3 } else { SIGNING_DOMAIN };
    let mut bytes = Vec::with_capacity(domain.len() + body.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(body);
    bytes
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ProjectAuthorizationSignatureErrorV2> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ProjectAuthorizationSignatureErrorV2::NonCanonical)
}
