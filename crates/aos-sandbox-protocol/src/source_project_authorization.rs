//! Canonical unverified Source project-authorization packet DATA.
//!
//! This module owns framing, claimed limits and packet commitments shared by
//! Publisher, Source and Policy. It owns no key, credential, journal, signer,
//! currentness check or permission to append. Decoding never grants authority.
//!
//! ```text
//! AOSPSC02 | version:u16be=2 | reserved:u16be=0 | issuer-generation:u64be |
//! project[16] | publisher-generation:u64be | publisher-head[32] |
//! publisher-revision[32] | request-id[16] | issuer-epoch:u64be |
//! seven tree ceilings:u32be each | unverified signature[64]
//! AOSPSC03 uses version=3 and inserts ResourceDimension::COUNT ceilings:u64be
//! in ResourceDimension::ALL order before the unverified signature.
//! ```

use aos_sandbox_core::source_tree_model::TreeLimitsV1;
use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceDimension, ResourceVector};
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSPSC02";
const VERSION: u16 = 2;
/// Bounds the PSC02 claim body, excluding its signature.
pub const PROJECT_AUTHORIZATION_SOURCE_BODY_BYTES_V2: usize = 160;
/// Bounds the PSC03 claim body, including every resource ceiling.
pub const PROJECT_AUTHORIZATION_SOURCE_BODY_BYTES_V3: usize =
    PROJECT_AUTHORIZATION_SOURCE_BODY_BYTES_V2 + ResourceDimension::COUNT * 8;
/// Bounds the complete PSC02 project-authorization packet.
pub const PROJECT_AUTHORIZATION_SOURCE_BYTES_V2: usize =
    PROJECT_AUTHORIZATION_SOURCE_BODY_BYTES_V2 + 64;
/// Bounds the complete PSC03 project-authorization packet.
pub const PROJECT_AUTHORIZATION_SOURCE_BYTES_V3: usize =
    PROJECT_AUTHORIZATION_SOURCE_BODY_BYTES_V3 + 64;
const BODY_BYTES: usize = PROJECT_AUTHORIZATION_SOURCE_BODY_BYTES_V2;
const BODY_BYTES_V3: usize = PROJECT_AUTHORIZATION_SOURCE_BODY_BYTES_V3;
const PACKET_DOMAIN: &[u8] = b"aos.sandbox.publisher-project-authorization.packet.v2\0";
const PACKET_DOMAIN_V3: &[u8] = b"aos.sandbox.publisher-project-authorization.packet.v3\0";

/// Reports malformed project-authorization DATA, not an owner admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProjectAuthorizationSourceDataErrorV2 {
    /// A packet recipe, sentinel claim or tree shape is noncanonical.
    #[error("invalid project authorization source DATA")]
    NonCanonical,
}

/// Retains structurally decoded claims without authenticating any authority.
///
/// Its private fields can only be populated by the canonical decoder. Neither
/// the signature bytes nor the claimed issuer, heads, epoch or resources are
/// trusted by decoding; protected owners must independently verify them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnverifiedProjectAuthorizationClaimsV2 {
    project: ProjectId,
    limits: TreeLimitsV1,
    issuer_generation: u64,
    publisher_generation: u64,
    publisher_head_digest: ObjectDigest,
    publisher_revision_digest: ObjectDigest,
    request_id: [u8; 16],
    epoch: u64,
    resource_envelope: Option<ResourceVector>,
}

impl UnverifiedProjectAuthorizationClaimsV2 {
    /// Returns the decoded project identity.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the seven structurally validated tree ceilings.
    #[must_use]
    pub const fn limits(&self) -> TreeLimitsV1 {
        self.limits
    }

    /// Returns the claimed issuer generation without authenticating it.
    #[must_use]
    pub const fn issuer_generation(&self) -> u64 {
        self.issuer_generation
    }

    /// Returns the claimed publisher generation without proving currentness.
    #[must_use]
    pub const fn publisher_generation(&self) -> u64 {
        self.publisher_generation
    }

    /// Returns the claimed publisher pointer commitment.
    #[must_use]
    pub const fn publisher_head_digest(&self) -> ObjectDigest {
        self.publisher_head_digest
    }

    /// Returns the claimed immutable publisher revision commitment.
    #[must_use]
    pub const fn publisher_revision_digest(&self) -> ObjectDigest {
        self.publisher_revision_digest
    }

    /// Returns the claimed administrative request identity.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the claimed issuer epoch without establishing a replay floor.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns all resource ceilings for PSC03, or absence for PSC02.
    #[must_use]
    pub const fn resource_envelope(&self) -> Option<ResourceVector> {
        self.resource_envelope
    }
}

/// Decodes one complete PSC02 or PSC03 packet as unverified DATA.
///
/// # Errors
/// Rejects foreign widths, magic or versions, nonzero reserved bytes, sentinel
/// claims, and inconsistent or excessive tree limits. Signature bytes are not
/// verified, and zero resource ceilings remain permitted.
pub fn parse_unverified_project_authorization_claims_v2(
    bytes: &[u8],
) -> Result<UnverifiedProjectAuthorizationClaimsV2, ProjectAuthorizationSourceDataErrorV2> {
    let body_bytes = packet_body_bytes(bytes)?;
    let body = &bytes[..body_bytes];
    if take::<2>(body, 10)? != [0; 2] {
        return Err(ProjectAuthorizationSourceDataErrorV2::NonCanonical);
    }
    let limits = TreeLimitsV1::new(
        read_limit(body, 132)?,
        read_limit(body, 136)?,
        read_limit(body, 140)?,
        read_limit(body, 144)?,
        read_limit(body, 148)?,
        read_limit(body, 152)?,
        read_limit(body, 156)?,
    )
    .map_err(|_| ProjectAuthorizationSourceDataErrorV2::NonCanonical)?;
    let resource_envelope = if body_bytes == BODY_BYTES_V3 {
        let mut values = [0; ResourceDimension::COUNT];
        for (index, value) in values.iter_mut().enumerate() {
            *value = u64::from_be_bytes(take::<8>(body, BODY_BYTES + index * 8)?);
        }
        Some(ResourceVector::new(values))
    } else {
        None
    };
    let claims = UnverifiedProjectAuthorizationClaimsV2 {
        project: ProjectId::from_bytes(take::<16>(body, 20)?),
        limits,
        issuer_generation: u64::from_be_bytes(take::<8>(body, 12)?),
        publisher_generation: u64::from_be_bytes(take::<8>(body, 36)?),
        publisher_head_digest: ObjectDigest::from_bytes(take::<32>(body, 44)?),
        publisher_revision_digest: ObjectDigest::from_bytes(take::<32>(body, 76)?),
        request_id: take::<16>(body, 108)?,
        epoch: u64::from_be_bytes(take::<8>(body, 124)?),
        resource_envelope,
    };
    if claims.project.as_bytes() == &[0; 16]
        || claims.request_id == [0; 16]
        || claims.issuer_generation == 0
        || claims.publisher_generation == 0
        || claims.publisher_head_digest.as_bytes() == &[0; 32]
        || claims.publisher_revision_digest.as_bytes() == &[0; 32]
        || claims.epoch == 0
    {
        return Err(ProjectAuthorizationSourceDataErrorV2::NonCanonical);
    }
    Ok(claims)
}

/// Selects the exact claim-body width from the complete packet recipe.
///
/// # Errors
/// Rejects unsupported packet widths, magic and versions. Other claim checks
/// remain in [`parse_unverified_project_authorization_claims_v2`].
// Width, magic and version select one closed recipe before any slicing.
pub fn packet_body_bytes(bytes: &[u8]) -> Result<usize, ProjectAuthorizationSourceDataErrorV2> {
    match (bytes.len(), bytes.get(..8), bytes.get(8..10)) {
        (PROJECT_AUTHORIZATION_SOURCE_BYTES_V2, Some(magic), Some(version))
            if magic == MAGIC && version == VERSION.to_be_bytes() =>
        {
            Ok(BODY_BYTES)
        }
        (PROJECT_AUTHORIZATION_SOURCE_BYTES_V3, Some(magic), Some(version))
            if magic == b"AOSPSC03" && version == 3_u16.to_be_bytes() =>
        {
            Ok(BODY_BYTES_V3)
        }
        _ => Err(ProjectAuthorizationSourceDataErrorV2::NonCanonical),
    }
}

/// Commits the exact packet bytes under their existing versioned DATA domain.
///
/// # Errors
/// Rejects unsupported packet widths, magic and versions. This function does
/// not validate the claims or authenticate the included signature.
pub fn project_authorization_packet_digest(
    bytes: &[u8],
) -> Result<ObjectDigest, ProjectAuthorizationSourceDataErrorV2> {
    let domain = if packet_body_bytes(bytes)? == BODY_BYTES_V3 {
        PACKET_DOMAIN_V3
    } else {
        PACKET_DOMAIN
    };
    Ok(commitment(domain, bytes))
}

fn read_limit(
    bytes: &[u8],
    offset: usize,
) -> Result<usize, ProjectAuthorizationSourceDataErrorV2> {
    usize::try_from(u32::from_be_bytes(take::<4>(bytes, offset)?))
        .map_err(|_| ProjectAuthorizationSourceDataErrorV2::NonCanonical)
}

fn commitment(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(domain)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ProjectAuthorizationSourceDataErrorV2> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ProjectAuthorizationSourceDataErrorV2::NonCanonical)
}

#[cfg(test)]
mod tests;
