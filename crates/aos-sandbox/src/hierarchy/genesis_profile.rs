//! Canonical data shared by the existing Controller, Source, and Root owners.
//!
//! These records carry administrative provenance, not current authority. Only
//! the held owner APIs may append a genesis or accept its independently held
//! Root floor. The local-Root profile trusts protected Root state; it does not
//! resist rollback of the whole host disk.
//!
//! ```text
//! AOSSGC01 | version:u16=1 | reserved[6] | project[16] |
//! AOSCSE01[224] | AOSPSC02[224] | publisher-pointer[32] |
//! publisher-revision[32] | project-authorization-head[32] |
//! administrative-role-tuple[32]
//! ```

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::source_seed::{
    ControllerSourceTreeSeedErrorV1, ControllerSourceTreeSeedV1, decode_source_tree_seed_body_v1,
};
use crate::journal::JournalError;
use crate::publisher_policy::{
    ProjectAuthorizationSourceErrorV2, PublisherPolicyError,
    parse_unverified_project_authorization_claims_v2,
};

/// Bounds one immutable Controller acceptance of the exact signed inputs.
pub const CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V1: usize = 608;

const ACCEPTANCE_MAGIC: &[u8; 8] = b"AOSSGC01";
const ACCEPTANCE_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.controller-acceptance.v1\0";

/// Reports a refused or incomplete held Source-genesis flight.
#[derive(Debug, thiserror::Error)]
pub enum SourceGenesisErrorV1 {
    /// A record, packet, sentinel, or exact graph join is invalid.
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
    /// A project or pending flight already belongs to a different exact input.
    #[error("Source genesis project or flight conflicts with retained state")]
    Conflict,
    /// The independently configured role or fixed owner custody changed.
    #[error("Source genesis owner or credential is not current")]
    Stale,
    /// Positive genesis admission is unavailable; historical recovery is separate.
    #[error("new Source genesis admission is unavailable")]
    AdmissionClosed,
    /// Protected journal replay, capacity, append, or readback failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Canonical hierarchy replay or member construction failed.
    #[error(transparent)]
    Hierarchy(#[from] super::protected_journal::HierarchyProtectedJournalErrorV1),
    /// Publisher ownership or canonical current-state validation failed.
    #[error(transparent)]
    Publisher(#[from] PublisherPolicyError),
    /// The independently pinned administrative seed failed verification.
    #[error(transparent)]
    Seed(#[from] ControllerSourceTreeSeedErrorV1),
    /// The separate project administrative authorization failed verification.
    #[error(transparent)]
    Authorization(#[from] ProjectAuthorizationSourceErrorV2),
    /// The original authenticated Root flight failed or was lost.
    #[error(transparent)]
    Transport(#[from] std::io::Error),
    /// A genuine kernel peer, cgroup, boot, or descriptor observation failed.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// A stream fragment violated its strict kernel-subject profile.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Subject(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
}

/// Retains the immutable signed input tuple accepted by the Controller owner.
///
/// Decoding authenticates neither the signatures nor their currentness. The
/// held Controller consumer independently rejoins both fixed issuers and the
/// actual current publisher/project-authorization records before use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerSourceGenesisAcceptanceRecordV1 {
    bytes: [u8; CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V1],
    seed: [u8; 224],
    authorization: [u8; 224],
}

impl ControllerSourceGenesisAcceptanceRecordV1 {
    pub(crate) fn new(
        seed: [u8; 224],
        authorization: [u8; 224],
        publisher_pointer: ObjectDigest,
        publisher_revision: ObjectDigest,
        authorization_head: ObjectDigest,
        administrative_roles: ObjectDigest,
    ) -> Result<Self, SourceGenesisErrorV1> {
        let claims = decode_source_tree_seed_body_v1(&seed[..160])?;
        let mut bytes = [0; CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V1];
        bytes[..8].copy_from_slice(ACCEPTANCE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..32].copy_from_slice(claims.project().as_bytes());
        bytes[32..256].copy_from_slice(&seed);
        bytes[256..480].copy_from_slice(&authorization);
        bytes[480..512].copy_from_slice(publisher_pointer.as_bytes());
        bytes[512..544].copy_from_slice(publisher_revision.as_bytes());
        bytes[544..576].copy_from_slice(authorization_head.as_bytes());
        bytes[576..608].copy_from_slice(administrative_roles.as_bytes());
        Self::from_record_bytes(&bytes)
    }

    /// Decodes canonical data without granting an append or currentness proof.
    ///
    /// # Errors
    /// Rejects wrong framing, sentinel commitments, or differing signed claims.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        if bytes.len() != CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V1
            || bytes.get(..8) != Some(ACCEPTANCE_MAGIC.as_slice())
            || bytes[8..16] != [0, 1, 0, 0, 0, 0, 0, 0]
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let record = Self {
            bytes: take(bytes, 0)?,
            seed: take(bytes, 32)?,
            authorization: take(bytes, 256)?,
        };
        let seed_packet = record.seed_packet();
        if &seed_packet[..8] != b"AOSCSE01" || seed_packet[8..12] != [0, 1, 0, 0] {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let seed = record.seed_claims()?;
        let authorization = parse_unverified_project_authorization_claims_v2(record.auth_packet())?;
        if record.project() != seed.project()
            || authorization.project != seed.project()
            || authorization.request_id != seed.request_id()
            || authorization.limits != seed.limits()
            || authorization.epoch != seed.epoch()
            || authorization.publisher_generation != seed.publisher_generation()
            || authorization.publisher_head_digest != seed.publisher_head()
            || record.publisher_pointer() != seed.publisher_head()
            || record.publisher_revision() != authorization.publisher_revision_digest
            || record.authorization_head() != seed.project_authorization_head()
            || record.bytes[480..]
                .chunks_exact(32)
                .any(|digest| digest == [0; 32])
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(record)
    }

    /// Returns the exact accepted project identity.
    #[must_use]
    pub fn project(&self) -> ProjectId {
        let mut project = [0; 16];
        project.copy_from_slice(&self.bytes[16..32]);
        ProjectId::from_bytes(project)
    }

    /// Borrows the original signed seed without reissuing it.
    #[must_use]
    pub fn seed_packet(&self) -> &[u8; 224] {
        &self.seed
    }

    /// Borrows the original separate project-authorization packet.
    #[must_use]
    pub fn auth_packet(&self) -> &[u8; 224] {
        &self.authorization
    }

    pub(crate) fn seed_claims(&self) -> Result<ControllerSourceTreeSeedV1, SourceGenesisErrorV1> {
        Ok(decode_source_tree_seed_body_v1(&self.bytes[32..192])?)
    }

    /// Returns the exact protected publisher-pointer commitment.
    #[must_use]
    pub fn publisher_pointer(&self) -> ObjectDigest {
        digest_at(&self.bytes, 480)
    }

    /// Returns the exact immutable publisher-revision commitment.
    #[must_use]
    pub fn publisher_revision(&self) -> ObjectDigest {
        digest_at(&self.bytes, 512)
    }

    /// Returns the exact retained administrative authorization head.
    #[must_use]
    pub fn authorization_head(&self) -> ObjectDigest {
        digest_at(&self.bytes, 544)
    }

    /// Returns the two independent administrative role-pin commitment.
    #[must_use]
    pub fn administrative_roles(&self) -> ObjectDigest {
        digest_at(&self.bytes, 576)
    }

    /// Borrows the canonical immutable acceptance bytes.
    #[must_use]
    pub const fn record_bytes(&self) -> &[u8; CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V1] {
        &self.bytes
    }

    /// Returns the domain-separated immutable acceptance commitment.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        hash(ACCEPTANCE_DOMAIN, &self.bytes)
    }
}

pub(crate) fn hash(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(domain)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

pub(crate) fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], SourceGenesisErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|part| part.try_into().ok())
        .ok_or(SourceGenesisErrorV1::NonCanonical)
}

pub(crate) fn digest_at(bytes: &[u8], offset: usize) -> ObjectDigest {
    let mut digest = [0; 32];
    digest.copy_from_slice(&bytes[offset..offset + 32]);
    ObjectDigest::from_bytes(digest)
}
