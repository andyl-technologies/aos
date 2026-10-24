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
//! AOSSGC02 retains the same seed and joins with exact AOSPSC03[400].
//! ```

use aos_sandbox_model::{ObjectDigest, ProjectId, ResourceVector};
use sha2::{Digest as _, Sha256};

use crate::controller_source_seed::{
    ControllerSourceTreeSeedErrorV1, ControllerSourceTreeSeedV1,
    decode_source_tree_seed_body_v1,
};
use crate::source_project_authorization::{
    ProjectAuthorizationSourceDataErrorV2, parse_unverified_project_authorization_claims_v2,
};

/// Bounds one immutable Controller acceptance of the exact signed inputs.
pub const CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V1: usize = 608;
/// Bounds an acceptance retaining the complete signed resource envelope.
pub const CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V2: usize = 784;

const ACCEPTANCE_MAGIC: &[u8; 8] = b"AOSSGC01";
const ACCEPTANCE_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.controller-acceptance.v1\0";
const ACCEPTANCE_DOMAIN_V2: &[u8] = b"aos.sandbox.source-genesis.controller-acceptance.v2\0";

/// Reports malformed immutable acceptance DATA without native owner failures.
#[derive(Debug, thiserror::Error)]
pub enum ControllerSourceGenesisAcceptanceDataErrorV1 {
    /// Framing, sentinels, or the exact signed-input joins are invalid.
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
    /// The retained seed body is malformed.
    #[error(transparent)]
    Seed(#[from] ControllerSourceTreeSeedErrorV1),
    /// The retained project-authorization body is malformed.
    #[error(transparent)]
    Authorization(#[from] ProjectAuthorizationSourceDataErrorV2),
}

/// Retains the immutable signed input tuple accepted by the Controller owner.
///
/// Decoding authenticates neither the signatures nor their currentness. The
/// held Controller consumer independently rejoins both fixed issuers and the
/// actual current publisher/project-authorization records before use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerSourceGenesisAcceptanceRecordV1 {
    bytes: Vec<u8>,
    seed: [u8; 224],
}

impl ControllerSourceGenesisAcceptanceRecordV1 {
    /// Constructs canonical comparison DATA from the exact signed input tuple.
    ///
    /// This does not verify signatures, retain a writer, admit a role, or grant
    /// currentness or permission to append.
    ///
    /// # Errors
    /// Rejects malformed packets, mismatched claims, or sentinel commitments.
    pub fn new(
        seed: [u8; 224],
        authorization: impl AsRef<[u8]>,
        publisher_pointer: ObjectDigest,
        publisher_revision: ObjectDigest,
        authorization_head: ObjectDigest,
        administrative_roles: ObjectDigest,
    ) -> Result<Self, ControllerSourceGenesisAcceptanceDataErrorV1> {
        let claims = decode_source_tree_seed_body_v1(&seed[..160])?;
        let authorization = authorization.as_ref();
        let authorization_claims = parse_unverified_project_authorization_claims_v2(authorization)?;
        let resource_version = authorization_claims.resource_envelope().is_some();
        let mut bytes = vec![0; 32 + seed.len() + authorization.len() + 128];
        bytes[..8].copy_from_slice(if resource_version { b"AOSSGC02" } else { ACCEPTANCE_MAGIC });
        bytes[8..10].copy_from_slice(&(if resource_version { 2_u16 } else { 1 }).to_be_bytes());
        bytes[16..32].copy_from_slice(claims.project().as_bytes());
        bytes[32..256].copy_from_slice(&seed);
        let joins = 256 + authorization.len();
        bytes[256..joins].copy_from_slice(authorization);
        bytes[joins..joins + 32].copy_from_slice(publisher_pointer.as_bytes());
        bytes[joins + 32..joins + 64].copy_from_slice(publisher_revision.as_bytes());
        bytes[joins + 64..joins + 96].copy_from_slice(authorization_head.as_bytes());
        bytes[joins + 96..].copy_from_slice(administrative_roles.as_bytes());
        Self::from_record_bytes(&bytes)
    }

    /// Decodes canonical data without granting an append or currentness proof.
    ///
    /// # Errors
    /// Rejects wrong framing, sentinel commitments, or differing signed claims.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, ControllerSourceGenesisAcceptanceDataErrorV1> {
        let resource_version = bytes.len() == CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V2
            && bytes.get(..8) == Some(b"AOSSGC02".as_slice())
            && bytes.get(8..16) == Some([0, 2, 0, 0, 0, 0, 0, 0].as_slice());
        let legacy = bytes.len() == CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V1
            && bytes.get(..8) == Some(ACCEPTANCE_MAGIC.as_slice())
            && bytes.get(8..16) == Some([0, 1, 0, 0, 0, 0, 0, 0].as_slice());
        if !legacy && !resource_version {
            return Err(ControllerSourceGenesisAcceptanceDataErrorV1::NonCanonical);
        }
        let record = Self {
            bytes: bytes.to_vec(),
            seed: take(bytes, 32)?,
        };
        let seed_packet = record.seed_packet();
        if &seed_packet[..8] != b"AOSCSE01" || seed_packet[8..12] != [0, 1, 0, 0] {
            return Err(ControllerSourceGenesisAcceptanceDataErrorV1::NonCanonical);
        }
        let seed = record.seed_claims()?;
        let authorization = parse_unverified_project_authorization_claims_v2(record.auth_packet())?;
        if record.project() != seed.project()
            || authorization.project() != seed.project()
            || authorization.request_id() != seed.request_id()
            || authorization.limits() != seed.limits()
            || authorization.epoch() != seed.epoch()
            || authorization.publisher_generation() != seed.publisher_generation()
            || authorization.publisher_head_digest() != seed.publisher_head()
            || record.publisher_pointer() != seed.publisher_head()
            || record.publisher_revision() != authorization.publisher_revision_digest()
            || record.authorization_head() != seed.project_authorization_head()
            || authorization.resource_envelope().is_some() != resource_version
            || record.bytes[record.joins_offset()..]
                .chunks_exact(32)
                .any(|digest| digest == [0; 32])
        {
            return Err(ControllerSourceGenesisAcceptanceDataErrorV1::NonCanonical);
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
    pub fn auth_packet(&self) -> &[u8] {
        &self.bytes[256..self.joins_offset()]
    }

    /// Decodes the retained seed body without authenticating its signature.
    ///
    /// # Errors
    /// Rejects noncanonical seed body fields.
    pub fn seed_claims(&self) -> Result<ControllerSourceTreeSeedV1, ControllerSourceGenesisAcceptanceDataErrorV1> {
        Ok(decode_source_tree_seed_body_v1(&self.bytes[32..192])?)
    }

    /// Returns the exact protected publisher-pointer commitment.
    #[must_use]
    pub fn publisher_pointer(&self) -> ObjectDigest {
        digest_at(&self.bytes, self.joins_offset())
    }

    /// Returns the exact immutable publisher-revision commitment.
    #[must_use]
    pub fn publisher_revision(&self) -> ObjectDigest {
        digest_at(&self.bytes, self.joins_offset() + 32)
    }

    /// Returns the exact retained administrative authorization head.
    #[must_use]
    pub fn authorization_head(&self) -> ObjectDigest {
        digest_at(&self.bytes, self.joins_offset() + 64)
    }

    /// Returns the two independent administrative role-pin commitment.
    #[must_use]
    pub fn administrative_roles(&self) -> ObjectDigest {
        digest_at(&self.bytes, self.joins_offset() + 96)
    }

    /// Borrows the canonical immutable acceptance bytes.
    #[must_use]
    pub fn record_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the domain-separated immutable acceptance commitment.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let domain = if self.bytes.len() == CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V2 {
            ACCEPTANCE_DOMAIN_V2
        } else {
            ACCEPTANCE_DOMAIN
        };
        hash(domain, &self.bytes)
    }

    /// Returns signed resource DATA only for the complete SGC02 recipe.
    ///
    /// Decoding this value does not authenticate a current owner or pay capacity.
    #[must_use]
    pub fn resource_envelope(&self) -> Option<ResourceVector> {
        parse_unverified_project_authorization_claims_v2(self.auth_packet())
            .ok()
            .and_then(|claims| claims.resource_envelope())
    }

    fn joins_offset(&self) -> usize {
        self.bytes.len() - 128
    }
}

fn hash(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
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
) -> Result<[u8; N], ControllerSourceGenesisAcceptanceDataErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|part| part.try_into().ok())
        .ok_or(ControllerSourceGenesisAcceptanceDataErrorV1::NonCanonical)
}

fn digest_at(bytes: &[u8], offset: usize) -> ObjectDigest {
    let mut digest = [0; 32];
    digest.copy_from_slice(&bytes[offset..offset + 32]);
    ObjectDigest::from_bytes(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::source_tree_model::TreeLimitsV1;
    use crate::controller_source_seed::sign_controller_source_tree_seed_v1;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn acceptance(project: ProjectId) -> ControllerSourceGenesisAcceptanceRecordV1 {
        let limits = TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap();
        let publisher_pointer = ObjectDigest::from_bytes([2; 32]);
        let authorization_head = ObjectDigest::from_bytes([3; 32]);
        let request = [4; 16];
        let publisher_generation = 5;
        let epoch = 9;
        let seed = sign_controller_source_tree_seed_v1(
            ControllerSourceTreeSeedV1::new(
                project,
                limits,
                publisher_generation,
                publisher_pointer,
                authorization_head,
                request,
                epoch,
            )
            .unwrap(),
            7,
            &SigningKey::from_bytes(&[41; 32]),
        )
        .unwrap();

        let publisher_revision = ObjectDigest::from_bytes([6; 32]);
        let mut authorization = [0; 224];
        authorization[..8].copy_from_slice(b"AOSPSC02");
        authorization[8..10].copy_from_slice(&2_u16.to_be_bytes());
        authorization[12..20].copy_from_slice(&8_u64.to_be_bytes());
        authorization[20..36].copy_from_slice(project.as_bytes());
        authorization[36..44].copy_from_slice(&publisher_generation.to_be_bytes());
        authorization[44..76].copy_from_slice(publisher_pointer.as_bytes());
        authorization[76..108].copy_from_slice(publisher_revision.as_bytes());
        authorization[108..124].copy_from_slice(&request);
        authorization[124..132].copy_from_slice(&epoch.to_be_bytes());
        for (index, limit) in [1_u32, 8, 7, 6, 5, 4, 3].into_iter().enumerate() {
            authorization[132 + index * 4..136 + index * 4].copy_from_slice(&limit.to_be_bytes());
        }
        let mut preimage = b"aos.sandbox.publisher-project-authorization-source.v2\0/var/lib/aos/sandboxd/controller.journal\0".to_vec();
        preimage.extend_from_slice(&authorization[..160]);
        authorization[160..]
            .copy_from_slice(&SigningKey::from_bytes(&[42; 32]).sign(&preimage).to_bytes());
        ControllerSourceGenesisAcceptanceRecordV1::new(
            seed,
            authorization,
            publisher_pointer,
            publisher_revision,
            authorization_head,
            ObjectDigest::from_bytes([7; 32]),
        )
        .unwrap()
    }

    #[test]
    fn signed_immutable_tuple_round_trips_without_claiming_currentness() {
        let expected = acceptance(ProjectId::from_bytes([1; 16]));
        let decoded = ControllerSourceGenesisAcceptanceRecordV1::from_record_bytes(
            expected.record_bytes(),
        ).unwrap();

        assert_eq!(decoded, expected);
        assert_eq!(decoded.record_bytes().len(), CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V1);
        assert_eq!(decoded.seed_claims().unwrap().project(), decoded.project());
        assert_eq!(decoded.digest(), expected.digest());
    }

    #[test]
    fn mismatched_project_and_sentinel_join_refuse_in_the_shared_codec() {
        let original = acceptance(ProjectId::from_bytes([1; 16]));
        let mut wrong_project = original.record_bytes().to_vec();
        wrong_project[16] ^= 1;
        let mut missing_roles = original.record_bytes().to_vec();
        missing_roles[576..608].fill(0);

        for bytes in [&wrong_project, &missing_roles] {
            assert!(matches!(
                ControllerSourceGenesisAcceptanceRecordV1::from_record_bytes(bytes),
                Err(ControllerSourceGenesisAcceptanceDataErrorV1::NonCanonical),
            ));
        }
    }
}
