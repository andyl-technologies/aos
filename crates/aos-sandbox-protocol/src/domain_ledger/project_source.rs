//! Owns immutable accepted-Create source hash inputs and commitment DATA.

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, RevocationScopeId, SandboxId};
use sha2::{Digest as _, Sha256};

const SOURCE_DOMAIN: &[u8] = b"aos.sandbox.public-create-project-source.v2\0";
/// Retains source hash inputs only; it cannot establish current publisher heads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalCreateProjectSourceHeadsV1 {
    projection_revision: ObjectDigest,
    publisher_generation: u64,
    publisher_digest: ObjectDigest,
    cache_domain_head: ObjectDigest,
    revocation_scope: RevocationScopeId,
    revocation_generation: u64,
    revocation_head: ObjectDigest,
}

impl HistoricalCreateProjectSourceHeadsV1 {
    pub const fn from_historical_fields(
        projection_revision: ObjectDigest,
        publisher_generation: u64,
        publisher_digest: ObjectDigest,
        cache_domain_head: ObjectDigest,
        revocation_scope: RevocationScopeId,
        revocation_generation: u64,
        revocation_head: ObjectDigest,
    ) -> Self {
        Self {
            projection_revision,
            publisher_generation,
            publisher_digest,
            cache_domain_head,
            revocation_scope,
            revocation_generation,
            revocation_head,
        }
    }

    pub const fn projection_revision(self) -> ObjectDigest {
        self.projection_revision
    }

    pub const fn publisher_digest(self) -> ObjectDigest {
        self.publisher_digest
    }

    pub fn record_bytes(self) -> [u8; 160] {
        let mut bytes = [0; 160];
        bytes[..32].copy_from_slice(self.projection_revision.as_bytes());
        bytes[32..40].copy_from_slice(&self.publisher_generation.to_be_bytes());
        bytes[40..72].copy_from_slice(self.publisher_digest.as_bytes());
        bytes[72..104].copy_from_slice(self.cache_domain_head.as_bytes());
        bytes[104..120].copy_from_slice(self.revocation_scope.as_bytes());
        bytes[120..128].copy_from_slice(&self.revocation_generation.to_be_bytes());
        bytes[128..].copy_from_slice(self.revocation_head.as_bytes());
        bytes
    }

    pub fn from_record_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 160 {
            return None;
        }
        let row = Self {
            projection_revision: ObjectDigest::from_bytes(bytes[..32].try_into().ok()?),
            publisher_generation: u64::from_be_bytes(bytes[32..40].try_into().ok()?),
            publisher_digest: ObjectDigest::from_bytes(bytes[40..72].try_into().ok()?),
            cache_domain_head: ObjectDigest::from_bytes(bytes[72..104].try_into().ok()?),
            revocation_scope: RevocationScopeId::from_bytes(bytes[104..120].try_into().ok()?),
            revocation_generation: u64::from_be_bytes(bytes[120..128].try_into().ok()?),
            revocation_head: ObjectDigest::from_bytes(bytes[128..].try_into().ok()?),
        };
        row.is_valid().then_some(row)
    }

    pub fn is_valid(self) -> bool {
        self.projection_revision.as_bytes() != &[0; 32]
            && self.publisher_generation != 0
            && self.publisher_digest.as_bytes() != &[0; 32]
            && self.cache_domain_head.as_bytes() != &[0; 32]
            && self.revocation_scope.as_bytes() != &[0; 16]
            && self.revocation_generation != 0
            && self.revocation_head.as_bytes() != &[0; 32]
    }
}

pub fn create_project_source_commitment_v1(
    operation: OperationId,
    admission_revision: ObjectDigest,
    admission_generation: u64,
    sandbox: SandboxId,
    project: ProjectId,
    heads: HistoricalCreateProjectSourceHeadsV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(SOURCE_DOMAIN)
            .chain_update(operation.as_bytes())
            .chain_update(admission_revision.as_bytes())
            .chain_update(admission_generation.to_be_bytes())
            .chain_update(sandbox.as_bytes())
            .chain_update(project.as_bytes())
            .chain_update(heads.record_bytes())
            .finalize()
            .into(),
    )
}

