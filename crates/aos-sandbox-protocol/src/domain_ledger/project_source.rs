//! Owns immutable accepted-Create source hash inputs and commitment DATA.
//!
//! These fields describe the accepted Create input independently of Source's
//! five-row admission history. They do not establish current publisher, cache,
//! or revocation heads. Native validation and held writer loans stay upper.
//!
//! The fixed 160-byte layout contains no framing or checksum. Generations are
//! big-endian; the commitment hashes the complete layout after the operation,
//! admission revision/generation, sandbox, and project in their original order.
//!
//! ```text
//! projection-revision:32 | publisher-generation:u64 | publisher-digest:32 |
//! cache-domain-head:32 | revocation-scope:16 | revocation-generation:u64 |
//! revocation-head:32
//! ```

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
    /// Assembles unchecked historical fields without asserting current heads.
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

    /// Returns the accepted projection revision used by historical reconciliation.
    pub const fn projection_revision(self) -> ObjectDigest {
        self.projection_revision
    }

    /// Returns the accepted publisher digest used by historical reconciliation.
    pub const fn publisher_digest(self) -> ObjectDigest {
        self.publisher_digest
    }

    /// Returns the complete fixed-width historical commitment input.
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

    /// Decodes exactly 160 bytes, rejecting every zero identity or generation.
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

    /// Checks nonzero historical fields without authenticating their currentness.
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

/// Hashes the exact accepted Create identities and complete historical source input.
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

#[cfg(test)]
mod tests {
    use super::super::root_project_history::project_admission_client_nonce_v1;
    use super::*;

    #[test]
    fn asymmetric_generations_pin_source_commitment_and_client_nonce() {
        let operation = OperationId::from_bytes([0x21; 16]);
        let heads = HistoricalCreateProjectSourceHeadsV1::from_historical_fields(
            ObjectDigest::from_bytes([0x31; 32]),
            0x1112_1314_1516_1718,
            ObjectDigest::from_bytes([0x32; 32]),
            ObjectDigest::from_bytes([0x33; 32]),
            RevocationScopeId::from_bytes([0x34; 16]),
            0x2122_2324_2526_2728,
            ObjectDigest::from_bytes([0x35; 32]),
        );
        let bytes = heads.record_bytes();
        assert_eq!(
            &bytes[32..40],
            &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
        );
        assert_eq!(
            &bytes[120..128],
            &[0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28]
        );
        assert_eq!(
            HistoricalCreateProjectSourceHeadsV1::from_record_bytes(&bytes),
            Some(heads)
        );

        let commitment = create_project_source_commitment_v1(
            operation,
            ObjectDigest::from_bytes([0x22; 32]),
            0x0102_0304_0506_0708,
            SandboxId::from_bytes([0x23; 16]),
            ProjectId::from_bytes([0x24; 16]),
            heads,
        );
        // Independent SHA-256 vectors use the literal domains and ordered
        // fixed-width fields, with all three generations in big-endian order.
        assert_eq!(
            commitment.as_bytes(),
            &[
                0x4b, 0x43, 0xc4, 0xe2, 0x42, 0x43, 0x06, 0xe7, 0x08, 0x76, 0x1a, 0x4b, 0xe1, 0x9a,
                0x8c, 0xd2, 0xa6, 0xfd, 0xac, 0xb4, 0x31, 0xd9, 0xe5, 0x4d, 0x2d, 0xa8, 0xba, 0x80,
                0x82, 0xf1, 0x53, 0x2f,
            ]
        );
        assert_eq!(
            project_admission_client_nonce_v1(operation, commitment),
            [
                0xea, 0x0e, 0x0a, 0x31, 0x8e, 0xaa, 0x81, 0x3d, 0x6e, 0xeb, 0xec, 0xd5, 0x02, 0xef,
                0xb9, 0x71,
            ]
        );
    }
}
