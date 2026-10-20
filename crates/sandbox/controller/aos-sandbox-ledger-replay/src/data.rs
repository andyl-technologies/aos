//! Preserves pure Source DATA failures and the shared fixed field helpers.

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::source_project_authorization::ProjectAuthorizationSourceDataErrorV2;
use sha2::{Digest as _, Sha256};

/// Reports a canonical Source successor DATA failure without native authority.
#[derive(Debug, thiserror::Error)]
pub enum SourceSuccessorDataErrorV2 {
    /// A saved project or phase conflicts with its exact original association.
    #[error("Source genesis project or flight conflicts with retained state")]
    Conflict,
    /// The original canonical administrative seed verifier failed.
    #[error(transparent)]
    Seed(#[from] aos_sandbox_protocol::controller_source_seed::ControllerSourceTreeSeedErrorV1),
    /// A fixed field, signature or exact administrative crosslink differs.
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
    /// The original pure administrative authorization decoder failed.
    #[error(transparent)]
    Authorization(#[from] ProjectAuthorizationSourceDataErrorV2),
    /// The original pinned administrative signature or generation check failed.
    #[error(transparent)]
    AuthorizationSignature(#[from] aos_sandbox_protocol::publisher_project_authorization::ProjectAuthorizationSignatureErrorV2),
}

/// Returns the existing domain-separated Source object commitment.
pub fn hash(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(domain)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

/// Copies the exact fixed field from its canonical input.
///
/// # Errors
/// Rejects an absent or nonexact field without replacing its original input.
pub fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SourceSuccessorDataErrorV2> {
    bytes
        .get(offset..offset + N)
        .and_then(|part| part.try_into().ok())
        .ok_or(SourceSuccessorDataErrorV2::NonCanonical)
}

/// Copies a digest field after its caller has established the fixed extent.
///
/// # Panics
/// Panics when the caller has not established the exact32-byte field extent.
pub fn digest_at(bytes: &[u8], offset: usize) -> ObjectDigest {
    let mut digest = [0; 32];
    digest.copy_from_slice(&bytes[offset..offset + 32]);
    ObjectDigest::from_bytes(digest)
}

impl From<aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceDataErrorV1>
    for SourceSuccessorDataErrorV2
{
    fn from(error: aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceDataErrorV1) -> Self {
        use aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceDataErrorV1;
        match error {
            ControllerSourceGenesisAcceptanceDataErrorV1::NonCanonical => Self::NonCanonical,
            ControllerSourceGenesisAcceptanceDataErrorV1::Seed(error) => Self::Seed(error),
            ControllerSourceGenesisAcceptanceDataErrorV1::Authorization(error) => Self::Authorization(error),
        }
    }
}

impl From<crate::genesis::SourceGenesisReceiptDataErrorV1> for SourceSuccessorDataErrorV2 {
    fn from(error: crate::genesis::SourceGenesisReceiptDataErrorV1) -> Self {
        match error {
            crate::genesis::SourceGenesisReceiptDataErrorV1::NonCanonical => Self::NonCanonical,
        }
    }
}

#[cfg(test)]
mod signature_error_tests {
    use super::*;
    use aos_sandbox_protocol::publisher_project_authorization::ProjectAuthorizationSignatureErrorV2;

    #[test]
    fn authorization_signature_projection_keeps_each_original_typed_leaf() {
        for error in [ProjectAuthorizationSignatureErrorV2::NonCanonical,
            ProjectAuthorizationSignatureErrorV2::Stale, ProjectAuthorizationSignatureErrorV2::Signature] {
            let expected = std::mem::discriminant(&error);
            let projected = SourceSuccessorDataErrorV2::from(error);

            assert!(matches!(projected, SourceSuccessorDataErrorV2::AuthorizationSignature(actual)
                if std::mem::discriminant(&actual) == expected));
        }
    }
}
