//! Purpose-specific commitments used by lifecycle semantic facts.

use aos_sandbox_core::{model::snapshot::RetentionClaim, ObjectDigest};
use sha2::{Digest as _, Sha256};

use super::LifecycleModelError;

/// Commits a canonical snapshot manifest independently of object identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleSnapshotManifestDigestV1(pub(super) ObjectDigest);

/// Commits the generic witness together with exact method-family facts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleMethodSemanticCommitDigestV1(pub(super) ObjectDigest);

/// Commits a complete dependency graph and its verified tombstone postorder.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleCascadePlanDigestV1(pub(super) ObjectDigest);

/// Commits every typed field of one portable snapshot retention claim.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleRetentionClaimDigestV1(ObjectDigest);

impl LifecycleRetentionClaimDigestV1 {
    /// Commits the complete typed retention claim without retaining authority.
    #[must_use]
    pub fn from_claim(claim: &RetentionClaim) -> Self {
        let mut hasher = Sha256::new().chain_update(b"aos.sandbox.lifecycle.retention-claim.v1\0");
        match claim {
            RetentionClaim::Storage {
                resource,
                opaque_version,
                version_sha256,
                receipt,
            } => {
                hasher = hasher
                    .chain_update([1])
                    .chain_update(resource.as_bytes())
                    .chain_update((opaque_version.as_bytes().len() as u64).to_be_bytes())
                    .chain_update(opaque_version.as_bytes())
                    .chain_update(version_sha256.as_bytes())
                    .chain_update(receipt.digest().as_bytes());
            }
            RetentionClaim::Content { object, receipt } => {
                hasher = hash_claim_descriptor(hasher.chain_update([2]), object)
                    .chain_update(receipt.digest().as_bytes());
            }
            RetentionClaim::Nix {
                environment,
                receipt,
            } => {
                hasher = hash_claim_descriptor(hasher.chain_update([3]), environment)
                    .chain_update(receipt.digest().as_bytes());
            }
            RetentionClaim::Service {
                service,
                checkpoint_version,
                checkpoint_sha256,
                receipt,
                available_until,
            } => {
                hasher = hasher
                    .chain_update([4])
                    .chain_update(service.as_bytes())
                    .chain_update((checkpoint_version.as_bytes().len() as u64).to_be_bytes())
                    .chain_update(checkpoint_version.as_bytes())
                    .chain_update(checkpoint_sha256.as_bytes())
                    .chain_update(receipt.digest().as_bytes())
                    .chain_update([u8::from(available_until.is_some())])
                    .chain_update(available_until.unwrap_or(0).to_be_bytes());
            }
            RetentionClaim::Secret {
                issuer,
                secret,
                opaque_version,
                restore_scope,
                receipt,
                expires_seconds,
            } => {
                hasher = hasher
                    .chain_update([5])
                    .chain_update(issuer.as_bytes())
                    .chain_update(secret.as_bytes())
                    .chain_update((opaque_version.as_bytes().len() as u64).to_be_bytes())
                    .chain_update(opaque_version.as_bytes())
                    .chain_update(restore_scope.as_bytes())
                    .chain_update(receipt.digest().as_bytes())
                    .chain_update([u8::from(expires_seconds.is_some())])
                    .chain_update(expires_seconds.unwrap_or(0).to_be_bytes());
            }
        }
        Self(ObjectDigest::from_bytes(hasher.finalize().into()))
    }

    /// Returns the underlying domain-separated SHA-256 commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }

    pub(super) fn from_stored(value: ObjectDigest) -> Result<Self, LifecycleModelError> {
        if value.as_bytes() == &[0; 32] {
            Err(LifecycleModelError::CorruptEncoding)
        } else {
            Ok(Self(value))
        }
    }
}

fn hash_claim_descriptor(
    hasher: sha2::Sha256,
    descriptor: &aos_sandbox_core::ObjectDescriptor,
) -> sha2::Sha256 {
    hasher
        .chain_update((descriptor.media_type().as_str().len() as u64).to_be_bytes())
        .chain_update(descriptor.media_type().as_str().as_bytes())
        .chain_update(descriptor.digest().as_bytes())
        .chain_update(descriptor.encoded_size().to_be_bytes())
}

impl LifecycleCascadePlanDigestV1 {
    /// Returns the underlying SHA-256 commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }

    pub(super) fn from_stored(value: ObjectDigest) -> Result<Self, LifecycleModelError> {
        if value.as_bytes() == &[0; 32] {
            Err(LifecycleModelError::CorruptEncoding)
        } else {
            Ok(Self(value))
        }
    }
}

impl LifecycleMethodSemanticCommitDigestV1 {
    /// Returns the underlying SHA-256 commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }
}

impl LifecycleSnapshotManifestDigestV1 {
    /// Commits exact canonical snapshot-manifest bytes.
    #[must_use]
    pub fn commit(bytes: &[u8]) -> Self {
        Self(ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.snapshot-manifest.v1\0")
                .chain_update(bytes)
                .finalize()
                .into(),
        ))
    }

    /// Returns the underlying SHA-256 commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }

    pub(super) fn from_stored(value: ObjectDigest) -> Result<Self, LifecycleModelError> {
        if value.as_bytes() == &[0; 32] {
            Err(LifecycleModelError::CorruptEncoding)
        } else {
            Ok(Self(value))
        }
    }
}
