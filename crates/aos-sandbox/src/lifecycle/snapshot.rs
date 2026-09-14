//! Checked portable-snapshot retention evidence for lifecycle commit.
//!
//! The decoder accepts only the core deterministic-CBOR snapshot format and
//! proves that every embedded retention claim has one position-matched durable
//! acknowledgement. The resulting value carries no lease token or authority.

use aos_sandbox_core::format::{decode_snapshot, encode_snapshot, DecodeLimits};
use aos_sandbox_core::model::snapshot::{RetentionClaim, Snapshot};
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    LifecycleModelError, LifecycleProtectedRetentionLedgerV1, LifecycleRetentionAcknowledgementV1,
    LifecycleRetentionClaimDigestV1, LifecycleSnapshotManifestDigestV1,
    MAXIMUM_LIFECYCLE_EXPECTATIONS,
};

/// Commits the exact snapshot tombstone document published by deletion.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleSnapshotTombstoneDigestV1(ObjectDigest);

impl LifecycleSnapshotTombstoneDigestV1 {
    /// Commits exact canonical tombstone bytes in a dedicated domain.
    #[must_use]
    pub fn commit(bytes: &[u8]) -> Self {
        Self(ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.snapshot-tombstone.v1\0")
                .chain_update(bytes)
                .finalize()
                .into(),
        ))
    }

    /// Returns the underlying purpose-separated commitment.
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

/// Retains a decoded core snapshot and its complete acknowledgement proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleValidatedSnapshotV1 {
    snapshot: Snapshot,
    manifest: LifecycleSnapshotManifestDigestV1,
    acknowledgements: Vec<LifecycleRetentionAcknowledgementV1>,
}

impl LifecycleValidatedSnapshotV1 {
    /// Decodes canonical snapshot bytes and proves complete receipt coverage.
    ///
    /// `limits` remains caller selected, but this layer additionally applies
    /// the lifecycle expectation ceiling before retaining acknowledgements.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for invalid snapshot CBOR,
    /// excessive claims, a missing acknowledgement, or any mismatched receipt.
    pub fn decode(
        canonical_snapshot: &[u8],
        limits: DecodeLimits,
        retention_ledger: &LifecycleProtectedRetentionLedgerV1,
        acknowledgements: Vec<LifecycleRetentionAcknowledgementV1>,
    ) -> Result<Self, LifecycleModelError> {
        let snapshot = decode_snapshot(canonical_snapshot, limits)
            .map_err(|_| LifecycleModelError::InvalidModel)?;
        if encode_snapshot(&snapshot) != canonical_snapshot {
            return Err(LifecycleModelError::InvalidModel);
        }
        let claims = snapshot.retention_claims();
        if claims.is_empty()
            || claims.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || acknowledgements.len() != claims.len()
            || claims.iter().zip(&acknowledgements).enumerate().any(
                |(index, (claim, acknowledgement))| {
                    u32::try_from(index).ok() != Some(acknowledgement.claim_index())
                        || LifecycleRetentionClaimDigestV1::from_claim(claim)
                            != acknowledgement.claim()
                        || claim_receipt(claim) != acknowledgement.claim_receipt()
                        || !acknowledgement.is_bound_to(retention_ledger)
                },
            )
            || acknowledgements
                .iter()
                .enumerate()
                .any(|(index, acknowledgement)| {
                    acknowledgements[..index].iter().any(|previous| {
                        previous.resource() == acknowledgement.resource()
                            && previous.holder() == acknowledgement.holder()
                    })
                })
            || acknowledgements.first().is_some_and(|first| {
                acknowledgements.iter().any(|acknowledgement| {
                    acknowledgement.revision() != first.revision()
                        || acknowledgement.ledger() != first.ledger()
                })
            })
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            snapshot,
            manifest: LifecycleSnapshotManifestDigestV1::commit(canonical_snapshot),
            acknowledgements,
        })
    }

    /// Borrows the fully decoded portable snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// Returns the commitment to the exact canonical snapshot bytes.
    #[must_use]
    pub const fn manifest(&self) -> LifecycleSnapshotManifestDigestV1 {
        self.manifest
    }

    /// Borrows the complete position-matched acknowledgement set.
    #[must_use]
    pub fn acknowledgements(&self) -> &[LifecycleRetentionAcknowledgementV1] {
        &self.acknowledgements
    }
}

fn claim_receipt(claim: &RetentionClaim) -> aos_sandbox_core::ObjectDigest {
    match claim {
        RetentionClaim::Storage { receipt, .. }
        | RetentionClaim::Content { receipt, .. }
        | RetentionClaim::Nix { receipt, .. }
        | RetentionClaim::Service { receipt, .. }
        | RetentionClaim::Secret { receipt, .. } => receipt.digest(),
    }
}
