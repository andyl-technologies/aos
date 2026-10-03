//! Opaque journal verification for lifecycle records and checkpoints.

use aos_sandbox_core::ObjectDigest;

use super::{LifecycleModelError, MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS};

/// Proves a journal verifier admitted an exact replay/checkpoint set.
///
/// The value has no public scalar constructor. Journal custody issues it only
/// after authenticating the namespace, compaction floor, and exact digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleReplayVerificationV1 {
    pub(super) authority: ObjectDigest,
    accepted_records: Vec<ObjectDigest>,
    accepted_checkpoints: Vec<ObjectDigest>,
}

impl LifecycleReplayVerificationV1 {
    pub(crate) fn from_verified_authority(
        authority: ObjectDigest,
        accepted_records: Vec<ObjectDigest>,
        accepted_checkpoints: Vec<ObjectDigest>,
    ) -> Result<Self, LifecycleModelError> {
        if authority.as_bytes() == &[0; 32]
            || accepted_records.len() > MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS
            || accepted_checkpoints.len() > MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS
            || accepted_records
                .iter()
                .chain(&accepted_checkpoints)
                .any(|digest| digest.as_bytes() == &[0; 32])
            || !accepted_records.windows(2).all(|pair| pair[0] < pair[1])
            || !accepted_checkpoints
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            authority,
            accepted_records,
            accepted_checkpoints,
        })
    }

    /// Returns the opaque verifier-issued authority commitment.
    #[must_use]
    pub const fn authority(&self) -> ObjectDigest {
        self.authority
    }

    pub(super) fn accepts_record(&self, digest: ObjectDigest) -> bool {
        self.accepted_records.binary_search(&digest).is_ok()
    }

    pub(super) fn accepts_checkpoint(&self, digest: ObjectDigest) -> bool {
        self.accepted_checkpoints.binary_search(&digest).is_ok()
    }
}
