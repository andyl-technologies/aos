//! Opaque journal verification for lifecycle records and checkpoints.

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError;

use super::MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS;

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
        mut accepted_records: Vec<ObjectDigest>,
        mut accepted_checkpoints: Vec<ObjectDigest>,
    ) -> Result<Self, LifecycleModelError> {
        Self::from_verified_authority_decode_parts(
            authority,
            &mut accepted_records,
            &mut accepted_checkpoints,
        )
    }

    /// Validates the same model while retaining borrowed graph inputs on refusal.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_verified_authority_decode_parts(
        authority: ObjectDigest,
        accepted_records: &mut Vec<ObjectDigest>,
        accepted_checkpoints: &mut Vec<ObjectDigest>,
    ) -> Result<Self, LifecycleModelError> {
        if authority.as_bytes() == &[0; 32]
            || accepted_records.len() > MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS
            || accepted_checkpoints.len() > MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS
            || accepted_records
                .iter()
                .chain(accepted_checkpoints.iter())
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
            accepted_records: std::mem::take(accepted_records),
            accepted_checkpoints: std::mem::take(accepted_checkpoints),
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

#[cfg(test)]
mod decode_custody_tests {
    use super::*;

    #[test]
    fn refused_verifier_keeps_both_original_catalog_allocations() {
        let mut accepted = vec![ObjectDigest::from_bytes([1; 32])];
        let mut checkpoints = vec![ObjectDigest::from_bytes([2; 32])];
        let accepted_pointer = accepted.as_ptr();
        let checkpoint_pointer = checkpoints.as_ptr();

        assert!(LifecycleReplayVerificationV1::from_verified_authority_decode_parts(
            ObjectDigest::from_bytes([0; 32]), &mut accepted, &mut checkpoints,
        ).is_err());
        assert_eq!(accepted.as_ptr(), accepted_pointer);
        assert_eq!(checkpoints.as_ptr(), checkpoint_pointer);
        assert_eq!(accepted, vec![ObjectDigest::from_bytes([1; 32])]);
        assert_eq!(checkpoints, vec![ObjectDigest::from_bytes([2; 32])]);
    }
}

impl LifecycleReplayVerificationV1 {
    // Two actual writer clones each allocate their own accepted catalogs.
    // Input ownership is already funded; no caller supplies a row amount.
    pub(super) fn writer_clone_receiving_demand_v1(&self)->Option<aos_sandbox_model::ResourceVector> {
        let rows=self.accepted_records.len().checked_add(self.accepted_checkpoints.len())?;
        let bytes=rows.checked_mul(std::mem::size_of::<ObjectDigest>())?.checked_mul(4)?;
        Some(aos_sandbox_model::ResourceVector::ZERO
            .with(aos_sandbox_model::ResourceDimension::MemoryBytes,u64::try_from(bytes).ok()?)
            .with(aos_sandbox_model::ResourceDimension::MetadataEntries,u64::try_from(rows.checked_mul(2)?).ok()?))
    }
}
