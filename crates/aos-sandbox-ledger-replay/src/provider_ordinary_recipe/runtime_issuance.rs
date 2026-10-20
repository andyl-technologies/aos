//! Shares the historical runtime-evidence schema and timing cross-links.
//!
//! The concrete Domain owner retains the separate native/historical ledger
//! provenance join. Decoding these fields supplies no current Host observation,
//! session, holder or grant.
//!
//! ```text
//! runtime: {binding_revision, binding_digest, publication_digest,
//!           assignment_digest, lease_generation, lease_digest,
//!           payload_scope_handle, boot_id, clock_provenance,
//!           observed_wall_seconds, observed_boottime_nanoseconds,
//!           expires_wall_seconds, deadline_boottime_nanoseconds}
//! ```

/// Defines the existing private runtime schema and timing comparison.
#[macro_export]
macro_rules! define_provider_runtime_issuance_data_recipe_v1 {
    (invalid_metadata: $invalid_metadata:expr, crosslink: $crosslink:expr) => {
        /// Retains immutable runtime-observation audit facts behind a local capability.
        ///
        /// This value is not a live proof, including when deserialization succeeds.
        /// Registry replay checks its claims, timing, and protected historical binding;
        /// online admission must separately acquire current runtime authority.
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(deny_unknown_fields)]
        pub struct RuntimeIssuanceEvidenceV1 {
            binding_revision: u64,
            binding_digest: ObjectDigest,
            publication_digest: ObjectDigest,
            assignment_digest: ObjectDigest,
            lease_generation: u64,
            lease_digest: ObjectDigest,
            payload_scope_handle: [u8; 32],
            boot_id: [u8; 16],
            clock_provenance: [u8; 16],
            observed_wall_seconds: i64,
            observed_boottime_nanoseconds: u64,
            expires_wall_seconds: i64,
            deadline_boottime_nanoseconds: u64,
        }
        
        impl RuntimeIssuanceEvidenceV1 {
            pub(super) fn validate_for(
                &self,
                metadata: &IssuanceDecisionMetadataV1,
            ) -> Result<(), PublisherAuthorityError> {
                let duration = self
                    .expires_wall_seconds
                    .checked_sub(self.observed_wall_seconds)
                    .and_then(|seconds| u64::try_from(seconds).ok())
                    .filter(|seconds| (1..=30).contains(seconds))
                    .and_then(|seconds| seconds.checked_mul(1_000_000_000))
                    .ok_or($invalid_metadata)?;
                if self.binding_revision == 0
                    || self.lease_generation == 0
                    || self.payload_scope_handle == [0; 32]
                    || [
                        self.binding_digest,
                        self.publication_digest,
                        self.assignment_digest,
                        self.lease_digest,
                    ]
                    .iter()
                    .any(|digest| digest.as_bytes() == &[0; 32])
                    || self.boot_id == [0; 16]
                    || self.clock_provenance == [0; 16]
                    || self.boot_id != metadata.boot_id()
                    || self.clock_provenance != metadata.clock_provenance()
                    || self.observed_boottime_nanoseconds.checked_add(duration)
                        != Some(self.deadline_boottime_nanoseconds)
                    || metadata.observed_wall_seconds() < self.observed_wall_seconds
                    || metadata.observed_wall_seconds() >= self.expires_wall_seconds
                    || metadata.observed_boottime_nanoseconds() < self.observed_boottime_nanoseconds
                    || metadata.observed_boottime_nanoseconds() >= self.deadline_boottime_nanoseconds
                {
                    return Err($crosslink);
                }
                let wall_elapsed = metadata
                    .observed_wall_seconds()
                    .checked_sub(self.observed_wall_seconds)
                    .and_then(|seconds| u64::try_from(seconds).ok())
                    .and_then(|seconds| seconds.checked_mul(1_000_000_000))
                    .ok_or($crosslink)?;
                let boot_elapsed =
                    metadata.observed_boottime_nanoseconds() - self.observed_boottime_nanoseconds;
                if wall_elapsed.abs_diff(boot_elapsed)
                    > aos_sandbox_core::ownership_lease::CLOCK_PAIR_TOLERANCE_NANOSECONDS
                {
                    return Err($crosslink);
                }
                Ok(())
            }
        }
    };
}
