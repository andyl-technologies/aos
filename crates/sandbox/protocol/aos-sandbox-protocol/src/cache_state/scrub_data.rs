//! Passive repeated backing observations used by canonical Cache recovery.
//!
//! Fields and commitments describe historical DATA. They neither establish a
//! native observation nor issue the Native ScrubEvidence verifier wrapper.

use aos_sandbox_model::{ObjectDescriptor, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

use super::{BackingObjectIdentityV1, ImmutableSealV1, object_descriptor_commitment};
use super::authority_record::CacheAuthorityScopeV1;

/// Captures one stable protected-root-relative backing observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackingObservationV1 {
    /// Opaque root custody generation digest.
    pub root_custody: ObjectDigest,
    /// Exact protected root generation reopened for this observation.
    pub root_generation: u64,
    /// Opaque digest of the derived canonical relative name.
    pub canonical_name: ObjectDigest,
    /// Stable backing identity under that root.
    pub backing: BackingObjectIdentityV1,
    /// Exact regular-file or snapshot byte size.
    pub size: u64,
    /// Independently measured immutable seal.
    pub seal: ImmutableSealV1,
    /// Whether the reopened description is read-only.
    pub read_only: bool,
    /// Whether root-relative resolution prohibited symlinks and mount crossing.
    pub confined_resolution: bool,
}

impl BackingObservationV1 {
    /// Validates complete, read-only confined historical observation DATA.
    ///
    /// # Errors
    ///
    /// Returns [`ScrubDataErrorV1`] for an invalid seal or missing fixed facts.
    pub fn validate(self) -> Result<Self, ScrubDataErrorV1> {
        self.seal.validate()?;
        if self.root_custody.as_bytes() == &[0; 32]
            || self.root_generation == 0
            || self.canonical_name.as_bytes() == &[0; 32]
            || self.size == 0
            || !self.read_only
            || !self.confined_resolution
        {
            return Err(ScrubDataErrorV1::InvalidObservation);
        }
        Ok(self)
    }
}

/// Binds repeated physical observations to one exact catalog generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrubEvidenceDataV1 {
    /// Idempotent scrub operation.
    pub operation: OperationId,
    /// Catalog generation being verified.
    pub catalog_digest: ObjectDigest,
    /// Observation immediately after root-relative reopen.
    pub before_validation: BackingObservationV1,
    /// Observation repeated after digest/size/seal validation.
    pub after_validation: BackingObservationV1,
    /// Digest of the verified object bytes.
    pub content_digest: ObjectDigest,
    /// Digest of the complete historical scrub observation.
    pub digest: ObjectDigest,
    /// Historical authority scope commitment; no current permission.
    pub authority_scope: CacheAuthorityScopeV1,
    /// Historical authority-record digest; no current permission.
    pub authority_record: ObjectDigest,
}

impl ScrubEvidenceDataV1 {
    /// Returns the exact historical scrub-scope and record commitments.
    #[must_use]
    pub const fn authority_binding(&self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.authority_scope, self.authority_record)
    }

    /// Validates stable repeated observations and the evidence digest.
    ///
    /// # Errors
    ///
    /// Returns [`ScrubDataErrorV1::InvalidObservation`] for sentinel, unstable, or
    /// incorrectly committed observations.
    pub fn validate(self) -> Result<Self, ScrubDataErrorV1> {
        self.before_validation.validate()?;
        self.after_validation.validate()?;
        if self.operation.as_bytes() == &[0; 16]
            || self.catalog_digest.as_bytes() == &[0; 32]
            || self.content_digest.as_bytes() == &[0; 32]
            || self.before_validation != self.after_validation
            || self.digest != scrub_digest(&self)
        {
            return Err(ScrubDataErrorV1::InvalidObservation);
        }
        Ok(self)
    }
}

/// Reports malformed historical scrub observations.
#[derive(Debug, thiserror::Error)]
pub enum ScrubDataErrorV1 {
    /// Repeated physical facts are incomplete, unstable or incorrectly committed.
    #[error("cache scrub observation is invalid")]
    InvalidObservation,
    /// The historical seal fails its canonical catalog validation.
    #[error(transparent)]
    Catalog(#[from] super::CatalogError),
}

/// Commits the exact descriptor and repeated historical observations.
pub fn scrub_subject(
    object: &ObjectDescriptor,
    before: BackingObservationV1,
    after: BackingObservationV1,
    content_digest: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.scrub-subject.v1\0");
    hasher.update(object_descriptor_commitment(object).as_bytes());
    update_observation(&mut hasher, before);
    update_observation(&mut hasher, after);
    hasher.update(content_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Commits the complete historical scrub fields, excluding authority DATA.
#[doc(hidden)]
pub fn scrub_digest(evidence: &ScrubEvidenceDataV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.scrub-evidence.v1\0");
    hasher.update(evidence.operation.as_bytes());
    hasher.update(evidence.catalog_digest.as_bytes());
    update_observation(&mut hasher, evidence.before_validation);
    update_observation(&mut hasher, evidence.after_validation);
    hasher.update(evidence.content_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn update_observation(hasher: &mut Sha256, observation: BackingObservationV1) {
    hasher.update(observation.root_custody.as_bytes());
    hasher.update(observation.root_generation.to_be_bytes());
    hasher.update(observation.canonical_name.as_bytes());
    hasher.update(observation.backing.as_bytes());
    hasher.update(observation.size.to_be_bytes());
    hasher.update([observation.seal.profile as u8]);
    hasher.update(observation.seal.measurement.as_bytes());
    hasher.update([u8::from(observation.read_only)]);
    hasher.update([u8::from(observation.confined_resolution)]);
}
