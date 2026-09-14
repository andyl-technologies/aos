//! Root-relative immutable backing scrub and quarantine decisions.
//!
//! Scrub observations are minted by a trusted root custodian after reopening
//! the canonical name beneath the protected root.  They bind two identity and
//! seal observations around validation.  Raw paths, file descriptors, device
//! numbers, and inode numbers never enter this model.  Quarantine prevents new
//! reads but deliberately makes no secure-erasure claim.

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

use super::admission::{AdmissionError, CacheAdmissionStateV1};
use super::catalog::{BackingObjectIdentityV1, CatalogPresenceV1, ImmutableSealV1};
use super::domain::{
    CacheAuthorityError, CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheAuthorityScopeV1,
    VerifiedCacheCapabilityV1, object_descriptor_commitment,
};

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
    fn validate(self) -> Result<Self, ScrubError> {
        self.seal.validate()?;
        if self.root_custody.as_bytes() == &[0; 32]
            || self.root_generation == 0
            || self.canonical_name.as_bytes() == &[0; 32]
            || self.size == 0
            || !self.read_only
            || !self.confined_resolution
        {
            return Err(ScrubError::InvalidObservation);
        }
        Ok(self)
    }
}

/// Binds repeated physical observations to one exact catalog generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrubEvidenceV1 {
    /// Idempotent scrub operation.
    pub(crate) operation: OperationId,
    /// Catalog generation being verified.
    pub(crate) catalog_digest: ObjectDigest,
    /// Observation immediately after root-relative reopen.
    pub(crate) before_validation: BackingObservationV1,
    /// Observation repeated after digest/size/seal validation.
    pub(crate) after_validation: BackingObservationV1,
    /// Digest of the verified object bytes.
    pub(crate) content_digest: ObjectDigest,
    /// Digest of the complete trusted scrub evidence.
    pub(crate) digest: ObjectDigest,
    pub(crate) authority_scope: CacheAuthorityScopeV1,
    pub(crate) authority_record: ObjectDigest,
}

impl ScrubEvidenceV1 {
    /// Constructs evidence from repeated trusted physical observations.
    ///
    /// # Errors
    ///
    /// Returns [`ScrubError::InvalidObservation`] when the observations are
    /// incomplete, unstable, or sentinel-valued.
    pub fn from_verified(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        state: &CacheAdmissionStateV1,
        operation: OperationId,
        object: &ObjectDescriptor,
        before_validation: BackingObservationV1,
        after_validation: BackingObservationV1,
        content_digest: ObjectDigest,
        now: u64,
    ) -> Result<Self, ScrubError> {
        let entry = state
            .catalog_entry(object)
            .ok_or(ScrubError::UnknownObject)?;
        let subject = scrub_subject(object, before_validation, after_validation, content_digest);
        let authority_scope = CacheAuthorityScopeV1::new(
            entry.partition,
            subject,
            Some(operation),
            entry.digest,
            entry.root_custody,
            entry.generation,
            capability.scope().valid_until(),
        )?;
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::Scrub,
            authority_scope,
            now,
        )?;
        let mut evidence = Self {
            operation,
            catalog_digest: entry.digest,
            before_validation,
            after_validation,
            content_digest,
            digest: ObjectDigest::from_bytes([0; 32]),
            authority_scope,
            authority_record: capability.record_digest(),
        };
        evidence.digest = scrub_digest(&evidence);
        evidence.validate()
    }

    /// Validates stable repeated observations and the evidence digest.
    ///
    /// # Errors
    ///
    /// Returns [`ScrubError::InvalidObservation`] for sentinel, unstable, or
    /// incorrectly committed observations.
    pub fn validate(self) -> Result<Self, ScrubError> {
        self.before_validation.validate()?;
        self.after_validation.validate()?;
        if self.operation.as_bytes() == &[0; 16]
            || self.catalog_digest.as_bytes() == &[0; 32]
            || self.content_digest.as_bytes() == &[0; 32]
            || self.before_validation != self.after_validation
            || self.digest != scrub_digest(&self)
        {
            return Err(ScrubError::InvalidObservation);
        }
        Ok(self)
    }
}

/// Selects the fail-closed result of comparing scrub evidence with catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrubDecisionV1 {
    /// All identity, size, digest, seal, and root checks match.
    Healthy,
    /// At least one immutable physical fact differs; readers must be denied.
    Quarantine {
        /// Exact evidence retained for diagnosis and recovery.
        evidence_digest: ObjectDigest,
    },
}

/// Evaluates and applies scrub evidence to one catalog entry.
///
/// # Errors
///
/// Returns [`ScrubError`] for malformed evidence, absent/stale catalog state,
/// or an invalid quarantine transition.
pub fn apply_scrub(
    owner: &CacheAuthorityOwner<'_, '_>,
    capability: &VerifiedCacheCapabilityV1,
    state: &mut CacheAdmissionStateV1,
    object: &ObjectDescriptor,
    evidence: ScrubEvidenceV1,
    now: u64,
) -> Result<ScrubDecisionV1, ScrubError> {
    let evidence = evidence.validate()?;
    owner.validate_for_effect_at(
        capability,
        CacheAuthorityPurposeV1::Scrub,
        evidence.authority_scope,
        now,
    )?;
    if capability.record_digest() != evidence.authority_record {
        return Err(ScrubError::InvalidObservation);
    }
    let entry = state
        .catalog_entry(object)
        .ok_or(ScrubError::UnknownObject)?
        .clone();
    if entry.digest != evidence.catalog_digest {
        return Err(ScrubError::StaleCatalog);
    }

    let observed = evidence.after_validation;
    let matches = observed.backing == entry.backing
        && observed.root_custody == entry.root_custody
        && observed.root_generation == entry.root_generation
        && observed.canonical_name == entry.canonical_name
        && observed.size == entry.descriptor.encoded_size()
        && observed.seal == entry.seal
        && evidence.content_digest == entry.descriptor.digest()
        && entry.presence == CatalogPresenceV1::Committed;
    if matches {
        return Ok(ScrubDecisionV1::Healthy);
    }

    let quarantined = entry.transition(CatalogPresenceV1::Quarantined)?;
    state.replace_catalog_entry(entry.digest, quarantined)?;
    Ok(ScrubDecisionV1::Quarantine {
        evidence_digest: evidence.digest,
    })
}

/// Restores a quarantined entry only after a fresh exact protected scrub.
///
/// # Errors
///
/// Returns [`ScrubError`] unless every immutable fact matches the quarantined
/// catalog generation and the scrub capability remains current.
pub fn repair_quarantined(
    owner: &CacheAuthorityOwner<'_, '_>,
    capability: &VerifiedCacheCapabilityV1,
    state: &mut CacheAdmissionStateV1,
    object: &ObjectDescriptor,
    evidence: ScrubEvidenceV1,
    now: u64,
) -> Result<ObjectDigest, ScrubError> {
    let evidence = evidence.validate()?;
    owner.validate_for_effect_at(
        capability,
        CacheAuthorityPurposeV1::Scrub,
        evidence.authority_scope,
        now,
    )?;
    let entry = state
        .catalog_entry(object)
        .ok_or(ScrubError::UnknownObject)?
        .clone();
    let observed = evidence.after_validation;
    if entry.presence != CatalogPresenceV1::Quarantined
        || entry.digest != evidence.catalog_digest
        || observed.backing != entry.backing
        || observed.root_custody != entry.root_custody
        || observed.root_generation != entry.root_generation
        || observed.canonical_name != entry.canonical_name
        || observed.size != entry.descriptor.encoded_size()
        || observed.seal != entry.seal
        || evidence.content_digest != entry.descriptor.digest()
        || capability.record_digest() != evidence.authority_record
    {
        return Err(ScrubError::InvalidObservation);
    }
    let repaired = entry.transition(CatalogPresenceV1::Committed)?;
    state.replace_catalog_entry(entry.digest, repaired.clone())?;
    Ok(repaired.digest)
}

/// Reports scrub observation and quarantine failures.
#[derive(Debug, thiserror::Error)]
pub enum ScrubError {
    /// Physical evidence is incomplete, unstable, or incorrectly committed.
    #[error("cache scrub observation is invalid")]
    InvalidObservation,
    /// The requested catalog object is absent.
    #[error("cache scrub object is absent")]
    UnknownObject,
    /// Catalog state advanced after the scrub began.
    #[error("cache scrub catalog generation is stale")]
    StaleCatalog,
    /// Catalog mutation failed.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// Catalog validation failed.
    #[error(transparent)]
    Catalog(#[from] super::catalog::CatalogError),
    /// Protected scrub or quarantine lifecycle authority failed.
    #[error(transparent)]
    Authority(#[from] CacheAuthorityError),
}

pub(crate) fn scrub_subject(
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

fn scrub_digest(evidence: &ScrubEvidenceV1) -> ObjectDigest {
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
