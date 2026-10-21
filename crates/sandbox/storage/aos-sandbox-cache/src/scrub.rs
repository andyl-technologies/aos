//! Root-relative immutable backing scrub and quarantine decisions.
//!
//! Scrub observations are minted by a trusted root custodian after reopening
//! the canonical name beneath the protected root.  They bind two identity and
//! seal observations around validation.  Raw paths, file descriptors, device
//! numbers, and inode numbers never enter this model.  Quarantine prevents new
//! reads but deliberately makes no secure-erasure claim.

use aos_sandbox_model::{ObjectDescriptor, ObjectDigest, OperationId};

use aos_sandbox_protocol::cache_state::CatalogPresenceV1;

use super::admission::{AdmissionError, CacheAdmissionStateV1};
use super::domain::{
    CacheAuthorityError, CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheAuthorityScopeV1,
    VerifiedCacheCapabilityV1,
};

pub use aos_sandbox_protocol::cache_state::scrub_data::BackingObservationV1;
pub(crate) use aos_sandbox_protocol::cache_state::scrub_data::scrub_subject;
use aos_sandbox_protocol::cache_state::scrub_data::{ScrubEvidenceDataV1, scrub_digest};

/// Binds a live verifier-issued scrub to its exact historical DATA.
///
/// Historical DATA cannot construct the Native wrapper.
///
/// ```compile_fail
/// use aos_sandbox_protocol::cache_state::scrub_data::ScrubEvidenceDataV1;
/// fn issue(data: ScrubEvidenceDataV1) {
///     let _ = aos_sandbox_cache::scrub::ScrubEvidenceV1(data);
/// }
/// ```
///
/// The historical projection cannot mutate the verifier-issued wrapper.
///
/// ```compile_fail
/// use aos_sandbox_cache::scrub::ScrubEvidenceV1;
/// fn rewrite(mut proof: ScrubEvidenceV1) {
///     proof.operation = aos_sandbox_model::OperationId::from_bytes([1; 16]);
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrubEvidenceV1(ScrubEvidenceDataV1);

impl std::ops::Deref for ScrubEvidenceV1 {
    type Target = ScrubEvidenceDataV1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ScrubEvidenceV1 {
    pub(crate) const fn authority_binding(&self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.0.authority_scope, self.0.authority_record)
    }

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
        let authority_scope = crate::domain::new_cache_authority_scope_v1(
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
        let mut evidence = ScrubEvidenceDataV1 {
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
        Self(evidence).validate()
    }

    /// Validates the historical fields without replacing live authority.
    ///
    /// # Errors
    ///
    /// Returns [`ScrubError`] for malformed observations or commitment.
    pub fn validate(self) -> Result<Self, ScrubError> {
        self.0.validate()?;
        Ok(self)
    }

    pub(crate) fn recover_historical(data: ScrubEvidenceDataV1) -> Self {
        Self(data)
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
    Catalog(#[from] aos_sandbox_protocol::cache_state::CatalogError),
    /// Protected scrub or quarantine lifecycle authority failed.
    #[error(transparent)]
    Authority(#[from] CacheAuthorityError),
}

impl From<aos_sandbox_protocol::cache_state::scrub_data::ScrubDataErrorV1> for ScrubError {
    fn from(error: aos_sandbox_protocol::cache_state::scrub_data::ScrubDataErrorV1) -> Self {
        use aos_sandbox_protocol::cache_state::scrub_data::ScrubDataErrorV1;
        match error {
            ScrubDataErrorV1::InvalidObservation => Self::InvalidObservation,
            ScrubDataErrorV1::Catalog(error) => Self::Catalog(error),
        }
    }
}
