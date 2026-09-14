//! Protected source-release authority for publisher admission.
//!
//! A content digest, pathname, descriptor, or producer signature is not release
//! authority. This registry retains controller decisions that explicitly permit
//! one authenticated holder to move one exact raw-content object into one exact
//! project cache domain. Revocation denies new admissions but cannot cancel an
//! already retained completion permit.

use std::collections::BTreeMap;

use aos_sandbox_core::{
    ObjectDescriptor, ObjectDigest, PrincipalId, ProjectId, ResourceId,
    model::{CacheDomain, CacheDomainKind},
};

use super::model::{digest_parts, validate_nonzero};

/// States whether a source release can authorize a new admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceReleaseStateV1 {
    /// New exact admissions may cite this release before expiry.
    Active,
    /// New use is denied; already-retained permits remain obligations.
    Revoked,
}

/// Retains one immutable source-release decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReleaseV1 {
    /// Stable release identity used by the publisher request commitment.
    pub release_digest: ObjectDigest,
    /// Authenticated holder allowed to exercise the decision.
    pub holder: PrincipalId,
    /// Destination project.
    pub project: ProjectId,
    /// Destination logical cache resource.
    pub cache_resource: ResourceId,
    /// Destination disclosure domain.
    pub cache_domain: CacheDomain,
    /// Exact released content.
    pub content: ObjectDescriptor,
    /// Protected producer/output evidence commitment.
    pub producer_evidence: ObjectDigest,
    /// Release-policy revision commitment.
    pub release_policy: ObjectDigest,
    /// Inclusive controller wall-clock start.
    pub not_before_seconds: i64,
    /// Exclusive controller wall-clock end.
    pub expires_seconds: i64,
    /// Current immutable release state.
    pub state: SourceReleaseStateV1,
}

impl SourceReleaseV1 {
    /// Constructs one active release and derives its stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`SourceReleaseError::InvalidRelease`] for sentinel identities,
    /// invalid validity, or a non-project destination domain.
    #[allow(clippy::too_many_arguments)]
    pub fn active(
        holder: PrincipalId,
        project: ProjectId,
        cache_resource: ResourceId,
        cache_domain: CacheDomain,
        content: ObjectDescriptor,
        producer_evidence: ObjectDigest,
        release_policy: ObjectDigest,
        not_before_seconds: i64,
        expires_seconds: i64,
    ) -> Result<Self, SourceReleaseError> {
        let mut release = Self {
            release_digest: ObjectDigest::from_bytes([0; 32]),
            holder,
            project,
            cache_resource,
            cache_domain,
            content,
            producer_evidence,
            release_policy,
            not_before_seconds,
            expires_seconds,
            state: SourceReleaseStateV1::Active,
        };
        release.release_digest = source_release_digest(&release);
        release.validate()
    }

    /// Validates and derives the release identity from all immutable fields.
    ///
    /// The supplied value's `release_digest` must equal the domain-separated
    /// digest derived by this method; callers cannot select a convenient handle.
    ///
    /// # Errors
    ///
    /// Returns [`SourceReleaseError::InvalidRelease`] for sentinel identities,
    /// malformed validity, non-project domain, or a digest mismatch.
    pub fn validate(self) -> Result<Self, SourceReleaseError> {
        validate_nonzero(&[
            ("source release", self.release_digest.as_bytes()),
            ("source holder", self.holder.as_bytes()),
            ("source project", self.project.as_bytes()),
            ("source cache resource", self.cache_resource.as_bytes()),
            (
                "source cache domain",
                self.cache_domain.domain_id().as_bytes(),
            ),
            (
                "source producer evidence",
                self.producer_evidence.as_bytes(),
            ),
            ("source release policy", self.release_policy.as_bytes()),
        ])
        .map_err(|_| SourceReleaseError::InvalidRelease)?;
        if self.not_before_seconds >= self.expires_seconds
            || self.cache_domain.kind() != CacheDomainKind::Project
            || self.release_digest != source_release_digest(&self)
        {
            return Err(SourceReleaseError::InvalidRelease);
        }
        Ok(self)
    }

    /// Checks exact current use against independently authenticated facts.
    ///
    /// # Errors
    ///
    /// Returns [`SourceReleaseError`] when revoked, expired, or any holder,
    /// project, resource, domain, or content fact differs.
    pub(super) fn authorize(
        &self,
        holder: PrincipalId,
        project: ProjectId,
        resource: ResourceId,
        domain: CacheDomain,
        content: &ObjectDescriptor,
        now_seconds: i64,
    ) -> Result<(), SourceReleaseError> {
        if self.state != SourceReleaseStateV1::Active {
            return Err(SourceReleaseError::Revoked);
        }
        if now_seconds < self.not_before_seconds || now_seconds >= self.expires_seconds {
            return Err(SourceReleaseError::Expired);
        }
        if self.holder != holder
            || self.project != project
            || self.cache_resource != resource
            || self.cache_domain != domain
            || &self.content != content
        {
            return Err(SourceReleaseError::ScopeMismatch);
        }
        Ok(())
    }
}

/// Reports source-release persistence and authorization failures.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceReleaseError {
    /// Release facts or derived identity are malformed.
    #[error("invalid publisher source-release record")]
    InvalidRelease,
    /// A release identity was reused with different immutable facts.
    #[error("publisher source-release identity conflicts with retained state")]
    IdentityConflict,
    /// No release has the requested commitment.
    #[error("publisher source-release record is absent")]
    Absent,
    /// Release is outside its controller-observed validity interval.
    #[error("publisher source-release record is expired")]
    Expired,
    /// Release was revoked for new use.
    #[error("publisher source-release record is revoked")]
    Revoked,
    /// Independently authenticated destination or content facts differ.
    #[error("publisher source-release scope does not match the request")]
    ScopeMismatch,
    /// Registry capacity is exhausted.
    #[error("publisher source-release registry is full")]
    Capacity,
    /// Complete replay contains malformed or conflicting state.
    #[error("publisher source-release replay is corrupt")]
    CorruptState,
}

/// Holds bounded, fully validated source-release state.
#[derive(Clone, Debug)]
pub struct SourceReleaseRegistry {
    releases: BTreeMap<[u8; 32], SourceReleaseV1>,
    maximum_releases: usize,
}

/// Borrows a release after exact current authorization.
///
/// The private field prevents construction from a decoded or caller-created
/// [`SourceReleaseV1`]. Its lifetime ties use to the fully replayed registry.
#[derive(Debug)]
pub struct AuthorizedSourceRelease<'registry> {
    release: &'registry SourceReleaseV1,
}

impl AuthorizedSourceRelease<'_> {
    /// Returns the exact protected release digest committed by the request.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.release.release_digest
    }

    pub(super) const fn release(&self) -> &SourceReleaseV1 {
        self.release
    }
}

impl SourceReleaseRegistry {
    /// Replays a complete bounded registry before allowing lookups.
    ///
    /// # Errors
    ///
    /// Returns [`SourceReleaseError`] for a zero/excessive limit, malformed
    /// record, duplicate identity, or capacity excess.
    pub fn replay(
        maximum_releases: usize,
        releases: impl IntoIterator<Item = SourceReleaseV1>,
    ) -> Result<Self, SourceReleaseError> {
        if maximum_releases == 0 || maximum_releases > 65_536 {
            return Err(SourceReleaseError::Capacity);
        }
        let mut registry = Self {
            releases: BTreeMap::new(),
            maximum_releases,
        };
        for release in releases {
            let release = release.validate()?;
            let key = *release.release_digest.as_bytes();
            if let Some(previous) = registry.releases.get(&key) {
                let mut expected = previous.clone();
                expected.state = SourceReleaseStateV1::Revoked;
                if previous.state != SourceReleaseStateV1::Active || release != expected {
                    return Err(SourceReleaseError::IdentityConflict);
                }
            } else if registry.releases.len() >= maximum_releases {
                return Err(SourceReleaseError::Capacity);
            }
            registry.releases.insert(key, release);
        }
        Ok(registry)
    }

    /// Installs one fresh immutable release decision.
    ///
    /// Exact replay is idempotent; differing use of the same digest fails.
    ///
    /// # Errors
    ///
    /// Returns [`SourceReleaseError`] for malformed facts, conflicting identity,
    /// or capacity exhaustion.
    pub(crate) fn install(
        &mut self,
        _owner: &super::SourceRegistryOwnerToken,
        release: SourceReleaseV1,
    ) -> Result<&SourceReleaseV1, SourceReleaseError> {
        let release = release.validate()?;
        let key = *release.release_digest.as_bytes();
        if let Some(existing) = self.releases.get(&key) {
            return if existing == &release {
                Ok(existing)
            } else {
                Err(SourceReleaseError::IdentityConflict)
            };
        }
        if self.releases.len() >= self.maximum_releases {
            return Err(SourceReleaseError::Capacity);
        }
        self.releases.insert(key, release);
        self.releases
            .get(&key)
            .ok_or(SourceReleaseError::CorruptState)
    }

    /// Resolves and authorizes one exact current source release.
    ///
    /// # Errors
    ///
    /// Returns [`SourceReleaseError`] for absence, revocation, expiry, or scope
    /// mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &self,
        release: ObjectDigest,
        holder: PrincipalId,
        project: ProjectId,
        resource: ResourceId,
        domain: CacheDomain,
        content: &ObjectDescriptor,
        now_seconds: i64,
    ) -> Result<AuthorizedSourceRelease<'_>, SourceReleaseError> {
        let record = self
            .releases
            .get(release.as_bytes())
            .ok_or(SourceReleaseError::Absent)?;
        record.authorize(holder, project, resource, domain, content, now_seconds)?;
        Ok(AuthorizedSourceRelease { release: record })
    }

    /// Revokes a release for new admissions while retaining its exact identity.
    ///
    /// # Errors
    ///
    /// Returns [`SourceReleaseError::Absent`] for an unknown release.
    pub(crate) fn revoke(
        &mut self,
        _owner: &super::SourceRegistryOwnerToken,
        release: ObjectDigest,
    ) -> Result<SourceReleaseV1, SourceReleaseError> {
        let current = self
            .releases
            .get_mut(release.as_bytes())
            .ok_or(SourceReleaseError::Absent)?;
        current.state = SourceReleaseStateV1::Revoked;
        Ok(current.clone())
    }
}

fn source_release_digest(release: &SourceReleaseV1) -> ObjectDigest {
    digest_parts(
        b"aos.sandbox.publisher.source-release.v1\0",
        &[
            release.holder.as_bytes(),
            release.project.as_bytes(),
            release.cache_resource.as_bytes(),
            &[domain_code(release.cache_domain)],
            release.cache_domain.domain_id().as_bytes(),
            release.content.media_type().as_str().as_bytes(),
            release.content.digest().as_bytes(),
            &release.content.encoded_size().to_be_bytes(),
            release.producer_evidence.as_bytes(),
            release.release_policy.as_bytes(),
            &release.not_before_seconds.to_be_bytes(),
            &release.expires_seconds.to_be_bytes(),
        ],
    )
}

pub(super) fn domain_code(domain: CacheDomain) -> u8 {
    use aos_sandbox_core::model::CacheDomainKind;

    match domain.kind() {
        CacheDomainKind::Private => 1,
        CacheDomainKind::Project => 2,
        CacheDomainKind::TrustDomain => 3,
        CacheDomainKind::Public => 4,
    }
}
