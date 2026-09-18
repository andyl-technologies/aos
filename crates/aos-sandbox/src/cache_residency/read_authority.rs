//! Current independent read authority and opaque descriptor handoff plans.
//!
//! A catalog hit does not authorize disclosure.  Handoff requires a current
//! authority decision, a committed exact catalog generation, a retained pin,
//! and fresh physical revalidation.  The result is an opaque plan for a trusted
//! custodian; it contains no operating-system descriptor or path scalar.

use aos_sandbox_core::{
    AttachmentId, IncarnationId, ObjectDescriptor, ObjectDigest, PrincipalId, ProjectId, SandboxId,
    ViewId, model::CacheDomain,
};
use sha2::{Digest as _, Sha256};

use super::admission::CacheAdmissionStateV1;
use super::catalog::{BackingObjectIdentityV1, CatalogEntryV1, CatalogPresenceV1, ImmutableSealV1};
use super::domain::{
    AuthorizedLookupKey, CacheAuthorityError, CacheAuthorityOwner, CacheAuthorityPurposeV1,
    CacheAuthorityScopeV1, LookupAuthorityScopeV1, PhysicalPartitionId, VerifiedCacheCapabilityV1,
    object_descriptor_commitment, validate_object_descriptor,
};
use super::pin::{CachePinId, CachePinKindV1};

/// Carries a controller-resolved current read decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentReadAuthorityV1 {
    principal: PrincipalId,
    project: ProjectId,
    view: ViewId,
    attachment: AttachmentId,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: u64,
    partition: PhysicalPartitionId,
    disclosure: CacheDomain,
    lookup_key: AuthorizedLookupKey,
    descriptor: ObjectDescriptor,
    policy_revision: ObjectDigest,
    revocation_generation: u64,
    source_generation: u64,
    valid_until: u64,
    decision_digest: ObjectDigest,
}

impl CurrentReadAuthorityV1 {
    /// Issues one exact lookup/read decision from a current protected capability.
    ///
    /// # Errors
    ///
    /// Returns [`ReadAuthorityError`] for sentinel facts, scope mismatch, or a
    /// protected journal generation that is no longer current.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        principal: PrincipalId,
        project: ProjectId,
        view: ViewId,
        attachment: AttachmentId,
        sandbox: SandboxId,
        incarnation: IncarnationId,
        assignment_epoch: u64,
        partition: PhysicalPartitionId,
        disclosure: CacheDomain,
        descriptor: ObjectDescriptor,
        policy_revision: ObjectDigest,
        revocation_generation: u64,
        source_generation: u64,
        valid_until: u64,
        now: u64,
    ) -> Result<Self, ReadAuthorityError> {
        let authority_plan = read_authority_binding(
            principal,
            project,
            view,
            attachment,
            sandbox,
            incarnation,
            assignment_epoch,
            disclosure,
            policy_revision,
            source_generation,
        );
        let lookup_scope = LookupAuthorityScopeV1::from_verified_at(
            owner,
            capability,
            partition,
            principal,
            policy_revision,
            authority_plan,
            disclosure,
            &descriptor,
            revocation_generation,
            valid_until,
            now,
        )?;
        let authority = Self {
            principal,
            project,
            view,
            attachment,
            sandbox,
            incarnation,
            assignment_epoch,
            partition,
            disclosure,
            lookup_key: AuthorizedLookupKey::derive(partition, lookup_scope, &descriptor)
                .map_err(|_| ReadAuthorityError::InvalidAuthority)?,
            descriptor,
            policy_revision,
            revocation_generation,
            source_generation,
            valid_until,
            decision_digest: capability.record_digest(),
        };
        authority.clone().validate()?;
        Ok(authority)
    }

    /// Validates complete current authority and its non-sentinel generations.
    ///
    /// # Errors
    ///
    /// Returns [`ReadAuthorityError::InvalidAuthority`] for incomplete facts.
    fn validate(self) -> Result<Self, ReadAuthorityError> {
        if self.principal.as_bytes() == &[0; 16]
            || self.project.as_bytes() == &[0; 16]
            || self.view.as_bytes() == &[0; 16]
            || self.attachment.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.incarnation.as_bytes() == &[0; 16]
            || self.assignment_epoch == 0
            || self.policy_revision.as_bytes() == &[0; 32]
            || self.lookup_key.digest().as_bytes() == &[0; 32]
            || validate_object_descriptor(&self.descriptor).is_err()
            || self.revocation_generation == 0
            || self.source_generation == 0
            || self.valid_until == 0
            || self.decision_digest.as_bytes() == &[0; 32]
        {
            return Err(ReadAuthorityError::InvalidAuthority);
        }
        Ok(self)
    }

    fn validate_current(
        &self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        now: u64,
    ) -> Result<(), ReadAuthorityError> {
        let scope = CacheAuthorityScopeV1::new(
            self.partition,
            object_descriptor_commitment(&self.descriptor),
            None,
            read_authority_binding(
                self.principal,
                self.project,
                self.view,
                self.attachment,
                self.sandbox,
                self.incarnation,
                self.assignment_epoch,
                self.disclosure,
                self.policy_revision,
                self.source_generation,
            ),
            self.partition.backing().root(),
            self.revocation_generation,
            self.valid_until,
        )?;
        owner.validate_for_effect_at(capability, CacheAuthorityPurposeV1::Read, scope, now)?;
        if capability.record_digest() != self.decision_digest {
            return Err(ReadAuthorityError::InvalidAuthority);
        }
        Ok(())
    }

    pub(crate) fn revalidate_cache_lookup(
        &self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        now: u64,
    ) -> Result<
        (
            PhysicalPartitionId,
            &ObjectDescriptor,
            AuthorizedLookupKey,
            u64,
        ),
        ReadAuthorityError,
    > {
        self.validate_current(owner, capability, now)?;
        Ok((
            self.partition,
            &self.descriptor,
            self.lookup_key,
            self.valid_until,
        ))
    }
}

/// Captures fresh physical facts immediately before descriptor handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadBackingObservationV1 {
    /// Exact catalog generation reopened beneath protected root custody.
    catalog_digest: ObjectDigest,
    /// Exact protected root custody generation reopened for the read.
    root_custody: ObjectDigest,
    root_generation: u64,
    /// Canonical root-relative name commitment reopened for the read.
    canonical_name: ObjectDigest,
    /// Opaque stable backing identity.
    backing: BackingObjectIdentityV1,
    /// Re-observed immutable seal.
    seal: ImmutableSealV1,
    /// Re-observed exact size.
    size: u64,
    /// True only when root-relative resolution and read-only open succeeded.
    confined_read_only: bool,
    /// Digest of trusted before/after identity observation.
    evidence_digest: ObjectDigest,
    authority_scope: CacheAuthorityScopeV1,
}

impl ReadBackingObservationV1 {
    /// Issues a physical read observation from a protected verifier record.
    ///
    /// # Errors
    ///
    /// Returns [`ReadAuthorityError`] for malformed facts or stale scope.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        entry: &CatalogEntryV1,
        root_custody: ObjectDigest,
        root_generation: u64,
        canonical_name: ObjectDigest,
        backing: BackingObjectIdentityV1,
        seal: ImmutableSealV1,
        size: u64,
        confined_read_only: bool,
        valid_until: u64,
        now: u64,
    ) -> Result<Self, ReadAuthorityError> {
        if root_custody.as_bytes() == &[0; 32]
            || root_generation == 0
            || canonical_name.as_bytes() == &[0; 32]
            || size == 0
            || !confined_read_only
            || seal.validate().is_err()
        {
            return Err(ReadAuthorityError::PhysicalMismatch);
        }
        let subject = read_observation_subject(
            entry,
            root_custody,
            root_generation,
            canonical_name,
            backing,
            seal,
            size,
            confined_read_only,
        );
        let authority_scope = CacheAuthorityScopeV1::new(
            entry.partition,
            subject,
            None,
            entry.digest,
            entry.root_custody,
            entry.generation,
            valid_until,
        )?;
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::Read,
            authority_scope,
            now,
        )?;
        Ok(Self {
            catalog_digest: entry.digest,
            root_custody,
            root_generation,
            canonical_name,
            backing,
            seal,
            size,
            confined_read_only,
            evidence_digest: capability.record_digest(),
            authority_scope,
        })
    }

    fn validate_current(
        self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        now: u64,
    ) -> Result<(), ReadAuthorityError> {
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::Read,
            self.authority_scope,
            now,
        )?;
        if capability.record_digest() != self.evidence_digest {
            return Err(ReadAuthorityError::PhysicalMismatch);
        }
        Ok(())
    }
}

/// Authorizes one exact opaque descriptor handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescriptorHandoffPlanV1 {
    /// Exact current read-decision digest.
    authority_digest: ObjectDigest,
    /// Committed catalog generation.
    catalog_digest: ObjectDigest,
    /// Retained kernel-reference or backing-registration pin.
    pin: CachePinId,
    /// Complete immutable object descriptor.
    descriptor: ObjectDescriptor,
    /// Opaque backing identity.
    backing: BackingObjectIdentityV1,
    /// Fresh physical evidence.
    physical_evidence: ObjectDigest,
    /// Latest time at which the custodian may begin handoff.
    valid_until: u64,
    /// Digest of all handoff semantics.
    digest: ObjectDigest,
}

/// Confirms post-handoff physical identity and retained authority bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorHandoffReceiptV1 {
    /// Exact handoff plan.
    plan_digest: ObjectDigest,
    /// Post-handoff physical observation.
    post_handoff_evidence: ObjectDigest,
    /// Digest of the complete confirmation.
    digest: ObjectDigest,
}

impl DescriptorHandoffPlanV1 {
    pub(crate) const fn authority_digest(&self) -> ObjectDigest {
        self.authority_digest
    }

    pub(crate) const fn catalog_digest(&self) -> ObjectDigest {
        self.catalog_digest
    }

    pub(crate) fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }

    pub(crate) const fn physical_evidence(&self) -> ObjectDigest {
        self.physical_evidence
    }

    pub(crate) const fn valid_until(&self) -> u64 {
        self.valid_until
    }

    /// Returns the opaque backing identity for the trusted custodian.
    #[must_use]
    pub const fn backing(&self) -> BackingObjectIdentityV1 {
        self.backing
    }

    /// Returns the exact retained pin that must accompany handoff.
    #[must_use]
    pub const fn pin(&self) -> CachePinId {
        self.pin
    }

    /// Returns the canonical handoff-plan commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

impl DescriptorHandoffReceiptV1 {
    pub(crate) const fn plan_digest(self) -> ObjectDigest {
        self.plan_digest
    }

    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Prepares an opaque descriptor handoff from exact current facts.
///
/// # Errors
///
/// Returns [`ReadAuthorityError`] for expired authority, absent/noncommitted
/// catalog, mismatched pin, or physical revalidation failure.
pub fn prepare_descriptor_handoff(
    owner: &CacheAuthorityOwner<'_, '_>,
    capability: &VerifiedCacheCapabilityV1,
    observation_capability: &VerifiedCacheCapabilityV1,
    state: &CacheAdmissionStateV1,
    authority: CurrentReadAuthorityV1,
    pin_id: CachePinId,
    descriptor: ObjectDescriptor,
    observation: ReadBackingObservationV1,
    now: u64,
) -> Result<DescriptorHandoffPlanV1, ReadAuthorityError> {
    let authority = authority.validate()?;
    authority.validate_current(owner, capability, now)?;
    observation.validate_current(owner, observation_capability, now)?;
    if now >= authority.valid_until {
        return Err(ReadAuthorityError::Expired);
    }
    if authority.descriptor != descriptor {
        return Err(ReadAuthorityError::InvalidAuthority);
    }
    let entry = state
        .catalog_entry(&descriptor)
        .ok_or(ReadAuthorityError::NotAvailable)?;
    if entry.partition != authority.partition
        || entry.presence != CatalogPresenceV1::Committed
        || observation.catalog_digest != entry.digest
        || observation.root_custody != entry.root_custody
        || observation.root_generation != entry.root_generation
        || observation.canonical_name != entry.canonical_name
        || observation.backing != entry.backing
        || observation.seal != entry.seal
        || observation.size != entry.descriptor.encoded_size()
        || !observation.confined_read_only
        || observation.evidence_digest.as_bytes() == &[0; 32]
    {
        return Err(ReadAuthorityError::PhysicalMismatch);
    }
    let pin = state
        .pins()
        .pin(pin_id)
        .ok_or(ReadAuthorityError::PinAbsent)?;
    if pin.partition != authority.partition
        || pin.object != descriptor
        || pin.project != authority.project
        || pin.view != authority.view
        || pin.attachment != Some(authority.attachment)
        || pin.sandbox != Some(authority.sandbox)
        || pin.incarnation != Some(authority.incarnation)
        || pin.assignment_epoch != authority.assignment_epoch
        || !matches!(
            pin.kind,
            CachePinKindV1::KernelReference | CachePinKindV1::BackingRegistration
        )
        || !pin.permits_new_use(now)
    {
        return Err(ReadAuthorityError::PinMismatch);
    }
    let mut plan = DescriptorHandoffPlanV1 {
        authority_digest: authority.decision_digest,
        catalog_digest: entry.digest,
        pin: pin_id,
        descriptor,
        backing: entry.backing,
        physical_evidence: observation.evidence_digest,
        valid_until: authority.valid_until.min(pin.lease_valid_until),
        digest: ObjectDigest::from_bytes([0; 32]),
    };
    plan.digest = handoff_digest(&plan);
    Ok(plan)
}

/// Confirms the backing identity again after descriptor handoff.
///
/// This confirmation does not extend authority. It proves that the exact
/// committed backing remained stable across the handoff and that the same pin
/// still exists. A trusted adapter retains the descriptor only after this
/// receipt is durably associated with the consumer registration.
///
/// # Errors
///
/// Returns [`ReadAuthorityError`] for expired/mismatched authority, stale
/// catalog or pin state, or a changed physical observation.
pub fn confirm_descriptor_handoff(
    owner: &CacheAuthorityOwner<'_, '_>,
    capability: &VerifiedCacheCapabilityV1,
    observation_capability: &VerifiedCacheCapabilityV1,
    state: &CacheAdmissionStateV1,
    authority: CurrentReadAuthorityV1,
    plan: &DescriptorHandoffPlanV1,
    observation: ReadBackingObservationV1,
    now: u64,
) -> Result<DescriptorHandoffReceiptV1, ReadAuthorityError> {
    let authority = authority.validate()?;
    authority.validate_current(owner, capability, now)?;
    observation.validate_current(owner, observation_capability, now)?;
    if now >= plan.valid_until
        || plan.authority_digest != authority.decision_digest
        || plan.descriptor != authority.descriptor
        || plan.digest != handoff_digest(plan)
    {
        return Err(ReadAuthorityError::Expired);
    }
    let entry = state
        .catalog_entry(&plan.descriptor)
        .ok_or(ReadAuthorityError::NotAvailable)?;
    let pin = state
        .pins()
        .pin(plan.pin)
        .ok_or(ReadAuthorityError::PinAbsent)?;
    if entry.presence != CatalogPresenceV1::Committed
        || entry.digest != plan.catalog_digest
        || entry.backing != plan.backing
        || observation.catalog_digest != plan.catalog_digest
        || observation.root_custody != entry.root_custody
        || observation.root_generation != entry.root_generation
        || observation.canonical_name != entry.canonical_name
        || observation.backing != plan.backing
        || observation.seal != entry.seal
        || observation.size != entry.descriptor.encoded_size()
        || !observation.confined_read_only
        || observation.evidence_digest.as_bytes() == &[0; 32]
        || pin.partition != authority.partition
        || pin.object != plan.descriptor
        || pin.project != authority.project
        || pin.view != authority.view
        || pin.attachment != Some(authority.attachment)
        || pin.sandbox != Some(authority.sandbox)
        || pin.incarnation != Some(authority.incarnation)
        || pin.assignment_epoch != authority.assignment_epoch
    {
        return Err(ReadAuthorityError::PhysicalMismatch);
    }
    let mut receipt = DescriptorHandoffReceiptV1 {
        plan_digest: plan.digest,
        post_handoff_evidence: observation.evidence_digest,
        digest: ObjectDigest::from_bytes([0; 32]),
    };
    receipt.digest = handoff_receipt_digest(&receipt);
    Ok(receipt)
}

/// Reports independent read-authority and handoff failures.
#[derive(Debug, thiserror::Error)]
pub enum ReadAuthorityError {
    /// Current read authority is incomplete.
    #[error("cache read authority is invalid")]
    InvalidAuthority,
    /// Current read authority no longer permits a new handoff.
    #[error("cache read authority expired")]
    Expired,
    /// The object is absent or not committed for readers.
    #[error("cache object is not available")]
    NotAvailable,
    /// No retained pin has the required identity.
    #[error("cache read pin is absent")]
    PinAbsent,
    /// The pin does not bind the current reader, view, attachment, and object.
    #[error("cache read pin mismatches authority")]
    PinMismatch,
    /// Fresh physical facts differ from committed catalog identity.
    #[error("cache read backing revalidation failed")]
    PhysicalMismatch,
    /// Protected read authority verification failed.
    #[error(transparent)]
    Authority(#[from] CacheAuthorityError),
}

#[allow(clippy::too_many_arguments)]
fn read_authority_binding(
    principal: PrincipalId,
    project: ProjectId,
    view: ViewId,
    attachment: AttachmentId,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: u64,
    disclosure: CacheDomain,
    policy_revision: ObjectDigest,
    source_generation: u64,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.read-authority-binding.v1\0");
    hasher.update(principal.as_bytes());
    hasher.update(project.as_bytes());
    hasher.update(view.as_bytes());
    hasher.update(attachment.as_bytes());
    hasher.update(sandbox.as_bytes());
    hasher.update(incarnation.as_bytes());
    hasher.update(assignment_epoch.to_be_bytes());
    hasher.update(disclosure.domain_id().as_bytes());
    hasher.update(policy_revision.as_bytes());
    hasher.update(source_generation.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn handoff_digest(plan: &DescriptorHandoffPlanV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.descriptor-handoff.v1\0");
    hasher.update(plan.authority_digest.as_bytes());
    hasher.update(plan.catalog_digest.as_bytes());
    hasher.update(plan.pin.as_bytes());
    let media = plan.descriptor.media_type().as_str().as_bytes();
    hasher.update((media.len() as u16).to_be_bytes());
    hasher.update(media);
    hasher.update(plan.descriptor.digest().as_bytes());
    hasher.update(plan.descriptor.encoded_size().to_be_bytes());
    hasher.update(plan.backing.as_bytes());
    hasher.update(plan.physical_evidence.as_bytes());
    hasher.update(plan.valid_until.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn handoff_receipt_digest(receipt: &DescriptorHandoffReceiptV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.descriptor-handoff-receipt.v1\0");
    hasher.update(receipt.plan_digest.as_bytes());
    hasher.update(receipt.post_handoff_evidence.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn read_observation_subject(
    entry: &CatalogEntryV1,
    root_custody: ObjectDigest,
    root_generation: u64,
    canonical_name: ObjectDigest,
    backing: BackingObjectIdentityV1,
    seal: ImmutableSealV1,
    size: u64,
    confined_read_only: bool,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.read-observation-subject.v1\0");
    hasher.update(entry.digest.as_bytes());
    hasher.update(root_custody.as_bytes());
    hasher.update(root_generation.to_be_bytes());
    hasher.update(canonical_name.as_bytes());
    hasher.update(backing.as_bytes());
    hasher.update([seal.profile as u8]);
    hasher.update(seal.measurement.as_bytes());
    hasher.update(size.to_be_bytes());
    hasher.update([u8::from(confined_read_only)]);
    ObjectDigest::from_bytes(hasher.finalize().into())
}
