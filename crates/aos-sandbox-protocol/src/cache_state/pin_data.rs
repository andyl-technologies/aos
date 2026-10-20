//! Historical Cache pin and drain model DATA used by canonical replay.
//!
//! These fields and scope commitments do not issue Native pin/drain wrappers,
//! acquire a lease, prove a kernel reference drain or permit compaction.

use aos_sandbox_core::{AttachmentId, IncarnationId, ObjectDescriptor, ObjectDigest,
    ProjectId, SandboxId, ViewId};
use super::{PhysicalPartitionId, object_descriptor_commitment, validate_object_descriptor};
use super::authority_record::{CacheAuthorityScopeV1, CacheAuthorityRecordDataErrorV1};

/// Identifies one durable pin obligation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CachePinId([u8; 16]);

impl CachePinId {
    /// Constructs a nonzero pin identity.
    ///
    /// # Errors
    ///
    /// Returns [`PinDataErrorV1::InvalidPin`] for the zero sentinel.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, PinDataErrorV1> {
        if bytes == [0; 16] {
            return Err(PinDataErrorV1::InvalidPin);
        }
        Ok(Self(bytes))
    }

    /// Borrows the identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Selects one historical correctness obligation class.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CachePinKindV1 {
    /// A view or attached runtime historically depends on the object.
    LogicalLease = 1,
    /// The authoritative source revision must remain retrievable.
    SourceRetention = 2,
    /// The kernel may retain an open, mapping, lookup, or passthrough reference.
    KernelReference = 3,
    /// A backing registration remains installed outside ordinary process FDs.
    BackingRegistration = 4,
}

/// Records historical pin-to-consumer and immutable object bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachePinDataV1 {
    /// Stable idempotent pin identity.
    pub id: CachePinId,
    /// Exact physical partition.
    pub partition: PhysicalPartitionId,
    /// Complete immutable object descriptor within that partition.
    pub object: ObjectDescriptor,
    /// Project charged for this dependency.
    pub project: ProjectId,
    /// Logical view holding the dependency.
    pub view: ViewId,
    /// Attachment holding the dependency, if one exists.
    pub attachment: Option<AttachmentId>,
    /// Sandbox consumer, if one exists.
    pub sandbox: Option<SandboxId>,
    /// Exact consumer incarnation for runtime-bound pins.
    pub incarnation: Option<IncarnationId>,
    /// Closed pin class.
    pub kind: CachePinKindV1,
    /// Monotone assignment epoch, or zero for assignment-independent source retention.
    pub assignment_epoch: u64,
    /// Authority expiry for new use; kernel/backing obligations ignore it for release.
    pub lease_valid_until: u64,
    /// Digest of independently established authority or kernel evidence.
    pub evidence: ObjectDigest,
    /// Historical acquisition scope; no current permission.
    pub authority_scope: CacheAuthorityScopeV1,
}

impl CachePinDataV1 {
    /// Returns the historical pin identity.
    #[must_use]
    pub const fn id(&self) -> CachePinId { self.id }

    /// Returns the exact historical acquisition-scope and evidence commitments.
    #[must_use]
    pub const fn authority_binding(&self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.authority_scope, self.evidence)
    }

    /// Derives an exact historical logical-pin scope.
    ///
    /// # Errors
    ///
    /// Returns [`PinDataErrorV1`] for invalid scope coordinates.
    #[allow(clippy::too_many_arguments)]
    pub fn logical_acquisition_scope(
        id: CachePinId,
        partition: PhysicalPartitionId,
        object: &ObjectDescriptor,
        project: ProjectId,
        view: ViewId,
        attachment: Option<AttachmentId>,
        sandbox: Option<SandboxId>,
        incarnation: Option<IncarnationId>,
        assignment_epoch: u64,
        lease_valid_until: u64,
    ) -> Result<CacheAuthorityScopeV1, PinDataErrorV1> {
        let subject = pin_subject_fields(
            id,
            partition,
            object,
            project,
            view,
            attachment,
            sandbox,
            incarnation,
            CachePinKindV1::LogicalLease,
            assignment_epoch,
            lease_valid_until,
        );
        CacheAuthorityScopeV1::new(
            partition,
            subject,
            None,
            subject,
            partition.backing().root(),
            assignment_epoch.max(1),
            lease_valid_until,
        )
        .map_err(PinDataErrorV1::from)
    }

    /// Reconstructs complete historical fields without Native authority.
    ///
    /// # Errors
    ///
    /// Returns [`PinDataErrorV1`] for an invalid historical shape or scope.
    pub fn recover_historical(
        id: CachePinId,
        partition: PhysicalPartitionId,
        object: ObjectDescriptor,
        project: ProjectId,
        view: ViewId,
        attachment: Option<AttachmentId>,
        sandbox: Option<SandboxId>,
        incarnation: Option<IncarnationId>,
        kind: CachePinKindV1,
        assignment_epoch: u64,
        lease_valid_until: u64,
        evidence: ObjectDigest,
    ) -> Result<Self, PinDataErrorV1> {
        let subject = pin_subject_fields(
            id,
            partition,
            &object,
            project,
            view,
            attachment,
            sandbox,
            incarnation,
            kind,
            assignment_epoch,
            lease_valid_until,
        );
        let authority_scope = CacheAuthorityScopeV1::new(
            partition,
            subject,
            None,
            subject,
            partition.backing().root(),
            assignment_epoch.max(1),
            lease_valid_until,
        )?;
        Self {
            id,
            partition,
            object,
            project,
            view,
            attachment,
            sandbox,
            incarnation,
            kind,
            assignment_epoch,
            lease_valid_until,
            evidence,
            authority_scope,
        }
        .validate()
    }

    /// Validates complete historical pin shape and scope bindings.
    ///
    /// # Errors
    ///
    /// Returns [`PinDataErrorV1`] for invalid fields or scope commitment.
    pub fn validate(self) -> Result<Self, PinDataErrorV1> {
        self.validate_ref()?;
        Ok(self)
    }

    /// Validates borrowed historical pin fields without cloning their descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`PinDataErrorV1`] for an invalid pin shape or scope.
    pub fn validate_ref(&self) -> Result<(), PinDataErrorV1> {
        let view_only_logical = self.kind == CachePinKindV1::LogicalLease
            && self.attachment.is_none()
            && self.sandbox.is_none()
            && self.incarnation.is_none()
            && self.assignment_epoch == 0;
        let attached_runtime = matches!(
            self.kind,
            CachePinKindV1::LogicalLease
                | CachePinKindV1::KernelReference
                | CachePinKindV1::BackingRegistration
        ) && self.attachment.is_some()
            && self.sandbox.is_some()
            && self.incarnation.is_some()
            && self.assignment_epoch != 0;
        let source_retention = self.kind == CachePinKindV1::SourceRetention
            && self.attachment.is_none()
            && self.sandbox.is_none()
            && self.incarnation.is_none()
            && self.assignment_epoch == 0;
        if validate_object_descriptor(&self.object).is_err()
            || self.project.as_bytes() == &[0; 16]
            || self.view.as_bytes() == &[0; 16]
            || self.evidence.as_bytes() == &[0; 32]
            || self.lease_valid_until == 0
            || !(view_only_logical || attached_runtime || source_retention)
            || pin_acquisition_scope(&self).is_err()
            || pin_acquisition_scope(&self).is_ok_and(|scope| scope != self.authority_scope)
        {
            return Err(PinDataErrorV1::InvalidPin);
        }
        Ok(())
    }
}

/// Selects the exact proven drain outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PinDrainOutcomeV1 {
    /// No kernel-like reference was ever installed.
    NeverInstalled = 1,
    /// Consumer absence and all open/mapping/lookup/backing references were proved.
    ConsumerAbsentAndReferencesClosed = 2,
}

/// Records historical authority-bound DATA for one pin release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinDrainEvidenceDataV1 {
    /// Exact historical pin identity.
    pub pin: CachePinId,
    /// Historical class-specific drain outcome.
    pub outcome: PinDrainOutcomeV1,
    /// Historical protected drain-record commitment.
    pub digest: ObjectDigest,
    /// Historical drain scope; no current permission.
    pub authority_scope: CacheAuthorityScopeV1,
}

impl PinDrainEvidenceDataV1 {
    /// Returns the historical drain commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest { self.digest }

    /// Returns the historical drain outcome.
    #[must_use]
    pub const fn outcome(self) -> PinDrainOutcomeV1 { self.outcome }

    /// Returns the historical drain expiry.
    #[must_use]
    pub const fn valid_until(self) -> u64 { self.authority_scope.valid_until() }

    /// Returns the exact historical drain-scope and record commitments.
    #[must_use]
    pub const fn authority_binding(self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.authority_scope, self.digest)
    }

    /// Reconstructs complete historical fields without Native authority.
    ///
    /// # Errors
    ///
    /// Returns [`PinDataErrorV1`] for an invalid historical shape or scope.
    pub fn recover_historical(
        pin: &CachePinDataV1,
        outcome: PinDrainOutcomeV1,
        digest: ObjectDigest,
        valid_until: u64,
    ) -> Result<Self, PinDataErrorV1> {
        let authority_scope = pin_drain_scope(pin, outcome, valid_until)?;
        let evidence = Self {
            pin: pin.id,
            outcome,
            digest,
            authority_scope,
        };
        evidence.validate_replay(pin)?;
        Ok(evidence)
    }

    /// Validates exact historical drain-to-pin correspondence.
    ///
    /// # Errors
    ///
    /// Returns [`PinDataErrorV1`] for mismatched or insufficient drain facts.
    pub fn validate_replay(self, pin: &CachePinDataV1) -> Result<(), PinDataErrorV1> {
        let expected = pin_drain_scope(pin, self.outcome, self.authority_scope.valid_until())?;
        if expected != self.authority_scope || self.pin != pin.id {
            return Err(PinDataErrorV1::EvidenceMismatch);
        }
        validate_release(pin, self)
    }
}

/// Reports malformed historical pin or drain DATA.
#[derive(Debug, thiserror::Error)]
pub enum PinDataErrorV1 {
    /// Required pin identity, scope or evidence is missing.
    #[error("cache pin is invalid")]
    InvalidPin,
    /// An identity or logical consumer conflicts with retained facts.
    #[error("cache pin identity conflicts")]
    Conflict,
    /// The configured retained namespace capacity is exhausted.
    #[error("cache pin ledger capacity is exhausted")]
    Capacity,
    /// A historical pin-compaction floor is malformed.
    #[error("cache pin compaction floor is invalid")]
    InvalidFloor,
    /// Drain facts do not bind the exact historical pin.
    #[error("cache pin release evidence mismatches")]
    EvidenceMismatch,
    /// A kernel-like reference lacks the required closed-reference outcome.
    #[error("cache physical-reference drain is not proved")]
    DrainNotProved,
    /// Historical authority-scope coordinates are invalid.
    #[error(transparent)]
    Authority(#[from] CacheAuthorityRecordDataErrorV1),
}

/// Projects or validates canonical historical pin drain scope DATA.
///
/// # Errors
///
/// Returns [`PinDataErrorV1`] for an invalid historical scope or binding.
#[doc(hidden)]
pub fn pin_drain_scope(
    pin: &CachePinDataV1,
    outcome: PinDrainOutcomeV1,
    valid_until: u64,
) -> Result<CacheAuthorityScopeV1, PinDataErrorV1> {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.pin-drain-subject.v1\0");
    hasher.update(pin_subject(pin).as_bytes());
    hasher.update(pin.evidence.as_bytes());
    hasher.update([outcome as u8]);
    let subject = ObjectDigest::from_bytes(hasher.finalize().into());
    CacheAuthorityScopeV1::new(
        pin.partition,
        subject,
        None,
        pin.evidence,
        pin.partition.backing().root(),
        pin.assignment_epoch.max(1),
        valid_until,
    )
    .map_err(PinDataErrorV1::from)
}

/// Projects or validates canonical historical pin acquisition scope DATA.
///
/// # Errors
///
/// Returns [`PinDataErrorV1`] for an invalid historical scope or binding.
#[doc(hidden)]
pub fn pin_acquisition_scope(pin: &CachePinDataV1) -> Result<CacheAuthorityScopeV1, PinDataErrorV1> {
    let subject = pin_subject(pin);
    CacheAuthorityScopeV1::new(
        pin.partition,
        subject,
        None,
        subject,
        pin.partition.backing().root(),
        pin.assignment_epoch.max(1),
        pin.lease_valid_until,
    )
    .map_err(PinDataErrorV1::from)
}

/// Projects or validates canonical historical pin subject DATA.
#[doc(hidden)]
pub fn pin_subject(pin: &CachePinDataV1) -> ObjectDigest {
    pin_subject_fields(
        pin.id,
        pin.partition,
        &pin.object,
        pin.project,
        pin.view,
        pin.attachment,
        pin.sandbox,
        pin.incarnation,
        pin.kind,
        pin.assignment_epoch,
        pin.lease_valid_until,
    )
}

/// Projects or validates canonical historical valid logical renewal DATA.
#[doc(hidden)]
pub fn valid_logical_renewal(previous: &CachePinDataV1, renewed: &CachePinDataV1) -> bool {
    previous.kind == CachePinKindV1::LogicalLease
        && renewed.kind == CachePinKindV1::LogicalLease
        && previous.id == renewed.id
        && previous.partition == renewed.partition
        && previous.object == renewed.object
        && previous.project == renewed.project
        && previous.view == renewed.view
        && previous.attachment == renewed.attachment
        && previous.sandbox == renewed.sandbox
        && previous.incarnation == renewed.incarnation
        && previous.assignment_epoch == renewed.assignment_epoch
        && previous.lease_valid_until <= renewed.lease_valid_until
}

/// Projects or validates canonical historical pin subject fields DATA.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn pin_subject_fields(
    id: CachePinId,
    partition: PhysicalPartitionId,
    object: &ObjectDescriptor,
    project: ProjectId,
    view: ViewId,
    attachment: Option<AttachmentId>,
    sandbox: Option<SandboxId>,
    incarnation: Option<IncarnationId>,
    kind: CachePinKindV1,
    assignment_epoch: u64,
    lease_valid_until: u64,
) -> ObjectDigest {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.pin-subject.v1\0");
    hasher.update(id.as_bytes());
    hasher.update(partition.digest().as_bytes());
    hasher.update(object_descriptor_commitment(object).as_bytes());
    hasher.update(project.as_bytes());
    hasher.update(view.as_bytes());
    hasher.update(attachment.map_or([0; 16], |value| value.into_bytes()));
    hasher.update(sandbox.map_or([0; 16], |value| value.into_bytes()));
    hasher.update(incarnation.map_or([0; 16], |value| value.into_bytes()));
    hasher.update([kind as u8]);
    hasher.update(assignment_epoch.to_be_bytes());
    hasher.update(lease_valid_until.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Projects or validates canonical historical validate release DATA.
///
/// # Errors
///
/// Returns [`PinDataErrorV1`] for an invalid historical scope or binding.
#[doc(hidden)]
pub fn validate_release(pin: &CachePinDataV1, drain: PinDrainEvidenceDataV1) -> Result<(), PinDataErrorV1> {
    pin.clone().validate()?;
    if drain.pin != pin.id || drain.digest.as_bytes() == &[0; 32] {
        return Err(PinDataErrorV1::EvidenceMismatch);
    }
    if matches!(
        pin.kind,
        CachePinKindV1::KernelReference | CachePinKindV1::BackingRegistration
    ) && drain.outcome != PinDrainOutcomeV1::ConsumerAbsentAndReferencesClosed
    {
        return Err(PinDataErrorV1::DrainNotProved);
    }
    Ok(())
}


/// Reports a malformed pin or noncanonical historical initial-pin ordering.
#[derive(Debug, thiserror::Error)]
pub enum InitialPinSetDataErrorV1 {
    /// One supplied historical pin is malformed.
    #[error(transparent)]
    Pin(PinDataErrorV1),
    /// The supplied count or strict identity order is invalid.
    #[error("cache initial-pin ordering mismatches")]
    Mismatch,
}

/// Commits an exact historical initial pin set without issuing Native authority.
///
/// # Errors
///
/// Returns [`InitialPinSetDataErrorV1`] for a malformed pin, excessive count or
/// noncanonical identity order. The empty set has a domain-separated digest.
pub fn initial_pin_set_digest<P: std::borrow::Borrow<CachePinDataV1>>(
    pins: &[P],
) -> Result<ObjectDigest, InitialPinSetDataErrorV1> {
    use sha2::{Digest as _, Sha256};

    if pins.len() > 65_536 {
        return Err(InitialPinSetDataErrorV1::Mismatch);
    }
    let mut previous = None;
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.initial-pin-set.v1\0");
    hasher.update((pins.len() as u32).to_be_bytes());
    for row in pins {
        let pin: &CachePinDataV1 = std::borrow::Borrow::borrow(row);
        pin.clone().validate().map_err(InitialPinSetDataErrorV1::Pin)?;
        if previous.is_some_and(|id| id >= pin.id) {
            return Err(InitialPinSetDataErrorV1::Mismatch);
        }
        previous = Some(pin.id);
        hasher.update(pin.id.as_bytes());
        hasher.update(pin.partition.digest().as_bytes());
        super::hash_descriptor_fields_u16_v1(&mut hasher, &pin.object);
        hasher.update(pin.project.as_bytes());
        hasher.update(pin.view.as_bytes());
        hasher.update(pin.attachment.map_or([0; 16], |id| id.into_bytes()));
        hasher.update(pin.sandbox.map_or([0; 16], |id| id.into_bytes()));
        hasher.update(pin.incarnation.map_or([0; 16], |id| id.into_bytes()));
        hasher.update([pin.kind as u8]);
        hasher.update(pin.assignment_epoch.to_be_bytes());
        hasher.update(pin.lease_valid_until.to_be_bytes());
        hasher.update(pin.evidence.as_bytes());
    }
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}
