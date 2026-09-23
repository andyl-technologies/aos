//! Distinct logical, source-retention, kernel-reference, and backing pins.
//!
//! Lease expiry prevents new lookup and begins drain; it does not erase a
//! kernel-held reference.  Physical eviction is possible only after every pin
//! class for an object reaches zero and committed source retention remains
//! sufficient for any active lazy view that can refetch the object.

use std::collections::BTreeMap;
use std::marker::PhantomData;

use aos_sandbox_core::{
    AttachmentId, IncarnationId, ObjectDescriptor, ObjectDigest, ProjectId, SandboxId, ViewId,
};

use super::accounting::{AccountingError, CacheUsageV1};
use super::domain::{
    CacheAuthorityError, CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheAuthorityScopeV1,
    PhysicalPartitionId, VerifiedCacheCapabilityV1, object_descriptor_commitment,
    validate_object_descriptor,
};

pub(crate) const PIN_FLOOR_BYTES: usize = 136;

/// Identifies one durable pin obligation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CachePinId([u8; 16]);

impl CachePinId {
    /// Constructs a nonzero pin identity.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::InvalidPin`] for the zero sentinel.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, PinError> {
        if bytes == [0; 16] {
            return Err(PinError::InvalidPin);
        }
        Ok(Self(bytes))
    }

    /// Borrows the identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Fences a protected compacted pin-tombstone prefix against identity reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinCompactionFloorV1 {
    pin: CachePinId,
    partition: ObjectDigest,
    checkpoint: ObjectDigest,
    generation: u64,
    digest: ObjectDigest,
}

/// Proves that one retained release prefix is absent from the locked owner.
///
/// The proof borrows an owner snapshot through its lifetime. Retained pin IDs
/// are checked again against the ledger before any tombstone is discarded.
#[must_use = "the owner-validated absence must be consumed by pin compaction"]
pub struct CachePinCompactionPhysicalProofV1<'snapshot> {
    partition: PhysicalPartitionId,
    floor: CachePinId,
    released: Vec<CachePinId>,
    _snapshot: PhantomData<&'snapshot ()>,
}

impl<'snapshot> CachePinCompactionPhysicalProofV1<'snapshot> {
    pub(in crate::cache_residency) fn from_verified(
        partition: PhysicalPartitionId,
        floor: CachePinId,
        released: Vec<CachePinId>,
    ) -> Self {
        Self {
            partition,
            floor,
            released,
            _snapshot: PhantomData,
        }
    }
}

impl PinCompactionFloorV1 {
    /// Returns the greatest compacted pin identity.
    #[must_use]
    pub const fn pin(self) -> CachePinId {
        self.pin
    }

    /// Returns the protected checkpoint anchoring compaction.
    #[must_use]
    pub const fn checkpoint(self) -> ObjectDigest {
        self.checkpoint
    }
}

/// Encodes a protected pin-compaction floor into its canonical fixed format.
///
/// # Errors
///
/// Returns [`PinError::InvalidFloor`] for an inconsistent recovered floor.
pub fn encode_pin_compaction_floor(
    floor: PinCompactionFloorV1,
) -> Result<[u8; PIN_FLOOR_BYTES], PinError> {
    if floor.digest
        != pin_compaction_floor_digest(
            floor.pin,
            floor.partition,
            floor.checkpoint,
            floor.generation,
        )
    {
        return Err(PinError::InvalidFloor);
    }
    let mut bytes = [0_u8; PIN_FLOOR_BYTES];
    bytes[0..8].copy_from_slice(b"AOSPFL01");
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..32].copy_from_slice(floor.pin.as_bytes());
    bytes[32..64].copy_from_slice(floor.partition.as_bytes());
    bytes[64..96].copy_from_slice(floor.checkpoint.as_bytes());
    bytes[96..104].copy_from_slice(&floor.generation.to_be_bytes());
    bytes[104..136].copy_from_slice(floor.digest.as_bytes());
    Ok(bytes)
}

/// Recovers a pin floor only under its exact current protected capability.
///
/// # Errors
///
/// Returns [`PinError`] for malformed bytes, scope mismatch, or expiry.
pub fn decode_pin_compaction_floor(
    owner: &CacheAuthorityOwner<'_, '_>,
    capability: &VerifiedCacheCapabilityV1,
    partition: PhysicalPartitionId,
    bytes: &[u8],
    now: u64,
) -> Result<PinCompactionFloorV1, PinError> {
    let floor = decode_pin_compaction_floor_persisted(partition, bytes)?;
    let scope = pin_compaction_scope(
        partition,
        floor.pin,
        floor.checkpoint,
        floor.generation,
        capability.scope().valid_until(),
    )?;
    owner.validate_for_effect_at(capability, CacheAuthorityPurposeV1::Replay, scope, now)?;
    Ok(floor)
}

pub(crate) fn decode_pin_compaction_floor_persisted(
    partition: PhysicalPartitionId,
    bytes: &[u8],
) -> Result<PinCompactionFloorV1, PinError> {
    if bytes.len() != PIN_FLOOR_BYTES
        || &bytes[0..8] != b"AOSPFL01"
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
    {
        return Err(PinError::InvalidFloor);
    }
    let pin = CachePinId::from_bytes(read_pin_array(bytes, 16)?)?;
    let floor = PinCompactionFloorV1 {
        pin,
        partition: ObjectDigest::from_bytes(read_pin_array(bytes, 32)?),
        checkpoint: ObjectDigest::from_bytes(read_pin_array(bytes, 64)?),
        generation: u64::from_be_bytes(read_pin_array(bytes, 96)?),
        digest: ObjectDigest::from_bytes(read_pin_array(bytes, 104)?),
    };
    if floor.partition != partition.digest()
        || floor.checkpoint.as_bytes() == &[0; 32]
        || floor.digest
            != pin_compaction_floor_digest(
                floor.pin,
                floor.partition,
                floor.checkpoint,
                floor.generation,
            )
    {
        return Err(PinError::InvalidFloor);
    }
    Ok(floor)
}

/// Selects one semantically distinct correctness obligation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CachePinKindV1 {
    /// An authorized view or attached runtime logically depends on the object.
    LogicalLease = 1,
    /// The authoritative source revision must remain retrievable.
    SourceRetention = 2,
    /// The kernel may retain an open, mapping, lookup, or passthrough reference.
    KernelReference = 3,
    /// A backing registration remains installed outside ordinary process FDs.
    BackingRegistration = 4,
}

/// Binds a pin to its complete consumer and object identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachePinV1 {
    /// Stable idempotent pin identity.
    pub(crate) id: CachePinId,
    /// Exact physical partition.
    pub(crate) partition: PhysicalPartitionId,
    /// Complete immutable object descriptor within that partition.
    pub(crate) object: ObjectDescriptor,
    /// Project charged for this dependency.
    pub(crate) project: ProjectId,
    /// Logical view holding the dependency.
    pub(crate) view: ViewId,
    /// Attachment holding the dependency, if one exists.
    pub(crate) attachment: Option<AttachmentId>,
    /// Sandbox consumer, if one exists.
    pub(crate) sandbox: Option<SandboxId>,
    /// Exact consumer incarnation for runtime-bound pins.
    pub(crate) incarnation: Option<IncarnationId>,
    /// Closed pin class.
    pub(crate) kind: CachePinKindV1,
    /// Monotone assignment epoch, or zero for assignment-independent source retention.
    pub(crate) assignment_epoch: u64,
    /// Authority expiry for new use; kernel/backing obligations ignore it for release.
    pub(crate) lease_valid_until: u64,
    /// Digest of independently established authority or kernel evidence.
    pub(crate) evidence: ObjectDigest,
    authority_scope: CacheAuthorityScopeV1,
}

/// Retains a released pin tombstone and exact drain evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedCachePinV1 {
    /// Complete historical pin binding.
    pub pin: CachePinV1,
    /// Exact authority-bound evidence that permitted release.
    pub drain: PinDrainEvidenceV1,
}

impl CachePinV1 {
    pub(crate) const fn authority_binding(&self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.authority_scope, self.evidence)
    }

    /// Returns the durable identity retained across logical lease renewals.
    #[must_use]
    pub const fn id(&self) -> CachePinId {
        self.id
    }

    /// Returns the physical cache partition retaining this obligation.
    #[must_use]
    pub const fn partition(&self) -> PhysicalPartitionId {
        self.partition
    }

    /// Borrows the exact immutable object retained by this obligation.
    #[must_use]
    pub const fn object(&self) -> &ObjectDescriptor {
        &self.object
    }

    /// Returns the consumer project.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the consumer view.
    #[must_use]
    pub const fn view(&self) -> ViewId {
        self.view
    }

    /// Returns the consuming attachment, when the pin is attachment-scoped.
    #[must_use]
    pub const fn attachment(&self) -> Option<AttachmentId> {
        self.attachment
    }

    /// Returns the obligation class.
    #[must_use]
    pub const fn kind(&self) -> CachePinKindV1 {
        self.kind
    }

    /// Returns the exact acquisition evidence required by a later release.
    #[must_use]
    pub const fn evidence(&self) -> ObjectDigest {
        self.evidence
    }

    /// Returns the deadline after which this lease permits no new use.
    #[must_use]
    pub const fn lease_valid_until(&self) -> u64 {
        self.lease_valid_until
    }

    pub(crate) fn logical_drain_scope(
        &self,
        valid_until: u64,
    ) -> Result<CacheAuthorityScopeV1, PinError> {
        if self.kind != CachePinKindV1::LogicalLease {
            return Err(PinError::EvidenceMismatch);
        }
        pin_drain_scope(self, PinDrainOutcomeV1::NeverInstalled, valid_until)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recover_historical(
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
    ) -> Result<Self, PinError> {
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

    /// Issues one exact pin from current protected assignment/source authority.
    ///
    /// # Errors
    ///
    /// Returns [`PinError`] for malformed fields, stale authority, or expiry.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
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
        now: u64,
    ) -> Result<Self, PinError> {
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
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::PinAcquire,
            authority_scope,
            now,
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
            evidence: capability.record_digest(),
            authority_scope,
        }
        .validate()
    }

    /// Validates complete pin bindings and class-specific shape.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::InvalidPin`] for missing identity, evidence, or
    /// required consumer/assignment bindings.
    pub fn validate(self) -> Result<Self, PinError> {
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
            return Err(PinError::InvalidPin);
        }
        Ok(self)
    }

    pub(crate) fn validate_current(
        &self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        now: u64,
    ) -> Result<(), PinError> {
        let expected = pin_acquisition_scope(self)?;
        if expected != self.authority_scope || capability.record_digest() != self.evidence {
            return Err(PinError::EvidenceMismatch);
        }
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::PinAcquire,
            expected,
            now,
        )?;
        Ok(())
    }

    /// Returns whether lease time still permits a new logical use.
    #[must_use]
    pub const fn permits_new_use(&self, now: u64) -> bool {
        self.lease_valid_until > now
    }
}

/// Materializes exact pin obligations without collapsing pin classes.
#[derive(Clone, Debug)]
pub struct CachePinLedgerV1 {
    maximum_records: usize,
    pins: BTreeMap<CachePinId, CachePinV1>,
    logical_consumers: BTreeMap<LogicalPinConsumerKeyV1, CachePinId>,
    released: BTreeMap<CachePinId, ReleasedCachePinV1>,
    compacted_through: Option<PinCompactionFloorV1>,
}

type LogicalPinConsumerKeyV1 = (
    ObjectDigest,
    ObjectDigest,
    ProjectId,
    ViewId,
    Option<AttachmentId>,
);

impl CachePinLedgerV1 {
    /// Constructs an empty bounded pin ledger.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::Capacity`] for zero or excessive retention bounds.
    pub fn new(maximum_records: usize) -> Result<Self, PinError> {
        if maximum_records == 0 || maximum_records > 1_000_000 {
            return Err(PinError::Capacity);
        }
        Ok(Self {
            maximum_records,
            pins: BTreeMap::new(),
            logical_consumers: BTreeMap::new(),
            released: BTreeMap::new(),
            compacted_through: None,
        })
    }

    /// Replays a complete pin set with exact identity uniqueness.
    ///
    /// # Errors
    ///
    /// Returns [`PinError`] for malformed or conflicting pins.
    pub fn replay(
        maximum_records: usize,
        compacted_through: Option<PinCompactionFloorV1>,
        pins: impl IntoIterator<Item = CachePinV1>,
        released: impl IntoIterator<Item = ReleasedCachePinV1>,
    ) -> Result<Self, PinError> {
        let mut ledger = Self::new(maximum_records)?;
        ledger.compacted_through = compacted_through;
        for pin in pins {
            let pin = pin.validate()?;
            if ledger
                .compacted_through
                .is_some_and(|floor| pin.id <= floor.pin)
            {
                return Err(PinError::Conflict);
            }
            if ledger.pins.len() + ledger.released.len() >= ledger.maximum_records {
                return Err(PinError::Capacity);
            }
            if let Some(key) = logical_consumer_key(&pin)
                && ledger.logical_consumers.insert(key, pin.id).is_some()
            {
                return Err(PinError::Conflict);
            }
            if ledger.pins.insert(pin.id, pin).is_some() {
                return Err(PinError::Conflict);
            }
        }
        for tombstone in released {
            validate_release(&tombstone.pin, tombstone.drain)?;
            if ledger
                .compacted_through
                .is_some_and(|floor| tombstone.pin.id <= floor.pin)
            {
                return Err(PinError::Conflict);
            }
            if ledger.pins.len() + ledger.released.len() >= ledger.maximum_records {
                return Err(PinError::Capacity);
            }
            if ledger.pins.contains_key(&tombstone.pin.id)
                || ledger.released.contains_key(&tombstone.pin.id)
            {
                return Err(PinError::Conflict);
            }
            ledger.released.insert(tombstone.pin.id, tombstone);
        }
        Ok(ledger)
    }

    /// Inserts one pin, treating exact replay as idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::Conflict`] if the ID names different facts.
    pub fn acquire(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        pin: CachePinV1,
        now: u64,
    ) -> Result<(), PinError> {
        let pin = pin.validate()?;
        pin.validate_current(owner, capability, now)?;
        if self
            .compacted_through
            .is_some_and(|floor| pin.id <= floor.pin)
        {
            return Err(PinError::Conflict);
        }
        if self.released.contains_key(&pin.id) {
            return Err(PinError::Conflict);
        }
        let logical_key = logical_consumer_key(&pin);
        if logical_key.as_ref().is_some_and(|key| {
            self.logical_consumers
                .get(key)
                .is_some_and(|id| *id != pin.id)
        }) {
            return Err(PinError::Conflict);
        }
        if let Some(existing) = self.pins.get(&pin.id) {
            return if existing == &pin {
                Ok(())
            } else {
                Err(PinError::Conflict)
            };
        }
        if self.pins.len() + self.released.len() >= self.maximum_records {
            return Err(PinError::Capacity);
        }
        if let Some(key) = logical_key {
            self.logical_consumers.insert(key, pin.id);
        }
        self.pins.insert(pin.id, pin);
        Ok(())
    }

    /// Renews the sole logical pin without changing its consumer identity.
    ///
    /// Renewal retains the original ID, so a later release names one exact
    /// obligation even after the lease or its current authority changes.
    ///
    /// # Errors
    ///
    /// Returns [`PinError`] if the consumer has no pin, its runtime binding
    /// changed, the lease shrinks, or the new acquisition authority is stale.
    pub fn renew_logical(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        renewed: CachePinV1,
        now: u64,
    ) -> Result<(), PinError> {
        let renewed = renewed.validate()?;
        renewed.validate_current(owner, capability, now)?;
        let existing = self
            .logical_consumer_pin(
                renewed.partition,
                &renewed.object,
                renewed.project,
                renewed.view,
                renewed.attachment,
            )
            .ok_or(PinError::Absent)?;
        if !valid_logical_renewal(existing, &renewed) {
            return Err(PinError::Conflict);
        }
        self.pins.insert(renewed.id, renewed);
        Ok(())
    }

    /// Releases one exact pin after authoritative drain evidence.
    ///
    /// # Errors
    ///
    /// Returns [`PinError`] if the pin is absent, the evidence does not bind
    /// the retained pin, or a kernel/backing release lacks a proved drain.
    pub fn release(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        id: CachePinId,
        expected_evidence: ObjectDigest,
        drain: PinDrainEvidenceV1,
        now: u64,
    ) -> Result<ReleasedCachePinV1, PinError> {
        if let Some(released) = self.released.get(&id) {
            drain.validate_current(owner, capability, &released.pin, now)?;
            return if released.pin.evidence == expected_evidence && released.drain == drain {
                Ok(released.clone())
            } else {
                Err(PinError::Conflict)
            };
        }
        let pin = self.pins.get(&id).ok_or(PinError::Absent)?;
        drain.validate_current(owner, capability, pin, now)?;
        if pin.evidence != expected_evidence
            || drain.pin != id
            || drain.digest.as_bytes() == &[0; 32]
        {
            return Err(PinError::EvidenceMismatch);
        }
        if matches!(
            pin.kind,
            CachePinKindV1::KernelReference | CachePinKindV1::BackingRegistration
        ) && drain.outcome != PinDrainOutcomeV1::ConsumerAbsentAndReferencesClosed
        {
            return Err(PinError::DrainNotProved);
        }
        validate_release(pin, drain)?;
        if let Some(key) = logical_consumer_key(pin)
            && self.logical_consumers.get(&key) != Some(&id)
        {
            return Err(PinError::Conflict);
        }
        let pin = self.pins.remove(&id).ok_or(PinError::Absent)?;
        if let Some(key) = logical_consumer_key(&pin) {
            self.logical_consumers.remove(&key);
        }
        let released = ReleasedCachePinV1 { pin, drain };
        self.released.insert(id, released.clone());
        Ok(released)
    }

    /// Compacts a released tombstone prefix while permanently fencing its IDs.
    ///
    /// The retained high-water ID prevents a compacted identity from ever
    /// being admitted again. Active pins at or below the requested floor make
    /// compaction fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::Conflict`] for a non-monotone or active floor, or
    /// when physical absence was not proved for the exact released prefix.
    #[allow(clippy::too_many_arguments)]
    pub fn compact_released_through(
        &mut self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        partition: PhysicalPartitionId,
        floor: CachePinId,
        physical_absence: CachePinCompactionPhysicalProofV1<'_>,
        checkpoint: ObjectDigest,
        generation: u64,
        valid_until: u64,
        now: u64,
    ) -> Result<PinCompactionFloorV1, PinError> {
        if self
            .compacted_through
            .is_some_and(|current| floor <= current.pin)
            || self.pins.keys().any(|id| *id <= floor)
            || self
                .released
                .range(..=floor)
                .any(|(_, released)| released.pin.partition != partition)
            || physical_absence.partition != partition
            || physical_absence.floor != floor
            || !self
                .released
                .range(..=floor)
                .map(|(id, _)| *id)
                .eq(physical_absence.released.iter().copied())
            || checkpoint.as_bytes() == &[0; 32]
        {
            return Err(PinError::Conflict);
        }
        let scope = pin_compaction_scope(partition, floor, checkpoint, generation, valid_until)?;
        owner.validate_for_effect_at(capability, CacheAuthorityPurposeV1::Replay, scope, now)?;
        self.released.retain(|id, _| *id > floor);
        let floor = PinCompactionFloorV1 {
            pin: floor,
            partition: partition.digest(),
            checkpoint,
            generation,
            digest: pin_compaction_floor_digest(floor, partition.digest(), checkpoint, generation),
        };
        self.compacted_through = Some(floor);
        Ok(floor)
    }

    /// Returns whether an object has any physical-reclamation blocker.
    #[must_use]
    pub fn blocks_eviction(
        &self,
        partition: PhysicalPartitionId,
        object: &ObjectDescriptor,
    ) -> bool {
        self.pins.values().any(|pin| {
            pin.partition == partition
                && &pin.object == object
                && pin.kind != CachePinKindV1::SourceRetention
        })
    }

    /// Returns one retained pin without treating it as current authority.
    #[must_use]
    pub fn pin(&self, id: CachePinId) -> Option<&CachePinV1> {
        self.pins.get(&id)
    }

    /// Finds the sole active logical pin for an exact consumer and object.
    ///
    /// The returned pin is retained state, not current acquisition or drain
    /// authority. A release must separately prove its exact drain evidence.
    #[must_use]
    pub fn logical_consumer_pin(
        &self,
        partition: PhysicalPartitionId,
        object: &ObjectDescriptor,
        project: ProjectId,
        view: ViewId,
        attachment: Option<AttachmentId>,
    ) -> Option<&CachePinV1> {
        let key = (
            partition.digest(),
            object_descriptor_commitment(object),
            project,
            view,
            attachment,
        );
        self.logical_consumers
            .get(&key)
            .and_then(|id| self.pins.get(id))
            .filter(|pin| {
                pin.partition == partition
                    && &pin.object == object
                    && pin.project == project
                    && pin.view == view
                    && pin.attachment == attachment
                    && pin.kind == CachePinKindV1::LogicalLease
            })
    }

    /// Selects the next unused identity above every retained or compacted pin.
    ///
    /// The caller must still commit under current protected state; this
    /// selection alone does not reserve the identity.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::Capacity`] if the 128-bit identity space is exhausted.
    pub fn next_pin_id(&self) -> Result<CachePinId, PinError> {
        let greatest = [
            self.pins.last_key_value().map(|(id, _)| *id),
            self.released.last_key_value().map(|(id, _)| *id),
            self.compacted_through.map(|floor| floor.pin),
        ]
        .into_iter()
        .flatten()
        .max();
        let next = greatest.map_or(Some(1), |id| {
            u128::from_be_bytes(*id.as_bytes()).checked_add(1)
        });
        CachePinId::from_bytes(next.ok_or(PinError::Capacity)?.to_be_bytes())
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &CachePinV1> {
        self.pins.values()
    }

    /// Computes pin-class usage for atomic quota validation.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Overflow`] if a count cannot be represented.
    pub fn usage(
        &self,
    ) -> Result<(BTreeMap<[u8; 16], CacheUsageV1>, CacheUsageV1), AccountingError> {
        let mut projects = BTreeMap::<[u8; 16], CacheUsageV1>::new();
        let mut node = CacheUsageV1::default();
        for pin in self.pins.values() {
            let project = projects.entry(*pin.project.as_bytes()).or_default();
            match pin.kind {
                CachePinKindV1::LogicalLease => {
                    increment(&mut project.logical_pins)?;
                    increment(&mut node.logical_pins)?;
                }
                CachePinKindV1::SourceRetention => {
                    increment(&mut project.source_retentions)?;
                    increment(&mut node.source_retentions)?;
                }
                CachePinKindV1::KernelReference => {
                    increment(&mut project.kernel_references)?;
                    increment(&mut node.kernel_references)?;
                }
                CachePinKindV1::BackingRegistration => {
                    increment(&mut project.backing_registrations)?;
                    increment(&mut node.backing_registrations)?;
                }
            }
        }
        Ok((projects, node))
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

/// Carries opaque authority-bound evidence for one pin release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinDrainEvidenceV1 {
    pin: CachePinId,
    outcome: PinDrainOutcomeV1,
    digest: ObjectDigest,
    authority_scope: CacheAuthorityScopeV1,
}

impl PinDrainEvidenceV1 {
    pub(crate) const fn authority_binding(self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.authority_scope, self.digest)
    }

    pub(crate) const fn valid_until(self) -> u64 {
        self.authority_scope.valid_until()
    }

    pub(crate) fn recover_historical(
        pin: &CachePinV1,
        outcome: PinDrainOutcomeV1,
        digest: ObjectDigest,
        valid_until: u64,
    ) -> Result<Self, PinError> {
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

    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }

    pub(crate) const fn outcome(self) -> PinDrainOutcomeV1 {
        self.outcome
    }

    pub(crate) fn validate_replay(self, pin: &CachePinV1) -> Result<(), PinError> {
        let expected = pin_drain_scope(pin, self.outcome, self.authority_scope.valid_until())?;
        if expected != self.authority_scope || self.pin != pin.id {
            return Err(PinError::EvidenceMismatch);
        }
        validate_release(pin, self)
    }

    /// Issues drain evidence from one exact current protected observation.
    ///
    /// # Errors
    ///
    /// Returns [`PinError`] for a mismatched pin or stale protected capability.
    pub fn from_verified(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        pin: &CachePinV1,
        outcome: PinDrainOutcomeV1,
        valid_until: u64,
        now: u64,
    ) -> Result<Self, PinError> {
        let authority_scope = pin_drain_scope(pin, outcome, valid_until)?;
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::PinDrain,
            authority_scope,
            now,
        )?;
        Ok(Self {
            pin: pin.id,
            outcome,
            digest: capability.record_digest(),
            authority_scope,
        })
    }

    fn validate_current(
        self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        pin: &CachePinV1,
        now: u64,
    ) -> Result<(), PinError> {
        let expected = pin_drain_scope(pin, self.outcome, self.authority_scope.valid_until())?;
        if self.authority_scope != expected || self.digest != capability.record_digest() {
            return Err(PinError::EvidenceMismatch);
        }
        owner.validate_for_effect_at(
            capability,
            CacheAuthorityPurposeV1::PinDrain,
            expected,
            now,
        )?;
        Ok(())
    }
}

/// Reports malformed or unsafe pin transitions.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    /// A pin lacks a required identity, scope, or evidence binding.
    #[error("cache pin is invalid")]
    InvalidPin,
    /// A pin identity or active logical consumer conflicts with retained facts.
    #[error("cache pin identity conflicts")]
    Conflict,
    /// No retained pin has the requested identity.
    #[error("cache pin is absent")]
    Absent,
    /// Release evidence does not bind the exact pin.
    #[error("cache pin release evidence mismatches")]
    EvidenceMismatch,
    /// Physical reference drain was not authoritatively proved.
    #[error("cache physical-reference drain is not proved")]
    DrainNotProved,
    /// Retained active and released pin records exhaust the configured bound.
    #[error("cache pin ledger capacity is exhausted")]
    Capacity,
    /// A pin-compaction floor codec or protected binding is invalid.
    #[error("cache pin compaction floor is invalid")]
    InvalidFloor,
    /// Protected pin-drain authority verification failed.
    #[error(transparent)]
    Authority(#[from] CacheAuthorityError),
}

fn pin_drain_scope(
    pin: &CachePinV1,
    outcome: PinDrainOutcomeV1,
    valid_until: u64,
) -> Result<CacheAuthorityScopeV1, PinError> {
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
    .map_err(PinError::from)
}

fn pin_compaction_scope(
    partition: PhysicalPartitionId,
    floor: CachePinId,
    checkpoint: ObjectDigest,
    generation: u64,
    valid_until: u64,
) -> Result<CacheAuthorityScopeV1, PinError> {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.pin-compaction-subject.v1\0");
    hasher.update(floor.as_bytes());
    hasher.update(checkpoint.as_bytes());
    let subject = ObjectDigest::from_bytes(hasher.finalize().into());
    Ok(CacheAuthorityScopeV1::new(
        partition,
        subject,
        None,
        checkpoint,
        partition.backing().root(),
        generation,
        valid_until,
    )?)
}

fn pin_compaction_floor_digest(
    pin: CachePinId,
    partition: ObjectDigest,
    checkpoint: ObjectDigest,
    generation: u64,
) -> ObjectDigest {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.pin-compaction-floor.v1\0");
    hasher.update(pin.as_bytes());
    hasher.update(partition.as_bytes());
    hasher.update(checkpoint.as_bytes());
    hasher.update(generation.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn read_pin_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], PinError> {
    let end = offset.checked_add(N).ok_or(PinError::InvalidFloor)?;
    let slice = bytes.get(offset..end).ok_or(PinError::InvalidFloor)?;
    <[u8; N]>::try_from(slice).map_err(|_| PinError::InvalidFloor)
}

fn increment(value: &mut u64) -> Result<(), AccountingError> {
    *value = value.checked_add(1).ok_or(AccountingError::Overflow)?;
    Ok(())
}

fn pin_acquisition_scope(pin: &CachePinV1) -> Result<CacheAuthorityScopeV1, PinError> {
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
    .map_err(PinError::from)
}

fn pin_subject(pin: &CachePinV1) -> ObjectDigest {
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

fn logical_consumer_key(pin: &CachePinV1) -> Option<LogicalPinConsumerKeyV1> {
    (pin.kind == CachePinKindV1::LogicalLease).then(|| {
        (
            pin.partition.digest(),
            object_descriptor_commitment(&pin.object),
            pin.project,
            pin.view,
            pin.attachment,
        )
    })
}

pub(crate) fn valid_logical_renewal(previous: &CachePinV1, renewed: &CachePinV1) -> bool {
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

#[allow(clippy::too_many_arguments)]
fn pin_subject_fields(
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

fn validate_release(pin: &CachePinV1, drain: PinDrainEvidenceV1) -> Result<(), PinError> {
    pin.clone().validate()?;
    if drain.pin != pin.id || drain.digest.as_bytes() == &[0; 32] {
        return Err(PinError::EvidenceMismatch);
    }
    if matches!(
        pin.kind,
        CachePinKindV1::KernelReference | CachePinKindV1::BackingRegistration
    ) && drain.outcome != PinDrainOutcomeV1::ConsumerAbsentAndReferencesClosed
    {
        return Err(PinError::DrainNotProved);
    }
    Ok(())
}
