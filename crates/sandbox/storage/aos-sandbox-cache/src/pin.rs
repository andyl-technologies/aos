//! Distinct logical, source-retention, kernel-reference, and backing pins.
//!
//! Lease expiry prevents new lookup and begins drain; it does not erase a
//! kernel-held reference.  Physical eviction is possible only after every pin
//! class for an object reaches zero and committed source retention remains
//! sufficient for any active lazy view that can refetch the object.

use std::collections::BTreeMap;
use std::marker::PhantomData;

use aos_sandbox_model::{
    AttachmentId, IncarnationId, ObjectDescriptor, ObjectDigest, ProjectId, SandboxId, ViewId,
};

use aos_sandbox_protocol::cache_state::{
    AccountingError, CacheUsageV1, PhysicalPartitionId, object_descriptor_commitment,
    validate_object_descriptor,
};

use super::domain::{
    CacheAuthorityError, CacheAuthorityOwner, CacheAuthorityPurposeV1, CacheAuthorityScopeV1,
    VerifiedCacheCapabilityV1,
};

use aos_sandbox_protocol::cache_state::pin_data::{self, CachePinDataV1, PinDrainEvidenceDataV1, pin_subject_fields};
pub use aos_sandbox_protocol::cache_state::pin_data::{CachePinId, CachePinKindV1, PinDrainOutcomeV1};
pub(crate) use aos_sandbox_protocol::cache_state::pin_data::valid_logical_renewal;
use aos_sandbox_protocol::cache_state::pin_ledger::{self, logical_consumer_key};
use aos_sandbox_protocol::cache_state::pin_floor::PinCompactionFloorDataV1;
pub(crate) use aos_sandbox_protocol::cache_state::pin_floor::PIN_FLOOR_BYTES;

/// Retains a Native historical floor issued by its protected decoding or compaction path.
///
/// Historical DATA cannot construct the Native floor wrapper.
///
/// ```compile_fail
/// fn issue(data: aos_sandbox_protocol::cache_state::pin_floor::PinCompactionFloorDataV1) {
///     let _ = aos_sandbox_cache::pin::PinCompactionFloorV1(data);
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinCompactionFloorV1(PinCompactionFloorDataV1);

impl std::ops::Deref for PinCompactionFloorV1 {
    type Target = PinCompactionFloorDataV1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PinCompactionFloorV1 {
    pub(crate) const fn from_parsed_history_data_v1(data: PinCompactionFloorDataV1) -> Self {
        Self(data)
    }

    /// Returns the greatest compacted pin identity.
    #[must_use]
    pub const fn pin(self) -> CachePinId {
        self.0.pin
    }

    /// Returns the protected checkpoint anchoring compaction.
    #[must_use]
    pub const fn checkpoint(self) -> ObjectDigest {
        self.0.checkpoint
    }
}

/// Encodes a protected historical pin floor using its canonical DATA codec.
///
/// # Errors
///
/// Returns [`PinError::InvalidFloor`] for an inconsistent floor commitment.
pub fn encode_pin_compaction_floor(
    floor: PinCompactionFloorV1,
) -> Result<[u8; PIN_FLOOR_BYTES], PinError> {
    aos_sandbox_protocol::cache_state::pin_floor::encode_pin_compaction_floor(floor.0)
        .map_err(PinError::from)
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
    pub(crate) fn from_verified(
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

/// Retains a verifier-issued pin around its canonical historical fields.
///
/// Historical DATA cannot issue the Native wrapper.
///
/// ```compile_fail
/// fn issue(data: aos_sandbox_protocol::cache_state::pin_data::CachePinDataV1) {
///     let _ = aos_sandbox_cache::pin::CachePinV1(data);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachePinV1(CachePinDataV1);

impl std::ops::Deref for CachePinV1 {
    type Target = CachePinDataV1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Retains a released Native pin and its exact drain proof.
pub type ReleasedCachePinV1 = pin_ledger::ReleasedCachePinDataV1<CachePinV1, PinDrainEvidenceV1>;

impl CachePinV1 {
    pub(crate) fn from_parsed_history_data_v1(data: CachePinDataV1) -> Self {
        Self(data)
    }

    pub(crate) const fn historical_data_v1(&self) -> &CachePinDataV1 {
        &self.0
    }

    // The authority issuer uses this same subject binding before the pin
    // exists; `from_verified` independently checks it against the capability.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn logical_acquisition_scope(
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
    ) -> Result<CacheAuthorityScopeV1, PinError> {
        CachePinDataV1::logical_acquisition_scope(
            id, partition, object, project, view, attachment, sandbox,
            incarnation, assignment_epoch, lease_valid_until,
        ).map_err(PinError::from)
    }

    pub(crate) const fn authority_binding(&self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.0.authority_scope, self.0.evidence)
    }

    /// Returns the durable identity retained across logical lease renewals.
    #[must_use]
    pub const fn id(&self) -> CachePinId {
        self.0.id
    }

    /// Returns the physical cache partition retaining this obligation.
    #[must_use]
    pub const fn partition(&self) -> PhysicalPartitionId {
        self.0.partition
    }

    /// Borrows the exact immutable object retained by this obligation.
    #[must_use]
    pub const fn object(&self) -> &ObjectDescriptor {
        &self.0.object
    }

    /// Returns the consumer project.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.0.project
    }

    /// Returns the consumer view.
    #[must_use]
    pub const fn view(&self) -> ViewId {
        self.0.view
    }

    /// Returns the consuming attachment, when the pin is attachment-scoped.
    #[must_use]
    pub const fn attachment(&self) -> Option<AttachmentId> {
        self.0.attachment
    }

    /// Returns the obligation class.
    #[must_use]
    pub const fn kind(&self) -> CachePinKindV1 {
        self.0.kind
    }

    /// Returns the exact acquisition evidence required by a later release.
    #[must_use]
    pub const fn evidence(&self) -> ObjectDigest {
        self.0.evidence
    }

    /// Returns the deadline after which this lease permits no new use.
    #[must_use]
    pub const fn lease_valid_until(&self) -> u64 {
        self.0.lease_valid_until
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
        Ok(Self(CachePinDataV1::recover_historical(
            id, partition, object, project, view, attachment, sandbox,
            incarnation, kind, assignment_epoch, lease_valid_until, evidence,
        )?))
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
        let authority_scope = crate::domain::new_cache_authority_scope_v1(
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
        Self(CachePinDataV1 {
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
        })
        .validate()
    }

    /// Validates complete pin bindings and class-specific shape.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::InvalidPin`] for missing identity, evidence, or
    /// required consumer/assignment bindings.
    pub fn validate(self) -> Result<Self, PinError> {
        Ok(Self(self.0.validate()?))
    }

    pub(crate) fn validate_current(
        &self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        now: u64,
    ) -> Result<(), PinError> {
        require_pin_current_data_v1(&self.0, owner, capability, now)
    }

    /// Returns whether lease time still permits a new logical use.
    #[must_use]
    pub const fn permits_new_use(&self, now: u64) -> bool {
        self.0.lease_valid_until > now
    }
}

/// Holds the actual protected pin projection with its verifier-issued rows.
#[derive(Clone, Debug)]
pub struct CachePinLedgerV1(pin_ledger::CachePinLedgerDataV1<CachePinV1, PinDrainEvidenceV1, PinCompactionFloorV1>);

impl CachePinLedgerV1 {
    /// Constructs an empty bounded pin ledger.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::Capacity`] for zero or excessive retention bounds.
    pub fn new(maximum_records: usize) -> Result<Self, PinError> {
        Ok(Self(pin_ledger::CachePinLedgerDataV1::new(maximum_records)?))
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
        Ok(Self(pin_ledger::CachePinLedgerDataV1::replay(
            maximum_records, compacted_through, pins, released,
        )?))
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
        if self.0
            .compacted_through
            .is_some_and(|floor| pin.id <= floor.pin)
        {
            return Err(PinError::Conflict);
        }
        if self.0.released.contains_key(&pin.id) {
            return Err(PinError::Conflict);
        }
        let logical_key = logical_consumer_key(&pin);
        if logical_key.as_ref().is_some_and(|key| {
            self.0.logical_consumers
                .get(key)
                .is_some_and(|id| *id != pin.id)
        }) {
            return Err(PinError::Conflict);
        }
        if let Some(existing) = self.0.pins.get(&pin.id) {
            return if existing == &pin {
                Ok(())
            } else {
                Err(PinError::Conflict)
            };
        }
        if self.0.pins.len() + self.0.released.len() >= self.0.maximum_records {
            return Err(PinError::Capacity);
        }
        if let Some(key) = logical_key {
            self.0.logical_consumers.insert(key, pin.id);
        }
        self.0.pins.insert(pin.id, pin);
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
        self.0.pins.insert(renewed.id, renewed);
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
        if let Some(released) = self.0.released.get(&id) {
            drain.validate_current(owner, capability, &released.pin, now)?;
            return if released.pin.evidence == expected_evidence && released.drain == drain {
                Ok(released.clone())
            } else {
                Err(PinError::Conflict)
            };
        }
        let pin = self.0.pins.get(&id).ok_or(PinError::Absent)?;
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
            && self.0.logical_consumers.get(&key) != Some(&id)
        {
            return Err(PinError::Conflict);
        }
        let pin = self.0.pins.remove(&id).ok_or(PinError::Absent)?;
        if let Some(key) = logical_consumer_key(&pin) {
            self.0.logical_consumers.remove(&key);
        }
        let released = ReleasedCachePinV1 { pin, drain };
        self.0.released.insert(id, released.clone());
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
        if self.0
            .compacted_through
            .is_some_and(|current| floor <= current.pin)
            || self.0.pins.keys().any(|id| *id <= floor)
            || self.0
                .released
                .range(..=floor)
                .any(|(_, released)| released.pin.partition != partition)
            || physical_absence.partition != partition
            || physical_absence.floor != floor
            || !self.0
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
        self.0.released.retain(|id, _| *id > floor);
        let floor = PinCompactionFloorV1(PinCompactionFloorDataV1 {
            pin: floor,
            partition: partition.digest(),
            checkpoint,
            generation,
            digest: aos_sandbox_protocol::cache_state::pin_floor::pin_compaction_floor_digest(floor, partition.digest(), checkpoint, generation),
        });
        self.0.compacted_through = Some(floor);
        Ok(floor)
    }

    /// Returns whether an object has any physical-reclamation blocker.
    #[must_use]
    pub fn blocks_eviction(
        &self,
        partition: PhysicalPartitionId,
        object: &ObjectDescriptor,
    ) -> bool {
        self.0.blocks_eviction(partition, object)
    }

    /// Returns one retained pin without treating it as current authority.
    #[must_use]
    pub fn pin(&self, id: CachePinId) -> Option<&CachePinV1> {
        self.0.pin(id)
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
        self.0.logical_consumer_pin(partition, object, project, view, attachment)
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
        self.0.next_pin_id().map_err(PinError::from)
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &CachePinV1> {
        self.0.values()
    }

    /// Computes pin-class usage for atomic quota validation.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Overflow`] if a count cannot be represented.
    pub fn usage(
        &self,
    ) -> Result<(BTreeMap<[u8; 16], CacheUsageV1>, CacheUsageV1), AccountingError> {
        self.0.usage()
    }
}

/// Retains verifier-issued drain evidence around its historical fields.
///
/// Historical DATA cannot issue the Native drain wrapper.
///
/// ```compile_fail
/// fn issue(data: aos_sandbox_protocol::cache_state::pin_data::PinDrainEvidenceDataV1) {
///     let _ = aos_sandbox_cache::pin::PinDrainEvidenceV1(data);
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinDrainEvidenceV1(PinDrainEvidenceDataV1);

impl std::ops::Deref for PinDrainEvidenceV1 {
    type Target = PinDrainEvidenceDataV1;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PinDrainEvidenceV1 {
    pub(crate) const fn from_parsed_history_data_v1(data: PinDrainEvidenceDataV1) -> Self {
        Self(data)
    }

    pub(crate) const fn historical_data_v1(self) -> PinDrainEvidenceDataV1 {
        self.0
    }

    pub(crate) const fn authority_binding(self) -> (CacheAuthorityScopeV1, ObjectDigest) {
        (self.0.authority_scope, self.0.digest)
    }

    pub(crate) const fn valid_until(self) -> u64 {
        self.0.authority_scope.valid_until()
    }

    pub(crate) fn recover_historical(
        pin: &CachePinV1,
        outcome: PinDrainOutcomeV1,
        digest: ObjectDigest,
        valid_until: u64,
    ) -> Result<Self, PinError> {
        Ok(Self(PinDrainEvidenceDataV1::recover_historical(
            pin, outcome, digest, valid_until,
        )?))
    }

    pub(crate) const fn digest(self) -> ObjectDigest {
        self.0.digest
    }

    pub(crate) const fn outcome(self) -> PinDrainOutcomeV1 {
        self.0.outcome
    }

    pub(crate) fn validate_replay(self, pin: &CachePinV1) -> Result<(), PinError> {
        self.0.validate_replay(pin).map_err(PinError::from)
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
        Ok(Self(PinDrainEvidenceDataV1 {
            pin: pin.id,
            outcome,
            digest: capability.record_digest(),
            authority_scope,
        }))
    }

    fn validate_current(
        self,
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        pin: &CachePinV1,
        now: u64,
    ) -> Result<(), PinError> {
        require_pin_drain_current_data_v1(self.0, owner, capability, pin, now)
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
    Ok(crate::domain::new_cache_authority_scope_v1(
        partition,
        subject,
        None,
        checkpoint,
        partition.backing().root(),
        generation,
        valid_until,
    )?)
}

fn pin_acquisition_scope(pin: &CachePinV1) -> Result<CacheAuthorityScopeV1, PinError> {
    pin_data::pin_acquisition_scope(pin).map_err(PinError::from)
}

fn pin_drain_scope(
    pin: &CachePinV1,
    outcome: PinDrainOutcomeV1,
    valid_until: u64,
) -> Result<CacheAuthorityScopeV1, PinError> {
    pin_data::pin_drain_scope(pin, outcome, valid_until).map_err(PinError::from)
}

fn validate_release(pin: &CachePinV1, drain: PinDrainEvidenceV1) -> Result<(), PinError> {
    pin_data::validate_release(pin, drain.0).map_err(PinError::from)
}

impl From<pin_data::PinDataErrorV1> for PinError {
    fn from(error: pin_data::PinDataErrorV1) -> Self {
        match error {
            pin_data::PinDataErrorV1::InvalidPin => Self::InvalidPin,
            pin_data::PinDataErrorV1::Conflict => Self::Conflict,
            pin_data::PinDataErrorV1::Capacity => Self::Capacity,
            pin_data::PinDataErrorV1::InvalidFloor => Self::InvalidFloor,
            pin_data::PinDataErrorV1::EvidenceMismatch => Self::EvidenceMismatch,
            pin_data::PinDataErrorV1::DrainNotProved => Self::DrainNotProved,
            pin_data::PinDataErrorV1::Authority(error) => Self::Authority(error.into()),
        }
    }
}

#[cfg(test)]
mod historical_representation_tests {
    use super::*;

    #[test]
    fn native_pin_wrappers_preserve_inline_size_and_alignment() {
        assert_eq!(std::mem::size_of::<CachePinV1>(), std::mem::size_of::<CachePinDataV1>());
        assert_eq!(std::mem::align_of::<CachePinV1>(), std::mem::align_of::<CachePinDataV1>());
        assert_eq!(std::mem::size_of::<PinDrainEvidenceV1>(), std::mem::size_of::<PinDrainEvidenceDataV1>());
        assert_eq!(std::mem::align_of::<PinDrainEvidenceV1>(), std::mem::align_of::<PinDrainEvidenceDataV1>());
        assert_eq!(std::mem::size_of::<CachePinLedgerV1>(), std::mem::size_of::<pin_ledger::CachePinLedgerDataV1<CachePinV1, PinDrainEvidenceV1, PinCompactionFloorV1>>());
        assert_eq!(std::mem::align_of::<CachePinLedgerV1>(), std::mem::align_of::<pin_ledger::CachePinLedgerDataV1<CachePinV1, PinDrainEvidenceV1, PinCompactionFloorV1>>());
    }
}

impl std::borrow::Borrow<CachePinDataV1> for CachePinV1 {
    fn borrow(&self) -> &CachePinDataV1 {
        &self.0
    }
}

impl std::borrow::Borrow<PinDrainEvidenceDataV1> for PinDrainEvidenceV1 {
    fn borrow(&self) -> &PinDrainEvidenceDataV1 {
        &self.0
    }
}

pub(crate) fn decode_pin_compaction_floor_persisted(
    partition: PhysicalPartitionId,
    bytes: &[u8],
) -> Result<PinCompactionFloorV1, PinError> {
    Ok(PinCompactionFloorV1(
        aos_sandbox_protocol::cache_state::pin_floor::decode_pin_compaction_floor_persisted(partition, bytes)?,
    ))
}

impl std::borrow::Borrow<PinCompactionFloorDataV1> for PinCompactionFloorV1 {
    fn borrow(&self) -> &PinCompactionFloorDataV1 {
        &self.0
    }
}

pub(crate) fn require_pin_current_data_v1(
    pin: &CachePinDataV1,
    owner: &CacheAuthorityOwner<'_, '_>,
    capability: &VerifiedCacheCapabilityV1,
    now: u64,
) -> Result<(), PinError> {
    let expected = pin_data::pin_acquisition_scope(pin).map_err(PinError::from)?;
    if expected != pin.authority_scope || capability.record_digest() != pin.evidence {
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

pub(crate) fn require_pin_drain_current_data_v1(
    drain: PinDrainEvidenceDataV1,
    owner: &CacheAuthorityOwner<'_, '_>,
    capability: &VerifiedCacheCapabilityV1,
    pin: &CachePinDataV1,
    now: u64,
) -> Result<(), PinError> {
    let expected = pin_data::pin_drain_scope(pin, drain.outcome, drain.authority_scope.valid_until()).map_err(PinError::from)?;
    if drain.authority_scope != expected || drain.digest != capability.record_digest() {
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
