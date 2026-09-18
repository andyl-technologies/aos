//! Protected project and node cache accounting.
//!
//! Reservation promises, committed residency, retained source obligations, and
//! logical/kernel/backing pins are accounted independently.  Mutations apply to
//! a cloned projection and replace live state only after every checked total
//! and hard quota succeeds, providing the pure reducer's atomicity boundary.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, OperationId, ProjectId};

use super::domain::{PhysicalPartitionId, validate_object_descriptor};

/// Bounds all protected accounting replay material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountingLimitsV1 {
    /// Maximum protected project quota records.
    pub maximum_project_quotas: usize,
    /// Maximum retained reservation generations.
    pub maximum_reservations: usize,
}

impl AccountingLimitsV1 {
    fn validate(self) -> Result<Self, AccountingError> {
        if self.maximum_project_quotas == 0
            || self.maximum_project_quotas > 1_000_000
            || self.maximum_reservations == 0
            || self.maximum_reservations > 1_000_000
        {
            return Err(AccountingError::InvalidQuota);
        }
        Ok(self)
    }
}

/// Identifies one cache capacity reservation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheReservationId([u8; 16]);

impl CacheReservationId {
    /// Constructs a nonzero reservation identity.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::InvalidRecord`] for the zero sentinel.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, AccountingError> {
        if bytes == [0; 16] {
            return Err(AccountingError::InvalidRecord);
        }
        Ok(Self(bytes))
    }

    /// Borrows the exact identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Defines hard physical and logical limits for one node partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeCacheQuotaV1 {
    /// Physical partition governed by this quota.
    pub partition: PhysicalPartitionId,
    /// Maximum charged physical bytes, including uncertain reservations.
    pub maximum_physical_bytes: u64,
    /// Maximum committed resident object count.
    pub maximum_resident_objects: u64,
    /// Maximum logical consumer pins across the partition.
    pub maximum_logical_pins: u64,
    /// Maximum upstream source-retention obligations.
    pub maximum_source_retentions: u64,
    /// Maximum kernel open/mapping/lookup references.
    pub maximum_kernel_references: u64,
    /// Maximum passthrough or backing registrations.
    pub maximum_backing_registrations: u64,
    /// Capacity retained for already-admitted recovery obligations.
    pub recovery_reserve_bytes: u64,
    /// High-water mark that initiates eviction planning.
    pub high_water_bytes: u64,
    /// Low-water target used to size eviction plans.
    pub low_water_bytes: u64,
}

impl NodeCacheQuotaV1 {
    /// Validates a coherent hard capacity envelope.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::InvalidQuota`] for zero, inverted, or
    /// impossible water marks and reserves.
    pub fn validate(self) -> Result<Self, AccountingError> {
        if self.maximum_physical_bytes == 0
            || self.maximum_resident_objects == 0
            || self.maximum_logical_pins == 0
            || self.maximum_source_retentions == 0
            || self.maximum_kernel_references == 0
            || self.maximum_backing_registrations == 0
            || self.recovery_reserve_bytes > self.maximum_physical_bytes
            || self.low_water_bytes > self.high_water_bytes
            || self.high_water_bytes > self.maximum_physical_bytes
        {
            return Err(AccountingError::InvalidQuota);
        }
        Ok(self)
    }
}

/// Defines protected project-attributed limits within a node partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectCacheQuotaV1 {
    /// Project to which logical demand is attributed.
    pub project: ProjectId,
    /// Physical partition in which demand may be served.
    pub partition: PhysicalPartitionId,
    /// Maximum outstanding reservation and residency bytes.
    pub maximum_charged_bytes: u64,
    /// Maximum logical pin count.
    pub maximum_logical_pins: u64,
    /// Maximum source-retention obligation count.
    pub maximum_source_retentions: u64,
    /// Maximum kernel-reference pin count attributed to the project.
    pub maximum_kernel_references: u64,
    /// Maximum backing-registration pin count attributed to the project.
    pub maximum_backing_registrations: u64,
}

impl ProjectCacheQuotaV1 {
    /// Validates one nonempty project quota.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::InvalidQuota`] for sentinel or zero limits.
    pub fn validate(self) -> Result<Self, AccountingError> {
        if self.project.as_bytes() == &[0; 16]
            || self.maximum_charged_bytes == 0
            || self.maximum_logical_pins == 0
            || self.maximum_source_retentions == 0
            || self.maximum_kernel_references == 0
            || self.maximum_backing_registrations == 0
        {
            return Err(AccountingError::InvalidQuota);
        }
        Ok(self)
    }
}

/// States how reservation bytes remain charged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReservationStateV1 {
    /// Capacity is promised before allocation or fetch.
    Reserved = 1,
    /// An effect outcome is ambiguous and the full promise remains charged.
    Uncertain = 2,
    /// Exact used bytes were converted into committed residency.
    Converted = 3,
    /// A proven pre-effect or absent outcome released the promise.
    Released = 4,
    /// Physical reclamation was proved after committed residency.
    Evicted = 5,
}

/// Retains one immutable reservation generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheReservationV1 {
    /// Stable reservation identity.
    pub id: CacheReservationId,
    /// Idempotent operation owning the reservation.
    pub operation: OperationId,
    /// Attributed project.
    pub project: ProjectId,
    /// Exact physical partition.
    pub partition: PhysicalPartitionId,
    /// Complete object planned for admission.
    pub descriptor: ObjectDescriptor,
    /// Worst-case charged bytes.
    pub reserved_bytes: u64,
    /// Exact immutable admission plan that owns these bytes.
    pub plan_digest: ObjectDigest,
    /// Exact bytes converted to residency, otherwise zero.
    pub resident_bytes: u64,
    /// Closed reservation state.
    pub state: ReservationStateV1,
    /// Monotone generation.
    pub generation: u64,
    /// Exact predecessor digest, absent only at generation one.
    pub predecessor: Option<ObjectDigest>,
    /// Complete record commitment.
    pub digest: ObjectDigest,
}

impl CacheReservationV1 {
    pub(crate) fn validate_record(&self) -> Result<(), AccountingError> {
        validate_reservation(self)
    }

    /// Produces a checked successor without changing its immutable binding.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::InvalidTransition`] for an illegal state or
    /// byte conversion, and [`AccountingError::GenerationExhausted`] on overflow.
    pub fn successor(
        &self,
        state: ReservationStateV1,
        resident_bytes: u64,
    ) -> Result<Self, AccountingError> {
        let legal = matches!(
            (self.state, state),
            (ReservationStateV1::Reserved, ReservationStateV1::Uncertain)
                | (ReservationStateV1::Reserved, ReservationStateV1::Converted)
                | (ReservationStateV1::Reserved, ReservationStateV1::Released)
                | (ReservationStateV1::Uncertain, ReservationStateV1::Converted)
                | (ReservationStateV1::Uncertain, ReservationStateV1::Released)
                | (ReservationStateV1::Converted, ReservationStateV1::Evicted)
        );
        let valid_bytes = match state {
            ReservationStateV1::Converted => {
                resident_bytes > 0 && resident_bytes <= self.reserved_bytes
            }
            _ => resident_bytes == 0,
        };
        if !legal || !valid_bytes {
            return Err(AccountingError::InvalidTransition);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(AccountingError::GenerationExhausted)?;
        let mut next = Self {
            id: self.id,
            operation: self.operation,
            project: self.project,
            partition: self.partition,
            descriptor: self.descriptor.clone(),
            reserved_bytes: self.reserved_bytes,
            plan_digest: self.plan_digest,
            resident_bytes,
            state,
            generation,
            predecessor: Some(self.digest),
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        next.digest = reservation_digest(&next);
        Ok(next)
    }
}

/// Aggregates separately meaningful cache charges.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheUsageV1 {
    /// Reserved or uncertain bytes not yet converted or released.
    pub reservation_bytes: u64,
    /// Committed physical residency bytes.
    pub residency_bytes: u64,
    /// Committed resident object count.
    pub resident_objects: u64,
    /// Project-attributed logical pin count.
    pub logical_pins: u64,
    /// Retained upstream source obligations.
    pub source_retentions: u64,
    /// Kernel references observed for physical reclamation safety.
    pub kernel_references: u64,
    /// Backing registrations retained outside ordinary process FD limits.
    pub backing_registrations: u64,
}

impl CacheUsageV1 {
    /// Returns all physical bytes conservatively charged at the node.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Overflow`] if totals cannot be represented.
    pub fn physical_charged_bytes(self) -> Result<u64, AccountingError> {
        self.reservation_bytes
            .checked_add(self.residency_bytes)
            .ok_or(AccountingError::Overflow)
    }
}

/// Materializes protected quota and reservation state.
#[derive(Clone, Debug)]
pub struct CacheAccountingV1 {
    limits: AccountingLimitsV1,
    node_quota: NodeCacheQuotaV1,
    project_quotas: BTreeMap<[u8; 16], ProjectCacheQuotaV1>,
    reservations: BTreeMap<CacheReservationId, CacheReservationV1>,
    node_usage: CacheUsageV1,
    project_usage: BTreeMap<[u8; 16], CacheUsageV1>,
}

impl CacheAccountingV1 {
    /// Replays quotas and latest reservation records into checked totals.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] for malformed quotas, conflicting records,
    /// broken digests, overflow, or a retained state above a hard quota.
    pub fn replay(
        limits: AccountingLimitsV1,
        node_quota: NodeCacheQuotaV1,
        project_quotas: impl IntoIterator<Item = ProjectCacheQuotaV1>,
        reservations: impl IntoIterator<Item = CacheReservationV1>,
    ) -> Result<Self, AccountingError> {
        let limits = limits.validate()?;
        let node_quota = node_quota.validate()?;
        let mut state = Self {
            limits,
            node_quota,
            project_quotas: BTreeMap::new(),
            reservations: BTreeMap::new(),
            node_usage: CacheUsageV1::default(),
            project_usage: BTreeMap::new(),
        };
        for quota in project_quotas {
            if state.project_quotas.len() >= state.limits.maximum_project_quotas {
                return Err(AccountingError::ReplayLimitExceeded);
            }
            let quota = quota.validate()?;
            if quota.partition != state.node_quota.partition
                || state
                    .project_quotas
                    .insert(*quota.project.as_bytes(), quota)
                    .is_some()
            {
                return Err(AccountingError::InvalidQuota);
            }
        }
        for reservation in reservations {
            if state.reservations.len() >= state.limits.maximum_reservations {
                return Err(AccountingError::ReplayLimitExceeded);
            }
            validate_reservation(&reservation)?;
            if reservation.partition != state.node_quota.partition
                || state
                    .reservations
                    .insert(reservation.id, reservation)
                    .is_some()
            {
                return Err(AccountingError::CorruptState);
            }
        }
        state.recompute()?;
        Ok(state)
    }

    /// Atomically reserves worst-case bytes before any allocation.
    ///
    /// Exact identity and facts replay without charging twice.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] for conflict, unknown project quota, or
    /// project/node capacity exhaustion.
    pub fn reserve(
        &mut self,
        id: CacheReservationId,
        operation: OperationId,
        project: ProjectId,
        descriptor: ObjectDescriptor,
        reserved_bytes: u64,
        plan_digest: ObjectDigest,
    ) -> Result<CacheReservationV1, AccountingError> {
        if operation.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || validate_object_descriptor(&descriptor).is_err()
            || reserved_bytes < descriptor.encoded_size()
            || plan_digest.as_bytes() == &[0; 32]
        {
            return Err(AccountingError::InvalidRecord);
        }
        let mut reservation = CacheReservationV1 {
            id,
            operation,
            project,
            partition: self.node_quota.partition,
            descriptor,
            reserved_bytes,
            plan_digest,
            resident_bytes: 0,
            state: ReservationStateV1::Reserved,
            generation: 1,
            predecessor: None,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        reservation.digest = reservation_digest(&reservation);
        if let Some(existing) = self.reservations.get(&id) {
            return if existing == &reservation {
                Ok(existing.clone())
            } else {
                Err(AccountingError::Conflict)
            };
        }
        if !self.project_quotas.contains_key(project.as_bytes()) {
            return Err(AccountingError::UnknownProjectQuota);
        }
        if self.reservations.len() >= self.limits.maximum_reservations {
            return Err(AccountingError::ReplayLimitExceeded);
        }

        let mut next = self.clone();
        next.reservations.insert(id, reservation.clone());
        next.recompute()?;
        let ordinary_limit = next
            .node_quota
            .maximum_physical_bytes
            .checked_sub(next.node_quota.recovery_reserve_bytes)
            .ok_or(AccountingError::InvalidQuota)?;
        if next.node_usage.physical_charged_bytes()? > ordinary_limit {
            return Err(AccountingError::NodeQuotaExceeded);
        }
        *self = next;
        Ok(reservation)
    }

    /// Atomically installs an exact successor reservation state.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] for absent identity, predecessor mismatch,
    /// invalid transition, or quota failure.
    pub fn transition(
        &mut self,
        id: CacheReservationId,
        expected_digest: ObjectDigest,
        state: ReservationStateV1,
        resident_bytes: u64,
    ) -> Result<CacheReservationV1, AccountingError> {
        let current = self
            .reservations
            .get(&id)
            .ok_or(AccountingError::ReservationAbsent)?;
        if current.state == state
            && current.resident_bytes == resident_bytes
            && current.predecessor == Some(expected_digest)
        {
            return Ok(current.clone());
        }
        if current.digest != expected_digest {
            return Err(AccountingError::Conflict);
        }
        let successor = current.successor(state, resident_bytes)?;
        let mut next = self.clone();
        next.reservations.insert(id, successor.clone());
        next.recompute()?;
        *self = next;
        Ok(successor)
    }

    /// Replaces pin-derived counts after an atomic integrated projection check.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError`] when the supplied counts overflow project or
    /// node limits.
    pub(crate) fn with_pin_usage(
        &self,
        per_project: &BTreeMap<[u8; 16], CacheUsageV1>,
        node_pin_usage: CacheUsageV1,
    ) -> Result<Self, AccountingError> {
        let mut next = self.clone();
        next.recompute()?;
        next.node_usage.logical_pins = node_pin_usage.logical_pins;
        next.node_usage.source_retentions = node_pin_usage.source_retentions;
        next.node_usage.kernel_references = node_pin_usage.kernel_references;
        next.node_usage.backing_registrations = node_pin_usage.backing_registrations;
        for (project, pins) in per_project {
            let usage = next.project_usage.entry(*project).or_default();
            usage.logical_pins = pins.logical_pins;
            usage.source_retentions = pins.source_retentions;
            usage.kernel_references = pins.kernel_references;
            usage.backing_registrations = pins.backing_registrations;
        }
        next.validate_totals()?;
        Ok(next)
    }

    /// Returns the current checked node usage.
    #[must_use]
    pub const fn node_usage(&self) -> CacheUsageV1 {
        self.node_usage
    }

    /// Returns the node high-water threshold.
    #[must_use]
    pub const fn high_water_bytes(&self) -> u64 {
        self.node_quota.high_water_bytes
    }

    /// Returns the node low-water target.
    #[must_use]
    pub const fn low_water_bytes(&self) -> u64 {
        self.node_quota.low_water_bytes
    }

    /// Returns the exact physical partition governed by this projection.
    #[must_use]
    pub const fn partition(&self) -> PhysicalPartitionId {
        self.node_quota.partition
    }

    /// Returns bytes that must be reclaimed to reach low water after admission.
    ///
    /// A zero result means current charge is at or below high water. The value
    /// is advisory planning input; it never authorizes candidate selection.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Overflow`] if checked charge cannot be added.
    pub fn eviction_requirement(&self) -> Result<u64, AccountingError> {
        let charged = self.node_usage.physical_charged_bytes()?;
        if charged <= self.node_quota.high_water_bytes {
            return Ok(0);
        }
        charged
            .checked_sub(self.node_quota.low_water_bytes)
            .ok_or(AccountingError::Overflow)
    }

    /// Returns one retained reservation without granting allocation authority.
    #[must_use]
    pub fn reservation(&self, id: CacheReservationId) -> Option<&CacheReservationV1> {
        self.reservations.get(&id)
    }

    fn recompute(&mut self) -> Result<(), AccountingError> {
        self.node_usage = CacheUsageV1::default();
        self.project_usage.clear();
        for reservation in self.reservations.values() {
            validate_reservation(reservation)?;
            let usage = self
                .project_usage
                .entry(*reservation.project.as_bytes())
                .or_default();
            match reservation.state {
                ReservationStateV1::Reserved | ReservationStateV1::Uncertain => {
                    checked_add(&mut usage.reservation_bytes, reservation.reserved_bytes)?;
                    checked_add(
                        &mut self.node_usage.reservation_bytes,
                        reservation.reserved_bytes,
                    )?;
                }
                ReservationStateV1::Converted => {
                    checked_add(&mut usage.residency_bytes, reservation.resident_bytes)?;
                    checked_add(&mut usage.resident_objects, 1)?;
                    checked_add(
                        &mut self.node_usage.residency_bytes,
                        reservation.resident_bytes,
                    )?;
                    checked_add(&mut self.node_usage.resident_objects, 1)?;
                }
                ReservationStateV1::Released | ReservationStateV1::Evicted => {}
            }
        }
        self.validate_totals()
    }

    fn validate_totals(&self) -> Result<(), AccountingError> {
        if self.node_usage.physical_charged_bytes()? > self.node_quota.maximum_physical_bytes
            || self.node_usage.resident_objects > self.node_quota.maximum_resident_objects
            || self.node_usage.logical_pins > self.node_quota.maximum_logical_pins
            || self.node_usage.source_retentions > self.node_quota.maximum_source_retentions
            || self.node_usage.kernel_references > self.node_quota.maximum_kernel_references
            || self.node_usage.backing_registrations > self.node_quota.maximum_backing_registrations
        {
            return Err(AccountingError::NodeQuotaExceeded);
        }
        for (project, usage) in &self.project_usage {
            let quota = self
                .project_quotas
                .get(project)
                .ok_or(AccountingError::UnknownProjectQuota)?;
            if usage.physical_charged_bytes()? > quota.maximum_charged_bytes
                || usage.logical_pins > quota.maximum_logical_pins
                || usage.source_retentions > quota.maximum_source_retentions
                || usage.kernel_references > quota.maximum_kernel_references
                || usage.backing_registrations > quota.maximum_backing_registrations
            {
                return Err(AccountingError::ProjectQuotaExceeded);
            }
        }
        Ok(())
    }
}

/// Reports protected accounting failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AccountingError {
    /// A hard quota or water-mark policy is malformed.
    #[error("cache quota is invalid")]
    InvalidQuota,
    /// A reservation or retained successor is malformed.
    #[error("cache accounting record is invalid")]
    InvalidRecord,
    /// A project has no protected quota in this partition.
    #[error("cache project quota is absent")]
    UnknownProjectQuota,
    /// An identity, predecessor, or immutable binding conflicts.
    #[error("cache accounting compare-and-swap conflict")]
    Conflict,
    /// No retained reservation has the requested identity.
    #[error("cache reservation is absent")]
    ReservationAbsent,
    /// A reservation state transition is illegal.
    #[error("cache reservation transition is invalid")]
    InvalidTransition,
    /// The project-attributed hard quota is exhausted.
    #[error("cache project quota is exhausted")]
    ProjectQuotaExceeded,
    /// The node physical hard quota is exhausted.
    #[error("cache node quota is exhausted")]
    NodeQuotaExceeded,
    /// Checked arithmetic overflowed.
    #[error("cache accounting arithmetic overflow")]
    Overflow,
    /// A monotone generation is exhausted.
    #[error("cache accounting generation is exhausted")]
    GenerationExhausted,
    /// Replayed protected state is inconsistent.
    #[error("cache accounting state is corrupt")]
    CorruptState,
    /// Protected replay input exceeds its configured record bound.
    #[error("cache accounting replay bound is exceeded")]
    ReplayLimitExceeded,
}

fn validate_reservation(reservation: &CacheReservationV1) -> Result<(), AccountingError> {
    let state_bytes_valid = match reservation.state {
        ReservationStateV1::Converted => {
            reservation.resident_bytes > 0
                && reservation.resident_bytes <= reservation.reserved_bytes
        }
        _ => reservation.resident_bytes == 0,
    };
    if reservation.operation.as_bytes() == &[0; 16]
        || reservation.project.as_bytes() == &[0; 16]
        || validate_object_descriptor(&reservation.descriptor).is_err()
        || reservation.reserved_bytes < reservation.descriptor.encoded_size()
        || reservation.plan_digest.as_bytes() == &[0; 32]
        || reservation.generation == 0
        || (reservation.generation == 1) != reservation.predecessor.is_none()
        || !state_bytes_valid
        || reservation.digest != reservation_digest(reservation)
    {
        return Err(AccountingError::InvalidRecord);
    }
    Ok(())
}

fn reservation_digest(reservation: &CacheReservationV1) -> ObjectDigest {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.reservation.v1\0");
    hasher.update(reservation.id.as_bytes());
    hasher.update(reservation.operation.as_bytes());
    hasher.update(reservation.project.as_bytes());
    hasher.update(reservation.partition.digest().as_bytes());
    let media = reservation.descriptor.media_type().as_str().as_bytes();
    hasher.update((media.len() as u16).to_be_bytes());
    hasher.update(media);
    hasher.update(reservation.descriptor.digest().as_bytes());
    hasher.update(reservation.descriptor.encoded_size().to_be_bytes());
    hasher.update(reservation.reserved_bytes.to_be_bytes());
    hasher.update(reservation.plan_digest.as_bytes());
    hasher.update(reservation.resident_bytes.to_be_bytes());
    hasher.update([reservation.state as u8]);
    hasher.update(reservation.generation.to_be_bytes());
    hasher.update(
        reservation
            .predecessor
            .map_or([0; 32], |digest| *digest.as_bytes()),
    );
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn checked_add(target: &mut u64, value: u64) -> Result<(), AccountingError> {
    *target = target.checked_add(value).ok_or(AccountingError::Overflow)?;
    Ok(())
}
