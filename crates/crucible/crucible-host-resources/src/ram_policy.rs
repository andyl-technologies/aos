//! Portable operational RAM policy and reserve-before-apply resource ownership.
//!
//! These records contain no guest pointers, modeled clocks, or RAM digests.
//! Resident targets are preferences; strict peak admission remains a separate
//! resource entitlement. Template owners account shared physical resources once.
//! An ambiguous transition retains its complete peak until explicit convergence.

use std::collections::BTreeMap;

use crate::host_supervision::HostOperationBudgets;

/// Maximum simultaneously admitted resource owners in one bounded ledger.
pub const MAX_RAM_RESOURCE_OWNERS: usize = 4096;

/// Generation-bound operational RAM arena target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostRamTarget {
    /// Daemon incarnation; stale epochs cannot select recovered replacements.
    pub daemon_epoch: [u8; 32],
    /// Opaque authenticated execution or retained-template owner identity.
    pub owner_id: [u8; 32],
    /// Opaque node identity, or the template identity for a template owner.
    pub node_id: [u8; 32],
    /// Process/controller incarnation, advanced without reuse on replacement.
    pub owner_generation: u64,
    /// Independently advanced RAM mapping/topology ownership incarnation.
    pub arena_generation: u64,
    /// Explicit distinction between a private node and shared retained source.
    pub retained_template: bool,
}

/// Host placement mode; all modes preserve complete logical guest RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HostRamMode {
    /// Best-effort page cache with separately admitted peak capacity.
    Managed = 0,
    /// Complete backing with minimal safely evictable residency.
    DiskOriented = 1,
    /// Full prefaulted RAM with separately established residency locks.
    ResidentRequired = 2,
}

/// Operational-only policy for one running arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostRamPolicy {
    /// Desired placement mode, independently qualified by backend capabilities.
    pub mode: HostRamMode,
    /// Desired guest-page working set; this is not a hard peak guarantee.
    pub resident_target_bytes: u64,
    /// Relative cold-page eviction preference from zero through one hundred.
    pub eviction_preference: u8,
    /// Positive admitted background writeback rate.
    pub writeback_bytes_per_second: u64,
    /// Positive maximum concurrent paging I/O operations.
    pub maximum_paging_io_in_flight: u32,
    /// Permits bounded prefetch on an admitted target increase.
    pub prefetch_on_increase: bool,
    /// Fixed live operational deadline roster.
    pub latency: HostOperationBudgets,
}

/// Independently qualified backend behavior and compulsory resource floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostRamCapabilities {
    /// Complete logical guest RAM capacity.
    pub logical_ram_bytes: u64,
    /// Non-evictable process, manager, and fault-progress residency.
    pub compulsory_resident_bytes: u64,
    /// Sound worst-case guest-page execution peak; full RAM absent a proof.
    pub minimum_execution_peak_bytes: u64,
    /// Maximum genuinely supported concurrent paging I/O slots.
    pub maximum_paging_io_slots: u64,
    /// Backend can adjust the running arena without guest cooperation.
    pub dynamic_residency: bool,
    /// Backend can preserve all pages on disk and remove cold mappings safely.
    pub disk_oriented: bool,
    /// Backend can establish and maintain the required per-owner memory locks.
    pub resident_required: bool,
}

/// Independently bounded host resources reserved before physical application.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostResourceVector {
    /// Complete host resident peak, including compulsory overhead and buffers.
    pub resident_peak_bytes: u64,
    /// Preserved backing entitlement, including future unique dirty contents.
    pub backing_peak_bytes: u64,
    /// Independently limited metadata subset, already included in relevant peaks.
    pub metadata_bytes: u64,
    /// Independently limited transient staging subset of resident/disk peaks.
    pub staging_bytes: u64,
    /// Paging and preservation I/O slots.
    pub paging_io_slots: u64,
    /// CPU/vCPU admission slots.
    pub cpu_slots: u64,
    /// Process and worker-task admission slots.
    pub task_slots: u64,
    /// Owned descriptor allowance.
    pub file_descriptors: u64,
}

impl HostResourceVector {
    fn components(self) -> [u64; 8] {
        [
            self.resident_peak_bytes,
            self.backing_peak_bytes,
            self.metadata_bytes,
            self.staging_bytes,
            self.paging_io_slots,
            self.cpu_slots,
            self.task_slots,
            self.file_descriptors,
        ]
    }

    fn from_components(values: [u64; 8]) -> Self {
        Self {
            resident_peak_bytes: values[0],
            backing_peak_bytes: values[1],
            metadata_bytes: values[2],
            staging_bytes: values[3],
            paging_io_slots: values[4],
            cpu_slots: values[5],
            task_slots: values[6],
            file_descriptors: values[7],
        }
    }

    /// Returns whether every resource component fits another vector.
    pub fn fits(self, ceiling: Self) -> bool {
        self.components()
            .into_iter()
            .zip(ceiling.components())
            .all(|(used, limit)| used <= limit)
    }

    fn add(self, additional: Self) -> Result<Self, HostRamPolicyError> {
        let left = self.components();
        let right = additional.components();
        let mut result = [0; 8];
        for index in 0..8 {
            result[index] = left[index]
                .checked_add(right[index])
                .ok_or(HostRamPolicyError::CapacityRefused)?;
        }
        Ok(Self::from_components(result))
    }

    fn subtract(self, removed: Self) -> Result<Self, HostRamPolicyError> {
        let left = self.components();
        let right = removed.components();
        let mut result = [0; 8];
        for index in 0..8 {
            result[index] = left[index]
                .checked_sub(right[index])
                .ok_or(HostRamPolicyError::OwnershipUncertain)?;
        }
        Ok(Self::from_components(result))
    }
}

/// Typed operational policy/admission refusal.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HostRamPolicyError {
    /// A policy field is outside its portable contract.
    #[error("invalid host RAM policy")]
    InvalidPolicy,
    /// Requested backend behavior has not been qualified.
    #[error("unsupported host RAM policy capability")]
    Unsupported,
    /// An execution peak or complete preservation entitlement is insufficient.
    #[error("host RAM resource capacity refused")]
    CapacityRefused,
    /// The exact target is no longer an admitted owner.
    #[error("host RAM owner is not current")]
    NotCurrent,
    /// A caller used an obsolete reservation revision.
    #[error("host RAM reservation revision conflict: current {current}")]
    RevisionConflict {
        /// Current reservation revision.
        current: u64,
    },
    /// An earlier transition still owns its peak.
    #[error("host RAM reservation transition is still pending")]
    TransitionPending,
    /// An identity counter would wrap.
    #[error("host RAM reservation identity exhausted")]
    IdentityExhausted,
    /// Accounting or late completion cannot establish safe release.
    #[error("host RAM resource ownership is uncertain")]
    OwnershipUncertain,
}

impl HostRamPolicy {
    /// Validates a live update, allowing budget-only tuning of fixed placement.
    ///
    /// # Errors
    ///
    /// Returns the same admission errors as [`Self::validate`]. A backend that
    /// cannot change residency may still revise operational latency allowances
    /// when every placement field remains identical to its admitted policy.
    pub fn validate_update(
        self,
        previous: Self,
        mut capabilities: HostRamCapabilities,
        admitted: HostResourceVector,
        finite_outer: bool,
    ) -> Result<(), HostRamPolicyError> {
        if (Self {
            latency: previous.latency,
            ..self
        }) == previous
        {
            capabilities.dynamic_residency = true;
        }
        self.validate(capabilities, admitted, finite_outer)
    }

    /// Validates a target against qualified capabilities and admitted resources.
    ///
    /// # Errors
    ///
    /// Returns typed refusal for malformed fields, unsupported live behavior,
    /// insufficient inter-boundary peak, or incomplete backing entitlement.
    pub fn validate(
        self,
        capabilities: HostRamCapabilities,
        admitted: HostResourceVector,
        finite_outer: bool,
    ) -> Result<(), HostRamPolicyError> {
        if self.resident_target_bytes > capabilities.logical_ram_bytes
            || self.eviction_preference > 100
            || self.writeback_bytes_per_second == 0
            || self.maximum_paging_io_in_flight == 0
            || capabilities.minimum_execution_peak_bytes > capabilities.logical_ram_bytes
            || self.latency.validate(finite_outer).is_err()
        {
            return Err(HostRamPolicyError::InvalidPolicy);
        }
        if capabilities.maximum_paging_io_slots == 0
            || u64::from(self.maximum_paging_io_in_flight) > capabilities.maximum_paging_io_slots
            || !capabilities.dynamic_residency
            || (self.mode == HostRamMode::DiskOriented && !capabilities.disk_oriented)
            || (self.mode == HostRamMode::ResidentRequired && !capabilities.resident_required)
        {
            return Err(HostRamPolicyError::Unsupported);
        }
        let guest_peak = if self.mode == HostRamMode::ResidentRequired {
            capabilities.logical_ram_bytes
        } else {
            capabilities
                .minimum_execution_peak_bytes
                .max(self.resident_target_bytes)
        };
        let required = guest_peak
            .checked_add(capabilities.compulsory_resident_bytes)
            .ok_or(HostRamPolicyError::CapacityRefused)?;
        if admitted.resident_peak_bytes < required
            || admitted.backing_peak_bytes < capabilities.logical_ram_bytes
            || admitted.paging_io_slots < u64::from(self.maximum_paging_io_in_flight)
        {
            return Err(HostRamPolicyError::CapacityRefused);
        }
        Ok(())
    }
}

/// Generation-bound reserve-before-apply transition identity and entitlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostResourceTransition {
    /// Exact owner; replacement targets cannot acknowledge this transition.
    pub target: HostRamTarget,
    /// Nonreused resource transition identity.
    pub transition_id: u64,
    /// Reservation revision installed when transition peak was reserved.
    pub reservation_revision: u64,
    /// Final entitlement after authenticated physical convergence.
    pub requested: HostResourceVector,
    /// Complete held peak, including simultaneous old and new obligations.
    pub held_peak: HostResourceVector,
}

#[derive(Clone, Copy, Debug)]
struct Reservation {
    revision: u64,
    held: HostResourceVector,
    pending: Option<HostResourceTransition>,
}

/// Bounded sole-writer accounting for nodes, attempts, and shared templates.
#[derive(Debug)]
pub struct HostResourceLedger {
    capacity: HostResourceVector,
    used: HostResourceVector,
    next_transition: u64,
    owners: BTreeMap<HostRamTarget, Reservation>,
}

impl HostResourceLedger {
    /// Creates an empty ledger with independent resource ceilings.
    pub fn new(capacity: HostResourceVector) -> Self {
        Self {
            capacity,
            used: HostResourceVector::default(),
            next_transition: 0,
            owners: BTreeMap::new(),
        }
    }

    /// Returns the complete reserved vector, including unfinished transitions.
    pub const fn reserved(&self) -> HostResourceVector {
        self.used
    }

    /// Returns the configured complete ceiling and current subset entitlements.
    pub const fn capacity(&self) -> HostResourceVector {
        self.capacity
    }

    /// Admits one exact unique owner without altering immutable assignment data.
    ///
    /// Shared pages belong to their retained-template owner, not each child.
    /// Child vectors must reserve independently reachable private growth.
    ///
    /// # Errors
    ///
    /// Returns refusal for duplicate owners, generation zero, exhausted owner
    /// count, overflow, or insufficient capacity.
    pub fn admit(
        &mut self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostRamPolicyError> {
        if target.owner_generation == 0 || target.arena_generation == 0 {
            return Err(HostRamPolicyError::InvalidPolicy);
        }
        if self.owners.contains_key(&target) || self.owners.len() >= MAX_RAM_RESOURCE_OWNERS {
            return Err(HostRamPolicyError::CapacityRefused);
        }
        let used = self.used.add(resources)?;
        if !used.fits(self.capacity) {
            return Err(HostRamPolicyError::CapacityRefused);
        }
        self.owners.insert(
            target,
            Reservation {
                revision: 0,
                held: resources,
                pending: None,
            },
        );
        self.used = used;
        Ok(())
    }

    /// Reclassifies an initial reservation after authenticated sealed inventory.
    ///
    /// Complete resident, disk, CPU, task, descriptor, and I/O entitlements stay
    /// fixed. Exact metadata and staging increases consume the owner's existing
    /// authored subset entitlements. This operation neither widens ceilings nor releases
    /// capacity nor creates a policy revision.
    /// The caller proves that guest execution and registry publication have not
    /// begun and that the complete inventory belongs to this exact arena.
    ///
    /// # Errors
    /// Refuses stale initial resources, a policy transition, reduced subset
    /// entitlements, changed complete entitlements, or aggregate exhaustion.
    pub fn repartition_before_execution(
        &mut self,
        target: HostRamTarget,
        expected_initial: HostResourceVector,
        resources: HostResourceVector,
    ) -> Result<(), HostRamPolicyError> {
        let owner = self
            .owners
            .get(&target)
            .ok_or(HostRamPolicyError::NotCurrent)?;
        if owner.revision != 0 || owner.pending.is_some() || owner.held != expected_initial {
            return Err(HostRamPolicyError::OwnershipUncertain);
        }
        let mut complete = resources;
        complete.metadata_bytes = expected_initial.metadata_bytes;
        complete.staging_bytes = expected_initial.staging_bytes;
        if complete != expected_initial
            || resources.metadata_bytes < expected_initial.metadata_bytes
            || resources.staging_bytes < expected_initial.staging_bytes
            || resources.metadata_bytes > resources.resident_peak_bytes
            || resources.staging_bytes > resources.resident_peak_bytes
        {
            return Err(HostRamPolicyError::CapacityRefused);
        }
        let capacity = self.capacity;
        let subset_total = capacity
            .metadata_bytes
            .checked_add(capacity.staging_bytes)
            .ok_or(HostRamPolicyError::CapacityRefused)?;
        let used = self.used.subtract(expected_initial)?.add(resources)?;
        if subset_total > capacity.resident_peak_bytes || !used.fits(capacity) {
            return Err(HostRamPolicyError::CapacityRefused);
        }
        let owner = self
            .owners
            .get_mut(&target)
            .ok_or(HostRamPolicyError::OwnershipUncertain)?;
        owner.held = resources;
        self.used = used;
        self.capacity = capacity;
        Ok(())
    }

    /// Reserves a sound transient peak before any physical policy application.
    ///
    /// # Errors
    ///
    /// Returns refusal for a stale target/revision, pending transition,
    /// incomplete old/new peak, or insufficient capacity. Failure has no effect.
    pub fn begin_transition(
        &mut self,
        target: HostRamTarget,
        expected_revision: u64,
        requested: HostResourceVector,
        transition_peak: HostResourceVector,
    ) -> Result<HostResourceTransition, HostRamPolicyError> {
        let owner = self
            .owners
            .get(&target)
            .ok_or(HostRamPolicyError::NotCurrent)?;
        if owner.revision != expected_revision {
            return Err(HostRamPolicyError::RevisionConflict {
                current: owner.revision,
            });
        }
        if owner.pending.is_some() {
            return Err(HostRamPolicyError::TransitionPending);
        }
        if !owner.held.fits(transition_peak) || !requested.fits(transition_peak) {
            return Err(HostRamPolicyError::CapacityRefused);
        }
        let increase = transition_peak.subtract(owner.held)?;
        let used = self.used.add(increase)?;
        if !used.fits(self.capacity) {
            return Err(HostRamPolicyError::CapacityRefused);
        }
        let revision = owner
            .revision
            .checked_add(1)
            .ok_or(HostRamPolicyError::IdentityExhausted)?;
        let id = self
            .next_transition
            .checked_add(1)
            .ok_or(HostRamPolicyError::IdentityExhausted)?;
        let transition = HostResourceTransition {
            target,
            transition_id: id,
            reservation_revision: revision,
            requested,
            held_peak: transition_peak,
        };
        let owner = self
            .owners
            .get_mut(&target)
            .ok_or(HostRamPolicyError::OwnershipUncertain)?;
        owner.revision = revision;
        owner.held = transition_peak;
        owner.pending = Some(transition);
        self.next_transition = id;
        self.used = used;
        Ok(transition)
    }

    /// Releases surplus only after exact generation-bound convergence evidence.
    ///
    /// The caller must authenticate physical disposition before providing the
    /// transition. A lost response or ambiguous I/O must retain the pending peak.
    ///
    /// # Errors
    ///
    /// Returns refusal for stale target/transition evidence or uncertain totals.
    pub fn finish_transition(
        &mut self,
        transition: HostResourceTransition,
    ) -> Result<(), HostRamPolicyError> {
        let owner = self
            .owners
            .get(&transition.target)
            .ok_or(HostRamPolicyError::NotCurrent)?;
        if owner.pending != Some(transition) {
            return Err(HostRamPolicyError::OwnershipUncertain);
        }
        let release = owner.held.subtract(transition.requested)?;
        let used = self.used.subtract(release)?;
        let owner = self
            .owners
            .get_mut(&transition.target)
            .ok_or(HostRamPolicyError::OwnershipUncertain)?;
        owner.held = transition.requested;
        owner.pending = None;
        self.used = used;
        Ok(())
    }

    /// Returns a target's current held peak and reservation revision.
    pub fn owner_reservation(&self, target: HostRamTarget) -> Option<(u64, HostResourceVector)> {
        self.owners
            .get(&target)
            .map(|owner| (owner.revision, owner.held))
    }

    /// Releases a proved stopped owner after all I/O and backing references end.
    ///
    /// # Errors
    ///
    /// Returns refusal while a transition still owns unresolved resources or
    /// when target authority/accounting is uncertain.
    pub fn release(&mut self, target: HostRamTarget) -> Result<(), HostRamPolicyError> {
        let owner = self
            .owners
            .get(&target)
            .ok_or(HostRamPolicyError::NotCurrent)?;
        if owner.pending.is_some() {
            return Err(HostRamPolicyError::TransitionPending);
        }
        self.release_after_cleanup(target)
    }

    /// Discharges the retained peak after all processes and host borrowers finish.
    ///
    /// The caller proves process termination, source-worker termination,
    /// borrowed-buffer completion, and control-operation drainage. Cleanup of
    /// a pending transition does not claim that physical convergence occurred.
    ///
    /// # Errors
    /// Refuses stale ownership or uncertain retained resource accounting.
    pub fn release_after_cleanup(
        &mut self,
        target: HostRamTarget,
    ) -> Result<(), HostRamPolicyError> {
        let owner = self
            .owners
            .get(&target)
            .ok_or(HostRamPolicyError::NotCurrent)?;
        let used = self.used.subtract(owner.held)?;
        self.owners.remove(&target);
        self.used = used;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
