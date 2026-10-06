//! Actual preparation and retained-template service admission under the actor.

use crucible_api::host_operational::HostOperationalError;
use crucible_linux_resource::ram_policy::{HostResourceLedger, HostResourceVector};

use super::*;

pub(super) type HostServiceReservations =
    BTreeMap<[u8; 32], (HostResourceVector, HostResourceLedger)>;

impl<L, V> LocalExecutorSupervisor<L, V> {
    /// Reserves a source service beside an already charged active child assignment.
    ///
    /// The caller supplies the existing execution's opaque operational owner,
    /// rather than another speculative assignment vector. Both its active
    /// worker and complete node partition must still belong to this actor.
    ///
    /// # Errors
    /// Refuses queued, canceled, completing, retired, unknown or service-only
    /// owner identities, a missing complete assignment charge, or insufficient
    /// remaining capacity for the independently retained service.
    pub(crate) fn reserve_host_ram_service_with_admitted_assignment(
        &mut self,
        owner: [u8; 32],
        service: HostResourceVector,
        existing_execution_owner: [u8; 32],
    ) -> Result<(), HostOperationalError> {
        let execution = self
            .active
            .iter()
            .find_map(|(execution, active)| {
                (crate::host_operational_registry::operational_identity(execution.as_bytes())
                    == existing_execution_owner
                    && active.worker_in_flight
                    && !active.cancellation.is_canceled())
                .then_some(*execution)
            })
            .ok_or(HostOperationalError::Unavailable)?;
        if self.pending_completions.contains_key(&execution)
            || self.pending_cancellations.contains_key(&execution)
            || self
                .host_ram_resources
                .get(&execution)
                .is_none_or(|(ceiling, _)| {
                    self.assignment_node_ceiling().ok().as_ref() != Some(ceiling)
                })
        {
            return Err(HostOperationalError::Unavailable);
        }
        // The assignment already occupies UsedCapacity in this same actor.
        // Reserve only the Service; checking another assignment would count
        // the existing child peak twice and incorrectly refuse valid forks.
        self.reserve_host_ram_service(owner, service)
    }

    /// Reserves a service while preserving an explicitly authored assignment peak.
    ///
    /// # Errors
    /// Refuses missing deployed limits, overflow, or insufficient capacity for
    /// both peaks. The future assignment is checked without being charged.
    pub(crate) fn reserve_host_ram_service_with_assignment_headroom(
        &mut self,
        owner: [u8; 32],
        service: HostResourceVector,
        assignment: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        let Some((authored_assignment, _, _)) = self.host_assignment_resources else {
            return Err(HostOperationalError::Unavailable);
        };
        if assignment != authored_assignment {
            return Err(HostOperationalError::Unavailable);
        }
        if [
            assignment.resident_peak_bytes,
            assignment.backing_peak_bytes,
            assignment.cpu_slots,
            assignment.paging_io_slots,
            assignment.task_slots,
            assignment.file_descriptors,
        ]
        .contains(&0)
            || assignment
                .metadata_bytes
                .checked_add(assignment.staging_bytes)
                .is_none_or(|bytes| bytes > assignment.resident_peak_bytes)
        {
            return Err(HostOperationalError::Unavailable);
        }
        let cpus = service
            .cpu_slots
            .checked_add(assignment.cpu_slots)
            .and_then(|slots| u32::try_from(slots).ok())
            .and_then(|slots| self.used.vcpus.checked_add(slots))
            .ok_or(HostOperationalError::Unavailable)?;
        let resident = service
            .resident_peak_bytes
            .checked_add(assignment.resident_peak_bytes)
            .and_then(|bytes| self.used.resident_bytes.checked_add(bytes))
            .ok_or(HostOperationalError::Unavailable)?;
        let disk = service
            .backing_peak_bytes
            .checked_add(assignment.backing_peak_bytes)
            .and_then(|bytes| self.used.disk_bytes.checked_add(bytes))
            .ok_or(HostOperationalError::Unavailable)?;
        let operational = self.host_operational_used.add(service)?.add(assignment)?;
        let capacity = self
            .host_operational_capacity
            .ok_or(HostOperationalError::Unavailable)?;
        if cpus > self.capacity.maximum_vcpus
            || resident > self.capacity.maximum_resident_bytes
            || disk > self.capacity.maximum_disk_bytes
            || !operational.fits(capacity)
        {
            return Err(HostOperationalError::Unavailable);
        }
        self.reserve_host_ram_service(owner, service)
    }

    pub(crate) fn host_ram_service_nodes_cleaned(
        &self,
        owner: [u8; 32],
    ) -> Result<bool, HostOperationalError> {
        let (_, ledger) = self
            .host_service_resources
            .get(&owner)
            .ok_or(HostOperationalError::Unavailable)?;
        Ok(ledger.reserved() == HostResourceVector::default())
    }

    /// Reserves an explicit preparation or template service before any launch.
    ///
    /// # Errors
    /// Refuses duplicate identities, missing deployed capacity, bounded owner
    /// exhaustion, overflow, or any global CPU, memory, disk, I/O, task or FD limit.
    pub(crate) fn reserve_host_ram_service(
        &mut self,
        owner: [u8; 32],
        ceiling: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        if self
            .active
            .keys()
            .chain(self.host_retained_resources.keys())
            .any(|execution| {
                crate::host_operational_registry::operational_identity(execution.as_bytes())
                    == owner
            })
        {
            return Err(HostOperationalError::Unavailable);
        }
        reserve_service_account(
            self.capacity,
            self.host_operational_capacity
                .ok_or(HostOperationalError::Unavailable)?,
            &mut self.used,
            &mut self.host_operational_used,
            &mut self.host_service_resources,
            owner,
            ceiling,
        )
    }

    /// Discharges a service only after every registered physical owner was cleaned.
    ///
    /// # Errors
    /// Refuses live or ambiguous node reservations, stale service ownership,
    /// uncertain cap retirement, or accounting failure. Refusal retains all charges.
    pub(crate) fn release_host_ram_service_after_cleanup(
        &mut self,
        owner: [u8; 32],
    ) -> Result<(), HostOperationalError> {
        if self.host_startup_namespace_owner == Some(owner) {
            // No namespace deletion or authenticated rebind receipt exists on
            // this close-only path. Preserve the original account, even after
            // every descriptor closed; the durable backing still belongs to it.
            return Err(HostOperationalError::Unavailable);
        }
        let (ceiling, ledger) = self
            .host_service_resources
            .get(&owner)
            .ok_or(HostOperationalError::Unavailable)?;
        if ledger.reserved() != HostResourceVector::default() {
            return Err(HostOperationalError::Unavailable);
        }
        let cpus =
            u32::try_from(ceiling.cpu_slots).map_err(|_| HostOperationalError::Unavailable)?;
        let used = UsedCapacity {
            vcpus: self
                .used
                .vcpus
                .checked_sub(cpus)
                .ok_or(HostOperationalError::Unavailable)?,
            resident_bytes: self
                .used
                .resident_bytes
                .checked_sub(ceiling.resident_peak_bytes)
                .ok_or(HostOperationalError::Unavailable)?,
            disk_bytes: self
                .used
                .disk_bytes
                .checked_sub(ceiling.backing_peak_bytes)
                .ok_or(HostOperationalError::Unavailable)?,
        };
        let operational = self.host_operational_used.subtract(*ceiling)?;
        self.host_operational_registry.retire_service(
            crate::host_operational_registry::operational_identity(self.daemon_epoch.as_bytes()),
            owner,
        )?;
        self.host_service_resources.remove(&owner);
        self.host_service_partitions.remove(&owner);
        self.used = used;
        self.host_operational_used = operational;
        Ok(())
    }

    pub(super) fn has_host_service_owner(&self, daemon: [u8; 32], owner: [u8; 32]) -> bool {
        daemon
            == crate::host_operational_registry::operational_identity(self.daemon_epoch.as_bytes())
            && self.host_service_resources.contains_key(&owner)
    }
}

/// Charges the single real account before either ledger bootstrap or live service I/O.
pub(super) fn reserve_service_account(
    capacity: ExecutorCapacity,
    operational_capacity: HostOperationalCapacity,
    used: &mut UsedCapacity,
    operational_used: &mut HostOperationalUse,
    services: &mut HostServiceReservations,
    owner: [u8; 32],
    ceiling: HostResourceVector,
) -> Result<(), HostOperationalError> {
    if owner == [0; 32]
        || services.contains_key(&owner)
        || services.len() >= 64
        || ceiling.resident_peak_bytes == 0
        || ceiling.backing_peak_bytes == 0
        || ceiling.cpu_slots == 0
        || ceiling.paging_io_slots == 0
        || ceiling.task_slots == 0
        || ceiling.file_descriptors == 0
        || ceiling
            .metadata_bytes
            .checked_add(ceiling.staging_bytes)
            .is_none_or(|bytes| bytes > ceiling.resident_peak_bytes)
    {
        return Err(HostOperationalError::Unavailable);
    }
    let cpus = u32::try_from(ceiling.cpu_slots).map_err(|_| HostOperationalError::Unavailable)?;
    let updated_use = UsedCapacity {
        vcpus: used
            .vcpus
            .checked_add(cpus)
            .ok_or(HostOperationalError::Unavailable)?,
        resident_bytes: used
            .resident_bytes
            .checked_add(ceiling.resident_peak_bytes)
            .ok_or(HostOperationalError::Unavailable)?,
        disk_bytes: used
            .disk_bytes
            .checked_add(ceiling.backing_peak_bytes)
            .ok_or(HostOperationalError::Unavailable)?,
    };
    let operational = operational_used.add(ceiling)?;
    if updated_use.vcpus > capacity.maximum_vcpus
        || updated_use.resident_bytes > capacity.maximum_resident_bytes
        || updated_use.disk_bytes > capacity.maximum_disk_bytes
        || !operational.fits(operational_capacity)
    {
        return Err(HostOperationalError::Unavailable);
    }
    services.insert(owner, (ceiling, HostResourceLedger::new(ceiling)));
    *used = updated_use;
    *operational_used = operational;
    Ok(())
}
