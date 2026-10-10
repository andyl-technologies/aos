//! Complete per-assignment RAM partitions under the existing executor actor.

use crucible_api::host_operational::{HostOperationalError, HostReservationAmendment};
use crucible_linux_resource::ram_policy::{
    HostRamTarget, HostResourceLedger, HostResourceTransition, HostResourceVector,
};

use super::*;

impl<L, V> LocalExecutorSupervisor<L, V> {
    /// Installs independent physical, guest request, and watcher entitlements.
    ///
    /// The complete physical vector is charged once. One watcher task and the
    /// explicit watcher resident allowance are retained within that vector;
    /// node admission receives only its remaining subset. The guest request
    /// limits remain unchanged, including a zero guest disk allowance.
    ///
    /// # Errors
    /// Refuses replacement, existing owners, malformed bounds or a deployment
    /// whose global capacities cannot admit even one complete assignment.
    pub fn with_host_assignment_resources(
        mut self,
        vector: HostResourceVector,
        limits: AttemptResourceLimits,
        watcher_service_resident_bytes: u64,
    ) -> Result<Self, HostOperationalError> {
        if self.host_assignment_resources.is_some()
            || !self.active.is_empty()
            || !self.host_service_resources.is_empty()
            || !self.host_ram_resources.is_empty()
        {
            return Err(HostOperationalError::Unavailable);
        }
        let charge = assignment_charge(
            self.capacity,
            self.host_operational_capacity
                .ok_or(HostOperationalError::Unavailable)?,
            vector,
            limits,
            watcher_service_resident_bytes,
        )?;
        self.host_watcher_resident_bytes = Some(watcher_service_resident_bytes);
        self.host_assignment_resources = Some((vector, limits, charge));
        Ok(self)
    }

    pub(super) fn assignment_node_ceiling(
        &self,
    ) -> Result<HostResourceVector, HostOperationalError> {
        let (mut node, _, _) = self
            .host_assignment_resources
            .ok_or(HostOperationalError::Unavailable)?;
        let watcher = self
            .host_watcher_resident_bytes
            .ok_or(HostOperationalError::Unavailable)?;
        node.resident_peak_bytes = node
            .resident_peak_bytes
            .checked_sub(watcher)
            .ok_or(HostOperationalError::Unavailable)?;
        node.task_slots = node
            .task_slots
            .checked_sub(1)
            .ok_or(HostOperationalError::Unavailable)?;
        Ok(node)
    }

    pub(crate) fn host_ram_owner_ceiling(
        &self,
        daemon: [u8; 32],
        owner: [u8; 32],
    ) -> Result<HostResourceVector, HostOperationalError> {
        if self.has_host_service_owner(daemon, owner) {
            return self
                .host_service_partitions
                .get(&owner)
                .copied()
                .or_else(|| {
                    self.host_service_resources
                        .get(&owner)
                        .map(|(ceiling, _)| *ceiling)
                })
                .ok_or(HostOperationalError::Unavailable);
        }
        let execution = self.ram_execution(daemon, owner)?;
        self.host_ram_resources
            .get(&execution)
            .map(|(ceiling, _)| *ceiling)
            .ok_or(HostOperationalError::Unavailable)
    }

    pub(crate) fn assignment_resource_limits(&self) -> Option<AttemptResourceLimits> {
        self.host_assignment_resources.map(|(_, limits, _)| limits)
    }

    pub(super) fn supports_assignment(&self, resources: AttemptResourceLimits) -> bool {
        self.capacity.supports(resources)
            && self.assignment_resource_limits().is_none_or(|limits| {
                resources.maximum_vcpus() <= limits.maximum_vcpus()
                    && resources.maximum_resident_bytes() <= limits.maximum_resident_bytes()
                    && resources.maximum_disk_bytes() <= limits.maximum_disk_bytes()
                    && resources.maximum_execution_quanta() <= limits.maximum_execution_quanta()
            })
    }

    pub(super) fn charged_assignment_resources(
        &self,
        resources: AttemptResourceLimits,
    ) -> UsedCapacity {
        self.host_assignment_resources.map_or(
            UsedCapacity {
                vcpus: resources.maximum_vcpus(),
                resident_bytes: resources.maximum_resident_bytes(),
                disk_bytes: resources.maximum_disk_bytes(),
            },
            |(_, _, charge)| charge,
        )
    }

    /// Installs immutable explicit deployed operational capacity before admission.
    ///
    /// # Errors
    /// Refuses replacement or installation after a physical owner was admitted.
    pub fn with_host_operational_capacity(
        mut self,
        capacity: HostOperationalCapacity,
    ) -> Result<Self, HostOperationalError> {
        if self.host_operational_capacity.is_some() || !self.host_ram_resources.is_empty() {
            return Err(HostOperationalError::Unavailable);
        }
        if capacity
            .maximum_metadata_bytes()
            .checked_add(capacity.maximum_staging_bytes())
            .is_none_or(|bytes| bytes > self.capacity.maximum_resident_bytes)
            || capacity.maximum_staging_bytes() > self.capacity.maximum_disk_bytes
        {
            return Err(HostOperationalError::Unavailable);
        }
        self.host_operational_capacity = Some(capacity);
        Ok(self)
    }

    pub(crate) fn host_resource_capacities(
        &self,
    ) -> Option<(HostResourceVector, HostResourceVector)> {
        let operational = self.host_operational_capacity?;
        let (assignment, _, _) = self.host_assignment_resources?;
        let aggregate = HostResourceVector {
            resident_peak_bytes: self.capacity.maximum_resident_bytes,
            backing_peak_bytes: self.capacity.maximum_disk_bytes,
            metadata_bytes: operational.maximum_metadata_bytes(),
            staging_bytes: operational.maximum_staging_bytes(),
            paging_io_slots: operational.maximum_paging_io_slots(),
            cpu_slots: u64::from(self.capacity.maximum_vcpus),
            task_slots: operational.maximum_task_slots(),
            file_descriptors: operational.maximum_file_descriptors(),
        };
        Some((aggregate, assignment))
    }

    pub(crate) fn host_resource_availability(&self) -> Option<HostResourceVector> {
        let (aggregate, _) = self.host_resource_capacities()?;
        Some(HostResourceVector {
            resident_peak_bytes: aggregate
                .resident_peak_bytes
                .checked_sub(self.used.resident_bytes)?,
            backing_peak_bytes: aggregate
                .backing_peak_bytes
                .checked_sub(self.used.disk_bytes)?,
            metadata_bytes: aggregate
                .metadata_bytes
                .checked_sub(self.host_operational_used.metadata_bytes)?,
            staging_bytes: aggregate
                .staging_bytes
                .checked_sub(self.host_operational_used.staging_bytes)?,
            paging_io_slots: aggregate
                .paging_io_slots
                .checked_sub(self.host_operational_used.paging_io_slots)?,
            cpu_slots: aggregate
                .cpu_slots
                .checked_sub(u64::from(self.used.vcpus))?,
            task_slots: aggregate
                .task_slots
                .checked_sub(self.host_operational_used.task_slots)?,
            file_descriptors: aggregate
                .file_descriptors
                .checked_sub(self.host_operational_used.file_descriptors)?,
        })
    }

    pub(crate) fn repartition_host_ram_node_before_cpu(
        &mut self,
        target: HostRamTarget,
        expected_initial: HostResourceVector,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        if self.has_host_service_owner(target.daemon_epoch, target.owner_id) {
            let (_, ledger) = self
                .host_service_resources
                .get_mut(&target.owner_id)
                .ok_or(HostOperationalError::Unavailable)?;
            ledger
                .repartition_before_execution(target, expected_initial, resources)
                .map_err(|_| HostOperationalError::Unavailable)?;
            // The separately retained service ceiling includes its watcher.
            // Reclassification changes only the configured node partition.
            return Ok(());
        }
        let execution = self.ram_execution(target.daemon_epoch, target.owner_id)?;
        let (ceiling, ledger) = self
            .host_ram_resources
            .get_mut(&execution)
            .ok_or(HostOperationalError::Unavailable)?;
        ledger
            .repartition_before_execution(target, expected_initial, resources)
            .map_err(|_| HostOperationalError::Unavailable)?;
        *ceiling = ledger.capacity();
        Ok(())
    }

    pub(crate) fn release_host_ram_node_after_cleanup(
        &mut self,
        target: HostRamTarget,
    ) -> Result<(), HostOperationalError> {
        if self.has_host_service_owner(target.daemon_epoch, target.owner_id) {
            return self
                .host_service_resources
                .get_mut(&target.owner_id)
                .ok_or(HostOperationalError::Unavailable)?
                .1
                .release_after_cleanup(target)
                .map_err(|_| HostOperationalError::Unavailable);
        }
        let execution = self.ram_execution(target.daemon_epoch, target.owner_id)?;
        let ledger = &self
            .host_ram_resources
            .get(&execution)
            .ok_or(HostOperationalError::Unavailable)?
            .1;
        let held = ledger
            .owner_reservation(target)
            .ok_or(HostOperationalError::Unavailable)?
            .1;
        let retaining = self.host_retained_resources.contains_key(&execution);
        let release = if retaining {
            let cpus =
                u32::try_from(held.cpu_slots).map_err(|_| HostOperationalError::Unavailable)?;
            let used = UsedCapacity {
                vcpus: self
                    .used
                    .vcpus
                    .checked_sub(cpus)
                    .ok_or(HostOperationalError::Unavailable)?,
                resident_bytes: self
                    .used
                    .resident_bytes
                    .checked_sub(held.resident_peak_bytes)
                    .ok_or(HostOperationalError::Unavailable)?,
                disk_bytes: self
                    .used
                    .disk_bytes
                    .checked_sub(held.backing_peak_bytes)
                    .ok_or(HostOperationalError::Unavailable)?,
            };
            Some((used, self.host_operational_used.subtract(held)?))
        } else {
            // Active assignments retain their entire pre-admitted partition.
            None
        };
        let last_retained_node = retaining && ledger.reserved() == held;
        if last_retained_node {
            self.host_operational_registry
                .retire_execution(target.daemon_epoch, target.owner_id)?;
        }

        let ledger = &mut self
            .host_ram_resources
            .get_mut(&execution)
            .ok_or(HostOperationalError::Unavailable)?
            .1;
        ledger
            .release_after_cleanup(target)
            .map_err(|_| HostOperationalError::Unavailable)?;
        let remaining = ledger.reserved();
        if let Some((used, operational_used)) = release {
            if last_retained_node {
                self.host_retained_resources.remove(&execution);
                self.host_ram_resources.remove(&execution);
            } else {
                self.host_retained_resources.insert(execution, remaining);
            }
            self.used = used;
            self.host_operational_used = operational_used;
        }
        Ok(())
    }

    fn unpublished_reservation(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        let ledger = if self.has_host_service_owner(target.daemon_epoch, target.owner_id) {
            &self
                .host_service_resources
                .get(&target.owner_id)
                .ok_or(HostOperationalError::Unavailable)?
                .1
        } else {
            let execution = self.ram_execution(target.daemon_epoch, target.owner_id)?;
            &self
                .host_ram_resources
                .get(&execution)
                .ok_or(HostOperationalError::Unavailable)?
                .1
        };
        if ledger.owner_reservation(target) != Some((0, resources)) {
            return Err(HostOperationalError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn release_unpublished_host_ram_node_after_cleanup(
        &mut self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.unpublished_reservation(target, resources)?;
        self.release_host_ram_node_after_cleanup(target)?;
        self.host_unpublished_quarantine.remove(&target);
        Ok(())
    }

    pub(crate) fn quarantine_unpublished_host_ram_node(
        &mut self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.unpublished_reservation(target, resources)?;
        if !self.host_unpublished_quarantine.contains_key(&target)
            && self.host_unpublished_quarantine.len() >= 4096
        {
            return Err(HostOperationalError::Unavailable);
        }
        self.host_unpublished_quarantine.insert(target, resources);
        Ok(())
    }

    fn ram_execution(
        &self,
        daemon: [u8; 32],
        owner: [u8; 32],
    ) -> Result<ExecutionId, HostOperationalError> {
        if daemon
            != crate::host_operational_registry::operational_identity(self.daemon_epoch.as_bytes())
        {
            return Err(HostOperationalError::Unavailable);
        }
        self.active
            .keys()
            .chain(self.host_retained_resources.keys())
            .copied()
            .find(|execution| {
                crate::host_operational_registry::operational_identity(execution.as_bytes())
                    == owner
            })
            .ok_or(HostOperationalError::Unavailable)
    }

    pub(crate) fn configure_host_ram_owner(
        &mut self,
        daemon: [u8; 32],
        owner: [u8; 32],
        ceiling: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        if self.has_host_service_owner(daemon, owner) {
            let reserved = self
                .host_service_resources
                .get(&owner)
                .ok_or(HostOperationalError::Unavailable)?
                .0;
            if !ceiling.fits(reserved) {
                return Err(HostOperationalError::Unavailable);
            }
            if let Some(existing) = self.host_service_partitions.get(&owner) {
                return if *existing == ceiling {
                    Ok(())
                } else {
                    Err(HostOperationalError::Unavailable)
                };
            }
            let ledger = &mut self
                .host_service_resources
                .get_mut(&owner)
                .ok_or(HostOperationalError::Unavailable)?
                .1;
            if ledger.reserved() != HostResourceVector::default() {
                return Err(HostOperationalError::Unavailable);
            }
            *ledger = HostResourceLedger::new(ceiling);
            self.host_service_partitions.insert(owner, ceiling);
            return Ok(());
        }
        let execution = self.ram_execution(daemon, owner)?;
        let resources = self
            .active
            .get(&execution)
            .ok_or(HostOperationalError::Unavailable)?
            .request
            .resources();
        if ceiling.resident_peak_bytes > resources.maximum_resident_bytes()
            || ceiling.backing_peak_bytes > resources.maximum_disk_bytes()
            || ceiling.cpu_slots > u64::from(resources.maximum_vcpus())
            || ceiling.metadata_bytes > ceiling.resident_peak_bytes
            || ceiling.staging_bytes > ceiling.resident_peak_bytes
            || ceiling.paging_io_slots == 0
            || ceiling.task_slots == 0
            || ceiling.file_descriptors == 0
        {
            return Err(HostOperationalError::Unavailable);
        }
        if let Some((existing, _)) = self.host_ram_resources.get(&execution) {
            return if *existing == ceiling {
                Ok(())
            } else {
                Err(HostOperationalError::Unavailable)
            };
        }
        let capacity = self
            .host_operational_capacity
            .ok_or(HostOperationalError::Unavailable)?;
        let used = self.host_operational_used.add(ceiling)?;
        if !used.fits(capacity) {
            return Err(HostOperationalError::Unavailable);
        }
        // The full assignment ceiling was already charged in UsedCapacity.
        // Partition admission cannot weaken it or add an uncharged host delta.
        self.host_ram_resources
            .insert(execution, (ceiling, HostResourceLedger::new(ceiling)));
        self.host_operational_used = used;
        Ok(())
    }

    pub(crate) fn admit_host_ram_node(
        &mut self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        if self.has_host_service_owner(target.daemon_epoch, target.owner_id) {
            if !self.host_service_partitions.contains_key(&target.owner_id) {
                return Err(HostOperationalError::Unavailable);
            }
            let ledger = &mut self
                .host_service_resources
                .get_mut(&target.owner_id)
                .ok_or(HostOperationalError::Unavailable)?
                .1;
            if let Some((_, existing)) = ledger.owner_reservation(target) {
                return if existing == resources {
                    Ok(())
                } else {
                    Err(HostOperationalError::Unavailable)
                };
            }
            return ledger
                .admit(target, resources)
                .map_err(|_| HostOperationalError::Unavailable);
        }
        let execution = self.ram_execution(target.daemon_epoch, target.owner_id)?;
        let (_, ledger) = self
            .host_ram_resources
            .get_mut(&execution)
            .ok_or(HostOperationalError::Unavailable)?;
        if let Some((_, existing)) = ledger.owner_reservation(target) {
            return if existing == resources {
                Ok(())
            } else {
                Err(HostOperationalError::Unavailable)
            };
        }
        ledger
            .admit(target, resources)
            .map_err(|_| HostOperationalError::Unavailable)
    }

    pub(crate) fn begin_host_ram_transition(
        &mut self,
        target: HostRamTarget,
        amendment: HostReservationAmendment,
    ) -> Result<HostResourceTransition, HostOperationalError> {
        if self.has_host_service_owner(target.daemon_epoch, target.owner_id) {
            return self
                .host_service_resources
                .get_mut(&target.owner_id)
                .ok_or(HostOperationalError::Unavailable)?
                .1
                .begin_transition(
                    target,
                    amendment.expected_reservation_revision,
                    amendment.requested,
                    amendment.transition_peak,
                )
                .map_err(|_| HostOperationalError::Unavailable);
        }
        let execution = self.ram_execution(target.daemon_epoch, target.owner_id)?;
        self.host_ram_resources
            .get_mut(&execution)
            .ok_or(HostOperationalError::Unavailable)?
            .1
            .begin_transition(
                target,
                amendment.expected_reservation_revision,
                amendment.requested,
                amendment.transition_peak,
            )
            .map_err(|_| HostOperationalError::Unavailable)
    }

    pub(crate) fn finish_host_ram_transition(
        &mut self,
        transition: HostResourceTransition,
    ) -> Result<(), HostOperationalError> {
        let target = transition.target;
        if self.has_host_service_owner(target.daemon_epoch, target.owner_id) {
            return self
                .host_service_resources
                .get_mut(&target.owner_id)
                .ok_or(HostOperationalError::Unavailable)?
                .1
                .finish_transition(transition)
                .map_err(|_| HostOperationalError::Unavailable);
        }
        let execution = self.ram_execution(target.daemon_epoch, target.owner_id)?;
        self.host_ram_resources
            .get_mut(&execution)
            .ok_or(HostOperationalError::Unavailable)?
            .1
            .finish_transition(transition)
            .map_err(|_| HostOperationalError::Unavailable)
    }
}

/// Validates the same authored assignment partition before bootstrap and live admission.
pub(super) fn assignment_charge(
    aggregate: ExecutorCapacity,
    operational: HostOperationalCapacity,
    vector: HostResourceVector,
    limits: AttemptResourceLimits,
    watcher_service_resident_bytes: u64,
) -> Result<UsedCapacity, HostOperationalError> {
    let cpus = u32::try_from(vector.cpu_slots).map_err(|_| HostOperationalError::Unavailable)?;

    let node_resident = vector
        .resident_peak_bytes
        .checked_sub(watcher_service_resident_bytes)
        .filter(|bytes| *bytes > 0)
        .ok_or(HostOperationalError::Unavailable)?;
    if watcher_service_resident_bytes <= 256 * 1024
        || vector.task_slots <= 1
        || vector
            .metadata_bytes
            .checked_add(vector.staging_bytes)
            .is_none_or(|bytes| bytes > node_resident)
        || !aggregate.supports(limits)
        || limits.maximum_vcpus() > cpus
        || limits.maximum_resident_bytes() > vector.resident_peak_bytes
        || limits.maximum_disk_bytes() > vector.backing_peak_bytes
        || cpus > aggregate.maximum_vcpus
        || vector.resident_peak_bytes > aggregate.maximum_resident_bytes
        || vector.backing_peak_bytes > aggregate.maximum_disk_bytes
        || vector.paging_io_slots == 0
        || vector.task_slots == 0
        || vector.file_descriptors == 0
        || !HostOperationalUse::default().add(vector)?.fits(operational)
    {
        return Err(HostOperationalError::Unavailable);
    }
    Ok(UsedCapacity {
        vcpus: cpus,
        resident_bytes: vector.resident_peak_bytes,
        disk_bytes: vector.backing_peak_bytes,
    })
}
