//! Native kernel fixture admission for an initial strict-resident child.
//!
//! This route changes no advertised capability. It admits only the sealed
//! initial policy and publishes the owner after the actual native controller
//! proves the lock receipt for its granted inventory and applied revision.

use super::*;

impl HostOperationalRegistry {
    pub(crate) fn register_native_resident_initial(
        &self,
        target: HostRamTarget,
        policy: HostRamPolicy,
        resources: HostResourceVector,
        supervisor: HostOperationSupervisor,
        client: Option<RamControlClient>,
    ) -> Result<(), RamControlError> {
        let mut registration = self.native_registration(
            target,
            policy,
            resources,
            supervisor,
            client,
            HostRamQualification::default(),
        )?;
        registration.native_resident_initial = true;
        self.register_node(registration)
            .map_err(|_| RamControlError::AuthorityMismatch)
    }
}

pub(super) fn validate_entitlement(
    policy: HostRamPolicy,
    capabilities: HostRamCapabilities,
    resources: HostResourceVector,
    finite_outer: bool,
) -> Result<(), HostOperationalError> {
    // Strict initialization is not a live policy capability. The kernel must
    // still perform and attest placement before this node can be published.
    let required = capabilities
        .logical_ram_bytes
        .checked_add(capabilities.compulsory_resident_bytes)
        .ok_or(HostOperationalError::Unavailable)?;
    if policy.mode != crucible_linux_resource::ram_policy::HostRamMode::ResidentRequired
        || policy.resident_target_bytes > capabilities.logical_ram_bytes
        || policy.eviction_preference > 100
        || policy.writeback_bytes_per_second == 0
        || policy.maximum_paging_io_in_flight != 1
        || policy.latency.validate(finite_outer).is_err()
        || resources.resident_peak_bytes < required
        || resources.backing_peak_bytes < capabilities.logical_ram_bytes
        || resources.paging_io_slots < 1
    {
        return Err(HostOperationalError::Unavailable);
    }
    Ok(())
}

pub(super) fn validate_receipt(reply: &RamControlReply) -> Result<(), HostOperationalError> {
    let inventory = reply.inventory.ok_or(HostOperationalError::Unavailable)?;
    let receipt = reply
        .placement_receipt
        .ok_or(HostOperationalError::Unavailable)?;
    if reply.disposition != crucible_protocol::ram_control::RamControlDisposition::Accepted
        || reply.requested_policy_revision != 1
        || reply.applied_policy_revision != 1
        || reply.reservation_revision != 0
        || !inventory.granted
        || reply.logical_ram_bytes == 0
        || reply.logical_ram_bytes != inventory.logical_bytes
        || receipt.mode != crucible_protocol::ram_control::RamControlMode::ResidentRequired
        || receipt.policy_revision != reply.applied_policy_revision
        || receipt.topology_generation != inventory.topology_generation
        || receipt.placement_epoch == 0
        || receipt.locked_bytes == 0
        || !receipt.locked_bytes.is_multiple_of(4096)
        || receipt.disk_preserved_logical_pages != 0
        || receipt.disk_preserved_logical_bytes != 0
        || receipt.ram_write_generation_at_cut != 0
    {
        return Err(HostOperationalError::Unavailable);
    }
    // locked_bytes denotes native deduplicated rounded spans, not the sum of
    // aliased logical regions. The controller authenticates the exact spans.
    Ok(())
}
