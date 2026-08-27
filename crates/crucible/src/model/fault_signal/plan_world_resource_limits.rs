//! Scenario-authored resource admission for immutable World declarations.
//!
//! Runtime limits cannot shrink an already admitted topology. This module
//! therefore charges static network, storage, and node capacities while the
//! fault plan is still being bound to its authoritative World.

use std::collections::BTreeSet;

use super::*;

pub(super) fn validate_world_resource_limits(
    limits: FaultResourceLimits,
    world: &World,
) -> Result<(), FaultSignalAuthoringError> {
    let topology = world.fault_topology();
    for (field, count) in [
        ("network_interfaces", topology.network_interfaces.len()),
        ("network_segments", topology.network_segments.len()),
        ("network_forwarders", topology.network_forwarders.len()),
        ("network_media", topology.network_media.len()),
        ("network_queues", topology.network_queues.len()),
        ("network_paths", topology.network_paths.len()),
        ("storage_devices", topology.storage_devices.len()),
        ("nodes", world.vm_nodes().len()),
    ] {
        reserve_world_usize(limits, field, 0, count)?;
    }

    for path in &topology.network_paths {
        reserve_world_usize(limits, "network_path_hops", 0, path.hops.len())?;
    }
    for medium in &topology.network_media {
        reserve_world_usize(
            limits,
            "network_resources_per_medium",
            0,
            medium.resources.len(),
        )?;
        let participants = topology
            .network_segments
            .iter()
            .filter(|segment| segment.medium.as_ref() == Some(&medium.id))
            .flat_map(|segment| [&segment.interface_a, &segment.interface_b])
            .collect::<BTreeSet<_>>()
            .len();
        reserve_world_usize(limits, "network_medium_participants", 0, participants)?;
    }
    let forwarding_entries = topology
        .network_forwarders
        .iter()
        .try_fold(0_u64, |total, forwarder| {
            total.checked_add(u64::from(forwarder.table_capacity))
        })
        .ok_or_else(|| {
            FaultSignalAuthoringError::ResourceLimit(FaultResourceLimitError::UsageOverflow {
                field: "network_forwarding_entries",
                current: u64::MAX,
                requested: 1,
                configured: limits.network_forwarding_entries,
                hard: FaultResourceLimits::compiled_maximum().network_forwarding_entries,
            })
        })?;
    limits
        .reserve("network_forwarding_entries", 0, forwarding_entries)
        .map_err(FaultSignalAuthoringError::ResourceLimit)?;

    for device in &topology.storage_devices {
        let persistence = &device.persistence;
        for (field, requested) in [
            ("storage_request_bytes", persistence.maximum_request_bytes),
            (
                "storage_cache_bytes_per_device",
                persistence
                    .volatile_cache_bytes
                    .checked_add(persistence.controller_buffer_bytes)
                    .ok_or_else(|| {
                        FaultSignalAuthoringError::ResourceLimit(
                            FaultResourceLimitError::UsageOverflow {
                                field: "storage_cache_bytes_per_device",
                                current: persistence.volatile_cache_bytes,
                                requested: persistence.controller_buffer_bytes,
                                configured: limits.storage_cache_bytes_per_device,
                                hard: FaultResourceLimits::compiled_maximum()
                                    .storage_cache_bytes_per_device,
                            },
                        )
                    })?,
            ),
            (
                "storage_cache_entries_per_device",
                u64::from(persistence.cache_entries)
                    .checked_add(u64::from(persistence.controller_entries))
                    .ok_or_else(|| {
                        FaultSignalAuthoringError::ResourceLimit(
                            FaultResourceLimitError::UsageOverflow {
                                field: "storage_cache_entries_per_device",
                                current: u64::from(persistence.cache_entries),
                                requested: u64::from(persistence.controller_entries),
                                configured: limits.storage_cache_entries_per_device,
                                hard: FaultResourceLimits::compiled_maximum()
                                    .storage_cache_entries_per_device,
                            },
                        )
                    })?,
            ),
            (
                "storage_persistence_dependencies",
                u64::from(persistence.persistence_dependencies),
            ),
            (
                "storage_retained_versions_per_interval",
                u64::from(persistence.retained_versions_per_interval),
            ),
        ] {
            limits
                .reserve(field, 0, requested)
                .map_err(FaultSignalAuthoringError::ResourceLimit)?;
        }
        if let Some((erase_block_bytes, _page_bytes, _endurance)) = device.media.flash_geometry() {
            let blocks = persistence.length_bytes.div_ceil(erase_block_bytes);
            limits
                .reserve("storage_flash_blocks_per_device", 0, blocks)
                .map_err(FaultSignalAuthoringError::ResourceLimit)?;
        }
    }
    let queue_operations = topology
        .storage_controllers
        .iter()
        .flat_map(|controller| &controller.paths)
        .chain(
            topology
                .storage_arrays
                .iter()
                .flat_map(|array| &array.paths),
        )
        .try_fold(0_u64, |total, path| {
            total.checked_add(u64::from(path.queue_depth))
        })
        .ok_or_else(|| {
            FaultSignalAuthoringError::ResourceLimit(FaultResourceLimitError::UsageOverflow {
                field: "storage_queue_operations",
                current: u64::MAX,
                requested: 1,
                configured: limits.storage_queue_operations,
                hard: FaultResourceLimits::compiled_maximum().storage_queue_operations,
            })
        })?;
    limits
        .reserve("storage_queue_operations", 0, queue_operations)
        .map_err(FaultSignalAuthoringError::ResourceLimit)?;
    for array in &topology.storage_arrays {
        reserve_world_usize(limits, "storage_array_members", 0, array.members.len())?;
    }

    for node in world.vm_nodes() {
        limits
            .reserve("vcpus_per_node", 0, u64::from(node.smp_vcpus))
            .map_err(FaultSignalAuthoringError::ResourceLimit)?;
    }
    for capabilities in &topology.node_capabilities {
        reserve_world_usize(
            limits,
            "accelerators_per_node",
            0,
            capabilities.accelerators.len(),
        )?;
    }
    Ok(())
}

fn reserve_world_usize(
    limits: FaultResourceLimits,
    field: &'static str,
    current: usize,
    requested: usize,
) -> Result<(), FaultSignalAuthoringError> {
    let current = u64::try_from(current).map_err(|_| {
        FaultSignalAuthoringError::ResourceLimit(FaultResourceLimitError::Representation {
            field,
            value: u64::MAX,
        })
    })?;
    let requested = u64::try_from(requested).map_err(|_| {
        FaultSignalAuthoringError::ResourceLimit(FaultResourceLimitError::Representation {
            field,
            value: u64::MAX,
        })
    })?;
    limits
        .reserve(field, current, requested)
        .map_err(FaultSignalAuthoringError::ResourceLimit)
}

pub(super) fn reserve_usize(
    limits: FaultResourceLimits,
    field: &'static str,
    current: usize,
    requested: usize,
) -> Result<(), FaultSignalPlanError> {
    let current = u64::try_from(current).map_err(|_| {
        FaultSignalPlanError::ResourceLimit(FaultResourceLimitError::Representation {
            field,
            value: u64::MAX,
        })
    })?;
    let requested = u64::try_from(requested).map_err(|_| {
        FaultSignalPlanError::ResourceLimit(FaultResourceLimitError::Representation {
            field,
            value: u64::MAX,
        })
    })?;
    limits
        .reserve(field, current, requested)
        .map_err(FaultSignalPlanError::ResourceLimit)
}
