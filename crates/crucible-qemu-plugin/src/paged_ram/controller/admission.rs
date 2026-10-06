//! Authenticates actual sealed inventory and applies a pre-CPU host resource grant.
//!
//! SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// Reports actual native regions and waits for the one authenticated startup grant.
///
/// The decoder is invoked only after its conservative scratch bound fits the
/// original staging entitlement. It reads metadata only under the caller's real
/// native pre-CPU admission fence. No root-cache lock may be held across this call.
///
/// # Errors
/// Refuses malformed inventory, missing staging, stale/repeated grants, expired
/// initial setup, failed native sealing or failed actual arena-owner installation.
pub(crate) fn admit_native_inventory(
    generation: u64,
    logical_bytes: u64,
    native_metadata_bytes: u64,
    native_scratch_bytes: u64,
    region_count: u32,
    read_regions: impl FnOnce() -> Result<Vec<RegionDescriptor>, RamError>,
) -> Result<Option<u64>, RamError> {
    let Some(controller) = controller()? else {
        return Ok(None);
    };
    if generation == 0
        || logical_bytes == 0
        || native_metadata_bytes == 0
        || native_scratch_bytes == 0
        || region_count == 0
        || region_count > 4096
    {
        return Err(RamError::Invariant(
            "invalid native RAM admission inventory",
        ));
    }
    let scratch = (region_count as u64)
        .checked_mul(
            (2 * (std::mem::size_of::<RegionDescriptor>()
                + 255
                + std::mem::size_of::<RamControlInventoryRegion>()
                + 64)) as u64,
        )
        .and_then(|bytes| bytes.checked_add(RAM_CONTROL_MAX_BYTES as u64))
        .ok_or("RAM inventory scratch overflow")?;
    // SAFETY: the matching GPL-private exporter writes exactly three bounded
    // scalar counts under this actual pre-CPU main-actor/BQL admission fence.
    let export = unsafe {
        std::mem::transmute::<*mut c_void, NativeOwnerInventory>(symbol(
            b"qemu_plugin_crucible_ram_owner_inventory_v1\0",
        )?)
    };
    let mut owner_resources = RamControlOwnerInventory {
        existing_tasks: 0,
        existing_file_descriptors: 0,
        registered_service_tasks: 0,
        prospective_tasks: 1,
        prospective_file_descriptors: 4,
    };
    let status = export(
        &mut owner_resources.existing_tasks,
        &mut owner_resources.existing_file_descriptors,
        &mut owner_resources.registered_service_tasks,
    );
    if status != 0 {
        return Err(RamError::Native {
            operation: "authenticate pre-CPU owner inventory",
            status,
        });
    }
    let resources = controller
        .state
        .lock()
        .map_err(|_| RamError::Invariant("RAM controller poisoned"))?
        .resources;
    if scratch > resources.staging_bytes {
        return Err(RamError::Invariant("RAM inventory staging not admitted"));
    }
    let operation: Arc<dyn SourceOperation> =
        Arc::from(controller.begin(SourceOperationClass::ControlSetup)?);
    let regions = read_regions()?;
    if regions.len() != region_count as usize {
        return Err(RamError::Invariant("native RAM inventory count changed"));
    }
    let mut total = 0_u64;
    let mut portable = Vec::new();
    portable.try_reserve_exact(regions.len())?;
    for (ordinal, region) in regions.iter().enumerate() {
        total = total
            .checked_add(region.logical_length())
            .ok_or("RAM inventory sum overflow")?;
        portable.push(RamControlInventoryRegion::new(
            ordinal as u32,
            region.logical_length(),
            region.class() as u8,
            region.id(),
        )?);
    }
    if total != logical_bytes {
        return Err(RamError::Invariant(
            "native RAM inventory byte count changed",
        ));
    }
    drop(regions);
    {
        let mut state = controller
            .state
            .lock()
            .map_err(|_| RamError::Invariant("RAM controller poisoned"))?;
        if state.inventory.is_some() || state.owner.is_some() {
            return Err(RamError::Invariant("RAM inventory already admitted"));
        }
        state.inventory = Some(Inventory {
            report: RamControlInventoryReport {
                topology_generation: generation,
                logical_bytes,
                region_count,
                native_metadata_bytes,
                native_scratch_bytes,
                owner_resources,
                granted: false,
            },
            regions: portable,
            grant: None,
            operation: Some(operation.clone()),
        });
    }
    let (grant, spill_quota) = loop {
        let slice = operation.wait_slice()?;
        let grant = controller
            .state
            .lock()
            .map_err(|_| RamError::Invariant("RAM controller poisoned"))?
            .inventory
            .as_ref()
            .and_then(|inventory| inventory.grant);
        if let Some(grant) = grant {
            break grant;
        }
        std::thread::sleep(slice.min(Duration::from_millis(10)));
    };
    let mut allowance = 0;
    let status = (controller.native_grant)(generation, grant.metadata_bytes, &mut allowance);
    if status != 0 || allowance == 0 {
        controller.mark_failed();
        return Err(RamError::Native {
            operation: "grant native RAM inventory",
            status,
        });
    }
    let owner = PausedPagingOwner::new(grant, controller.clone())?;
    owner.seal_geometry(generation, logical_bytes)?;
    let spill = controller
        .spill
        .lock()
        .map_err(|_| RamError::Invariant("RAM spill custody poisoned"))?
        .take()
        .ok_or("RAM spill custody absent")?;
    owner.install_spill(spill, spill_quota)?;
    owner.install_reader()?;
    super::super::restore::install(owner.clone())?;
    {
        let mut state = controller
            .state
            .lock()
            .map_err(|_| RamError::Invariant("RAM controller poisoned"))?;
        state.resources = grant;
        state.owner = Some(owner);
        let inventory = state
            .inventory
            .as_mut()
            .ok_or("RAM inventory authority lost")?;
        inventory.regions.clear();
    }
    Ok(Some(allowance))
}

/// Returns the exact authenticated spill subset after native inventory grant.
///
/// # Errors
/// Refuses absent or incomplete managed resource admission.
pub(crate) fn admitted_spill_quota() -> Result<Option<u64>, RamError> {
    let Some(controller) = controller()? else {
        return Ok(None);
    };
    let state = controller
        .state
        .lock()
        .map_err(|_| RamError::Invariant("RAM controller poisoned"))?;
    Ok(Some(
        state
            .inventory
            .as_ref()
            .and_then(|inventory| inventory.grant)
            .ok_or("RAM spill grant missing")?
            .1,
    ))
}

/// Publishes completed root-metadata admission after the observer verifies its account.
///
/// # Errors
/// Refuses absent/stale setup, missing native grant or actual owner, or repeated completion.
pub(crate) fn complete_native_admission(generation: u64) -> Result<(), RamError> {
    let Some(controller) = controller()? else {
        return Ok(());
    };
    let operation = {
        let mut state = controller
            .state
            .lock()
            .map_err(|_| RamError::Invariant("RAM controller poisoned"))?;
        if state.owner.is_none() {
            return Err(RamError::Invariant("RAM owner not installed"));
        }
        let inventory = state.inventory.as_mut().ok_or("RAM inventory missing")?;
        if inventory.report.topology_generation != generation
            || inventory.report.granted
            || inventory.grant.is_none()
        {
            return Err(RamError::Invariant("RAM admission completion stale"));
        }
        inventory
            .operation
            .take()
            .ok_or("RAM admission operation missing")?
    };
    if let Err(error) = operation.complete() {
        let mut state = controller
            .state
            .lock()
            .map_err(|_| RamError::Invariant("RAM controller poisoned"))?;
        state.failed = true;
        if let Some(inventory) = state.inventory.as_mut() {
            inventory.operation = Some(operation);
        }
        return Err(error.into());
    }
    let mut state = controller
        .state
        .lock()
        .map_err(|_| RamError::Invariant("RAM controller poisoned"))?;
    if state.failed || state.owner.is_none() {
        return Err(RamError::Invariant("RAM admission disposition failed"));
    }
    let inventory = state.inventory.as_mut().ok_or("RAM inventory missing")?;
    if inventory.report.topology_generation != generation || inventory.report.granted {
        return Err(RamError::Invariant("RAM admission completion stale"));
    }
    inventory.report.granted = true;
    Ok(())
}
