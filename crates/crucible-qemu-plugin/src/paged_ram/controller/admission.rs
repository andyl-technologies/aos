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
    let (owner_resources, operation) = export_owner_inventory(&controller, |inventory| {
        export(
            &mut inventory.existing_tasks,
            &mut inventory.existing_file_descriptors,
            &mut inventory.registered_service_tasks,
        )
    })?;
    let resources = controller
        .state
        .lock()
        .map_err(|_| RamError::Invariant("RAM controller poisoned"))?
        .resources;
    if scratch > resources.staging_bytes {
        return Err(RamError::Invariant("RAM inventory staging not admitted"));
    }
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
    // Move the already staged descriptor owner into canonical validation. The
    // existing two-inventory staging request covers its transient shared slice;
    // no descriptor or topology clone is created for the metadata request.
    let topology = crucible_ram::Topology::new(regions, crucible_ram::Limits::default())?;
    if topology.total_logical_bytes() != logical_bytes {
        return Err(RamError::Invariant(
            "canonical RAM inventory byte count changed",
        ));
    }
    let spill_quota_required = topology.regions().iter().try_fold(0_u64, |total, region| {
        region
            .geometry()
            .page_count()
            .checked_mul(2 * super::super::PAGE_BYTES as u64)
            .and_then(|bytes| total.checked_add(bytes))
            .ok_or(RamError::Invariant("sealed spill metadata extent overflow"))
    })?;
    let rust_metadata_required_bytes =
        PausedPagingOwner::required_rust_metadata_bytes(&topology, spill_quota_required)?;
    drop(topology);
    operation.wait_slice()?;
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
                rust_metadata_required_bytes,
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
    let allowance = grant_native_rust_allowance(
        &controller,
        operation.as_ref(),
        generation,
        grant.metadata_bytes,
        rust_metadata_required_bytes,
    )?;
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

/// Checks the native residual grant before pager or service construction.
///
/// The request remains under the same installing operation; the native return
/// is an independently owned allowance, never a new installer purpose.
///
/// # Errors
/// Refuses an expired original, failed native grant, or a residual allowance
/// below the complete reported Rust requirement.
pub(super) fn grant_native_rust_allowance(
    controller: &LivePagerController,
    operation: &dyn SourceOperation,
    generation: u64,
    metadata_bytes: u64,
    rust_metadata_required_bytes: u64,
) -> Result<u64, RamError> {
    operation.wait_slice()?;
    let mut allowance = 0;
    let status = (controller.native_grant)(generation, metadata_bytes, &mut allowance);
    if status != 0 || allowance == 0 {
        controller.mark_failed();
        return Err(RamError::Native {
            operation: "grant native RAM inventory",
            status,
        });
    }
    if allowance < rust_metadata_required_bytes {
        controller.mark_failed();
        return Err(RamError::MetadataAdmission {
            required: rust_metadata_required_bytes,
            admitted: allowance,
        });
    }
    operation.wait_slice()?;
    Ok(allowance)
}

// Only this explicit native status precedes every collector or census effect.
// Negative errno values preserve terminal causes and never authorize a retry.
const NATIVE_INVENTORY_PENDING_RECORD: c_int = 1;

/// Keeps native census and subsequent grant installation under one setup start.
///
/// The native call remains on the pre-CPU main actor with BQL. It can block while
/// draining native workers, so the independent host setup watchdog supplies
/// process containment; these checks refuse a late success before publication.
/// A record-drain pending result retries under that same setup operation before
/// native census begins. No controller lock is held while the exporter runs.
///
/// # Errors
/// Refuses expired or unavailable original setup authority before export or
/// publication, and preserves the original native status when export fails.
pub(super) fn export_owner_inventory(
    controller: &LivePagerController,
    mut export: impl FnMut(&mut RamControlOwnerInventory) -> c_int,
) -> Result<(RamControlOwnerInventory, Arc<dyn SourceOperation>), RamError> {
    let operation: Arc<dyn SourceOperation> =
        Arc::from(controller.begin(SourceOperationClass::ControlSetup)?);
    let mut inventory = RamControlOwnerInventory {
        existing_tasks: 0,
        existing_file_descriptors: 0,
        registered_service_tasks: 0,
        prospective_tasks: 1,
        prospective_file_descriptors: 5,
    };
    loop {
        operation.wait_slice()?;
        let status = export(&mut inventory);
        if status == 0 {
            break;
        }
        if status != NATIVE_INVENTORY_PENDING_RECORD {
            return Err(RamError::Native {
                operation: "authenticate pre-CPU owner inventory",
                status,
            });
        }
        if inventory.existing_tasks != 0
            || inventory.existing_file_descriptors != 0
            || inventory.registered_service_tasks != 0
        {
            return Err(RamError::Invariant(
                "pending native inventory contains census output",
            ));
        }

        // Native retains the same requested dispatch hold before its census.
        // Current records can drain without Main; preserve this setup start and
        // leave all collector or cleanup failures terminal.
        let slice = operation.wait_slice()?;
        std::thread::sleep(slice.min(Duration::from_millis(10)));
    }
    operation.wait_slice()?;
    if inventory.existing_tasks == 0
        || inventory.existing_file_descriptors == 0
        || inventory.registered_service_tasks > inventory.existing_tasks
    {
        return Err(RamError::Invariant("native owner census is incomplete"));
    }

    Ok((inventory, operation))
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
