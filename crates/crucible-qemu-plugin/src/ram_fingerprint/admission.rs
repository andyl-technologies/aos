//! Admits dense RAM identity capacity against the actual realized native inventory.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

#[repr(C)]
#[derive(Default)]
pub(super) struct AdmissionHeader {
    schema: u32,
    region_count: u32,
    topology_generation: u64,
    logical_bytes: u64,
    native_metadata_bytes: u64,
    native_scratch_bytes: u64,
}

/// Reads the sealed inventory without entering a RAM capture or writer epoch.
///
/// The caller holds native BQL authority. The returned reservation accounts for
/// the native-order descriptors and their canonical validation inventory; it
/// remains owned for as long as the descriptor vector is retained. No observer
/// mutex is held during native reads or later physical paging transitions.
///
/// # Errors
///
/// Refuses missing native exports, unsealed or stale topology, invalid bounds,
/// competing observer admission, and insufficient shared metadata capacity.
pub(crate) fn admitted_inventory() -> Result<
    (
        u64,
        Vec<RegionDescriptor>,
        MetadataBudget,
        MetadataReservation,
    ),
    RamError,
> {
    type ReadAdmissionHeader = extern "C" fn(*mut AdmissionHeader) -> c_int;
    // SAFETY: this private metadata-only export uses the exact repr(C) header
    // above and retains no pointer to the stack output after returning.
    let read_header = unsafe {
        std::mem::transmute::<*mut c_void, ReadAdmissionHeader>(symbol(
            b"qemu_plugin_crucible_ram_admission_header_v1\0",
        )?)
    };
    let budget = fork_metadata_budget()?;
    let mut header = AdmissionHeader::default();
    status(read_header(&mut header), "read sealed RAM admission")?;
    if header.schema != 1
        || header.region_count == 0
        || header.region_count as usize > MAX_REGIONS
        || header.topology_generation == 0
        || header.logical_bytes == 0
        || header.native_metadata_bytes == 0
        || header.native_scratch_bytes == 0
    {
        return Err(RamError::Invariant("invalid sealed RAM admission header"));
    }
    let inventory_bytes = (header.region_count as u64)
        .checked_mul((std::mem::size_of::<RegionDescriptor>() + 255 + 32) as u64)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or("sealed RAM inventory metadata overflow")?;
    let reservation = budget.reserve_bytes(inventory_bytes)?;
    let read = observer()?.apis.admission_region;
    let regions = read_region_inventory(
        header.region_count,
        header.topology_generation,
        |generation, index, output| read(generation, index, output),
    )?;
    let topology = Topology::new(regions.clone(), Limits::default())?;
    if topology.total_logical_bytes() != header.logical_bytes {
        return Err(RamError::Invariant(
            "sealed RAM inventory byte count disagrees",
        ));
    }
    Ok((header.topology_generation, regions, budget, reservation))
}

pub(super) extern "C" fn observe_admission(
    header: *const AdmissionHeader,
    allowance: u64,
) -> c_int {
    if header.is_null() {
        return -libc::EINVAL;
    }
    let result = std::panic::catch_unwind(|| -> Result<(), RamError> {
        // SAFETY: the native initialization fence lends a complete metadata-only
        // header for this synchronous callback; it contains no RAM addresses.
        let header = unsafe { &*header };
        if header.schema != 1
            || header.region_count == 0
            || header.region_count as usize > MAX_REGIONS
            || header.topology_generation == 0
            || header.logical_bytes == 0
            || header.native_metadata_bytes == 0
            || header.native_scratch_bytes == 0
        {
            return Err(RamError::Invariant("invalid native RAM admission header"));
        }
        let observer = observer()?;
        #[cfg(all(target_os = "linux", feature = "kernel-swap-measurement"))]
        let allowance = crate::paged_ram::research_resident::apply_native_grant(
            header.topology_generation,
            header.logical_bytes,
        )?
        .unwrap_or(allowance);

        #[cfg(target_os = "linux")]
        let allowance = crate::paged_ram::controller::admit_native_inventory(
            header.topology_generation,
            header.logical_bytes,
            header.native_metadata_bytes,
            header.native_scratch_bytes,
            header.region_count,
            || {
                read_region_inventory(
                    header.region_count,
                    header.topology_generation,
                    |generation, index, output| {
                        (observer.apis.admission_region)(generation, index, output)
                    },
                )
            },
        )?
        .unwrap_or(allowance);
        if allowance == 0 {
            return Err(RamError::MetadataAdmission {
                required: 1,
                admitted: 0,
            });
        }
        let budget = observer
            .cache
            .try_lock()
            .map_err(|_| "RAM admission observer is active")?
            .metadata_budget(allowance)?;
        let inventory_bytes = (header.region_count as u64)
            .checked_mul((std::mem::size_of::<RegionDescriptor>() + 255 + 32) as u64)
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or("RAM admission inventory metadata overflow")?;
        // Both the native-order decoder inventory and canonical topology may
        // coexist before their precise retained sizes are known.
        let _inventory = budget
            .reserve_bytes(inventory_bytes)
            .map_err(display_error)?;
        let regions = read_region_inventory(
            header.region_count,
            header.topology_generation,
            |generation, index, output| (observer.apis.admission_region)(generation, index, output),
        )?;
        let topology = Topology::new(regions, Limits::default()).map_err(display_error)?;
        if topology.total_logical_bytes() != header.logical_bytes {
            return Err(RamError::Invariant(
                "native RAM admission inventory byte count disagrees",
            ));
        }
        // Four dense versions conservatively cover the committed snapshot, old
        // virtual batch candidate, growing replacement and transient update.
        // Encoded records/source decoding are bounded independently by the
        // public three-mebibyte record ceiling, with nine concurrent owners.
        let mut required = RamSnapshot::maximum_metadata_bytes(&topology, 4)
            .map_err(display_error)?
            .checked_add(9 * 3 * 1024 * 1024)
            .ok_or("RAM metadata requirement overflow")?;
        #[cfg(target_os = "linux")]
        if let Some(spill_quota) = crate::paged_ram::controller::admitted_spill_quota()? {
            let pages = topology.regions().iter().try_fold(0_u64, |total, region| {
                total
                    .checked_add(region.geometry().page_count())
                    .ok_or("RAM page-state count overflow")
            })?;
            let regions = u32::try_from(topology.regions().len())
                .map_err(|_| RamError::Invariant("RAM pager region count overflow"))?;
            required = required
                .checked_add(
                    crate::paged_ram::PausedPagingOwner::required_metadata_bytes(
                        pages,
                        regions,
                        spill_quota,
                    )?,
                )
                .ok_or("RAM paging metadata requirement overflow")?;
        }
        if allowance < required {
            return Err(RamError::MetadataAdmission {
                required,
                admitted: allowance,
            });
        }
        #[cfg(target_os = "linux")]
        crate::paged_ram::controller::complete_native_admission(header.topology_generation)?;
        Ok(())
    });
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            crate::ram_diagnostics::emit(crate::ram_diagnostics::RamDiagnostic::AdmissionRefused(
                &error,
            ));
            -libc::ENOMEM
        }
        Err(_) => -libc::EIO,
    }
}
