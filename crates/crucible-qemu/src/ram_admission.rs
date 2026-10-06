//! Checks the known launch shape before authoritative native RAM admission.
//!
//! Declared main RAM is a startup lower bound. The GPL executor must validate
//! its complete sealed inventory, native metadata and scratch before guest
//! execution. These requirements neither prove eviction safety nor account for
//! independently owned QEMU process, device-state or retained-template resources.

use crucible_linux_resource::ram_policy::HostResourceVector;
use crucible_ram::{Limits, RamError, RamSnapshot, RegionClass, RegionDescriptor, Topology};

/// Bounds one simultaneously admitted host CAS operation's transport and codec work.
///
/// This scratch belongs to the Apache host process outside the QEMU cgroup.
/// Native scratch is independently reported and retained inside that cgroup.
pub const RAM_CAS_OPERATION_SCRATCH_BYTES: u64 = 4 * 1024 * 1024;

/// Bounds retained records and source/encoding work for the RAM observer.
///
/// Three scopes may coexist in each of a committed view, prepared candidate
/// and transient encoding/source owner. Each record has the public codec's
/// independently enforced three-mebibyte ceiling. This metadata belongs to the
/// GPL observer inside QEMU, together with its Merkle and paging metadata; it
/// is not an allowance for the host's separately owned CAS graph or index.
pub const RAM_ROOT_RECORD_METADATA_BYTES: u64 = 9 * 3 * 1024 * 1024;

/// Bounds two private spill generations using complete logical page slots.
///
/// Each region rounds independently, so partial device pages never disappear
/// through division of an aggregate logical byte count.
///
/// # Errors
///
/// Refuses an empty inventory or overflow in the rounded two-generation quota.
pub fn private_spill_quota_bytes(topology: &Topology) -> Result<u64, RamError> {
    logical_page_count(topology)?
        .checked_mul(2 * 4096)
        .ok_or(RamError::Overflow)
}

fn logical_page_count(topology: &Topology) -> Result<u64, RamError> {
    if topology.total_logical_bytes() == 0 {
        return Err(RamError::InvalidLength);
    }
    topology.regions().iter().try_fold(0_u64, |total, region| {
        total
            .checked_add(region.geometry().page_count())
            .ok_or(RamError::Overflow)
    })
}

// The private executor independently checks these conservative bounds against
// its actual slot leases, page states and arena allocations before activation.
fn private_paging_metadata_bytes(topology: &Topology) -> Result<u64, RamError> {
    let pages = logical_page_count(topology)?;
    let slots = private_spill_quota_bytes(topology)? / 4096;
    let store = slots
        .checked_mul(256)
        .and_then(|bytes| bytes.checked_add(1024))
        .ok_or(RamError::Overflow)?;
    let page_states = pages.checked_mul(80).ok_or(RamError::Overflow)?;
    let arenas = (topology.regions().len() as u64)
        .checked_mul(128)
        .and_then(|bytes| bytes.checked_add(1024))
        .ok_or(RamError::Overflow)?;
    store
        .checked_add(page_states)
        .and_then(|bytes| bytes.checked_add(arenas))
        .and_then(|bytes| bytes.checked_mul(2))
        // Native mutation staging includes duplicate upper-page coordinates;
        // the pinned producer refuses batches beyond 65,536 entries.
        .and_then(|bytes| bytes.checked_add(56 * 65536 + 2 * 4096))
        .and_then(|bytes| bytes.checked_add((16 * pages.min(65536)).div_ceil(4096) * 4096 + 4096))
        .ok_or(RamError::Overflow)
}

fn mapping_alignment_reserve(topology: &Topology) -> Result<u64, RamError> {
    (topology.regions().len() as u64)
        .checked_mul(2 * 4096)
        .ok_or(RamError::Overflow)
}

/// Calculates RAM resource requirements from an authenticated native inventory.
///
/// Native metadata and scratch are complete peak quantities from the executor,
/// including its independently owned dirty, borrower and capture planes. Four
/// dense immutable snapshots and two page-rounded private spill generations
/// are admitted alongside two logical backing versions;
/// CAS transport work is additionally bounded by its operation concurrency.
/// A caller composes this RAM subsystem with its process and device-state
/// reserves before comparing it with the retained complete node entitlement.
///
/// # Errors
///
/// Returns an error for an empty inventory, zero native peak or operation count,
/// or arithmetic overflow in any resource component.
pub fn actual_inventory_ram_requirements(
    topology: &Topology,
    native_metadata_bytes: u64,
    native_scratch_bytes: u64,
    simultaneous_cas_operations: u32,
) -> Result<HostResourceVector, RamError> {
    if topology.total_logical_bytes() == 0
        || native_metadata_bytes == 0
        || native_scratch_bytes == 0
        || simultaneous_cas_operations == 0
    {
        return Err(RamError::InvalidLength);
    }
    let paging_metadata = private_paging_metadata_bytes(topology)?;
    let metadata_bytes = RamSnapshot::maximum_metadata_bytes(topology, 4)?
        .checked_add(RAM_ROOT_RECORD_METADATA_BYTES)
        .and_then(|bytes| bytes.checked_add(paging_metadata))
        .and_then(|bytes| bytes.checked_add(native_metadata_bytes))
        .ok_or(RamError::Overflow)?;
    let staging_bytes = RAM_CAS_OPERATION_SCRATCH_BYTES
        .checked_mul(u64::from(simultaneous_cas_operations))
        .and_then(|bytes| bytes.checked_add(native_scratch_bytes))
        .ok_or(RamError::Overflow)?;
    let logical_bytes = topology.total_logical_bytes();
    let resident_peak_bytes = logical_bytes
        .checked_add(mapping_alignment_reserve(topology)?)
        .and_then(|bytes| bytes.checked_add(metadata_bytes))
        .and_then(|bytes| bytes.checked_add(staging_bytes))
        .ok_or(RamError::Overflow)?;
    let spill_quota = private_spill_quota_bytes(topology)?;
    let backing_peak_bytes = logical_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(spill_quota))
        .and_then(|bytes| bytes.checked_add(staging_bytes))
        .ok_or(RamError::Overflow)?;

    Ok(HostResourceVector {
        resident_peak_bytes,
        backing_peak_bytes,
        metadata_bytes,
        staging_bytes,
        paging_io_slots: u64::from(simultaneous_cas_operations),
        cpu_slots: 0,
        task_slots: 0,
        file_descriptors: 0,
    })
}

/// Calculates checked startup requirements for declared main RAM.
///
/// Dense Merkle capacity admits four live immutable versions, rather than
/// assuming the guest retains zero pages or a sparse working set. Native capture
/// inventory reserves its complete 4096-region bound; the dirty bitmap reserve
/// covers the declared contiguous main-RAM span and one RCU growth predecessor.
/// Native admission replaces these lower-bound topology assumptions with the
/// actual complete inventory and refuses insufficient entitlement before any
/// guest instruction. A caller additionally reserves QEMU process, device-state,
/// launch descriptors/tasks and template ownership from its actual contract.
///
/// # Errors
///
/// Returns an error for zero RAM or operation concurrency, invalid logical
/// geometry, or overflow in any resident, backing, metadata or scratch quantity.
pub fn known_ram_launch_requirements(
    declared_ram_bytes: u64,
    simultaneous_cas_operations: u32,
) -> Result<HostResourceVector, RamError> {
    if declared_ram_bytes == 0 || simultaneous_cas_operations == 0 {
        return Err(RamError::InvalidLength);
    }
    let topology = Topology::new(
        vec![RegionDescriptor::new(
            "main-ram",
            RegionClass::MutableMain,
            declared_ram_bytes,
        )?],
        Limits::default(),
    )?;
    // A committed view, old batch candidate, growing replacement and one
    // transient update may coexist while another virtual batch action prepares.
    let paging_metadata = private_paging_metadata_bytes(&topology)?;
    let rust_metadata = RamSnapshot::maximum_metadata_bytes(&topology, 4)?
        .checked_add(RAM_ROOT_RECORD_METADATA_BYTES)
        .and_then(|bytes| bytes.checked_add(paging_metadata))
        .ok_or(RamError::Overflow)?;

    // The native observer accounts both sealed and temporary region catalogs:
    // 288-byte region + 32-byte allocation charge + 16-byte pointer slack.
    let capture_metadata = 4096_u64
        .checked_mul(672)
        .and_then(|bytes| bytes.checked_add(128))
        .ok_or(RamError::Overflow)?;
    let dirty_span_bytes = 8_u64 * 1024 * 1024 * 1024;
    let dirty_blocks = declared_ram_bytes
        .checked_add(dirty_span_bytes - 1)
        .ok_or(RamError::Overflow)?
        / dirty_span_bytes;
    let dirty_metadata = dirty_blocks
        .checked_mul(2 * (256 * 1024 + 32 + 8))
        .and_then(|bytes| bytes.checked_add(128))
        .ok_or(RamError::Overflow)?;
    let metadata_bytes = rust_metadata
        .checked_add(capture_metadata)
        .and_then(|bytes| bytes.checked_add(dirty_metadata))
        .ok_or(RamError::Overflow)?;
    let staging_bytes = RAM_CAS_OPERATION_SCRATCH_BYTES
        .checked_add(16 * 1024)
        .and_then(|bytes| bytes.checked_mul(u64::from(simultaneous_cas_operations)))
        .ok_or(RamError::Overflow)?;
    let resident_peak_bytes = declared_ram_bytes
        .checked_add(mapping_alignment_reserve(&topology)?)
        .and_then(|bytes| bytes.checked_add(metadata_bytes))
        .and_then(|bytes| bytes.checked_add(staging_bytes))
        .ok_or(RamError::Overflow)?;
    let spill_quota = private_spill_quota_bytes(&topology)?;
    let backing_peak_bytes = declared_ram_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(spill_quota))
        .and_then(|bytes| bytes.checked_add(staging_bytes))
        .ok_or(RamError::Overflow)?;

    Ok(HostResourceVector {
        resident_peak_bytes,
        backing_peak_bytes,
        metadata_bytes,
        staging_bytes,
        paging_io_slots: u64::from(simultaneous_cas_operations),
        // These resources belong to the complete process contract, not the RAM
        // subsystem. This vector must be composed with that owner before launch.
        cpu_slots: 0,
        task_slots: 0,
        file_descriptors: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_floor_composes_independent_concurrent_scratch() {
        let single = known_ram_launch_requirements(512 * 1024 * 1024, 1)
            .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"));
        let pair = known_ram_launch_requirements(512 * 1024 * 1024, 2)
            .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"));
        assert_eq!(single.metadata_bytes, pair.metadata_bytes);
        assert_eq!(pair.staging_bytes, single.staging_bytes * 2);
        assert_eq!(
            pair.resident_peak_bytes - single.resident_peak_bytes,
            single.staging_bytes
        );
        assert!(single.resident_peak_bytes > 512 * 1024 * 1024);
        assert!(single.backing_peak_bytes > 1024 * 1024 * 1024);
    }

    #[test]
    fn invalid_and_overflowing_shapes_refuse_before_reservation() {
        assert!(known_ram_launch_requirements(0, 1).is_err());
        assert!(known_ram_launch_requirements(4096, 0).is_err());
        assert!(known_ram_launch_requirements(u64::MAX, u32::MAX).is_err());
    }

    #[test]
    fn authenticated_inventory_accounts_device_ram_and_exact_native_peaks() {
        let topology = Topology::new(
            vec![
                RegionDescriptor::new("main", RegionClass::MutableMain, 8192)
                    .unwrap_or_else(|error| panic!("RAM admission fixture: {error}")),
                RegionDescriptor::new("device", RegionClass::MutableDevice, 4096)
                    .unwrap_or_else(|error| panic!("RAM admission fixture: {error}")),
            ],
            Limits::default(),
        )
        .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"));
        let actual = actual_inventory_ram_requirements(&topology, 16384, 32768, 2)
            .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"));

        assert_eq!(
            actual.metadata_bytes,
            RamSnapshot::maximum_metadata_bytes(&topology, 4)
                .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"))
                + RAM_ROOT_RECORD_METADATA_BYTES
                + private_paging_metadata_bytes(&topology)
                    .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"))
                + 16384
        );
        assert_eq!(
            actual.staging_bytes,
            2 * RAM_CAS_OPERATION_SCRATCH_BYTES + 32768
        );
        assert_eq!(
            actual.resident_peak_bytes,
            12288 + 2 * 4096 * 2 + actual.metadata_bytes + actual.staging_bytes
        );
        assert_eq!(actual.backing_peak_bytes, 4 * 12288 + actual.staging_bytes);
        assert!(actual_inventory_ram_requirements(&topology, 0, 32768, 2).is_err());
        assert!(actual_inventory_ram_requirements(&topology, u64::MAX, 32768, 2).is_err());
    }

    #[test]
    fn partial_regions_reserve_whole_spill_slots_and_mapping_padding() {
        let topology = Topology::new(
            vec![
                RegionDescriptor::new("main", RegionClass::MutableMain, 4097)
                    .unwrap_or_else(|error| panic!("RAM admission fixture: {error}")),
                RegionDescriptor::new("device", RegionClass::MutableDevice, 1)
                    .unwrap_or_else(|error| panic!("RAM admission fixture: {error}")),
            ],
            Limits::default(),
        )
        .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"));

        assert_eq!(
            private_spill_quota_bytes(&topology)
                .unwrap_or_else(|error| panic!("RAM admission fixture: {error}")),
            2 * 3 * 4096
        );
        let paging_metadata = private_paging_metadata_bytes(&topology)
            .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"));
        // Duplicate native mutation targets retain the producer's complete
        // 65,536-entry bound even for this three-page guest. Unique-coordinate
        // receipts instead round these three pages to one allocation page.
        let native_mutation_scratch = 56 * 65_536 + 2 * 4096;
        let unique_coordinate_receipt = 4096 + 4096;
        assert_eq!(
            paging_metadata - native_mutation_scratch - unique_coordinate_receipt,
            8160
        );
        let actual = actual_inventory_ram_requirements(&topology, 16384, 32768, 1)
            .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"));
        assert_eq!(
            actual.backing_peak_bytes,
            2 * 4098 + 24576 + actual.staging_bytes
        );
        assert_eq!(
            actual.resident_peak_bytes,
            4098 + 16384 + actual.metadata_bytes + actual.staging_bytes
        );
    }
}
