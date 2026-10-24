//! Checks the known launch shape before authoritative native RAM admission.
//!
//! Declared main RAM is a startup lower bound. The GPL executor must validate
//! its complete sealed inventory, native metadata and scratch before guest
//! execution. These requirements neither prove eviction safety nor account for
//! independently owned QEMU process, device-state or retained-template resources.

use crucible_host_resources::ram_policy::HostResourceVector;
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

// This declared-shape lower bound cannot describe private target layouts. Actual
// admission uses the executor's complete versioned request for the sealed shape.
fn known_private_paging_metadata_lower_bound(topology: &Topology) -> Result<u64, RamError> {
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
        .and_then(|bytes| {
            bytes
                .checked_add(2 * crucible_qemu_protocol::ram_control::RAM_PERFORMANCE_BANK_RESERVE_BYTES)
        })
        .and_then(|bytes| bytes.checked_add(2 * (16 * topology.regions().len() as u64 + 256)))
        .ok_or(RamError::Overflow)
}

fn mapping_alignment_reserve(topology: &Topology) -> Result<u64, RamError> {
    (topology.regions().len() as u64)
        .checked_mul(2 * 4096)
        .ok_or(RamError::Overflow)
}

/// Calculates RAM resource requirements from an authenticated native inventory.
///
/// Native metadata and scratch retain the executor's independent ownership.
/// The authenticated Rust requirement includes four dense immutable snapshots,
/// live and staged pager controls, and two private spill generations. The host
/// composes these requests alongside two logical backing versions;
/// CAS transport work is additionally bounded by its operation concurrency.
/// A caller composes this RAM subsystem with its process and device-state
/// reserves before comparing it with the retained complete node entitlement.
///
/// # Errors
///
/// Returns an error for an empty inventory, zero peak or operation count,
/// a Rust request below the public observer lower bound, or arithmetic overflow.
pub fn actual_inventory_ram_requirements(
    topology: &Topology,
    native_metadata_bytes: u64,
    native_scratch_bytes: u64,
    rust_metadata_required_bytes: u64,
    simultaneous_cas_operations: u32,
) -> Result<HostResourceVector, RamError> {
    if topology.total_logical_bytes() == 0
        || native_metadata_bytes == 0
        || native_scratch_bytes == 0
        || rust_metadata_required_bytes == 0
        || simultaneous_cas_operations == 0
    {
        return Err(RamError::InvalidLength);
    }
    // Only the public observer lower bound is independently reconstructed here.
    // Private pager layouts come from the authenticated immutable report; they
    // are never guessed by, linked into or reissued from the Apache host.
    let observer_lower_bound = RamSnapshot::maximum_metadata_bytes(topology, 4)?
        .checked_add(RAM_ROOT_RECORD_METADATA_BYTES)
        .ok_or(RamError::Overflow)?;
    if rust_metadata_required_bytes < observer_lower_bound {
        return Err(RamError::ResourceLimit);
    }
    let metadata_bytes = native_metadata_bytes
        .checked_add(rust_metadata_required_bytes)
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
    let paging_metadata = known_private_paging_metadata_lower_bound(&topology)?;
    let rust_metadata = RamSnapshot::maximum_metadata_bytes(&topology, 4)?
        .checked_add(RAM_ROOT_RECORD_METADATA_BYTES)
        .and_then(|bytes| bytes.checked_add(paging_metadata))
        .ok_or(RamError::Overflow)?;

    // The native observer accounts both sealed and temporary region catalogs:
    // 328-byte region + 32-byte allocation charge + 16-byte pointer slack.
    let capture_metadata = 4096_u64
        .checked_mul(752)
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
    fn corrected_capture_floor_refuses_an_unchanged_narrow_entitlement() {
        use crucible_host_resources::ram_policy::{HostRamTarget, HostResourceLedger};

        let current = known_ram_launch_requirements(512 * 1024 * 1024, 1)
            .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"));

        // The historical region was eight bytes smaller and had no 32-byte
        // independent observation workspace. Keep that original capacity.
        let previous = HostResourceVector {
            resident_peak_bytes: current.resident_peak_bytes - 327_680,
            metadata_bytes: current.metadata_bytes - 327_680,
            ..current
        };
        let target = HostRamTarget {
            daemon_epoch: [1; 32],
            owner_id: [2; 32],
            node_id: [3; 32],
            owner_generation: 1,
            arena_generation: 1,
            retained_template: false,
        };
        let mut ledger = HostResourceLedger::new(previous);
        ledger
            .admit(target, previous)
            .unwrap_or_else(|error| panic!("previous launch entitlement fixture: {error}"));
        ledger
            .release_after_cleanup(target)
            .unwrap_or_else(|error| panic!("completed launch entitlement fixture: {error}"));

        assert!(ledger.admit(target, current).is_err());
        assert_eq!(ledger.capacity(), previous);
        assert_eq!(ledger.reserved(), HostResourceVector::default());
        assert_eq!(ledger.owner_reservation(target), None);
    }

    #[test]
    fn invalid_and_overflowing_shapes_refuse_before_reservation() {
        assert!(known_ram_launch_requirements(0, 1).is_err());
        assert!(known_ram_launch_requirements(4096, 0).is_err());
        assert!(known_ram_launch_requirements(u64::MAX, u32::MAX).is_err());
    }

    #[test]
    fn independent_observation_workspace_refuses_previous_capture_entitlement() {
        use crucible_host_resources::ram_policy::{HostRamTarget, HostResourceLedger};

        let current = known_ram_launch_requirements(512 * 1024 * 1024, 1)
            .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"));
        let previous = HostResourceVector {
            resident_peak_bytes: current.resident_peak_bytes - 262_144,
            metadata_bytes: current.metadata_bytes - 262_144,
            ..current
        };
        let target = HostRamTarget {
            daemon_epoch: [1; 32],
            owner_id: [2; 32],
            node_id: [3; 32],
            owner_generation: 1,
            arena_generation: 1,
            retained_template: false,
        };
        let mut ledger = HostResourceLedger::new(previous);
        ledger
            .admit(target, previous)
            .unwrap_or_else(|error| panic!("previous capture entitlement fixture: {error}"));
        ledger
            .release_after_cleanup(target)
            .unwrap_or_else(|error| panic!("completed capture entitlement fixture: {error}"));

        assert!(ledger.admit(target, current).is_err());
        assert_eq!(ledger.capacity(), previous);
        assert_eq!(ledger.reserved(), HostResourceVector::default());
        assert_eq!(ledger.owner_reservation(target), None);
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
        let rust_request = RamSnapshot::maximum_metadata_bytes(&topology, 4).unwrap()
            + RAM_ROOT_RECORD_METADATA_BYTES
            + known_private_paging_metadata_lower_bound(&topology).unwrap();
        let actual = actual_inventory_ram_requirements(&topology, 16384, 32768, rust_request, 2)
            .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"));

        assert_eq!(
            actual.metadata_bytes,
            RamSnapshot::maximum_metadata_bytes(&topology, 4)
                .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"))
                + RAM_ROOT_RECORD_METADATA_BYTES
                + known_private_paging_metadata_lower_bound(&topology)
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
        assert!(actual_inventory_ram_requirements(&topology, 0, 32768, rust_request, 2).is_err());
        assert!(
            actual_inventory_ram_requirements(&topology, u64::MAX, 32768, rust_request, 2).is_err()
        );
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
        let paging_metadata = known_private_paging_metadata_lower_bound(&topology)
            .unwrap_or_else(|error| panic!("RAM admission fixture: {error}"));
        // Duplicate native mutation targets retain the producer's complete
        // 65,536-entry bound even for this three-page guest. Unique-coordinate
        // receipts instead round these three pages to one allocation page.
        let native_mutation_scratch = 56 * 65_536 + 2 * 4096;
        let unique_coordinate_receipt = 4096 + 4096;
        // Parent and staged child each retain two 16-byte lock spans plus
        // their separately admitted 256-byte inventory ownership envelope.
        let lock_inventories = 2 * (2 * 16 + 256);
        // Parent and independently staged child each reserve an optional fixed bank.
        let diagnostic_banks =
            2 * crucible_qemu_protocol::ram_control::RAM_PERFORMANCE_BANK_RESERVE_BYTES;
        assert_eq!(
            paging_metadata
                - native_mutation_scratch
                - unique_coordinate_receipt
                - lock_inventories
                - diagnostic_banks,
            8160
        );
        let rust_request = RamSnapshot::maximum_metadata_bytes(&topology, 4).unwrap()
            + RAM_ROOT_RECORD_METADATA_BYTES
            + paging_metadata;
        let actual = actual_inventory_ram_requirements(&topology, 16384, 32768, rust_request, 1)
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

    #[test]
    fn complete_report_refuses_the_unchanged_omitting_entitlement() {
        use crucible_host_resources::ram_policy::{HostRamTarget, HostResourceLedger};

        let topology = Topology::new(
            vec![RegionDescriptor::new("main", RegionClass::MutableMain, 4096).unwrap()],
            Limits::default(),
        )
        .unwrap();
        let observer = RamSnapshot::maximum_metadata_bytes(&topology, 4).unwrap()
            + RAM_ROOT_RECORD_METADATA_BYTES;
        let historical_rust =
            observer + known_private_paging_metadata_lower_bound(&topology).unwrap();
        // This scalar models the extra target controls in an authenticated report.
        // The Apache host never interprets their private layout or issues credit.
        let complete_rust = historical_rust + 8192;
        let old =
            actual_inventory_ram_requirements(&topology, 4096, 16384, historical_rust, 1).unwrap();
        let complete =
            actual_inventory_ram_requirements(&topology, 4096, 16384, complete_rust, 1).unwrap();
        assert_eq!(complete.metadata_bytes - old.metadata_bytes, 8192);
        assert_eq!(complete.resident_peak_bytes - old.resident_peak_bytes, 8192);
        assert_eq!(complete.backing_peak_bytes, old.backing_peak_bytes);
        assert_eq!(complete.metadata_bytes - 4096, complete_rust);

        let target = HostRamTarget {
            daemon_epoch: [1; 32],
            owner_id: [2; 32],
            node_id: [3; 32],
            owner_generation: 1,
            arena_generation: 1,
            retained_template: false,
        };
        let mut unchanged = HostResourceLedger::new(old);
        assert!(unchanged.admit(target, complete).is_err());
        assert_eq!(unchanged.capacity(), old);
        assert_eq!(unchanged.reserved(), HostResourceVector::default());
        let mut exact = HostResourceLedger::new(complete);
        exact.admit(target, complete).unwrap();
        assert_eq!(exact.owner_reservation(target).unwrap().1, complete);
        assert!(actual_inventory_ram_requirements(&topology, 4096, 16384, 0, 1).is_err());
        assert!(
            actual_inventory_ram_requirements(&topology, 4096, 16384, observer - 1, 1).is_err()
        );
        assert!(actual_inventory_ram_requirements(&topology, 4096, 16384, u64::MAX, 1).is_err());
    }
}
