//! Shared region-layout test fixtures.

use super::*;

pub(super) fn layout(config: RegionConfig) -> RegionLayout {
    match RegionLayout::for_config(config) {
        Ok(layout) => layout,
        Err(error) => panic!("region layout should be valid: {error}"),
    }
}

#[cfg(all(
    target_arch = "x86_64",
    target_abi = "",
    target_endian = "little",
    target_env = "gnu",
    target_os = "linux",
    target_pointer_width = "64"
))]
pub(super) fn allocation(config: RegionConfig) -> RegionAllocation {
    match RegionAllocation::new(config) {
        Ok(allocation) => allocation,
        Err(error) => panic!("region allocation should be valid: {error}"),
    }
}

#[cfg(all(
    target_arch = "x86_64",
    target_abi = "",
    target_endian = "little",
    target_env = "gnu",
    target_os = "linux",
    target_pointer_width = "64"
))]
pub(super) fn assert_slot(allocation: &RegionAllocation, slot: usize, kind: u8, status: u8) {
    let snapshot = allocation.slots()[slot].snapshot();
    assert_eq!(snapshot.kind, kind);
    assert_eq!(snapshot.status, status);
    assert_eq!(snapshot.max_advance_icount, 0);
}

#[cfg(all(
    target_arch = "x86_64",
    target_abi = "",
    target_endian = "little",
    target_env = "gnu",
    target_os = "linux",
    target_pointer_width = "64"
))]
pub(super) fn ring(index: u32, src_slot: usize, dst_slot: usize) -> DirectedRing {
    DirectedRing {
        index,
        src_slot: src_slot as u32,
        dst_slot: dst_slot as u32,
    }
}
