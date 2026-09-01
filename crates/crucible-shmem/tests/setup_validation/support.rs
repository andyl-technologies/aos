//! Shared setup-validation decoding and mapped-region fixtures.

use super::*;

pub(super) fn valid_snapshot() -> (RegionLayout, RegionHeaderSnapshot) {
    let layout = match RegionLayout::for_config(RegionConfig::new(2, DEFAULT_QUEUE_CAPACITY, 3)) {
        Ok(layout) => layout,
        Err(error) => panic!("valid setup region layout should build: {error}"),
    };
    let header = RegionHeader::new(layout);
    (layout, header.snapshot())
}

pub(super) fn header_snapshot_from_bytes(bytes: &[u8]) -> RegionHeaderSnapshot {
    RegionHeaderSnapshot {
        magic: read_u64(bytes, REGION_HEADER_MAGIC_OFFSET),
        abi_version: read_u32(bytes, REGION_HEADER_ABI_VERSION_OFFSET),
        node_count: read_u32(bytes, REGION_HEADER_NODE_COUNT_OFFSET),
        queue_capacity: read_u32(bytes, REGION_HEADER_QUEUE_CAPACITY_OFFSET),
        ring_count: read_u32(bytes, REGION_HEADER_RING_COUNT_OFFSET),
        ring_hdr_off: read_u64(bytes, REGION_HEADER_RING_HDR_OFF_OFFSET),
        ring_data_off: read_u64(bytes, REGION_HEADER_RING_DATA_OFF_OFFSET),
        entry_stride: read_u64(bytes, REGION_HEADER_ENTRY_STRIDE_OFFSET),
        region_size: read_u64(bytes, REGION_HEADER_REGION_SIZE_OFFSET),
        icount_shift: read_u32(bytes, REGION_HEADER_ICOUNT_SHIFT_OFFSET),
        pause_requested: 0,
        shutdown_requested: 0,
        fault_payload_arena_bytes: read_u32(bytes, REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET),
    }
}

pub(super) fn read_u8(bytes: &[u8], offset: usize) -> u8 {
    bytes[offset]
}

pub(super) fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut out = [0; 2];
    out.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(out)
}

pub(super) fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut out = [0; 4];
    out.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(out)
}

pub(super) fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut out = [0; 8];
    out.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(out)
}

#[cfg(unix)]
pub(super) fn temp_region_file() -> std::fs::File {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "crucible-shmem-setup-validation-{}-{}",
        std::process::id(),
        unique_temp_suffix()
    ));

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) => panic!("failed to create temporary setup region: {error}"),
    };
    if let Err(error) = std::fs::remove_file(&path) {
        panic!("failed to unlink temporary setup region: {error}");
    }
    file
}

#[cfg(unix)]
pub(super) fn unique_temp_suffix() -> u64 {
    NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(unix)]
pub(super) fn mapped_region_from_allocation(allocation: &RegionAllocation) -> MappedSetupRegion {
    let layout = allocation.layout();
    let bytes = match allocation.setup_region_bytes() {
        Ok(bytes) => bytes,
        Err(error) => panic!("setup-region bytes should serialize: {error}"),
    };
    let mut temp = temp_region_file();
    if let Err(error) = temp.set_len(layout.region_size) {
        panic!("failed to size temporary setup region: {error}");
    }
    if let Err(error) = temp.write_all(&bytes) {
        panic!("failed to write temporary setup region: {error}");
    }
    match mmap_setup_region(temp.as_fd(), layout.region_size) {
        Ok(mapped) => mapped,
        Err(error) => panic!("setup region mmap should succeed: {error}"),
    }
}
