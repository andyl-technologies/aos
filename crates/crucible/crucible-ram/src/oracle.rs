//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Independently recomputes canonical RAM roots from every logical byte.
//!
//! This qualification path intentionally does not use production digest helpers,
//! persistent tree construction, cached pages, changed-page selection, or dirty
//! epochs. It streams pages through one 4096-byte buffer and reduces the complete
//! tree recursively. Callers must provide an independently coherent byte reader.

use crate::{
    RamError, RamRootDigest, RegionClass, RegionDescriptor, RegionTreeDigest, Scope, Topology,
};

/// Recomputes a named scope from a complete coherent logical byte reader.
///
/// `read` must fill the entire supplied valid-length buffer for the requested
/// region/page, or return an error. Residency and dirty metadata cannot decide
/// which pages it reads. `max_pages` bounds work before the first read.
///
/// # Errors
///
/// Returns [`RamError`] for excessive work, overflow, or reader failures.
pub fn recompute(
    topology: &Topology,
    scope: Scope,
    max_pages: u64,
    mut read: impl FnMut(&RegionDescriptor, u64, &mut [u8]) -> Result<(), RamError>,
) -> Result<RamRootDigest, RamError> {
    let mut total = 0_u64;
    let mut selected = 0_u32;
    for region in topology.regions() {
        if includes(scope, region.class()) {
            total = total
                .checked_add(page_count(region.logical_length()))
                .ok_or(RamError::Overflow)?;
            selected += 1;
        }
    }
    if total > max_pages {
        return Err(RamError::ResourceLimit);
    }

    let mut topology_hash = hash(b"crucible.ram.topology.v1\0");
    topology_hash.update(&4096_u32.to_be_bytes());
    topology_hash.update(&(topology.regions().len() as u32).to_be_bytes());
    for region in topology.regions() {
        descriptor(&mut topology_hash, region);
    }

    let mut root = hash(b"crucible.ram.root.v1\0");
    root.update(&1_u32.to_be_bytes());
    root.update(&4096_u32.to_be_bytes());
    let scope_bytes: &[u8] = match scope {
        Scope::Execution => b"execution",
        Scope::Exact => b"exact",
        Scope::Lifecycle => b"lifecycle",
    };
    root.update(&(scope_bytes.len() as u32).to_be_bytes());
    root.update(scope_bytes);
    root.update(topology_hash.finalize().as_bytes());
    root.update(&selected.to_be_bytes());
    for region in topology.regions() {
        if includes(scope, region.class()) {
            descriptor(&mut root, region);
            root.update(recompute_region(region, max_pages, &mut read)?.as_bytes());
        }
    }
    Ok(RamRootDigest::from_bytes(*root.finalize().as_bytes()))
}

/// Recomputes every page and padding node of one region independently.
///
/// # Errors
///
/// Returns [`RamError`] for work-limit excess, overflow, or reader failures.
pub fn recompute_region(
    region: &RegionDescriptor,
    max_pages: u64,
    mut read: impl FnMut(&RegionDescriptor, u64, &mut [u8]) -> Result<(), RamError>,
) -> Result<RegionTreeDigest, RamError> {
    let count = page_count(region.logical_length());
    if count > max_pages {
        return Err(RamError::ResourceLimit);
    }
    let width = count
        .checked_next_power_of_two()
        .ok_or(RamError::Overflow)?;
    let height = width.trailing_zeros();
    let mut buffer = [0_u8; 4096];
    let node = reduce(region, 0, height, count, &mut buffer, &mut read)?;
    let mut wrapper = hash(b"crucible.ram.region-tree.v1\0");
    wrapper.update(&region.logical_length().to_be_bytes());
    wrapper.update(&count.to_be_bytes());
    wrapper.update(&height.to_be_bytes());
    wrapper.update(&node);
    Ok(RegionTreeDigest::from_bytes(*wrapper.finalize().as_bytes()))
}

fn page_count(length: u64) -> u64 {
    length / 4096 + u64::from(!length.is_multiple_of(4096))
}

fn includes(scope: Scope, class: RegionClass) -> bool {
    match scope {
        Scope::Execution => matches!(class, RegionClass::MutableMain | RegionClass::MutableDevice),
        Scope::Exact | Scope::Lifecycle => true,
    }
}

fn descriptor(hasher: &mut blake3::Hasher, region: &RegionDescriptor) {
    hasher.update(&(region.id().len() as u32).to_be_bytes());
    hasher.update(region.id().as_bytes());
    let (class, mask) = match region.class() {
        RegionClass::MutableMain => (1, 7),
        RegionClass::MutableDevice => (2, 7),
        RegionClass::ImmutableImage => (3, 6),
        RegionClass::ContinuationPrivate => (4, 6),
    };
    hasher.update(&[class, mask]);
    hasher.update(&region.logical_length().to_be_bytes());
}

fn hash(tag: &[u8]) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    hasher
}

fn reduce(
    region: &RegionDescriptor,
    start: u64,
    height: u32,
    count: u64,
    buffer: &mut [u8; 4096],
    read: &mut impl FnMut(&RegionDescriptor, u64, &mut [u8]) -> Result<(), RamError>,
) -> Result<[u8; 32], RamError> {
    if height == 0 {
        if start >= count {
            return Ok(*hash(b"crucible.ram.empty.v1\0").finalize().as_bytes());
        }
        let offset = start.checked_mul(4096).ok_or(RamError::Overflow)?;
        let length = (region.logical_length() - offset).min(4096) as usize;
        read(region, start, &mut buffer[..length])?;
        let mut page = hash(b"crucible.ram.page.v1\0");
        page.update(&(length as u32).to_be_bytes());
        page.update(&buffer[..length]);
        let mut leaf = hash(b"crucible.ram.leaf.v1\0");
        leaf.update(page.finalize().as_bytes());
        return Ok(*leaf.finalize().as_bytes());
    }
    let half = 1_u64 << (height - 1);
    let left = reduce(region, start, height - 1, count, buffer, read)?;
    let right = reduce(region, start + half, height - 1, count, buffer, read)?;
    let mut parent = hash(b"crucible.ram.node.v1\0");
    parent.update(&height.to_be_bytes());
    parent.update(&left);
    parent.update(&right);
    Ok(*parent.finalize().as_bytes())
}
