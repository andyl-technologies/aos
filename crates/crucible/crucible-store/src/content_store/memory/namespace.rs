//! Fixed original namespace custody for the complete standard-library map.
//!
//! The authored object ceiling bounds zero-byte entries and the simultaneous
//! node/split peak. One original loan survives deletion and churn until every
//! node closes; entry bodies and payloads keep their independent callers.

use super::{ContentId, MemoryBody, StoreError, StorePhysicalQuotaBinderHandle};
use crate::owned_decode::ResourceLoan;
use std::alloc::Layout;
use std::ptr::NonNull;

const NODE_KEYS: usize = 11;
const MINIMUM_KEYS: u64 = 5;
const MINIMUM_CHILDREN: u64 = MINIMUM_KEYS + 1;

pub(super) struct Namespace {
    original: StorePhysicalQuotaBinderHandle,
    _credit: ResourceLoan,
}

impl std::fmt::Debug for Namespace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Namespace").finish_non_exhaustive()
    }
}

impl Namespace {
    pub(super) fn admit(
        maximum_objects: u64,
        original: StorePhysicalQuotaBinderHandle,
    ) -> Result<Self, StoreError> {
        let bytes = allocation_bytes(maximum_objects)?;
        original.verify_memory_namespace()?;
        let credit = original.reserve_memory_namespace(bytes)?;
        original.verify_memory_namespace()?;
        Ok(Self {
            original,
            _credit: credit,
        })
    }

    pub(super) fn verify_original(&self) -> Result<(), StoreError> {
        self.original.verify_memory_namespace()
    }
}

// This envelope reproduces the measured pinned Rust1.98.1 node geometry:
// parent pointer, parent index, length, 11 keys/values, then 12 internal edges.
// LeafNode uses Rust layout; InternalNode alone is repr(C). The external
// allocator witness binds real ContentId40/4 and MemoryBody8 requests to
// leaf544/internal640 with 8-byte alignment, rather than a stable layout ABI.
fn node_layouts() -> Result<(u64, u64), StoreError> {
    let extend = |base: Layout, next: Layout| {
        base.extend(next)
            .map(|(layout, _)| layout)
            .map_err(|_| StoreError::Quota)
    };
    let leaf = extend(Layout::new::<Option<NonNull<()>>>(), Layout::new::<u16>())?;
    let leaf = extend(leaf, Layout::new::<u16>())?;
    let leaf = extend(
        leaf,
        Layout::array::<ContentId>(NODE_KEYS).map_err(|_| StoreError::Quota)?,
    )?;
    let leaf = extend(
        leaf,
        Layout::array::<MemoryBody>(NODE_KEYS).map_err(|_| StoreError::Quota)?,
    )?
    .pad_to_align();
    let internal = extend(
        leaf,
        Layout::array::<NonNull<()>>(NODE_KEYS + 1).map_err(|_| StoreError::Quota)?,
    )?
    .pad_to_align();
    Ok((
        u64::try_from(leaf.size()).map_err(|_| StoreError::Quota)?,
        u64::try_from(internal.size()).map_err(|_| StoreError::Quota)?,
    ))
}

pub(super) fn allocation_bytes(maximum_objects: u64) -> Result<u64, StoreError> {
    if maximum_objects == 0 {
        return Err(StoreError::Quota);
    }
    let (leaf, internal) = node_layouts()?;
    // A fresh map with this hard ceiling can never perform its first split.
    if maximum_objects <= NODE_KEYS as u64 {
        return Ok(leaf);
    }

    // At n=M-1 before insertion, root-internal occupancy gives n>=6L-1;
    // child-degree accounting gives I<=floor((L+3)/5). Root-leaf is included
    // by L>=1. Height h requires n>=2*6^h-1. These are conservative bounds,
    // including arbitrary deletion/churn; they are not per-insertion loans.
    let leaves = (maximum_objects / MINIMUM_CHILDREN).max(1);
    let internals = leaves
        .checked_add(MINIMUM_KEYS - 2)
        .ok_or(StoreError::Quota)?
        / MINIMUM_KEYS;
    let mut height = 0u64;
    let mut occupied = maximum_objects / 2;
    while occupied >= MINIMUM_CHILDREN {
        occupied /= MINIMUM_CHILDREN;
        height = height.checked_add(1).ok_or(StoreError::Quota)?;
    }

    // insert_recursing allocates at most one right node per level and one
    // new internal root. Cover these transient allocations before any split.
    let leaves = leaves.checked_add(1).ok_or(StoreError::Quota)?;
    let internals = internals
        .checked_add(height)
        .and_then(|nodes| nodes.checked_add(1))
        .ok_or(StoreError::Quota)?;
    leaves
        .checked_mul(leaf)
        .and_then(|bytes| internals.checked_mul(internal)?.checked_add(bytes))
        .ok_or(StoreError::Quota)
}
