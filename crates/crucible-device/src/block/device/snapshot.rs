//! Block-device checkpoint snapshot representation.

use std::collections::{BTreeMap, BTreeSet};

use crate::fault::IoFaults;
use crate::inflight::PendingResponse;
use crate::subnode::IoCoreSnapshot;

use super::super::overlay::{OverlayDelta, PAGE_SIZE};
use super::BlockLatency;

/// The device half of a block sub-node's `MaterializedState` ([IO-11], [IO-23]).
///
/// Holds the overlay delta (dirty pages only), a full-overlay page set for
/// self-contained restore, the dirty page set (so a mid-epoch restore preserves
/// the next checkpoint's delta, [IO-7]), the latency model (part of the `World`,
/// [IO-10]), the device RNG cursor, the active fault table, the in-flight responses
/// (inside `core`), the base hash, and the device length. It **never** holds the
/// base image bytes ([TEMP-9]); restore re-supplies the content-addressed base
/// and verifies its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockSnapshot {
    /// The uniform-core snapshot: clock, rings, in-flight responses.
    pub core: IoCoreSnapshot,
    /// The BLAKE3 content hash of the (omitted) base image, for restore checks.
    pub base_hash: [u8; 32],
    /// The device length in bytes (the base image size).
    pub device_length: u64,
    /// The overlay delta: only pages dirtied since the last checkpoint boundary.
    pub overlay_delta: OverlayDelta,
    /// The full overlay page set, for parent-free self-contained restore.
    pub full_pages: BTreeMap<u64, [u8; PAGE_SIZE]>,
    /// The dirty page set at snapshot time.
    pub dirty: BTreeSet<u64>,
    /// The deterministic latency model parameters.
    pub latency: BlockLatency,
    /// The active I/O fault table.
    pub faults: IoFaults,
    /// The per-device RNG stream cursor.
    pub rng_position: u64,
}

impl BlockSnapshot {
    /// Returns the number of pages in the captured delta.
    #[must_use]
    pub fn delta_page_count(&self) -> usize {
        self.overlay_delta.pages.len()
    }

    /// Returns the in-flight responses captured in the snapshot.
    #[must_use]
    pub fn inflight(&self) -> &[PendingResponse] {
        &self.core.inflight
    }
}
