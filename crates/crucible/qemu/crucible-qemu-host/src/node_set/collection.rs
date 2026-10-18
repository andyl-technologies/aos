//! Construction and bounded collection diagnostics for a QEMU node set.

use std::collections::BTreeMap;

use super::{QemuHostParallelismEvidence, QemuNodeSet};

impl QemuNodeSet {
    /// Builds an empty node set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            permanently_closed: Vec::new(),
            fault_event_staging_budget: None,
            pending_selectable_requests: BTreeMap::new(),
            parked_campaign_markers: BTreeMap::new(),
            retained_observable_events: Vec::new(),
            last_host_parallelism: None,
        }
    }

    /// Returns evidence from the latest production host-concurrent round.
    #[must_use]
    pub fn last_host_parallelism(&self) -> Option<&QemuHostParallelismEvidence> {
        self.last_host_parallelism.as_ref()
    }

    /// Returns the number of live nodes in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns whether the set has no live nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl Default for QemuNodeSet {
    fn default() -> Self {
        Self::new()
    }
}
