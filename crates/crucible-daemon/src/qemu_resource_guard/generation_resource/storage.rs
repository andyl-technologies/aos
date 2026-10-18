//! Selected-node storage paid before a QEMU generation owner is constructed.
//!
//! Each selected node retains its copied identity, one monotonic generation
//! fence, and exactly two live cells. Registration never grows this storage.

use super::*;
use std::sync::Weak;

/// Prevalidated, finite storage for the exact selected node set.
///
/// The containing caller must admit the measured body before preparing it.
/// This storage carries identities and capacity, not resource authority.
#[derive(Debug)]
pub struct QemuAttemptGenerationStorage {
    pub(super) generations: Arc<Mutex<QemuAttemptGenerationState>>,
}

/// Selects the same existing registry allocation without retaining a guard.
///
/// This Weak identity binds storage reuse to its original containing Source;
/// it neither issues a generation lease nor authenticates native authority.
#[derive(Clone)]
pub(crate) struct QemuGenerationStorageSelection {
    generations: Weak<Mutex<QemuAttemptGenerationState>>,
}

impl QemuGenerationStorageSelection {
    /// Compares immutable selected identities without entering any operation.
    pub(crate) fn matches_nodes<'a>(&self, nodes: impl Iterator<Item = &'a NodeId>) -> bool {
        let Some(generations) = self.generations.upgrade() else {
            return false;
        };
        let Ok(state) = generations.try_lock() else {
            return false;
        };
        state.nodes.iter().map(|row| &row.node).eq(nodes)
    }

    /// Compares existing allocations; identity alone grants no resource use.
    pub(crate) fn same_selection(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.generations, &other.generations)
    }

    pub(super) fn matches(&self, generations: &Arc<Mutex<QemuAttemptGenerationState>>) -> bool {
        Weak::ptr_eq(&self.generations, &Arc::downgrade(generations))
    }
}

impl QemuAttemptGenerationStorage {
    /// Copies only the exact already-paid registry's nonowning selection.
    pub(crate) fn selection(&self) -> QemuGenerationStorageSelection {
        QemuGenerationStorageSelection {
            generations: Arc::downgrade(&self.generations),
        }
    }

    /// Lends only an alias of this existing prepaid registry body.
    pub(crate) fn lend_existing(&self) -> Self {
        Self {
            generations: Arc::clone(&self.generations),
        }
    }

    /// Resets local metadata only after its containing native loans returned.
    ///
    /// The caller separately proves exact physical return. Unique access proves
    /// only that no Loop or generation lease can still use these local rows.
    pub(crate) fn reset_after_target_return(&mut self) -> bool {
        let Some(state) = self.returned_target_state() else {
            return false;
        };
        for row in &mut state.nodes {
            row.latest = None;
        }
        true
    }

    /// Checks actual unique, empty metadata before terminal history disposal.
    ///
    /// This does not attest native return. Its caller separately requires every
    /// genuine Target loan's journal and actual Loop/contract alias destruction.
    pub(crate) fn can_reset_after_target_return(&mut self) -> bool {
        self.returned_target_state().is_some()
    }

    fn returned_target_state(&mut self) -> Option<&mut QemuAttemptGenerationState> {
        let state = Arc::get_mut(&mut self.generations)?.get_mut().ok()?;
        if state.abandoned
            || state
                .nodes
                .iter()
                .any(|row| row.active.iter().any(Option::is_some))
        {
            return None;
        }
        Some(state)
    }

    /// Checks exact selected identities without issuing a lease or changing rows.
    pub(crate) fn matches_nodes<'a>(
        &self,
        nodes: impl Iterator<Item = &'a NodeId>,
    ) -> Result<bool, LifecycleApiError> {
        let selected = self
            .generations
            .lock()
            .map_err(|_| generation_error("selected Source registry is poisoned"))?;
        Ok(nodes.eq(selected.nodes.iter().map(|row| &row.node)))
    }

    /// Measures the selected registry without allocating or consuming a guard.
    ///
    /// Includes the actual shared body, row payload and copied node-name bytes.
    /// Payload capacities are requested explicitly; allocator metadata follows
    /// the containing Main owner's allocation conventions.
    ///
    /// # Errors
    /// Refuses empty, excessive, duplicate or noncanonical node selections and
    /// layout or byte arithmetic overflow. Nodes must be in increasing order.
    pub fn control_bytes<'a>(
        nodes: impl Iterator<Item = &'a NodeId>,
    ) -> Result<u64, LifecycleApiError> {
        Self::layout(nodes).map(|(_, _, bytes)| bytes)
    }

    /// Allocates the selected body before any owned resource guard is moved.
    ///
    /// The caller must retain its authentic prebirth containing-body payment
    /// before this operation; a size measurement alone grants no allocation.
    ///
    /// # Errors
    /// Refuses invalid selection or storage reservation failure. No guard is
    /// accepted, quarantined or dropped on these pure construction failures.
    pub fn prepare<'a>(
        nodes: impl Clone + Iterator<Item = &'a NodeId>,
    ) -> Result<Self, LifecycleApiError> {
        let (count, mut remaining_names, _) = Self::layout(nodes.clone())?;
        let mut rows: Vec<GenerationNodeState> = Vec::new();
        rows.try_reserve_exact(count)
            .map_err(|source| generation_error(format!("reserve generation rows: {source}")))?;
        for node in nodes {
            if rows.len() >= count || rows.last().is_some_and(|row| row.node >= *node) {
                return Err(generation_error(
                    "generation selection changed during preparation",
                ));
            }
            remaining_names = remaining_names
                .checked_sub(node.name.len())
                .ok_or_else(|| {
                    generation_error("generation identity extent changed during preparation")
                })?;
            let mut name = String::new();
            name.try_reserve_exact(node.name.len()).map_err(|source| {
                generation_error(format!("reserve generation identity: {source}"))
            })?;
            name.push_str(&node.name);
            rows.push(GenerationNodeState {
                node: NodeId { name },
                latest: None,
                active: [None; MAX_QEMU_ATTEMPT_GENERATIONS_PER_NODE],
            });
        }
        if rows.len() != count || remaining_names != 0 {
            return Err(generation_error(
                "generation selection extent changed during preparation",
            ));
        }
        Ok(Self {
            generations: Arc::new(Mutex::new(QemuAttemptGenerationState {
                nodes: rows,
                abandoned: false,
            })),
        })
    }

    fn layout<'a>(
        nodes: impl Iterator<Item = &'a NodeId>,
    ) -> Result<(usize, usize, u64), LifecycleApiError> {
        let mut count = 0_usize;
        let mut names = 0_usize;
        let mut previous = None;
        for node in nodes {
            if previous.is_some_and(|previous: &NodeId| previous >= node) {
                return Err(generation_error(
                    "generation nodes are duplicated or out of order",
                ));
            }
            previous = Some(node);
            count = count
                .checked_add(1)
                .filter(|count| *count <= MAX_QEMU_ATTEMPT_GENERATION_NODES)
                .ok_or_else(|| generation_error("generation node bound is exhausted"))?;
            names = names
                .checked_add(node.name.len())
                .ok_or_else(|| generation_error("generation identity extent overflows"))?;
        }
        if count == 0 {
            return Err(generation_error("generation node selection is empty"));
        }
        let rows = std::alloc::Layout::array::<GenerationNodeState>(count)
            .map_err(|_| generation_error("generation row layout overflows"))?;
        let (shared, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<Mutex<QemuAttemptGenerationState>>())
        .map_err(|_| generation_error("generation shared layout overflows"))?;
        let bytes = shared
            .pad_to_align()
            .size()
            .checked_add(rows.size())
            .and_then(|bytes| bytes.checked_add(names))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| generation_error("generation storage extent overflows"))?;
        Ok((count, names, bytes))
    }
}

#[derive(Debug)]
pub(super) struct GenerationNodeState {
    pub(super) node: NodeId,
    pub(super) latest: Option<u64>,
    pub(super) active: [Option<u64>; MAX_QEMU_ATTEMPT_GENERATIONS_PER_NODE],
}

#[cfg(test)]
mod tests;
