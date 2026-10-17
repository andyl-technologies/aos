//! Selected-node storage paid before a QEMU generation owner is constructed.
//!
//! Each selected node retains its copied identity, one monotonic generation
//! fence, and exactly two live cells. Registration never grows this storage.

use super::*;

/// Prevalidated, finite storage for the exact selected node set.
///
/// The containing caller must admit the measured body before preparing it.
/// This storage carries identities and capacity, not resource authority.
#[derive(Debug)]
pub struct QemuAttemptGenerationStorage {
    pub(super) generations: Arc<Mutex<QemuAttemptGenerationState>>,
}

impl QemuAttemptGenerationStorage {
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
