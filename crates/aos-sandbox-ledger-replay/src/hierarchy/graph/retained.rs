//! Owns reached graph construction and validation DATA on normal errors.
//!
//! Every predicate remains in the parent shared engine. Guards move actual
//! containers into pre-existing fields without cloning or allocating on Drop.
//! Successful ancestry paths dispose only after their complete depth transfer.

use super::*;
pub(in crate::hierarchy) use aos_sandbox_core::bounded_codec::{CaptureOnDropV1, RetainingIterV1};

#[derive(Default)]
pub(super) struct GraphWalkOriginalsV1 {
    pub(super) cursor: Option<SandboxId>,
    pub(super) known_parent_depth: Option<usize>,
    pub(super) next_depth: Option<usize>,
    pub(super) active_depth: Option<usize>,
    pub(super) active_descendant: Option<(usize, SandboxId)>,
}

#[derive(Default)]
pub(super) struct GraphValidationOriginalsV1 {
    pub(super) live_incarnations: Option<BTreeSet<IncarnationId>>,
    pub(super) child_counts: Option<BTreeMap<SandboxId, usize>>,
    pub(super) depths: Option<BTreeMap<SandboxId, usize>>,
    pub(super) path_set: Option<BTreeSet<SandboxId>>,
    pub(super) path: Option<Vec<SandboxId>>,
    pub(super) descendants: Option<BTreeMap<SandboxId, usize>>,
    pub(super) live_descendants: Option<BTreeMap<SandboxId, usize>>,
    pub(super) deepest_first: Option<Vec<(usize, SandboxId)>>,
    pub(super) walk: GraphWalkOriginalsV1,
    pub(super) outcome: Option<Result<(), SandboxTreeError>>,
}

#[derive(Default)]
pub(in crate::hierarchy) struct TreeBuildOriginalsV1 {
    pub(super) records_input: Option<Vec<SandboxTreeRecordV1>>,
    pub(super) tombstones_input: Option<Vec<SandboxId>>,
    pub(super) records: Option<BTreeMap<SandboxId, SandboxTreeRecordV1>>,
    pub(super) tombstones: Option<BTreeSet<SandboxId>>,
    pub(super) validation: GraphValidationOriginalsV1,
    pub(super) outcome: Option<Result<(), SandboxTreeError>>,
}

impl TreeBuildOriginalsV1 {
    pub(in crate::hierarchy) fn failure(&self) -> Option<&SandboxTreeError> {
        self.validation.outcome.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.outcome.as_ref().and_then(|result| result.as_ref().err()))
    }

    pub(in crate::hierarchy) fn construction_bytes_v1() -> Option<usize> {
        // These are actual distinct stack/return guards, not model maxima.
        let guards = std::mem::size_of::<CaptureOnDropV1<'static, Vec<SandboxTreeRecordV1>>>()
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, Vec<SandboxId>>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, BTreeMap<SandboxId, SandboxTreeRecordV1>>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, BTreeSet<SandboxId>>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, BTreeSet<IncarnationId>>>())?
            .checked_add(4 * std::mem::size_of::<CaptureOnDropV1<'static, BTreeMap<SandboxId, usize>>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, BTreeSet<SandboxId>>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, Vec<SandboxId>>>())?
            .checked_add(std::mem::size_of::<CaptureOnDropV1<'static, Vec<(usize, SandboxId)>>>())?
            .checked_add(std::mem::size_of::<RetainingIterV1<'static, SandboxId>>())?
            .checked_add(std::mem::size_of::<RetainingIterV1<'static, (usize, SandboxId)>>())?;
        std::mem::size_of::<Self>().checked_add(guards)
    }

    /// Bounds keyed graph entries and the sorted descendant identity index.
    pub(in crate::hierarchy) fn named_entries_v2(
        records: usize,
        tombstones: usize,
    ) -> Option<usize> {
        // Record map, live-incarnation set, child counts, depths, ancestry set,
        // descendants and live descendants each contain at most one per record.
        // The deepest-first identity index is a distinct eighth named plane.
        // Raw input/growth buffers and ancestry cursor scratch are Memory only.
        records.checked_mul(8)?.checked_add(tombstones)
    }

    pub(in crate::hierarchy) fn dynamic_footprint_v1(
        records: usize,
        tombstones: usize,
    ) -> Option<(usize, usize)> {
        fn tree_nodes<T>(count: usize) -> Option<usize> {
            // A full eleven-element node and twelve links per reached element
            // dominate B-tree occupancy without an amortized fill assumption.
            let node = 11usize.checked_mul(std::mem::size_of::<T>())?
                .checked_add(12usize.checked_mul(std::mem::size_of::<usize>())?)?;
            count.checked_mul(node)
        }
        let record_nodes = tree_nodes::<(SandboxId, SandboxTreeRecordV1)>(records)?;
        let tombstone_nodes = tree_nodes::<SandboxId>(tombstones)?;
        let live_nodes = tree_nodes::<IncarnationId>(records)?;
        // Child counts, depths, descendants and live descendants are separate.
        let count_nodes = tree_nodes::<(SandboxId, usize)>(records)?.checked_mul(4)?;
        let path_set = tree_nodes::<SandboxId>(records)?;
        // Raw decoded inputs, active ancestry path and sorted depth work have
        // their own Vec live/growth/reallocation backing at actual cardinality.
        let vectors = records.checked_add(4)?.checked_mul(std::mem::size_of::<SandboxTreeRecordV1>())?
            .checked_add(tombstones.checked_add(4)?.checked_mul(std::mem::size_of::<SandboxId>())?)?
            .checked_add(records.checked_add(4)?.checked_mul(std::mem::size_of::<SandboxId>())?)?
            .checked_add(records.checked_add(4)?.checked_mul(std::mem::size_of::<(usize, SandboxId)>())?)?
            // B-tree FromIterator may use an intermediate sort/bulk-build Vec.
            // These are separate from decoded inputs and final tree nodes.
            .checked_add(records.checked_add(4)?.checked_mul(std::mem::size_of::<(SandboxId, SandboxTreeRecordV1)>())?)?
            .checked_add(tombstones.checked_add(4)?.checked_mul(std::mem::size_of::<SandboxId>())?)?
            .checked_mul(3)?;
        let memory = record_nodes.checked_add(tombstone_nodes)?.checked_add(live_nodes)?
            .checked_add(count_nodes)?.checked_add(path_set)?.checked_add(vectors)?;
        // Seven per-record tree planes, one tombstone plane and six Vec backs.
        let cells = records.checked_mul(7)?.checked_add(tombstones)?.checked_add(6)?;
        Some((memory, cells))
    }
}

#[cfg(test)]
impl TreeBuildOriginalsV1 {
    pub(in crate::hierarchy) fn retained_path_v1(&self) -> Option<&[SandboxId]> {
        self.validation.path.as_deref()
    }

    pub(in crate::hierarchy) fn retained_descendant_work_v1(&self) -> Option<&[(usize, SandboxId)]> {
        self.validation.deepest_first.as_deref()
    }

    pub(in crate::hierarchy) fn retained_depth_count_v1(&self) -> usize {
        self.validation.depths.as_ref().map_or(0, BTreeMap::len)
    }

    pub(in crate::hierarchy) fn retained_tombstone_input_v1(&self) -> Option<&[SandboxId]> {
        self.tombstones_input.as_deref()
    }
}
