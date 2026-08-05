//! Serial heap-allocation accounting for the demand-region shadow probe.
//!
//! The probe takes a fence immediately before requested-attribute evaluation
//! and scans the serial stores at demand completion. It reports both the exact
//! bump distance consumed by evaluator arenas and requested object sizes by
//! runtime kind. Requested sizes exclude allocator padding; list spines remain
//! out-of-arena and are therefore reported separately.

use super::*;

/// One count-and-requested-byte allocation tally.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DemandRegionKindBytes {
    /// Number of allocations in the fenced suffix.
    pub(crate) count: u64,
    /// Requested inline allocation bytes, excluding allocator padding.
    pub(crate) requested_bytes: u64,
}

impl DemandRegionKindBytes {
    fn add(&mut self, bytes: usize) {
        self.count = self.count.saturating_add(1);
        self.requested_bytes = self.requested_bytes.saturating_add(bytes as u64);
    }
}

/// A non-rooting serial heap position captured at demand-epoch entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DemandRegionAllocationFence {
    pub(crate) records: usize,
    pub(crate) strings_and_paths: usize,
    pub(crate) lists: usize,
    pub(crate) attrs: usize,
    pub(crate) closures: usize,
    pub(crate) typed_thunks: usize,
    pub(crate) boxed_scalars: usize,
    pub(crate) worker_used_bytes: usize,
    pub(crate) permanent_used_bytes: usize,
}

/// Allocation-byte census for one requested-attribute demand epoch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DemandRegionAllocationCensus {
    /// Whether every serial store retained the fenced prefix.
    pub(crate) fence_valid: bool,
    /// Exact bump distance consumed in the worker arena.
    pub(crate) worker_arena_used_bytes: u64,
    /// Exact bump distance consumed in the permanent arena.
    pub(crate) permanent_arena_used_bytes: u64,
    /// Thunk/Promise records, including headerless typed thunk heads.
    pub(crate) promises: DemandRegionKindBytes,
    /// User-lambda closure records.
    pub(crate) closures: DemandRegionKindBytes,
    /// Partially applied builtin records.
    pub(crate) primops: DemandRegionKindBytes,
    /// List object records, excluding their moved `Vec` spines.
    pub(crate) lists: DemandRegionKindBytes,
    /// Attribute-set object records.
    pub(crate) attrs: DemandRegionKindBytes,
    /// String and path records.
    pub(crate) strings_and_paths: DemandRegionKindBytes,
    /// Any serial record with a tag outside the preceding classes.
    pub(crate) other: DemandRegionKindBytes,
    /// Exact retained capacity of moved list spines.
    pub(crate) list_spine_bytes: u64,
    /// Boxed scalar payload cells outside the evaluator arenas.
    pub(crate) boxed_scalar_payload_bytes: u64,
}

impl DemandRegionAllocationCensus {
    /// Returns exact evaluator-arena bump consumption.
    pub(crate) const fn arena_used_bytes(self) -> u64 {
        self.worker_arena_used_bytes
            .saturating_add(self.permanent_arena_used_bytes)
    }

    /// Returns requested inline bytes classified by runtime kind.
    pub(crate) const fn requested_inline_bytes(self) -> u64 {
        self.promises
            .requested_bytes
            .saturating_add(self.closures.requested_bytes)
            .saturating_add(self.primops.requested_bytes)
            .saturating_add(self.lists.requested_bytes)
            .saturating_add(self.attrs.requested_bytes)
            .saturating_add(self.strings_and_paths.requested_bytes)
            .saturating_add(self.other.requested_bytes)
    }

    /// Returns known out-of-arena payload bytes.
    pub(crate) const fn known_external_bytes(self) -> u64 {
        self.list_spine_bytes
            .saturating_add(self.boxed_scalar_payload_bytes)
    }
}

impl EvalHeap {
    /// Captures a serial heap allocation fence without retaining heap values.
    ///
    /// Returns `None` for shared heaps because shard publication has no single
    /// suffix order.
    pub(crate) fn demand_region_allocation_fence(&self) -> Option<DemandRegionAllocationFence> {
        if self.shared.is_some() {
            return None;
        }
        let (boxed_scalars, _) = self.boxed_scalar_census_totals();
        Some(DemandRegionAllocationFence {
            records: self.records.len(),
            strings_and_paths: self.flat.len(),
            lists: self.flat_lists.len(),
            attrs: self.flat_attrs.len(),
            closures: self.flat_closures.len(),
            typed_thunks: self.typed_thunk_heads.len(),
            boxed_scalars,
            worker_used_bytes: self.arena_stats().used_bytes,
            permanent_used_bytes: self.permanent_arena_stats().used_bytes,
        })
    }

    /// Classifies allocations made after `fence` without retaining heap roots.
    pub(crate) fn demand_region_allocation_census(
        &self,
        fence: DemandRegionAllocationFence,
    ) -> DemandRegionAllocationCensus {
        let (boxed_scalars, _) = self.boxed_scalar_census_totals();
        let worker = self.arena_stats();
        let permanent = self.permanent_arena_stats();
        let fence_valid = fence.records <= self.records.len()
            && fence.strings_and_paths <= self.flat.len()
            && fence.lists <= self.flat_lists.len()
            && fence.attrs <= self.flat_attrs.len()
            && fence.closures <= self.flat_closures.len()
            && fence.typed_thunks <= self.typed_thunk_heads.len()
            && fence.boxed_scalars <= boxed_scalars
            && fence.worker_used_bytes <= worker.used_bytes
            && fence.permanent_used_bytes <= permanent.used_bytes;
        let mut census = DemandRegionAllocationCensus {
            fence_valid,
            worker_arena_used_bytes: worker.used_bytes.saturating_sub(fence.worker_used_bytes)
                as u64,
            permanent_arena_used_bytes: permanent
                .used_bytes
                .saturating_sub(fence.permanent_used_bytes)
                as u64,
            boxed_scalar_payload_bytes: boxed_scalars
                .saturating_sub(fence.boxed_scalars)
                .saturating_mul(std::mem::size_of::<u64>())
                as u64,
            ..DemandRegionAllocationCensus::default()
        };
        if !fence_valid {
            return census;
        }

        for record in self.records.iter().skip(fence.records) {
            if record.is_retired() {
                continue;
            }
            add_tagged(&mut census, record.object.tag(), record.layout.size_bytes);
        }
        for object in self.flat.iter().skip(fence.strings_and_paths) {
            census.strings_and_paths.add(object.size_bytes());
        }
        for object in self.flat_lists.iter().skip(fence.lists) {
            census.lists.add(object.size_bytes());
            census.list_spine_bytes = census.list_spine_bytes.saturating_add(
                object
                    .object()
                    .payload()
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Value>()) as u64,
            );
        }
        for object in self.flat_attrs.iter().skip(fence.attrs) {
            census.attrs.add(object.size_bytes());
        }
        for object in self.flat_closures.iter().skip(fence.closures) {
            let payload = object.object().payload();
            if !payload.is_retired() {
                add_tagged(&mut census, payload.tag(), object.size_bytes());
            }
        }
        for (_, bytes) in self
            .typed_thunk_heads
            .initialized_regions()
            .skip(fence.typed_thunks)
        {
            census.promises.add(bytes);
        }
        census
    }
}

fn add_tagged(census: &mut DemandRegionAllocationCensus, tag: ValueTag, bytes: usize) {
    match tag {
        ValueTag::Thunk => census.promises.add(bytes),
        ValueTag::Lambda => census.closures.add(bytes),
        ValueTag::Primop => census.primops.add(bytes),
        ValueTag::List => census.lists.add(bytes),
        ValueTag::Attrs => census.attrs.add(bytes),
        ValueTag::String | ValueTag::Path => census.strings_and_paths.add(bytes),
        _ => census.other.add(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demand_fence_classifies_exact_serial_suffix_bytes() {
        let mut heap = EvalHeap::new();
        let fence = heap
            .demand_region_allocation_fence()
            .expect("serial heap has a fence");
        heap.alloc_list(NixList::new(vec![Value::int(1), Value::int(2)]))
            .expect("list allocates");
        heap.alloc_thunk(EvalThunk::released_forced(Value::int(3)))
            .expect("thunk allocates");

        let census = heap.demand_region_allocation_census(fence);
        assert!(census.fence_valid);
        assert_eq!(census.lists.count, 1);
        assert_eq!(census.promises.count, 1);
        assert_eq!(
            census.list_spine_bytes,
            2 * std::mem::size_of::<Value>() as u64
        );
        assert!(census.arena_used_bytes() >= census.requested_inline_bytes());
    }

    #[test]
    fn demand_fence_does_not_count_preexisting_objects() {
        let mut heap = EvalHeap::new();
        heap.alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("preexisting list allocates");
        let fence = heap
            .demand_region_allocation_fence()
            .expect("serial heap has a fence");

        let census = heap.demand_region_allocation_census(fence);
        assert_eq!(
            census,
            DemandRegionAllocationCensus {
                fence_valid: true,
                ..DemandRegionAllocationCensus::default()
            }
        );
    }
}
