//! Ready-import-exclusive heap ownership census.
//!
//! This compile-time-only diagnostic partitions one already-complete precise
//! root set into `ImportCache` roots and every other mutator root. It walks both
//! partitions with the ordinary weak-liveness scanner, proves that their union
//! reconciles with an unfiltered scan, and inventories objects reached only
//! from Ready import-cache roots. The returned stable addresses and initial
//! last-touch epochs are the input to a later reuse-window classifier; this
//! module does not retain state across evaluator phases or mutate the heap.

use std::collections::HashSet;

use super::*;
use crate::eval::ThunkState;

/// The storage and semantic class of one Ready-exclusive heap object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadyExclusiveObjectKind {
    /// A legacy record-table object carrying the given runtime tag.
    Record(ValueTag),
    /// A flat string.
    String,
    /// A flat path.
    Path,
    /// A flat list.
    List,
    /// A flat attribute set.
    Attrs,
    /// A suspended flat thunk.
    SuspendedThunk,
    /// A blackholed flat thunk.
    BlackholeThunk,
    /// A forced flat thunk.
    ForcedThunk,
    /// A flat lambda closure.
    Lambda,
    /// A flat builtin or partially applied builtin.
    Primop,
    /// A suspended headerless typed-thunk head.
    SuspendedTypedThunk,
    /// A blackholed headerless typed-thunk head.
    BlackholeTypedThunk,
    /// A forced headerless typed-thunk head.
    ForcedTypedThunk,
    /// A typed-thunk head whose state word could not be classified.
    InvalidTypedThunk,
}

/// One heap object retained exclusively by Ready import-cache roots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadyExclusiveCandidate {
    address: usize,
    kind: ReadyExclusiveObjectKind,
    inline_bytes: u64,
    list_spine_bytes: u64,
    initial_touch_epoch: Option<u64>,
}

impl ReadyExclusiveCandidate {
    /// Returns the object's stable evaluator-heap address.
    pub(crate) const fn address(self) -> usize {
        self.address
    }

    /// Returns the object's storage and semantic class at capture time.
    pub(crate) const fn kind(self) -> ReadyExclusiveObjectKind {
        self.kind
    }

    /// Returns bytes reserved inline with the current heap object.
    pub(crate) const fn inline_bytes(self) -> u64 {
        self.inline_bytes
    }

    /// Returns malloc-backed list-spine bytes retained by this object.
    pub(crate) const fn list_spine_bytes(self) -> u64 {
        self.list_spine_bytes
    }

    /// Returns the last-touch epoch observed at capture, when the storage has one.
    pub(crate) const fn initial_touch_epoch(self) -> Option<u64> {
        self.initial_touch_epoch
    }

    /// Returns the currently attributable bytes retained by this object.
    pub(crate) const fn attributable_bytes(self) -> u64 {
        self.inline_bytes.saturating_add(self.list_spine_bytes)
    }
}

/// A reconciled Ready-import root-ownership census.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadyExclusiveCensus {
    ready_roots: usize,
    other_roots: usize,
    all_reachable_objects: usize,
    ready_reachable_objects: usize,
    other_reachable_objects: usize,
    shared_reachable_objects: usize,
    union_reconciled: bool,
    unclassified_exclusive_objects: usize,
    candidates: Vec<ReadyExclusiveCandidate>,
    inline_bytes: u64,
    list_spine_bytes: u64,
}

impl ReadyExclusiveCensus {
    /// Returns the number of Ready import-cache roots in the supplied root set.
    pub(crate) const fn ready_roots(&self) -> usize {
        self.ready_roots
    }

    /// Returns the number of roots not owned by the import cache.
    pub(crate) const fn other_roots(&self) -> usize {
        self.other_roots
    }

    /// Returns objects reached by the unfiltered root scan.
    pub(crate) const fn all_reachable_objects(&self) -> usize {
        self.all_reachable_objects
    }

    /// Returns objects reached from Ready import-cache roots.
    pub(crate) const fn ready_reachable_objects(&self) -> usize {
        self.ready_reachable_objects
    }

    /// Returns objects reached from every non-import root.
    pub(crate) const fn other_reachable_objects(&self) -> usize {
        self.other_reachable_objects
    }

    /// Returns objects shared by Ready and non-import root closures.
    pub(crate) const fn shared_reachable_objects(&self) -> usize {
        self.shared_reachable_objects
    }

    /// Returns whether partition union exactly equals unfiltered reachability.
    pub(crate) const fn union_reconciled(&self) -> bool {
        self.union_reconciled
    }

    /// Returns exclusive addresses not attributable to an iterable heap store.
    pub(crate) const fn unclassified_exclusive_objects(&self) -> usize {
        self.unclassified_exclusive_objects
    }

    /// Returns Ready-exclusive candidates in ascending address order.
    pub(crate) fn candidates(&self) -> &[ReadyExclusiveCandidate] {
        &self.candidates
    }

    /// Returns current inline bytes across classified exclusive candidates.
    pub(crate) const fn inline_bytes(&self) -> u64 {
        self.inline_bytes
    }

    /// Returns current malloc-backed list-spine bytes across candidates.
    pub(crate) const fn list_spine_bytes(&self) -> u64 {
        self.list_spine_bytes
    }

    /// Returns total currently attributable candidate bytes.
    pub(crate) const fn attributable_bytes(&self) -> u64 {
        self.inline_bytes.saturating_add(self.list_spine_bytes)
    }
}

impl EvalHeap {
    /// Partitions precise roots and inventories Ready-import-exclusive objects.
    ///
    /// Hash-cons tables are not roots. Object graph scans use no touch-stamping
    /// accessors, so capture does not make an otherwise cold candidate appear
    /// reused in a later window.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if any root or transitive edge is malformed,
    /// detached typed-thunk work is not represented by valid source-labelled
    /// roots, a thunk state is invalid, or candidate storage cannot grow.
    pub(crate) fn ready_exclusive_census(
        &self,
        roots: &EvalRootSet,
    ) -> Result<ReadyExclusiveCensus, EvalHeapError> {
        let ready_roots = roots
            .roots()
            .iter()
            .filter(|root| matches!(root.source(), EvalRootSource::ImportCache { .. }))
            .count();
        let other_roots = roots.len().saturating_sub(ready_roots);
        let ready = self.weak_reachable_addresses_matching(roots, |source| {
            matches!(source, EvalRootSource::ImportCache { .. })
        })?;
        let other = self.weak_reachable_addresses_matching(roots, |source| {
            !matches!(source, EvalRootSource::ImportCache { .. })
        })?;
        let all = self.weak_reachable_addresses(roots)?;
        let union_count = ready.union(&other).count();
        let union_reconciled = union_count == all.len()
            && all
                .iter()
                .all(|address| ready.contains(address) || other.contains(address));
        let shared_reachable_objects = ready.intersection(&other).count();
        let mut exclusive = HashSet::new();
        exclusive.try_reserve(ready.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: "Ready-exclusive address set",
                entries: ready.len(),
            }
        })?;
        exclusive.extend(ready.difference(&other).copied());

        let mut candidates = Vec::new();
        candidates.try_reserve_exact(exclusive.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: "Ready-exclusive candidates",
                entries: exclusive.len(),
            }
        })?;

        for record in &self.records {
            if record.is_retired() {
                continue;
            }
            let address = record.ptr.as_ptr() as usize;
            if !exclusive.contains(&address) {
                continue;
            }
            candidates.push(ReadyExclusiveCandidate {
                address,
                kind: ReadyExclusiveObjectKind::Record(record.object.tag()),
                inline_bytes: record.layout.size_bytes as u64,
                list_spine_bytes: 0,
                initial_touch_epoch: Some(record.last_touch_epoch.get()),
            });
        }
        for object in self.flat.iter() {
            let address = object.ptr().as_ptr() as usize;
            if !exclusive.contains(&address) {
                continue;
            }
            let kind = match object.object().kind() {
                FlatObjectKind::String => ReadyExclusiveObjectKind::String,
                FlatObjectKind::Path => ReadyExclusiveObjectKind::Path,
                _ => continue,
            };
            candidates.push(ReadyExclusiveCandidate {
                address,
                kind,
                inline_bytes: object.size_bytes() as u64,
                list_spine_bytes: 0,
                initial_touch_epoch: Some(object.object().last_touch_epoch()),
            });
        }
        for object in self.flat_lists.iter() {
            let address = object.ptr().as_ptr() as usize;
            if !exclusive.contains(&address) {
                continue;
            }
            let list_spine_bytes = object
                .object()
                .payload()
                .capacity()
                .saturating_mul(std::mem::size_of::<Value>())
                as u64;
            candidates.push(ReadyExclusiveCandidate {
                address,
                kind: ReadyExclusiveObjectKind::List,
                inline_bytes: object.size_bytes() as u64,
                list_spine_bytes,
                initial_touch_epoch: Some(object.object().last_touch_epoch()),
            });
        }
        for object in self.flat_attrs.iter() {
            let address = object.ptr().as_ptr() as usize;
            if !exclusive.contains(&address) {
                continue;
            }
            candidates.push(ReadyExclusiveCandidate {
                address,
                kind: ReadyExclusiveObjectKind::Attrs,
                inline_bytes: object.size_bytes() as u64,
                list_spine_bytes: 0,
                initial_touch_epoch: Some(object.object().last_touch_epoch()),
            });
        }
        for object in self.flat_closures.iter() {
            let address = object.ptr().as_ptr() as usize;
            if !exclusive.contains(&address) {
                continue;
            }
            let kind = match object.object().payload() {
                FlatClosurePayload::Thunk(thunk) => {
                    ready_exclusive_thunk_kind(thunk.cell().state()?)
                }
                FlatClosurePayload::SharedThunk(thunk) => {
                    ready_exclusive_thunk_kind(thunk.cell().state()?)
                }
                FlatClosurePayload::Lambda(_) => ReadyExclusiveObjectKind::Lambda,
                FlatClosurePayload::Primop(_) => ReadyExclusiveObjectKind::Primop,
                FlatClosurePayload::Retired(_) => continue,
            };
            candidates.push(ReadyExclusiveCandidate {
                address,
                kind,
                inline_bytes: object.size_bytes() as u64,
                list_spine_bytes: 0,
                initial_touch_epoch: Some(object.object().last_touch_epoch()),
            });
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            if !exclusive.contains(&address) {
                continue;
            }
            let kind = match NonNull::new(address as *mut HeapObject)
                .and_then(|ptr| self.typed_thunk_heads.resolve(ptr).ok())
                .and_then(StableThunkHead::state)
            {
                Some(ThunkState::Suspended) => ReadyExclusiveObjectKind::SuspendedTypedThunk,
                Some(ThunkState::Blackhole) => ReadyExclusiveObjectKind::BlackholeTypedThunk,
                Some(ThunkState::Forced) => ReadyExclusiveObjectKind::ForcedTypedThunk,
                None => ReadyExclusiveObjectKind::InvalidTypedThunk,
            };
            candidates.push(ReadyExclusiveCandidate {
                address,
                kind,
                inline_bytes: bytes as u64,
                list_spine_bytes: 0,
                initial_touch_epoch: None,
            });
        }

        candidates.sort_unstable_by_key(|candidate| candidate.address);
        let inline_bytes = candidates.iter().fold(0_u64, |total, candidate| {
            total.saturating_add(candidate.inline_bytes)
        });
        let list_spine_bytes = candidates.iter().fold(0_u64, |total, candidate| {
            total.saturating_add(candidate.list_spine_bytes)
        });
        let unclassified_exclusive_objects = exclusive.len().saturating_sub(candidates.len());
        Ok(ReadyExclusiveCensus {
            ready_roots,
            other_roots,
            all_reachable_objects: all.len(),
            ready_reachable_objects: ready.len(),
            other_reachable_objects: other.len(),
            shared_reachable_objects,
            union_reconciled,
            unclassified_exclusive_objects,
            candidates,
            inline_bytes,
            list_spine_bytes,
        })
    }

    /// Reads a captured candidate's current last-touch epoch without stamping it.
    ///
    /// Returns `None` for headerless typed-thunk heads, which intentionally
    /// carry no generic flat-object epoch, and for an address that no longer
    /// names the captured storage class. A later phase-window classifier must
    /// treat either case as unattributed rather than cold.
    pub(crate) fn ready_exclusive_candidate_touch_epoch(
        &self,
        candidate: ReadyExclusiveCandidate,
    ) -> Option<u64> {
        let ptr = NonNull::new(candidate.address() as *mut HeapObject)?;
        match candidate.kind() {
            ReadyExclusiveObjectKind::Record(tag) => self
                .records
                .iter()
                .find(|record| {
                    !record.is_retired() && record.ptr == ptr && record.object.tag() == tag
                })
                .map(|record| record.last_touch_epoch.get()),
            ReadyExclusiveObjectKind::String => self
                .flat
                .resolve(ptr, FlatObjectKind::String)
                .ok()
                .map(|object| object.last_touch_epoch()),
            ReadyExclusiveObjectKind::Path => self
                .flat
                .resolve(ptr, FlatObjectKind::Path)
                .ok()
                .map(|object| object.last_touch_epoch()),
            ReadyExclusiveObjectKind::List => self
                .flat_lists
                .resolve(ptr, FlatObjectKind::List)
                .ok()
                .map(|object| object.last_touch_epoch()),
            ReadyExclusiveObjectKind::Attrs => self
                .flat_attrs
                .resolve(ptr, FlatObjectKind::Attrs)
                .ok()
                .map(|object| object.last_touch_epoch()),
            ReadyExclusiveObjectKind::SuspendedThunk
            | ReadyExclusiveObjectKind::BlackholeThunk
            | ReadyExclusiveObjectKind::ForcedThunk => self
                .flat_closures
                .resolve(ptr, FlatObjectKind::Thunk)
                .ok()
                .map(|object| object.last_touch_epoch()),
            ReadyExclusiveObjectKind::Lambda => self
                .flat_closures
                .resolve(ptr, FlatObjectKind::Lambda)
                .ok()
                .map(|object| object.last_touch_epoch()),
            ReadyExclusiveObjectKind::Primop => self
                .flat_closures
                .resolve(ptr, FlatObjectKind::Primop)
                .ok()
                .map(|object| object.last_touch_epoch()),
            ReadyExclusiveObjectKind::SuspendedTypedThunk
            | ReadyExclusiveObjectKind::BlackholeTypedThunk
            | ReadyExclusiveObjectKind::ForcedTypedThunk
            | ReadyExclusiveObjectKind::InvalidTypedThunk => None,
        }
    }
}

/// Classifies the mutable state of one ordinary flat thunk.
const fn ready_exclusive_thunk_kind(state: ThunkState) -> ReadyExclusiveObjectKind {
    match state {
        ThunkState::Suspended => ReadyExclusiveObjectKind::SuspendedThunk,
        ThunkState::Blackhole => ReadyExclusiveObjectKind::BlackholeThunk,
        ThunkState::Forced => ReadyExclusiveObjectKind::ForcedThunk,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partitions_shared_and_ready_exclusive_descendants() {
        let mut heap = EvalHeap::new();
        let shared = heap
            .alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("shared list allocates");
        let exclusive = heap
            .alloc_list(NixList::new(vec![Value::int(2)]))
            .expect("exclusive list allocates");
        let ready_root = heap
            .alloc_list(NixList::new(vec![shared, exclusive]))
            .expect("Ready root allocates");
        let other_root = heap
            .alloc_list(NixList::new(vec![shared]))
            .expect("other root allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_import_cache(0, ready_root)
            .expect("Ready root records");
        roots
            .try_push_value_stack(0, other_root)
            .expect("other root records");

        let census = heap
            .ready_exclusive_census(&roots)
            .expect("partitioned scan succeeds");

        assert!(census.union_reconciled());
        assert_eq!(census.ready_roots(), 1);
        assert_eq!(census.other_roots(), 1);
        assert_eq!(census.all_reachable_objects(), 4);
        assert_eq!(census.ready_reachable_objects(), 3);
        assert_eq!(census.other_reachable_objects(), 2);
        assert_eq!(census.shared_reachable_objects(), 1);
        assert_eq!(census.unclassified_exclusive_objects(), 0);
        assert_eq!(census.candidates().len(), 2);
        assert!(
            census
                .candidates()
                .iter()
                .all(|candidate| candidate.kind() == ReadyExclusiveObjectKind::List)
        );

        let exclusive_addresses = [
            ready_root
                .as_heap_ptr()
                .expect("Ready root is a heap value")
                .as_ptr() as usize,
            exclusive
                .as_heap_ptr()
                .expect("exclusive descendant is a heap value")
                .as_ptr() as usize,
        ];
        let expected_inline = heap
            .flat_lists
            .iter()
            .filter(|object| exclusive_addresses.contains(&(object.ptr().as_ptr() as usize)))
            .map(|object| object.size_bytes() as u64)
            .sum::<u64>();
        let expected_spines = heap
            .flat_lists
            .iter()
            .filter(|object| exclusive_addresses.contains(&(object.ptr().as_ptr() as usize)))
            .map(|object| {
                object
                    .object()
                    .payload()
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Value>()) as u64
            })
            .sum::<u64>();
        assert_eq!(census.inline_bytes(), expected_inline);
        assert_eq!(census.list_spine_bytes(), expected_spines);
        assert_eq!(
            census.attributable_bytes(),
            expected_inline + expected_spines
        );
        assert!(census.candidates().iter().all(|candidate| {
            candidate.initial_touch_epoch().is_some()
                && candidate.attributable_bytes()
                    == candidate.inline_bytes() + candidate.list_spine_bytes()
        }));
    }

    #[test]
    fn shared_ready_root_has_no_exclusive_candidate() {
        let mut heap = EvalHeap::new();
        let shared = heap
            .alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("shared list allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_import_cache(0, shared)
            .expect("Ready root records");
        roots
            .try_push_value_stack(0, shared)
            .expect("other root records");

        let census = heap
            .ready_exclusive_census(&roots)
            .expect("partitioned scan succeeds");

        assert!(census.union_reconciled());
        assert_eq!(census.all_reachable_objects(), 1);
        assert_eq!(census.ready_reachable_objects(), 1);
        assert_eq!(census.other_reachable_objects(), 1);
        assert_eq!(census.shared_reachable_objects(), 1);
        assert!(census.candidates().is_empty());
        assert_eq!(census.attributable_bytes(), 0);
    }

    #[test]
    fn capture_scan_does_not_stamp_candidate_touch_epochs() {
        let mut heap = EvalHeap::new();
        heap.set_epoch_tracking_enabled(true);
        let exclusive = heap
            .alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("exclusive list allocates");
        let ready_root = heap
            .alloc_list(NixList::new(vec![exclusive]))
            .expect("Ready root allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_import_cache(0, ready_root)
            .expect("Ready root records");

        let census = heap
            .ready_exclusive_census(&roots)
            .expect("partitioned scan succeeds");

        for candidate in census.candidates() {
            assert_eq!(
                heap.ready_exclusive_candidate_touch_epoch(*candidate),
                candidate.initial_touch_epoch(),
                "capture traversal must not stamp candidate access"
            );
        }
        let exclusive_address = exclusive
            .as_heap_ptr()
            .expect("exclusive list is a heap value")
            .as_ptr() as usize;
        let exclusive_candidate = census
            .candidates()
            .iter()
            .find(|candidate| candidate.address() == exclusive_address)
            .copied()
            .expect("exclusive descendant is inventoried");
        let initial = exclusive_candidate
            .initial_touch_epoch()
            .expect("flat list has a touch epoch");
        heap.get_list(exclusive)
            .expect("ordinary list resolution succeeds");
        let current = heap
            .ready_exclusive_candidate_touch_epoch(exclusive_candidate)
            .expect("flat list still has a touch epoch");
        assert!(current > initial);
    }
}
