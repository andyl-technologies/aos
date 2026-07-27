//! Nonmoving execution-176 lifetime-quarantine shadow.
//!
//! The shadow leaves candidate objects and their payloads untouched. Semantic
//! heap access doors consult an exact reservation-relative sparse bitmap and
//! aggregate later accesses. Scan-only doors deliberately do not consult it:
//! the lifetime census and root scanner must not manufacture evidence against
//! the candidate set they are validating.

use super::census::{LifetimeCohortCandidate, LifetimeCohortCandidateKind};
use super::{EvalHeap, EvalHeapError, EvalRootSet, EvalRootSource};
use crate::heap::flat::FlatObjectKind;
use crate::value::{HeapObject, Value};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::ptr::NonNull;

const PAGE_SHIFT: usize = 12;
const PAGE_BYTES: usize = 1 << PAGE_SHIFT;
const WORD_BYTES: usize = std::mem::size_of::<u64>();
const BITS_PER_PAGE: usize = PAGE_BYTES / WORD_BYTES;
const BITMAP_WORDS: usize = BITS_PER_PAGE / u64::BITS as usize;
const FIRST_HIT_LIMIT: usize = 32;
const TERMINAL_REACHABLE_SAMPLE_LIMIT: usize = 16;

/// One semantic access origin reported by the quarantine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifetimeQuarantineOrigin {
    /// A generic record payload was resolved.
    Record,
    /// A flat string or path payload was resolved.
    StringOrPath,
    /// A flat list payload was resolved.
    List,
    /// A flat attribute-set payload or its metadata was resolved.
    Attrs,
    /// A flat closure's allocation domain was queried.
    AllocationDomain,
    /// A flat closure's heap generation was queried.
    Generation,
    /// A flat lambda payload was resolved.
    GetLambda,
    /// A flat primop payload was resolved.
    GetPrimop,
    /// A flat thunk payload was resolved.
    GetThunk,
    /// A stable pointer to a serial flat-thunk payload was requested.
    SerialFlatThunkPayloadPtr,
    /// A flat thunk payload was cloned.
    CloneThunk,
    /// An inline flat-closure capture tail was read.
    ClosureCapture,
    /// A live closure payload was mutated or shared by the force path.
    ClosureMutation,
    /// A weak hash-cons identity was returned to evaluation.
    HashConsReuse,
    /// Raw value identity influenced semantic control flow.
    Identity,
}

impl LifetimeQuarantineOrigin {
    const COUNT: usize = 15;

    const fn index(self) -> usize {
        match self {
            Self::Record => 0,
            Self::StringOrPath => 1,
            Self::List => 2,
            Self::Attrs => 3,
            Self::AllocationDomain => 4,
            Self::Generation => 5,
            Self::GetLambda => 6,
            Self::GetPrimop => 7,
            Self::GetThunk => 8,
            Self::SerialFlatThunkPayloadPtr => 9,
            Self::CloneThunk => 10,
            Self::ClosureCapture => 11,
            Self::ClosureMutation => 12,
            Self::HashConsReuse => 13,
            Self::Identity => 14,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::StringOrPath => "string_or_path",
            Self::List => "list",
            Self::Attrs => "attrs",
            Self::AllocationDomain => "allocation_domain",
            Self::Generation => "generation",
            Self::GetLambda => "get_lambda",
            Self::GetPrimop => "get_primop",
            Self::GetThunk => "get_thunk",
            Self::SerialFlatThunkPayloadPtr => "serial_flat_thunk_payload_ptr",
            Self::CloneThunk => "clone_thunk",
            Self::ClosureCapture => "closure_capture",
            Self::ClosureMutation => "closure_mutation",
            Self::HashConsReuse => "hashcons_reuse",
            Self::Identity => "identity",
        }
    }

    const ALL: [Self; Self::COUNT] = [
        Self::Record,
        Self::StringOrPath,
        Self::List,
        Self::Attrs,
        Self::AllocationDomain,
        Self::Generation,
        Self::GetLambda,
        Self::GetPrimop,
        Self::GetThunk,
        Self::SerialFlatThunkPayloadPtr,
        Self::CloneThunk,
        Self::ClosureCapture,
        Self::ClosureMutation,
        Self::HashConsReuse,
        Self::Identity,
    ];
}

/// Result of attempting to install the default-off quarantine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifetimeQuarantineInstallReport {
    /// The current inventory was installed.
    Installed {
        /// Number of generic objects represented by the bitmap.
        objects: usize,
        /// Attributable bytes represented by the installed objects.
        bytes: u64,
        /// Typed heads excluded until semantic and scan probes are separated.
        typed_heads_excluded: usize,
    },
    /// The heap layout cannot support the exact fast membership test.
    Refused {
        /// Stable refusal reason for diagnostics and focused tests.
        reason: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateMetadata {
    address: usize,
    kind: LifetimeCohortCandidateKind,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FirstHit {
    candidate: CandidateMetadata,
    origin: LifetimeQuarantineOrigin,
}

#[derive(Debug)]
struct HitDetails {
    first_hits: Vec<FirstHit>,
    unique_addresses_by_origin: [HashSet<usize>; LifetimeQuarantineOrigin::COUNT],
    unique_objects_by_origin: [u64; LifetimeQuarantineOrigin::COUNT],
    unique_bytes_by_origin: [u64; LifetimeQuarantineOrigin::COUNT],
}

impl Default for HitDetails {
    fn default() -> Self {
        Self {
            first_hits: Vec::new(),
            unique_addresses_by_origin: std::array::from_fn(|_| HashSet::new()),
            unique_objects_by_origin: [0; LifetimeQuarantineOrigin::COUNT],
            unique_bytes_by_origin: [0; LifetimeQuarantineOrigin::COUNT],
        }
    }
}

/// One quarantined object reached from an exact terminal root.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TerminalReachableSample {
    candidate: CandidateMetadata,
    root_source: EvalRootSource,
}

/// Live-graph-only terminal validation of an installed quarantine.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TerminalReachabilityReport {
    graph_objects: usize,
    candidate_objects: usize,
    candidate_bytes: u64,
    samples: Vec<TerminalReachableSample>,
}

/// Exact sparse candidate-membership index and aggregate access report.
#[derive(Debug)]
pub(super) struct LifetimeQuarantine {
    base: usize,
    capacity: usize,
    /// Page number to one-based index in `bitmaps`; zero means empty page.
    directory: Vec<u32>,
    bitmaps: Vec<[u64; BITMAP_WORDS]>,
    candidates: Vec<CandidateMetadata>,
    /// Exact fallback for record-table addresses outside the flat reservation.
    record_addresses: Vec<usize>,
    candidate_bytes: u64,
    total_hits: Cell<u64>,
    hits_by_origin: [Cell<u64>; LifetimeQuarantineOrigin::COUNT],
    details: RefCell<HitDetails>,
}

impl LifetimeQuarantine {
    fn build(
        base: usize,
        capacity: usize,
        candidates: &[LifetimeCohortCandidate],
    ) -> Result<(Self, usize), &'static str> {
        let page_count = capacity
            .checked_add(PAGE_BYTES - 1)
            .ok_or("reservation page count overflow")?
            >> PAGE_SHIFT;
        let mut directory = Vec::new();
        directory
            .try_reserve_exact(page_count)
            .map_err(|_| "quarantine page directory allocation failed")?;
        directory.resize(page_count, 0_u32);

        let mut metadata = Vec::new();
        metadata
            .try_reserve_exact(candidates.len())
            .map_err(|_| "quarantine candidate metadata allocation failed")?;
        let mut typed_heads_excluded = 0_usize;
        let mut candidate_bytes = 0_u64;
        let mut record_addresses = Vec::new();
        record_addresses
            .try_reserve(candidates.len())
            .map_err(|_| "quarantine record-address allocation failed")?;
        for candidate in candidates {
            if candidate.kind == LifetimeCohortCandidateKind::TypedThunk {
                typed_heads_excluded = typed_heads_excluded.saturating_add(1);
                continue;
            }
            metadata.push(CandidateMetadata {
                address: candidate.address,
                kind: candidate.kind,
                bytes: candidate.attributable_bytes(),
            });
            candidate_bytes = candidate_bytes.saturating_add(candidate.attributable_bytes());
            if matches!(candidate.kind, LifetimeCohortCandidateKind::Record(_)) {
                record_addresses.push(candidate.address);
                continue;
            }
            let Some(offset) = candidate.address.checked_sub(base) else {
                return Err("flat candidate precedes serial reservation");
            };
            if offset >= capacity || offset % WORD_BYTES != 0 {
                return Err("flat candidate is outside or unaligned in serial reservation");
            }
        }
        metadata.sort_unstable_by_key(|candidate| candidate.address);
        metadata.dedup_by_key(|candidate| candidate.address);
        record_addresses.sort_unstable();
        record_addresses.dedup();

        let mut bitmaps = Vec::<[u64; BITMAP_WORDS]>::new();
        bitmaps
            .try_reserve(metadata.len().min(page_count))
            .map_err(|_| "quarantine sparse bitmap allocation failed")?;
        for candidate in &metadata {
            if matches!(candidate.kind, LifetimeCohortCandidateKind::Record(_)) {
                continue;
            }
            let offset = candidate.address - base;
            let page = offset >> PAGE_SHIFT;
            let bitmap_index = if directory[page] == 0 {
                bitmaps.push([0_u64; BITMAP_WORDS]);
                let one_based = u32::try_from(bitmaps.len())
                    .map_err(|_| "quarantine sparse bitmap index overflow")?;
                directory[page] = one_based;
                bitmaps.len() - 1
            } else {
                directory[page] as usize - 1
            };
            let slot = (offset & (PAGE_BYTES - 1)) / WORD_BYTES;
            bitmaps[bitmap_index][slot / u64::BITS as usize] |=
                1_u64 << (slot % u64::BITS as usize);
        }

        Ok((
            Self {
                base,
                capacity,
                directory,
                bitmaps,
                candidates: metadata,
                record_addresses,
                candidate_bytes,
                total_hits: Cell::new(0),
                hits_by_origin: std::array::from_fn(|_| Cell::new(0)),
                details: RefCell::new(HitDetails::default()),
            },
            typed_heads_excluded,
        ))
    }

    #[inline]
    fn contains(&self, address: usize, origin: LifetimeQuarantineOrigin) -> bool {
        if origin == LifetimeQuarantineOrigin::Record {
            return self.record_addresses.binary_search(&address).is_ok();
        }
        if origin == LifetimeQuarantineOrigin::Identity
            && self.record_addresses.binary_search(&address).is_ok()
        {
            return true;
        }
        let Some(offset) = address.checked_sub(self.base) else {
            return false;
        };
        if offset >= self.capacity || offset % WORD_BYTES != 0 {
            return false;
        }
        let page = offset >> PAGE_SHIFT;
        let one_based = self.directory[page];
        if one_based == 0 {
            return false;
        }
        let slot = (offset & (PAGE_BYTES - 1)) / WORD_BYTES;
        let bitmap = &self.bitmaps[one_based as usize - 1];
        bitmap[slot / u64::BITS as usize] & (1_u64 << (slot % u64::BITS as usize)) != 0
    }

    #[inline]
    fn observe(&self, address: usize, origin: LifetimeQuarantineOrigin) {
        if !self.contains(address, origin) {
            return;
        }
        self.total_hits.set(self.total_hits.get().saturating_add(1));
        let counter = &self.hits_by_origin[origin.index()];
        counter.set(counter.get().saturating_add(1));
        let Ok(index) = self
            .candidates
            .binary_search_by_key(&address, |candidate| candidate.address)
        else {
            return;
        };
        let mut details = self.details.borrow_mut();
        let origin_index = origin.index();
        if details.unique_addresses_by_origin[origin_index].insert(address) {
            details.unique_objects_by_origin[origin_index] =
                details.unique_objects_by_origin[origin_index].saturating_add(1);
            details.unique_bytes_by_origin[origin_index] = details.unique_bytes_by_origin
                [origin_index]
                .saturating_add(self.candidates[index].bytes);
        }
        if details.first_hits.len() >= FIRST_HIT_LIMIT
            || details
                .first_hits
                .iter()
                .any(|hit| hit.candidate.address == address)
        {
            return;
        }
        details.first_hits.push(FirstHit {
            candidate: self.candidates[index],
            origin,
        });
    }

    fn emit_report(&self) {
        let details = self.details.borrow();
        let origins = LifetimeQuarantineOrigin::ALL
            .map(|origin| {
                let index = origin.index();
                format!(
                    "\"{}\":{{\"calls\":{},\"objects\":{},\"bytes\":{}}}",
                    origin.name(),
                    self.hits_by_origin[index].get(),
                    details.unique_objects_by_origin[index],
                    details.unique_bytes_by_origin[index]
                )
            })
            .join(",");
        let first_hits = details
            .first_hits
            .iter()
            .map(|hit| {
                format!(
                    "[{},\"{}\",\"{}\"]",
                    hit.candidate.address,
                    candidate_kind_name(hit.candidate.kind),
                    hit.origin.name()
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        eprintln!(
            "aos_nix_lifetime_quarantine \
             {{\"version\":1,\"execution\":176,\"objects\":{},\"bytes\":{},\
             \"hits\":{},\"by_origin\":{{{origins}}},\"first_hits\":[{first_hits}],\
             \"retirement_performed\":false,\"typed_heads_quarantined\":false}}",
            self.candidates.len(),
            self.candidate_bytes,
            self.total_hits.get(),
        );
    }

    fn terminal_reachability(
        &self,
        heap: &EvalHeap,
        roots: &EvalRootSet,
    ) -> Result<TerminalReachabilityReport, EvalHeapError> {
        let mut candidate_objects = 0_usize;
        let mut candidate_bytes = 0_u64;
        let mut samples = Vec::new();
        samples
            .try_reserve_exact(TERMINAL_REACHABLE_SAMPLE_LIMIT)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: "lifetime-quarantine terminal samples",
                entries: TERMINAL_REACHABLE_SAMPLE_LIMIT,
            })?;
        let reachable = heap.weak_reachable_addresses_matching_and_observe(
            roots,
            |_| true,
            |address, root_index| {
                let Ok(candidate_index) = self
                    .candidates
                    .binary_search_by_key(&address, |candidate| candidate.address)
                else {
                    return;
                };
                let candidate = self.candidates[candidate_index];
                candidate_objects = candidate_objects.saturating_add(1);
                candidate_bytes = candidate_bytes.saturating_add(candidate.bytes);
                if samples.len() >= TERMINAL_REACHABLE_SAMPLE_LIMIT {
                    return;
                }
                let Some(root) = roots.roots().get(root_index) else {
                    return;
                };
                samples.push(TerminalReachableSample {
                    candidate,
                    root_source: root.source().clone(),
                });
            },
        )?;
        Ok(TerminalReachabilityReport {
            graph_objects: reachable.len(),
            candidate_objects,
            candidate_bytes,
            samples,
        })
    }

    fn emit_terminal_reachability(&self, report: &TerminalReachabilityReport) {
        let samples = report
            .samples
            .iter()
            .map(|sample| {
                let root_source = format!("{:?}", sample.root_source);
                let root_source_json = format!("{root_source:?}");
                format!(
                    "[{},\"{}\",{},{root_source_json}]",
                    sample.candidate.address,
                    candidate_kind_name(sample.candidate.kind),
                    sample.candidate.bytes,
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        eprintln!(
            "aos_nix_lifetime_quarantine_terminal_reachability \
             {{\"version\":1,\"execution\":176,\"terminal_graph_objects\":{},\
             \"installed\":[{},{}],\"reachable\":[{},{}],\
             \"samples\":[{samples}],\"sample_limit\":{},\
             \"exact_terminal_roots\":true,\"full_heap_inventory\":false,\
             \"retirement_performed\":false}}",
            report.graph_objects,
            self.candidates.len(),
            self.candidate_bytes,
            report.candidate_objects,
            report.candidate_bytes,
            TERMINAL_REACHABLE_SAMPLE_LIMIT,
        );
    }
}

impl EvalHeap {
    /// Installs the exact generic-object inventory for execution 176.
    pub(crate) fn install_lifetime_quarantine(
        &mut self,
        candidates: &[LifetimeCohortCandidate],
    ) -> LifetimeQuarantineInstallReport {
        let Some(resolver) = self.serial_reservation else {
            self.lifetime_quarantine = None;
            return LifetimeQuarantineInstallReport::Refused {
                reason: "serial Candidate-C reservation is unavailable",
            };
        };
        let (quarantine, typed_heads_excluded) =
            match LifetimeQuarantine::build(resolver.base, resolver.capacity, candidates) {
                Ok(built) => built,
                Err(reason) => {
                    self.lifetime_quarantine = None;
                    return LifetimeQuarantineInstallReport::Refused { reason };
                }
            };
        let report = LifetimeQuarantineInstallReport::Installed {
            objects: quarantine.candidates.len(),
            bytes: quarantine.candidate_bytes,
            typed_heads_excluded,
        };
        self.lifetime_quarantine = Some(quarantine);
        report
    }

    /// Clears any installed quarantine after an admission invariant changes.
    pub(crate) fn clear_lifetime_quarantine(&mut self) {
        self.lifetime_quarantine = None;
    }

    /// Emits the aggregate access report for an installed quarantine.
    pub(crate) fn emit_lifetime_quarantine_report(&self) {
        if let Some(quarantine) = &self.lifetime_quarantine {
            quarantine.emit_report();
        }
    }

    /// Returns whether an execution-176 quarantine remains installed.
    pub(crate) fn lifetime_quarantine_is_installed(&self) -> bool {
        self.lifetime_quarantine.is_some()
    }

    /// Traverses terminal live objects and intersects them with the quarantine.
    ///
    /// Unlike the lifetime cohort census, this never inventories unreachable
    /// heap objects or extends the cumulative candidate vectors.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if exact-root traversal encounters a malformed
    /// object or cannot allocate its live-graph work storage.
    pub(crate) fn emit_lifetime_quarantine_terminal_reachability(
        &self,
        roots: &EvalRootSet,
    ) -> Result<(), EvalHeapError> {
        let Some(quarantine) = &self.lifetime_quarantine else {
            return Ok(());
        };
        let report = quarantine.terminal_reachability(self, roots)?;
        quarantine.emit_terminal_reachability(&report);
        Ok(())
    }

    /// Records one semantic access without affecting scan-only resolution.
    #[inline]
    pub(in crate::eval::heap) fn observe_lifetime_quarantine_ptr(
        &self,
        ptr: NonNull<HeapObject>,
        origin: LifetimeQuarantineOrigin,
    ) {
        if let Some(quarantine) = &self.lifetime_quarantine {
            quarantine.observe(ptr.as_ptr() as usize, origin);
        }
    }

    /// Records semantic use of a value's raw identity without touching it.
    #[inline]
    pub(in crate::eval) fn observe_value_identity(&self, value: Value) {
        if !value.tag().is_heap() {
            return;
        }
        if let Some(location) = self.serial_heap_location(value, value.tag()) {
            self.observe_lifetime_quarantine_ptr(location.ptr, LifetimeQuarantineOrigin::Identity);
            return;
        }
        if let Ok(ptr) = value.as_heap_ptr() {
            self.observe_lifetime_quarantine_ptr(ptr, LifetimeQuarantineOrigin::Identity);
        }
    }
}

const fn candidate_kind_name(kind: LifetimeCohortCandidateKind) -> &'static str {
    match kind {
        LifetimeCohortCandidateKind::Record(_) => "record",
        LifetimeCohortCandidateKind::String => "string",
        LifetimeCohortCandidateKind::Path => "path",
        LifetimeCohortCandidateKind::List => "list",
        LifetimeCohortCandidateKind::Attrs => "attrs",
        LifetimeCohortCandidateKind::Closure(FlatObjectKind::String) => "flat_string",
        LifetimeCohortCandidateKind::Closure(FlatObjectKind::Path) => "flat_path",
        LifetimeCohortCandidateKind::Closure(FlatObjectKind::List) => "flat_list",
        LifetimeCohortCandidateKind::Closure(FlatObjectKind::Attrs) => "flat_attrs",
        LifetimeCohortCandidateKind::Closure(FlatObjectKind::Thunk) => "flat_thunk",
        LifetimeCohortCandidateKind::Closure(FlatObjectKind::Lambda) => "flat_lambda",
        LifetimeCohortCandidateKind::Closure(FlatObjectKind::Primop) => "flat_primop",
        LifetimeCohortCandidateKind::Closure(FlatObjectKind::BoxedInt) => "flat_boxed_int",
        LifetimeCohortCandidateKind::Closure(FlatObjectKind::BoxedFloat) => "flat_boxed_float",
        LifetimeCohortCandidateKind::Closure(FlatObjectKind::ThunkHead) => "flat_thunk_head",
        LifetimeCohortCandidateKind::TypedThunk => "typed_thunk",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::ValueTag;

    fn candidate(address: usize) -> LifetimeCohortCandidate {
        LifetimeCohortCandidate {
            address,
            kind: LifetimeCohortCandidateKind::Record(ValueTag::Thunk),
            inline_bytes: 32,
            external_bytes: 8,
            initial_touch_epoch: Some(1),
        }
    }

    fn flat_candidate(address: usize) -> LifetimeCohortCandidate {
        LifetimeCohortCandidate {
            address,
            kind: LifetimeCohortCandidateKind::List,
            inline_bytes: 32,
            external_bytes: 8,
            initial_touch_epoch: Some(1),
        }
    }

    #[test]
    fn exact_sparse_membership_distinguishes_candidate_and_neighbor() {
        let (quarantine, excluded) =
            LifetimeQuarantine::build(0x1000, 0x4000, &[flat_candidate(0x1800)])
                .expect("test quarantine builds");
        assert_eq!(excluded, 0);
        assert!(quarantine.contains(0x1800, LifetimeQuarantineOrigin::List));
        assert!(!quarantine.contains(0x1808, LifetimeQuarantineOrigin::List));
        quarantine.observe(0x1808, LifetimeQuarantineOrigin::List);
        assert_eq!(quarantine.total_hits.get(), 0);
        quarantine.observe(0x1800, LifetimeQuarantineOrigin::List);
        assert_eq!(quarantine.total_hits.get(), 1);
    }

    #[test]
    fn typed_heads_are_excluded_and_invalid_geometry_is_refused() {
        let mut typed = candidate(0x1800);
        typed.kind = LifetimeCohortCandidateKind::TypedThunk;
        let (quarantine, excluded) = LifetimeQuarantine::build(0x1000, 0x4000, &[typed])
            .expect("typed exclusion still builds");
        assert_eq!(excluded, 1);
        assert!(!quarantine.contains(0x1800, LifetimeQuarantineOrigin::GetThunk));
        let (record_quarantine, _) =
            LifetimeQuarantine::build(0x2000, 0x1000, &[candidate(0x1800)])
                .expect("out-of-reservation records use the exact fallback");
        assert!(record_quarantine.contains(0x1800, LifetimeQuarantineOrigin::Record));
        assert!(matches!(
            LifetimeQuarantine::build(0x2000, 0x1000, &[flat_candidate(0x1800)]),
            Err("flat candidate precedes serial reservation")
        ));
    }

    #[test]
    fn closure_candidate_subtypes_and_semantic_doors_remain_distinct() {
        let closure = LifetimeCohortCandidate {
            address: 0x1800,
            kind: LifetimeCohortCandidateKind::Closure(FlatObjectKind::Thunk),
            inline_bytes: 32,
            external_bytes: 8,
            initial_touch_epoch: Some(1),
        };
        let (quarantine, excluded) = LifetimeQuarantine::build(0x1000, 0x4000, &[closure])
            .expect("flat closure quarantine builds");
        assert_eq!(excluded, 0);
        assert_eq!(candidate_kind_name(closure.kind), "flat_thunk");

        let origins = [
            LifetimeQuarantineOrigin::AllocationDomain,
            LifetimeQuarantineOrigin::Generation,
            LifetimeQuarantineOrigin::GetLambda,
            LifetimeQuarantineOrigin::GetPrimop,
            LifetimeQuarantineOrigin::GetThunk,
            LifetimeQuarantineOrigin::SerialFlatThunkPayloadPtr,
            LifetimeQuarantineOrigin::CloneThunk,
        ];
        for origin in origins {
            quarantine.observe(closure.address, origin);
        }

        let details = quarantine.details.borrow();
        assert_eq!(quarantine.total_hits.get(), origins.len() as u64);
        for origin in origins {
            assert_eq!(quarantine.hits_by_origin[origin.index()].get(), 1);
            assert_eq!(details.unique_objects_by_origin[origin.index()], 1);
            assert_eq!(details.unique_bytes_by_origin[origin.index()], 40);
        }
        assert_eq!(details.first_hits.len(), 1);
        assert_eq!(details.first_hits[0].candidate.kind, closure.kind);
        assert_eq!(
            details.first_hits[0].origin,
            LifetimeQuarantineOrigin::AllocationDomain
        );
    }

    #[test]
    fn constructing_and_membership_checks_do_not_self_observe() {
        let (quarantine, _) = LifetimeQuarantine::build(0x1000, 0x4000, &[candidate(0x1800)])
            .expect("test quarantine builds");
        assert!(quarantine.contains(0x1800, LifetimeQuarantineOrigin::Record));
        assert_eq!(quarantine.total_hits.get(), 0);
        assert!(quarantine.details.borrow().first_hits.is_empty());
    }

    #[test]
    fn unsupported_heap_refusal_clears_a_prior_shadow() {
        let (quarantine, _) = LifetimeQuarantine::build(0x1000, 0x4000, &[candidate(0x1800)])
            .expect("test quarantine builds");
        let mut heap =
            EvalHeap::with_initial_chunk_bytes(4096).expect("chunked test heap constructs");
        heap.lifetime_quarantine = Some(quarantine);
        assert_eq!(
            heap.install_lifetime_quarantine(&[candidate(0x1800)]),
            LifetimeQuarantineInstallReport::Refused {
                reason: "serial Candidate-C reservation is unavailable"
            }
        );
        assert!(heap.lifetime_quarantine.is_none());
    }

    #[test]
    fn value_identity_observes_only_exact_installed_candidates() {
        let mut heap = EvalHeap::new();
        let candidate_value = heap
            .alloc_string(crate::string::NixString::from_bytes(
                b"identity-candidate".to_vec(),
            ))
            .expect("candidate string allocates");
        let noncandidate_value = heap
            .alloc_string(crate::string::NixString::from_bytes(
                b"identity-noncandidate".to_vec(),
            ))
            .expect("noncandidate string allocates");
        let address = candidate_value
            .as_string_ptr()
            .expect("candidate string has a pointer")
            .as_ptr() as usize;
        let installed = LifetimeCohortCandidate {
            address,
            kind: LifetimeCohortCandidateKind::String,
            inline_bytes: 32,
            external_bytes: 8,
            initial_touch_epoch: Some(1),
        };
        assert!(matches!(
            heap.install_lifetime_quarantine(&[installed]),
            LifetimeQuarantineInstallReport::Installed { objects: 1, .. }
        ));

        heap.observe_value_identity(Value::int(1));
        heap.observe_value_identity(noncandidate_value);
        heap.observe_value_identity(candidate_value);
        heap.observe_value_identity(candidate_value);

        let quarantine = heap
            .lifetime_quarantine
            .as_ref()
            .expect("quarantine remains installed");
        let origin = LifetimeQuarantineOrigin::Identity.index();
        let details = quarantine.details.borrow();
        assert_eq!(quarantine.total_hits.get(), 2);
        assert_eq!(quarantine.hits_by_origin[origin].get(), 2);
        assert_eq!(details.unique_objects_by_origin[origin], 1);
        assert_eq!(details.unique_bytes_by_origin[origin], 40);
    }

    #[test]
    fn terminal_reachability_intersects_only_the_live_graph_and_attributes_root() {
        let mut heap = EvalHeap::new();
        let reachable = heap
            .alloc_string(crate::string::NixString::from_bytes(b"reachable".to_vec()))
            .expect("reachable string allocates");
        let unreachable = heap
            .alloc_string(crate::string::NixString::from_bytes(
                b"unreachable".to_vec(),
            ))
            .expect("unreachable string allocates");
        let root = heap
            .alloc_list(crate::list::NixList::new(vec![reachable]))
            .expect("root list allocates");
        let reachable_address = reachable
            .as_string_ptr()
            .expect("reachable string has a pointer")
            .as_ptr() as usize;
        let unreachable_address = unreachable
            .as_string_ptr()
            .expect("unreachable string has a pointer")
            .as_ptr() as usize;
        let candidates = [
            LifetimeCohortCandidate {
                address: reachable_address,
                kind: LifetimeCohortCandidateKind::String,
                inline_bytes: 32,
                external_bytes: 8,
                initial_touch_epoch: Some(1),
            },
            LifetimeCohortCandidate {
                address: unreachable_address,
                kind: LifetimeCohortCandidateKind::String,
                inline_bytes: 64,
                external_bytes: 16,
                initial_touch_epoch: Some(1),
            },
        ];
        assert!(matches!(
            heap.install_lifetime_quarantine(&candidates),
            LifetimeQuarantineInstallReport::Installed { objects: 2, .. }
        ));
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(7, root)
            .expect("root set accepts the terminal list");

        let quarantine = heap
            .lifetime_quarantine
            .as_ref()
            .expect("quarantine remains installed");
        let report = quarantine
            .terminal_reachability(&heap, &roots)
            .expect("terminal live graph scans");

        assert_eq!(report.graph_objects, 2);
        assert_eq!(report.candidate_objects, 1);
        assert_eq!(report.candidate_bytes, 40);
        assert_eq!(report.samples.len(), 1);
        assert_eq!(report.samples[0].candidate.address, reachable_address);
        assert_eq!(
            report.samples[0].root_source,
            EvalRootSource::ValueStack { slot: 7 }
        );
    }

    #[test]
    fn terminal_reachability_bounds_samples_without_truncating_aggregates() {
        let mut heap = EvalHeap::new();
        let mut values = Vec::new();
        let mut candidates = Vec::new();
        for index in 0..(TERMINAL_REACHABLE_SAMPLE_LIMIT + 4) {
            let value = heap
                .alloc_string(crate::string::NixString::from_bytes(
                    format!("candidate-{index}").into_bytes(),
                ))
                .expect("candidate string allocates");
            let address = value
                .as_string_ptr()
                .expect("candidate string has a pointer")
                .as_ptr() as usize;
            values.push(value);
            candidates.push(LifetimeCohortCandidate {
                address,
                kind: LifetimeCohortCandidateKind::String,
                inline_bytes: 1,
                external_bytes: 0,
                initial_touch_epoch: Some(1),
            });
        }
        let root = heap
            .alloc_list(crate::list::NixList::new(values))
            .expect("root list allocates");
        assert!(matches!(
            heap.install_lifetime_quarantine(&candidates),
            LifetimeQuarantineInstallReport::Installed { objects, .. }
                if objects == TERMINAL_REACHABLE_SAMPLE_LIMIT + 4
        ));
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, root)
            .expect("root set accepts the terminal list");

        let quarantine = heap
            .lifetime_quarantine
            .as_ref()
            .expect("quarantine remains installed");
        let report = quarantine
            .terminal_reachability(&heap, &roots)
            .expect("terminal live graph scans");

        assert_eq!(report.graph_objects, TERMINAL_REACHABLE_SAMPLE_LIMIT + 5);
        assert_eq!(
            report.candidate_objects,
            TERMINAL_REACHABLE_SAMPLE_LIMIT + 4
        );
        assert_eq!(
            report.candidate_bytes,
            (TERMINAL_REACHABLE_SAMPLE_LIMIT + 4) as u64
        );
        assert_eq!(report.samples.len(), TERMINAL_REACHABLE_SAMPLE_LIMIT);
    }
}
