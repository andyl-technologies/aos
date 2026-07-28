//! Read-only projection of nonmoving dead-page retirement.
//!
//! The probe uses the evaluator's storage-aware weak graph to project
//! invalidating dead weak candidates, dropping dead-owned list spines,
//! shrinking weak metadata, and advising pages containing no live arena
//! object. It never mutates the heap or root set.
//!
//! Candidate-C ambiguous words are admitted only when their domain, allocation
//! start, and semantic kind match the live traceable-allocation directory.
//! Physical credit is based on one `mincore` query per dead reservation page
//! and fails closed if any query is unavailable.

use std::collections::HashSet;
use std::fmt;
use std::ptr::NonNull;

use super::arena::any_value_heap_ptr;
use super::*;
use crate::value::compressed::CompressedValueWord;

const DEFAULT_PAGE_BYTES: usize = 4096;
const TARGET_RSS_BYTES: u64 = 239_054_848;
const SAFETY_RSS_BYTES: u64 = 216 * 1024 * 1024;
const ALLOCATION_GRANULE_BYTES: u64 = 8;
const IMMIX_LINE_BYTES: u64 = 128;
const ALLOCATION_DIRECTORY_TABLE: &str = "nonmoving traceable allocation directory";
const FLAT_REGISTRY_ENTRY_BYTES: usize = std::mem::size_of::<usize>() * 2
    + if cfg!(target_pointer_width = "32") {
        std::mem::size_of::<u32>()
    } else {
        0
    };
const HASH_BUCKET_SLOT_BYTES: usize = std::mem::size_of::<HotXxh3Hash>()
    + std::mem::size_of::<Vec<Value>>()
    + std::mem::size_of::<usize>();

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DeadPageProjection {
    total: u64,
    live: u64,
    dead: u64,
    runs: u64,
    largest_run: u64,
    resident_dead: u64,
    page_bytes: u64,
    residency_exact: bool,
}

impl DeadPageProjection {
    fn resident_dead_bytes(self) -> u64 {
        self.resident_dead.saturating_mul(self.page_bytes)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MetadataProjection {
    current: u64,
    live_sized: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RegistryProjection {
    strings_paths: MetadataProjection,
    lists: MetadataProjection,
    attrs: MetadataProjection,
    closures: MetadataProjection,
}

impl RegistryProjection {
    fn strict_reclaimable(self) -> u64 {
        self.strings_paths
            .reclaimable()
            .saturating_add(self.lists.reclaimable())
            .saturating_add(self.attrs.reclaimable())
    }
}

impl MetadataProjection {
    fn reclaimable(self) -> u64 {
        self.current.saturating_sub(self.live_sized)
    }

    fn add(&mut self, current: usize, live: usize) {
        self.current = self.current.saturating_add(current as u64);
        self.live_sized = self.live_sized.saturating_add(live as u64);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct HashProjection {
    buckets: u64,
    candidates: u64,
    live_buckets: u64,
    live_candidates: u64,
    metadata: MetadataProjection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TraceableAllocation {
    address: usize,
    index: u32,
    bytes: usize,
    tag: ValueTag,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AmbiguousWordProjection {
    words: u64,
    codec_valid: u64,
    indexed: u64,
    same_domain: u64,
    exact_start: u64,
    kind_match: u64,
    unique_roots: u64,
    already_precise_reachable: u64,
    newly_reachable_objects: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SideMetadataProjection {
    allocation_start_bytes: u64,
    mark_bytes: u64,
    line_bytes: u64,
    page_bytes: u64,
    total_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ChronologicalPeakProjection {
    post_reclaim_rss_bytes: u64,
    collection_peak_bytes: u64,
    chronological_peak_bytes: u64,
}

/// Read-only accounting for one hypothetical nonmoving collection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NonmovingReclaimProjection {
    roots: u64,
    reachable_objects: u64,
    allocated_objects: u64,
    pages: DeadPageProjection,
    dead_list_spine_bytes: u64,
    registries: RegistryProjection,
    hashes: HashProjection,
    ambiguous_words: AmbiguousWordProjection,
    side_metadata: SideMetadataProjection,
    mark_scratch_bytes: u64,
    rss_bytes: u64,
    adjusted_rss_bytes: u64,
    collection_peak_bytes: u64,
    adjusted_peak_bytes: u64,
    raw_peak_bytes: u64,
    samples: u64,
    count_monotonic: bool,
    independent_capture: bool,
}

impl fmt::Display for NonmovingReclaimProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\"roots\":{},\"reachable_objects\":{},\"allocated_objects\":{},\
             \"pages\":{{\"total\":{},\"live\":{},\"dead\":{},\"dead_runs\":{},\
             \"largest_dead_run_pages\":{},\"resident_dead\":{},\"page_bytes\":{},\
             \"dead_page_residency_exact\":{}}},\
             \"ambiguous_words\":{{\"words\":{},\"codec_valid\":{},\"indexed\":{},\
             \"same_domain\":{},\"exact_allocation_start\":{},\"kind_match\":{},\
             \"unique_roots\":{},\"already_precise_reachable\":{},\
             \"newly_reachable_objects\":{}}},\
             \"dead_owned_external\":{{\"list_spine_bytes\":{},\
             \"coverage\":\"list_capacity_only\",\
             \"credited_to_chronological_peak\":false}},\
             \"registries\":{{\
             \"strings_paths\":[{},{},{},false],\"lists\":[{},{},{},false],\
             \"attrs\":[{},{},{},false],\"closures\":[{},{},{},false],\
             \"tuple\":\"current_structural_bytes,live_sized_structural_bytes,\
             reclaimable_bytes,credited_to_chronological_peak\",\
             \"logical_reclaimable_bytes_uncredited\":{},\
             \"closure_exclusion\":\"tail handles embed store_index; shrinking requires \
             re-signing live handles and roots\"}},\
             \"hash_indexes\":{{\"current_buckets\":{},\"current_candidates\":{},\
             \"live_buckets\":{},\"live_candidates\":{},\
             \"current_structural_bytes\":{},\"live_sized_structural_bytes\":{},\
             \"reclaimable_bytes\":{},\"credited_to_strict_schedule\":false}},\
             \"mark\":{{\"projected_scratch_bytes\":{},\
             \"layout\":\"u32 object starts + object bits + u32 worklist + page bits\"}},\
             \"side_metadata\":{{\"allocation_start_bytes\":{},\"mark_bytes\":{},\
             \"line_bytes\":{},\"page_bytes\":{},\"total_bytes\":{},\
             \"layout\":\"one start bit and one mark bit per 8-byte used-lane \
             granule, one bit per 128-byte line, one bit per used page\"}},\
             \"schedule\":{{\"rss_bytes\":{},\"adjusted_rss_bytes\":{},\
             \"collection_peak_bytes\":{},\"adjusted_peak_bytes\":{},\
             \"raw_peak_bytes\":{},\"samples\":{},\
             \"dead_page_count_monotonic\":{},\"target_bytes\":{},\"target_pass\":{},\
             \"safety_bytes\":{},\"safety_pass\":{},\
             \"chronology\":\"first collection at this checkpoint\",\
             \"capture_mode\":\"{}\"}},\
             \"measurement_scratch\":{{\"projected_collector_scratch_is_not_probe_scratch\":true,\
             \"probe_hash_sets_and_vectors_excluded_from_adjustment\":true,\
             \"multi_milestone_raw_rss_may_include_prior_probe_scratch\":{}}},\
             \"semantics\":{{\"mutates_heap\":false,\"mutates_roots\":false,\
             \"reuses_sweep\":false,\"dead_hash_candidates_must_be_invalidated\":true}},\
             \"excluded\":{{\"allocator_and_hash_control_bytes\":true,\
             \"captured_environment_frames\":true,\"dynamic_scopes\":true,\
             \"attrs_external_capacity\":true,\"typed_work_pool_metadata\":true,\
             \"record_arena_pages\":true,\"boxed_scalars_are_pinned\":true}}}}",
            self.roots,
            self.reachable_objects,
            self.allocated_objects,
            self.pages.total,
            self.pages.live,
            self.pages.dead,
            self.pages.runs,
            self.pages.largest_run,
            self.pages.resident_dead,
            self.pages.page_bytes,
            self.pages.residency_exact,
            self.ambiguous_words.words,
            self.ambiguous_words.codec_valid,
            self.ambiguous_words.indexed,
            self.ambiguous_words.same_domain,
            self.ambiguous_words.exact_start,
            self.ambiguous_words.kind_match,
            self.ambiguous_words.unique_roots,
            self.ambiguous_words.already_precise_reachable,
            self.ambiguous_words.newly_reachable_objects,
            self.dead_list_spine_bytes,
            self.registries.strings_paths.current,
            self.registries.strings_paths.live_sized,
            self.registries.strings_paths.reclaimable(),
            self.registries.lists.current,
            self.registries.lists.live_sized,
            self.registries.lists.reclaimable(),
            self.registries.attrs.current,
            self.registries.attrs.live_sized,
            self.registries.attrs.reclaimable(),
            self.registries.closures.current,
            self.registries.closures.live_sized,
            self.registries.closures.reclaimable(),
            self.registries.strict_reclaimable(),
            self.hashes.buckets,
            self.hashes.candidates,
            self.hashes.live_buckets,
            self.hashes.live_candidates,
            self.hashes.metadata.current,
            self.hashes.metadata.live_sized,
            self.hashes.metadata.reclaimable(),
            self.mark_scratch_bytes,
            self.side_metadata.allocation_start_bytes,
            self.side_metadata.mark_bytes,
            self.side_metadata.line_bytes,
            self.side_metadata.page_bytes,
            self.side_metadata.total_bytes,
            self.rss_bytes,
            self.adjusted_rss_bytes,
            self.collection_peak_bytes,
            self.adjusted_peak_bytes,
            self.raw_peak_bytes,
            self.samples,
            self.count_monotonic,
            TARGET_RSS_BYTES,
            self.adjusted_peak_bytes < TARGET_RSS_BYTES,
            SAFETY_RSS_BYTES,
            self.adjusted_peak_bytes < SAFETY_RSS_BYTES,
            if self.independent_capture {
                "single_milestone_fresh_process"
            } else {
                "carried_multi_milestone"
            },
            !self.independent_capture,
        )
    }
}

impl EvalHeap {
    /// Projects nonmoving reclamation and a first-collection chronological peak.
    ///
    /// Hash-cons tables do not seed reachability. Reported external and
    /// metadata savings are conservative structural lower bounds.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if weak traversal finds a stale root, malformed
    /// edge, or invalid thunk state; if allocation-directory, ambiguous-root,
    /// or scanner storage cannot grow; or if one traceable allocation cannot be
    /// represented by the Candidate-C reservation directory.
    pub(crate) fn nonmoving_reclaim_projection(
        &self,
        roots: &EvalRootSet,
        rss_bytes: u64,
        peak_rss_bytes: u64,
        _modules: usize,
        independent_capture: bool,
        ambiguous_words: &[u64],
    ) -> Result<NonmovingReclaimProjection, EvalHeapError> {
        let precise_reachable = self.weak_reachable_addresses(roots)?;
        let allocations = self.traceable_allocation_directory()?;
        let domain = self.flat_arena.arena_domain_id();
        let (ambiguous_roots, mut ambiguous_projection) =
            filter_ambiguous_words(ambiguous_words, domain, &allocations)?;
        ambiguous_projection.already_precise_reachable = ambiguous_roots
            .iter()
            .filter(|value| {
                value
                    .as_heap_ptr()
                    .is_ok_and(|ptr| precise_reachable.contains(&(ptr.as_ptr() as usize)))
            })
            .count() as u64;
        let mut augmented_roots = roots.clone();
        let mut root_slot = roots.len();
        for value in ambiguous_roots {
            augmented_roots
                .try_push_value_stack(root_slot, value)
                .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                    table: "nonmoving ambiguous roots",
                    entries: root_slot.saturating_add(1),
                })?;
            root_slot = root_slot
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: "nonmoving ambiguous roots",
                })?;
        }
        let reachable = self.weak_reachable_addresses(&augmented_roots)?;
        ambiguous_projection.newly_reachable_objects =
            reachable.len().saturating_sub(precise_reachable.len()) as u64;
        let residency = self.flat_reservation_residency();
        let page_bytes = residency
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map_or(DEFAULT_PAGE_BYTES, |sample| sample.page_size);
        let mut total_pages = HashSet::new();
        let mut live_pages = HashSet::new();
        let mut dead_list_spine_bytes = 0u64;

        for allocation in &allocations {
            mark_pages(
                &mut total_pages,
                allocation.index as usize,
                allocation.bytes,
                page_bytes,
            );
            if reachable.contains(&allocation.address) {
                mark_pages(
                    &mut live_pages,
                    allocation.index as usize,
                    allocation.bytes,
                    page_bytes,
                );
            }
        }
        for object in self.flat_lists.iter() {
            let address = object.ptr().as_ptr() as usize;
            if !reachable.contains(&address) {
                dead_list_spine_bytes = dead_list_spine_bytes.saturating_add(
                    (object.object().payload().capacity() as u64)
                        .saturating_mul(std::mem::size_of::<Value>() as u64),
                );
            }
        }
        let mut scalar_regions = Vec::new();
        self.compressed_scalars
            .append_cell_regions(0, &mut scalar_regions);
        for (address, bytes) in scalar_regions {
            let ptr = NonNull::new(address as *mut HeapObject).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: ALLOCATION_DIRECTORY_TABLE,
                },
            )?;
            let index = self.flat_arena.index_for_pointer(ptr).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: ALLOCATION_DIRECTORY_TABLE,
                },
            )?;
            mark_pages(&mut total_pages, index.raw() as usize, bytes, page_bytes);
            mark_pages(&mut live_pages, index.raw() as usize, bytes, page_bytes);
        }

        let mut dead_pages: Vec<_> = total_pages.difference(&live_pages).copied().collect();
        dead_pages.sort_unstable();
        let (runs, largest_run) = coalesced_page_runs(&dead_pages);
        let (resident_dead, residency_exact) = exact_resident_dead_pages(&dead_pages, |page| {
            let byte_offset = page.checked_mul(page_bytes)?;
            let raw = u32::try_from(byte_offset).ok()?;
            self.flat_arena
                .page_is_resident_at_index(crate::heap::ArenaIndex::new(raw))
                .and_then(Result::ok)
        });
        let pages = DeadPageProjection {
            total: total_pages.len() as u64,
            live: live_pages.len() as u64,
            dead: dead_pages.len() as u64,
            runs,
            largest_run,
            resident_dead,
            page_bytes: page_bytes as u64,
            residency_exact,
        };
        let registries = self.registry_projection(&reachable);
        let mut hashes = HashProjection::default();
        for table in [
            &self.string_cons,
            &self.path_cons,
            &self.list_cons,
            &self.attrs_cons,
        ] {
            let next = hash_projection(table, &reachable)?;
            hashes.buckets = hashes.buckets.saturating_add(next.buckets);
            hashes.candidates = hashes.candidates.saturating_add(next.candidates);
            hashes.live_buckets = hashes.live_buckets.saturating_add(next.live_buckets);
            hashes.live_candidates = hashes.live_candidates.saturating_add(next.live_candidates);
            hashes.metadata.add(
                next.metadata.current as usize,
                next.metadata.live_sized as usize,
            );
        }
        let objects = allocations.len().saturating_add(
            self.records
                .iter()
                .filter(|record| !record.is_retired())
                .count(),
        );
        let mark_scratch_bytes =
            projected_mark_scratch(objects, reachable.len(), total_pages.len());
        let stats =
            self.flat_arena
                .reservation_stats()
                .unwrap_or(crate::heap::ReservedArenaStats {
                    virtual_reserved_bytes: 0,
                    used_bytes: 0,
                    low_used_bytes: 0,
                    high_used_bytes: 0,
                    available_bytes: 0,
                });
        let side_metadata =
            side_metadata_projection(stats.low_used_bytes, stats.high_used_bytes, page_bytes);
        let chronology = chronological_peak_projection(
            rss_bytes,
            peak_rss_bytes,
            pages.resident_dead_bytes(),
            side_metadata.total_bytes,
            mark_scratch_bytes,
        );
        Ok(NonmovingReclaimProjection {
            roots: roots.len() as u64,
            reachable_objects: reachable.len() as u64,
            allocated_objects: objects as u64,
            pages,
            dead_list_spine_bytes,
            registries,
            hashes,
            ambiguous_words: ambiguous_projection,
            side_metadata,
            mark_scratch_bytes,
            rss_bytes,
            adjusted_rss_bytes: chronology.post_reclaim_rss_bytes,
            collection_peak_bytes: chronology.collection_peak_bytes,
            adjusted_peak_bytes: chronology.chronological_peak_bytes,
            raw_peak_bytes: peak_rss_bytes,
            samples: 1,
            count_monotonic: true,
            independent_capture,
        })
    }

    fn traceable_allocation_directory(&self) -> Result<Vec<TraceableAllocation>, EvalHeapError> {
        let capacity = self
            .flat
            .len()
            .saturating_add(self.flat_lists.len())
            .saturating_add(self.flat_attrs.len())
            .saturating_add(self.flat_closures.len())
            .saturating_add(self.typed_thunk_heads.len());
        let mut allocations = Vec::new();
        allocations.try_reserve_exact(capacity).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: ALLOCATION_DIRECTORY_TABLE,
                entries: capacity,
            }
        })?;
        let mut push = |ptr: NonNull<HeapObject>, bytes: usize, tag: ValueTag| {
            let index = self.flat_arena.index_for_pointer(ptr).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: ALLOCATION_DIRECTORY_TABLE,
                },
            )?;
            allocations.push(TraceableAllocation {
                address: ptr.as_ptr() as usize,
                index: index.raw(),
                bytes,
                tag,
            });
            Ok::<(), EvalHeapError>(())
        };
        for object in self.flat.iter() {
            let tag = match object.object().kind() {
                FlatObjectKind::String => ValueTag::String,
                FlatObjectKind::Path => ValueTag::Path,
                _ => {
                    return Err(EvalHeapError::RootScanLengthOverflow {
                        table: ALLOCATION_DIRECTORY_TABLE,
                    });
                }
            };
            push(object.ptr(), object.size_bytes(), tag)?;
        }
        for object in self.flat_lists.iter() {
            push(object.ptr(), object.size_bytes(), ValueTag::List)?;
        }
        for object in self.flat_attrs.iter() {
            push(object.ptr(), object.size_bytes(), ValueTag::Attrs)?;
        }
        for object in self.flat_closures.iter() {
            let payload = object.object().payload();
            if !payload.is_retired() {
                push(object.ptr(), object.size_bytes(), payload.tag())?;
            }
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            let ptr = NonNull::new(address as *mut HeapObject).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: ALLOCATION_DIRECTORY_TABLE,
                },
            )?;
            push(ptr, bytes, ValueTag::Thunk)?;
        }
        allocations.sort_unstable_by_key(|allocation| allocation.index);
        if allocations
            .windows(2)
            .any(|pair| pair[0].index == pair[1].index)
        {
            return Err(EvalHeapError::RootScanLengthOverflow {
                table: ALLOCATION_DIRECTORY_TABLE,
            });
        }
        Ok(allocations)
    }

    fn registry_projection(&self, reachable: &HashSet<usize>) -> RegistryProjection {
        let project = |capacity: usize, live: usize| MetadataProjection {
            current: capacity.saturating_mul(FLAT_REGISTRY_ENTRY_BYTES) as u64,
            live_sized: live.saturating_mul(FLAT_REGISTRY_ENTRY_BYTES) as u64,
        };
        RegistryProjection {
            strings_paths: project(
                self.flat.registry_capacity(),
                self.flat
                    .iter()
                    .filter(|entry| reachable.contains(&(entry.ptr().as_ptr() as usize)))
                    .count(),
            ),
            lists: project(
                self.flat_lists.registry_capacity(),
                self.flat_lists
                    .iter()
                    .filter(|entry| reachable.contains(&(entry.ptr().as_ptr() as usize)))
                    .count(),
            ),
            attrs: project(
                self.flat_attrs.registry_capacity(),
                self.flat_attrs
                    .iter()
                    .filter(|entry| reachable.contains(&(entry.ptr().as_ptr() as usize)))
                    .count(),
            ),
            closures: project(
                self.flat_closures.registry_capacity(),
                self.flat_closures
                    .iter()
                    .filter(|entry| reachable.contains(&(entry.ptr().as_ptr() as usize)))
                    .count(),
            ),
        }
    }
}

fn hash_projection(
    table: &HashConsTable<HotXxh3Hash, Value>,
    reachable: &HashSet<usize>,
) -> Result<HashProjection, EvalHeapError> {
    let (buckets, bucket_capacity, candidates, candidate_capacity) = table.storage_counts();
    let mut live_keys = HashSet::new();
    let mut live_candidates = 0usize;
    for (key, _index, value) in table.committed_entries() {
        let (_tag, ptr) = any_value_heap_ptr(*value)?;
        if reachable.contains(&(ptr.as_ptr() as usize)) {
            live_candidates = live_candidates.saturating_add(1);
            live_keys.insert(*key);
        }
    }
    let live_buckets = live_keys.len();
    Ok(HashProjection {
        buckets: buckets as u64,
        candidates: candidates as u64,
        live_buckets: live_buckets as u64,
        live_candidates: live_candidates as u64,
        metadata: MetadataProjection {
            current: bucket_capacity
                .saturating_mul(HASH_BUCKET_SLOT_BYTES)
                .saturating_add(candidate_capacity.saturating_mul(std::mem::size_of::<Value>()))
                as u64,
            live_sized: live_buckets
                .saturating_mul(HASH_BUCKET_SLOT_BYTES)
                .saturating_add(live_candidates.saturating_mul(std::mem::size_of::<Value>()))
                as u64,
        },
    })
}

fn filter_ambiguous_words(
    words: &[u64],
    domain: Option<crate::heap::ArenaDomainId>,
    allocations: &[TraceableAllocation],
) -> Result<(Vec<Value>, AmbiguousWordProjection), EvalHeapError> {
    let mut projection = AmbiguousWordProjection {
        words: words.len() as u64,
        ..AmbiguousWordProjection::default()
    };
    let Some(domain) = domain else {
        return Ok((Vec::new(), projection));
    };
    let mut unique = HashSet::new();
    unique
        .try_reserve(words.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: "nonmoving ambiguous root uniqueness",
            entries: words.len(),
        })?;
    let mut roots = Vec::new();
    roots
        .try_reserve(words.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: "nonmoving ambiguous root values",
            entries: words.len(),
        })?;
    for raw in words {
        let Ok(word) = CompressedValueWord::from_raw(*raw) else {
            continue;
        };
        projection.codec_valid = projection.codec_valid.saturating_add(1);
        let (Some(candidate_domain), Some(index)) = (word.arena_domain(), word.arena_index())
        else {
            continue;
        };
        projection.indexed = projection.indexed.saturating_add(1);
        if candidate_domain != domain {
            continue;
        }
        projection.same_domain = projection.same_domain.saturating_add(1);
        let Ok(position) =
            allocations.binary_search_by_key(&index.raw(), |allocation| allocation.index)
        else {
            continue;
        };
        projection.exact_start = projection.exact_start.saturating_add(1);
        if allocations[position].tag != word.semantic_tag() {
            continue;
        }
        projection.kind_match = projection.kind_match.saturating_add(1);
        if unique.insert(word.raw()) {
            roots.push(Value::from_word(word));
        }
    }
    projection.unique_roots = roots.len() as u64;
    Ok((roots, projection))
}

fn exact_resident_dead_pages(
    pages: &[usize],
    mut page_is_resident: impl FnMut(usize) -> Option<bool>,
) -> (u64, bool) {
    let mut resident = 0u64;
    for page in pages {
        match page_is_resident(*page) {
            Some(true) => resident = resident.saturating_add(1),
            Some(false) => {}
            None => return (0, false),
        }
    }
    (resident, true)
}

fn side_metadata_projection(
    low_used_bytes: usize,
    high_used_bytes: usize,
    page_size: usize,
) -> SideMetadataProjection {
    let lane_bits = |bytes: usize, unit: u64| {
        let bytes = bytes as u64;
        let units = bytes.div_ceil(unit);
        units.div_ceil(8)
    };
    let allocation_start_bytes = lane_bits(low_used_bytes, ALLOCATION_GRANULE_BYTES)
        .saturating_add(lane_bits(high_used_bytes, ALLOCATION_GRANULE_BYTES));
    let mark_bytes = allocation_start_bytes;
    let line_bytes = lane_bits(low_used_bytes, IMMIX_LINE_BYTES)
        .saturating_add(lane_bits(high_used_bytes, IMMIX_LINE_BYTES));
    let page_bytes = if page_size == 0 {
        0
    } else {
        lane_bits(low_used_bytes, page_size as u64)
            .saturating_add(lane_bits(high_used_bytes, page_size as u64))
    };
    SideMetadataProjection {
        allocation_start_bytes,
        mark_bytes,
        line_bytes,
        page_bytes,
        total_bytes: allocation_start_bytes
            .saturating_add(mark_bytes)
            .saturating_add(line_bytes)
            .saturating_add(page_bytes),
    }
}

fn chronological_peak_projection(
    current_rss_bytes: u64,
    pre_probe_peak_rss_bytes: u64,
    resident_reclaimable_bytes: u64,
    persistent_side_metadata_bytes: u64,
    collection_scratch_bytes: u64,
) -> ChronologicalPeakProjection {
    let post_reclaim_rss_bytes = current_rss_bytes
        .saturating_sub(resident_reclaimable_bytes)
        .saturating_add(persistent_side_metadata_bytes);
    let collection_peak_bytes = current_rss_bytes
        .saturating_add(persistent_side_metadata_bytes)
        .saturating_add(collection_scratch_bytes);
    ChronologicalPeakProjection {
        post_reclaim_rss_bytes,
        collection_peak_bytes,
        chronological_peak_bytes: pre_probe_peak_rss_bytes
            .max(collection_peak_bytes)
            .max(post_reclaim_rss_bytes),
    }
}

fn mark_pages(pages: &mut HashSet<usize>, address: usize, bytes: usize, page_bytes: usize) {
    if bytes == 0 || page_bytes == 0 {
        return;
    }
    let first = address / page_bytes;
    let last = address.saturating_add(bytes.saturating_sub(1)) / page_bytes;
    for page in first..=last {
        pages.insert(page);
    }
}

fn coalesced_page_runs(pages: &[usize]) -> (u64, u64) {
    let Some(_first) = pages.first() else {
        return (0, 0);
    };
    let mut runs = 1u64;
    let mut current = 1u64;
    let mut largest = 1u64;
    for pair in pages.windows(2) {
        if pair[1] == pair[0].saturating_add(1) {
            current = current.saturating_add(1);
            largest = largest.max(current);
        } else {
            runs = runs.saturating_add(1);
            current = 1;
        }
    }
    (runs, largest)
}

fn projected_mark_scratch(objects: usize, reachable: usize, pages: usize) -> u64 {
    objects
        .saturating_mul(std::mem::size_of::<u32>())
        .saturating_add(objects.saturating_add(7) / 8)
        .saturating_add(reachable.saturating_mul(std::mem::size_of::<u32>()))
        .saturating_add(pages.saturating_add(7) / 8) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_disjoint_dead_page_runs() {
        assert_eq!(coalesced_page_runs(&[1, 2, 3, 5, 8, 9]), (3, 3));
        assert_eq!(coalesced_page_runs(&[]), (0, 0));
    }

    #[test]
    fn exact_dead_page_residency_credits_only_resident_pages() {
        let (resident, exact) = exact_resident_dead_pages(&[2, 4, 6], |page| Some(page != 4));
        assert_eq!(resident, 2);
        assert!(exact);
    }

    #[test]
    fn dead_page_residency_fails_closed_on_one_missing_query() {
        assert_eq!(
            exact_resident_dead_pages(&[2, 4, 6], |page| (page != 4).then_some(true)),
            (0, false)
        );
    }

    #[test]
    fn side_metadata_rounds_each_used_lane_independently() {
        let projection = side_metadata_projection(9, 8, 4096);
        assert_eq!(projection.allocation_start_bytes, 2);
        assert_eq!(projection.mark_bytes, 2);
        assert_eq!(projection.line_bytes, 2);
        assert_eq!(projection.page_bytes, 2);
        assert_eq!(projection.total_bytes, 8);
    }

    #[test]
    fn chronology_never_repairs_an_existing_peak() {
        let projection = chronological_peak_projection(200, 300, 100, 10, 20);
        assert_eq!(projection.post_reclaim_rss_bytes, 110);
        assert_eq!(projection.collection_peak_bytes, 230);
        assert_eq!(projection.chronological_peak_bytes, 300);
    }

    #[test]
    fn chronology_charges_collection_overlap_before_reclamation() {
        let projection = chronological_peak_projection(200, 180, 500, 10, 20);
        assert_eq!(projection.post_reclaim_rss_bytes, 10);
        assert_eq!(projection.collection_peak_bytes, 230);
        assert_eq!(projection.chronological_peak_bytes, 230);
    }

    #[test]
    fn ambiguous_words_require_domain_start_and_kind() {
        let domain = crate::heap::ArenaDomainId::allocate_logical().expect("test domain allocates");
        let other = crate::heap::ArenaDomainId::allocate_logical().expect("other domain allocates");
        let allocation = TraceableAllocation {
            address: 0x1000,
            index: 64,
            bytes: 32,
            tag: ValueTag::String,
        };
        let accepted =
            CompressedValueWord::heap(domain, ValueTag::String, crate::heap::ArenaIndex::new(64))
                .expect("string word encodes");
        let wrong_domain =
            CompressedValueWord::heap(other, ValueTag::String, crate::heap::ArenaIndex::new(64))
                .expect("other-domain word encodes");
        let interior =
            CompressedValueWord::heap(domain, ValueTag::String, crate::heap::ArenaIndex::new(72))
                .expect("interior word encodes");
        let wrong_kind =
            CompressedValueWord::heap(domain, ValueTag::List, crate::heap::ArenaIndex::new(64))
                .expect("wrong-kind word encodes");
        let invalid = u64::MAX;
        let inline = CompressedValueWord::null();
        let words = [
            accepted.raw(),
            accepted.raw(),
            wrong_domain.raw(),
            interior.raw(),
            wrong_kind.raw(),
            invalid,
            inline.raw(),
        ];

        let (roots, projection) = filter_ambiguous_words(&words, Some(domain), &[allocation])
            .expect("filtering succeeds");

        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].word(), accepted);
        assert_eq!(projection.words, 7);
        assert_eq!(projection.codec_valid, 6);
        assert_eq!(projection.indexed, 5);
        assert_eq!(projection.same_domain, 4);
        assert_eq!(projection.exact_start, 3);
        assert_eq!(projection.kind_match, 2);
        assert_eq!(projection.unique_roots, 1);
    }

    #[test]
    fn ambiguous_words_decline_without_a_reservation_domain() {
        let (roots, projection) =
            filter_ambiguous_words(&[CompressedValueWord::null().raw()], None, &[])
                .expect("missing domain declines");
        assert!(roots.is_empty());
        assert_eq!(projection.words, 1);
        assert_eq!(projection.codec_valid, 0);
    }

    #[test]
    fn heap_projection_sees_dead_list_spine_and_live_registry() {
        let mut heap = EvalHeap::new();
        let live = heap
            .alloc_string(NixString::from_bytes(b"live".to_vec()))
            .expect("live string allocates");
        heap.alloc_list(NixList::new(vec![live; 64]))
            .expect("dead list allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, live)
            .expect("live root records");
        let result = heap
            .nonmoving_reclaim_projection(&roots, 1024 * 1024, 1024 * 1024, 512, true, &[])
            .expect("projection succeeds");
        assert_eq!(result.reachable_objects, 1);
        assert!(result.allocated_objects >= 2);
        assert!(result.dead_list_spine_bytes >= 64 * std::mem::size_of::<Value>() as u64);
        assert!(
            result.registries.strings_paths.current >= result.registries.strings_paths.live_sized
        );
        assert!(result.pages.dead <= result.pages.total);
    }

    #[test]
    fn heap_projection_traces_an_exact_ambiguous_root() {
        let mut heap = EvalHeap::new();
        let ambiguous = heap
            .alloc_string(NixString::from_bytes(b"ambiguous".to_vec()))
            .expect("ambiguous string allocates");
        let result = heap
            .nonmoving_reclaim_projection(
                &EvalRootSet::new(),
                1024 * 1024,
                1024 * 1024,
                512,
                true,
                &[ambiguous.payload_bits()],
            )
            .expect("projection succeeds");

        assert_eq!(result.ambiguous_words.unique_roots, 1);
        assert_eq!(result.ambiguous_words.already_precise_reachable, 0);
        assert_eq!(result.ambiguous_words.newly_reachable_objects, 1);
        assert_eq!(result.reachable_objects, 1);
    }

    #[test]
    fn strict_registry_credit_excludes_closure_capacity() {
        let registries = RegistryProjection {
            strings_paths: MetadataProjection {
                current: 80,
                live_sized: 32,
            },
            lists: MetadataProjection {
                current: 64,
                live_sized: 16,
            },
            attrs: MetadataProjection {
                current: 48,
                live_sized: 32,
            },
            closures: MetadataProjection {
                current: 4096,
                live_sized: 16,
            },
        };

        assert_eq!(registries.strict_reclaimable(), 48 + 48 + 16);
        assert_ne!(
            registries.strict_reclaimable(),
            registries
                .strict_reclaimable()
                .saturating_add(registries.closures.reclaimable())
        );
    }
}
