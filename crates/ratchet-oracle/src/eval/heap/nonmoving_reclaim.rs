//! Read-only projection of nonmoving dead-page retirement.
//!
//! The probe uses the evaluator's storage-aware weak graph to project
//! invalidating dead weak candidates, dropping dead-owned list spines,
//! shrinking weak metadata, and advising pages containing no live arena
//! object. It never mutates the heap or root set.
//!
//! Reservation residency is currently aggregate. Consequently, physical page
//! credit is granted only when every used reservation page was resident at the
//! sample; otherwise logical dead pages are reported with zero RSS credit.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Mutex, OnceLock};

use super::arena::any_value_heap_ptr;
use super::*;

const DEFAULT_PAGE_BYTES: usize = 4096;
const TARGET_RSS_BYTES: u64 = 233_972 * 1024;
const SAFETY_RSS_BYTES: u64 = 216 * 1024 * 1024;
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
    full_residency: bool,
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
    mark_scratch_bytes: u64,
    rss_bytes: u64,
    adjusted_rss_bytes: u64,
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
             \"full_used_reservation_resident\":{}}},\
             \"dead_owned_external\":{{\"list_spine_bytes\":{},\
             \"coverage\":\"list_capacity_only\"}},\
             \"registries\":{{\
             \"strings_paths\":[{},{},{},true],\"lists\":[{},{},{},true],\
             \"attrs\":[{},{},{},true],\"closures\":[{},{},{},false],\
             \"tuple\":\"current_structural_bytes,live_sized_structural_bytes,\
             reclaimable_bytes,credited_to_strict_schedule\",\
             \"strict_reclaimable_bytes\":{},\
             \"closure_exclusion\":\"tail handles embed store_index; shrinking requires \
             re-signing live handles and roots\"}},\
             \"hash_indexes\":{{\"current_buckets\":{},\"current_candidates\":{},\
             \"live_buckets\":{},\"live_candidates\":{},\
             \"current_structural_bytes\":{},\"live_sized_structural_bytes\":{},\
             \"reclaimable_bytes\":{},\"credited_to_strict_schedule\":false}},\
             \"mark\":{{\"projected_scratch_bytes\":{},\
             \"layout\":\"u32 object starts + object bits + u32 worklist + page bits\"}},\
             \"schedule\":{{\"rss_bytes\":{},\"adjusted_rss_bytes\":{},\
             \"adjusted_peak_bytes\":{},\"raw_peak_bytes\":{},\"samples\":{},\
             \"dead_page_count_monotonic\":{},\"target_bytes\":{},\"target_pass\":{},\
             \"safety_bytes\":{},\"safety_pass\":{},\"capture_mode\":\"{}\"}},\
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
            self.pages.full_residency,
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
            self.rss_bytes,
            self.adjusted_rss_bytes,
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReclaimSchedule {
    last_modules: usize,
    last_dead_pages: u64,
    adjusted_peak: u64,
    raw_peak: u64,
    samples: u64,
    monotonic: bool,
}

impl ReclaimSchedule {
    fn observe(
        &mut self,
        modules: usize,
        rss: u64,
        reclaimable: u64,
        scratch: u64,
        dead_pages: u64,
    ) -> (u64, u64, u64, u64, bool) {
        if self.samples != 0 && modules <= self.last_modules {
            *self = Self::default();
        }
        let adjusted = rss.saturating_sub(reclaimable).saturating_add(scratch);
        let current_monotonic = self.samples == 0 || dead_pages >= self.last_dead_pages;
        self.monotonic = (self.samples == 0 || self.monotonic) && current_monotonic;
        self.adjusted_peak = self.adjusted_peak.max(adjusted);
        self.raw_peak = self.raw_peak.max(rss);
        self.samples = self.samples.saturating_add(1);
        self.last_modules = modules;
        self.last_dead_pages = dead_pages;
        (
            adjusted,
            self.adjusted_peak,
            self.raw_peak,
            self.samples,
            self.monotonic,
        )
    }
}

static SCHEDULE: OnceLock<Mutex<ReclaimSchedule>> = OnceLock::new();

impl EvalHeap {
    /// Projects nonmoving reclamation and its carried adjusted-RSS schedule.
    ///
    /// Hash-cons tables do not seed reachability. Reported external and
    /// metadata savings are conservative structural lower bounds.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if weak traversal finds a stale root, malformed
    /// edge, invalid thunk state, or cannot grow scanner storage.
    pub(crate) fn nonmoving_reclaim_projection(
        &self,
        roots: &EvalRootSet,
        rss_bytes: u64,
        modules: usize,
        independent_capture: bool,
    ) -> Result<NonmovingReclaimProjection, EvalHeapError> {
        let reachable = self.weak_reachable_addresses(roots)?;
        let residency = self.flat_reservation_residency();
        let page_bytes = residency
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map_or(DEFAULT_PAGE_BYTES, |sample| sample.page_size);
        let full_residency = residency
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .is_some_and(|sample| sample.total_pages == sample.total_resident_pages);
        let mut total_pages = HashSet::new();
        let mut live_pages = HashSet::new();
        let mut objects = 0usize;
        let mut dead_list_spine_bytes = 0u64;

        let mut extent = |address: usize, bytes: usize, live: bool| {
            objects = objects.saturating_add(1);
            mark_pages(&mut total_pages, address, bytes, page_bytes);
            if live {
                mark_pages(&mut live_pages, address, bytes, page_bytes);
            }
        };
        for object in self.flat.iter() {
            let address = object.ptr().as_ptr() as usize;
            extent(address, object.size_bytes(), reachable.contains(&address));
        }
        for object in self.flat_lists.iter() {
            let address = object.ptr().as_ptr() as usize;
            let live = reachable.contains(&address);
            extent(address, object.size_bytes(), live);
            if !live {
                dead_list_spine_bytes = dead_list_spine_bytes.saturating_add(
                    (object.object().payload().capacity() as u64)
                        .saturating_mul(std::mem::size_of::<Value>() as u64),
                );
            }
        }
        for object in self.flat_attrs.iter() {
            let address = object.ptr().as_ptr() as usize;
            extent(address, object.size_bytes(), reachable.contains(&address));
        }
        for object in self.flat_closures.iter() {
            let address = object.ptr().as_ptr() as usize;
            extent(address, object.size_bytes(), reachable.contains(&address));
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            extent(address, bytes, reachable.contains(&address));
        }
        let mut scalar_regions = Vec::new();
        self.compressed_scalars
            .append_cell_regions(0, &mut scalar_regions);
        for (address, bytes) in scalar_regions {
            extent(address, bytes, true);
        }

        let mut dead_pages: Vec<_> = total_pages.difference(&live_pages).copied().collect();
        dead_pages.sort_unstable();
        let (runs, largest_run) = coalesced_page_runs(&dead_pages);
        let pages = DeadPageProjection {
            total: total_pages.len() as u64,
            live: live_pages.len() as u64,
            dead: dead_pages.len() as u64,
            runs,
            largest_run,
            resident_dead: if full_residency {
                dead_pages.len() as u64
            } else {
                0
            },
            page_bytes: page_bytes as u64,
            full_residency,
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
        objects = objects.saturating_add(
            self.records
                .iter()
                .filter(|record| !record.is_retired())
                .count(),
        );
        let mark_scratch_bytes =
            projected_mark_scratch(objects, reachable.len(), total_pages.len());
        let reclaimable = pages
            .resident_dead_bytes()
            .saturating_add(dead_list_spine_bytes)
            .saturating_add(registries.strict_reclaimable());
        let schedule = SCHEDULE.get_or_init(|| Mutex::new(ReclaimSchedule::default()));
        let (adjusted_rss_bytes, adjusted_peak_bytes, raw_peak_bytes, samples, count_monotonic) =
            match schedule.lock() {
                Ok(mut state) => {
                    if independent_capture {
                        *state = ReclaimSchedule::default();
                    }
                    state.observe(
                        modules,
                        rss_bytes,
                        reclaimable,
                        mark_scratch_bytes,
                        pages.dead,
                    )
                }
                Err(poisoned) => {
                    let mut state = poisoned.into_inner();
                    if independent_capture {
                        *state = ReclaimSchedule::default();
                    }
                    state.observe(
                        modules,
                        rss_bytes,
                        reclaimable,
                        mark_scratch_bytes,
                        pages.dead,
                    )
                }
            };
        Ok(NonmovingReclaimProjection {
            roots: roots.len() as u64,
            reachable_objects: reachable.len() as u64,
            allocated_objects: objects as u64,
            pages,
            dead_list_spine_bytes,
            registries,
            hashes,
            mark_scratch_bytes,
            rss_bytes,
            adjusted_rss_bytes,
            adjusted_peak_bytes,
            raw_peak_bytes,
            samples,
            count_monotonic,
            independent_capture,
        })
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
    fn schedule_carries_peak_and_resets_for_a_new_evaluator() {
        let mut schedule = ReclaimSchedule::default();
        assert_eq!(
            schedule.observe(512, 300, 100, 10, 20),
            (210, 210, 300, 1, true)
        );
        assert_eq!(
            schedule.observe(768, 400, 250, 10, 25),
            (160, 210, 400, 2, true)
        );
        assert_eq!(schedule.observe(64, 90, 30, 5, 2), (65, 65, 90, 1, true));
    }

    #[test]
    fn adjusted_rss_saturates_before_adding_mark_scratch() {
        let mut schedule = ReclaimSchedule::default();
        assert_eq!(schedule.observe(512, 10, 100, 7, 1).0, 7);
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
            .nonmoving_reclaim_projection(&roots, 1024 * 1024, 512, true)
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
