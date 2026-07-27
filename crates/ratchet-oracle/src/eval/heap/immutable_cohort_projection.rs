//! Read-only projection of all-object immutable cohort packing.
//!
//! Unlike a reachability evacuation, this diagnostic classifies every serial
//! heap object. Immutable objects are assigned conservative headerless layouts;
//! mutable objects remain pinned. Because the modeled representation preserves
//! one stable handle per object, the projection does not assume that recursive
//! Rust locals have been published as collector roots.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ptr::NonNull;
use std::sync::Arc;

use crate::eval::env::{EvalEnv, EvalFrame};
use crate::eval::thunk::ThunkState;

use super::*;

const PAGE_BYTES: usize = 4096;
const HANDLE_BYTES: usize = 8;
const FORWARDING_SCRATCH_BYTES: usize = 12;
const ENGINEERING_GATE_BYTES: usize = 226_492_416;
const NAMED_STATE_GATE_BYTES: usize = 92_609 * 1024 * 1024 / 1000;

/// A stable fingerprint for one object projected as immutable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ImmutableCohortFingerprint {
    /// Source address, used only as a diagnostic identity.
    pub(crate) address: usize,
    /// Fingerprint of observable payload words and immutable metadata.
    pub(crate) fingerprint: u64,
}

/// All-object packing accounting at one chronological checkpoint.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ImmutableCohortProjection {
    /// Immutable objects eligible for headerless packing.
    pub(crate) freezable_objects: usize,
    /// Mutable or conservatively retained objects.
    pub(crate) pinned_objects: usize,
    /// Objects whose storage kind was not classified.
    pub(crate) unclassified_objects: usize,
    /// Current inline and known external bytes of freezable objects.
    pub(crate) freezable_current_bytes: usize,
    /// Conservative packed bytes for freezable objects.
    pub(crate) compact_bytes: usize,
    /// Current bytes charged to pinned objects and known payloads.
    pub(crate) pinned_bytes: usize,
    /// Bytes for one stable routing entry per classified object.
    pub(crate) handle_table_bytes: usize,
    /// Rebuilt weak-index bytes at a load factor no greater than 0.75.
    pub(crate) weak_index_bytes: usize,
    /// Temporary forwarding/fingerprint scratch.
    pub(crate) scratch_bytes: usize,
    /// Source pages containing freezable objects and no pinned object.
    pub(crate) releasable_source_page_bytes: usize,
    /// Known separately allocated payload bytes released by packing.
    pub(crate) releasable_external_bytes: usize,
    /// Maximum destination-minus-released-source bytes during address-order streaming.
    pub(crate) streaming_net_peak_bytes: usize,
    /// Immutable payload fingerprints for later mutation checks.
    pub(crate) fingerprints: Vec<ImmutableCohortFingerprint>,
}

impl ImmutableCohortProjection {
    /// Returns the total modeled bytes released after publication.
    pub(crate) const fn released_bytes(&self) -> usize {
        self.releasable_source_page_bytes
            .saturating_add(self.releasable_external_bytes)
    }

    /// Returns the persistent bytes added by stable routing and packed storage.
    pub(crate) const fn installed_bytes(&self) -> usize {
        self.compact_bytes
            .saturating_add(self.handle_table_bytes)
            .saturating_add(self.weak_index_bytes)
    }

    /// Projects the post-publication process RSS from an observed RSS.
    pub(crate) const fn projected_post_rss(&self, current_rss: usize) -> usize {
        current_rss
            .saturating_sub(self.released_bytes())
            .saturating_add(self.installed_bytes())
    }

    /// Projects the address-order streaming watermark from an observed RSS.
    pub(crate) const fn projected_streaming_peak_rss(&self, current_rss: usize) -> usize {
        current_rss
            .saturating_add(self.handle_table_bytes)
            .saturating_add(self.weak_index_bytes)
            .saturating_add(self.scratch_bytes)
            .saturating_add(self.streaming_net_peak_bytes)
    }
}

impl fmt::Display for ImmutableCohortProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\"freezable_objects\":{},\"pinned_objects\":{},\
             \"unclassified_objects\":{},\"freezable_current_bytes\":{},\
             \"compact_bytes\":{},\"pinned_bytes\":{},\"handle_table_bytes\":{},\
             \"weak_index_bytes\":{},\"scratch_bytes\":{},\
             \"releasable_source_page_bytes\":{},\"releasable_external_bytes\":{},\
             \"streaming_net_peak_bytes\":{},\"engineering_gate_bytes\":{},\
             \"named_state_gate_bytes\":{},\"named_state_bytes\":{},\
             \"named_state_pass\":{},\"classification_pass\":{}}}",
            self.freezable_objects,
            self.pinned_objects,
            self.unclassified_objects,
            self.freezable_current_bytes,
            self.compact_bytes,
            self.pinned_bytes,
            self.handle_table_bytes,
            self.weak_index_bytes,
            self.scratch_bytes,
            self.releasable_source_page_bytes,
            self.releasable_external_bytes,
            self.streaming_net_peak_bytes,
            ENGINEERING_GATE_BYTES,
            NAMED_STATE_GATE_BYTES,
            self.installed_bytes().saturating_add(self.pinned_bytes),
            self.installed_bytes().saturating_add(self.pinned_bytes) <= NAMED_STATE_GATE_BYTES,
            self.unclassified_objects == 0,
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PageProjection {
    pinned: bool,
    compact_bytes: usize,
}

impl EvalHeap {
    /// Projects every current serial object into immutable packed or pinned storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when a typed thunk head cannot be resolved or
    /// its state cannot be read.
    pub(crate) fn immutable_cohort_projection(
        &self,
    ) -> Result<ImmutableCohortProjection, EvalHeapError> {
        let mut result = ImmutableCohortProjection::default();
        let mut pages = HashMap::<usize, PageProjection>::new();
        let mut frames = HashSet::<*const EvalFrame>::new();
        let mut weak_entries = 0usize;

        for record in &self.records {
            if record.is_retired() {
                continue;
            }
            result.pinned_objects = result.pinned_objects.saturating_add(1);
            result.pinned_bytes = result.pinned_bytes.saturating_add(record.layout.size_bytes);
            note_pages(
                &mut pages,
                record.ptr.as_ptr() as usize,
                record.layout.size_bytes,
                true,
                0,
            );
        }
        for object in self.flat.iter() {
            let string = object.object().payload();
            let compact = align8(8usize.saturating_add(string.len()));
            note_freezable(
                &mut result,
                &mut pages,
                object.ptr().as_ptr() as usize,
                object.size_bytes(),
                0,
                compact,
                fingerprint_bytes(string.bytes()),
            );
            weak_entries = weak_entries.saturating_add(1);
        }
        for object in self.flat_lists.iter() {
            let list = object.object().payload();
            let external = list.capacity().saturating_mul(std::mem::size_of::<Value>());
            let compact = align8(
                8usize.saturating_add(list.len().saturating_mul(std::mem::size_of::<Value>())),
            );
            note_freezable(
                &mut result,
                &mut pages,
                object.ptr().as_ptr() as usize,
                object.size_bytes(),
                external,
                compact,
                fingerprint_values(list.as_slice()),
            );
            weak_entries = weak_entries.saturating_add(1);
        }
        for object in self.flat_attrs.iter() {
            let attrs = &object.object().payload().attrs;
            let compact = align8(8usize.saturating_add(attrs.len().saturating_mul(32)));
            let mut fingerprint = mix(0, attrs.len() as u64);
            for entry in attrs.iter_lexicographic() {
                fingerprint = mix(fingerprint, u64::from(entry.key.as_u32()));
                fingerprint = mix(fingerprint, entry.value.payload_bits());
            }
            note_freezable(
                &mut result,
                &mut pages,
                object.ptr().as_ptr() as usize,
                object.size_bytes(),
                0,
                compact,
                fingerprint,
            );
            weak_entries = weak_entries.saturating_add(1);
        }
        for object in self.flat_closures.iter() {
            let address = object.ptr().as_ptr() as usize;
            let bytes = object.size_bytes();
            match object.object().payload() {
                FlatClosurePayload::Thunk(thunk)
                    if thunk.cell().state() == Ok(ThunkState::Forced) =>
                {
                    note_forced_thunk(&mut result, &mut pages, address, bytes, thunk);
                    charge_env(thunk.env(), &mut frames, &mut result);
                }
                FlatClosurePayload::SharedThunk(thunk)
                    if thunk.cell().state() == Ok(ThunkState::Forced) =>
                {
                    note_forced_thunk(&mut result, &mut pages, address, bytes, thunk);
                    charge_env(thunk.env(), &mut frames, &mut result);
                }
                FlatClosurePayload::Retired(_) => {}
                FlatClosurePayload::Thunk(thunk) => {
                    note_pinned(&mut result, &mut pages, address, bytes);
                    charge_env(thunk.env(), &mut frames, &mut result);
                }
                FlatClosurePayload::SharedThunk(thunk) => {
                    note_pinned(&mut result, &mut pages, address, bytes);
                    charge_env(thunk.env(), &mut frames, &mut result);
                }
                FlatClosurePayload::Lambda(lambda) => {
                    note_pinned(&mut result, &mut pages, address, bytes);
                    charge_env(Some(lambda.env()), &mut frames, &mut result);
                }
                FlatClosurePayload::Primop(primop) => {
                    note_pinned(&mut result, &mut pages, address, bytes);
                    result.pinned_bytes = result.pinned_bytes.saturating_add(
                        primop
                            .args()
                            .len()
                            .saturating_mul(std::mem::size_of::<EvalPrimOpArg>()),
                    );
                }
            }
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            let Some(ptr) = NonNull::new(address as *mut HeapObject) else {
                result.unclassified_objects = result.unclassified_objects.saturating_add(1);
                continue;
            };
            let Ok(head) = self.typed_thunk_heads.resolve(ptr) else {
                result.unclassified_objects = result.unclassified_objects.saturating_add(1);
                continue;
            };
            if head.state() == Some(ThunkState::Forced) {
                let cached = head
                    .published_value()
                    .ok()
                    .flatten()
                    .map_or(0, Value::payload_bits);
                note_freezable(
                    &mut result,
                    &mut pages,
                    address,
                    bytes,
                    0,
                    8,
                    mix(ThunkState::Forced.as_u64(), cached),
                );
            } else {
                note_pinned(&mut result, &mut pages, address, bytes);
                if let Some(work) = self.typed_thunk_work_ref(ptr)? {
                    result.pinned_bytes = result
                        .pinned_bytes
                        .saturating_add(std::mem::size_of::<EvalThunk>());
                    charge_env(work.env(), &mut frames, &mut result);
                }
            }
        }

        let (boxed_scalars, boxed_payload_bytes) = self.boxed_scalar_census_totals();
        result.pinned_objects = result.pinned_objects.saturating_add(boxed_scalars);
        result.pinned_bytes = result.pinned_bytes.saturating_add(boxed_payload_bytes);
        let classified = result
            .freezable_objects
            .saturating_add(result.pinned_objects);
        result.handle_table_bytes = classified.saturating_mul(HANDLE_BYTES);
        result.scratch_bytes = result
            .freezable_objects
            .saturating_mul(FORWARDING_SCRATCH_BYTES);
        result.weak_index_bytes = weak_entries
            .saturating_mul(4)
            .saturating_add(2)
            .saturating_div(3)
            .saturating_mul(16);

        let mut page_rows = pages.into_iter().collect::<Vec<_>>();
        page_rows.sort_unstable_by_key(|(page, _)| *page);
        let mut installed = 0usize;
        let mut released = 0usize;
        let mut peak = 0usize;
        for (_, page) in page_rows {
            installed = installed.saturating_add(page.compact_bytes);
            if !page.pinned {
                released = released.saturating_add(PAGE_BYTES);
                result.releasable_source_page_bytes = result
                    .releasable_source_page_bytes
                    .saturating_add(PAGE_BYTES);
            }
            peak = peak.max(installed.saturating_sub(released));
        }
        result.streaming_net_peak_bytes = peak;
        Ok(result)
    }
}

fn note_freezable(
    result: &mut ImmutableCohortProjection,
    pages: &mut HashMap<usize, PageProjection>,
    address: usize,
    inline_bytes: usize,
    external_bytes: usize,
    compact_bytes: usize,
    fingerprint: u64,
) {
    result.freezable_objects = result.freezable_objects.saturating_add(1);
    result.freezable_current_bytes = result
        .freezable_current_bytes
        .saturating_add(inline_bytes)
        .saturating_add(external_bytes);
    result.compact_bytes = result.compact_bytes.saturating_add(compact_bytes);
    result.releasable_external_bytes = result
        .releasable_external_bytes
        .saturating_add(external_bytes);
    result.fingerprints.push(ImmutableCohortFingerprint {
        address,
        fingerprint,
    });
    note_pages(pages, address, inline_bytes, false, compact_bytes);
}

fn note_pinned(
    result: &mut ImmutableCohortProjection,
    pages: &mut HashMap<usize, PageProjection>,
    address: usize,
    bytes: usize,
) {
    result.pinned_objects = result.pinned_objects.saturating_add(1);
    result.pinned_bytes = result.pinned_bytes.saturating_add(bytes);
    note_pages(pages, address, bytes, true, 0);
}

fn note_forced_thunk(
    result: &mut ImmutableCohortProjection,
    pages: &mut HashMap<usize, PageProjection>,
    address: usize,
    bytes: usize,
    thunk: &EvalThunk,
) {
    let cached = thunk
        .cell()
        .cached_value()
        .ok()
        .flatten()
        .map_or(0, Value::payload_bits);
    note_freezable(
        result,
        pages,
        address,
        bytes,
        0,
        8,
        mix(ThunkState::Forced.as_u64(), cached),
    );
}

fn charge_env(
    env: Option<&EvalEnv>,
    frames: &mut HashSet<*const EvalFrame>,
    result: &mut ImmutableCohortProjection,
) {
    let Some(env) = env else {
        return;
    };
    for frame in env.frames().iter() {
        if frames.insert(Arc::as_ptr(frame)) {
            result.pinned_bytes = result.pinned_bytes.saturating_add(8).saturating_add(
                frame
                    .slot_count()
                    .saturating_mul(std::mem::size_of::<Value>()),
            );
        }
    }
}

fn note_pages(
    pages: &mut HashMap<usize, PageProjection>,
    address: usize,
    bytes: usize,
    pinned: bool,
    compact_bytes: usize,
) {
    if bytes == 0 {
        return;
    }
    let first = address / PAGE_BYTES;
    let last = address.saturating_add(bytes.saturating_sub(1)) / PAGE_BYTES;
    for page in first..=last {
        pages.entry(page).or_default().pinned |= pinned;
    }
    let row = pages.entry(first).or_default();
    row.compact_bytes = row.compact_bytes.saturating_add(compact_bytes);
}

fn fingerprint_bytes(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(*byte)
    })
}

fn fingerprint_values(values: &[Value]) -> u64 {
    values.iter().fold(values.len() as u64, |hash, value| {
        mix(hash, value.payload_bits())
    })
}

const fn mix(hash: u64, value: u64) -> u64 {
    hash.rotate_left(13) ^ value.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

const fn align8(bytes: usize) -> usize {
    bytes.saturating_add(7) & !7
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_classifies_immutable_data_and_mutable_thunks() {
        let mut heap = EvalHeap::new();
        heap.alloc_list(NixList::new(vec![Value::int(1), Value::int(2)]))
            .expect("list allocates");
        heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
            .expect("thunk allocates");

        let projection = heap
            .immutable_cohort_projection()
            .expect("projection succeeds");
        assert_eq!(projection.freezable_objects, 1);
        assert_eq!(projection.pinned_objects, 1);
        assert_eq!(projection.unclassified_objects, 0);
        assert_eq!(projection.fingerprints.len(), 1);
    }

    #[test]
    fn streaming_projection_releases_only_unpinned_pages() {
        let mut pages = HashMap::new();
        note_pages(&mut pages, PAGE_BYTES, 64, false, 16);
        note_pages(&mut pages, PAGE_BYTES + 128, 64, true, 0);
        note_pages(&mut pages, PAGE_BYTES * 2, 64, false, 16);
        let releasable = pages.values().filter(|page| !page.pinned).count();
        assert_eq!(releasable, 1);
    }

    #[test]
    fn projected_post_rss_charges_packed_state_and_releases_source() {
        let projection = ImmutableCohortProjection {
            compact_bytes: 100,
            handle_table_bytes: 20,
            weak_index_bytes: 30,
            releasable_source_page_bytes: 400,
            releasable_external_bytes: 50,
            ..ImmutableCohortProjection::default()
        };
        assert_eq!(projection.projected_post_rss(1_000), 700);
    }
}
