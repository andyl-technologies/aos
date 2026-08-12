//! Read-only projection of address-preserving virtual-page meshing.
//!
//! The projection assigns a 64-bit occupancy mask to each live 4 KiB arena
//! page, with one bit per 64-byte line. Two pages are constructively pairable
//! when their masks are disjoint. Mapping both virtual pages to one shared
//! physical page would then preserve every object address while removing one
//! physical page, provided retired holes are never reused.

use std::collections::HashMap;
use std::fmt;

use super::*;

const PAGE_BYTES: usize = 4096;
const LINE_BYTES: usize = 64;
const LINES_PER_PAGE: usize = PAGE_BYTES / LINE_BYTES;

/// Read-only accounting for one constructive page-meshing schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MeshProjection {
    roots: usize,
    reachable_objects: usize,
    live_pages: usize,
    occupied_lines: usize,
    max_line_frequency: usize,
    line_frequencies: [usize; LINES_PER_PAGE],
    cross_page_objects: usize,
    greedy_pairs: usize,
    greedy_bins: usize,
    line_bound_bins: usize,
}

impl Default for MeshProjection {
    fn default() -> Self {
        Self {
            roots: 0,
            reachable_objects: 0,
            live_pages: 0,
            occupied_lines: 0,
            max_line_frequency: 0,
            line_frequencies: [0; LINES_PER_PAGE],
            cross_page_objects: 0,
            greedy_pairs: 0,
            greedy_bins: 0,
            line_bound_bins: 0,
        }
    }
}

impl fmt::Display for MeshProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let certified_bins = self.line_bound_bins.max(self.max_line_frequency);
        let upper_bound_savings = self.live_pages.saturating_sub(certified_bins);
        let constructive_savings = self.live_pages.saturating_sub(self.greedy_bins);
        write!(
            f,
            "{{\"roots\":{},\"reachable_objects\":{},\"page_bytes\":{},\
             \"line_bytes\":{},\"live_pages\":{},\"occupied_lines\":{},\
             \"max_line_frequency\":{},\"line_frequencies\":{:?},\
             \"cross_page_objects\":{},\"constructive_greedy_pairs\":{},\
             \"constructive_greedy_bins\":{},\"constructive_page_savings\":{},\
             \"constructive_saved_bytes\":{},\"average_line_bound_bins\":{},\
             \"certified_bound_bins\":{},\
             \"line_bound_savings\":{},\
             \"semantics\":{{\"mutates_heap\":false,\"preserves_virtual_addresses\":true,\
             \"requires_retired_holes_never_reused\":true}}}}",
            self.roots,
            self.reachable_objects,
            PAGE_BYTES,
            LINE_BYTES,
            self.live_pages,
            self.occupied_lines,
            self.max_line_frequency,
            self.line_frequencies,
            self.cross_page_objects,
            self.greedy_pairs,
            self.greedy_bins,
            constructive_savings,
            constructive_savings.saturating_mul(PAGE_BYTES),
            self.line_bound_bins,
            certified_bins,
            upper_bound_savings,
        )
    }
}

impl EvalHeap {
    /// Projects compatible live-page pairs without mutating the heap.
    ///
    /// The constructive result is a valid pair-only lower bound. The line
    /// bound assumes arbitrary multi-page packing and is therefore only an
    /// upper bound on possible page savings.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the precise weak traversal encounters a
    /// stale root, malformed edge, or invalid thunk state.
    pub(crate) fn mesh_projection(
        &self,
        roots: &EvalRootSet,
    ) -> Result<MeshProjection, EvalHeapError> {
        let reachable = self.weak_reachable_addresses(roots)?;
        let mut masks = HashMap::<usize, u64>::new();
        let mut cross_page_objects = 0usize;

        let mut live_extent = |address: usize, bytes: usize| {
            if reachable.contains(&address) {
                if extent_crosses_page(address, bytes) {
                    cross_page_objects = cross_page_objects.saturating_add(1);
                }
                mark_extent_lines(&mut masks, address, bytes);
            }
        };
        for object in self.flat.iter() {
            live_extent(object.ptr().as_ptr() as usize, object.size_bytes());
        }
        for object in self.flat_lists.iter() {
            live_extent(object.ptr().as_ptr() as usize, object.size_bytes());
        }
        for object in self.flat_attrs.iter() {
            live_extent(object.ptr().as_ptr() as usize, object.size_bytes());
        }
        for object in self.flat_closures.iter() {
            live_extent(object.ptr().as_ptr() as usize, object.size_bytes());
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            live_extent(address, bytes);
        }

        // Boxed scalars are pinned and therefore always occupy their lines.
        let mut scalar_regions = Vec::new();
        self.compressed_scalars
            .append_cell_regions(0, &mut scalar_regions);
        for (address, bytes) in scalar_regions {
            if extent_crosses_page(address, bytes) {
                cross_page_objects = cross_page_objects.saturating_add(1);
            }
            mark_extent_lines(&mut masks, address, bytes);
        }

        let occupied_lines: usize = masks.values().map(|mask| mask.count_ones() as usize).sum();
        let mut line_frequencies = [0usize; LINES_PER_PAGE];
        for mask in masks.values() {
            for (line, frequency) in line_frequencies.iter_mut().enumerate() {
                if mask & (1u64 << line) != 0 {
                    *frequency = frequency.saturating_add(1);
                }
            }
        }
        let max_line_frequency = line_frequencies.iter().copied().max().unwrap_or(0);
        let live_pages = masks.len();
        let line_bound_bins = occupied_lines.div_ceil(LINES_PER_PAGE);
        let masks: Vec<_> = masks.into_values().collect();
        let greedy_pairs = constructive_greedy_pairs(masks.clone());
        let greedy_bins = constructive_greedy_bins(masks).len();
        Ok(MeshProjection {
            roots: roots.len(),
            reachable_objects: reachable.len(),
            live_pages,
            occupied_lines,
            max_line_frequency,
            line_frequencies,
            cross_page_objects,
            greedy_pairs,
            greedy_bins,
            line_bound_bins,
        })
    }
}

fn extent_crosses_page(address: usize, bytes: usize) -> bool {
    bytes != 0
        && address / PAGE_BYTES != address.saturating_add(bytes.saturating_sub(1)) / PAGE_BYTES
}

fn mark_extent_lines(masks: &mut HashMap<usize, u64>, address: usize, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let first_page = address / PAGE_BYTES;
    let last_page = address.saturating_add(bytes.saturating_sub(1)) / PAGE_BYTES;
    for page in first_page..=last_page {
        let page_start = page.saturating_mul(PAGE_BYTES);
        let start = address.saturating_sub(page_start).min(PAGE_BYTES);
        let end = address
            .saturating_add(bytes)
            .saturating_sub(page_start)
            .min(PAGE_BYTES);
        if start >= end {
            continue;
        }
        let first_line = start / LINE_BYTES;
        let last_line = end.saturating_sub(1) / LINE_BYTES;
        let width = last_line.saturating_sub(first_line).saturating_add(1);
        let bits = if width >= u64::BITS as usize {
            u64::MAX
        } else {
            ((1u64 << width) - 1) << first_line
        };
        *masks.entry(page).or_default() |= bits;
    }
}

fn constructive_greedy_pairs(mut masks: Vec<u64>) -> usize {
    // Dense pages have the fewest compatible partners, so commit them first
    // and search the sparse end for a disjoint mate.
    masks.sort_unstable_by_key(|mask| mask.count_ones());
    let mut pairs = 0usize;
    while let Some(mask) = masks.pop() {
        if let Some(index) = masks.iter().position(|candidate| mask & candidate == 0) {
            masks.swap_remove(index);
            pairs = pairs.saturating_add(1);
        }
    }
    pairs
}

fn constructive_greedy_bins(bins: Vec<u64>) -> Vec<u64> {
    let mut best = bins.clone();
    for dense_first in [true, false] {
        for sparse_mate_first in [true, false] {
            let candidate =
                constructive_greedy_bins_ordered(bins.clone(), dense_first, sparse_mate_first);
            if candidate.len() < best.len() {
                best = candidate;
            }
        }
    }
    best
}

fn constructive_greedy_bins_ordered(
    mut bins: Vec<u64>,
    dense_first: bool,
    sparse_mate_first: bool,
) -> Vec<u64> {
    loop {
        bins.sort_unstable_by_key(|mask| mask.count_ones());
        let before = bins.len();
        let mut available = vec![true; before];
        let mut next = Vec::with_capacity(before);
        for step in 0..before {
            let index = if dense_first { before - step - 1 } else { step };
            if !available[index] {
                continue;
            }
            available[index] = false;
            let mask = bins[index];
            let mate = if sparse_mate_first {
                (0..before).find(|candidate| available[*candidate] && mask & bins[*candidate] == 0)
            } else {
                (0..before)
                    .rev()
                    .find(|candidate| available[*candidate] && mask & bins[*candidate] == 0)
            };
            if let Some(mate) = mate {
                available[mate] = false;
                next.push(mask | bins[mate]);
            } else {
                next.push(mask);
            }
        }
        if next.len() == before {
            return next;
        }
        bins = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_mask_spans_page_boundary() {
        let mut masks = HashMap::new();
        mark_extent_lines(&mut masks, PAGE_BYTES - 8, 16);
        assert_eq!(masks.len(), 2);
        assert_eq!(masks[&0], 1u64 << 63);
        assert_eq!(masks[&1], 1);
    }

    #[test]
    fn greedy_schedule_only_pairs_disjoint_pages() {
        let masks = vec![0b0011, 0b1100, 0b0101, 0b1010, u64::MAX];
        assert_eq!(constructive_greedy_pairs(masks.clone()), 2);
        assert_eq!(constructive_greedy_bins(masks).len(), 3);
    }

    #[test]
    fn greedy_bins_combine_more_than_two_pages() {
        let bins = constructive_greedy_bins(vec![0b0001, 0b0010, 0b0100, 0b1000]);
        assert_eq!(bins, vec![0b1111]);
    }

    #[test]
    fn heap_projection_counts_a_live_page() {
        let mut heap = EvalHeap::new();
        let value = heap
            .alloc_string(NixString::from_bytes(b"mesh".to_vec()))
            .expect("string allocates");
        let mut roots = EvalRootSet::new();
        roots.try_push_value_stack(0, value).expect("root records");
        let projection = heap.mesh_projection(&roots).expect("projection succeeds");
        assert_eq!(projection.reachable_objects, 1);
        assert!(projection.live_pages >= 1);
        assert!(projection.occupied_lines >= 1);
    }
}
