//! Shadow replay model for alignment-safe reuse of retired flat-object extents.
//!
//! This module never supplies storage to the real allocator. When explicitly
//! enabled at runtime, allocation and retirement hooks replay the observed
//! Candidate-C event stream into a bounded-search segregated-fit model. Actual
//! object addresses therefore remain unchanged.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::fmt;

const MAX_SIZE_CLASSES_PROBED: usize = 4;
const MAX_HOLES_PROBED: usize = 8;

thread_local! {
    static SHADOW: RefCell<HoleReuseShadow> = RefCell::new(HoleReuseShadow::default());
}

/// Aggregate counters from one reusable-hole shadow replay.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HoleReuseShadowReport {
    /// Number of successful Candidate-C allocations observed.
    pub allocations: u64,
    /// Number of exact live allocations retired from the model.
    pub retirements: u64,
    /// Retirements whose address was not live in the model.
    pub unknown_retirements: u64,
    /// Allocations whose actual address unexpectedly replaced a live identity.
    pub address_collisions: u64,
    /// Sum of reserved bytes requested by observed allocations.
    pub allocated_bytes: u64,
    /// Current bytes owned by modeled live objects.
    pub live_bytes: u64,
    /// Maximum bytes owned by modeled live objects.
    pub peak_live_bytes: u64,
    /// Monotonic shadow-arena cursor, including alignment padding.
    pub modeled_high_water_bytes: u64,
    /// Allocation bytes served from retired extents.
    pub reused_bytes: u64,
    /// Number of allocations served from retired extents.
    pub reuse_allocations: u64,
    /// Candidate holes inspected by bounded lookup.
    pub probes: u64,
    /// Largest candidate-hole count for one allocation.
    pub max_probes: u64,
    /// Total bytes currently held in reusable retired extents.
    pub reusable_bytes: u64,
}

impl fmt::Display for HoleReuseShadowReport {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "{{\"allocations\":{},\"retirements\":{},\
             \"unknown_retirements\":{},\"address_collisions\":{},\
             \"allocated_bytes\":{},\"live_bytes\":{},\"peak_live_bytes\":{},\
             \"modeled_high_water_bytes\":{},\"reused_bytes\":{},\
             \"reuse_allocations\":{},\"probes\":{},\"max_probes\":{},\
             \"reusable_bytes\":{}}}",
            self.allocations,
            self.retirements,
            self.unknown_retirements,
            self.address_collisions,
            self.allocated_bytes,
            self.live_bytes,
            self.peak_live_bytes,
            self.modeled_high_water_bytes,
            self.reused_bytes,
            self.reuse_allocations,
            self.probes,
            self.max_probes,
            self.reusable_bytes,
        )
    }
}

/// Starts a fresh shadow replay on the current evaluator thread.
///
/// Later hooks are inert until this function is called. Calling it again
/// discards the previous model and starts from an empty arena.
pub fn start_hole_reuse_shadow() {
    SHADOW.with(|shadow| {
        *shadow.borrow_mut() = HoleReuseShadow {
            enabled: true,
            ..HoleReuseShadow::default()
        };
    });
}

/// Returns the current thread's shadow-replay counters.
pub fn hole_reuse_shadow_report() -> HoleReuseShadowReport {
    SHADOW.with(|shadow| shadow.borrow().report)
}

/// Records one successful Candidate-C reservation allocation.
pub(super) fn note_candidate_c_allocation(address: usize, size: usize, align: usize) {
    SHADOW.with(|shadow| shadow.borrow_mut().allocate(address, size, align));
}

/// Records one successful Candidate-C object retirement.
pub(super) fn note_candidate_c_retirement(address: usize) {
    SHADOW.with(|shadow| shadow.borrow_mut().retire(address));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Extent {
    start: usize,
    size: usize,
}

#[derive(Debug, Default)]
struct HoleReuseShadow {
    enabled: bool,
    cursor: usize,
    live: HashMap<usize, Extent>,
    holes: BTreeMap<usize, Vec<Extent>>,
    report: HoleReuseShadowReport,
}

impl HoleReuseShadow {
    fn allocate(&mut self, address: usize, size: usize, align: usize) {
        if !self.enabled || size == 0 || align == 0 || !align.is_power_of_two() {
            return;
        }
        let (extent, probes, reused) = self.take_hole(size, align).map_or_else(
            || (self.bump(size, align), 0, false),
            |(extent, probes)| (extent, probes, true),
        );
        if let Some(previous) = self.live.insert(address, extent) {
            self.report.address_collisions = self.report.address_collisions.saturating_add(1);
            self.insert_hole(previous);
            self.report.live_bytes = self.report.live_bytes.saturating_sub(previous.size as u64);
        }
        self.report.allocations = self.report.allocations.saturating_add(1);
        self.report.allocated_bytes = self.report.allocated_bytes.saturating_add(size as u64);
        self.report.live_bytes = self.report.live_bytes.saturating_add(size as u64);
        self.report.peak_live_bytes = self.report.peak_live_bytes.max(self.report.live_bytes);
        self.report.probes = self.report.probes.saturating_add(probes as u64);
        self.report.max_probes = self.report.max_probes.max(probes as u64);
        if reused {
            self.report.reuse_allocations = self.report.reuse_allocations.saturating_add(1);
            self.report.reused_bytes = self.report.reused_bytes.saturating_add(size as u64);
        }
        self.refresh_reusable_bytes();
    }

    fn retire(&mut self, address: usize) {
        if !self.enabled {
            return;
        }
        let Some(extent) = self.live.remove(&address) else {
            self.report.unknown_retirements = self.report.unknown_retirements.saturating_add(1);
            return;
        };
        self.report.retirements = self.report.retirements.saturating_add(1);
        self.report.live_bytes = self.report.live_bytes.saturating_sub(extent.size as u64);
        self.insert_hole(extent);
        self.refresh_reusable_bytes();
    }

    fn bump(&mut self, size: usize, align: usize) -> Extent {
        let start = align_up(self.cursor, align).unwrap_or(self.cursor);
        self.cursor = start.saturating_add(size);
        self.report.modeled_high_water_bytes = self.cursor as u64;
        Extent { start, size }
    }

    fn take_hole(&mut self, size: usize, align: usize) -> Option<(Extent, usize)> {
        let first_class = size_class(size)?;
        let classes: Vec<usize> = self
            .holes
            .range(first_class..)
            .take(MAX_SIZE_CLASSES_PROBED)
            .map(|(&class, _)| class)
            .collect();
        let mut probes = 0usize;
        for class in classes {
            let mut selected = None;
            if let Some(holes) = self.holes.get(&class) {
                for (index, hole) in holes.iter().enumerate() {
                    if probes == MAX_HOLES_PROBED {
                        break;
                    }
                    probes += 1;
                    let Some(start) = align_up(hole.start, align) else {
                        continue;
                    };
                    if start
                        .checked_add(size)
                        .is_some_and(|end| end <= hole.start.saturating_add(hole.size))
                    {
                        selected = Some((index, start));
                        break;
                    }
                }
            }
            if let Some((index, start)) = selected {
                let holes = self.holes.get_mut(&class)?;
                let hole = holes.swap_remove(index);
                if holes.is_empty() {
                    self.holes.remove(&class);
                }
                if start > hole.start {
                    self.insert_hole(Extent {
                        start: hole.start,
                        size: start - hole.start,
                    });
                }
                let end = start.checked_add(size)?;
                let hole_end = hole.start.checked_add(hole.size)?;
                if end < hole_end {
                    self.insert_hole(Extent {
                        start: end,
                        size: hole_end - end,
                    });
                }
                return Some((Extent { start, size }, probes));
            }
            if probes == MAX_HOLES_PROBED {
                break;
            }
        }
        self.report.probes = self.report.probes.saturating_add(probes as u64);
        self.report.max_probes = self.report.max_probes.max(probes as u64);
        None
    }

    fn insert_hole(&mut self, extent: Extent) {
        if extent.size == 0 {
            return;
        }
        let Some(class) = size_class(extent.size) else {
            return;
        };
        self.holes.entry(class).or_default().push(extent);
    }

    fn refresh_reusable_bytes(&mut self) {
        self.report.reusable_bytes = self
            .holes
            .values()
            .flat_map(|holes| holes.iter())
            .fold(0u64, |sum, extent| sum.saturating_add(extent.size as u64));
    }
}

fn size_class(size: usize) -> Option<usize> {
    size.checked_next_power_of_two()
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    value
        .checked_add(align.checked_sub(1)?)?
        .checked_div(align)?
        .checked_mul(align)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> HoleReuseShadow {
        HoleReuseShadow {
            enabled: true,
            ..HoleReuseShadow::default()
        }
    }

    #[test]
    fn aligned_split_reuses_only_the_requested_extent() {
        let mut shadow = model();
        shadow.allocate(10, 48, 8);
        shadow.retire(10);
        shadow.allocate(20, 16, 32);

        assert_eq!(shadow.live.get(&20), Some(&Extent { start: 0, size: 16 }));
        assert_eq!(shadow.report.modeled_high_water_bytes, 48);
        assert_eq!(shadow.report.reused_bytes, 16);
        assert_eq!(shadow.report.reusable_bytes, 32);
        assert_eq!(shadow.report.probes, 1);
    }

    #[test]
    fn alignment_padding_is_preserved_as_reusable_fragments() {
        let mut shadow = model();
        shadow.allocate(1, 48, 8);
        shadow.retire(1);
        shadow.allocate(2, 16, 32);
        shadow.allocate(3, 16, 32);

        assert_eq!(shadow.live.get(&2), Some(&Extent { start: 0, size: 16 }));
        assert_eq!(
            shadow.live.get(&3),
            Some(&Extent {
                start: 32,
                size: 16
            })
        );
        assert_eq!(shadow.report.reused_bytes, 32);
        assert_eq!(shadow.report.reusable_bytes, 16);
    }

    #[test]
    fn candidate_search_never_exceeds_probe_bound() {
        let mut shadow = model();
        for address in 0..20 {
            shadow.allocate(address, 8, 8);
        }
        for address in 0..20 {
            shadow.retire(address);
        }
        shadow.allocate(100, 16, 64);

        assert!(shadow.report.max_probes <= MAX_HOLES_PROBED as u64);
    }

    #[test]
    fn retirement_uses_actual_identity_not_modeled_address() {
        let mut shadow = model();
        shadow.allocate(0xdead_beef, 24, 8);
        shadow.retire(0xdead_beef);
        shadow.retire(0xdead_beef);

        assert_eq!(shadow.report.retirements, 1);
        assert_eq!(shadow.report.unknown_retirements, 1);
        assert_eq!(shadow.report.live_bytes, 0);
        assert_eq!(shadow.report.reusable_bytes, 24);
    }

    #[test]
    fn real_store_hooks_do_not_change_actual_allocation_addresses() {
        use crate::heap::flat::{
            FlatKindSet, FlatObjectKind, FlatObjectStore, SharedFlatStoreArena,
        };

        start_hole_reuse_shadow();
        let arena = SharedFlatStoreArena::new();
        assert!(arena.uses_reservation());
        let mut store =
            FlatObjectStore::with_shared_arena(arena, FlatKindSet::of(&[FlatObjectKind::BoxedInt]));
        let first = store
            .alloc(FlatObjectKind::BoxedInt, 1, 0, 1u64)
            .expect("first object allocates");
        store
            .retire(first.ptr, FlatObjectKind::BoxedInt)
            .expect("first object retires");
        let second = store
            .alloc(FlatObjectKind::BoxedInt, 2, 0, 2u64)
            .expect("second object allocates");

        assert_ne!(
            first.ptr, second.ptr,
            "the production bump allocator must remain unchanged"
        );
        let report = hole_reuse_shadow_report();
        assert_eq!(report.allocations, 2);
        assert_eq!(report.retirements, 1);
        assert_eq!(report.reuse_allocations, 1);
        assert_eq!(
            report.modeled_high_water_bytes,
            first.allocation.reserved_size as u64
        );
    }
}
