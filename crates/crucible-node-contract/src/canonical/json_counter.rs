//! Names fixed controls of the actual canonical JSON writer and object ordering.
//!
//! Dynamic Value/string/UTF16/ordered-map/input-Vec/heap-sort/output backing is
//! independent caller construction demand. This declaration names only the
//! actual requested control layouts. It is not a physical process-stack bound.
//!
//! The std mirrors are pinned to AOS Rust1.98.1 source (see the supplier source
//! manifest), not a public standard-library ABI. Both normal and size-optimized
//! same-constructor branches are included conservatively. A five-member object
//! takes insertion sort on the normal target; it is not claimed to use driftsort.

use super::canonical_number_counter_scratch_bytes_data;
use crate::ContractError;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    mem::{ManuallyDrop, MaybeUninit, size_of},
};

type Entry<'a> = (Vec<u16>, (&'a str, &'a Value));

// Exact repr(C) field roster in core/slice/sort/stable/mod.rs149. The zero-length
// Entry gives the buffer its actual alignment; no unaligned byte-array donor.
#[repr(C)]
#[allow(dead_code)]
struct SortStackStorage<T> {
    align: [T; 0],
    storage: [MaybeUninit<u8>; 4096],
}

// Private DriftsortRun is one usize. This mirror supplies its named66-element
// run stack, independently of the separate66-element desired-depth byte stack.
#[allow(dead_code)]
struct DriftRun(usize);

#[allow(dead_code)]
struct DriftControls {
    run_storage: MaybeUninit<[DriftRun; 66]>,
    desired_depth_storage: MaybeUninit<[u8; 66]>,
    run_pointer: *mut DriftRun,
    depth_pointer: *mut u8,
    stack_len: usize,
    scan_index: usize,
    length: usize,
    scale_factor: u64,
    minimum_run: usize,
    previous: DriftRun,
    next: DriftRun,
    left: DriftRun,
    desired_depth: u8,
}

#[allow(dead_code)]
struct MergeState<T> {
    start: *mut T,
    end: *mut T,
    destination: *mut T,
}

#[allow(dead_code)]
struct PartitionState<T> {
    scratch_base: *mut T,
    scan: *const T,
    num_left: usize,
    scratch_reverse: *mut T,
}

#[allow(dead_code)]
struct CopyOnDrop<T> {
    source: *const T,
    destination: *mut T,
    length: usize,
}

// Layout-only mirror; no operational fields or behavior are suppressed.
#[allow(dead_code)]
struct QuickControls<'a> {
    values: &'a mut [Entry<'a>],
    scratch: &'a mut [MaybeUninit<Entry<'a>>],
    ancestor: Option<&'a Entry<'a>>,
    comparison: &'a mut dyn FnMut(&Entry<'a>, &Entry<'a>) -> bool,
    length: usize,
    limit: u32,
    pivot_position: usize,
    pivot_copy: MaybeUninit<Entry<'a>>,
    pivot_reference: Option<&'a Entry<'a>>,
    equal_partition: bool,
    left_partition: usize,
    state: PartitionState<Entry<'a>>,
}

// Layout-only mirror; no operational fields or behavior are suppressed.
#[allow(dead_code)]
struct TinyControls<'a> {
    values: &'a mut [Entry<'a>],
    scratch: &'a mut [MaybeUninit<Entry<'a>>],
    comparison: &'a mut dyn FnMut(&Entry<'a>, &Entry<'a>) -> bool,
    length: usize,
    middle: usize,
    base: *mut Entry<'a>,
    left: *mut Entry<'a>,
    right: *mut Entry<'a>,
}

// These layout mirrors are never instantiated: they name the actual borrowed
// arguments/results in shared/pivot.rs. F is Sized, so its &mut F is thin.
#[allow(dead_code)]
struct PivotSelectionControls<'a> {
    values: &'a [Entry<'a>],
    comparison: *mut (),
    length: usize,
    base: *const Entry<'a>,
    chunk: usize,
    a: *const Entry<'a>,
    b: *const Entry<'a>,
    c: *const Entry<'a>,
    index: usize,
}

// median3_rec holds all three section pointers while its three n/8 children
// execute sequentially; sibling invocations do not overlap each other.
#[allow(dead_code)]
struct PivotRecursionControls<'a> {
    a: *const Entry<'a>,
    b: *const Entry<'a>,
    c: *const Entry<'a>,
    length: usize,
    comparison: *mut (),
    chunk: usize,
    result: *const Entry<'a>,
}

// The terminal median3 borrows three entries and retains three comparisons.
#[allow(dead_code)]
struct MedianControls<'a> {
    a: &'a Entry<'a>,
    b: &'a Entry<'a>,
    c: &'a Entry<'a>,
    comparison: *mut (),
    x: bool,
    y: bool,
    z: bool,
    result: *const Entry<'a>,
}

fn ordering_counter_scratch_data() -> usize {
    // FromIterator collects input entries, then sort_by selects std's stable
    // implementation. Normal driftsort's limit is2*ilog2(len|1), bounded by
    // 2*(usize::BITS-1); its zero-limit fallback is one eager drift invocation,
    // hence two independently live run/depth arrays. Tiny mergesort halves its
    // input at every level. These are type/algorithm controls, not record caps.
    let quick_frames = 2 * (usize::BITS as usize - 1);
    let tiny_frames = usize::BITS as usize;
    // Each pivot recursion divides its section length by eight. This includes
    // its terminal invocation for every representable slice length. It runs
    // while the current quicksort ancestry remains live, independently of the
    // run/depth stacks and the terminal median's own controls.
    let pivot_frames = (usize::BITS as usize).div_ceil(3) + 1;
    size_of::<SortStackStorage<Entry<'static>>>()
        + 2 * size_of::<DriftControls>()
        + quick_frames * size_of::<QuickControls<'static>>()
        + tiny_frames * size_of::<TinyControls<'static>>()
        + size_of::<PivotSelectionControls<'static>>()
        + pivot_frames * size_of::<PivotRecursionControls<'static>>()
        + size_of::<MedianControls<'static>>()
        + size_of::<MergeState<Entry<'static>>>()
        + size_of::<CopyOnDrop<Entry<'static>>>()
        + size_of::<ManuallyDrop<Entry<'static>>>()
        + 2 * size_of::<Vec<Entry<'static>>>()
        + size_of::<&mut [MaybeUninit<Entry<'static>>]>()
        + size_of::<&mut [Entry<'static>]>()
        + size_of::<[usize; 6]>()
        + size_of::<[*mut Entry<'static>; 6]>()
}

/// Names fixed canonical writer, formatter and same-object sort controls.
///
/// The unchanged writer rejects a65th nested container. Each earlier writer
/// frame owns only borrowed values, iterator/ordering headers and scalar state.
/// Sorting finishes before a child is recursively written, so only one actual
/// sort workspace overlaps the nested canonical frames. This includes both
/// pinned std sort branches conservatively, even for smaller actual objects.
/// Original input/DOM, ordering/formatter/output heap work and custom sink
/// ownership must be independently admitted by the actual caller.
pub fn canonical_json_counter_scratch_bytes_data() -> usize {
    let frame = size_of::<&Value>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<usize>()
        + size_of::<BTreeMap<Vec<u16>, (&str, &Value)>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, Value>>>()
        + size_of::<
            std::iter::Enumerate<
                std::collections::btree_map::Values<
                    'static,
                    Vec<u16>,
                    (&'static str, &'static Value),
                >,
            >,
        >()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<Result<(), ContractError>>();
    65 * frame
        + ordering_counter_scratch_data()
        + canonical_number_counter_scratch_bytes_data()
        + size_of::<std::str::EncodeUtf16<'static>>()
        + size_of::<Vec<u16>>()
        + size_of::<String>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<Vec<u8>, ContractError>>()
        + size_of::<Result<String, serde_json::Error>>()
        + size_of::<serde_json::Serializer<&mut Vec<u8>>>()
        + size_of::<serde_json::ser::CompactFormatter>()
        + size_of::<ContractError>()
        + size_of::<serde_json::Error>()
        + size_of::<std::io::Error>()
        + size_of::<[usize; 3]>()
}
