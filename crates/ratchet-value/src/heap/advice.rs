//! Portable heap page-advice shim.
//!
//! Memory advice is an optimization boundary: Linux can receive `madvise`
//! hints for dead, cold, evictable, or huge-page candidate ranges, while other
//! platforms report the hint as unsupported without changing correctness. The
//! runtime must therefore treat every applied, unsupported, rejected, or
//! empty-range outcome as advisory only.

use std::ptr::NonNull;

#[cfg(test)]
use super::{ArenaAllocation, BumpArena};
use crate::value::HeapObject;

/// A non-null byte range eligible for operating-system memory advice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryAdviceRange {
    ptr: NonNull<u8>,
    len: usize,
}

impl MemoryAdviceRange {
    /// Creates an empty byte range for heap page advice.
    ///
    /// Empty ranges always return [`MemoryAdviceOutcome::EmptyRange`] without
    /// issuing an operating-system call.
    pub const fn empty() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
        }
    }

    /// Creates a raw byte range for heap page advice.
    ///
    /// Linux advice is page-granular. The shim only advises complete pages
    /// fully contained by the supplied range; partial prefix and suffix pages
    /// are skipped.
    ///
    /// # Safety
    ///
    /// For non-empty ranges, the caller must ensure that `ptr..ptr + len` is a
    /// mapped heap-owned byte range and does not overflow address arithmetic.
    /// For destructive hints such as [`MemoryAdviceKind::Dead`] and
    /// [`MemoryAdviceKind::Free`], no live typed value may rely on the contents
    /// of any full page wholly contained by the supplied range.
    pub const unsafe fn from_raw_parts(ptr: NonNull<u8>, len: usize) -> Self {
        Self { ptr, len }
    }

    /// Returns the start pointer for this advisory range.
    pub const fn ptr(self) -> NonNull<u8> {
        self.ptr
    }

    /// Returns the byte length for this advisory range.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns whether the advisory range contains no bytes.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// The logical memory hint requested by the heap policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemoryAdviceKind {
    /// The range contains dead bytes that the OS may discard.
    Dead,
    /// The range is no longer needed but may keep its contents until reuse.
    Free,
    /// The range is cold and should be deprioritized by reclaim policy.
    Cold,
    /// The range should be reclaimed or paged out when the OS can do so.
    Evict,
    /// The range is a candidate for transparent huge pages.
    Huge,
}

impl MemoryAdviceKind {
    #[cfg(target_os = "linux")]
    const fn linux_madvise_flag(self) -> libc::c_int {
        match self {
            Self::Dead => libc::MADV_DONTNEED,
            Self::Free => libc::MADV_FREE,
            Self::Cold => libc::MADV_COLD,
            Self::Evict => libc::MADV_PAGEOUT,
            Self::Huge => libc::MADV_HUGEPAGE,
        }
    }
}

/// The result of applying or intentionally skipping a memory-advice request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemoryAdviceOutcome {
    /// The operating system accepted the advisory request.
    Applied {
        /// The hint that was passed to the operating system.
        kind: MemoryAdviceKind,
    },
    /// The target platform has no supported lowering for this hint.
    Unsupported {
        /// The hint that was skipped.
        kind: MemoryAdviceKind,
    },
    /// The range contained no bytes, so no operating-system call was needed.
    EmptyRange {
        /// The hint that was skipped.
        kind: MemoryAdviceKind,
    },
    /// The platform rejected the advisory request or the shim could not form a
    /// valid page-granular syscall range.
    Rejected {
        /// The hint that was skipped after rejection.
        kind: MemoryAdviceKind,
        /// The raw errno value, when the operating system reported one.
        raw_os_error: Option<i32>,
    },
}

/// Applies a generic heap memory hint to a byte range.
///
/// Empty ranges return [`MemoryAdviceOutcome::EmptyRange`] without making a
/// syscall. Non-Linux targets return [`MemoryAdviceOutcome::Unsupported`].
/// Linux applies advice only to complete pages wholly contained by the supplied
/// range; operating-system rejection is reported as
/// [`MemoryAdviceOutcome::Rejected`] because correctness must not depend on
/// advisory memory hints.
pub fn advise_range(kind: MemoryAdviceKind, range: MemoryAdviceRange) -> MemoryAdviceOutcome {
    if range.is_empty() {
        return MemoryAdviceOutcome::EmptyRange { kind };
    }
    advise_non_empty(kind, range)
}

/// Advises that a range contains dead bytes that may be discarded.
pub fn advise_dead(range: MemoryAdviceRange) -> MemoryAdviceOutcome {
    advise_range(MemoryAdviceKind::Dead, range)
}

/// Advises that a range may be lazily freed on reuse.
pub fn advise_free(range: MemoryAdviceRange) -> MemoryAdviceOutcome {
    advise_range(MemoryAdviceKind::Free, range)
}

/// Advises that a range is cold and can be deprioritized for residency.
pub fn advise_cold(range: MemoryAdviceRange) -> MemoryAdviceOutcome {
    advise_range(MemoryAdviceKind::Cold, range)
}

/// Advises that a typed heap-object allocation is cold.
///
/// This is the safe heap-object wrapper for non-destructive cold advice. The
/// caller supplies a heap-object allocation pointer and the logical object byte
/// length; the advice shim still trims the range to complete contained pages
/// before making a platform call.
pub fn advise_cold_heap_object_allocation(
    ptr: NonNull<HeapObject>,
    len: usize,
) -> MemoryAdviceOutcome {
    if len == 0 {
        return MemoryAdviceOutcome::EmptyRange {
            kind: MemoryAdviceKind::Cold,
        };
    }
    // SAFETY: the caller provides a typed heap-object allocation pointer and
    // its allocation length. `Cold` advice is non-destructive; the platform may
    // deprioritize residency but must preserve contents.
    let range = unsafe { MemoryAdviceRange::from_raw_parts(ptr.cast(), len) };
    advise_cold(range)
}

/// Advises that a range is a good candidate for OS eviction or pageout.
pub fn advise_evict(range: MemoryAdviceRange) -> MemoryAdviceOutcome {
    advise_range(MemoryAdviceKind::Evict, range)
}

/// Advises that a typed heap-object allocation is eligible for OS eviction.
///
/// This is the safe heap-object wrapper for non-destructive eviction advice.
/// The caller supplies a heap-object allocation pointer and the logical object
/// byte length; the advice shim still trims the range to complete contained
/// pages before making a platform call.
pub fn advise_evict_heap_object_allocation(
    ptr: NonNull<HeapObject>,
    len: usize,
) -> MemoryAdviceOutcome {
    if len == 0 {
        return MemoryAdviceOutcome::EmptyRange {
            kind: MemoryAdviceKind::Evict,
        };
    }
    // SAFETY: the caller provides a typed heap-object allocation pointer and
    // its allocation length. `Evict` advice asks the platform to reclaim or
    // page out while preserving contents.
    let range = unsafe { MemoryAdviceRange::from_raw_parts(ptr.cast(), len) };
    advise_evict(range)
}

/// Advises that a range is a candidate for transparent huge pages.
pub fn advise_huge(range: MemoryAdviceRange) -> MemoryAdviceOutcome {
    advise_range(MemoryAdviceKind::Huge, range)
}

#[cfg(target_os = "linux")]
fn advise_non_empty(kind: MemoryAdviceKind, range: MemoryAdviceRange) -> MemoryAdviceOutcome {
    let page_size = match system_page_size() {
        Some(page_size) => page_size,
        None => {
            return MemoryAdviceOutcome::Unsupported { kind };
        }
    };
    let range = match full_pages_in_range(range, page_size) {
        FullPageRange::Selected(range) => range,
        FullPageRange::Empty => {
            return MemoryAdviceOutcome::EmptyRange { kind };
        }
        FullPageRange::Invalid => {
            return MemoryAdviceOutcome::Rejected {
                kind,
                raw_os_error: None,
            };
        }
    };

    let rc = {
        // SAFETY: `range.ptr` is non-null and `range.len` was checked to be
        // non-zero and page-granular by `full_pages_in_range`. `madvise` is
        // advisory; it does not grant dereference rights and the caller remains
        // responsible for only passing ranges owned by the heap.
        unsafe {
            libc::madvise(
                range.ptr.as_ptr().cast::<libc::c_void>(),
                range.len,
                kind.linux_madvise_flag(),
            )
        }
    };
    if rc == 0 {
        return MemoryAdviceOutcome::Applied { kind };
    }
    MemoryAdviceOutcome::Rejected {
        kind,
        raw_os_error: std::io::Error::last_os_error().raw_os_error(),
    }
}

#[cfg(not(target_os = "linux"))]
fn advise_non_empty(kind: MemoryAdviceKind, _range: MemoryAdviceRange) -> MemoryAdviceOutcome {
    MemoryAdviceOutcome::Unsupported { kind }
}

#[cfg(target_os = "linux")]
enum FullPageRange {
    Selected(MemoryAdviceRange),
    Empty,
    Invalid,
}

#[cfg(target_os = "linux")]
fn full_pages_in_range(range: MemoryAdviceRange, page_size: usize) -> FullPageRange {
    let start = range.ptr.as_ptr() as usize;
    let Some(end) = start.checked_add(range.len) else {
        return FullPageRange::Invalid;
    };
    let Some(aligned_start) = round_up_to_multiple(start, page_size) else {
        return FullPageRange::Invalid;
    };
    let aligned_end = round_down_to_multiple(end, page_size);
    if aligned_start >= aligned_end {
        return FullPageRange::Empty;
    }
    let len = aligned_end - aligned_start;
    let Some(ptr) = NonNull::new(aligned_start as *mut u8) else {
        return FullPageRange::Invalid;
    };
    FullPageRange::Selected(MemoryAdviceRange { ptr, len })
}

/// The result of asking the process allocator to return free memory to the OS.
///
/// Evaluator teardown frees large transient structures (heap-record tables,
/// captured environments, string storage) back to the process allocator, which
/// may keep the pages dirty-but-free. On a long-lived process that runs many
/// evaluations, those retained pages dominate resident-set growth even though
/// live allocation stays bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AllocatorReleaseOutcome {
    /// The allocator was asked to release free memory and reported success.
    Released,
    /// The allocator reported that no memory could be released.
    NothingToRelease,
    /// This target has no supported allocator-release lowering.
    ///
    /// Darwin is intentionally unsupported: `libmalloc` performs its own
    /// pressure relief (observed empirically as periodic resident-set drops),
    /// and its `malloc_zone_pressure_relief` API has no binding in the pinned
    /// `libc`, while heap policy forbids ad-hoc `extern` declarations.
    Unsupported,
}

/// Asks the process allocator to return dirty-but-free memory to the OS.
///
/// On Linux/glibc this calls `malloc_trim(0)`, which releases free heap pages
/// (top-of-heap and per-arena) back to the kernel. Call it at evaluation
/// boundaries, never on a hot path: released pages fault back in on next use,
/// so trimming between timed measurements keeps resident-set numbers honest at
/// a small one-time refault cost.
pub fn release_free_allocator_memory() -> AllocatorReleaseOutcome {
    release_free_allocator_memory_for_target()
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn release_free_allocator_memory_for_target() -> AllocatorReleaseOutcome {
    let released = {
        // SAFETY: `malloc_trim(0)` is a glibc allocator maintenance call with
        // no memory-safety preconditions; it only releases allocator-owned
        // free pages and returns 1 when memory was returned to the system.
        unsafe { libc::malloc_trim(0) }
    };
    if released == 1 {
        AllocatorReleaseOutcome::Released
    } else {
        AllocatorReleaseOutcome::NothingToRelease
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn release_free_allocator_memory_for_target() -> AllocatorReleaseOutcome {
    AllocatorReleaseOutcome::Unsupported
}

#[cfg(target_os = "linux")]
fn round_up_to_multiple(value: usize, multiple: usize) -> Option<usize> {
    debug_assert!(multiple != 0);
    let remainder = value % multiple;
    if remainder == 0 {
        return Some(value);
    }
    value.checked_add(multiple - remainder)
}

#[cfg(target_os = "linux")]
fn round_down_to_multiple(value: usize, multiple: usize) -> usize {
    debug_assert!(multiple != 0);
    value - (value % multiple)
}

#[cfg(target_os = "linux")]
fn system_page_size() -> Option<usize> {
    let page_size = {
        // SAFETY: `sysconf(_SC_PAGESIZE)` is a side-effect-free libc query. The
        // return value is validated before conversion to `usize`.
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
    };
    if page_size <= 0 {
        return None;
    }
    usize::try_from(page_size).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arena_heap_object_allocation() -> (BumpArena, ArenaAllocation) {
        let mut arena = BumpArena::with_initial_chunk_bytes(4096).expect("arena creates");
        let allocation = arena
            .aos_alloc_string(128)
            .expect("string object allocates");
        (arena, allocation)
    }

    #[test]
    fn allocator_release_reports_a_target_appropriate_outcome() {
        // Generate some allocator churn so glibc targets have free pages to
        // consider; the outcome remains advisory on every platform.
        let churn: Vec<Vec<u8>> = (0..64).map(|_| vec![0_u8; 64 * 1024]).collect();
        drop(churn);

        let outcome = release_free_allocator_memory();
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        assert!(matches!(
            outcome,
            AllocatorReleaseOutcome::Released | AllocatorReleaseOutcome::NothingToRelease
        ));
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        assert_eq!(outcome, AllocatorReleaseOutcome::Unsupported);
    }

    #[test]
    fn range_reports_pointer_length_and_empty_state() {
        let mut bytes = vec![0_u8; 4096];
        let ptr = NonNull::new(bytes.as_mut_ptr()).expect("non-null byte buffer");
        let range = {
            // SAFETY: The range covers the live heap-owned byte buffer, and this test
            // only inspects metadata without issuing memory advice.
            unsafe { MemoryAdviceRange::from_raw_parts(ptr, bytes.len()) }
        };

        assert_eq!(range.ptr(), ptr);
        assert_eq!(range.len(), 4096);
        assert!(!range.is_empty());
        assert!(MemoryAdviceRange::empty().is_empty());
    }

    #[test]
    fn empty_ranges_skip_every_advice_kind_without_syscall() {
        for kind in [
            MemoryAdviceKind::Dead,
            MemoryAdviceKind::Free,
            MemoryAdviceKind::Cold,
            MemoryAdviceKind::Evict,
            MemoryAdviceKind::Huge,
        ] {
            assert_eq!(
                advise_range(kind, MemoryAdviceRange::empty()),
                MemoryAdviceOutcome::EmptyRange { kind }
            );
        }
    }

    #[test]
    fn typed_helpers_select_expected_advice_kind() {
        assert_eq!(
            advise_dead(MemoryAdviceRange::empty()),
            MemoryAdviceOutcome::EmptyRange {
                kind: MemoryAdviceKind::Dead
            }
        );
        assert_eq!(
            advise_free(MemoryAdviceRange::empty()),
            MemoryAdviceOutcome::EmptyRange {
                kind: MemoryAdviceKind::Free
            }
        );
        assert_eq!(
            advise_cold(MemoryAdviceRange::empty()),
            MemoryAdviceOutcome::EmptyRange {
                kind: MemoryAdviceKind::Cold
            }
        );
        assert_eq!(
            advise_cold_heap_object_allocation(NonNull::<HeapObject>::dangling(), 0),
            MemoryAdviceOutcome::EmptyRange {
                kind: MemoryAdviceKind::Cold
            }
        );
        assert_eq!(
            advise_evict(MemoryAdviceRange::empty()),
            MemoryAdviceOutcome::EmptyRange {
                kind: MemoryAdviceKind::Evict
            }
        );
        assert_eq!(
            advise_huge(MemoryAdviceRange::empty()),
            MemoryAdviceOutcome::EmptyRange {
                kind: MemoryAdviceKind::Huge
            }
        );
    }

    #[test]
    fn typed_helpers_preserve_kind_for_non_empty_subpage_ranges() {
        fn assert_subpage_outcome(outcome: MemoryAdviceOutcome, kind: MemoryAdviceKind) {
            #[cfg(target_os = "linux")]
            assert_eq!(outcome, MemoryAdviceOutcome::EmptyRange { kind });
            #[cfg(not(target_os = "linux"))]
            assert_eq!(outcome, MemoryAdviceOutcome::Unsupported { kind });
        }

        let mut bytes = vec![0_u8; 64];
        let mut range = || {
            // SAFETY: The range covers a live heap-owned byte buffer. On Linux
            // this sub-page range is trimmed to no complete pages before any
            // syscall; on non-Linux targets it reports `Unsupported`.
            unsafe {
                MemoryAdviceRange::from_raw_parts(
                    NonNull::new(bytes.as_mut_ptr()).expect("non-null byte buffer"),
                    bytes.len(),
                )
            }
        };

        assert_subpage_outcome(advise_dead(range()), MemoryAdviceKind::Dead);
        assert_subpage_outcome(advise_free(range()), MemoryAdviceKind::Free);
        assert_subpage_outcome(advise_cold(range()), MemoryAdviceKind::Cold);
        assert_subpage_outcome(advise_evict(range()), MemoryAdviceKind::Evict);
        assert_subpage_outcome(advise_huge(range()), MemoryAdviceKind::Huge);
    }

    #[test]
    fn cold_heap_object_allocation_helper_uses_cold_kind_for_non_empty_ranges() {
        let (_arena, allocation) = arena_heap_object_allocation();
        let outcome = advise_cold_heap_object_allocation(allocation.ptr, allocation.requested_size);

        let kind = match outcome {
            MemoryAdviceOutcome::Applied { kind }
            | MemoryAdviceOutcome::Unsupported { kind }
            | MemoryAdviceOutcome::EmptyRange { kind }
            | MemoryAdviceOutcome::Rejected { kind, .. } => kind,
        };
        assert_eq!(kind, MemoryAdviceKind::Cold);
    }

    #[test]
    fn evict_heap_object_allocation_helper_uses_evict_kind_for_non_empty_ranges() {
        let (_arena, allocation) = arena_heap_object_allocation();
        let outcome =
            advise_evict_heap_object_allocation(allocation.ptr, allocation.requested_size);

        let kind = match outcome {
            MemoryAdviceOutcome::Applied { kind }
            | MemoryAdviceOutcome::Unsupported { kind }
            | MemoryAdviceOutcome::EmptyRange { kind }
            | MemoryAdviceOutcome::Rejected { kind, .. } => kind,
        };
        assert_eq!(kind, MemoryAdviceKind::Evict);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_non_empty_ranges_return_unsupported_without_touching_memory() {
        for kind in [
            MemoryAdviceKind::Dead,
            MemoryAdviceKind::Free,
            MemoryAdviceKind::Cold,
            MemoryAdviceKind::Evict,
            MemoryAdviceKind::Huge,
        ] {
            let mut bytes = vec![0_u8; 4096];
            let range = {
                // SAFETY: The range covers a live heap-owned byte buffer. This test is
                // cfg-gated to targets where `advise_range` reports
                // `Unsupported` before issuing any operating-system call.
                unsafe {
                    MemoryAdviceRange::from_raw_parts(
                        NonNull::new(bytes.as_mut_ptr()).expect("non-null byte buffer"),
                        bytes.len(),
                    )
                }
            };

            assert_eq!(
                advise_range(kind, range),
                MemoryAdviceOutcome::Unsupported { kind }
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_skips_ranges_without_a_complete_page() {
        let mapping = TestMapping::new(1);
        let ptr = NonNull::new(mapping.ptr.as_ptr().wrapping_add(1)).expect("non-null range");
        let range = {
            // SAFETY: The range stays within the live test mapping and contains
            // no complete page after prefix/suffix trimming.
            unsafe { MemoryAdviceRange::from_raw_parts(ptr, mapping.len - 2) }
        };

        assert_eq!(
            advise_dead(range),
            MemoryAdviceOutcome::EmptyRange {
                kind: MemoryAdviceKind::Dead
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_applies_dead_advice_to_page_aligned_mmap_range() {
        let mapping = TestMapping::new(1);
        let range = {
            // SAFETY: The range covers the live anonymous test mapping. The
            // mapping holds no live typed heap values, so destructive
            // `MADV_DONTNEED` advice is acceptable.
            unsafe { MemoryAdviceRange::from_raw_parts(mapping.ptr, mapping.len) }
        };

        assert_eq!(
            advise_dead(range),
            MemoryAdviceOutcome::Applied {
                kind: MemoryAdviceKind::Dead
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_kind_flags_match_libc_madvise_constants() {
        assert_eq!(
            MemoryAdviceKind::Dead.linux_madvise_flag(),
            libc::MADV_DONTNEED
        );
        assert_eq!(MemoryAdviceKind::Free.linux_madvise_flag(), libc::MADV_FREE);
        assert_eq!(MemoryAdviceKind::Cold.linux_madvise_flag(), libc::MADV_COLD);
        assert_eq!(
            MemoryAdviceKind::Evict.linux_madvise_flag(),
            libc::MADV_PAGEOUT
        );
        assert_eq!(
            MemoryAdviceKind::Huge.linux_madvise_flag(),
            libc::MADV_HUGEPAGE
        );
    }

    #[cfg(target_os = "linux")]
    struct TestMapping {
        ptr: NonNull<u8>,
        len: usize,
    }

    #[cfg(target_os = "linux")]
    impl TestMapping {
        fn new(pages: usize) -> Self {
            let page_size = system_page_size().expect("page size");
            let len = page_size.checked_mul(pages).expect("mapping length");
            let raw_ptr = {
                // SAFETY: The mapping request uses a null address hint, a
                // non-zero page-rounded length, read/write protection, and an
                // anonymous private mapping with `fd = -1`. The returned
                // pointer is checked for `MAP_FAILED` and null before use.
                unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                }
            };
            assert_ne!(raw_ptr, libc::MAP_FAILED);
            let ptr = NonNull::new(raw_ptr.cast::<u8>()).expect("non-null mapping");
            Self { ptr, len }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TestMapping {
        fn drop(&mut self) {
            let rc = {
                // SAFETY: `ptr` and `len` are exactly the mapping returned by a
                // successful `mmap` in `TestMapping::new`.
                unsafe { libc::munmap(self.ptr.as_ptr().cast::<libc::c_void>(), self.len) }
            };
            assert_eq!(rc, 0, "munmap test mapping");
        }
    }
}
