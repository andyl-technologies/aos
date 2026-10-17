//! Owns a finite caller-owned trace of scalar allocation requests.
//!
//! Callers supply their original fixed 16, 32, 64 or 512 entry storage. A closed
//! thread-local selector chooses only those finite cases; the allocator never
//! follows an allocation address or invokes caller code. The separate process-wide32 mode reuses
//! the original global roster registry and samples its original source-live flag.

use std::alloc::Layout;
use std::cell::Cell;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::AllocationIdentity;

struct Entry {
    address: AtomicUsize,
    bytes: AtomicUsize,
    alignment: AtomicUsize,
}

impl Entry {
    const fn new() -> Self {
        Self {
            address: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            alignment: AtomicUsize::new(0),
        }
    }
}

/// Retains an original fixed-capacity scalar allocation trace in caller storage.
///
/// Entries contain addresses and layouts, never pointers to allocated contents.
/// Only the explicitly supported 16, 32, 64 and 512 thread-local captures can
/// arm thread-local storage; the separate global32 mode shares roster custody.
/// The caller keeps its original loan roster separately and
/// correlates its real constructor operations with the live allocation count.
/// Capture does not establish allocation ownership or original funding.
pub struct AllocationTrace<const CAPACITY: usize> {
    active: AtomicBool,
    count: AtomicUsize,
    reallocations: AtomicUsize,
    overflow: AtomicBool,
    entries: [Entry; CAPACITY],
}

impl<const CAPACITY: usize> AllocationTrace<CAPACITY> {
    /// Creates empty fixed storage without allocating.
    pub const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            count: AtomicUsize::new(0),
            reallocations: AtomicUsize::new(0),
            overflow: AtomicBool::new(false),
            entries: [const { Entry::new() }; CAPACITY],
        }
    }

    /// Returns the number of successful allocation requests in the selected scope.
    pub fn allocation_count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    /// Returns the separate native reallocation count.
    pub fn reallocations(&self) -> usize {
        self.reallocations.load(Ordering::SeqCst)
    }

    /// Reports exhausted entry capacity or a saturated request counter.
    pub fn overflowed(&self) -> bool {
        self.overflow.load(Ordering::SeqCst)
    }

    /// Reads the recorded scalar extents in their original request order.
    ///
    /// The capture owner reads entries after a request returns or after capture
    /// ends. Concurrent readers do not establish a completed request snapshot.
    /// Overflow or any reallocation invalidates an allocation-lifetime proof.
    pub fn entries(&self) -> impl Iterator<Item = AllocationTraceEntry> + '_ {
        self.entries[..self.allocation_count().min(CAPACITY)]
            .iter()
            .filter_map(|entry| {
                Some(AllocationTraceEntry {
                    identity: AllocationIdentity::from_address(NonZeroUsize::new(
                        entry.address.load(Ordering::SeqCst),
                    )?),
                    bytes: entry.bytes.load(Ordering::SeqCst),
                    alignment: entry.alignment.load(Ordering::SeqCst),
                })
            })
    }

    pub(super) fn record(&self, address: usize, layout: Layout, reallocation: bool) {
        if address == 0 {
            return;
        }
        if reallocation {
            if self
                .reallocations
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                    count.checked_add(1)
                })
                .is_err()
            {
                self.overflow.store(true, Ordering::SeqCst);
            }
            return;
        }
        let index = match self
            .count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_add(1)
            }) {
            Ok(index) => index,
            Err(_) => {
                self.overflow.store(true, Ordering::SeqCst);
                return;
            }
        };
        if let Some(entry) = self.entries.get(index) {
            entry.address.store(address, Ordering::SeqCst);
            entry.bytes.store(layout.size(), Ordering::SeqCst);
            entry.alignment.store(layout.align(), Ordering::SeqCst);
        } else {
            self.overflow.store(true, Ordering::SeqCst);
        }
    }
}

impl<const CAPACITY: usize> Default for AllocationTrace<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

/// Identifies one recorded request by scalar base address and actual layout.
#[derive(Clone, Copy, Debug)]
pub struct AllocationTraceEntry {
    identity: AllocationIdentity,
    bytes: usize,
    alignment: usize,
}

impl AllocationTraceEntry {
    /// Returns a scalar identity without borrowing its allocated contents.
    pub fn identity(self) -> AllocationIdentity {
        self.identity
    }

    /// Returns the actual requested byte extent.
    pub fn bytes(self) -> usize {
        self.bytes
    }

    /// Returns the actual requested alignment.
    pub fn alignment(self) -> usize {
        self.alignment
    }

    /// Checks whether a scalar address lies within this recorded extent.
    pub fn contains_address(self, address: usize) -> bool {
        self.identity.0 <= address && address < self.identity.0.saturating_add(self.bytes)
    }
}

/// Refuses overlapping or unavailable thread-local allocation capture.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AllocationTraceSetupError {
    /// A selected thread or this exact storage already has an active capture.
    #[error("an allocation trace is already active")]
    AlreadyArmed,
    /// Thread-local state is unavailable during teardown.
    #[error("allocation trace state is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy)]
enum SelectedTrace {
    Sixteen(&'static AllocationTrace<16>),
    ThirtyTwo(&'static AllocationTrace<32>),
    SixtyFour(&'static AllocationTrace<64>),
    FiveTwelve(&'static AllocationTrace<512>),
}

impl SelectedTrace {
    fn arm(self) -> bool {
        match self {
            Self::Sixteen(trace) => trace.arm(),
            Self::ThirtyTwo(trace) => trace.arm(),
            Self::SixtyFour(trace) => trace.arm(),
            Self::FiveTwelve(trace) => trace.arm(),
        }
    }

    fn disarm(self) {
        match self {
            Self::Sixteen(trace) => trace.active.store(false, Ordering::SeqCst),
            Self::ThirtyTwo(trace) => trace.active.store(false, Ordering::SeqCst),
            Self::SixtyFour(trace) => trace.active.store(false, Ordering::SeqCst),
            Self::FiveTwelve(trace) => trace.active.store(false, Ordering::SeqCst),
        }
    }

    fn record(self, address: usize, layout: Layout, reallocation: bool) {
        match self {
            Self::Sixteen(trace) => trace.record(address, layout, reallocation),
            Self::ThirtyTwo(trace) => trace.record(address, layout, reallocation),
            Self::SixtyFour(trace) => trace.record(address, layout, reallocation),
            Self::FiveTwelve(trace) => trace.record(address, layout, reallocation),
        }
    }
}

impl<const CAPACITY: usize> AllocationTrace<CAPACITY> {
    pub(super) fn disarm(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    pub(super) fn arm(&self) -> bool {
        if self
            .active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        self.count.store(0, Ordering::SeqCst);
        self.reallocations.store(0, Ordering::SeqCst);
        self.overflow.store(false, Ordering::SeqCst);
        true
    }
}

thread_local! {
    static TRACE: Cell<Option<SelectedTrace>> = const { Cell::new(None) };
}

struct Reset(SelectedTrace);

impl Drop for Reset {
    fn drop(&mut self) {
        let _ = TRACE.try_with(|cell| cell.set(None));
        self.0.disarm();
    }
}

fn capture<T>(
    trace: SelectedTrace,
    action: impl FnOnce() -> T,
) -> Result<T, AllocationTraceSetupError> {
    TRACE
        .try_with(|cell| {
            if cell.get().is_some() || !trace.arm() {
                return Err(AllocationTraceSetupError::AlreadyArmed);
            }
            cell.set(Some(trace));
            Ok(())
        })
        .map_err(|_| AllocationTraceSetupError::Unavailable)??;
    let _reset = Reset(trace);
    Ok(action())
}

// Each public capture binds one of the four original storage capacities to a
// closed selector variant. Unsupported sizes cannot arm allocator observation.
macro_rules! define_capture {
    ($capacity:literal, $variant:ident) => {
        impl AllocationTrace<$capacity> {
            /// Captures this thread's requests in its original fixed storage.
            ///
            /// Nested capture refuses before resetting either storage or the
            /// existing selector. Live count reads preserve constructor-to-loan
            /// correlation. Return and unwind disarm capture; scalar entries
            /// remain readable to the owner. Other threads are excluded.
            ///
            /// # Errors
            /// Refuses overlapping thread/storage capture or unavailable TLS.
            ///
            /// # Panics
            /// Propagates an action panic after disarming capture.
            pub fn capture<T>(
                &'static self,
                action: impl FnOnce() -> T,
            ) -> Result<T, AllocationTraceSetupError> {
                capture(SelectedTrace::$variant(self), action)
            }
        }
    };
}

define_capture!(16, Sixteen);
define_capture!(32, ThirtyTwo);
define_capture!(64, SixtyFour);
define_capture!(512, FiveTwelve);

pub(super) fn record(address: usize, layout: Layout, reallocation: bool) {
    let _ = TRACE.try_with(|cell| {
        if let Some(trace) = cell.get() {
            trace.record(address, layout, reallocation);
        }
    });
}
