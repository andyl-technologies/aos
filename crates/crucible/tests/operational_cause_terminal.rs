//! Observes actual backend cause deallocation before original credit release.
//!
//! The exact same test target runs against the preceding ordinary Arc owner.
//! Observation only reads the originally admitted authority's live counter;
//! it neither allocates, logs nor locks another observer inside the allocator.

// crucible-lint: allow panic-shortcut -- causal fixtures panic outside allocator observation to identify ownership failures.
#![allow(clippy::unwrap_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crucible::BackendOperationalCause;
use crucible::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, DecodeScratch,
};

#[derive(Clone, Copy)]
struct Watch {
    capture: bool,
    expected_size: usize,
    expected_alignment: usize,
    count_allocations: bool,
    allocations: usize,
    target: usize,
    original_used: *const AtomicU64,
    expected_used: u64,
    observation: u8,
}

thread_local! {
    static WATCH: Cell<Watch> = const { Cell::new(empty_watch()) };
}

const fn empty_watch() -> Watch {
    Watch {
        capture: false,
        expected_size: 0,
        expected_alignment: 0,
        count_allocations: false,
        allocations: 0,
        target: 0,
        original_used: std::ptr::null(),
        expected_used: 0,
        observation: 0,
    }
}

struct ObserverAllocator;

// SAFETY: System receives every original allocation request unchanged. The
// watch is thread-local and compares addresses without reading freed contents.
unsafe impl GlobalAlloc for ObserverAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller's exact layout is forwarded to System.
        let pointer = unsafe { System.alloc(layout) };
        let _ = WATCH.try_with(|watch| {
            let mut state = watch.get();
            if state.count_allocations {
                state.allocations += 1;
            }
            if state.capture
                && layout.size() == state.expected_size
                && layout.align() == state.expected_alignment
            {
                state.capture = false;
                state.target = pointer as usize;
            }
            watch.set(state);
        });
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let observed = WATCH
            .try_with(|watch| {
                let mut state = watch.get();
                if state.target != 0 && state.target == pointer as usize {
                    state.target = 0;
                    watch.set(state);
                    Some(state)
                } else {
                    None
                }
            })
            .ok()
            .flatten();

        // SAFETY: The original pointer and layout are delegated exactly once.
        unsafe { System.dealloc(pointer, layout) };

        if let Some(mut state) = observed {
            // SAFETY: The original authority remains strongly owned by the
            // synchronous test or thread scope until this drop finishes. Its
            // counter address never escapes TLS or outlives that scope.
            let live = unsafe { &*state.original_used }.load(Ordering::SeqCst);
            state.observation = if live == state.expected_used { 1 } else { 2 };
            let _ = WATCH.try_with(|watch| watch.set(state));
        }
    }
}

#[global_allocator]
static ALLOCATOR: ObserverAllocator = ObserverAllocator;

struct Authority {
    used: AtomicU64,
    maximum: u64,
}

struct Credit {
    authority: Arc<Authority>,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.authority.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

struct AuthorityOwner(Arc<Authority>);

impl DecodeResourceAuthority for AuthorityOwner {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.0.used.load(Ordering::SeqCst) > self.0.maximum {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original allowance unavailable",
            )));
        }
        Ok(())
    }

    fn reserve(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, DecodeAdmissionError> {
        self.0
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|&next| next <= self.0.maximum)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("original allowance exhausted"))
            })?;
        Ok(crucible_cas::owned_decode::ResourceLoan::new(Credit {
            authority: self.0.clone(),
            bytes,
        }))
    }
}

struct FundedFailure {
    _original_credit: DecodeScratch,
}

impl fmt::Debug for FundedFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FundedFailure")
    }
}

impl fmt::Display for FundedFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original funded failure")
    }
}

impl Error for FundedFailure {}

struct Fixture {
    authority: Arc<Authority>,
    _budget: DecodeBudget,
    baseline: u64,
    funded: u64,
    target: usize,
    cause: BackendOperationalCause,
}

fn fixture() -> Fixture {
    let authority = Arc::new(Authority {
        used: AtomicU64::new(0),
        maximum: 65536,
    });
    let budget = DecodeBudget::new(Arc::new(AuthorityOwner(authority.clone())), 65536).unwrap();
    let baseline = authority.used.load(Ordering::SeqCst);
    let (layout, _) = Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<FundedFailure>())
        .unwrap();
    let extent = layout.pad_to_align().size();
    let credit = budget.reserve_scratch_bytes(extent as u64).unwrap();
    let funded = authority.used.load(Ordering::SeqCst);
    WATCH.with(|watch| {
        watch.set(Watch {
            capture: true,
            expected_size: extent,
            expected_alignment: layout.align(),
            count_allocations: true,
            ..empty_watch()
        })
    });
    let cause = BackendOperationalCause::new(FundedFailure {
        _original_credit: credit,
    });
    let captured = WATCH.with(|watch| watch.replace(empty_watch()));
    let target = captured.target;
    assert_ne!(
        target, 0,
        "actual concrete Arc differs from admitted extent"
    );
    assert_eq!(
        captured.allocations, 1,
        "cause constructor allocated more than one body"
    );
    println!(
        "concrete_failure_body={} control_extent={extent} control_alignment={} erased_handle={}",
        std::mem::size_of::<FundedFailure>(),
        layout.align(),
        std::mem::size_of::<BackendOperationalCause>(),
    );
    Fixture {
        authority,
        _budget: budget,
        baseline,
        funded,
        target,
        cause,
    }
}

fn arm(authority: &Authority, target: usize, funded: u64) {
    WATCH.with(|watch| {
        watch.set(Watch {
            target,
            original_used: &authority.used,
            expected_used: funded,
            ..empty_watch()
        })
    });
}

fn observation() -> u8 {
    WATCH.with(|watch| watch.replace(empty_watch())).observation
}

#[test]
fn actual_backend_control_closes_before_original_credit_refund() {
    let Fixture {
        authority,
        _budget,
        baseline,
        funded,
        target,
        cause,
    } = fixture();
    let clone = cause.clone();
    assert_eq!(cause, clone);
    assert!(cause.source().unwrap().is::<FundedFailure>());
    drop(cause);
    assert_eq!(authority.used.load(Ordering::SeqCst), funded);

    arm(&authority, target, funded);
    drop(clone);
    let observed = observation();

    assert_eq!(
        observed, 1,
        "original credit refunded before actual control free"
    );
    assert_eq!(authority.used.load(Ordering::SeqCst), baseline);
    assert_eq!(std::mem::size_of::<BackendOperationalCause>(), 16);
}

#[test]
fn concurrent_backend_observers_close_control_before_one_original_refund() {
    let Fixture {
        authority,
        _budget,
        baseline,
        funded,
        target,
        cause,
    } = fixture();
    let barrier = std::sync::Barrier::new(8);
    let clones: Vec<_> = (0..8).map(|_| cause.clone()).collect();
    drop(cause);

    let observations = std::thread::scope(|scope| {
        let workers: Vec<_> = clones
            .into_iter()
            .map(|cause| {
                let authority = &authority;
                let barrier = &barrier;
                scope.spawn(move || {
                    arm(authority, target, funded);
                    barrier.wait();
                    drop(cause);
                    observation()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });

    assert_eq!(observations.iter().filter(|&&value| value == 1).count(), 1);
    assert!(observations.iter().all(|&value| value <= 1));
    assert_eq!(authority.used.load(Ordering::SeqCst), baseline);
}

#[test]
fn backend_observer_unwind_closes_control_before_original_refund() {
    let Fixture {
        authority,
        _budget,
        baseline,
        funded,
        target,
        cause,
    } = fixture();

    arm(&authority, target, funded);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _original = cause;
        panic!("intentional backend observer unwind");
    }));
    let observed = observation();

    assert!(result.is_err());
    assert_eq!(observed, 1);
    assert_eq!(authority.used.load(Ordering::SeqCst), baseline);
}
