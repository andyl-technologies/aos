//! Observes actual backend cause deallocation before original credit release.
//!
//! The shared observer reads the originally admitted authority's live counter
//! after the selected control is physically freed. Scoped borrowers retain that
//! authority through every observation and join; they share no observer lock.

// crucible-lint: allow panic-shortcut -- causal fixtures panic outside allocator observation to identify ownership failures.
#![allow(clippy::unwrap_used)]

use std::alloc::Layout;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crucible::BackendOperationalCause;
use crucible::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, DecodeScratch,
};

use crucible_linux_resource::test_support::{AllocationIdentity, TestAllocationObserver};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

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
    target: AllocationIdentity,
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
    assert!(funded > baseline);
    assert!(funded > 0);

    let (cause, target, counts) =
        TestAllocationObserver::capture_layout_and_count(layout.pad_to_align(), || {
            BackendOperationalCause::new(FundedFailure {
                _original_credit: credit,
            })
        });
    let target = target.unwrap();
    assert_eq!(
        counts.allocations, 1,
        "cause constructor allocated more than one body"
    );
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);

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

    let ((), observed) =
        TestAllocationObserver::observe_atomic_after_free(&authority.used, target, || drop(clone));

    assert_eq!(
        observed,
        Some(funded),
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
                    let ((), observed) = TestAllocationObserver::observe_atomic_after_free(
                        &authority.used,
                        target,
                        || {
                            barrier.wait();
                            drop(cause);
                        },
                    );
                    observed
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });

    assert_eq!(observations.len(), 8);
    assert_eq!(
        observations
            .iter()
            .filter(|&&value| value == Some(funded))
            .count(),
        1
    );
    assert_eq!(
        observations.iter().filter(|value| value.is_none()).count(),
        7
    );
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

    let (result, observed) =
        TestAllocationObserver::observe_atomic_after_free(&authority.used, target, || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _original = cause;
                panic!("intentional backend observer unwind");
            }))
        });

    assert!(result.is_err());
    assert_eq!(observed, Some(funded));
    assert_eq!(authority.used.load(Ordering::SeqCst), baseline);
}
