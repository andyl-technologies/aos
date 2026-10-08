//! Observes original individual loans at actual enclosing control deallocation.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use std::sync::{Arc, Mutex};

use crucible_cas::content_store::{CheckedReader, StoreError, StorePhysicalQuotaGuard};
use crucible_cas::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeCustody, DecodeResourceAuthority, DecodeScope,
    DecodeScratch, ResourceLoan, current_budget,
};

const GRANTS: usize = 16;
const NOT_OBSERVED: u64 = u64::MAX;

static SERIAL: Mutex<()> = Mutex::new(());
static MAXIMUM: AtomicU64 = AtomicU64::new(4096);
static USED: AtomicU64 = AtomicU64::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static VERIFICATIONS: AtomicUsize = AtomicUsize::new(0);
static CLOSED: AtomicBool = AtomicBool::new(false);
static REQUESTED: [AtomicU64; GRANTS] = [const { AtomicU64::new(0) }; GRANTS];
static PAID: [AtomicU64; GRANTS] = [const { AtomicU64::new(0) }; GRANTS];
static REFUNDS: [AtomicUsize; GRANTS] = [const { AtomicUsize::new(0) }; GRANTS];
static ACCOUNT_CONTROL: AtomicUsize = AtomicUsize::new(0);
static AUTHORITY_CONTROL: AtomicUsize = AtomicUsize::new(0);
static ACCOUNT_GRANT: AtomicUsize = AtomicUsize::new(1);
static ACCOUNT_PAID_AT_CLOSE: AtomicU64 = AtomicU64::new(NOT_OBSERVED);
static AUTHORITY_PAID_AT_CLOSE: AtomicU64 = AtomicU64::new(NOT_OBSERVED);

#[derive(Clone, Copy, Default)]
struct Allocation {
    address: usize,
    bytes: usize,
}

#[derive(Clone, Copy)]
struct Capture {
    active: bool,
    arm_authority: bool,
    count: usize,
    overflow: bool,
    allocations: [Allocation; GRANTS],
}

const EMPTY_CAPTURE: Capture = Capture {
    active: false,
    arm_authority: false,
    count: 0,
    overflow: false,
    allocations: [Allocation {
        address: 0,
        bytes: 0,
    }; GRANTS],
};

thread_local! {
    static CAPTURE: Cell<Capture> = const { Cell::new(EMPTY_CAPTURE) };
}

struct ObservingAllocator;

// SAFETY: Original System pointer/layout pairs are passed through unchanged.
// Observation uses fixed TLS scalars and static atomics only, with no borrowed
// pointer, callback, allocation, blocking lock or panic inside the allocator.
unsafe impl GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The original valid layout is delegated unchanged to System.
        let pointer = unsafe { System.alloc(layout) };
        let _ = CAPTURE.try_with(|cell| {
            let mut capture = cell.get();
            if !capture.active {
                return;
            }
            if capture.count < GRANTS {
                capture.allocations[capture.count] = Allocation {
                    address: pointer as usize,
                    bytes: layout.size(),
                };
                capture.count += 1;
            } else {
                capture.overflow = true;
            }
            if capture.arm_authority
                && layout.size() == REQUESTED[0].load(Ordering::SeqCst) as usize
            {
                capture.arm_authority = false;
                AUTHORITY_CONTROL.store(pointer as usize, Ordering::SeqCst);
            }
            cell.set(capture);
        });
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if ACCOUNT_CONTROL.load(Ordering::SeqCst) == pointer as usize {
            let grant = ACCOUNT_GRANT.load(Ordering::SeqCst);
            if let Some(paid) = PAID.get(grant) {
                let _ = ACCOUNT_PAID_AT_CLOSE.compare_exchange(
                    NOT_OBSERVED,
                    paid.load(Ordering::SeqCst),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            }
        }
        if AUTHORITY_CONTROL.load(Ordering::SeqCst) == pointer as usize {
            let _ = AUTHORITY_PAID_AT_CLOSE.compare_exchange(
                NOT_OBSERVED,
                PAID[0].load(Ordering::SeqCst),
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
        // SAFETY: The original allocation is freed once with its original layout.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: ObservingAllocator = ObservingAllocator;

struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        ACCOUNT_CONTROL.store(0, Ordering::SeqCst);
        AUTHORITY_CONTROL.store(0, Ordering::SeqCst);
        CAPTURE.with(|capture| capture.set(EMPTY_CAPTURE));
    }
}

fn original(maximum: u64) -> (std::sync::MutexGuard<'static, ()>, Reset) {
    let serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    assert_eq!(USED.load(Ordering::SeqCst), 0);
    MAXIMUM.store(maximum, Ordering::SeqCst);
    CALLS.store(0, Ordering::SeqCst);
    VERIFICATIONS.store(0, Ordering::SeqCst);
    CLOSED.store(false, Ordering::SeqCst);
    ACCOUNT_CONTROL.store(0, Ordering::SeqCst);
    AUTHORITY_CONTROL.store(0, Ordering::SeqCst);
    ACCOUNT_GRANT.store(1, Ordering::SeqCst);
    ACCOUNT_PAID_AT_CLOSE.store(NOT_OBSERVED, Ordering::SeqCst);
    AUTHORITY_PAID_AT_CLOSE.store(NOT_OBSERVED, Ordering::SeqCst);
    for requested in &REQUESTED {
        requested.store(0, Ordering::SeqCst);
    }
    for grant in &PAID {
        grant.store(0, Ordering::SeqCst);
    }
    for refunds in &REFUNDS {
        refunds.store(0, Ordering::SeqCst);
    }
    (serial, Reset)
}

struct Credit {
    grant: usize,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        REFUNDS[self.grant].fetch_add(1, Ordering::SeqCst);
        PAID[self.grant].store(0, Ordering::SeqCst);
        USED.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

struct Guard;

impl StorePhysicalQuotaGuard for Guard {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(MAXIMUM.load(Ordering::SeqCst))
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        assert_eq!(descriptors, 0);
        let grant = CALLS.fetch_add(1, Ordering::SeqCst);
        assert!(grant < GRANTS);
        REQUESTED[grant].store(bytes, Ordering::SeqCst);
        let control = ResourceLoan::allocation_bytes::<Credit>();
        let charged = bytes.checked_add(control).ok_or(StoreError::Quota)?;
        USED.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
            used.checked_add(charged)
                .filter(|next| *next <= MAXIMUM.load(Ordering::SeqCst))
        })
        .map_err(|_| StoreError::Quota)?;
        assert!(grant < GRANTS);
        PAID[grant].store(charged, Ordering::SeqCst);
        Ok(ResourceLoan::new(Credit {
            grant,
            bytes: charged,
        }))
    }

    fn verify(&self) -> Result<(), StoreError> {
        VERIFICATIONS.fetch_add(1, Ordering::SeqCst);
        if CLOSED.load(Ordering::SeqCst) {
            Err(StoreError::Quota)
        } else {
            Ok(())
        }
    }
}

fn capture<T>(arm_authority: bool, action: impl FnOnce() -> T) -> (T, Capture) {
    CAPTURE.with(|cell| {
        cell.set(Capture {
            active: true,
            arm_authority,
            ..EMPTY_CAPTURE
        })
    });
    let value = action();
    let captured = CAPTURE.with(|cell| cell.replace(EMPTY_CAPTURE));
    assert!(!captured.overflow);
    (value, captured)
}

fn control_for(capture: &Capture, bytes: u64) -> usize {
    // Each paid native enclosing control has a unique actual System extent in
    // this constructor. Loan controls have their separately funded extent.
    let mut matches = capture.allocations[..capture.count]
        .iter()
        .filter(|allocation| allocation.bytes as u64 == bytes);
    let allocation = matches
        .next()
        .unwrap_or_else(|| panic!("the paid enclosing extent must identify an actual allocation"));
    assert!(
        matches.next().is_none(),
        "control identification must be unique"
    );
    allocation.address
}

fn native() -> DecodeBudget {
    let (budget, allocations) = capture(false, || {
        DecodeBudget::for_store(Arc::new(Guard))
            .unwrap_or_else(|error| panic!("original grant: {error}"))
    });
    ACCOUNT_CONTROL.store(
        control_for(&allocations, REQUESTED[1].load(Ordering::SeqCst)),
        Ordering::SeqCst,
    );
    AUTHORITY_CONTROL.store(
        control_for(&allocations, REQUESTED[0].load(Ordering::SeqCst)),
        Ordering::SeqCst,
    );
    budget
}

fn assert_paid_close(account: u64, authority: u64) {
    assert_eq!(ACCOUNT_PAID_AT_CLOSE.load(Ordering::SeqCst), account);
    assert_eq!(AUTHORITY_PAID_AT_CLOSE.load(Ordering::SeqCst), authority);
    assert_eq!(USED.load(Ordering::SeqCst), 0);
    assert_eq!(REFUNDS[0].load(Ordering::SeqCst), 1);
    assert_eq!(REFUNDS[1].load(Ordering::SeqCst), 1);
}

#[test]
fn actual_enclosing_controls_close_with_their_individual_original_loans_live() {
    let (_serial, _reset) = original(4096);
    let budget = native();
    let account = PAID[1].load(Ordering::SeqCst);
    let authority = PAID[0].load(Ordering::SeqCst);
    let moved = budget;
    let last = moved.clone();

    drop(moved);
    assert_eq!(ACCOUNT_PAID_AT_CLOSE.load(Ordering::SeqCst), NOT_OBSERVED);
    drop(last);

    assert_paid_close(account, authority);
}

#[test]
fn child_custody_and_closed_cleanup_keep_the_original_authority_identity() {
    let (_serial, _reset) = original(4096);
    let parent = native();
    let account = PAID[1].load(Ordering::SeqCst);
    let authority = PAID[0].load(Ordering::SeqCst);
    assert!(parent.is_exclusive());
    let child = parent.child().unwrap();
    let custody = child.custody();
    assert!(!parent.is_exclusive());
    let before = CALLS.load(Ordering::SeqCst);
    let verifications = VERIFICATIONS.load(Ordering::SeqCst);
    CLOSED.store(true, Ordering::SeqCst);
    assert!(!parent.is_exclusive());
    assert_eq!(CALLS.load(Ordering::SeqCst), before);
    assert_eq!(VERIFICATIONS.load(Ordering::SeqCst), verifications);

    drop(child);
    assert!(!parent.is_exclusive());
    drop(custody);
    assert!(parent.is_exclusive());
    assert!(parent.child().is_err());
    assert_eq!(CALLS.load(Ordering::SeqCst), before);
    drop(parent);

    assert_paid_close(account, authority);
    assert_eq!(REFUNDS[2].load(Ordering::SeqCst), 1);
}

#[test]
fn concurrent_aliases_close_original_controls_and_refund_once() {
    let (_serial, _reset) = original(4096);
    let budget = native();
    let account = PAID[1].load(Ordering::SeqCst);
    let authority = PAID[0].load(Ordering::SeqCst);
    let barrier = Arc::new(std::sync::Barrier::new(9));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let alias = budget.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            drop(alias);
        }));
    }
    drop(budget);
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(std::thread::JoinHandle::join)
        .collect();
    assert!(results.iter().all(Result::is_ok));

    assert_paid_close(account, authority);
}

#[test]
fn valid_borrower_unwind_closes_enclosing_controls_before_their_refunds() {
    let (_serial, _reset) = original(4096);
    let budget = native();
    let account = PAID[1].load(Ordering::SeqCst);
    let authority = PAID[0].load(Ordering::SeqCst);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _last = budget;
        panic!("intentional valid borrower unwind");
    }));
    assert!(result.is_err());

    assert_paid_close(account, authority);
}

struct ExternalAuthority;

impl DecodeResourceAuthority for ExternalAuthority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        Guard.verify().map_err(DecodeAdmissionError::new)
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        Guard
            .reserve_resources(0, bytes)
            .map_err(DecodeAdmissionError::new)
    }
}

#[test]
fn public_external_authority_aliases_keep_their_existing_exclusivity_contract() {
    let (_serial, _reset) = original(4096);
    ACCOUNT_GRANT.store(0, Ordering::SeqCst);
    let external = Arc::new(ExternalAuthority);
    let (budget, allocations) =
        capture(false, || DecodeBudget::new(external.clone(), 4096).unwrap());
    ACCOUNT_CONTROL.store(
        control_for(&allocations, REQUESTED[0].load(Ordering::SeqCst)),
        Ordering::SeqCst,
    );
    let original_account = PAID[0].load(Ordering::SeqCst);
    assert!(!budget.is_exclusive());
    drop(external);
    assert!(budget.is_exclusive());
    let child = budget.child().unwrap();
    assert!(!budget.is_exclusive());
    drop(child);
    CLOSED.store(true, Ordering::SeqCst);
    let before = VERIFICATIONS.load(Ordering::SeqCst);
    assert!(budget.is_exclusive());
    assert_eq!(VERIFICATIONS.load(Ordering::SeqCst), before);
    drop(budget);

    assert_eq!(
        ACCOUNT_PAID_AT_CLOSE.load(Ordering::SeqCst),
        original_account
    );
    assert_eq!(USED.load(Ordering::SeqCst), 0);
    assert_eq!(REFUNDS[0].load(Ordering::SeqCst), 1);
    assert_eq!(REFUNDS[1].load(Ordering::SeqCst), 1);
}

#[test]
fn nullable_custody_and_nested_scopes_restore_the_same_original_account() {
    let (_serial, _reset) = original(4096);
    assert!(current_budget().is_none());
    assert!(DecodeCustody::default().enter().is_none());
    let parent = native();
    let account = PAID[1].load(Ordering::SeqCst);
    let authority = PAID[0].load(Ordering::SeqCst);
    let custody = parent.custody();
    let scope = parent.enter();
    let child = parent.child().unwrap();
    let child_failure = DecodeAdmissionError::new(ScopedRefusal);
    child.record_failure(child_failure.clone());
    let nested = child.enter();
    let installed = current_budget().unwrap();
    assert_eq!(installed.failure().unwrap(), Some(child_failure.clone()));
    drop(installed);
    drop(nested);
    let restored = current_budget().unwrap();
    assert!(restored.check().is_ok());
    assert!(parent.failure().unwrap().is_none());
    drop(restored);
    drop(child);
    drop(scope);
    assert!(current_budget().is_none());
    let restored = custody.enter().unwrap();
    assert!(!parent.is_exclusive());
    drop(restored);
    drop(custody);
    assert!(parent.is_exclusive());
    drop(parent);

    assert_paid_close(account, authority);
}

#[test]
fn account_refusal_keeps_the_prepaid_native_authority_control_live_until_free() {
    for maximum in [100, 200] {
        let (_serial, _reset) = original(maximum);
        let (result, _) = capture(true, || DecodeBudget::for_store(Arc::new(Guard)));
        assert!(result.is_err());
        assert_ne!(
            REQUESTED[0].load(Ordering::SeqCst),
            ResourceLoan::allocation_bytes::<Credit>(),
        );
        assert_ne!(AUTHORITY_CONTROL.load(Ordering::SeqCst), 0);
        assert_eq!(
            AUTHORITY_PAID_AT_CLOSE.load(Ordering::SeqCst),
            REQUESTED[0].load(Ordering::SeqCst) + ResourceLoan::allocation_bytes::<Credit>()
        );
        assert_eq!(USED.load(Ordering::SeqCst), 0);
        assert_eq!(REFUNDS[0].load(Ordering::SeqCst), 1);
    }
}

#[test]
fn owner_and_nullable_slot_geometry_preserve_stored_custody() {
    let (_serial, _reset) = original(4096);
    let budget = native();
    eprintln!(
        "DECODE_OWNER_LAYOUT account_control={} authority_control={} budget={} optional_budget={} custody={} optional_custody={} scope={} optional_scope={} scratch={} optional_scratch={} checked_reader={}",
        REQUESTED[1].load(Ordering::SeqCst),
        REQUESTED[0].load(Ordering::SeqCst),
        std::mem::size_of::<DecodeBudget>(),
        std::mem::size_of::<Option<DecodeBudget>>(),
        std::mem::size_of::<DecodeCustody>(),
        std::mem::size_of::<Option<DecodeCustody>>(),
        std::mem::size_of::<DecodeScope>(),
        std::mem::size_of::<Option<DecodeScope>>(),
        std::mem::size_of::<DecodeScratch>(),
        std::mem::size_of::<Option<DecodeScratch>>(),
        std::mem::size_of::<CheckedReader>(),
    );
    assert_eq!(std::mem::size_of::<DecodeBudget>(), 8);
    assert_eq!(std::mem::size_of::<DecodeCustody>(), 8);
    assert_eq!(std::mem::size_of::<DecodeScope>(), 8);
    drop(budget);
    assert_eq!(USED.load(Ordering::SeqCst), 0);
}

#[derive(Debug)]
struct ScopedRefusal;

impl std::fmt::Display for ScopedRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original nested child fixture refusal")
    }
}

impl std::error::Error for ScopedRefusal {}
