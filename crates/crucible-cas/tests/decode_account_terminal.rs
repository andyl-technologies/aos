//! Observes original individual loans at actual enclosing control deallocation.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use std::sync::{Arc, Mutex};

use crucible_linux_resource::test_support::{
    AllocationIdentity, AllocationTrace, OriginalControlSelection, OriginalControlSession,
    OriginalControlSlot, OriginalControlSnapshot, OriginalControlsOutcome, OriginalStaticCounters,
    TestAllocationObserver,
};

use crucible_cas::content_store::{CheckedReader, StoreError, StorePhysicalQuotaGuard};
use crucible_cas::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeCustody, DecodeResourceAuthority, DecodeScope,
    DecodeScratch, ResourceLoan, current_budget,
};

const GRANTS: usize = 16;

static SERIAL: Mutex<()> = Mutex::new(());
static MAXIMUM: AtomicU64 = AtomicU64::new(4096);
static USED: AtomicU64 = AtomicU64::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static VERIFICATIONS: AtomicUsize = AtomicUsize::new(0);
static CLOSED: AtomicBool = AtomicBool::new(false);
static REQUESTED: [AtomicU64; GRANTS] = [const { AtomicU64::new(0) }; GRANTS];
static PAID: [AtomicU64; GRANTS] = [const { AtomicU64::new(0) }; GRANTS];
static REFUNDS: [AtomicUsize; GRANTS] = [const { AtomicUsize::new(0) }; GRANTS];
static TRACE: AllocationTrace<GRANTS> = AllocationTrace::new();

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

fn original(maximum: u64) -> std::sync::MutexGuard<'static, ()> {
    let serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    assert_eq!(USED.load(Ordering::SeqCst), 0);
    MAXIMUM.store(maximum, Ordering::SeqCst);
    CALLS.store(0, Ordering::SeqCst);
    VERIFICATIONS.store(0, Ordering::SeqCst);
    CLOSED.store(false, Ordering::SeqCst);
    for requested in &REQUESTED {
        requested.store(0, Ordering::SeqCst);
    }
    for grant in &PAID {
        grant.store(0, Ordering::SeqCst);
    }
    for refunds in &REFUNDS {
        refunds.store(0, Ordering::SeqCst);
    }
    serial
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

fn capture<T>(action: impl FnOnce() -> T) -> T {
    let value = TRACE
        .capture(action)
        .unwrap_or_else(|error| panic!("original allocation trace: {error}"));
    assert!(!TRACE.overflowed());
    assert_eq!(TRACE.reallocations(), 0);
    assert_eq!(TRACE.entries().count(), TRACE.allocation_count());
    value
}

fn control_for(bytes: u64) -> AllocationIdentity {
    // Each paid native enclosing control has a unique actual System extent in
    // this constructor. Loan controls have their separately funded extent.
    let mut matches = TRACE
        .entries()
        .filter(|allocation| allocation.bytes() as u64 == bytes);
    let allocation = matches
        .next()
        .unwrap_or_else(|| panic!("the paid enclosing extent must identify an actual allocation"));
    assert!(
        matches.next().is_none(),
        "control identification must be unique"
    );
    allocation.identity()
}

fn native(session: &OriginalControlSession) -> DecodeBudget {
    let budget = capture(|| {
        DecodeBudget::for_store(Arc::new(Guard))
            .unwrap_or_else(|error| panic!("original grant: {error}"))
    });
    session
        .arm(
            OriginalControlSlot::First,
            OriginalControlSelection::Explicit(control_for(REQUESTED[1].load(Ordering::SeqCst))),
            OriginalStaticCounters::U64(&PAID[1]),
            false,
        )
        .unwrap_or_else(|error| panic!("original control arm/report: {error}"));
    session
        .arm(
            OriginalControlSlot::Second,
            OriginalControlSelection::Explicit(control_for(REQUESTED[0].load(Ordering::SeqCst))),
            OriginalStaticCounters::U64(&PAID[0]),
            false,
        )
        .unwrap_or_else(|error| panic!("original control arm/report: {error}"));
    budget
}

fn assert_paid_close(session: &OriginalControlSession, account: u64, authority: u64) {
    let report = session
        .report()
        .unwrap_or_else(|error| panic!("original control arm/report: {error}"));
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
    assert_eq!(
        report.controls[0]
            .unwrap_or_else(|| panic!("actual original account control must close"))
            .before,
        OriginalControlSnapshot::U64(account)
    );
    assert_eq!(
        report.controls[1]
            .unwrap_or_else(|| panic!("actual original authority control must close"))
            .before,
        OriginalControlSnapshot::U64(authority)
    );
    assert_eq!(USED.load(Ordering::SeqCst), 0);
    assert_eq!(REFUNDS[0].load(Ordering::SeqCst), 1);
    assert_eq!(REFUNDS[1].load(Ordering::SeqCst), 1);
}

#[test]
fn actual_enclosing_controls_close_with_their_individual_original_loans_live() {
    let _serial = original(4096);
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        let budget = native(session);
        let account = PAID[1].load(Ordering::SeqCst);
        let authority = PAID[0].load(Ordering::SeqCst);
        let moved = budget;
        let last = moved.clone();

        drop(moved);
        assert!(session.report().unwrap().controls[0].is_none());
        drop(last);

        assert_paid_close(session, account, authority);
    })
    .unwrap();
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
}

#[test]
fn child_custody_and_closed_cleanup_keep_the_original_authority_identity() {
    let _serial = original(4096);
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        let parent = native(session);
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

        assert_paid_close(session, account, authority);
        assert_eq!(REFUNDS[2].load(Ordering::SeqCst), 1);
    })
    .unwrap();
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
}

#[test]
fn concurrent_aliases_close_original_controls_and_refund_once() {
    let _serial = original(4096);
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        let budget = native(session);
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

        assert_paid_close(session, account, authority);
    })
    .unwrap();
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
}

#[test]
fn valid_borrower_unwind_closes_enclosing_controls_before_their_refunds() {
    let _serial = original(4096);
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        let budget = native(session);
        let account = PAID[1].load(Ordering::SeqCst);
        let authority = PAID[0].load(Ordering::SeqCst);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _last = budget;
            panic!("intentional valid borrower unwind");
        }));
        assert!(result.is_err());

        assert_paid_close(session, account, authority);
    })
    .unwrap();
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
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
    let _serial = original(4096);
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        let external = Arc::new(ExternalAuthority);
        let budget = capture(|| DecodeBudget::new(external.clone(), 4096).unwrap());
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::Explicit(control_for(
                    REQUESTED[0].load(Ordering::SeqCst),
                )),
                OriginalStaticCounters::U64(&PAID[0]),
                false,
            )
            .unwrap();
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
            session.report().unwrap().controls[0].unwrap().before,
            OriginalControlSnapshot::U64(original_account)
        );
        assert_eq!(USED.load(Ordering::SeqCst), 0);
        assert_eq!(REFUNDS[0].load(Ordering::SeqCst), 1);
        assert_eq!(REFUNDS[1].load(Ordering::SeqCst), 1);
    })
    .unwrap();
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
}

#[test]
fn nullable_custody_and_nested_scopes_restore_the_same_original_account() {
    let _serial = original(4096);
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        assert!(current_budget().is_none());
        assert!(DecodeCustody::default().enter().is_none());
        let parent = native(session);
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

        assert_paid_close(session, account, authority);
    })
    .unwrap();
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
}

#[test]
fn account_refusal_keeps_the_prepaid_native_authority_control_live_until_free() {
    for maximum in [100, 200] {
        let _serial = original(maximum);
        let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
            session
                .arm(
                    OriginalControlSlot::Second,
                    OriginalControlSelection::FirstThreadRequestedExtent(&REQUESTED[0]),
                    OriginalStaticCounters::U64(&PAID[0]),
                    false,
                )
                .unwrap();
            let result = capture(|| DecodeBudget::for_store(Arc::new(Guard)));
            assert!(result.is_err());
            assert_ne!(
                REQUESTED[0].load(Ordering::SeqCst),
                ResourceLoan::allocation_bytes::<Credit>(),
            );
            assert!(session.report().unwrap().controls[1].is_some());
            assert_eq!(
                session.report().unwrap().controls[1].unwrap().before,
                OriginalControlSnapshot::U64(
                    REQUESTED[0].load(Ordering::SeqCst)
                        + ResourceLoan::allocation_bytes::<Credit>()
                )
            );
            assert_eq!(USED.load(Ordering::SeqCst), 0);
            assert_eq!(REFUNDS[0].load(Ordering::SeqCst), 1);
        })
        .unwrap();
        assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
    }
}

#[test]
fn owner_and_nullable_slot_geometry_preserve_stored_custody() {
    let _serial = original(4096);
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        let budget = native(session);
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
    })
    .unwrap();
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
}

#[derive(Debug)]
struct ScopedRefusal;

impl std::fmt::Display for ScopedRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original nested child fixture refusal")
    }
}

impl std::error::Error for ScopedRefusal {}
