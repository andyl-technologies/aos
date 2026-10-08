//! Typed checkpoint failures across scheduler clones and original-account close.
//!
//! Finite fixture loans model an original allowance; they do not establish
//! physical funding of the fixture's own controls or incoming error allocations.
//! SQL cases use the existing capped native transaction and cleanup fixture.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::error::Error;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crucible::{SchedulerError, SchedulerOperationalFailureClass};
use crucible_cas::content_store::{
    SqliteBlobBackend, SqliteCatalogOperation, SqliteCatalogOperationKind, SqliteCatalogSupervisor,
    SqliteCommitOutcome, StoreError,
};
use crucible_cas::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, ResourceLoan,
};
use crucible_cas::ram::{
    PreparedRamFailure, RamFailureAdmission, RamOperationFailure, RamStoreError,
};

thread_local! {
    static ALLOCATION_COUNT: Cell<Option<usize>> = const { Cell::new(None) };
    static ALLOCATION_LAYOUT: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
}

struct ObserverAllocator;

// SAFETY: Every original pointer and layout is forwarded unchanged to System.
// The thread-local observer counts calls without allocating or accessing memory.
unsafe impl GlobalAlloc for ObserverAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATION_COUNT.try_with(|count| {
            if let Some(value) = count.get() {
                count.set(Some(value + 1));
                let _ = ALLOCATION_LAYOUT.try_with(|observed| {
                    observed.set(Some((layout.size(), layout.align())));
                });
            }
        });
        // SAFETY: The caller's exact layout is forwarded to System.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The caller's original pointer and layout are forwarded unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObserverAllocator = ObserverAllocator;

// The existing SQL scope fixture reserves a sixfold diagnostic-copy bound for
// its 8 MiB native heap. Match its established 64 MiB finite fixture allowance.
const MODEL_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Default)]
struct AccountState {
    used: AtomicU64,
    reservations: AtomicUsize,
    closed: AtomicBool,
}

#[derive(Debug)]
struct OriginalClosed;

impl fmt::Display for OriginalClosed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original fixture authority closed")
    }
}

impl Error for OriginalClosed {}

struct Authority(Arc<AccountState>);

struct Credit {
    state: Arc<AccountState>,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.state.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(DecodeAdmissionError::new(OriginalClosed));
        }
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        if self
            .0
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= MODEL_LIMIT)
            })
            .is_err()
        {
            return Err(DecodeAdmissionError::new(OriginalClosed));
        }
        self.0.reservations.fetch_add(1, Ordering::AcqRel);
        Ok(ResourceLoan::new(Credit {
            state: self.0.clone(),
            bytes,
        }))
    }
}

// crucible-lint: allow panic-shortcut -- model setup requires its admitted original before testing first-cause custody.
#[allow(clippy::unwrap_used)]
fn account() -> (DecodeBudget, Arc<AccountState>) {
    let state = Arc::new(AccountState::default());
    let original = DecodeBudget::new(Arc::new(Authority(state.clone())), MODEL_LIMIT).unwrap();
    (original, state)
}

fn canceled() -> SchedulerError {
    SchedulerError::OperationalBoundary {
        class: SchedulerOperationalFailureClass::Canceled,
        message: String::from("original checkpoint boundary canceled"),
    }
}

fn retained(error: RamOperationFailure<SchedulerError>) -> SchedulerError {
    match error {
        RamOperationFailure::Retained(source) => SchedulerError::from_ram_failure(source),
        error => panic!("expected retained complete RAM cause: {error:?}"),
    }
}

fn storage(error: &SchedulerError) -> &RamStoreError {
    let SchedulerError::RamFailure { source, .. } = error else {
        panic!("scheduler must retain its typed RAM cause");
    };
    source.storage_failure()
}

fn sqlite_scope(error: &StoreError) -> &crucible_cas::content_store::SqliteScopeError {
    match error {
        StoreError::SqliteDiagnostic { source } => sqlite_scope(source.failure()),
        StoreError::SqliteScope { source } => source,
        other => panic!("complete SQL scope erased: {other:?}"),
    }
}

#[derive(Debug)]
struct IoPayload {
    drops: Arc<AtomicUsize>,
    panic: bool,
}

impl fmt::Display for IoPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original RAM stream payload")
    }
}

impl Error for IoPayload {}

impl Drop for IoPayload {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
        assert!(!self.panic, "intentional incoming payload unwind");
    }
}

#[test]
fn typed_io_clone_and_final_unwind_keep_original_loan() {
    eprintln!(
        "scheduler={}, RAM error={}, admission={}, shared carrier={}",
        std::mem::size_of::<SchedulerError>(),
        std::mem::size_of::<RamStoreError>(),
        std::mem::size_of::<RamFailureAdmission>(),
        PreparedRamFailure::<SchedulerError>::allocation_bytes().unwrap(),
    );
    for panic in [false, true] {
        let (original, state) = account();
        let prepared = PreparedRamFailure::<SchedulerError>::new(&original).unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let incoming = RamStoreError::Store(StoreError::StreamIo {
            operation: "read-original-RAM",
            source: io::Error::other(IoPayload {
                drops: drops.clone(),
                panic,
            }),
        });
        let first = canceled();
        state.closed.store(true, Ordering::Release);
        assert!(
            original.charge_bytes(1).is_err(),
            "poison the original ledger"
        );

        // Retaining an already produced failure uses the earlier credit even
        // after original cancellation; it does not seek another live authority.
        let reservations = state.reservations.load(Ordering::Acquire);
        ALLOCATION_COUNT.set(Some(0));
        let error = SchedulerError::from_ram_failure(prepared.retain(Some(first), incoming));
        assert_eq!(ALLOCATION_COUNT.replace(None), Some(1));
        assert_eq!(
            ALLOCATION_LAYOUT.take(),
            Some((
                PreparedRamFailure::<SchedulerError>::allocation_bytes().unwrap() as usize,
                std::mem::align_of::<SchedulerError>(),
            )),
            "actual carrier request matches the before-effect original charge"
        );
        let custody = error.clone();
        ALLOCATION_COUNT.set(Some(0));
        let clone = custody.clone();
        assert_eq!(ALLOCATION_COUNT.replace(None), Some(0));
        assert_eq!(error, clone);
        assert_eq!(state.reservations.load(Ordering::Acquire), reservations);
        assert_eq!(
            clone.operational_failure_class(),
            Some(SchedulerOperationalFailureClass::Canceled)
        );
        let RamStoreError::Store(StoreError::StreamIo { operation, source }) = storage(&clone)
        else {
            panic!("original stream I/O was erased");
        };
        assert_eq!(*operation, "read-original-RAM");
        assert!(
            source
                .get_ref()
                .unwrap()
                .downcast_ref::<IoPayload>()
                .is_some()
        );
        assert!(error.source().is_some());

        drop(original);
        drop(error);
        drop(custody);
        assert_eq!(drops.load(Ordering::Acquire), 0);
        assert!(state.used.load(Ordering::Acquire) > 0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(clone)));
        assert_eq!(result.is_err(), panic);
        assert_eq!(drops.load(Ordering::Acquire), 1);
        assert_eq!(state.used.load(Ordering::Acquire), 0);
    }
}

#[test]
fn original_refusal_precedes_callbacks_and_keeps_admission_custody() {
    let (original, state) = account();
    let prepared = PreparedRamFailure::<SchedulerError>::new(&original).unwrap();
    state.closed.store(true, Ordering::Release);
    let (foreign, foreign_state) = account();
    let entered = foreign.enter();
    let effects = Cell::new(0);
    let failure = prepared
        .run(
            &mut || {
                effects.set(effects.get() + 1);
                Ok(())
            },
            |_| {
                effects.set(effects.get() + 1);
                Ok::<(), RamStoreError>(())
            },
        )
        .unwrap_err();
    let RamOperationFailure::Admission(source) = failure else {
        panic!("original refusal must stay typed");
    };
    let error = SchedulerError::RamAdmission {
        source: RamFailureAdmission::Original(source),
        custody: original.custody(),
    };
    let clone = error.clone();
    assert_eq!(effects.get(), 0);
    assert_eq!(foreign_state.reservations.load(Ordering::Acquire), 1);
    assert!(
        error
            .source()
            .unwrap()
            .source()
            .unwrap()
            .source()
            .unwrap()
            .is::<OriginalClosed>()
    );
    drop(entered);
    drop(foreign);
    drop(original);
    drop(error);
    assert!(state.used.load(Ordering::Acquire) > 0);
    drop(clone);
    assert_eq!(state.used.load(Ordering::Acquire), 0);
}

#[test]
fn healthy_operation_releases_prepayment_without_shared_body_allocation() {
    let (original, state) = account();
    let initial = state.used.load(Ordering::Acquire);
    let prepared = PreparedRamFailure::<SchedulerError>::new(&original).unwrap();
    assert_eq!(
        state.used.load(Ordering::Acquire) - initial,
        PreparedRamFailure::<SchedulerError>::allocation_bytes().unwrap()
    );
    let reservations = state.reservations.load(Ordering::Acquire);

    ALLOCATION_COUNT.set(Some(0));
    let result = prepared.run(&mut || Ok(()), |boundary| {
        boundary()?;
        Ok::<_, RamStoreError>(42)
    });
    let allocations = ALLOCATION_COUNT.replace(None);

    assert_eq!(result.unwrap(), 42);
    assert_eq!(allocations, Some(0));
    assert_eq!(state.used.load(Ordering::Acquire), initial);
    assert_eq!(state.reservations.load(Ordering::Acquire), reservations);
    drop(original);
    assert_eq!(state.used.load(Ordering::Acquire), 0);
}

struct SqlSupervisor(Arc<AccountState>);

struct SqlOperation;

impl SqliteCatalogOperation for SqlOperation {
    fn check(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        Ok(())
    }
}

impl SqliteCatalogSupervisor for SqlSupervisor {
    fn reserve_resident_bytes(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        Authority(self.0.clone())
            .reserve(bytes)
            .map_err(|source| StoreError::DecodeAdmission {
                source,
                custody: None,
            })
    }

    fn begin(
        &self,
        _kind: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        Ok(Box::new(SqlOperation))
    }
}

// crucible-lint: allow panic-shortcut -- this fixture requires valid SQL setup and asserts the observed committed or uncertain result.
#[allow(clippy::unwrap_used)]
fn actual_sql_outcome(committed: bool) {
    let root = tempfile::tempdir().unwrap();
    let (original, state) = account();
    let entered = original.enter();
    let prepared = PreparedRamFailure::<SchedulerError>::new(&original).unwrap();
    let started = Cell::new(false);
    let calls = Cell::new(0);
    let mut observation = None;
    let error = prepared
        .run(
            &mut || {
                calls.set(calls.get() + 1);
                if started.get() {
                    Err(canceled())
                } else {
                    Ok(())
                }
            },
            |ram_boundary| {
                let observed = SqliteBlobBackend::checked_scope_failure_fixture_for_test(
                    root.path(),
                    &original,
                    Arc::new(SqlSupervisor(state.clone())),
                    committed,
                    &mut || ram_boundary().map_err(|_| StoreError::Unavailable),
                    &mut || started.set(true),
                )?;
                observation = Some((
                    observed.generation,
                    observed.quarantined,
                    observed.autocommit,
                ));
                Err::<(), RamStoreError>(observed.failure.into())
            },
        )
        .unwrap_err();
    let error = retained(error);
    let clone = error.clone();
    assert_eq!(
        calls.get(),
        3,
        "only first refused callback runs; retained error: {error:?}"
    );
    assert_eq!(
        clone.operational_failure_class(),
        Some(SchedulerOperationalFailureClass::Canceled)
    );
    let RamStoreError::Store(store) = storage(&clone) else {
        panic!("SQL cause erased")
    };
    let source = sqlite_scope(store);
    assert_eq!(
        source.outcome(),
        if committed {
            SqliteCommitOutcome::Committed
        } else {
            SqliteCommitOutcome::Uncertain
        }
    );
    assert!(matches!(
        source.work_failure(),
        Some(StoreError::Unavailable)
    ));
    assert_eq!(source.rollback_failure().is_some(), !committed);
    assert_eq!(source.restoration_failure().is_some(), !committed);
    let (generation, quarantined, autocommit) = observation.unwrap();
    assert_eq!(generation, if committed { 2 } else { 1 });
    assert_eq!(quarantined, !committed);
    assert_eq!(autocommit, committed);
    state.closed.store(true, Ordering::Release);
    drop(entered);
    drop(original);
    drop(error);
    assert!(state.used.load(Ordering::Acquire) > 0);
    drop(clone);
    assert_eq!(state.used.load(Ordering::Acquire), 0);
}

#[test]
fn actual_committed_sql_scope_survives_scheduler_clone() {
    actual_sql_outcome(true);
}

#[test]
fn actual_uncertain_sql_scope_keeps_both_cleanup_failures() {
    actual_sql_outcome(false);
}
