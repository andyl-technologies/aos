//! Exercises genuine native connections under explicit finite model issuers.
//!
//! Rust lifecycle and loan controls are charged by source-derived extents.
//! Loaded native fixed-state and initialization peak remain separate holds.

use crucible_linux_resource::test_support::{
    OriginalControlSelection, OriginalControlSlot, OriginalControlSnapshot,
    OriginalControlsOutcome, OriginalStaticCounters, TestAllocationObserver,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

static ISSUER_CLOSED: AtomicBool = AtomicBool::new(false);
static METADATA_CLOSED: AtomicBool = AtomicBool::new(false);
static CONNECTION_EXTENT: AtomicU64 = AtomicU64::new(0);

use crucible_cas::content_store::{
    SqliteHeapAuthority, SqliteHeapIssuer, SqliteProcessBootstrapAuthority, SqliteProcessHeap,
    StoreError,
};
use crucible_cas::owned_decode::ResourceLoan;
use rusqlite::OpenFlags;

struct ModelAuthority {
    maximum: u64,
    usage: Arc<Mutex<u64>>,
    watched_metadata: Mutex<Option<&'static AtomicBool>>,
}

impl ModelAuthority {
    fn new(maximum: u64) -> Arc<Self> {
        Arc::new(Self {
            maximum,
            usage: Arc::new(Mutex::new(0)),
            watched_metadata: Mutex::new(None),
        })
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.reserve_observed(bytes, None)
    }

    fn reserve_observed(
        &self,
        bytes: u64,
        closed: Option<&'static AtomicBool>,
    ) -> Result<ResourceLoan, StoreError> {
        let charged = bytes
            .checked_add(ResourceLoan::allocation_bytes::<ModelCredit>())
            .ok_or(StoreError::Quota)?;
        let mut usage = self.usage.lock().map_err(|_| StoreError::Quota)?;
        *usage = usage
            .checked_add(charged)
            .filter(|next| *next <= self.maximum)
            .ok_or(StoreError::Quota)?;
        Ok(ResourceLoan::new(ModelCredit {
            usage: self.usage.clone(),
            charged,
            closed,
        }))
    }

    fn used(&self) -> u64 {
        match self.usage.lock() {
            Ok(usage) => *usage,
            Err(error) => panic!("healthy model account: {error}"),
        }
    }
}

struct ModelCredit {
    usage: Arc<Mutex<u64>>,
    charged: u64,
    closed: Option<&'static AtomicBool>,
}

impl Drop for ModelCredit {
    fn drop(&mut self) {
        if let Some(closed) = self.closed {
            closed.store(true, Ordering::SeqCst);
        }
        let Ok(mut usage) = self.usage.lock() else {
            panic!("healthy model refund");
        };
        let Some(refunded) = usage.checked_sub(self.charged) else {
            panic!("original model loan");
        };
        *usage = refunded;
    }
}

impl SqliteHeapAuthority for ModelAuthority {
    fn verify_live(&self) -> Result<(), StoreError> {
        self.usage.lock().map(|_| ()).map_err(|_| StoreError::Quota)
    }

    fn reserve_heap(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.reserve(bytes)
    }

    fn reserve_metadata(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        CONNECTION_EXTENT.store(bytes, Ordering::SeqCst);
        let closed = *self
            .watched_metadata
            .lock()
            .map_err(|_| StoreError::Quota)?;
        self.reserve_observed(bytes, closed)
    }
}

struct ModelIssuer(Arc<ModelAuthority>);

impl SqliteHeapAuthority for ModelIssuer {
    fn verify_live(&self) -> Result<(), StoreError> {
        SqliteHeapAuthority::verify_live(self.0.as_ref())
    }
    fn reserve_heap(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.0.reserve_heap(bytes)
    }
    fn reserve_metadata(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.0.reserve_metadata(bytes)
    }
}

fn issuer(original: &Arc<ModelAuthority>) -> SqliteHeapIssuer {
    let Ok(credit) = original.reserve(SqliteHeapIssuer::control_bytes::<ModelIssuer>()) else {
        panic!("same original issuer control purpose");
    };
    SqliteHeapIssuer::new(ModelIssuer(original.clone()), credit)
}

impl SqliteProcessBootstrapAuthority for ModelAuthority {
    fn verify_live(&self) -> Result<(), StoreError> {
        SqliteHeapAuthority::verify_live(self)
    }

    fn reserve_bootstrap(&self, rust_metadata_bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.reserve(rust_metadata_bytes)
    }
}

#[test]
fn same_process_scope_retains_parallel_connections_and_allows_clean_successor() {
    const HEAP: u64 = 8 << 20;
    let bootstrap = ModelAuthority::new(256 << 20);
    let first = ModelAuthority::new(256 << 20);
    let second = ModelAuthority::new(256 << 20);
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;

    let (refused, issuer_report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::FirstThreadExtent(
                    std::num::NonZeroUsize::new(
                        SqliteHeapIssuer::control_bytes::<ModelIssuer>() as usize
                    )
                    .expect("concrete issuer control extent"),
                ),
                OriginalStaticCounters::Bool(&ISSUER_CLOSED),
                true,
            )
            .expect("prepaid issuer first-entry refusal");
        let credit = first
            .reserve_observed(
                SqliteHeapIssuer::control_bytes::<ModelIssuer>(),
                Some(&ISSUER_CLOSED),
            )
            .expect("original issuer control purpose");
        SqliteProcessHeap::install(
            SqliteHeapIssuer::new(ModelIssuer(first.clone()), credit),
            HEAP,
            2,
        )
    })
    .expect("issuer physical close observation");
    assert!(refused.is_err());
    assert_eq!(issuer_report.outcome, OriginalControlsOutcome::Complete);
    let issuer_close = issuer_report.controls[0].expect("real issuer control close");
    assert_eq!(issuer_close.before, OriginalControlSnapshot::Bool(false));
    assert_eq!(
        issuer_close.after,
        Some(OriginalControlSnapshot::Bool(false))
    );
    assert!(ISSUER_CLOSED.load(Ordering::SeqCst));
    assert_eq!(first.used(), 0);
    SqliteProcessHeap::prepare_bootstrap(bootstrap.as_ref()).expect("explicit model bootstrap");
    let bootstrap_used = bootstrap.used();
    assert!(bootstrap_used > 0);
    METADATA_CLOSED.store(false, Ordering::SeqCst);
    *first
        .watched_metadata
        .lock()
        .expect("original table credit marker") = Some(&METADATA_CLOSED);
    let table_extent = 2 * std::mem::size_of::<Option<Arc<()>>>();
    assert_ne!(
        table_extent as u64,
        ResourceLoan::allocation_bytes::<ModelCredit>()
    );
    assert_ne!(
        table_extent as u64,
        SqliteHeapIssuer::control_bytes::<ModelIssuer>()
    );
    let (refused, table_report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::FirstThreadExtent(
                    std::num::NonZeroUsize::new(table_extent)
                        .expect("original two-slot table extent"),
                ),
                OriginalStaticCounters::Bool(&METADATA_CLOSED),
                true,
            )
            .expect("original table close watch");
        SqliteProcessHeap::refuse_installation_after_table_for_test(issuer(&first), HEAP, 2)
    })
    .expect("actual late-refusal table close");
    assert!(matches!(refused, Err(StoreError::SqliteHeap { .. })));
    assert_eq!(table_report.outcome, OriginalControlsOutcome::Complete);
    let table_close = table_report.controls[0].expect("actual table System free");
    assert_eq!(table_close.before, OriginalControlSnapshot::Bool(false));
    assert_eq!(
        table_close.after,
        Some(OriginalControlSnapshot::Bool(false))
    );
    assert!(METADATA_CLOSED.load(Ordering::SeqCst));
    assert_eq!(first.used(), 0);
    *first
        .watched_metadata
        .lock()
        .expect("original table marker reset") = None;
    println!("late_refusal_table_extent={table_extent} original_metadata_closed_after_return=true");
    let heap = SqliteProcessHeap::install(issuer(&first), HEAP, 2).expect("first original heap");
    println!(
        "after_initialization_used={} initialization_highwater={}",
        crucible_sqlite_heap::memory_used(),
        crucible_sqlite_heap::memory_highwater()
    );
    assert!(first.used() > HEAP);
    assert!(SqliteProcessHeap::install(issuer(&second), HEAP, 2).is_err());
    assert_eq!(second.used(), 0);

    let a = heap.open_connection(":memory:", flags).expect("managed A");
    let b = heap.open_connection(":memory:", flags).expect("managed B");
    let connection_extent = CONNECTION_EXTENT.load(Ordering::SeqCst);
    let credit_extent = ResourceLoan::allocation_bytes::<ModelCredit>();
    assert_ne!(connection_extent, credit_extent);
    println!("connection_control_extent={connection_extent} model_credit_extent={credit_extent}");
    let before_excess = first.used();
    *first
        .watched_metadata
        .lock()
        .expect("original marker selection") = Some(&METADATA_CLOSED);
    METADATA_CLOSED.store(false, Ordering::SeqCst);
    let (refused, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::FirstThreadRequestedExtent(&CONNECTION_EXTENT),
                OriginalStaticCounters::Bool(&METADATA_CLOSED),
                true,
            )
            .expect("exact prepublication control");
        heap.open_connection(":memory:", flags)
    })
    .expect("real constructor observation");
    assert!(refused.is_err());
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
    let closed = report.controls[0].expect("actual selected control free");
    assert_eq!(closed.before, OriginalControlSnapshot::Bool(false));
    assert_eq!(closed.after, Some(OriginalControlSnapshot::Bool(false)));
    assert!(METADATA_CLOSED.load(Ordering::SeqCst));
    assert_eq!(first.used(), before_excess);

    // Ordinary Arc payload destruction refunds its nested loan before the
    // enclosing control closes. This negative validates the same flag witness.
    struct EarlyRefund {
        _loan: ResourceLoan,
    }
    METADATA_CLOSED.store(false, Ordering::SeqCst);
    let negative_extent = std::num::NonZeroUsize::new(
        std::mem::size_of::<EarlyRefund>() + 2 * std::mem::size_of::<usize>(),
    )
    .expect("actual negative Arc extent");
    let ((), report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::FirstThreadExtent(negative_extent),
                OriginalStaticCounters::Bool(&METADATA_CLOSED),
                true,
            )
            .expect("ordinary Arc negative");
        let loan = first
            .reserve_metadata(std::mem::size_of::<EarlyRefund>() as u64)
            .expect("same finite original negative credit");
        drop(Arc::new(EarlyRefund { _loan: loan }));
    })
    .expect("real negative close");
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
    let negative = report.controls[0].expect("negative actual enclosing free");
    assert_eq!(negative.before, OriginalControlSnapshot::Bool(true));
    assert_eq!(negative.after, Some(OriginalControlSnapshot::Bool(true)));
    *first.watched_metadata.lock().expect("marker reset") = None;
    assert_eq!(first.used(), before_excess);

    let barrier = Arc::new(std::sync::Barrier::new(3));
    std::thread::scope(|scope| {
        let barrier_a = barrier.clone();
        let worker_a = scope.spawn(move || {
            barrier_a.wait();
            a.execute_batch("CREATE TABLE a(value); INSERT INTO a VALUES(11)")
                .expect("actual native A");
            assert_eq!(
                a.query_row("SELECT value FROM a", [], |row| row.get::<_, i64>(0))
                    .expect("row A"),
                11
            );
        });
        let barrier_b = barrier.clone();
        let worker_b = scope.spawn(move || {
            barrier_b.wait();
            b.execute_batch("CREATE TABLE b(value); INSERT INTO b VALUES(22)")
                .expect("actual native B");
            assert_eq!(
                b.query_row("SELECT value FROM b", [], |row| row.get::<_, i64>(0))
                    .expect("row B"),
                22
            );
        });
        barrier.wait();
        worker_a.join().expect("real A join");
        worker_b.join().expect("real B join");
    });

    let retained = heap.clone();
    let refusal = heap
        .finish()
        .expect_err("live borrower fences terminal close");
    assert!(retained.open_connection(":memory:", flags).is_err());
    assert!(first.used() > HEAP);
    drop(refusal);
    drop(retained);
    heap.finish()
        .expect("all actual managed connections closed");
    assert_eq!(crucible_sqlite_heap::memory_used(), 0);
    assert!(
        first.used() > 0,
        "original caller still owns its heap control"
    );
    drop(heap);
    assert_eq!(first.used(), 0);
    assert_eq!(
        bootstrap.used(),
        bootstrap_used,
        "permanent process credit remains"
    );

    let successor = SqliteProcessHeap::install(issuer(&second), 4 << 20, 1)
        .expect("separate exact funded successor");
    let connection = successor
        .open_connection(":memory:", flags)
        .expect("successor native open");
    connection
        .execute_batch("CREATE TABLE next(value)")
        .expect("successor actual native effect");
    drop(connection);
    successor.finish().expect("clean successor");
    drop(successor);
    assert_eq!(second.used(), 0);

    let uncertain = ModelAuthority::new(256 << 20);
    let refused = ModelAuthority::new(256 << 20);
    let quarantined = SqliteProcessHeap::install(issuer(&uncertain), HEAP, 1)
        .expect("original owner before callback unwind");
    let connection = quarantined
        .open_connection(":memory:", flags)
        .expect("published native owner");
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<i64, _> =
            connection.query_row("SELECT 1", [], |_| panic!("actual row conversion unwind"));
    }));
    assert!(panic.is_err());
    drop(connection);
    assert!(
        quarantined.finish().is_err(),
        "poison retains the same native owner"
    );
    drop(quarantined);
    assert!(uncertain.used() > HEAP);
    assert!(SqliteProcessHeap::install(issuer(&refused), HEAP, 1).is_err());
    assert_eq!(
        refused.used(),
        0,
        "uncertain cleanup cannot issue a successor"
    );
    println!(
        "native_used={} native_highwater={} bootstrap_model={bootstrap_used}",
        crucible_sqlite_heap::memory_used(),
        crucible_sqlite_heap::memory_highwater()
    );
}
