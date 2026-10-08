//! Component proofs for genuine facade dispatch, finite waits and final custody.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::*;
use crate::content_store::StorePhysicalQuotaGuard;
use crate::owned_decode::DecodeBudget;

mod checked_readers;
mod composition;
mod publication_acceptance;

struct OriginalResources {
    used: AtomicU64,
    peak: AtomicU64,
    maximum: u64,
    revoked: AtomicBool,
    checks: AtomicUsize,
    starts: AtomicUsize,
    reservations: AtomicUsize,
    last_refused_bytes: AtomicU64,
    watched_loan_bytes: AtomicU64,
    watched_loan_closed: AtomicBool,
    resource_drops: AtomicUsize,
}

struct Loan {
    owner: Arc<OriginalResources>,
    bytes: u64,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if self.bytes == self.owner.watched_loan_bytes.load(Ordering::SeqCst) {
            self.owner.watched_loan_closed.store(true, Ordering::SeqCst);
        }
        self.owner
            .used
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::SeqCst);
    }
}

pub(super) struct Quota(Arc<OriginalResources>);

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(self.0.maximum)
    }

    fn reserve_resources(
        &self,
        _descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.0.reservations.fetch_add(1, Ordering::SeqCst);
        self.verify()?;
        let previous = self
            .0
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.0.maximum)
            })
            .map_err(|_| {
                self.0.last_refused_bytes.store(bytes, Ordering::SeqCst);
                StoreError::Quota
            })?;
        self.0.peak.fetch_max(previous + bytes, Ordering::SeqCst);
        Ok(crate::owned_decode::ResourceLoan::new(Loan {
            owner: Arc::clone(&self.0),
            bytes,
        }))
    }

    fn verify(&self) -> Result<(), StoreError> {
        self.0.checks.fetch_add(1, Ordering::SeqCst);
        if self.0.revoked.load(Ordering::SeqCst) {
            return Err(StoreError::Unauthorized);
        }
        Ok(())
    }
}

struct Supervisor(Arc<Quota>);

impl SqliteCatalogSupervisor for Supervisor {
    fn reserve_resident_bytes(
        &self,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.0.reserve_resources(0, bytes)
    }

    fn begin(
        &self,
        _kind: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        self.0.0.starts.fetch_add(1, Ordering::SeqCst);
        self.0.verify()?;
        Ok(Box::new(Operation(Arc::clone(&self.0))))
    }
}

struct Operation(Arc<Quota>);

impl SqliteCatalogOperation for Operation {
    fn check(&self) -> Result<(), StoreError> {
        self.0.verify()
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        self.0.verify()
    }
}

pub(super) fn original_quota() -> Arc<Quota> {
    Arc::new(Quota(Arc::new(OriginalResources {
        used: AtomicU64::new(0),
        peak: AtomicU64::new(0),
        maximum: 64 * 1024 * 1024,
        revoked: AtomicBool::new(false),
        checks: AtomicUsize::new(0),
        starts: AtomicUsize::new(0),
        reservations: AtomicUsize::new(0),
        last_refused_bytes: AtomicU64::new(0),
        watched_loan_bytes: AtomicU64::new(0),
        watched_loan_closed: AtomicBool::new(false),
        resource_drops: AtomicUsize::new(0),
    })))
}

#[test]
fn repeated_batches_release_staging_but_retain_each_live_result() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::repeated_batches_release_staging_but_retain_each_live_result",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("component catalog");
    let guard = original_quota();
    let backend = SqliteBlobBackend::open_with_physical_quota(
        "original-quota",
        root.path(),
        guard.clone(),
        8 * 1024 * 1024,
        Arc::new(Supervisor(Arc::clone(&guard))),
    )
    .expect("same-quota catalog");
    let inputs = objects();
    let account = DecodeBudget::for_store(guard.clone()).expect("original bank");
    let _scope = account.enter();
    let baseline = guard.0.used.load(Ordering::SeqCst);
    let first = backend
        .put_many_if_absent_with_boundary(&account, &inputs, &mut || guard.verify())
        .expect("first original-account batch")
        .accept_with_boundary(&mut || guard.verify())
        .expect("same outer operation accepts first receipt");
    let retained = guard.0.used.load(Ordering::SeqCst) - baseline;
    assert!(retained > 0);

    // Keeping the first result live must consume its own credit throughout
    // later batches; closing a later result releases only that result.
    for _ in 0..128 {
        let later = backend
            .put_many_if_absent_with_boundary(&account, &inputs, &mut || guard.verify())
            .expect("same original account reused without reset")
            .accept_with_boundary(&mut || guard.verify())
            .expect("same outer operation accepts later receipt");
        assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline + 2 * retained);
        drop(later);
        assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline + retained);
        account
            .check()
            .expect("no monotone temporary-charge accumulation");
    }
    drop(first);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
    assert!(guard.0.peak.load(Ordering::SeqCst) > baseline + 2 * retained);
    assert!(guard.0.peak.load(Ordering::SeqCst) <= guard.0.maximum);

    let source = BlobHandle::from_bytes(b"independently retained output");
    let output = source
        .read_all_with_boundary(&account, source.logical_length(), &mut || guard.verify())
        .expect("checked bytes loan");
    assert_eq!(
        guard.0.used.load(Ordering::SeqCst),
        baseline + output.len() as u64
    );
    drop(output);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
}

#[test]
fn checked_batch_original_allocation_refusal_preserves_cause_and_existing_result() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::checked_batch_original_allocation_refusal_preserves_cause_and_existing_result",
    ) {
        return;
    }
    let guard = original_quota();
    let root = tempfile::tempdir().expect("component catalog");
    let backend = bounded_leaf("component", root.path(), &guard);
    let inputs = objects();
    let account = DecodeBudget::for_store(guard.clone()).expect("original bank");
    let _scope = account.enter();
    let baseline = guard.0.used.load(Ordering::SeqCst);
    let retained = backend
        .put_many_if_absent_with_boundary(&account, &inputs, &mut || Ok(()))
        .expect("first live result");
    let held = guard.0.used.load(Ordering::SeqCst);
    let blocker = guard
        .reserve_resources(0, guard.0.maximum - held)
        .expect("exhaust same physical allocator without changing metadata maximum");

    let StoreError::DecodeAdmission { source, custody } = backend
        .put_many_if_absent_with_boundary(&account, &inputs, &mut || Ok(()))
        .expect_err("original allocator must reject another batch")
    else {
        panic!("expected preserved admission error");
    };
    assert!(custody.is_some(), "failure retains the original account");
    assert!(matches!(
        std::error::Error::source(&source).and_then(|cause| cause.downcast_ref::<StoreError>()),
        Some(StoreError::Quota)
    ));
    assert_eq!(
        retained.len(),
        inputs.len(),
        "prior owning result stays usable"
    );
    drop(blocker);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), held);
    assert!(account.check().is_err(), "original refusal stays sticky");
    drop(retained);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
}

#[test]
fn first_loan_refusal_retains_original_account_until_error_closes() {
    let guard = original_quota();
    let account = DecodeBudget::for_store(guard.clone()).expect("original bank");
    let scope = account.enter();
    let baseline = guard.0.used.load(Ordering::SeqCst);
    let blocker = guard
        .reserve_resources(0, guard.0.maximum - baseline)
        .expect("occupy the unchanged original physical allowance");

    let source = account
        .reserve_scratch_bytes(1)
        .err()
        .expect("first requested loan refuses original exhaustion");
    let error = admission_under(&account, source);
    assert!(matches!(
        std::error::Error::source(&error)
            .and_then(std::error::Error::source)
            .and_then(|source| source.downcast_ref::<StoreError>()),
        Some(StoreError::Quota)
    ));

    drop(blocker);
    drop(scope);
    drop(account);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);

    drop(error);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), 0);
}

#[test]
fn allocator_refusal_retains_original_account_without_boxing_its_cause() {
    let guard = original_quota();
    let account = DecodeBudget::for_store(guard.clone()).expect("original bank");
    let scope = account.enter();
    let baseline = guard.0.used.load(Ordering::SeqCst);
    let mut bytes = Vec::<u8>::new();

    let source = bytes
        .try_reserve_exact(usize::MAX)
        .expect_err("capacity overflow does not allocate storage");
    let error = allocation_under(&account, source);
    assert!(
        std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<std::collections::TryReserveError>())
            .is_some()
    );

    drop(scope);
    drop(account);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);

    drop(error);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), 0);
}

#[test]
fn nested_quota_receipt_name_growth_keeps_all_original_credits_to_last_drop() {
    let guard = original_quota();
    let root = tempfile::tempdir().expect("component catalog");
    let leaf = Arc::new(bounded_leaf("a", root.path(), &guard));
    let inner = Arc::new(
        super::super::super::physical_quota::PhysicalQuotaStore::new(
            "longer-original-authority-name",
            leaf.clone(),
            leaf,
            guard.clone(),
        )
        .expect("first genuine quota facade"),
    );
    let outer = super::super::super::physical_quota::PhysicalQuotaStore::new(
        "still-longer-name-on-the-same-original-authority",
        inner.clone(),
        inner,
        guard.clone(),
    )
    .expect("second genuine quota facade");
    let inputs = objects();
    let account = DecodeBudget::for_store(guard.clone()).expect("same account");
    let scope = account.enter();
    let baseline = guard.0.used.load(Ordering::SeqCst);
    let receipts = outer
        .put_many_if_absent_with_boundary(&account, &inputs, &mut || guard.verify())
        .expect("both original resource nodes retained");
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.placements[0].backend == outer.name())
    );
    assert!(guard.0.used.load(Ordering::SeqCst) > baseline);

    drop(scope);
    drop(account);
    drop(outer);
    let weak = Arc::downgrade(&guard);
    drop(guard);
    assert!(weak.upgrade().is_some());
    drop(receipts);
    assert!(
        weak.upgrade().is_none(),
        "no detached result or lingering temporary credits"
    );
}

// This leaf fixture performs the real private connection initialization with
// the same authority and resident loan. Facade dispatch is exercised separately
// through the public open_with_physical_quota constructor above.
pub(super) fn bounded_leaf(name: &str, root: &Path, guard: &Arc<Quota>) -> SqliteBlobBackend {
    let supervisor: Arc<dyn SqliteCatalogSupervisor> = Arc::new(Supervisor(Arc::clone(guard)));
    let operation = supervisor
        .begin(SqliteCatalogOperationKind::Write)
        .expect("original preparation");
    let lease = supervisor
        .reserve_resident_bytes(
            minimum_sqlite_catalog_resident_bytes(name, root).expect("actual leaf geometry"),
        )
        .expect("original resident loan");
    let mut backend = SqliteBlobBackend::open_inner(
        name.to_owned(),
        root.to_owned(),
        Some(8 * 1024 * 1024),
        Some(supervisor),
    )
    .expect("actual capped private connection");
    backend.resident_lease = lease.into();
    operation
        .complete()
        .expect("same original preparation closes");
    backend
}

pub(super) fn original_failure(error: &StoreError) -> &StoreError {
    match error {
        StoreError::SqliteDiagnostic { source } => original_failure(source.failure()),
        StoreError::SqliteScope { source } => {
            source.work_failure().map(original_failure).unwrap_or(error)
        }
        other => other,
    }
}

pub(super) fn objects() -> Vec<(ContentId, BlobHandle)> {
    [b"first".as_slice(), b"second", b"first"]
        .into_iter()
        .map(|bytes| {
            (
                ContentId::for_bytes(ObjectKind::Trace, 1, bytes),
                BlobHandle::from_bytes(bytes),
            )
        })
        .collect()
}

pub(super) fn expired() -> StoreError {
    StoreError::Supervision {
        source: Box::new(io::Error::new(
            io::ErrorKind::Interrupted,
            "original work expired",
        )),
    }
}

pub(super) fn assert_expired(error: StoreError) {
    let StoreError::Supervision { source } = original_failure(&error) else {
        panic!("expected original typed boundary failure");
    };
    assert_eq!(
        source
            .downcast_ref::<io::Error>()
            .expect("original I/O cause")
            .kind(),
        io::ErrorKind::Interrupted
    );
}

pub(in crate::content_store::sqlite) fn isolated_heap_test(name: &str) -> bool {
    if std::env::var_os("CRUCIBLE_SQLITE_CHECKED_BATCH_CHILD").is_some() {
        return false;
    }
    // SQLite's hard heap ceiling is process-global and cannot be raised.
    // Keep this real 8 MiB private-catalog assertion from changing other tests.
    let status =
        std::process::Command::new(std::env::current_exe().expect("component test executable"))
            .args(["--exact", name, "--nocapture"])
            .env("CRUCIBLE_SQLITE_CHECKED_BATCH_CHILD", "1")
            .status()
            .expect("isolated catalog component");
    assert!(status.success());
    true
}

#[test]
fn same_quota_arc_forwards_one_transaction_and_retains_last_receipt_owner() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::same_quota_arc_forwards_one_transaction_and_retains_last_receipt_owner",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("component catalog");
    let guard = original_quota();
    let backend = SqliteBlobBackend::open_with_physical_quota(
        "original-quota",
        root.path(),
        guard.clone(),
        8 * 1024 * 1024,
        Arc::new(Supervisor(Arc::clone(&guard))),
    )
    .expect("admitted component catalog");
    let selected: Arc<dyn StorePhysicalQuotaGuard> = guard.clone();
    assert!(Arc::ptr_eq(
        &selected,
        &backend.metadata_resources().expect("same quota authority")
    ));
    let account = DecodeBudget::for_store(selected).expect("original metadata bank");
    let scope = account.enter();
    let before = {
        let connection = Connection::open(root.path().join(DATABASE_FILE))
            .expect("inspect component generation");
        load_metadata(&connection).expect("generation").1
    };
    let inputs = objects();
    let starts = guard.0.starts.load(Ordering::SeqCst);
    let mut calls = 0;
    let receipts = backend
        .put_many_if_absent_with_boundary(&account, &inputs, &mut || {
            calls += 1;
            guard.verify()
        })
        .expect("genuinely forwarded checked batch");

    assert!(calls > inputs.len());
    assert_eq!(guard.0.starts.load(Ordering::SeqCst), starts + 1);
    assert_eq!(
        receipts
            .iter()
            .map(|receipt| receipt.id)
            .collect::<Vec<_>>(),
        inputs.iter().map(|(id, _)| *id).collect::<Vec<_>>()
    );
    assert!(receipts.iter().all(|receipt| receipt.placements.len() == 1
        && receipt.placements[0].backend == "original-quota"
        && receipt.is_durable()));
    let connection = Connection::open(root.path().join(DATABASE_FILE))
        .expect("inspect committed component database");
    assert_eq!(
        load_metadata(&connection).expect("committed generation").1,
        before + 1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, usize>(0))
            .expect("distinct rows"),
        2
    );
    drop(connection);

    drop(scope);
    drop(account);
    drop(backend);
    assert!(
        guard.0.used.load(Ordering::SeqCst) > 0,
        "receipts retain original metadata and operation loans"
    );
    let weak = Arc::downgrade(&guard);
    drop(guard);
    assert!(
        weak.upgrade().is_some(),
        "last result retains actual original authority"
    );
    drop(receipts);
    assert!(
        weak.upgrade().is_none(),
        "final result releases original authority"
    );
}

#[test]
fn caller_boundary_interrupts_each_contended_gate_without_renewal() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::caller_boundary_interrupts_each_contended_gate_without_renewal",
    ) {
        return;
    }
    let guard = original_quota();
    let root = tempfile::tempdir().expect("component catalog");
    let backend = bounded_leaf("component", root.path(), &guard);
    let account = DecodeBudget::for_store(guard.clone()).expect("finite component bank");
    let _scope = account.enter();
    let op = Operation(guard.clone());
    let mut calls = 0;
    std::thread::scope(|scope| {
        let (ready, acquired) = std::sync::mpsc::sync_channel(0);
        let (release, released) = std::sync::mpsc::sync_channel(0);
        let owner = scope.spawn(move || {
            let staging = catalog::write_gate(&op).expect("actual other-thread staging owner");
            ready.send(()).expect("announce held gate");
            released
                .recv()
                .expect("retain gate through original cancellation");
            drop(staging);
        });
        acquired.recv().expect("wait for actual gate owner");
        let error = backend
            .put_many_if_absent_with_boundary(&account, &[], &mut || {
                calls += 1;
                if calls == 32 { Err(expired()) } else { Ok(()) }
            })
            .expect_err("same callback refuses other-thread staging wait");
        assert_expired(error);
        assert_eq!(calls, 32);
        release.send(()).expect("release original owner");
        owner.join().expect("staging owner closes");
    });

    let inventory = backend
        .acquire_inventory_lock()
        .expect("occupy original inventory flock");
    calls = 0;
    let error = backend
        .put_many_if_absent_with_boundary(&account, &[], &mut || {
            calls += 1;
            if calls == 32 { Err(expired()) } else { Ok(()) }
        })
        .expect_err("same callback refuses inventory wait");
    assert_expired(error);
    assert_eq!(calls, 32);
    drop(inventory);

    let connection = backend
        .lock_connection()
        .expect("occupy original connection");
    calls = 0;
    let error = backend
        .put_many_if_absent_with_boundary(&account, &[], &mut || {
            calls += 1;
            if calls == 32 { Err(expired()) } else { Ok(()) }
        })
        .expect_err("same callback refuses connection wait");
    assert_expired(error);
    assert_eq!(calls, 32);
    drop(connection);
}

#[test]
fn original_boundary_refusal_rolls_back_staged_rows_and_generation() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::original_boundary_refusal_rolls_back_staged_rows_and_generation",
    ) {
        return;
    }
    let guard = original_quota();
    let root = tempfile::tempdir().expect("component catalog");
    let backend = bounded_leaf("component", root.path(), &guard);
    let account = DecodeBudget::for_store(guard.clone()).expect("finite component bank");
    let _scope = account.enter();
    let before = load_metadata(&backend.lock_connection().expect("inspect generation"))
        .expect("generation")
        .1;
    let mut inside_checks = 0;
    let error = backend
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || {
            if matches!(backend.connection.try_lock(), Err(TryLockError::WouldBlock)) {
                inside_checks += 1;
            }
            if inside_checks == 7 {
                Err(expired())
            } else {
                Ok(())
            }
        })
        .expect_err("expire after first insertion before commit");
    assert_expired(error);
    let connection = backend
        .lock_connection()
        .expect("released original connection");
    assert_eq!(
        load_metadata(&connection).expect("unchanged generation").1,
        before
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, usize>(0))
            .expect("rollback rows"),
        0
    );
}

#[test]
fn checked_sources_authenticate_eof_and_poll_original_read_waits() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::checked_sources_authenticate_eof_and_poll_original_read_waits",
    ) {
        return;
    }
    let guard = original_quota();
    let root = tempfile::tempdir().expect("component catalog");
    let backend = bounded_leaf("component", root.path(), &guard);
    let bytes = vec![0x5b; 128 * 1024 + 17];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
        .expect("ordinary source publication");
    let source = backend.read(id, None).expect("genuine SQLite source");
    let account = DecodeBudget::for_store(guard.clone()).expect("finite original account");
    let _scope = account.enter();
    let op = Operation(guard.clone());

    let staging = catalog::read_gate(&op).expect("occupy read gate");
    let mut calls = 0;
    let error = source
        .read_all_with_boundary(&account, 4 * 1024 * 1024, &mut || {
            calls += 1;
            if calls == 32 { Err(expired()) } else { Ok(()) }
        })
        .expect_err("original caller refuses source staging wait");
    assert_expired(error);
    assert_eq!(calls, 32);
    drop(staging);

    let reader_connection = backend
        .read_connection
        .lock()
        .expect("occupy source connection");
    calls = 0;
    let error = source
        .read_all_with_boundary(&account, 4 * 1024 * 1024, &mut || {
            calls += 1;
            if calls == 32 { Err(expired()) } else { Ok(()) }
        })
        .expect_err("original caller refuses source connection wait");
    assert_expired(error);
    assert_eq!(calls, 32);
    drop(reader_connection);

    let result = source
        .read_all_with_boundary(&account, 4 * 1024 * 1024, &mut || Ok(()))
        .expect("authenticated checked EOF");
    assert_eq!(&result[..], bytes);
    backend
        .lock_connection()
        .expect("component corruption injection")
        .execute(
            "UPDATE objects SET body = ?1 WHERE id = ?2",
            params![vec![0x7a_u8; bytes.len()], id.encode()],
        )
        .expect("corrupt body without changing length");
    assert!(
        matches!(original_failure(&source.read_all_with_boundary(&account, 4 * 1024 * 1024, &mut || Ok(())).expect_err("corrupt checked source")), StoreError::Corrupt { id: rejected } if *rejected == id)
    );
    assert!(
        source.read_all(4 * 1024 * 1024).is_err(),
        "ordinary EOF authentication remains enforced"
    );
}

#[test]
fn quota_source_batch_uses_original_write_scope_without_per_chunk_restarts() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::quota_source_batch_uses_original_write_scope_without_per_chunk_restarts",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("component catalog");
    let guard = original_quota();
    let backend = SqliteBlobBackend::open_with_physical_quota(
        "original",
        root.path(),
        guard.clone(),
        8 * 1024 * 1024,
        Arc::new(Supervisor(Arc::clone(&guard))),
    )
    .expect("actual quota facade and private SQLite child");
    let bytes = vec![0xa5; 130 * 1024];
    let original = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let rekeyed = ContentId::for_bytes(ObjectKind::Trace, 2, &bytes);
    backend
        .put_if_absent(original, &BlobHandle::from_bytes(bytes.clone()))
        .expect("existing singleton");
    let source = backend
        .read(original, None)
        .expect("quota-retained SQLite source");
    let account =
        DecodeBudget::for_store(backend.metadata_resources().expect("same metadata owner"))
            .expect("original finite bank");
    let _scope = account.enter();
    let starts = guard.0.starts.load(Ordering::SeqCst);
    let mut checks = 0;
    let receipts = backend
        .put_many_if_absent_with_boundary(&account, &[(rekeyed, source)], &mut || {
            checks += 1;
            guard.verify()
        })
        .expect("same-backend source finishes before writer lock");
    assert_eq!(
        guard.0.starts.load(Ordering::SeqCst),
        starts + 1,
        "read chunks borrow the original batch operation"
    );
    assert!(checks > 16);
    assert_eq!(receipts[0].id, rekeyed);
    assert_eq!(
        backend
            .read(rekeyed, None)
            .expect("rekeyed object")
            .read_all(4 * 1024 * 1024)
            .expect("ordinary read still works"),
        bytes
    );
}

#[test]
fn opaque_checked_dispatch_refuses_without_changing_singleton_metrics() {
    use crate::content_store::composition::MetricsStore;

    let root = tempfile::tempdir().expect("component catalog");
    struct OpaqueBackend(Arc<SqliteBlobBackend>);

    impl ImmutableBlobBackend for OpaqueBackend {
        fn name(&self) -> &str {
            self.0.name()
        }

        fn capabilities(&self) -> BackendCapabilities {
            self.0.capabilities()
        }

        fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
            self.0.contains(id)
        }

        fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
            self.0.read(id, range)
        }

        fn put_if_absent(
            &self,
            id: ContentId,
            source: &BlobHandle,
        ) -> Result<PutReceipt, StoreError> {
            self.0.put_if_absent(id, source)
        }
    }

    let backend =
        Arc::new(SqliteBlobBackend::open("component", root.path()).expect("component database"));
    let (metrics, state) = MetricsStore::new("metrics", Arc::new(OpaqueBackend(backend)));
    let input = objects();
    let account =
        DecodeBudget::for_store(original_quota()).expect("explicit finite caller account");
    assert!(matches!(
        metrics.put_many_if_absent_with_boundary(&account, &input, &mut || Ok(())),
        Err(StoreError::Unsupported {
            capability: "checked-publication-metadata-bound"
        })
    ));
    assert_eq!(state.snapshot().put_calls, 0);
    metrics
        .put_many_if_absent(&input)
        .expect("unchanged ordinary singleton metrics behavior");
    assert_eq!(state.snapshot().put_calls, input.len() as u64);
    assert_eq!(
        state.snapshot().put_logical_bytes,
        input
            .iter()
            .map(|(_, source)| source.logical_length())
            .sum::<u64>()
    );
    assert_eq!(state.snapshot().failures, 0);
    assert!(
        metrics
            .put_if_absent(input[0].0, &BlobHandle::from_bytes(b"wrong"))
            .is_err()
    );
    assert_eq!(state.snapshot().put_calls, input.len() as u64 + 1);
    assert_eq!(state.snapshot().failures, 1);
}

struct Authorizer {
    denied: AtomicBool,
    calls: AtomicUsize,
}

impl crate::content_store::StoreNamespaceAuthorizer for Authorizer {
    fn authorize(
        &self,
        operation: crate::content_store::StoreNamespaceOperation,
        _id: ContentId,
    ) -> Result<(), StoreError> {
        assert_eq!(
            operation,
            crate::content_store::StoreNamespaceOperation::Put
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.denied.load(Ordering::SeqCst) {
            Err(StoreError::Unauthorized)
        } else {
            Ok(())
        }
    }
}

#[test]
fn transparent_facades_forward_one_batch_preserving_policy_and_cache_behavior() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::transparent_facades_forward_one_batch_preserving_policy_and_cache_behavior",
    ) {
        return;
    }
    use crate::content_store::composition::{
        DurabilityPolicyStore, ReadThroughStore, VerifiedStore,
    };
    use crate::content_store::namespace::NamespacedStore;
    use std::collections::BTreeMap;

    let guard = original_quota();
    let root = tempfile::tempdir().expect("component catalog");
    let leaf = Arc::new(bounded_leaf("component", root.path(), &guard));
    let cache = Arc::new(MemoryBlobBackend::new("component-read-cache", 1024));
    let authoritative = Arc::new(ReadThroughStore::new("cache", cache.clone(), leaf.clone()));
    let durable = Arc::new(DurabilityPolicyStore::new(
        "policy",
        authoritative,
        BTreeMap::from([(
            ObjectKind::Trace,
            DurabilityRequirement::new(1, false).expect("one durable placement"),
        )]),
    ));
    let verified = Arc::new(VerifiedStore::new("verified", durable));
    let authorizer = Arc::new(Authorizer {
        denied: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    let backend = NamespacedStore::new("namespace", verified, authorizer.clone());
    let account = DecodeBudget::for_store(guard.clone()).expect("original finite component bank");
    let _scope = account.enter();
    let before = load_metadata(&leaf.lock_connection().expect("generation"))
        .expect("metadata")
        .1;
    let inputs = objects();
    let result = backend
        .put_many_if_absent_with_boundary(&account, &inputs, &mut || Ok(()))
        .expect("transparent checked chain");
    assert_eq!(result.len(), inputs.len());
    assert!(result.iter().all(PutReceipt::is_durable));
    assert_eq!(
        load_metadata(&leaf.lock_connection().expect("generation"))
            .expect("metadata")
            .1,
        before + 1
    );
    assert!(authorizer.calls.load(Ordering::SeqCst) >= inputs.len());
    for (id, _) in &inputs {
        assert!(
            !cache
                .contains(*id)
                .expect("writes do not promote to read cache")
        );
    }

    let extra_bytes = b"denied new object";
    let extra = ContentId::for_bytes(ObjectKind::Trace, 1, extra_bytes);
    authorizer.denied.store(true, Ordering::SeqCst);
    assert!(matches!(
        backend.put_many_if_absent_with_boundary(
            &account,
            &[(extra, BlobHandle::from_bytes(extra_bytes))],
            &mut || Ok(())
        ),
        Err(StoreError::Unauthorized)
    ));
    assert!(!leaf.contains(extra).expect("denied input never published"));
}

#[test]
fn existing_batch_bounds_refuse_before_any_source_or_row_publication() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::existing_batch_bounds_refuse_before_any_source_or_row_publication",
    ) {
        return;
    }
    let guard = original_quota();
    let root = tempfile::tempdir().expect("component catalog");
    let backend = bounded_leaf("component", root.path(), &guard);
    let account = DecodeBudget::for_store(guard.clone()).expect("original finite component bank");
    let _scope = account.enter();
    let input = objects();
    let too_many = vec![input[0].clone(); MAX_BATCH_OBJECTS + 1];
    assert!(matches!(
        backend.put_many_if_absent_with_boundary(&account, &too_many, &mut || Ok(())),
        Err(StoreError::Quota)
    ));
    let bytes = vec![0xa7_u8; MAX_BATCH_BYTES as usize + 1];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    assert!(matches!(
        backend.put_many_if_absent_with_boundary(
            &account,
            &[(id, BlobHandle::from_bytes(bytes))],
            &mut || Ok(())
        ),
        Err(StoreError::Quota)
    ));
    assert!(
        !backend
            .contains(input[0].0)
            .expect("count refusal leaves no row")
    );
    assert!(!backend.contains(id).expect("length refusal leaves no row"));
}

#[test]
fn corrupt_duplicate_refuses_new_rows_and_singleton_remains_available() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::corrupt_duplicate_refuses_new_rows_and_singleton_remains_available",
    ) {
        return;
    }
    let guard = original_quota();
    let root = tempfile::tempdir().expect("component catalog");
    let backend = bounded_leaf("component", root.path(), &guard);
    let inputs = objects();
    backend
        .put_if_absent(inputs[0].0, &inputs[0].1)
        .expect("unchanged singleton");
    backend
        .lock_connection()
        .expect("component corruption injection")
        .execute(
            "UPDATE objects SET body = ?1 WHERE id = ?2",
            params![b"wrong", inputs[0].0.encode()],
        )
        .expect("corrupt existing row");
    let account = DecodeBudget::for_store(guard.clone()).expect("finite component bank");
    let _scope = account.enter();
    let error = backend
        .put_many_if_absent_with_boundary(
            &account,
            &[inputs[1].clone(), inputs[0].clone()],
            &mut || Ok(()),
        )
        .expect_err("authenticate stored duplicate");
    assert!(matches!(original_failure(&error), StoreError::Corrupt { id } if *id == inputs[0].0));
    assert!(
        !backend
            .contains(inputs[1].0)
            .expect("no staged new row escaped")
    );
}

mod diagnostic;
