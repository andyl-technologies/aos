//! Finite original-owner proofs for paired checked SQLite administration.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::*;
use crate::content_store::fixture_sqlite_connection;
use crate::content_store::test_resources::FixtureResourceBudget;

struct Quota {
    resources: FixtureResourceBudget,
    revoked: AtomicBool,
    starts: AtomicUsize,
    peak_bytes: AtomicU64,
    peak_descriptors: AtomicU64,
}

impl Quota {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            resources: FixtureResourceBudget::new(16, 64 * 1024 * 1024),
            revoked: AtomicBool::new(false),
            starts: AtomicUsize::new(0),
            peak_bytes: AtomicU64::new(0),
            peak_descriptors: AtomicU64::new(0),
        })
    }
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(64 * 1024 * 1024)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.verify()?;
        let loan = self.resources.reserve(descriptors, bytes)?;
        let (descriptors, bytes) = self.resources.usage()?;
        self.peak_descriptors
            .fetch_max(descriptors, Ordering::SeqCst);
        self.peak_bytes.fetch_max(bytes, Ordering::SeqCst);
        Ok(loan)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.revoked.load(Ordering::Acquire) {
            Err(StoreError::Unauthorized)
        } else {
            Ok(())
        }
    }
}

struct Supervisor(Arc<Quota>);
struct Operation(Arc<Quota>);

impl SqliteCatalogSupervisor for Supervisor {
    fn reserve_resident_bytes(
        &self,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.0.reserve_resources(0, bytes)
    }

    fn begin(
        &self,
        _: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        self.0.starts.fetch_add(1, Ordering::SeqCst);
        self.0.verify()?;
        Ok(Box::new(Operation(self.0.clone())))
    }
}

impl SqliteCatalogOperation for Operation {
    fn check(&self) -> Result<(), StoreError> {
        self.0.verify()
    }
    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        self.0.verify()
    }
}

fn isolated(name: &str) -> bool {
    batch::tests::isolated_heap_test(name)
}

fn pair(root: &Path, guard: &Arc<Quota>) -> SqliteBlobAuthorities {
    SqliteBlobBackend::open_with_physical_quota_and_admin(
        "same-owner",
        root,
        guard.clone(),
        8 * 1024 * 1024,
        Arc::new(Supervisor(guard.clone())),
        &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
    )
    .expect("one admitted component catalog")
}

fn seeded(backend: &dyn ImmutableBlobBackend, count: usize) -> Vec<ContentId> {
    (0..count)
        .map(|index| {
            let bytes = index.to_le_bytes();
            let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
            backend
                .put_if_absent(id, &BlobHandle::from_bytes(bytes))
                .expect("durable seed");
            id
        })
        .collect()
}

#[test]
fn paired_views_and_outputs_hold_one_actual_original_owner() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::paired_views_and_outputs_hold_one_actual_original_owner",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let (backend, admin) = pair(root.path(), &guard);
    assert!(std::ptr::eq(
        Arc::as_ptr(&backend).cast::<()>(),
        Arc::as_ptr(&admin).cast::<()>()
    ));
    let ids = seeded(backend.as_ref(), 3);
    let account = DecodeBudget::for_store(guard.clone()).expect("original component account");
    let _scope = account.enter();
    let baseline = guard.resources.usage().expect("baseline");
    let starts = guard.starts.load(Ordering::SeqCst);
    let mut fence = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .expect("real fence");
    assert_eq!(guard.resources.usage().expect("FD owner").0, baseline.0 + 1);
    assert_eq!(guard.starts.load(Ordering::SeqCst), starts);
    let mut visited = Vec::new();
    let summary = fence
        .visit_inventory_with_boundary(
            &mut |row| {
                visited.push(row.id());
                Ok(())
            },
            &mut || guard.verify(),
        )
        .expect("terminal inventory");
    assert_eq!(summary.objects(), 3);
    assert_eq!(
        summary.logical_bytes(),
        3 * std::mem::size_of::<usize>() as u64
    );
    assert_eq!(summary.backend(), "same-owner");
    assert!(ids.iter().all(|id| visited.contains(id)));
    let receipt = fence
        .delete_candidates_with_boundary(&[ids[0], ids[0], ids[1]], &mut || guard.verify())
        .expect("ordered durable delete");
    assert_eq!(
        &*receipt,
        &[
            PlannedDeleteDisposition::Deleted,
            PlannedDeleteDisposition::AlreadyAbsent,
            PlannedDeleteDisposition::Deleted
        ]
    );
    drop(fence);
    assert!(guard.resources.usage().expect("retained outputs").1 > baseline.1);
    drop(backend);
    drop(admin);
    assert!(guard.resources.usage().expect("last outputs").1 > 0);
    drop(summary);
    drop(receipt);
    drop(_scope);
    drop(account);
    assert_eq!(
        guard.resources.usage().expect("full original restoration"),
        (0, 0)
    );
    assert_eq!(guard.peak_descriptors.load(Ordering::SeqCst), 1);
    assert!(guard.peak_bytes.load(Ordering::SeqCst) >= 48 * 1024 * 1024);
    assert!(guard.peak_bytes.load(Ordering::SeqCst) <= 64 * 1024 * 1024);
    let reopened = SqliteBlobBackend::open(
        "reopened",
        root.path(),
        &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
    )
    .expect("independent durable reopen");
    assert!(!reopened.contains(ids[0]).expect("removed"));
    assert!(!reopened.contains(ids[1]).expect("removed"));
    assert!(reopened.contains(ids[2]).expect("retained"));
}

#[test]
fn checked_and_ordinary_self_nesting_refuse_before_waiting_or_second_diagnostic() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::checked_and_ordinary_self_nesting_refuse_before_waiting_or_second_diagnostic",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let (_, admin) = pair(root.path(), &guard);
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let ordinary = admin
        .acquire_inventory_fence()
        .expect("legitimate ordinary fence");
    let before = guard.resources.usage().expect("ordinary usage");
    let error = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .err()
        .expect("same-thread nesting refuses");
    assert!(matches!(
        error.original_failure(),
        StoreError::Unsupported {
            capability: "paired-sql-inventory-fences"
        }
    ));
    assert_eq!(
        guard.resources.usage().expect("no retained second loan"),
        before
    );
    drop(error);
    drop(ordinary);
    let checked = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .expect("released gate reusable");
    let before = guard.resources.usage().expect("checked usage");
    let error = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .err()
        .expect("checked nesting refuses");
    assert!(matches!(
        error.original_failure(),
        StoreError::Unsupported {
            capability: "paired-sql-inventory-fences"
        }
    ));
    assert_eq!(guard.resources.usage().expect("no new diagnostic"), before);
    drop(error);
    drop(checked);
    let _last = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .expect("same original fence reacquired after close");
}

#[test]
fn repeated_inventory_and_sixty_four_delete_reuse_one_linear_diagnostic() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::repeated_inventory_and_sixty_four_delete_reuse_one_linear_diagnostic",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let (backend, admin) = pair(root.path(), &guard);
    let ids = seeded(backend.as_ref(), 64);
    let account = DecodeBudget::for_store(guard.clone()).expect("original finite account");
    let _scope = account.enter();
    let mut fence = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .expect("real fence");
    let retained = guard.resources.usage().expect("one diagnostic");
    assert!(retained.1 >= 48 * 1024 * 1024);
    for _ in 0..64 {
        let summary = fence
            .visit_inventory_with_boundary(&mut |_| Ok(()), &mut || guard.verify())
            .expect("same bank inventory");
        assert_eq!(summary.objects(), 64);
        drop(summary);
        assert_eq!(guard.resources.usage().expect("no accumulation"), retained);
    }
    let result = fence
        .delete_candidates_with_boundary(&ids, &mut || guard.verify())
        .expect("actual64 transaction");
    assert!(
        result
            .iter()
            .all(|value| *value == PlannedDeleteDisposition::Deleted)
    );
    drop(result);
    assert_eq!(
        guard.resources.usage().expect("same bank after64 rows"),
        retained
    );
    let result = fence
        .delete_candidates_with_boundary(&ids, &mut || guard.verify())
        .expect("idempotent absent64");
    assert!(
        result
            .iter()
            .all(|value| *value == PlannedDeleteDisposition::AlreadyAbsent)
    );
}

#[test]
fn corrupt_metadata_refuses_before_inventory_or_mutation_and_retains_error_bank() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::corrupt_metadata_refuses_before_inventory_or_mutation_and_retains_error_bank",
    ) {
        return;
    }
    for malformed in [
        "UPDATE metadata SET instance='wrong-type'",
        "UPDATE metadata SET instance=x'00'",
        "UPDATE metadata SET checksum=zeroblob(32)",
        "UPDATE metadata SET generation=-1",
    ] {
        let root = tempfile::tempdir().expect("catalog");
        let guard = Quota::new();
        let (backend, admin) = pair(root.path(), &guard);
        let ids = seeded(backend.as_ref(), 1);
        let foreign = fixture_sqlite_connection(root.path().join(DATABASE_FILE))
            .expect("external corruption fixture");
        foreign
            .execute_batch(malformed)
            .expect("actual malformed row");
        let account = DecodeBudget::for_store(guard.clone()).expect("same finite account");
        let _scope = account.enter();
        let before = guard.resources.usage().expect("baseline");
        let error = admin
            .acquire_inventory_fence_with_boundary(&mut || guard.verify())
            .err()
            .expect("metadata refusal");
        assert!(matches!(error, StoreError::SqliteDiagnostic { .. }));
        assert!(
            guard.resources.usage().expect("original live diagnostic").1
                >= before.1 + 48 * 1024 * 1024
        );
        let present: bool = with_id_text(ids[0], |encoded| {
            foreign
                .lock()
                .expect("managed external presence reader")
                .query_row(diagnostic::PRESENCE_SQL, [encoded], |row| row.get(0))
                .map_err(|source| database_error("external-object-presence", source))
        })
        .expect("independent object remains");
        assert!(present);
        drop(error);
        assert_eq!(
            guard.resources.usage().expect("error closes last credit"),
            before
        );
    }
}

#[test]
fn generation_overflow_preflights_all_removals_without_partial_delete() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::generation_overflow_preflights_all_removals_without_partial_delete",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let (backend, admin) = pair(root.path(), &guard);
    let ids = seeded(backend.as_ref(), 2);
    let foreign = fixture_sqlite_connection(root.path().join(DATABASE_FILE))
        .expect("foreign metadata fixture");
    let (instance, _) =
        load_metadata(&foreign.lock().expect("managed metadata connection")).expect("instance");
    let generation = i64::MAX as u64 - 1;
    foreign
        .execute(
            "UPDATE metadata SET generation=?1,checksum=?2",
            params![
                generation as i64,
                metadata_checksum(instance, generation).as_slice()
            ],
        )
        .expect("valid near-overflow generation");
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let mut fence = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .expect("valid held fence");
    let journal = root.path().join(format!("{DATABASE_FILE}-journal"));
    let mut mutation_observed = false;
    let error = fence
        .delete_candidates_with_boundary(&ids, &mut || {
            mutation_observed |= journal.exists();
            guard.verify()
        })
        .expect_err("second actual removal overflows signed SQL generation");
    assert!(
        !mutation_observed,
        "overflow must precede the first journaled mutation"
    );
    assert!(matches!(error.original_failure(), StoreError::Quota));
    assert_eq!(
        load_metadata(&foreign.lock().expect("managed metadata connection"))
            .expect("no advance")
            .1,
        generation
    );
    for id in ids {
        assert!(backend.contains(id).expect("all original objects retained"));
    }
    assert!(matches!(
        fence
            .delete_candidates_with_boundary(&[], &mut || guard.verify())
            .expect_err("error consumed checked bank")
            .original_failure(),
        StoreError::Unsupported {
            capability: "consumed-checked-sqlite-inventory-fence"
        }
    ));
}

#[test]
fn actual_foreign_sqlite_lock_polls_original_cancellation_without_native_busy_wait() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::actual_foreign_sqlite_lock_polls_original_cancellation_without_native_busy_wait",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let (_, admin) = pair(root.path(), &guard);
    let foreign =
        fixture_sqlite_connection(root.path().join(DATABASE_FILE)).expect("foreign writer");
    foreign
        .execute_batch("BEGIN EXCLUSIVE")
        .expect("actual SQLite exclusive lock");
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let mut polls = 0;
    let error = admin
        .acquire_inventory_fence_with_boundary(&mut || {
            polls += 1;
            if polls == 40 {
                Err(StoreError::Unauthorized)
            } else {
                guard.verify()
            }
        })
        .err()
        .expect("same original boundary cancels lock wait");
    assert_eq!(polls, 40);
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    foreign
        .execute_batch("ROLLBACK")
        .expect("release foreign lock");
    drop(error);
    let _fence = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .expect("same healthy connection with exact timeout restored");
}

#[test]
fn inventory_prefix_failure_does_not_replay_visits_or_invent_terminal_summary() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::inventory_prefix_failure_does_not_replay_visits_or_invent_terminal_summary",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let (backend, admin) = pair(root.path(), &guard);
    seeded(backend.as_ref(), 3);
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let mut fence = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .expect("fence");
    let mut visited = 0;
    let error = fence
        .visit_inventory_with_boundary(
            &mut |_| {
                visited += 1;
                if visited == 2 {
                    Err(StoreError::Unauthorized)
                } else {
                    Ok(())
                }
            },
            &mut || guard.verify(),
        )
        .expect_err("visitor refusal cannot become EOF");
    assert_eq!(visited, 2);
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert!(matches!(
        fence
            .visit_inventory_with_boundary(
                &mut |_| { panic!("consumed cursor must not replay visitor") },
                &mut || guard.verify()
            )
            .expect_err("consumed cursor")
            .original_failure(),
        StoreError::Unsupported { .. }
    ));
}

#[test]
fn late_actual_commit_failure_preserves_cached_generation_and_last_error_credit() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::late_actual_commit_failure_preserves_cached_generation_and_last_error_credit",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    // Use the same production leaf body to observe the scalar held-fence state.
    let mut backend = SqliteBlobBackend::open_inner(
        "component".into(),
        root.path().into(),
        8 * 1024 * 1024,
        Some(Arc::new(Supervisor(guard.clone()))),
        &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
    )
    .expect("private capped component leaf");
    backend.resident_lease = guard
        .reserve_resources(
            0,
            minimum_sqlite_catalog_resident_bytes("component", root.path()).expect("actual size"),
        )
        .expect("actual original lease")
        .into();
    let ids = seeded(&backend, 1);
    let foreign = fixture_sqlite_connection(root.path().join(DATABASE_FILE))
        .expect("independent durable observer");
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let baseline = guard.resources.usage().expect("baseline");
    let (mut fence, _fence_credit) =
        acquire_owned(&backend, &mut || guard.verify()).expect("actual production fence body");
    let before = fence.inner.generation;
    let error = fence
        .delete_candidates_with_boundary(&ids, &mut || {
            let present: bool = foreign
                .query_row("SELECT EXISTS(SELECT 1 FROM objects)", [], |row| row.get(0))
                .expect("external durable observation");
            if present {
                guard.verify()
            } else {
                Err(StoreError::Unauthorized)
            }
        })
        .expect_err("first actual post-COMMIT poll refuses");
    assert_eq!(fence.inner.generation, before + 1);
    assert_eq!(
        load_metadata(&foreign.lock().expect("managed metadata connection"))
            .expect("committed metadata")
            .1,
        before + 1
    );
    let StoreError::SqliteDiagnostic { source } = &error else {
        panic!("original diagnostic retained");
    };
    let StoreError::SqliteScope { source } = source.failure() else {
        panic!("typed scope outcome retained");
    };
    assert_eq!(source.outcome(), busy::SqliteCommitOutcome::Committed);
    assert!(source.rollback_failure().is_none());
    assert!(
        guard.resources.usage().expect("last error owns bank").1 >= baseline.1 + 48 * 1024 * 1024
    );
    drop(fence);
    drop(_fence_credit);
    assert!(
        guard.resources.usage().expect("error outlives fence").1 >= baseline.1 + 48 * 1024 * 1024
    );
    drop(error);
    assert_eq!(
        guard
            .resources
            .usage()
            .expect("exact last-owner restoration"),
        baseline
    );
}

#[test]
fn actual_commit_busy_keeps_one_original_scope_until_reader_releases() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::actual_commit_busy_keeps_one_original_scope_until_reader_releases",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let (backend, admin) = pair(root.path(), &guard);
    let ids = seeded(backend.as_ref(), 1);
    let foreign =
        fixture_sqlite_connection(root.path().join(DATABASE_FILE)).expect("foreign reader");
    foreign
        .execute_batch("BEGIN DEFERRED")
        .expect("read transaction");
    let count: i64 = foreign
        .query_row("SELECT count(*) FROM objects", [], |row| row.get(0))
        .expect("actual retained SHARED read lock");
    assert_eq!(count, 1);
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let mut fence = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .expect("compatible inventory fence");
    let starts = guard.starts.load(Ordering::SeqCst);
    let journal = root.path().join(format!("{DATABASE_FILE}-journal"));
    let mut mutation_polls = 0;
    let result = fence
        .delete_candidates_with_boundary(&ids, &mut || {
            if journal.exists() {
                mutation_polls += 1;
                if mutation_polls == 80 {
                    foreign
                        .execute_batch("ROLLBACK")
                        .expect("release actual foreign read lock");
                }
            }
            guard.verify()
        })
        .expect("manual FULL COMMIT retries base BUSY under original callback");
    assert!(mutation_polls >= 80);
    assert_eq!(&*result, &[PlannedDeleteDisposition::Deleted]);
    assert_eq!(guard.starts.load(Ordering::SeqCst), starts);
    assert_eq!(
        foreign
            .query_row("SELECT count(*) FROM objects", [], |row| row
                .get::<_, i64>(0))
            .expect("durable after release"),
        0
    );
}

#[test]
fn unwind_after_actual_delete_quarantines_every_alias_without_hidden_cleanup() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::unwind_after_actual_delete_quarantines_every_alias_without_hidden_cleanup",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let backend = SqliteBlobBackend::open_inner(
        "component".into(),
        root.path().into(),
        8 * 1024 * 1024,
        Some(Arc::new(Supervisor(guard.clone()))),
        &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
    )
    .expect("private capped leaf");
    let ids = seeded(&backend, 1);
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let (mut fence, _fence_credit) =
        acquire_owned(&backend, &mut || guard.verify()).expect("actual fence body");
    let journal = root.path().join(format!("{DATABASE_FILE}-journal"));
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = fence.delete_candidates_with_boundary(&ids, &mut || {
            assert!(
                !journal.exists(),
                "original callback unwinds after real uncommitted mutation"
            );
            guard.verify()
        });
    }));
    assert!(unwound.is_err());
    assert!(backend.quarantined.load(Ordering::Acquire));
    assert!(!fence.inner.connection.is_autocommit());
    assert!(matches!(
        backend.contains(ids[0]),
        Err(StoreError::Unavailable)
    ));
    assert!(matches!(
        fence
            .delete_candidates_with_boundary(&[], &mut || guard.verify())
            .expect_err("linear diagnostic consumed on unwind")
            .original_failure(),
        StoreError::Unsupported { .. }
    ));
    drop(fence);
    drop(backend);
    let reopened = SqliteBlobBackend::open(
        "reopened",
        root.path(),
        &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
    )
    .expect("connection drop recovers actual uncommitted transaction");
    assert!(
        reopened
            .contains(ids[0])
            .expect("uncommitted row deletion never published")
    );
}

#[test]
fn late_physical_facade_refusal_keeps_committed_outcome_and_consumes_same_bank() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::late_physical_facade_refusal_keeps_committed_outcome_and_consumes_same_bank",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let (backend, admin) = pair(root.path(), &guard);
    let ids = seeded(backend.as_ref(), 1);
    let foreign = fixture_sqlite_connection(root.path().join(DATABASE_FILE))
        .expect("independent durable observer");
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let baseline = guard.resources.usage().expect("baseline");
    let mut fence = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .expect("actual paired facade fence");
    let mut committed_polls = 0;
    let error = fence
        .delete_candidates_with_boundary(&ids, &mut || {
            let count: i64 = foreign
                .query_row("SELECT count(*) FROM objects", [], |row| row.get(0))
                .expect("actual durable observation");
            if count == 0 {
                committed_polls += 1;
                // The first three polls close SQL work, restore its timeout, and
                // accept the leaf receipt. Refuse the actual facade's final check.
                if committed_polls == 4 {
                    return Err(StoreError::Unauthorized);
                }
            }
            guard.verify()
        })
        .expect_err("late facade cannot acknowledge expired original boundary");
    assert_eq!(committed_polls, 4);
    let StoreError::SqliteDiagnostic { source } = &error else {
        panic!("same fence bank retained");
    };
    let StoreError::SqliteScope { source } = source.failure() else {
        panic!("committed token retained through facade");
    };
    assert_eq!(source.outcome(), busy::SqliteCommitOutcome::Committed);
    assert!(source.rollback_failure().is_none());
    assert_eq!(
        load_metadata(&foreign.lock().expect("managed metadata connection"))
            .expect("durable generation")
            .1,
        3
    );
    assert!(matches!(
        fence
            .delete_candidates_with_boundary(&[], &mut || guard.verify())
            .expect_err("consumed bank never cloned or replenished")
            .original_failure(),
        StoreError::Unsupported { .. }
    ));
    drop(fence);
    assert!(
        guard
            .resources
            .usage()
            .expect("error retains original48MiB")
            .1
            >= baseline.1 + 48 * 1024 * 1024
    );
    drop(error);
    assert_eq!(
        guard
            .resources
            .usage()
            .expect("last error closes exact loan"),
        baseline
    );
}

#[test]
fn late_facade_callback_cannot_hide_original_account_refusal() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::late_facade_callback_cannot_hide_original_account_refusal",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let (backend, admin) = pair(root.path(), &guard);
    let ids = seeded(backend.as_ref(), 1);
    let foreign =
        fixture_sqlite_connection(root.path().join(DATABASE_FILE)).expect("durable observer");
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let baseline = guard.resources.usage().expect("baseline");
    let mut fence = admin
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .expect("actual paired fence");
    let mut committed_polls = 0;

    let error = fence
        .delete_candidates_with_boundary(&ids, &mut || {
            let count: i64 = foreign
                .query_row("SELECT count(*) FROM objects", [], |row| row.get(0))
                .expect("actual durable observation");
            if count == 0 {
                committed_polls += 1;
                if committed_polls == 4 {
                    let refused = account.reserve_scratch_bytes(u64::MAX);
                    assert!(refused.is_err(), "original finite account refuses");
                }
            }
            // A successful callback and live physical guard cannot erase the
            // original account's sticky typed refusal at final acceptance.
            Ok(())
        })
        .expect_err("stored origin must be checked after the facade callback");
    assert_eq!(committed_polls, 4);
    guard
        .verify()
        .expect("physical guard remains independently live");
    assert!(matches!(
        error.original_failure(),
        StoreError::DecodeAdmission { .. }
    ));
    let StoreError::SqliteDiagnostic { source } = &error else {
        panic!("original diagnostic bank retained");
    };
    let StoreError::SqliteScope { source } = source.failure() else {
        panic!("final acceptance keeps the actual commit outcome");
    };
    assert_eq!(source.outcome(), busy::SqliteCommitOutcome::Committed);
    assert_eq!(
        load_metadata(&foreign.lock().expect("managed metadata connection"))
            .expect("durable generation")
            .1,
        3
    );

    drop(fence);
    assert!(guard.resources.usage().expect("retained bank").1 >= baseline.1 + 48 * 1024 * 1024);
    drop(error);
    assert_eq!(guard.resources.usage().expect("last error owner"), baseline);
}

#[test]
fn stored_fence_origin_funds_outputs_even_under_a_different_ambient_scope() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::stored_fence_origin_funds_outputs_even_under_a_different_ambient_scope",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let (_, admin) = pair(root.path(), &guard);
    let original = DecodeBudget::for_store(guard.clone()).expect("original finite account");
    let scope = original.enter();
    let mut fence = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .expect("actual origin retained");
    drop(scope);
    let other = Quota::new();
    let ambient = DecodeBudget::for_store(other.clone()).expect("unrelated ambient account");
    let _scope = ambient.enter();
    let other_baseline = other.resources.usage().expect("other baseline");
    let original_baseline = guard.resources.usage().expect("original held fence");
    let output = fence
        .visit_inventory_with_boundary(&mut |_| Ok(()), &mut || guard.verify())
        .expect("stored account output");
    assert_eq!(
        other.resources.usage().expect("no ambient substitution"),
        other_baseline
    );
    assert!(guard.resources.usage().expect("original paid output").1 > original_baseline.1);
    drop(output);
    assert_eq!(
        guard.resources.usage().expect("original output closes"),
        original_baseline
    );
}

#[test]
fn original_descriptor_exhaustion_refuses_before_child_fence_or_diagnostic_admission() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::original_descriptor_exhaustion_refuses_before_child_fence_or_diagnostic_admission",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let (_, admin) = pair(root.path(), &guard);
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let blocker = guard
        .reserve_resources(16, 1)
        .expect("all independently authored descriptor credit");
    let before = guard.resources.usage().expect("original usage");
    let starts = guard.starts.load(Ordering::SeqCst);
    let error = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .err()
        .expect("real physical owner refuses descriptor");
    assert!(matches!(error, StoreError::Quota));
    assert_eq!(
        guard
            .resources
            .usage()
            .expect("no diagnostic or child owner"),
        before
    );
    assert_eq!(guard.starts.load(Ordering::SeqCst), starts);
    drop(blocker);
    let _fence = admin
        .acquire_inventory_fence_with_boundary(&mut || guard.verify())
        .expect("same original credit reusable after real loan closes");
}

#[test]
fn cancellation_after_actual_delete_rolls_back_before_exact_timeout_restoration() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::cancellation_after_actual_delete_rolls_back_before_exact_timeout_restoration",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let guard = Quota::new();
    let backend = SqliteBlobBackend::open_inner(
        "component".into(),
        root.path().into(),
        8 * 1024 * 1024,
        Some(Arc::new(Supervisor(guard.clone()))),
        &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
    )
    .expect("private capped leaf");
    let ids = seeded(&backend, 2);
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let (mut fence, _fence_credit) =
        acquire_owned(&backend, &mut || guard.verify()).expect("actual fence body");
    let timeout: i64 = fence
        .inner
        .connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .expect("exact saved timeout");
    let generation = fence.inner.generation;
    let journal = root.path().join(format!("{DATABASE_FILE}-journal"));
    let mut actual_mutation = false;
    let error = fence
        .delete_candidates_with_boundary(&ids, &mut || {
            if journal.exists() {
                actual_mutation = true;
                Err(StoreError::Unauthorized)
            } else {
                guard.verify()
            }
        })
        .expect_err("cancel original work after real staged DELETE");
    assert!(actual_mutation);
    let StoreError::SqliteDiagnostic { source } = &error else {
        panic!("diagnostic retained");
    };
    let StoreError::SqliteScope { source } = source.failure() else {
        panic!("typed SQL outcome retained");
    };
    assert_eq!(source.outcome(), busy::SqliteCommitOutcome::NotCommitted);
    assert!(source.rollback_failure().is_none());
    assert!(source.restoration_failure().is_none());
    assert!(fence.inner.connection.is_autocommit());
    assert_eq!(
        fence
            .inner
            .connection
            .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
            .expect("actual restored timeout"),
        timeout
    );
    assert_eq!(
        load_metadata(&fence.inner.connection)
            .expect("no durable generation advance")
            .1,
        generation
    );
    assert_eq!(
        fence
            .inner
            .connection
            .query_row("SELECT count(*) FROM objects", [], |row| row
                .get::<_, i64>(0))
            .expect("all rows restored"),
        2
    );
    assert!(!backend.quarantined.load(Ordering::Acquire));
}

#[test]
fn post_acquisition_callback_reentry_sees_actual_mutex_owner_before_waiting() {
    if isolated(
        "content_store::sqlite::admin_batch::tests::post_acquisition_callback_reentry_sees_actual_mutex_owner_before_waiting",
    ) {
        return;
    }

    let mut calls = 0;
    let error = catalog::write_gate_with_boundary(&mut || {
        calls += 1;
        if calls == 2 {
            catalog::write_gate_with_boundary(&mut || Ok(())).map(|_| ())
        } else {
            Ok(())
        }
    })
    .err()
    .expect("terminal callback cannot reacquire its own actual mutex");
    assert!(matches!(
        error,
        StoreError::Unsupported {
            capability: "paired-sql-inventory-fences"
        }
    ));
    assert_eq!(calls, 2);
    let _recovered = catalog::write_gate_with_boundary(&mut || Ok(()))
        .expect("callback refusal unlocks actual mutex and clears marker");
}
