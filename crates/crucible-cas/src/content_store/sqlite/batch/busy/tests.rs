//! Real SQLite lock, durable-outcome, exact restoration and unwind proofs.

use super::*;

mod ram_cause;
use crate::content_store::StorePhysicalQuotaGuard;
use crate::owned_decode::DecodeBudget;

fn isolated(name: &str) -> bool {
    super::super::tests::isolated_heap_test(&format!(
        "content_store::sqlite::batch::busy::tests::{name}"
    ))
}

fn backend() -> (
    tempfile::TempDir,
    Arc<super::super::tests::Quota>,
    SqliteBlobBackend,
    DecodeBudget,
) {
    let root = tempfile::tempdir().expect("actual private catalog");
    let guard = super::super::tests::original_quota();
    let backend = super::super::tests::bounded_leaf("original", root.path(), &guard);
    let account = DecodeBudget::for_store(guard.clone()).expect("same original account");
    (root, guard, backend, account)
}

fn scope(error: &StoreError) -> &SqliteScopeError {
    match error {
        StoreError::SqliteDiagnostic { source } => scope(source.failure()),
        StoreError::SqliteScope { source } => source,
        other => panic!("expected original scope carrier: {other:?}"),
    }
}

fn timeout(connection: &Connection) -> i64 {
    connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .expect("actual timeout")
}

#[test]
fn foreign_write_lock_polls_original_callback_and_restores_exact_timeout() {
    if isolated("foreign_write_lock_polls_original_callback_and_restores_exact_timeout") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    backend
        .lock_connection()
        .expect("original connection")
        .busy_timeout(Duration::from_millis(1234))
        .expect("authored prior timeout");
    let foreign = Connection::open(root.path().join(DATABASE_FILE)).expect("foreign connection");
    foreign
        .execute_batch("BEGIN IMMEDIATE")
        .expect("actual foreign write lock");
    let mut checks = 0;

    let error = backend
        .put_many_if_absent_with_boundary(&account, &super::super::tests::objects(), &mut || {
            checks += 1;
            guard.verify()?;
            if checks == 256 {
                Err(super::super::tests::expired())
            } else {
                Ok(())
            }
        })
        .expect_err("original callback stops actual BUSY retry");
    assert_eq!(checks, 256);
    assert_eq!(scope(&error).outcome(), SqliteCommitOutcome::NotCommitted);
    assert!(matches!(
        error.original_failure(),
        StoreError::Supervision { .. }
    ));
    super::super::tests::assert_expired(error);
    foreign
        .execute_batch("ROLLBACK")
        .expect("release foreign lock");
    let connection = backend
        .lock_connection()
        .expect("original connection reusable");
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 1234);
    assert_eq!(
        load_metadata(&connection)
            .expect("no generation publication")
            .1,
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, usize>(0))
            .expect("row count"),
        0
    );
}

#[test]
fn actual_commit_busy_cancellation_rolls_back_and_restores_without_new_work() {
    if isolated("actual_commit_busy_cancellation_rolls_back_and_restores_without_new_work") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let foreign = Connection::open(root.path().join(DATABASE_FILE)).expect("foreign reader");
    foreign
        .execute_batch("BEGIN; SELECT * FROM objects;")
        .expect("retained SHARED read lock");
    let credit = diagnostic::admit(
        &account,
        backend.maximum_sqlite_heap_bytes,
        Some(root.path()),
    )
    .expect("original diagnostic loan");
    let mut connection = backend.lock_connection().expect("actual connection");
    connection
        .busy_timeout(Duration::from_millis(987))
        .expect("original timeout");
    let mut checks = 0;
    let mut committing = false;
    let error = diagnostic::retain_failure(credit, || {
        with_zero(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut || guard.verify(),
            |connection, progress, _| {
                assert_eq!(timeout(connection), 0);
                connection
                    .execute_batch("BEGIN DEFERRED")
                    .expect("real owned transaction");
                progress.began();
                connection
                    .execute(
                        "INSERT INTO objects (id, body) VALUES ('component', x'01')",
                        [],
                    )
                    .expect("write before COMMIT");
                advance_metadata(connection).expect("generation staged before COMMIT");
                committing = true;
                let result = retry(
                    connection,
                    true,
                    &backend.quarantined,
                    &mut || {
                        checks += 1;
                        guard.verify()?;
                        if checks == 32 {
                            Err(super::super::tests::expired())
                        } else {
                            Ok(())
                        }
                    },
                    |_| {
                        connection
                            .execute_batch("COMMIT")
                            .map_err(|source| database_error("actual-busy-commit", source))
                    },
                );
                if result.is_err() {
                    progress.commit_failed(connection);
                }
                result
            },
        )
        .and_then(|accepted| accepted.finish(Ok))
    })
    .expect_err("actual blocked COMMIT stops at original callback");
    assert!(committing);
    assert_eq!(checks, 32);
    assert_eq!(scope(&error).outcome(), SqliteCommitOutcome::NotCommitted);
    super::super::tests::assert_expired(error);
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 987);
    assert_eq!(
        load_metadata(&connection)
            .expect("generation rolled back")
            .1,
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, usize>(0))
            .expect("actual rollback"),
        0
    );
    assert!(!backend.quarantined.load(Ordering::Acquire));
    foreign.execute_batch("ROLLBACK").expect("release reader");
}

#[test]
fn only_base_busy_with_active_transaction_is_retryable() {
    if isolated("only_base_busy_with_active_transaction_is_retryable") {
        return;
    }
    let (_, guard, backend, account) = backend();
    let _scope = account.enter();
    let connection = backend.lock_connection().expect("actual connection");
    for (code, transactional) in [(6, false), (261, false), (517, false), (5, true)] {
        let credit = diagnostic::admit(&account, backend.maximum_sqlite_heap_bytes, None)
            .expect("original copy loan");
        let mut statements = 0;
        let error = diagnostic::retain_failure(credit, || {
            retry(
                &connection,
                transactional,
                &backend.quarantined,
                &mut || guard.verify(),
                |_| {
                    statements += 1;
                    Err::<(), _>(database_error(
                        "exact-ineligible-code",
                        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None),
                    ))
                },
            )
        })
        .expect_err("ineligible code/state preserves original refusal");
        assert_eq!(statements, 1);
        let StoreError::StreamIo { source, .. } = super::super::tests::original_failure(&error)
        else {
            panic!("original code carrier")
        };
        assert!(
            matches!(source.get_ref().and_then(|source| source.downcast_ref::<rusqlite::Error>()), Some(rusqlite::Error::SqliteFailure(error, None)) if error.extended_code == code)
        );
    }
}

#[test]
fn committed_outcome_survives_final_receipt_failure_and_releases_last_credit() {
    if isolated("committed_outcome_survives_final_receipt_failure_and_releases_last_credit") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let entered = account.enter();
    let credit = diagnostic::admit(
        &account,
        backend.maximum_sqlite_heap_bytes,
        Some(root.path()),
    )
    .expect("original copy loan");
    let mut connection = backend.lock_connection().expect("actual connection");
    let error = diagnostic::retain_failure(credit, || {
        let accepted = with_zero(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut || guard.verify(),
            |connection, progress, _| {
                connection
                    .execute_batch("BEGIN DEFERRED")
                    .expect("original transaction");
                progress.began();
                connection
                    .execute(
                        "INSERT INTO objects (id, body) VALUES ('component', x'01')",
                        [],
                    )
                    .expect("original write");
                advance_metadata(connection).expect("original generation");
                connection
                    .execute_batch("COMMIT")
                    .expect("actual durable commit");
                progress.committed();
                Ok(())
            },
        )?;
        accepted.finish(|()| Err::<(), _>(super::super::tests::expired()))
    })
    .expect_err("final completion failure preserves observed commit");
    assert_eq!(scope(&error).outcome(), SqliteCommitOutcome::Committed);
    assert!(matches!(
        error.original_failure(),
        StoreError::Supervision { .. }
    ));
    assert!(scope(&error).rollback_failure().is_none());
    assert_eq!(load_metadata(&connection).expect("durable generation").1, 2);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, usize>(0))
            .expect("committed row"),
        1
    );
    assert_eq!(timeout(&connection), 5000);
    drop(connection);
    drop(entered);
    drop(account);
    drop(backend);
    let weak = Arc::downgrade(&guard);
    drop(guard);
    assert!(weak.upgrade().is_some());
    drop(error);
    assert!(
        weak.upgrade().is_none(),
        "all retained error loans close last"
    );
}

#[test]
fn dual_cleanup_failure_retains_causes_and_quarantines_every_alias() {
    if isolated("dual_cleanup_failure_retains_causes_and_quarantines_every_alias") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let input = super::super::tests::objects();
    backend
        .put_if_absent(input[0].0, &input[0].1)
        .expect("initial ordinary object");
    let source = backend
        .read(input[0].0, None)
        .expect("previously issued source");
    let mut reader = source.open().expect("previously issued reader");
    let mut fence = backend
        .acquire_inventory_fence()
        .expect("previously issued fence");
    let credit = diagnostic::admit(
        &account,
        backend.maximum_sqlite_heap_bytes,
        Some(root.path()),
    )
    .expect("actual copy loan");
    let mut connection = backend
        .read_connection
        .lock()
        .expect("distinct actual reader connection");
    let error = diagnostic::retain_failure(credit, || {
        with_cleanup(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut || guard.verify(),
            |connection, progress, _| {
                connection
                    .execute_batch("BEGIN DEFERRED")
                    .expect("actual admitted transaction");
                progress.began();
                Err::<(), _>(super::super::tests::expired())
            },
            |_| Err(rusqlite::Error::InvalidQuery),
            |_, _| Err(rusqlite::Error::InvalidQuery),
        )
        .and_then(|accepted| accepted.finish(Ok))
    })
    .expect_err("actual unfinished transaction and failed restore refuse reuse");
    let failure = scope(&error);
    assert_eq!(failure.outcome(), SqliteCommitOutcome::Uncertain);
    assert!(matches!(
        failure.rollback_failure(),
        Some(rusqlite::Error::InvalidQuery)
    ));
    assert!(matches!(
        failure.restoration_failure(),
        Some(rusqlite::Error::InvalidQuery)
    ));
    assert!(failure.work_failure().is_some());
    assert!(backend.quarantined.load(Ordering::Acquire));
    drop(connection);
    assert!(matches!(
        backend.read(input[0].0, None),
        Err(StoreError::Unavailable)
    ));
    assert!(matches!(source.open(), Err(StoreError::Unavailable)));
    assert!(reader.read(&mut [0; 5]).is_err());
    assert!(matches!(
        fence.visit_inventory(&mut |_| Ok(())),
        Err(StoreError::Unavailable)
    ));
    assert!(matches!(
        fence.delete_candidate(input[0].0),
        Err(StoreError::Unavailable)
    ));
    assert!(matches!(
        backend.put_many_if_absent_with_boundary(&account, &[], &mut || guard.verify()),
        Err(StoreError::Unavailable)
    ));
}

#[test]
fn restore_failure_after_real_commit_never_erases_committed_outcome() {
    if isolated("restore_failure_after_real_commit_never_erases_committed_outcome") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let credit = diagnostic::admit(
        &account,
        backend.maximum_sqlite_heap_bytes,
        Some(root.path()),
    )
    .expect("actual copy loan");
    let mut connection = backend.lock_connection().expect("actual connection");
    let error = diagnostic::retain_failure(credit, || {
        with_cleanup(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut || guard.verify(),
            |connection, progress, _| {
                connection
                    .execute_batch("BEGIN DEFERRED")
                    .expect("real transaction");
                progress.began();
                advance_metadata(connection).expect("staged generation");
                connection.execute_batch("COMMIT").expect("durable success");
                progress.committed();
                Ok(())
            },
            |connection| connection.execute_batch("ROLLBACK"),
            |_, _| Err(rusqlite::Error::InvalidQuery),
        )
        .and_then(|accepted| accepted.finish(Ok))
    })
    .expect_err("restoration refusal is explicit after COMMIT");
    assert_eq!(scope(&error).outcome(), SqliteCommitOutcome::Committed);
    assert!(scope(&error).work_failure().is_none());
    assert!(matches!(
        error.original_failure(),
        StoreError::SqliteScope { .. }
    ));
    assert!(scope(&error).rollback_failure().is_none());
    assert!(scope(&error).restoration_failure().is_some());
    assert_eq!(load_metadata(&connection).expect("durable generation").1, 2);
    assert!(backend.quarantined.load(Ordering::Acquire));
}

#[test]
fn unwind_after_zero_quarantines_without_hidden_cleanup_or_timeout_reset() {
    if isolated("unwind_after_zero_quarantines_without_hidden_cleanup_or_timeout_reset") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let mut connection = backend
        .lock_connection()
        .expect("actual retained connection");
    let credit = diagnostic::admit(
        &account,
        backend.maximum_sqlite_heap_bytes,
        Some(root.path()),
    )
    .expect("actual copy loan");
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = diagnostic::retain_failure(credit, || {
            with_zero(
                &account,
                &mut connection,
                &backend.quarantined,
                &mut || guard.verify(),
                |connection, progress, _| -> Result<(), StoreError> {
                    connection
                        .execute_batch("BEGIN DEFERRED")
                        .expect("owned original transaction");
                    progress.began();
                    panic!("original callback unwinds after state mutation");
                },
            )
            .and_then(|accepted| accepted.finish(Ok))
        });
    }));
    assert!(unwound.is_err());
    assert!(backend.quarantined.load(Ordering::Acquire));
    assert!(!connection.is_autocommit(), "sentinel Drop runs no SQL");
    assert_eq!(
        timeout(&connection),
        0,
        "sentinel Drop does not pretend restoration succeeded"
    );
    drop(connection);
    assert!(matches!(
        backend.lock_connection(),
        Err(StoreError::Unavailable)
    ));
}

#[test]
fn checked_source_foreign_exclusive_lock_uses_original_callback_and_timeout() {
    if isolated("checked_source_foreign_exclusive_lock_uses_original_callback_and_timeout") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let input = super::super::tests::objects();
    backend
        .put_if_absent(input[0].0, &input[0].1)
        .expect("ordinary publication");
    let source = backend
        .read(input[0].0, None)
        .expect("retained actual source");
    backend
        .read_connection
        .lock()
        .expect("actual read connection")
        .busy_timeout(Duration::from_millis(777))
        .expect("authored original timeout");
    let foreign = Connection::open(root.path().join(DATABASE_FILE)).expect("foreign connection");
    foreign
        .execute_batch("BEGIN EXCLUSIVE")
        .expect("actual exclusive database lock");
    let mut checks = 0;

    let error = source
        .read_all_with_boundary(&account, 1024, &mut || {
            checks += 1;
            guard.verify()?;
            if checks == 64 {
                Err(super::super::tests::expired())
            } else {
                Ok(())
            }
        })
        .expect_err("same source callback ends SQLite BUSY wait");
    assert_eq!(checks, 64);
    assert_eq!(scope(&error).outcome(), SqliteCommitOutcome::NotCommitted);
    super::super::tests::assert_expired(error);
    foreign
        .execute_batch("ROLLBACK")
        .expect("release actual foreign lock");
    assert_eq!(
        timeout(
            &backend
                .read_connection
                .lock()
                .expect("restored actual reader")
        ),
        777
    );
    assert_eq!(
        source
            .read_all(1024)
            .expect("ordinary source remains unchanged"),
        b"first"
    );
}

#[test]
fn actual_base_busy_retry_keeps_transaction_and_commits_once_after_release() {
    if isolated("actual_base_busy_retry_keeps_transaction_and_commits_once_after_release") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let foreign = Connection::open(root.path().join(DATABASE_FILE)).expect("foreign writer");
    foreign
        .execute_batch("BEGIN IMMEDIATE")
        .expect("held actual writer lock");
    let attempts = std::cell::Cell::new(0);
    let mut released = false;
    let credit = diagnostic::admit(
        &account,
        backend.maximum_sqlite_heap_bytes,
        Some(root.path()),
    )
    .expect("original copy loan");
    let mut connection = backend.lock_connection().expect("original connection");

    diagnostic::retain_failure(credit, || {
        with_zero(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut || guard.verify(),
            |connection, progress, _| {
                connection
                    .execute_batch("BEGIN DEFERRED")
                    .expect("original admitted transaction");
                progress.began();
                retry(
                    connection,
                    true,
                    &backend.quarantined,
                    &mut || {
                        guard.verify()?;
                        if attempts.get() == 3 && !released {
                            foreign
                                .execute_batch("ROLLBACK")
                                .expect("controlled actual lock release");
                            released = true;
                        }
                        Ok(())
                    },
                    |_| {
                        attempts.set(attempts.get() + 1);
                        connection
                            .execute(
                                "INSERT INTO objects (id, body) VALUES ('component', x'01')",
                                [],
                            )
                            .map_err(|source| database_error("actual-busy-insert", source))
                    },
                )?;
                advance_metadata(connection).expect("one original metadata advance");
                connection
                    .execute_batch("COMMIT")
                    .expect("actual commit after release");
                progress.committed();
                Ok(())
            },
        )
        .and_then(|accepted| accepted.finish(Ok))
    })
    .expect("same original work retries only the blocked statement");
    assert!(released);
    assert_eq!(attempts.get(), 4);
    assert_eq!(load_metadata(&connection).expect("exact generation").1, 2);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, usize>(0))
            .expect("one actual insert"),
        1
    );
    assert_eq!(timeout(&connection), 5000);
    assert!(!backend.quarantined.load(Ordering::Acquire));
}

#[test]
fn successful_body_cannot_acknowledge_rows_that_cleanup_would_roll_back() {
    if isolated("successful_body_cannot_acknowledge_rows_that_cleanup_would_roll_back") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let credit = diagnostic::admit(
        &account,
        backend.maximum_sqlite_heap_bytes,
        Some(root.path()),
    )
    .expect("original loan");
    let mut connection = backend.lock_connection().expect("actual connection");
    let error = diagnostic::retain_failure(credit, || {
        with_zero(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut || guard.verify(),
            |connection, progress, _| {
                connection
                    .execute_batch("BEGIN DEFERRED")
                    .expect("real original transaction");
                progress.began();
                connection
                    .execute(
                        "INSERT INTO objects (id, body) VALUES ('component', x'01')",
                        [],
                    )
                    .expect("staged row");
                Ok(())
            },
        )
        .and_then(|accepted| accepted.finish(Ok))
    })
    .expect_err("uncommitted success cannot become an acknowledged receipt");
    assert_eq!(scope(&error).outcome(), SqliteCommitOutcome::NotCommitted);
    assert!(matches!(
        scope(&error).work_failure(),
        Some(StoreError::Unavailable)
    ));
    assert!(connection.is_autocommit());
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, usize>(0))
            .expect("explicit rollback"),
        0
    );
    assert_eq!(timeout(&connection), 5000);
    assert!(backend.quarantined.load(Ordering::Acquire));
}

#[test]
fn callback_busy_after_metadata_update_is_not_retried_as_sql() {
    if isolated("callback_busy_after_metadata_update_is_not_retried_as_sql") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let credit = diagnostic::admit(
        &account,
        backend.maximum_sqlite_heap_bytes,
        Some(root.path()),
    )
    .expect("original loan");
    let mut connection = backend.lock_connection().expect("actual connection");
    let mut callbacks = 0;
    let error = diagnostic::retain_failure(credit, || {
        with_zero(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut || guard.verify(),
            |connection, progress, _| {
                connection
                    .execute_batch("BEGIN DEFERRED")
                    .expect("real transaction");
                progress.began();
                metadata::advance_with_boundary(
                    connection,
                    &mut || {
                        callbacks += 1;
                        if callbacks == 6 {
                            assert_eq!(
                                load_metadata(connection)
                                    .expect("UPDATE actually completed")
                                    .1,
                                2
                            );
                            Err(database_error(
                                "original-callback-busy",
                                rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(5), None),
                            ))
                        } else {
                            guard.verify()
                        }
                    },
                    &backend.quarantined,
                )
            },
        )
        .and_then(|accepted| accepted.finish(Ok))
    })
    .expect_err("original callback failure cannot repeat the completed UPDATE");
    assert_eq!(callbacks, 6);
    assert_eq!(scope(&error).outcome(), SqliteCommitOutcome::NotCommitted);
    let StoreError::StreamIo { operation, .. } = super::super::tests::original_failure(&error)
    else {
        panic!("original callback cause")
    };
    assert_eq!(*operation, "original-callback-busy");
    assert_eq!(
        load_metadata(&connection)
            .expect("explicit rollback restores metadata")
            .1,
        1
    );
    assert_eq!(timeout(&connection), 5000);
}

#[test]
fn last_quarantine_owner_closes_before_original_backend_credit() {
    if isolated("last_quarantine_owner_closes_before_original_backend_credit") {
        return;
    }

    struct CreditObserver {
        marker: std::sync::Weak<AtomicBool>,
        released: Arc<AtomicBool>,
        _original: crate::owned_decode::ResourceLoan,
    }

    impl Drop for CreditObserver {
        fn drop(&mut self) {
            assert!(
                self.marker.upgrade().is_none(),
                "the shared quarantine payload must close before its original credit"
            );
            self.released.store(true, Ordering::SeqCst);
        }
    }

    for last_owner in ["backend", "source", "reader"] {
        let (_root, guard, mut backend, account) = backend();
        let _scope = account.enter();
        let released = Arc::new(AtomicBool::new(false));
        let original = backend
            .resident_lease
            .take()
            .expect("actual original backend resident loan");
        backend.resident_lease = crate::owned_decode::ResourceLoan::new(CreditObserver {
            marker: Arc::downgrade(&backend.quarantined),
            released: Arc::clone(&released),
            _original: original,
        })
        .into();

        if last_owner == "backend" {
            drop(backend);
        } else {
            let input = super::super::tests::objects();
            backend
                .put_if_absent(input[0].0, &input[0].1)
                .expect("actual singleton publication");
            let source = backend.read(input[0].0, None).expect("actual source");
            if last_owner == "source" {
                drop(backend);
                assert!(!released.load(Ordering::SeqCst));
                drop(source);
            } else {
                let reader = source.open().expect("actual reader");
                drop(backend);
                drop(source);
                assert!(!released.load(Ordering::SeqCst));
                drop(reader);
            }
        }

        assert!(released.load(Ordering::SeqCst));
        drop(_scope);
        drop(account);
        assert_eq!(Arc::strong_count(&guard), 1);
    }
}
