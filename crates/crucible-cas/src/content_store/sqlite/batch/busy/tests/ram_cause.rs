//! Actual SQL outcome and cleanup owners retained through a cloned RAM failure.

use std::cell::Cell;

use super::*;
use crate::ram::{PreparedRamFailure, RamOperationFailure, RamStoreError};

#[test]
fn pending_validation_retains_uncertain_sql_and_distinct_outer_failure() {
    if isolated("ram_cause::pending_validation_retains_uncertain_sql_and_distinct_outer_failure") {
        return;
    }
    pending_validation_cleanup(false);
}

#[test]
fn pending_validation_retains_committed_sql_and_distinct_outer_failure() {
    if isolated("ram_cause::pending_validation_retains_committed_sql_and_distinct_outer_failure") {
        return;
    }
    pending_validation_cleanup(true);
}

fn pending_validation_cleanup(committed: bool) {
    let (root, guard, backend, account) = backend();
    let entered = account.enter();
    let diagnostic_credit =
        diagnostic::admit(&account, &backend.connection, Some(root.path())).unwrap();
    let mut connection = backend.lock_connection().unwrap();
    let mut alias = None;
    let error = crate::ram::with_pending_validation_for_test(&account, |seal| {
        let provider = diagnostic::retain_failure(diagnostic_credit, || {
            with_cleanup(
                &account,
                &mut connection,
                &backend.quarantined,
                &mut || Ok(()),
                |connection, progress, _| {
                    connection.execute_batch("BEGIN DEFERRED").unwrap();
                    progress.began();
                    if committed {
                        connection
                            .execute(
                                "INSERT INTO objects (id, body) VALUES ('pending', x'01')",
                                [],
                            )
                            .unwrap();
                        advance_metadata(connection).unwrap();
                        connection.execute_batch("COMMIT").unwrap();
                        progress.committed();
                    }
                    // Validation remains an inline local value until cleanup
                    // has produced the complete actual provider outcome.
                    Err::<(), _>(StoreError::Unavailable)
                },
                |connection| {
                    if committed {
                        connection.execute_batch("ROLLBACK")
                    } else {
                        Err(rusqlite::Error::InvalidQuery)
                    }
                },
                |connection, previous| {
                    if committed {
                        connection.busy_timeout(previous)
                    } else {
                        Err(rusqlite::Error::InvalidQuery)
                    }
                },
            )
            .and_then(|accepted| accepted.finish(Ok))
        })
        .unwrap_err();
        let error = seal(
            RamStoreError::Invalid("pending validation before cleanup"),
            provider,
        );
        let StoreError::RamReadValidation { source } = error else {
            panic!("pure validation remains separate from boundary refusal");
        };
        alias = Some(source);
        Err(StoreError::Quota)
    });
    let StoreError::RamReadContinuation { source } = &error else {
        panic!("outer failure remains distinct and complete");
    };
    assert!(matches!(
        source.first_failure(),
        RamStoreError::Invalid("pending validation before cleanup")
    ));
    assert!(source.first_boundary().is_none());
    assert!(matches!(source.returned_failure(), StoreError::Quota));
    let first = alias.as_ref().unwrap();
    let RamStoreError::Store(provider) = first.storage_failure() else {
        panic!("actual SQL carrier remains owned");
    };
    let sql = scope(provider);
    assert!(matches!(sql.work_failure(), Some(StoreError::Unavailable)));
    if committed {
        assert_eq!(sql.outcome(), SqliteCommitOutcome::Committed);
        assert!(sql.rollback_failure().is_none());
        assert!(sql.restoration_failure().is_none());
        assert!(connection.is_autocommit());
        assert_eq!(timeout(&connection), 5000);
        assert_eq!(load_metadata(&connection).unwrap().1, 2);
    } else {
        assert_eq!(sql.outcome(), SqliteCommitOutcome::Uncertain);
        assert!(sql.rollback_failure().is_some());
        assert!(sql.restoration_failure().is_some());
        assert!(backend.quarantined.load(Ordering::SeqCst));
    }

    drop(connection);
    drop(entered);
    drop(account);
    drop(backend);
    let weak = Arc::downgrade(&guard);
    drop(guard);
    assert!(weak.upgrade().is_some());
    drop(error);
    assert!(
        weak.upgrade().is_some(),
        "the escaped original validation alias retains full SQL custody"
    );
    drop(alias);
    assert!(
        weak.upgrade().is_none(),
        "all original credits and provider outcomes have closed"
    );
}

#[test]
fn failed_work_keeps_first_validation_and_actual_uncertain_sql_cleanup() {
    if isolated("ram_cause::failed_work_keeps_first_validation_and_actual_uncertain_sql_cleanup") {
        return;
    }
    retained_work_cleanup(false);
}

#[test]
fn failed_work_keeps_first_validation_and_actual_committed_sql_outcome() {
    if isolated("ram_cause::failed_work_keeps_first_validation_and_actual_committed_sql_outcome") {
        return;
    }
    retained_work_cleanup(true);
}

fn retained_work_cleanup(committed: bool) {
    let (root, guard, backend, account) = backend();
    let entered = account.enter();
    let diagnostic_credit = diagnostic::admit(&account, &backend.connection, Some(root.path()))
        .expect("unchanged actual SQL diagnostic prepayment");
    let mut connection = backend.lock_connection().expect("actual capped connection");
    let mut first_identity = None;
    let error = crate::ram::with_failed_work_for_test(&account, |fail| {
        diagnostic::retain_failure(diagnostic_credit, || {
            with_cleanup(
                &account,
                &mut connection,
                &backend.quarantined,
                &mut || Ok(()),
                |connection, progress, _| {
                    connection
                        .execute_batch("BEGIN DEFERRED")
                        .expect("actual begin");
                    progress.began();
                    if committed {
                        connection
                            .execute(
                                "INSERT INTO objects (id, body) VALUES ('component', x'01')",
                                [],
                            )
                            .expect("actual insertion");
                        advance_metadata(connection).expect("actual metadata advance");
                        connection.execute_batch("COMMIT").expect("actual commit");
                        progress.committed();
                    }
                    let error = fail(RamStoreError::Invalid("first concrete read validation"));
                    let StoreError::RamValidation { source } = &error else {
                        panic!("a pure validation keeps its category before escaping");
                    };
                    first_identity = Some(source.clone());
                    Err::<(), _>(error)
                },
                |connection| {
                    if committed {
                        connection.execute_batch("ROLLBACK")
                    } else {
                        Err(rusqlite::Error::InvalidQuery)
                    }
                },
                |connection, previous| {
                    if committed {
                        connection.busy_timeout(previous)
                    } else {
                        Err(rusqlite::Error::InvalidQuery)
                    }
                },
            )
            .and_then(|accepted| accepted.finish(Ok))
        })
    });
    let StoreError::RamReadContinuation { source } = &error else {
        panic!("the actual complete SQL owner must remain beside the first error");
    };
    assert!(matches!(
        source.first_failure(),
        RamStoreError::Invalid("first concrete read validation")
    ));
    assert!(source.first_boundary().is_none());
    let sql = scope(source.returned_failure());
    let Some(StoreError::RamValidation { source: sql_first }) = sql.work_failure() else {
        panic!("SQL retains the very same escaped first validation owner");
    };
    assert_eq!(Some(sql_first), first_identity.as_ref());
    if committed {
        assert_eq!(sql.outcome(), SqliteCommitOutcome::Committed);
        assert!(sql.rollback_failure().is_none());
        assert!(sql.restoration_failure().is_none());
        assert_eq!(
            load_metadata(&connection)
                .expect("actual committed generation")
                .1,
            2
        );
        assert!(connection.is_autocommit());
        assert_eq!(timeout(&connection), 5000);
    } else {
        assert_eq!(sql.outcome(), SqliteCommitOutcome::Uncertain);
        assert!(sql.rollback_failure().is_some());
        assert!(sql.restoration_failure().is_some());
        assert!(backend.quarantined.load(Ordering::SeqCst));
    }
    drop(connection);
    drop(entered);
    drop(account);
    drop(backend);
    let weak = Arc::downgrade(&guard);
    drop(guard);
    assert!(
        weak.upgrade().is_some(),
        "the full original SQL bank remains owned"
    );
    drop(error);
    assert!(
        weak.upgrade().is_some(),
        "the escaped first alias retains its own original credit"
    );
    drop(first_identity);
    assert!(
        weak.upgrade().is_none(),
        "all original owners have now closed"
    );
}

fn exercise(committed: bool) {
    let (root, guard, backend, account) = backend();
    let entered = account.enter();
    let prepared = PreparedRamFailure::<io::Error>::new(&account).expect("prepaid typed carrier");
    let credit = diagnostic::admit(&account, &backend.connection, Some(root.path()))
        .expect("actual diagnostic copy loan");
    let mut connection = backend.lock_connection().expect("actual capped connection");
    let started = Cell::new(false);
    let calls = Cell::new(0);

    let error = prepared
        .run(
            &mut || {
                calls.set(calls.get() + 1);
                if started.get() {
                    Err(io::Error::from_raw_os_error(7))
                } else {
                    Ok(())
                }
            },
            |ram_boundary| {
                diagnostic::retain_failure(credit, || {
                    with_cleanup(
                        &account,
                        &mut connection,
                        &backend.quarantined,
                        &mut || ram_boundary().map_err(|_| StoreError::Unavailable),
                        |connection, progress, boundary| {
                            connection.execute_batch("BEGIN DEFERRED").expect("actual begin");
                            progress.began();
                            if committed {
                                connection
                                    .execute("INSERT INTO objects (id, body) VALUES ('component', x'01')", [])
                                    .expect("actual mutation");
                                advance_metadata(connection).expect("actual generation");
                                connection.execute_batch("COMMIT").expect("actual commit");
                                progress.committed();
                            }
                            started.set(true);
                            let first = boundary();
                            assert!(boundary().is_err(), "repeat poll remains refused");
                            first
                        },
                        |connection| {
                            if committed {
                                connection.execute_batch("ROLLBACK")
                            } else {
                                Err(rusqlite::Error::InvalidQuery)
                            }
                        },
                        |connection, previous| {
                            if committed {
                                connection.busy_timeout(previous)
                            } else {
                                Err(rusqlite::Error::InvalidQuery)
                            }
                        },
                    )
                    .and_then(|accepted| accepted.finish(Ok))
                })
                .map_err(RamStoreError::from)
            },
        )
        .expect_err("first refusal retains complete observed SQL outcome");

    let RamOperationFailure::Retained(cause) = error else {
        panic!("complete SQL outcome was discarded");
    };
    assert_eq!(
        calls.get(),
        3,
        "both original preparation polls and only the first refusal"
    );
    assert_eq!(
        cause.first_boundary().and_then(io::Error::raw_os_error),
        Some(7)
    );
    let RamStoreError::Store(storage) = cause.storage_failure() else {
        panic!("original SQL owner remains typed");
    };
    let failure = scope(storage);
    assert!(matches!(
        failure.work_failure(),
        Some(StoreError::Unavailable)
    ));
    if committed {
        assert_eq!(failure.outcome(), SqliteCommitOutcome::Committed);
        assert!(failure.rollback_failure().is_none());
        assert!(failure.restoration_failure().is_none());
        assert_eq!(load_metadata(&connection).expect("durable generation").1, 2);
        assert!(connection.is_autocommit());
        assert_eq!(timeout(&connection), 5000);
    } else {
        assert_eq!(failure.outcome(), SqliteCommitOutcome::Uncertain);
        assert!(matches!(
            failure.rollback_failure(),
            Some(rusqlite::Error::InvalidQuery)
        ));
        assert!(matches!(
            failure.restoration_failure(),
            Some(rusqlite::Error::InvalidQuery)
        ));
        assert!(backend.quarantined.load(Ordering::Acquire));
    }

    let clone = cause.clone();
    drop(connection);
    drop(entered);
    drop(account);
    drop(backend);
    let weak = Arc::downgrade(&guard);
    drop(guard);
    drop(cause);
    assert!(
        weak.upgrade().is_some(),
        "last clone retains actual SQL bank"
    );
    drop(clone);
    assert!(
        weak.upgrade().is_none(),
        "all original SQL owners close last"
    );
}

#[test]
fn retains_actual_commit_and_diagnostic_owner() {
    if isolated("ram_cause::retains_actual_commit_and_diagnostic_owner") {
        return;
    }
    exercise(true);
}

#[test]
fn retains_dual_cleanup_failure_and_uncertain_outcome() {
    if isolated("ram_cause::retains_dual_cleanup_failure_and_uncertain_outcome") {
        return;
    }
    exercise(false);
}
