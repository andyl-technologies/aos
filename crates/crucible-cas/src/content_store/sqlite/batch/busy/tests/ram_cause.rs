//! Actual SQL outcome and cleanup owners retained through a cloned RAM failure.

use std::cell::Cell;

use super::*;
use crate::ram::{PreparedRamFailure, RamOperationFailure, RamStoreError};

fn exercise(committed: bool) {
    let (root, guard, backend, account) = backend();
    let entered = account.enter();
    let prepared = PreparedRamFailure::<io::Error>::new(&account).expect("prepaid typed carrier");
    let credit = diagnostic::admit(
        &account,
        backend.maximum_sqlite_heap_bytes,
        Some(root.path()),
    )
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
