//! Actual native preparation counts, original refusal and rollback for batches.

use super::*;
use crate::content_store::sqlite::batch::write_statements;

#[test]
fn checked_batch_prepares_each_statement_once_and_keeps_duplicate_authentication() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::statement_reuse::checked_batch_prepares_each_statement_once_and_keeps_duplicate_authentication",
    ) {
        return;
    }
    let directory = tempfile::tempdir().expect("isolated statement catalog directory");
    let guard = original_quota();
    let backend = bounded_leaf("reused-statements", directory.path(), &guard);
    let original = DecodeBudget::for_store(guard.clone()).expect("same original metadata bank");
    let inputs = objects();
    let baseline = guard.0.used.load(Ordering::SeqCst);

    watch_statement_credit(&guard);
    let receipts = backend
        .put_many_if_absent_with_boundary(&original, &inputs, &mut || {
            verify_open_statement_credit(&guard)
        })
        .expect("actual checked batch operation");
    assert_eq!(write_statements::preparations(), [1, 1, 2, 1]);
    assert_eq!(receipts.iter().count(), inputs.len());
    assert_statement_credit_closed(&guard);
    drop(receipts);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);

    watch_statement_credit(&guard);
    let receipts = backend
        .put_many_if_absent_with_boundary(&original, &inputs, &mut || {
            verify_open_statement_credit(&guard)
        })
        .expect("actual checked batch operation");
    assert_eq!(write_statements::preparations(), [1, 0, 0, 1]);
    assert_statement_credit_closed(&guard);
    drop(receipts);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);

    // Presence remains only a hint: authenticate the actual stored duplicate.
    {
        let connection = backend
            .connection
            .lock()
            .expect("same managed catalog connection");
        let id = inputs[0].0;
        with_id_text(id, |encoded| {
            connection
                .execute(
                    "UPDATE objects SET body = ?2 WHERE id = ?1",
                    params![encoded, b"wrong".as_slice()],
                )
                .expect("actual checked batch operation");
            Ok(())
        })
        .expect("actual checked batch operation");
    }
    watch_statement_credit(&guard);
    let error = backend
        .put_many_if_absent_with_boundary(&original, &inputs, &mut || {
            verify_open_statement_credit(&guard)
        })
        .expect_err("actual checked refusal");
    assert!(matches!(original_failure(&error), StoreError::Corrupt { id } if *id == inputs[0].0));
    assert_eq!(write_statements::preparations(), [1, 0, 0, 1]);
    assert_statement_credit_closed(&guard);
    drop(error);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
}

#[test]
fn original_control_refusal_precedes_the_first_native_prepare() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::statement_reuse::original_control_refusal_precedes_the_first_native_prepare",
    ) {
        return;
    }
    let directory = tempfile::tempdir().expect("isolated statement catalog directory");
    let guard = original_quota();
    let backend = bounded_leaf("statement-control-refusal", directory.path(), &guard);
    let original = DecodeBudget::for_store(guard.clone()).expect("same original metadata bank");
    let input = objects().remove(0);
    let bytes = read_source(&original, &input.1, MAX_BATCH_BYTES, &mut || {
        verify_open_statement_credit(&guard)
    })
    .expect("actual checked batch operation");
    let staged = [(input.0, bytes)];
    let connection = backend
        .connection
        .lock()
        .expect("same managed catalog connection");
    let _diagnostic =
        super::super::diagnostic::admit(&original, &backend.connection, Some(&backend.root))
            .expect("actual checked batch operation");
    let available = guard.0.maximum - guard.0.used.load(Ordering::SeqCst);
    let held = original
        .reserve_scratch_bytes(available)
        .expect("actual checked batch operation");

    watch_statement_credit(&guard);
    let error = write_statements::stage(
        &connection,
        &staged,
        &original,
        &backend.quarantined,
        &mut || Ok(()),
    )
    .expect_err("actual checked refusal");

    assert_eq!(write_statements::preparations(), [0, 0, 0, 0]);
    assert_eq!(
        guard.0.last_refused_bytes.load(Ordering::SeqCst),
        write_statements::control_bytes().expect("target-sized fixed statement control")
    );
    assert!(matches!(error, StoreError::DecodeAdmission { .. }));
    assert!(connection.is_autocommit());
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, u64>(0))
            .expect("actual statement fixture"),
        0
    );
    drop((error, held));
}

#[test]
fn refusal_after_one_actual_insert_rolls_back_before_any_receipt() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::statement_reuse::refusal_after_one_actual_insert_rolls_back_before_any_receipt",
    ) {
        return;
    }
    let directory = tempfile::tempdir().expect("isolated statement catalog directory");
    let guard = original_quota();
    let backend = bounded_leaf("statement-rollback", directory.path(), &guard);
    let original = DecodeBudget::for_store(guard.clone()).expect("same original metadata bank");
    let inputs = objects();
    let baseline = guard.0.used.load(Ordering::SeqCst);
    let generation = load_metadata(
        &backend
            .connection
            .lock()
            .expect("same managed catalog connection"),
    )
    .expect("actual statement fixture")
    .1;
    watch_statement_credit(&guard);

    let error = backend
        .put_many_if_absent_with_boundary(&original, &inputs, &mut || {
            if write_statements::preparations()[2] == 1 {
                Err(expired())
            } else {
                verify_open_statement_credit(&guard)
            }
        })
        .expect_err("actual checked refusal");

    assert_eq!(write_statements::preparations(), [1, 1, 1, 1]);
    assert_statement_credit_closed(&guard);
    assert_expired(error);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
    let connection = backend
        .connection
        .lock()
        .expect("same managed catalog connection");
    assert!(connection.is_autocommit());
    assert_eq!(
        load_metadata(&connection)
            .expect("actual statement fixture")
            .1,
        generation
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, u64>(0))
            .expect("actual statement fixture"),
        0
    );
    drop(connection);

    watch_statement_credit(&guard);
    let receipts = backend
        .put_many_if_absent_with_boundary(&original, &inputs, &mut || {
            verify_open_statement_credit(&guard)
        })
        .expect("actual checked batch operation");
    assert_eq!(write_statements::preparations(), [1, 1, 2, 1]);
    assert_statement_credit_closed(&guard);
    drop(receipts);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
}

#[test]
fn native_insert_failure_keeps_typed_cause_and_closes_statements_before_rollback() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::statement_reuse::native_insert_failure_keeps_typed_cause_and_closes_statements_before_rollback",
    ) {
        return;
    }
    let directory = tempfile::tempdir().expect("native failure catalog");
    let guard = original_quota();
    let backend = bounded_leaf("statement-native-failure", directory.path(), &guard);
    let original = DecodeBudget::for_store(guard.clone()).expect("same original bank");
    let inputs = objects();
    let baseline = guard.0.used.load(Ordering::SeqCst);
    let generation = {
        let connection = backend.connection.lock().expect("same managed connection");
        // A fixed fixture trigger produces a real SQLite step error. It is not
        // a production schema, injected StoreError or arbitrary diagnostic text.
        connection
            .execute_batch(
                "CREATE TRIGGER reject_statement_insert BEFORE INSERT ON objects \
             BEGIN SELECT RAISE(ABORT, 'statement-reuse-native-refusal'); END;",
            )
            .expect("fixed native refusal trigger");
        load_metadata(&connection).expect("existing generation").1
    };
    watch_statement_credit(&guard);

    let error = backend
        .put_many_if_absent_with_boundary(&original, &inputs, &mut || {
            verify_open_statement_credit(&guard)
        })
        .expect_err("actual native INSERT refuses before any receipt");

    assert_eq!(write_statements::preparations(), [1, 1, 0, 1]);
    assert_statement_credit_closed(&guard);
    let StoreError::StreamIo { operation, source } = original_failure(&error) else {
        panic!("retain the actual native step failure: {error:?}");
    };
    assert_eq!(*operation, "stage-sqlite-batch-object");
    let native = source
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<rusqlite::Error>())
        .expect("typed rusqlite failure remains owned");
    assert!(
        matches!(native, rusqlite::Error::SqliteFailure(code, Some(message))
        if code.extended_code == 1811 && message == "statement-reuse-native-refusal")
    );
    let scope = match &error {
        StoreError::SqliteDiagnostic { source } => source.failure(),
        other => other,
    };
    let StoreError::SqliteScope { source } = scope else {
        panic!("retain checked transaction cleanup: {scope:?}");
    };
    assert_eq!(source.outcome(), busy::SqliteCommitOutcome::NotCommitted);
    assert!(source.rollback_failure().is_none());
    assert!(source.restoration_failure().is_none());
    drop(error);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);

    {
        let connection = backend.connection.lock().expect("same closed connection");
        assert!(connection.is_autocommit());
        assert_eq!(
            load_metadata(&connection)
                .expect("unpublished generation")
                .1,
            generation
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                    .get::<_, u64>(0))
                .expect("actual rollback inventory"),
            0
        );
        connection
            .execute_batch("DROP TRIGGER reject_statement_insert;")
            .expect("remove only fixed test trigger");
    }

    watch_statement_credit(&guard);
    let receipts = backend
        .put_many_if_absent_with_boundary(&original, &inputs, &mut || {
            verify_open_statement_credit(&guard)
        })
        .expect("same managed connection succeeds after actual step/reset/rollback");
    assert_eq!(write_statements::preparations(), [1, 1, 2, 1]);
    assert_statement_credit_closed(&guard);
    drop(receipts);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
}

fn watch_statement_credit(guard: &Quota) {
    write_statements::reset_preparations();
    guard.0.watched_loan_bytes.store(
        write_statements::control_bytes().expect("target-sized statement control"),
        Ordering::SeqCst,
    );
    guard.0.watched_loan_closed.store(false, Ordering::SeqCst);
}

fn verify_open_statement_credit(guard: &Quota) -> Result<(), StoreError> {
    let [presence, _, _, closed] = write_statements::preparations();
    if presence > 0 && closed == 0 {
        assert!(
            !guard.0.watched_loan_closed.load(Ordering::SeqCst),
            "same original control loan must outlive active native statements"
        );
    }
    guard.verify()
}

fn assert_statement_credit_closed(guard: &Quota) {
    assert!(
        guard.0.watched_loan_closed.load(Ordering::SeqCst),
        "actual loan Drop follows native handle fields on success or failure"
    );
}
