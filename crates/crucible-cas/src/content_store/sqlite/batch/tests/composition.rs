//! Main-derived original verification and retained error classification proofs.

use super::*;
use crate::content_store::sqlite::batch::diagnostic as retained_diagnostic;

#[test]
fn live_verification_uses_the_stored_guard_without_new_credit() {
    let guard = original_quota();
    let account = DecodeBudget::for_store(guard.clone()).expect("original finite bank");
    let _scope = account.enter();
    let used = guard.0.used.load(Ordering::SeqCst);
    let checks = guard.0.checks.load(Ordering::SeqCst);

    crate::content_store::batch::account().expect("same original live guard");
    assert_eq!(guard.0.used.load(Ordering::SeqCst), used);
    assert_eq!(guard.0.checks.load(Ordering::SeqCst), checks + 1);

    guard.0.revoked.store(true, Ordering::SeqCst);
    let Err(error) = crate::content_store::batch::account() else {
        panic!("revoked actual origin must refuse");
    };
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert_eq!(guard.0.used.load(Ordering::SeqCst), used);
    drop(error);

    guard.0.revoked.store(false, Ordering::SeqCst);
    account
        .verify_live()
        .expect("verification added no sticky refusal");
}

#[test]
fn live_verification_preserves_earlier_sticky_refusal_before_guard_revocation() {
    let guard = original_quota();
    let account = DecodeBudget::for_store(guard.clone()).expect("original finite bank");
    let _scope = account.enter();
    let Err(original) = account.reserve_scratch_bytes(guard.0.maximum) else {
        panic!("whole-bank request must refuse existing account overhead");
    };
    guard.0.revoked.store(true, Ordering::SeqCst);
    let checks = guard.0.checks.load(Ordering::SeqCst);

    let Err(error) = crate::content_store::batch::account() else {
        panic!("original sticky cause must win");
    };
    let StoreError::DecodeAdmission { source, .. } = &error else {
        panic!("original typed account refusal must remain admitted failure");
    };
    assert_eq!(source, &original);
    assert_eq!(guard.0.checks.load(Ordering::SeqCst), checks);
}

#[test]
fn checked_output_refuses_origin_revoked_at_eof_and_releases_raw_copy() {
    let guard = original_quota();
    let account = DecodeBudget::for_store(guard.clone()).expect("original finite bank");
    let _scope = account.enter();
    let used = guard.0.used.load(Ordering::SeqCst);
    let mut read_calls = 0;

    let Err(error) = crate::content_store::batch::read_reader_under(
        &account,
        &account,
        1,
        1,
        &mut || Ok(()),
        &mut |output, _| {
            read_calls += 1;
            if read_calls == 1 {
                output[0] = 7;
                Ok(1)
            } else {
                guard.0.revoked.store(true, Ordering::SeqCst);
                Ok(0)
            }
        },
    ) else {
        panic!("EOF cannot accept output after the real origin closes");
    };

    assert_eq!(read_calls, 2);
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert_eq!(guard.0.used.load(Ordering::SeqCst), used);
    guard.0.revoked.store(false, Ordering::SeqCst);
    account
        .verify_live()
        .expect("same original account remains healthy");
}

#[test]
fn quota_after_actual_commit_keeps_typed_category_and_diagnostic_credit() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::composition::quota_after_actual_commit_keeps_typed_category_and_diagnostic_credit",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("private component catalog");
    let guard = original_quota();
    let backend = bounded_leaf("original", root.path(), &guard);
    let account = DecodeBudget::for_store(guard.clone()).expect("original finite bank");
    let _scope = account.enter();
    let baseline = guard.0.used.load(Ordering::SeqCst);
    let credit = retained_diagnostic::admit(&account, &backend.connection, Some(root.path()))
        .expect("original diagnostic preloan");
    let mut connection = backend.lock_connection().expect("actual connection");

    let error = retained_diagnostic::retain_failure(credit, || {
        let accepted = busy::with_zero(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut || guard.verify(),
            |connection, progress, _| {
                connection.execute_batch("BEGIN DEFERRED").expect("begin");
                progress.began();
                connection
                    .execute(
                        "INSERT INTO objects (id, body) VALUES ('component', x'01')",
                        [],
                    )
                    .expect("actual mutation");
                advance_metadata(connection).expect("actual generation");
                connection.execute_batch("COMMIT").expect("actual commit");
                progress.committed();
                Ok(())
            },
        )?;
        accepted.finish(|()| {
            let used = guard.0.used.load(Ordering::SeqCst);
            let _competitor = guard.reserve_resources(0, guard.0.maximum - used - 1024)?;
            account
                .reserve_scratch_bytes(2048)
                .map_err(|error| admission_under(&account, error))
                .map(|_| ())
        })
    })
    .expect_err("genuine original bank refuses final capacity");

    assert!(matches!(error.original_failure(), StoreError::Quota));
    let StoreError::SqliteDiagnostic { source } = &error else {
        panic!("diagnostic owner remains retained");
    };
    let StoreError::SqliteScope { source } = source.failure() else {
        panic!("scope outcome remains retained");
    };
    assert_eq!(source.outcome(), busy::SqliteCommitOutcome::Committed);
    assert!(source.rollback_failure().is_none());
    assert!(source.restoration_failure().is_none());
    assert_eq!(load_metadata(&connection).expect("durable generation").1, 2);
    assert!(guard.0.used.load(Ordering::SeqCst) >= baseline + 48 * 1024 * 1024);

    drop(connection);
    drop(error);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
    guard
        .reserve_resources(0, 2048)
        .expect("same physical credit reusable");
}
