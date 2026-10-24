//! Checked SQLite diagnostic preloan, typed causes and last-owner lifetime.

use super::*;

fn isolated(name: &str) -> bool {
    isolated_heap_test(&format!(
        "content_store::sqlite::batch::tests::diagnostic::{name}"
    ))
}

#[test]
fn ordinary_backend_retains_its_genuine_heap_bound_for_checked_diagnostics() {
    if isolated("ordinary_backend_retains_its_genuine_heap_bound_for_checked_diagnostics") {
        return;
    }
    let root = tempfile::tempdir().expect("ordinary catalog");
    let heap =
        crate::content_store::fixture_sqlite_heap().expect("same authored fixture process heap");
    let backend = SqliteBlobBackend::open("ordinary", root.path(), &heap)
        .expect("same heap ordinary catalog");
    assert_eq!(
        backend.connection.maximum_heap_bytes(),
        heap.maximum_heap_bytes()
    );

    let guard = original_quota();
    let account = DecodeBudget::for_store(guard.clone()).expect("original diagnostic account");
    let inputs = objects();
    backend
        .put_many_if_absent_with_boundary(&account, &inputs, &mut || guard.verify())
        .expect("actual finite heap admits checked diagnostics");
    let source = backend
        .read(inputs[0].0, None)
        .expect("actual stored source");
    assert_eq!(
        &*source
            .read_all_with_boundary(&account, 1024, &mut || guard.verify())
            .expect("same bound reaches checked source"),
        b"first"
    );

    backend
        .put_many_if_absent(&inputs)
        .expect("ordinary batch remains available");
    backend
        .put_if_absent(inputs[0].0, &inputs[0].1)
        .expect("ordinary singleton remains available");
    assert_eq!(
        source
            .read_all(1024)
            .expect("ordinary source remains available"),
        b"first"
    );
}

#[test]
fn diagnostic_admission_precedes_sql_and_inventory_path_allocation() {
    if isolated("diagnostic_admission_precedes_sql_and_inventory_path_allocation") {
        return;
    }
    let root = tempfile::tempdir().expect("private catalog");
    let guard = original_quota();
    let backend = bounded_leaf("same-origin", root.path(), &guard);
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let before = guard.0.used.load(Ordering::SeqCst);
    let blocker = guard
        .reserve_resources(0, guard.0.maximum - before - 1024)
        .expect("leave enough for empty receipts, not a diagnostic copy");
    let inventory = backend
        .acquire_inventory_lock()
        .expect("hold actual writer fence");
    let mut calls = 0;

    let error = backend
        .put_many_if_absent_with_boundary(&account, &[], &mut || {
            calls += 1;
            if calls > 16 {
                Err(expired())
            } else {
                guard.verify()
            }
        })
        .expect_err("preloan refusal occurs before waiting on held inventory");
    assert!(calls < 16);
    let StoreError::DecodeAdmission { source, custody } = error else {
        panic!("initial preloan returns inline original admission cause");
    };
    assert!(custody.is_some());
    assert!(matches!(
        std::error::Error::source(&source).and_then(|cause| cause.downcast_ref::<StoreError>()),
        Some(StoreError::Quota)
    ));
    drop(blocker);
    drop(inventory);
    assert_eq!(
        load_metadata(&backend.lock_connection().expect("same connection"))
            .expect("unchanged metadata")
            .1,
        1
    );
}

#[test]
fn typed_sqlite_error_retains_its_actual_preloan_until_last_drop() {
    if isolated("typed_sqlite_error_retains_its_actual_preloan_until_last_drop") {
        return;
    }
    let root = tempfile::tempdir().expect("private catalog");
    let guard = original_quota();
    let backend = bounded_leaf("same-origin", root.path(), &guard);
    backend
        .lock_connection()
        .expect("test-only malformed metadata")
        .execute("UPDATE metadata SET instance = 'wrong-type'", [])
        .expect("malformed type");
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let scope = account.enter();
    let baseline = guard.0.used.load(Ordering::SeqCst);

    let error = backend
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || guard.verify())
        .expect_err("real metadata decoder preserves original typed SQLite error");
    let StoreError::SqliteDiagnostic { source } = &error else {
        panic!("retained checked diagnostic");
    };
    let StoreError::StreamIo { source: io, .. } = original_failure(source.failure()) else {
        panic!("original database error carrier");
    };
    assert!(
        matches!(io.get_ref().and_then(|cause| cause.downcast_ref::<rusqlite::Error>()),
        Some(rusqlite::Error::InvalidColumnType(0, name, _)) if name == "instance")
    );
    assert!(guard.0.used.load(Ordering::SeqCst) >= baseline + 48 * 1024 * 1024);
    assert_eq!(
        backend
            .lock_connection()
            .expect("original connection after rollback")
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, usize>(0))
            .expect("row count"),
        0
    );

    drop(scope);
    drop(account);
    drop(backend);
    let owner = Arc::clone(&guard.0);
    let weak = Arc::downgrade(&guard);
    drop(guard);
    assert!(
        weak.upgrade().is_some(),
        "retained error owns original authority"
    );
    assert!(owner.used.load(Ordering::SeqCst) >= 48 * 1024 * 1024);
    drop(error);
    assert!(weak.upgrade().is_none());
    assert_eq!(owner.used.load(Ordering::SeqCst), 0);
}

#[test]
fn hostile_schema_message_and_inventory_path_failure_keep_diagnostic_custody() {
    if isolated("hostile_schema_message_and_inventory_path_failure_keep_diagnostic_custody") {
        return;
    }
    let root = tempfile::tempdir().expect("private catalog");
    let guard = original_quota();
    let backend = bounded_leaf("same-origin", root.path(), &guard);
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let _scope = account.enter();
    let baseline = guard.0.used.load(Ordering::SeqCst);
    {
        let connection = backend
            .lock_connection()
            .expect("test-only schema corruption");
        connection
            .execute_batch("PRAGMA writable_schema=ON")
            .expect("test-only mutable schema");
        let name = "hostile".repeat(4096);
        connection
            .execute(
                "UPDATE sqlite_schema SET name = ?1, sql = 'not valid SQL' WHERE name = 'objects'",
                [&name],
            )
            .expect("hostile retained schema name");
        connection
            .execute_batch("PRAGMA writable_schema=OFF; PRAGMA schema_version=42;")
            .expect("force genuine schema reload");
    }
    let error = backend
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || guard.verify())
        .expect_err("actual binding copies hostile schema message only after preloan");
    let StoreError::StreamIo { source, .. } = original_failure(&error) else {
        panic!("original SQLite cause");
    };
    let Some(rusqlite::Error::SqliteFailure(_, Some(message))) = source
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<rusqlite::Error>())
    else {
        panic!("actual SQLite schema diagnostic");
    };
    assert!(message.len() >= 4096);
    assert!(guard.0.used.load(Ordering::SeqCst) >= baseline + 48 * 1024 * 1024);
    drop(error);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);

    std::fs::remove_file(root.path().join(LOCK_FILE)).expect("test-only remove fence name");
    let error = backend
        .put_many_if_absent_with_boundary(&account, &[], &mut || guard.verify())
        .expect_err("actual inventory open failure");
    assert!(
        matches!(original_failure(&error), StoreError::Io { path, .. } if path == &root.path().join(LOCK_FILE))
    );
    assert!(guard.0.used.load(Ordering::SeqCst) >= baseline + 48 * 1024 * 1024);
    drop(error);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), baseline);
}

#[test]
fn checked_sqlite_source_error_retains_original_credit_to_last_owner() {
    if isolated("checked_sqlite_source_error_retains_original_credit_to_last_owner") {
        return;
    }
    let root = tempfile::tempdir().expect("private catalog");
    let guard = original_quota();
    let backend = bounded_leaf("same-origin", root.path(), &guard);
    let inputs = objects();
    backend
        .put_if_absent(inputs[0].0, &inputs[0].1)
        .expect("ordinary publication");
    let source = backend
        .read(inputs[0].0, None)
        .expect("actual leased source");
    backend
        .lock_connection()
        .expect("test-only type corruption")
        .execute("UPDATE objects SET body = 'first'", [])
        .expect("same length, wrong column type");
    let account = DecodeBudget::for_store(guard.clone()).expect("original account");
    let scope = account.enter();
    let baseline = guard.0.used.load(Ordering::SeqCst);

    let error = source
        .read_all_with_boundary(&account, 1024, &mut || guard.verify())
        .expect_err("binding source error remains typed and prepaid");
    let StoreError::StreamIo { source: io, .. } = original_failure(&error) else {
        panic!("original database source error");
    };
    assert!(matches!(
        io.get_ref()
            .and_then(|cause| cause.downcast_ref::<rusqlite::Error>()),
        Some(rusqlite::Error::InvalidColumnType(0, _, _))
    ));
    assert!(guard.0.used.load(Ordering::SeqCst) >= baseline + 48 * 1024 * 1024);

    drop(scope);
    drop(account);
    drop(source);
    drop(backend);
    let owner = Arc::clone(&guard.0);
    let weak = Arc::downgrade(&guard);
    drop(guard);
    assert!(weak.upgrade().is_some());
    drop(error);
    assert!(weak.upgrade().is_none());
    assert_eq!(owner.used.load(Ordering::SeqCst), 0);
}
