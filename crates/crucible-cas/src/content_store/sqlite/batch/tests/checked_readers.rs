//! Real checked SQL reader state, deferred ownership and original-boundary tests.

use super::*;

fn isolated(name: &str) -> bool {
    isolated_heap_test(name)
}

fn catalog(root: &Path, guard: &Arc<Quota>) -> Arc<dyn ImmutableBlobBackend> {
    SqliteBlobBackend::open_with_physical_quota(
        "checked-reader",
        root,
        guard.clone(),
        8 * 1024 * 1024,
        Arc::new(Supervisor(guard.clone())),
        &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
    )
    .expect("finite component catalog")
}

#[test]
fn deferred_source_and_reader_keep_original_after_facade_and_scope_drop() {
    if isolated(
        "content_store::sqlite::batch::tests::checked_readers::deferred_source_and_reader_keep_original_after_facade_and_scope_drop",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("component root");
    let guard = original_quota();
    let backend = catalog(root.path(), &guard);
    let bytes = vec![0x5a; 128 * 1024 + 19];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
        .expect("seed");
    let account = DecodeBudget::for_store(guard.clone()).expect("original");
    let scope = account.enter();
    let source = backend
        .read_with_boundary(&account, id, None, &mut || guard.verify())
        .expect("checked metadata");
    drop(scope);
    drop(account);
    drop(backend);

    let caller_guard = original_quota();
    let caller = DecodeBudget::for_store(caller_guard).expect("independent current caller");
    let caller_scope = caller.enter();
    let starts = guard.0.starts.load(Ordering::SeqCst);
    let operation = Supervisor(guard.clone())
        .begin(SqliteCatalogOperationKind::Read)
        .expect("one original read guard");
    let mut reader = source
        .open_with_boundary(&mut || operation.check())
        .expect("saved original deferred open");
    drop(source);
    let mut observed = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let count = reader
            .read_with_boundary(&mut buffer, &mut || operation.check())
            .expect("same finite read");
        if count == 0 {
            break;
        }
        observed.extend_from_slice(&buffer[..count]);
    }
    operation
        .complete()
        .expect("complete the same original guard");
    assert_eq!(observed, bytes);
    assert_eq!(
        guard.0.starts.load(Ordering::SeqCst),
        starts + 1,
        "one read operation, not per chunk"
    );
    assert!(guard.0.used.load(Ordering::SeqCst) > 0);
    drop(reader);
    drop(caller_scope);
    drop(caller);
    assert_eq!(
        guard.0.used.load(Ordering::SeqCst),
        0,
        "last reader closes source and credits"
    );
    assert!(guard.0.peak.load(Ordering::SeqCst) <= guard.0.maximum);
}

#[test]
fn late_eof_failure_is_sticky_and_owns_diagnostic_until_error_drop() {
    if isolated(
        "content_store::sqlite::batch::tests::checked_readers::late_eof_failure_is_sticky_and_owns_diagnostic_until_error_drop",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("component root");
    let guard = original_quota();
    let backend = catalog(root.path(), &guard);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"");
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(b""))
        .expect("seed");
    let account = DecodeBudget::for_store(guard.clone()).expect("original");
    let scope = account.enter();
    let source = backend
        .read_with_boundary(&account, id, None, &mut || Ok(()))
        .expect("metadata");
    let mut reader = source.open_with_boundary(&mut || Ok(())).expect("reader");
    let mut calls = 0;
    // Determine the genuine nonempty EOF path's terminal boundary, then use
    // an independent reader to refuse that exact last transition.
    reader
        .read_with_boundary(&mut [0; 1], &mut || {
            calls += 1;
            Ok(())
        })
        .expect("EOF oracle");
    drop(reader);
    let mut reader = source
        .open_with_boundary(&mut || Ok(()))
        .expect("independent reader");
    let mut seen = 0;
    let error = reader
        .read_with_boundary(&mut [0; 1], &mut || {
            seen += 1;
            if seen == calls {
                Err(expired())
            } else {
                Ok(())
            }
        })
        .expect_err("last EOF poll refuses");
    assert!(matches!(
        original_failure(&error),
        StoreError::Supervision { .. }
    ));
    assert!(
        reader
            .read_with_boundary(&mut [0; 1], &mut || Ok(()))
            .is_err(),
        "expiry cannot reset authentication"
    );
    drop(reader);
    drop(source);
    drop(backend);
    drop(scope);
    drop(account);
    assert!(
        guard.0.used.load(Ordering::SeqCst) >= 48 * 1024 * 1024,
        "error retains original bank"
    );
    drop(error);
    assert_eq!(guard.0.used.load(Ordering::SeqCst), 0);
}

#[test]
fn ranged_eof_authenticates_hidden_suffix_and_empty_output_does_not_finish() {
    if isolated(
        "content_store::sqlite::batch::tests::checked_readers::ranged_eof_authenticates_hidden_suffix_and_empty_output_does_not_finish",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("component root");
    let guard = original_quota();
    let backend = bounded_leaf("checked-range", root.path(), &guard);
    let bytes = vec![3; 3 * 64 * 1024 + 7];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
        .expect("seed");
    let account = DecodeBudget::for_store(guard.clone()).expect("original");
    let scope = account.enter();
    let source = backend
        .read_with_boundary(
            &account,
            id,
            Some(ByteRange {
                offset: 64 * 1024,
                length: 11,
            }),
            &mut || Ok(()),
        )
        .expect("range");
    let mut reader = source.open_with_boundary(&mut || Ok(())).expect("reader");
    assert_eq!(
        reader
            .read_with_boundary(&mut [], &mut || Ok(()))
            .expect("empty buffer"),
        0
    );
    let mut output = [0; 11];
    assert_eq!(
        reader
            .read_with_boundary(&mut output, &mut || Ok(()))
            .expect("range bytes"),
        11
    );
    assert_eq!(output, [3; 11]);
    let mut corrupt = bytes;
    *corrupt.last_mut().expect("nonempty") = 4;
    backend
        .lock_connection()
        .expect("inject suffix corruption")
        .execute(
            "UPDATE objects SET body = ?1 WHERE id = ?2",
            params![corrupt, id.encode()],
        )
        .expect("corrupt suffix");
    let error = reader
        .read_with_boundary(&mut [0; 1], &mut || Ok(()))
        .expect_err("suffix digest refusal");
    assert!(
        matches!(original_failure(&error), StoreError::Corrupt { id: rejected } if *rejected == id)
    );
    drop(error);
    drop(reader);
    drop(source);
    drop(scope);
}

#[test]
fn metadata_and_chunk_foreign_connection_waits_poll_same_original() {
    if isolated(
        "content_store::sqlite::batch::tests::checked_readers::metadata_and_chunk_foreign_connection_waits_poll_same_original",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("component root");
    let guard = original_quota();
    let backend = bounded_leaf("checked-wait", root.path(), &guard);
    let bytes = vec![7; 64 * 1024 + 1];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes))
        .expect("seed");
    let account = DecodeBudget::for_store(guard.clone()).expect("original");
    let _scope = account.enter();
    let source = backend
        .read_with_boundary(&account, id, None, &mut || Ok(()))
        .expect("metadata");
    let lock = backend
        .read_connection
        .lock()
        .expect("foreign connection holder");
    let mut polls = 0;
    let error = match backend.read_with_boundary(&account, id, None, &mut || {
        polls += 1;
        if polls == 32 { Err(expired()) } else { Ok(()) }
    }) {
        Err(error) => error,
        Ok(_) => panic!("held metadata connection must refuse"),
    };
    assert_expired(error);
    assert_eq!(polls, 32);
    drop(lock);
    let mut reader = source.open_with_boundary(&mut || Ok(())).expect("reader");
    let lock = backend
        .read_connection
        .lock()
        .expect("foreign chunk holder");
    polls = 0;
    let error = reader
        .read_with_boundary(&mut [0; 4096], &mut || {
            polls += 1;
            if polls == 32 { Err(expired()) } else { Ok(()) }
        })
        .expect_err("held chunk connection must refuse");
    assert_expired(error);
    drop(lock);
    assert!(
        reader
            .read_with_boundary(&mut [0; 1], &mut || Ok(()))
            .is_err()
    );
    assert_eq!(polls, 32);
}

#[test]
fn foreign_sql_lock_refuses_metadata_and_chunks_and_restores_timeout() {
    if isolated(
        "content_store::sqlite::batch::tests::checked_readers::foreign_sql_lock_refuses_metadata_and_chunks_and_restores_timeout",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("component root");
    let guard = original_quota();
    let backend = bounded_leaf("checked-busy", root.path(), &guard);
    let bytes = vec![7; 64 * 1024 + 1];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes))
        .expect("seed");
    let account = DecodeBudget::for_store(guard.clone()).expect("original");
    let _scope = account.enter();
    let source = backend
        .read_with_boundary(&account, id, None, &mut || Ok(()))
        .expect("metadata");
    let foreign = crate::content_store::fixture_sqlite_heap()
        .expect("authored SQLite fixture process")
        .open_connection(
            root.path().join(DATABASE_FILE),
            rusqlite::OpenFlags::default(),
        )
        .expect("independent SQL holder");
    foreign
        .execute_batch("BEGIN EXCLUSIVE")
        .expect("real foreign SQL lock");

    let mut polls = 0;
    let error = match backend.read_with_boundary(&account, id, None, &mut || {
        polls += 1;
        if polls == 32 { Err(expired()) } else { Ok(()) }
    }) {
        Err(error) => error,
        Ok(_) => panic!("foreign SQL lock must block checked length query"),
    };
    assert_expired(error);
    assert_eq!(polls, 32);
    let mut reader = source
        .open_with_boundary(&mut || Ok(()))
        .expect("deferred open performs no SQL");
    polls = 0;
    let error = reader
        .read_with_boundary(&mut [0; 4096], &mut || {
            polls += 1;
            if polls == 32 { Err(expired()) } else { Ok(()) }
        })
        .expect_err("real chunk wait ends at original refusal");
    assert_expired(error);
    assert_eq!(polls, 32);
    foreign
        .execute_batch("ROLLBACK")
        .expect("release foreign lock");
    assert!(!backend.quarantined.load(Ordering::Acquire));
    let restored: i64 = backend
        .read_connection
        .lock()
        .expect("inspect exact connection")
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .expect("restored sentinel");
    assert_eq!(
        restored, 5000,
        "both checked calls restore existing timeout before return"
    );
    assert!(
        reader
            .read_with_boundary(&mut [0; 1], &mut || Ok(()))
            .is_err()
    );
}
