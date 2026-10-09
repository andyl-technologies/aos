//! Actual SQLite snapshot, pre-body refusal and timeout preservation controls.

use super::*;

fn foreign_connection(root: &std::path::Path) -> crate::content_store::SqliteConnection {
    let connection = crate::content_store::fixture_sqlite_heap()
        .unwrap()
        .open_connection(root.join(DATABASE_FILE), rusqlite::OpenFlags::default())
        .unwrap();
    connection
        .lock()
        .unwrap()
        .set_prepared_statement_cache_capacity(0);
    connection
}

#[test]
fn actual_producer_busy_metadata_keeps_original_refusal_and_restores_timeout() {
    if isolated(
        "snapshot::actual_producer_busy_metadata_keeps_original_refusal_and_restores_timeout",
    ) {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let id = ContentId::for_bytes(ObjectKind::RamTree, 1, &[7; 64]);
    backend
        .lock_connection()
        .unwrap()
        .execute(
            "INSERT INTO objects (id,body) VALUES (?1,?2)",
            rusqlite::params![id.encode(), [7_u8; 64].as_slice()],
        )
        .unwrap();
    backend
        .read_connection
        .lock()
        .unwrap()
        .busy_timeout(Duration::from_millis(654))
        .unwrap();
    let heap = backend.maximum_sqlite_heap_bytes.unwrap();
    let _foreign_resources = guard.reserve_resources(3, heap).unwrap();
    let foreign = foreign_connection(root.path());
    foreign.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let mut calls = 0;

    let error = backend
        .consume_canonical_snapshot(
            &account,
            id,
            4096,
            &mut || {
                calls += 1;
                if calls == 16 {
                    Err(StoreError::Unauthorized)
                } else {
                    guard.verify()
                }
            },
            |_| panic!("a busy metadata query has not admitted any body"),
            |_| panic!("busy refusal must not consume a BLOB"),
        )
        .unwrap_err();

    assert_eq!(calls, 16);
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    let sql = scope(&error);
    assert_eq!(sql.outcome(), SqliteCommitOutcome::NotCommitted);
    assert!(sql.rollback_failure().is_none());
    assert!(sql.restoration_failure().is_none());
    let connection = backend.read_connection.lock().unwrap();
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 654);
    assert!(!backend.quarantined.load(Ordering::Acquire));
    foreign.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn actual_producer_closed_original_refuses_before_callback_or_metadata() {
    if isolated("snapshot::actual_producer_closed_original_refuses_before_callback_or_metadata") {
        return;
    }
    let (_root, _guard, backend, namespace) = backend();
    let operation = namespace.child().unwrap();
    let first = operation.charge_bytes(u64::MAX).unwrap_err();
    let id = ContentId::for_bytes(ObjectKind::RamTree, 1, b"not requested");

    let error = backend
        .consume_canonical_snapshot(
            &operation,
            id,
            4096,
            &mut || panic!("a closed original must precede callback effects"),
            |_| panic!("a closed original must precede metadata admission"),
            |_| panic!("a closed original must precede BLOB consumption"),
        )
        .unwrap_err();

    match error.original_failure() {
        StoreError::DecodeAdmission { source, .. } => assert_eq!(source, &first),
        other => panic!("lost original admission category: {other:?}"),
    }
    assert!(backend.read_connection.lock().unwrap().is_autocommit());
    drop(error);
    drop(first);
    drop(operation);
    namespace.verify_live().unwrap();
}

#[test]
fn actual_producer_refuses_metadata_before_borrowing_body() {
    if isolated("snapshot::actual_producer_refuses_metadata_before_borrowing_body") {
        return;
    }
    let (_root, _guard, backend, account) = backend();
    let _scope = account.enter();
    let id = ContentId::for_bytes(ObjectKind::RamTree, 1, &[7; 64]);
    backend
        .lock_connection()
        .unwrap()
        .execute(
            "INSERT INTO objects (id,body) VALUES (?1,?2)",
            rusqlite::params![id.encode(), [7_u8; 64].as_slice()],
        )
        .unwrap();
    backend
        .read_connection
        .lock()
        .unwrap()
        .busy_timeout(Duration::from_millis(765))
        .unwrap();
    let mut admissions = 0;

    let error = backend
        .consume_canonical_snapshot(
            &account,
            id,
            4096,
            &mut || Ok(()),
            |length| {
                admissions += 1;
                assert_eq!(length, 64);
                Err(StoreError::Quota)
            },
            |_| panic!("metadata refusal must not consume any BLOB"),
        )
        .unwrap_err();

    assert_eq!(admissions, 1);
    let sql = scope(&error);
    assert_eq!(sql.outcome(), SqliteCommitOutcome::NotCommitted);
    assert!(matches!(sql.work_failure(), Some(StoreError::Quota)));
    assert!(sql.rollback_failure().is_none());
    assert!(sql.restoration_failure().is_none());
    let connection = backend.read_connection.lock().unwrap();
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 765);
}

#[test]
fn actual_producer_body_remains_in_admitted_snapshot_during_external_replacement() {
    if isolated(
        "snapshot::actual_producer_body_remains_in_admitted_snapshot_during_external_replacement",
    ) {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let bytes = [7; 64];
    let id = ContentId::for_bytes(ObjectKind::RamTree, 1, &bytes);
    backend
        .lock_connection()
        .unwrap()
        .execute(
            "INSERT INTO objects (id,body) VALUES (?1,?2)",
            rusqlite::params![id.encode(), bytes.as_slice()],
        )
        .unwrap();
    let wal = backend
        .lock_connection()
        .unwrap()
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get::<_, String>(0))
        .unwrap();
    assert_eq!(wal, "wal");
    let heap = backend.maximum_sqlite_heap_bytes.unwrap();
    let _foreign_resources = guard.reserve_resources(3, heap).unwrap();
    let foreign = foreign_connection(root.path());
    let mut admissions = 0;
    let mut consumers = 0;

    backend
        .consume_canonical_snapshot(
            &account,
            id,
            4096,
            &mut || Ok(()),
            |length| {
                admissions += 1;
                assert_eq!(length, bytes.len() as u64);
                foreign
                    .execute(
                        "UPDATE objects SET body = zeroblob(8192) WHERE id = ?1",
                        [id.encode()],
                    )
                    .unwrap();
                Ok(())
            },
            |actual| {
                consumers += 1;
                assert_eq!(actual, bytes);
                true
            },
        )
        .unwrap();

    assert_eq!(admissions, 1);
    assert_eq!(consumers, 1);
    let error = backend
        .consume_canonical_snapshot(
            &account,
            id,
            4096,
            &mut || Ok(()),
            |length| {
                assert_eq!(length, 8192);
                Err(StoreError::Quota)
            },
            |_| panic!("the next oversized realization must be refused before borrowing"),
        )
        .unwrap_err();
    assert!(matches!(
        scope(&error).work_failure(),
        Some(StoreError::Quota)
    ));
    assert_eq!(scope(&error).outcome(), SqliteCommitOutcome::NotCommitted);
    assert!(backend.read_connection.lock().unwrap().is_autocommit());
}

#[test]
fn actual_work_eof_original_refusal_dominates_pending_tree_validation() {
    if isolated("snapshot::actual_work_eof_original_refusal_dominates_pending_tree_validation") {
        return;
    }
    let (_root, _guard, backend, namespace) = backend();
    let operation = namespace.child().unwrap();
    let _scope = operation.enter();
    let page = crucible_ram::PageDigest::hash(&[7; 4096]).unwrap();
    let child = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"fixture-page");
    let children = std::collections::BTreeSet::from([crate::content_envelope::ContentChild::new(
        "page", child,
    )
    .unwrap()]);
    let mut body = vec![1];
    body.extend_from_slice(crucible_ram::leaf_digest(page).as_bytes());
    body.extend_from_slice(&0_u32.to_be_bytes());
    body.extend_from_slice(&1_u64.to_be_bytes());
    body.extend_from_slice(page.as_bytes());
    let bytes =
        crate::content_envelope::ContentEnvelope::new("crucible.ram.tree", 1, children, body)
            .unwrap()
            .canonical_bytes();
    let id = ContentId::for_bytes(ObjectKind::RamTree, 1, &bytes);
    backend
        .lock_connection()
        .unwrap()
        .execute(
            "INSERT INTO objects (id,body) VALUES (?1,?2)",
            rusqlite::params![id.encode(), bytes],
        )
        .unwrap();
    let different = crucible_ram::leaf_digest(crucible_ram::PageDigest::hash(&[8; 4096]).unwrap());
    let mut calls = 0;
    let mut first = None;

    let error = crate::ram::read_tree_for_test(&backend, &operation, id, different, &mut || {
        calls += 1;
        // The healthy actual producer has eleven callbacks. The final one
        // follows borrowed body validation and real snapshot cleanup.
        if calls == 11 {
            first = Some(operation.charge_bytes(u64::MAX).unwrap_err());
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(calls, 11);
    let first = first.unwrap();
    let crate::ram::RamStoreError::Store(error) = error else {
        panic!("actual EOF admission failure retains its owning provider scope");
    };
    match error.original_failure() {
        StoreError::DecodeAdmission { source, .. } => assert_eq!(source, &first),
        other => panic!("pending validation masked actual EOF refusal: {other:?}"),
    }
    let actual = match &error {
        StoreError::RamValidation { source } => match source.storage_failure() {
            crate::ram::RamStoreError::Store(provider) => scope(provider),
            other => panic!("lost actual provider scope: {other:?}"),
        },
        other => panic!("unexpected original admission category: {other:?}"),
    };
    assert_eq!(actual.outcome(), SqliteCommitOutcome::NotCommitted);
    assert!(actual.rollback_failure().is_none());
    assert!(actual.restoration_failure().is_none());
    assert!(backend.read_connection.lock().unwrap().is_autocommit());
    drop(error);
    drop(first);
    drop(_scope);
    drop(operation);
    namespace.verify_live().unwrap();
}

#[test]
fn actual_work_consumes_sql_snapshot_and_keeps_pending_validation_after_cleanup() {
    if isolated(
        "snapshot::actual_work_consumes_sql_snapshot_and_keeps_pending_validation_after_cleanup",
    ) {
        return;
    }
    let (_root, _guard, backend, account) = backend();
    let _scope = account.enter();
    let page = crucible_ram::PageDigest::hash(&[7; 4096]).unwrap();
    let digest = crucible_ram::leaf_digest(page);
    let child = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"fixture-page");
    let mut children = std::collections::BTreeSet::new();
    children.insert(crate::content_envelope::ContentChild::new("page", child).unwrap());
    let mut body = vec![1];
    body.extend_from_slice(digest.as_bytes());
    body.extend_from_slice(&0_u32.to_be_bytes());
    body.extend_from_slice(&1_u64.to_be_bytes());
    body.extend_from_slice(page.as_bytes());
    let envelope =
        crate::content_envelope::ContentEnvelope::new("crucible.ram.tree", 1, children, body)
            .unwrap();
    let bytes = envelope.canonical_bytes();
    let id = ContentId::for_bytes(ObjectKind::RamTree, 1, &bytes);
    backend
        .lock_connection()
        .unwrap()
        .execute(
            "INSERT INTO objects (id,body) VALUES (?1,?2)",
            rusqlite::params![id.encode(), bytes],
        )
        .unwrap();
    {
        let connection = backend.read_connection.lock().unwrap();
        connection
            .busy_timeout(Duration::from_millis(1234))
            .unwrap();
    }

    let mut callbacks = 0;
    crate::ram::read_tree_for_test(&backend, &account, id, digest, &mut || {
        callbacks += 1;
        Ok(())
    })
    .unwrap();
    {
        let connection = backend.read_connection.lock().unwrap();
        assert!(connection.is_autocommit());
        assert_eq!(timeout(&connection), 1234);
    }
    eprintln!("actual_work_sql_callbacks={callbacks}");

    let different = crucible_ram::leaf_digest(crucible_ram::PageDigest::hash(&[8; 4096]).unwrap());
    let error = crate::ram::read_tree_for_test(&backend, &account, id, different, &mut || Ok(()))
        .unwrap_err();
    let crate::ram::RamStoreError::Store(StoreError::RamReadValidation { source }) = error else {
        panic!("pending pure validation must retain the actual complete SQL outcome");
    };
    assert!(matches!(
        source.first_validation(),
        crate::ram::RamStoreError::Invalid("tree reference geometry")
    ));
    let crate::ram::RamStoreError::Store(provider) = source.storage_failure() else {
        panic!("actual SQL scope remains owned");
    };
    let sql = scope(provider);
    assert_eq!(sql.outcome(), SqliteCommitOutcome::NotCommitted);
    assert!(sql.rollback_failure().is_none());
    assert!(sql.restoration_failure().is_none());
    assert!(matches!(
        sql.work_failure(),
        Some(StoreError::Unsupported {
            capability: "bounded-canonical-validation-refused"
        })
    ));
    let connection = backend.read_connection.lock().unwrap();
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 1234);
}

const METADATA: &str = "SELECT typeof(body) = 'blob', length(body) FROM objects WHERE id = ?1";
const BODY: &str = "SELECT CASE WHEN typeof(body) = 'blob' AND length(body) = ?2 AND length(body) <= ?3 THEN body ELSE NULL END FROM objects WHERE id = ?1";

#[derive(Default)]
struct Queries {
    metadata: usize,
    body: usize,
}

fn query_names(account: &DecodeBudget) -> crate::owned_decode::DecodeScratch {
    let previous_sql_name = [
        diagnostic::PRESENCE_SQL,
        diagnostic::INSERT_SQL,
        diagnostic::SOURCE_SQL,
        diagnostic::METADATA_SQL,
        diagnostic::UPDATE_SQL,
        diagnostic::INVENTORY_SQL,
        diagnostic::DELETE_SQL,
    ]
    .into_iter()
    .map(str::len)
    .max()
    .unwrap();
    account
        .reserve_scratch_bytes((2 * BODY.len().saturating_sub(previous_sql_name)) as u64)
        .unwrap()
}

fn read_bounded<T>(
    connection: &Connection,
    id: ContentId,
    maximum: u64,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    queries: &mut Queries,
    admit: impl FnOnce(u64) -> Result<(), StoreError>,
    consume: impl FnOnce(&[u8]) -> T,
) -> Result<T, StoreError> {
    crate::content_store::batch::with_id_text(id, |encoded| {
        queries.metadata += 1;
        let (kind, length) = connection
            .query_row(METADATA, [encoded], |row| {
                Ok((row.get::<_, bool>(0)?, row.get::<_, i64>(1)?))
            })
            .optional()
            .map_err(|source| database_error("read-snapshot-metadata", source))?
            .ok_or(StoreError::NotFound { id })?;
        let length = u64::try_from(length).map_err(|_| StoreError::Corrupt { id })?;
        if length > maximum {
            return Err(StoreError::Quota);
        }
        admit(length)?;
        boundary()?;

        queries.body += 1;
        let mut statement = connection
            .prepare(BODY)
            .map_err(|source| database_error("prepare-snapshot-body", source))?;
        let mut rows = statement
            .query(rusqlite::params![encoded, length, maximum])
            .map_err(|source| database_error("query-snapshot-body", source))?;
        let row = rows
            .next()
            .map_err(|source| database_error("read-snapshot-body", source))?
            .ok_or(StoreError::NotFound { id })?;
        let bytes = row
            .get_ref(0)
            .map_err(|source| database_error("borrow-snapshot-body", source))?
            .as_blob()
            .map_err(|_| StoreError::Corrupt { id })?;
        if !kind || bytes.len() as u64 != length || !id.authenticates(bytes) {
            return Err(StoreError::Corrupt { id });
        }
        Ok(consume(bytes))
    })
}

#[test]
fn refused_metadata_performs_no_body_query_and_restores_timeout() {
    if isolated("snapshot::refused_metadata_performs_no_body_query_and_restores_timeout") {
        return;
    }
    let (_root, guard, backend, account) = backend();
    let _ambient = account.enter();
    let source = BlobHandle::from_bytes(vec![7; 64]);
    let id = ContentId::for_bytes(ObjectKind::RamTree, 1, &[7; 64]);
    backend.put_if_absent(id, &source).unwrap();
    let mut connection = backend.read_connection.lock().unwrap();
    connection
        .busy_timeout(Duration::from_millis(1234))
        .unwrap();
    let diagnostic = diagnostic::admit(&account, backend.maximum_sqlite_heap_bytes, None).unwrap();
    // The prototype's longer CASE query has its own exact copied-SQL-name
    // envelope, under the SAME original finite bank, before SQL preparation.
    let _query_names = query_names(&account);
    let mut queries = Queries::default();
    let mut consumers = 0;
    let mut checks = 0;

    let error = diagnostic::retain_failure(diagnostic, || {
        super::super::snapshot::with_snapshot(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut || {
                checks += 1;
                guard.verify()
            },
            |connection, boundary| {
                read_bounded(
                    connection,
                    id,
                    4096,
                    boundary,
                    &mut queries,
                    |_| Err(StoreError::Quota),
                    |_| consumers += 1,
                )
            },
        )
    })
    .err()
    .unwrap();

    assert_eq!(queries.metadata, 1);
    assert_eq!(queries.body, 0);
    assert_eq!(consumers, 0);
    assert_eq!(checks, 3);
    assert!(matches!(
        scope(&error).work_failure(),
        Some(StoreError::Quota)
    ));
    assert_eq!(scope(&error).outcome(), SqliteCommitOutcome::NotCommitted);
    assert!(scope(&error).rollback_failure().is_none());
    assert!(scope(&error).restoration_failure().is_none());
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 1234);
}

#[test]
fn external_oversized_replacement_cannot_change_admitted_snapshot_body() {
    if isolated("snapshot::external_oversized_replacement_cannot_change_admitted_snapshot_body") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _ambient = account.enter();
    let bytes = [7; 64];
    let id = ContentId::for_bytes(ObjectKind::RamTree, 1, &bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    let wal = backend
        .lock_connection()
        .unwrap()
        .query_row("PRAGMA journal_mode=WAL", [], |row| {
            Ok(matches!(
                row.get_ref(0)?,
                rusqlite::types::ValueRef::Text(b"wal")
            ))
        })
        .unwrap();
    assert!(wal);

    // The additional adversarial connection uses this fixture's existing
    // finite physical bank; it does not admit a second logical namespace.
    let heap = backend.maximum_sqlite_heap_bytes.unwrap();
    let _foreign_resources = guard.reserve_resources(3, heap).unwrap();
    let foreign = foreign_connection(root.path());
    let diagnostic = diagnostic::admit(&account, Some(heap), None).unwrap();
    let _query_names = query_names(&account);
    let mut connection = backend.read_connection.lock().unwrap();
    connection.busy_timeout(Duration::from_millis(987)).unwrap();
    let mut queries = Queries::default();
    let mut consumers = 0;

    let accepted = diagnostic::retain_failure(diagnostic, || {
        super::super::snapshot::with_snapshot(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut || guard.verify(),
            |connection, boundary| {
                read_bounded(
                    connection,
                    id,
                    4096,
                    boundary,
                    &mut queries,
                    |length| {
                        assert_eq!(length, 64);
                        crate::content_store::batch::with_id_text(id, |encoded| {
                            assert_eq!(
                                foreign
                                    .execute(
                                        "UPDATE objects SET body = zeroblob(8192) WHERE id = ?1",
                                        [encoded],
                                    )
                                    .unwrap(),
                                1
                            );
                            Ok(())
                        })?;
                        Ok(())
                    },
                    |body| {
                        consumers += 1;
                        assert_eq!(body, bytes);
                        body.len()
                    },
                )
            },
        )
    })
    .unwrap();

    assert_eq!(*accepted.value(), 64);
    assert_eq!(accepted.outcome, SqliteCommitOutcome::NotCommitted);
    assert_eq!((queries.metadata, queries.body, consumers), (1, 1, 1));
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 987);
    drop(accepted);

    // A NEW operation observes the replacement, refuses its actual metadata
    // before body projection, and never grants trust to the stale content ID.
    let diagnostic = diagnostic::admit(&account, Some(heap), None).unwrap();
    let mut following = Queries::default();
    let error = diagnostic::retain_failure(diagnostic, || {
        super::super::snapshot::with_snapshot(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut || guard.verify(),
            |connection, boundary| {
                read_bounded(
                    connection,
                    id,
                    4096,
                    boundary,
                    &mut following,
                    |_| panic!("oversized metadata cannot be admitted"),
                    |_| panic!("oversized body must not be queried or consumed"),
                )
            },
        )
    })
    .err()
    .unwrap();

    assert_eq!((following.metadata, following.body), (1, 0));
    assert!(matches!(
        scope(&error).work_failure(),
        Some(StoreError::Quota)
    ));
    assert_eq!(scope(&error).outcome(), SqliteCommitOutcome::NotCommitted);
    assert!(scope(&error).rollback_failure().is_none());
    assert!(scope(&error).restoration_failure().is_none());
    assert_eq!(timeout(&connection), 987);
}

#[test]
fn final_callback_original_poisoning_refuses_value_after_real_snapshot_cleanup() {
    if isolated(
        "snapshot::final_callback_original_poisoning_refuses_value_after_real_snapshot_cleanup",
    ) {
        return;
    }
    let (_root, _guard, backend, namespace) = backend();
    let operation = namespace.child().unwrap();
    let mut connection = backend.read_connection.lock().unwrap();
    connection.busy_timeout(Duration::from_millis(321)).unwrap();
    let diagnostic =
        diagnostic::admit(&operation, backend.maximum_sqlite_heap_bytes, None).unwrap();
    let mut calls = 0;
    let completed = std::cell::Cell::new(false);
    let mut first = None;

    let error = diagnostic::retain_failure(diagnostic, || {
        super::super::snapshot::with_snapshot(
            &operation,
            &mut connection,
            &backend.quarantined,
            &mut || {
                calls += 1;
                if completed.get() {
                    first = Some(operation.charge_bytes(u64::MAX).unwrap_err());
                }
                Ok(())
            },
            |connection, _| {
                assert!(!connection.is_autocommit());
                completed.set(true);
                Ok(42_u64)
            },
        )
    })
    .err()
    .unwrap();

    let first = first.unwrap();
    assert_eq!(calls, 4);
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 321);
    assert_eq!(scope(&error).outcome(), SqliteCommitOutcome::NotCommitted);
    assert!(scope(&error).rollback_failure().is_none());
    assert!(scope(&error).restoration_failure().is_none());
    match error.original_failure() {
        StoreError::DecodeAdmission { source, .. } => assert_eq!(source, &first),
        other => panic!("lost actual original refusal: {other:?}"),
    }
    assert_eq!(operation.check().unwrap_err(), first);
    drop(error);
    drop(first);
    drop(operation);
    namespace.verify_live().unwrap();
}

#[test]
fn closed_original_refuses_before_callback_or_read_transaction() {
    if isolated("snapshot::closed_original_refuses_before_callback_or_read_transaction") {
        return;
    }
    let (_root, _guard, backend, namespace) = backend();
    let operation = namespace.child().unwrap();
    let first = operation.charge_bytes(u64::MAX).unwrap_err();
    let mut connection = backend.read_connection.lock().unwrap();
    connection.busy_timeout(Duration::from_millis(456)).unwrap();

    let error = super::super::snapshot::with_snapshot(
        &operation,
        &mut connection,
        &backend.quarantined,
        &mut || panic!("original refusal precedes all callbacks"),
        |_, _| -> Result<(), StoreError> {
            panic!("original refusal precedes all transaction/query effects")
        },
    )
    .err()
    .unwrap();

    match error.original_failure() {
        StoreError::DecodeAdmission { source, .. } => assert_eq!(source, &first),
        other => panic!("lost pre-effect original refusal: {other:?}"),
    }
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 456);
    drop(error);
    drop(first);
    drop(operation);
    namespace.verify_live().unwrap();
}
