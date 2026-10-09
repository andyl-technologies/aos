//! Contracts SQLite BUSY handling against the same original operation.
//!
//! Every admitted call retains its exact connection, transaction state, quarantine
//! marker, callback, and statement closure. Companion contracts bind base BUSY
//! classification, original-boundary checks, zero native timeout, and explicit
//! rollback and restoration. Additional calls and changed obligations fail closed.

use super::{Companion, Contract};

const BUSY_OBLIGATIONS: &[&str] = &[
    r#"fn retry<T>(
    connection: &Connection,
    transactional: bool,
    quarantined: &AtomicBool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    mut statement: impl FnMut(&mut dyn FnMut() -> Result<(), StoreError>) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    loop {
        healthy(quarantined)?;
        boundary()?;
        match statement(boundary) {
            Ok(value) => return Ok(value),
            Err(error) => {
                let busy = match &error {
                    StoreError::StreamIo { source, .. } => source
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<rusqlite::Error>())
                        .is_some_and(|error| {
                            matches!(error,
                            rusqlite::Error::SqliteFailure(code, _) if code.extended_code == 5)
                        }),
                    _ => false,
                };
                // Exact base BUSY is retryable only while the admitted
                // transaction remains active. LOCKED and extended BUSY codes
                // keep their original cause; auto-aborted work is never replayed.
                if !busy || (transactional && connection.is_autocommit()) {
                    return Err(error);
                }
                boundary()?;
                std::thread::yield_now();
            }
        }
    }
}"#,
    r#"fn with_zero<T>(
    original: &crate::owned_decode::DecodeBudget,
    connection: &mut Connection,
    quarantined: &AtomicBool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    work: impl FnOnce(
        &mut Connection,
        &mut Progress,
        &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<T, StoreError>,
) -> Result<Accepted<T>, StoreError> {
    with_cleanup(
        original,
        connection,
        quarantined,
        boundary,
        work,
        |connection| connection.execute_batch("ROLLBACK"),
        |connection, saved| connection.busy_timeout(saved),
    )
}"#,
    r#"original
        .verify_live()
        .map_err(|error| admission_under(original, error))?;
    healthy(quarantined)?;
    boundary()?;
    original
        .verify_live()
        .map_err(|error| admission_under(original, error))?;
    if !connection.is_autocommit() {
        quarantined.store(true, Ordering::Release);
        return Err(StoreError::Unavailable);
    }"#,
    r#"let mut result = match connection.busy_timeout(Duration::ZERO) {
        Ok(()) => work(connection, &mut progress, boundary),
        Err(source) => Err(database_error("disable-sqlite-busy-wait", source)),
    };"#,
    r#"let rollback = if connection.is_autocommit() {
        None
    } else if progress.owns_transaction {
        match rollback(connection) {
            Ok(()) if connection.is_autocommit() => None,
            Ok(()) => Some(rusqlite::Error::InvalidQuery),
            Err(source) => Some(source),
        }
    } else {
        Some(rusqlite::Error::InvalidQuery)
    };"#,
    r#"let restoration = restore(connection, Duration::from_millis(saved)).err();
    if rollback.is_some() || restoration.is_some() {
        quarantined.store(true, Ordering::Release);
    }"#,
    r#"let result = if rollback.is_none() && restoration.is_none() {
        result.and_then(|value| {
            healthy(quarantined)?;
            boundary()?;
            Ok(value)
        })
    } else {
        result
    };"#,
    r#"let credit = original
        .reserve_scratch_bytes(bytes)
        .map_err(|error| admission_under(original, error))?;"#,
];

const BUSY_COMPANION: Companion = Companion {
    path: "crates/crucible-cas/src/content_store/sqlite/batch/busy.rs",
    required: BUSY_OBLIGATIONS,
    counts: &[
        ("fn retry<T>(", 1),
        ("connection.busy_timeout(Duration::ZERO)", 1),
    ],
};

const MANAGED_CONNECTION_COMPANION: Companion = Companion {
    path: "crates/crucible-cas/src/content_store/sqlite/process_heap/connection.rs",
    required: &[r#"    pub(in crate::content_store::sqlite) fn try_lock_for(
        &self,
        operation: &'static str,
    ) -> Result<Option<SqliteConnectionGuard<'_>>, StoreError> {
        self.heap.verify_live()?;
        let owner = self
            .connection
            .as_ref()
            .ok_or_else(|| refusal("SQLite connection handle has closed"))?;
        match owner.connection.try_lock() {
            Ok(guard) => {
                self.heap.verify_live()?;
                if guard.is_none() {
                    return Err(refusal("SQLite native connection has closed").into());
                }
                Ok(Some(SqliteConnectionGuard { guard }))
            }
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Poisoned(_)) => Err(StoreError::Poisoned { operation }),
        }
    }"#],
    counts: &[("fn try_lock_for(", 1)],
};

const BUSY_COMPANIONS: &[Companion] = &[BUSY_COMPANION, MANAGED_CONNECTION_COMPANION];

const FIXTURE_CONNECTION_COMPANION: Companion = Companion {
    path: "crates/crucible-cas/src/content_store/sqlite_fixture.rs",
    required: &[r#"pub fn fixture_sqlite_connection(
    path: impl AsRef<Path>,
) -> Result<SqliteConnection, FixtureSqliteConnectionError> {
    let heap = fixture_sqlite_heap().map_err(FixtureSqliteConnectionError::Admission)?;
    heap.open_connection(path, rusqlite::OpenFlags::default())
        .map_err(FixtureSqliteConnectionError::Open)
}"#],
    counts: &[("fn fixture_sqlite_connection(", 1)],
};

const BUSY_FIXTURE_COMPANIONS: &[Companion] = &[
    BUSY_COMPANION,
    MANAGED_CONNECTION_COMPANION,
    FIXTURE_CONNECTION_COMPANION,
];

const CHECKED_READER_COMPANIONS: &[Companion] = &[
    BUSY_COMPANION,
    MANAGED_CONNECTION_COMPANION,
    Companion {
        path: "crates/crucible-cas/src/content_store/checked_reader.rs",
        required: &[r#"fn check(
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    original
        .verify_live()
        .map_err(|error| batch::admission_under(original, error))?;
    boundary()?;
    original
        .verify_live()
        .map_err(|error| batch::admission_under(original, error))
}"#],
        counts: &[("fn check(", 1)],
    },
];

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-cas",
        target: "src/content_store/sqlite/admin_batch",
        required: &[
            r#"fn check(
    backend: &SqliteBlobBackend,
    account: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    account
        .verify_live()
        .map_err(|error| admission_under(account, error))?;
    busy::healthy(&backend.quarantined)?;
    boundary()?;
    account
        .verify_live()
        .map_err(|error| admission_under(account, error))?;
    busy::healthy(&backend.quarantined)
}"#,
            r#"fn delete_candidates_with_boundary(
        &mut self,
        ids: &[ContentId],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<DeleteBatchReceipt, StoreError> {
        self.run(|inner, account| {
            let backend = inner.backend;
            let mut original = || check(backend, account, boundary);
            original()?;
            if ids.len() > MAX_BATCH_OBJECTS {
                return Err(StoreError::Quota);
            }
            let credit = account
                .reserve_scratch_array::<PlannedDeleteDisposition>(ids.len())
                .map_err(|error| admission_under(account, error))?;
            let mut dispositions = Vec::new();
            dispositions
                .try_reserve_exact(ids.len())
                .map_err(|error| allocation_under(account, error))?;
            let accepted = busy::with_zero(
                account,
                &mut inner.connection,
                &backend.quarantined,
                &mut original,
                |connection, progress, original| {
                    let shared: &Connection = connection;
                    let mut transaction ="#,
            r#"if let Err(error) = commit {
                        progress.commit_failed(&transaction);
                        return Err(error);
                    }
                    progress.committed();"#,
            r#"let accepted = accepted.check(|_| original())?;
            Ok(DeleteBatchReceipt::new(accepted, credit))"#,
        ],
        expressions: &[
            (
                r#"busy::retry(shared, false, &backend.quarantined, original, |_| {
                            rusqlite::Transaction::new_unchecked(
                                shared,
                                rusqlite::TransactionBehavior::Deferred,
                            )
                            .map_err(|source| database_error("begin-sqlite-blob-delete", source))
                        })"#,
                1,
            ),
            (
                r#"busy::retry(
                            &transaction,
                            true,
                            &backend.quarantined,
                            original,
                            |_| {
                                with_id_text(*id, |encoded| {
                                    transaction
                                        .query_row(diagnostic::PRESENCE_SQL, [encoded], |row| {
                                            row.get(0)
                                        })
                                        .map_err(|source| {
                                            database_error("test-sqlite-delete-presence", source)
                                        })
                                })
                            },
                        )"#,
                1,
            ),
            (
                r#"busy::retry(
                            &transaction,
                            true,
                            &backend.quarantined,
                            original,
                            |_| {
                                with_id_text(*id, |encoded| {
                                    transaction
                                        .execute(diagnostic::DELETE_SQL, [encoded])
                                        .map_err(|source| {
                                            database_error("delete-sqlite-blob-candidate", source)
                                        })
                                })
                            },
                        )"#,
                1,
            ),
            (
                r#"busy::retry(&transaction, true, &backend.quarantined, original, |_| {
                            transaction.execute_batch("COMMIT").map_err(|source| {
                                database_error("commit-sqlite-blob-delete", source)
                            })
                        })"#,
                1,
            ),
        ],
        companions: BUSY_COMPANIONS,
    },
    Contract {
        package: "crucible-cas",
        target: "src/content_store/sqlite/batch/busy/tests",
        required: &[
            r#"fn actual_commit_busy_cancellation_rolls_back_and_restores_without_new_work() {
    if isolated("actual_commit_busy_cancellation_rolls_back_and_restores_without_new_work") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let foreign = fixture_sqlite_connection(root.path().join(DATABASE_FILE))
        .expect("foreign reader");
    foreign
        .execute_batch("BEGIN; SELECT * FROM objects;")
        .expect("retained SHARED read lock");
    let credit = diagnostic::admit(&account, &backend.connection, Some(root.path()))
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
                let result = "#,
            r#"fn only_base_busy_with_active_transaction_is_retryable() {
    if isolated("only_base_busy_with_active_transaction_is_retryable") {
        return;
    }
    let (_, guard, backend, account) = backend();
    let _scope = account.enter();
    let connection = backend.lock_connection().expect("actual connection");
    for (code, transactional) in [(6, false), (261, false), (517, false), (5, true)] {
        let credit = diagnostic::admit(&account, &backend.connection, None)
            .expect("original copy loan");
        let mut statements = 0;
        let error = diagnostic::retain_failure(credit, || {
            "#,
            r#"fn actual_base_busy_retry_keeps_transaction_and_commits_once_after_release() {
    if isolated("actual_base_busy_retry_keeps_transaction_and_commits_once_after_release") {
        return;
    }
    let (root, guard, backend, account) = backend();
    let _scope = account.enter();
    let foreign = fixture_sqlite_connection(root.path().join(DATABASE_FILE))
        .expect("foreign writer");
    foreign
        .execute_batch("BEGIN IMMEDIATE")
        .expect("held actual writer lock");
    let attempts = std::cell::Cell::new(0);
    let mut released = false;
    let credit = diagnostic::admit(&account, &backend.connection, Some(root.path()))
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
                "#,
            r#"assert_eq!(checks, 32);"#,
            r#"super::super::tests::assert_expired(error);"#,
            r#"assert_eq!(timeout(&connection), 987);"#,
            r#"assert_eq!(statements, 1);"#,
            r#"for (code, transactional) in [(6, false), (261, false), (517, false), (5, true)] {"#,
            r#"assert_eq!(attempts.get(), 4);"#,
            r#"assert_eq!(load_metadata(&connection).expect("exact generation").1, 2);"#,
            r#"assert_eq!(timeout(&connection), 5000);"#,
        ],
        expressions: &[
            (
                r#"retry(
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
                )"#,
                1,
            ),
            (
                r#"retry(
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
            )"#,
                1,
            ),
            (
                r#"retry(
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
                )"#,
                1,
            ),
            (
                r#"fn actual_base_busy_retry_keeps_transaction_and_commits_once_after_release()"#,
                1,
            ),
        ],
        companions: BUSY_FIXTURE_COMPANIONS,
    },
    Contract {
        package: "crucible-cas",
        target: "src/content_store/sqlite/batch/busy",
        required: BUSY_OBLIGATIONS,
        expressions: &[(r#"fn retry<T>("#, 1)],
        companions: BUSY_COMPANIONS,
    },
    Contract {
        package: "crucible-cas",
        target: "src/content_store/sqlite/batch/metadata",
        required: &[
            r#"fn advance_with_boundary(
    connection: &Connection,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    quarantined: &std::sync::atomic::AtomicBool,
) -> Result<(), StoreError> {
    let (instance, generation) = load_with_boundary(connection, true, boundary, quarantined)?;
    let next = generation.checked_add(1).ok_or(StoreError::Quota)?;
    let next_sql = i64::try_from(next).map_err(|_| StoreError::Quota)?;
    let checksum = metadata_checksum(instance, next);
    boundary()?;
    busy::retry(connection, true, quarantined, boundary, |_| {
        connection
            .execute(
                diagnostic::UPDATE_SQL,
                params![next_sql, checksum.as_slice()],
            )
            .map_err(|source| database_error("advance-sqlite-blob-generation", source))
    })?;
    boundary()?;
    Ok(())
}"#,
            r#"fn load_with_boundary(
    connection: &Connection,
    transactional: bool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    quarantined: &std::sync::atomic::AtomicBool,
) -> Result<([u8; 32], u64), StoreError> {
    boundary()?;
    // SQLite may materialize each column in its separately bounded allocator.
    // Borrowing the value avoids an unbounded Rust Vec before length checks.
    let row = busy::retry(connection, transactional, quarantined, boundary, |_| {
        connection
            .query_row(diagnostic::METADATA_SQL, [], |row| {
                Ok((
                    fixed_blob(row, 0, "instance")?,
                    row.get::<_, i64>(1)?,
                    fixed_blob(row, 2, "checksum")?,
                ))
            })
            .map_err(|source| database_error("read-sqlite-blob-metadata", source))
    })?;
    boundary()?;
    let (Some(instance), generation, Some(checksum)) = row else {
        return Err(invalid_metadata());
    };
    let generation = u64::try_from(generation).map_err(|_| invalid_metadata())?;
    if generation == 0 || checksum != metadata_checksum(instance, generation) {
        return Err(invalid_metadata());
    }
    Ok((instance, generation))
}"#,
        ],
        expressions: &[
            (
                r#"busy::retry(connection, true, quarantined, boundary, |_| {
        connection
            .execute(
                diagnostic::UPDATE_SQL,
                params![next_sql, checksum.as_slice()],
            )
            .map_err(|source| database_error("advance-sqlite-blob-generation", source))
    })"#,
                1,
            ),
            (
                r#"busy::retry(connection, transactional, quarantined, boundary, |_| {
        connection
            .query_row(diagnostic::METADATA_SQL, [], |row| {
                Ok((
                    fixed_blob(row, 0, "instance")?,
                    row.get::<_, i64>(1)?,
                    fixed_blob(row, 2, "checksum")?,
                ))
            })
            .map_err(|source| database_error("read-sqlite-blob-metadata", source))
    })"#,
                1,
            ),
        ],
        companions: BUSY_COMPANIONS,
    },
    Contract {
        package: "crucible-cas",
        target: "src/content_store/sqlite/batch/reader",
        required: &[
            r#"fn chunk_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        offset: u64,
        length: usize,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<ReadChunk, StoreError> {
        boundary()?;
        original
            .verify_live()
            .map_err(|error| admission_under(original, error))?;
        let credit = original
            .reserve_scratch_array::<u8>(length)
            .map_err(|error| admission_under(original, error))?;
        let mut connection = loop {
            busy::healthy(&self.quarantined)?;
            boundary()?;
            match self.connection.try_lock_for("lock-sqlite-blob-reader")? {
                Some(connection) => {
                    busy::healthy(&self.quarantined)?;
                    break connection;
                }
                None => std::thread::yield_now(),
            }
        };
        boundary()?;
        let sqlite_offset = i64::try_from(offset)
            .ok()
            .and_then(|offset| offset.checked_add(1))
            .ok_or(StoreError::Quota)?;
        let accepted = busy::with_zero(
            original,
            &mut connection,
            &self.quarantined,
            boundary,
            |connection, _, boundary| {
                busy::retry(connection, false, &self.quarantined, boundary, |_| {
                    let mut statement = connection
                        .prepare_cached(diagnostic::SOURCE_SQL)
                        .map_err(|source| database_error("prepare-sqlite-batch-source", source))?;
                    with_id_text(self.id, |encoded| {
                        statement
                            .query_row(
                                params![encoded, sqlite_offset, length as i64, self.logical_length],
                                |row| {
                                    if length == 0 {
                                        row.get::<_, Option<Vec<u8>>>(0)
                                            .map(Option::unwrap_or_default)
                                    } else {
                                        row.get::<_, Vec<u8>>(0)
                                    }
                                },
                            )
                            .optional()
                            .map_err(|source| database_error("read-sqlite-batch-source", source))
                    })
                })
            },
        )?;
        accepted.finish(|bytes| {
            boundary()?;
            let bytes = bytes.ok_or(StoreError::Corrupt { id: self.id })?;
            if bytes.len() != length {
                return Err(StoreError::Corrupt { id: self.id });
            }
            Ok(ReadChunk {
                bytes,
                _credit: credit,
            })
        })
    }"#,
            r#"self.scan_with_boundary(original, self.logical_length, boundary)?;
        drop(self.chunk_with_boundary(original, 0, 0, boundary)?);
        if *self.hasher.finalize().as_bytes() != self.id.digest() {
            return Err(StoreError::Corrupt { id: self.id });
        }
        self.finalized = true;
        boundary()?;
        Ok(0)"#,
        ],
        expressions: &[(
            r#"busy::retry(connection, false, &self.quarantined, boundary, |_| {
                    let mut statement = connection
                        .prepare_cached(diagnostic::SOURCE_SQL)
                        .map_err(|source| database_error("prepare-sqlite-batch-source", source))?;
                    with_id_text(self.id, |encoded| {
                        statement
                            .query_row(
                                params![encoded, sqlite_offset, length as i64, self.logical_length],
                                |row| {
                                    if length == 0 {
                                        row.get::<_, Option<Vec<u8>>>(0)
                                            .map(Option::unwrap_or_default)
                                    } else {
                                        row.get::<_, Vec<u8>>(0)
                                    }
                                },
                            )
                            .optional()
                            .map_err(|source| database_error("read-sqlite-batch-source", source))
                    })
                })"#,
            1,
        )],
        companions: BUSY_COMPANIONS,
    },
    Contract {
        package: "crucible-cas",
        target: "src/content_store/sqlite/batch",
        required: &[
            r#"fn check_original(
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    account: &crate::owned_decode::DecodeBudget,
    operation: Option<&dyn SqliteCatalogOperation>,
) -> Result<(), StoreError> {
    boundary()?;
    account
        .verify_live()
        .map_err(|error| admission_under(account, error))?;
    if let Some(operation) = operation {
        operation.check()?;
    }
    Ok(())
}"#,
            r#"fn put_batch_with_boundary(
        &self,
        account: &crate::owned_decode::DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        account
            .verify_live()
            .map_err(|error| admission_under(account, error))?;
        busy::healthy(&self.quarantined)?;
        boundary()?;
        account
            .verify_live()
            .map_err(|error| admission_under(account, error))?;
        if objects.len() > MAX_BATCH_OBJECTS {
            return Err(StoreError::Quota);
        }
        let operation = self
            .catalog_supervisor
            .as_ref()
            .map(|supervisor| supervisor.begin(SqliteCatalogOperationKind::Write))
            .transpose()?;
        let _staging = catalog::write_gate_with_boundary(&mut || {
            check_original(boundary, account, operation.as_deref())
        })?;

        // Sources may read this same database. Authenticate every source
        // before taking the inventory or write-connection lock.
        let _staged_credit = account
            .reserve_scratch_array::<(ContentId, OwnedBlobBytes)>(objects.len())
            .map_err(|error| admission_under(account, error))?;
        let receipt_credit = admit_receipts(account, objects.len(), self.name.len())?;
        let staged = {
            let mut check = || check_original(boundary, account, operation.as_deref());
            let mut staged = Vec::new();
            staged
                .try_reserve_exact(objects.len())
                .map_err(|error| allocation_under(account, error))?;
            let mut total_bytes = 0_u64;
            for (id, source) in objects {
                check()?;
                total_bytes = total_bytes
                    .checked_add(source.logical_length())
                    .ok_or(StoreError::Quota)?;
                if total_bytes > MAX_BATCH_BYTES {
                    return Err(StoreError::Quota);
                }
                let bytes =
                    read_source(account, source, MAX_BATCH_BYTES, &mut check).map_err(|error| {
                        match error {
                            StoreError::InvalidSourceLength { .. } => {
                                StoreError::Corrupt { id: *id }
                            }
                            other => other,
                        }
                    })?;
                validate_bytes(*id, &bytes)?;
                check()?;
                staged.push((*id, bytes));
            }
            staged
        };

        let mut diagnostic_credit = Some(diagnostic::admit(
            account,
            &self.connection,
            Some(&self.root),
        )?);
        let result = (|| {
            let _inventory_lock = self.inventory_lock_with_boundary(account, &mut || {
                check_original(boundary, account, operation.as_deref())
            })?;
            let mut connection = self.connection_with_boundary(&mut || {
                check_original(boundary, account, operation.as_deref())
            })?;
            let accepted = busy::with_zero(
                account,
                &mut connection,
                &self.quarantined,
                &mut || check_original(boundary, account, operation.as_deref()),
                |connection, progress, check| {
                    let shared: &Connection = connection;
                    let mut transaction ="#,
            r#"if let Err(error) = commit {
                            progress.commit_failed(&transaction);
                            return Err(error);
                        }
                        progress.committed();"#,
            r#"operation.complete()?;
                }
                boundary()?;
                account
                    .verify_live()
                    .map_err(|error| admission_under(account, error))?;
                busy::healthy(&self.quarantined)?;"#,
        ],
        expressions: &[
            (
                r#"busy::retry(shared, false, &self.quarantined, check, |_| {
                            rusqlite::Transaction::new_unchecked(
                                shared,
                                rusqlite::TransactionBehavior::Deferred,
                            )
                            .map_err(|source| database_error("begin-sqlite-blob-batch", source))
                        })"#,
                1,
            ),
            (
                r#"busy::retry(&transaction, true, &self.quarantined, check, |_| {
                                with_id_text(*id, |encoded| {
                                    transaction
                                        .query_row(diagnostic::PRESENCE_SQL, [encoded], |row| {
                                            row.get(0)
                                        })
                                        .map_err(|source| {
                                            database_error("test-sqlite-batch-presence", source)
                                        })
                                })
                            })"#,
                1,
            ),
            (
                r#"busy::retry(&transaction, true, &self.quarantined, check, |_| {
                                with_id_text(*id, |encoded| {
                                    transaction
                                        .execute(
                                            diagnostic::INSERT_SQL,
                                            params![encoded, &bytes[..]],
                                        )
                                        .map_err(|source| {
                                            database_error("stage-sqlite-batch-object", source)
                                        })
                                })
                            })"#,
                1,
            ),
            (
                r#"busy::retry(&transaction, true, &self.quarantined, check, |_| {
                        transaction
                            .execute_batch("COMMIT")
                            .map_err(|source| database_error("commit-sqlite-blob-batch", source))
                    })"#,
                1,
            ),
        ],
        companions: BUSY_COMPANIONS,
    },
    Contract {
        package: "crucible-cas",
        target: "src/content_store/sqlite/checked_reader",
        required: &[
            r#"let original = caller.clone();
    super::super::checked_reader::check(&original, boundary)?;
    let diagnostic = diagnostic::admit(&original, &backend.connection, None)?;
    diagnostic::retain_failure(diagnostic, || {
        busy::healthy(&backend.quarantined)?;
        let mut check = || {
            super::super::checked_reader::check(&original, boundary)?;
            busy::healthy(&backend.quarantined)
        };
        let credit = original
            .reserve_scratch_bytes(
                (std::mem::size_of::<SqliteBlobSource>() + 2 * std::mem::size_of::<usize>()) as u64,
            )
            .map_err(|error| super::super::batch::admission_under(&original, error))?;
        let _staging = catalog::read_gate_with_boundary(&mut check)?;
        let mut connection = loop {
            check()?;
            match backend
                .read_connection
                .try_lock_for("lock-checked-sqlite-length")?
            {
                Some(connection) => break connection,
                None => std::thread::yield_now(),
            }
        };
        let accepted = busy::with_zero(
            &original,
            &mut connection,
            &backend.quarantined,
            &mut check,
            |connection, _, check| {
                "#,
            r#"let handle = accepted.finish(|length| {
            check()?;"#,
            r#"drop(connection);
        drop(_staging);
        super::super::checked_reader::check(&original, boundary)?;
        Ok(handle)
    })"#,
        ],
        expressions: &[(
            r#"busy::retry(connection, false, &backend.quarantined, check, |_| {
                    let mut statement = connection
                        .prepare_cached("SELECT length(body) FROM objects WHERE id = ?1")
                        .map_err(|source| {
                            database_error("prepare-checked-sqlite-length", source)
                        })?;
                    super::super::batch::with_id_text(id, |encoded| {
                        statement
                            .query_row([encoded], |row| row.get::<_, i64>(0))
                            .optional()
                            .map_err(|source| database_error("read-checked-sqlite-length", source))
                    })
                })"#,
            1,
        )],
        companions: CHECKED_READER_COMPANIONS,
    },
    Contract {
        package: "crucible-cas",
        target: "src/content_store/sqlite",
        required: &[
            r#"fn query_stored_with_boundary<T>(
    connection: &Connection,
    quarantined: Option<&std::sync::atomic::AtomicBool>,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    mut query: impl FnMut() -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    match quarantined {
        Some(marker) => batch::busy::retry(connection, true, marker, boundary, |_| query()),
        None => query(),
    }
}"#,
            r#"fn authenticate_stored_with_boundary(
    connection: &Connection,
    id: ContentId,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    account: Option<&crate::owned_decode::DecodeBudget>,
    quarantined: Option<&std::sync::atomic::AtomicBool>,
) -> Result<(), StoreError> {
    if account.is_some() != quarantined.is_some() {
        return Err(StoreError::InvalidComposition {
            reason: "checked SQLite authentication requires its original quarantine marker",
        });
    }
    boundary()?;"#,
            r#"boundary()?;
        if chunk.len() != chunk_length {
            return Err(StoreError::Corrupt { id });
        }"#,
        ],
        expressions: &[(
            r#"batch::busy::retry(connection, true, marker, boundary, |_| query())"#,
            1,
        )],
        companions: BUSY_COMPANIONS,
    },
];

#[test]
fn fixture_connections_require_the_same_heap_flags_and_original_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let contract = CONTRACTS
        .iter()
        .find(|contract| contract.target == "src/content_store/sqlite/batch/busy/tests")
        .expect("reviewed real BUSY fixture");
    let root = super::super::super::workspace_root();
    let source = std::fs::read_to_string(root.join(format!(
        "crates/{}/{}.rs",
        contract.package, contract.target
    )))?;
    let source = super::super::super::scrub_comments_and_strings(&source);
    let companions = super::read_companions(contract)?;
    let fixture = companions.last().expect("bound fixture delegate");

    for (before, after) in [
        (
            "fixture_sqlite_heap()",
            "isolated_small_fixture_sqlite_heap()",
        ),
        ("OpenFlags::default()", "OpenFlags::SQLITE_OPEN_READ_ONLY"),
        (
            "map_err(FixtureSqliteConnectionError::Admission)",
            "map_err(|_| FixtureSqliteConnectionError::Open(StoreError::Unavailable))",
        ),
        (
            "map_err(FixtureSqliteConnectionError::Open)",
            "map_err(|_| FixtureSqliteConnectionError::Open(StoreError::Quota))",
        ),
    ] {
        let before = super::pattern(before);
        let after = super::pattern(after);
        let compact = super::pattern(fixture);
        assert!(compact.contains(&before), "applicable fixture mutation");
        let mut changed = companions.clone();
        *changed.last_mut().expect("bound fixture delegate") = compact.replace(&before, &after);
        let masked = super::mask_with_companions(contract, &source, &changed);
        assert!(
            super::super::super::flaky_escape_failures("unreviewed", "unreviewed", &masked)
                .iter()
                .any(|finding| finding.contains("`retry`")),
            "changed fixture scope, flags or original error must reject the operational exception"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "operational_sqlite_tests.rs"]
mod tests;
