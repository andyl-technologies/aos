//! Test-only genuine transaction and deterministic dual-cleanup failures.

use super::*;

/// Observes an actual checked transaction after its work and cleanup refuse.
#[derive(Debug)]
pub struct SqliteScopeFaultObservation {
    /// Complete checked failure retaining its original scope and diagnostic loans.
    pub failure: StoreError,
    /// Actual catalog generation read from the same connection after cleanup.
    pub generation: u64,
    /// Actual native busy timeout read from the same connection after cleanup.
    pub busy_timeout_ms: i64,
    /// Whether the checked cleanup engine quarantined the connection.
    pub quarantined: bool,
    /// Whether SQLite reports that the original transaction has terminated.
    pub autocommit: bool,
}

impl SqliteBlobBackend {
    /// Exercises an actual capped transaction through the normal checked cleanup engine.
    ///
    /// This component fixture borrows the caller's original metadata account
    /// and original catalog supervisor. A committed case executes real COMMIT;
    /// the other injects static rollback and restoration errors after real BEGIN.
    /// The supplied hook runs after the transaction starts, before repeated
    /// caller boundary checks. The supplied original process heap has the
    /// fixture's authored 8 MiB ceiling.
    ///
    /// # Errors
    /// Returns original preparation, credit, SQLite, or observation failures, or
    /// refuses a fixture whose boundary unexpectedly accepts completed work.
    pub fn checked_scope_failure_fixture_for_test(
        root: &Path,
        original: &crate::owned_decode::DecodeBudget,
        supervisor: Arc<dyn SqliteCatalogSupervisor>,
        committed: bool,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
        started: &mut dyn FnMut(),
        heap: &crate::content_store::SqliteProcessHeap,
    ) -> Result<SqliteScopeFaultObservation, StoreError> {
        original
            .verify_live()
            .map_err(|error| admission_under(original, error))?;

        let name = "native-scope-fixture";
        let operation = supervisor.begin(SqliteCatalogOperationKind::Write)?;
        let lease = supervisor
            .reserve_resident_bytes(minimum_sqlite_catalog_resident_bytes(name, root)?)?;
        let mut backend = Self::open_inner(
            name.to_owned(),
            root.to_owned(),
            8 * 1024 * 1024,
            Some(supervisor),
            heap,
        )?;
        backend.resident_lease = lease.into();
        operation.complete()?;
        let credit = diagnostic::admit(original, &backend.connection, Some(root))?;
        let mut connection = backend.lock_connection()?;

        let result = diagnostic::retain_failure(credit, || {
            with_cleanup(
                original,
                &mut connection,
                &backend.quarantined,
                boundary,
                |connection, progress, boundary| {
                    connection
                        .execute_batch("BEGIN DEFERRED")
                        .map_err(|source| database_error("fixture-begin", source))?;
                    progress.began();
                    if committed {
                        connection
                            .execute(
                                "INSERT INTO objects (id, body) VALUES ('component', x'01')",
                                [],
                            )
                            .map_err(|source| database_error("fixture-insert", source))?;
                        advance_metadata(connection)?;
                        connection
                            .execute_batch("COMMIT")
                            .map_err(|source| database_error("fixture-commit", source))?;
                        progress.committed();
                    }
                    started();
                    let first = boundary();
                    let _ = boundary();
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
        });
        let failure = result.err().ok_or(StoreError::InvalidComposition {
            reason: "checked scope fault fixture requires an original boundary refusal",
        })?;
        let generation = load_metadata(&connection)?.1;
        let busy_timeout_ms = connection
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .map_err(|source| database_error("fixture-observe-timeout", source))?;
        Ok(SqliteScopeFaultObservation {
            failure,
            generation,
            busy_timeout_ms,
            quarantined: backend.quarantined.load(Ordering::Acquire),
            autocommit: connection.is_autocommit(),
        })
    }
}
