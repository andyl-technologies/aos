//! Binds retained SQLite statement retries to their original batch caller.
//!
//! Exact expressions cover current presence, insert and preparation attempts.
//! The owner and caller obligations preserve admission, authentication and closure
//! before metadata or COMMIT; they do not permit an additional test attempt.

use super::super::{Companion, Contract};
use super::{BUSY_COMPANION, MANAGED_CONNECTION_COMPANION};

// The owner closes its native handles before releasing the same original loan.
const WRITE_STATEMENT_OBLIGATIONS: &[&str] = &[
    r#"struct BatchStatements<'connection> {
    presence: Statement<'connection>,
    insert: Option<Statement<'connection>>,
    #[cfg(test)]
    _closed: StatementsClosed,
    // Fields close in declaration order: both native handles precede this loan.
    _credit: DecodeScratch,
}"#,
    r#"    fn prepare(
        connection: &'connection Connection,
        original: &crate::owned_decode::DecodeBudget,
        quarantined: &AtomicBool,
        check: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        // Cover the fixed owner and transient move/prepare headers before the
        // first handle. Native allocations use the connection's already-paid
        // managed process heap. The caller's diagnostic loan separately covers
        // converted errors; this loan covers the new fixed Rust headers.
        let bytes = control_bytes()?;
        let credit = original
            .reserve_scratch_bytes(bytes)
            .map_err(|error| admission_under(original, error))?;
        let presence = prepare_statement(
            connection,
            diagnostic::PRESENCE_SQL,
            "test-sqlite-batch-presence",
            quarantined,
            check,
        )?;
        Ok(Self {
            presence,
            insert: None,
            #[cfg(test)]
            _closed: StatementsClosed,
            _credit: credit,
        })
    }"#,
    r#"pub(super) fn stage(
    connection: &Connection,
    objects: &[(ContentId, OwnedBlobBytes)],
    original: &crate::owned_decode::DecodeBudget,
    quarantined: &AtomicBool,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<bool, StoreError> {
    if objects.is_empty() {
        return Ok(false);
    }
    let mut statements = BatchStatements::prepare(connection, original, quarantined, check)?;
    let mut inserted = false;
    for (id, bytes) in objects {
        check()?;
        let exists = statements.contains(connection, *id, quarantined, check)?;
        check()?;
        if exists {
            authenticate_stored_with_boundary(
                connection,
                *id,
                check,
                Some(original),
                Some(quarantined),
            )?;
        } else {
            statements.insert(connection, *id, bytes, quarantined, check)?;
            inserted = true;
        }
        check()?;
    }
    // Statement query/execute has reset every cursor. Safe binding Drop then
    // finalizes both handles before metadata, COMMIT or the caller's cleanup.
    // Its ignored finalize-status behavior is inherited from query_row/execute.
    drop(statements);
    Ok(inserted)
}"#,
    r#"if self.insert.is_none() {
            self.insert = Some(prepare_statement(
                connection,
                diagnostic::INSERT_SQL,
                "stage-sqlite-batch-object",
                quarantined,
                check,
            )?);
        }"#,
    r#"let statement = self.insert.as_mut().ok_or(StoreError::Unavailable)?;"#,
    r#"fn control_bytes() -> Result<u64, StoreError> {
    std::mem::size_of::<BatchStatements<'_>>()
        .checked_add(
            std::mem::size_of::<Statement<'_>>()
                .checked_mul(2)
                .ok_or(StoreError::Quota)?,
        )
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(StoreError::Quota)
}

fn prepare_statement<'connection>(
    connection: &'connection Connection,
    sql: &'static str,
    operation: &'static str,
    quarantined: &AtomicBool,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<Statement<'connection>, StoreError> {
    busy::retry(connection, true, quarantined, check, |_| {
        #[cfg(test)]
        PREPARES.with(|counts| {
            let mut value = counts.get();
            let slot = usize::from(sql == diagnostic::INSERT_SQL);
            value[slot] = value[slot].saturating_add(1);
            counts.set(value);
        });
        connection
            .prepare(sql)
            .map_err(|source| database_error(operation, source))
    })
}"#,
];

pub(super) const BATCH_STATEMENT_COMPANIONS: &[Companion] = &[
    BUSY_COMPANION,
    MANAGED_CONNECTION_COMPANION,
    Companion {
        path: "crates/crucible-cas/src/content_store/sqlite/batch/write_statements.rs",
        required: WRITE_STATEMENT_OBLIGATIONS,
        counts: &[("busy::retry(", 3), ("pub(super) fn stage(", 1)],
    },
];

const STATEMENT_CALLER_COMPANIONS: &[Companion] = &[
    BUSY_COMPANION,
    MANAGED_CONNECTION_COMPANION,
    Companion {
        path: "crates/crucible-cas/src/content_store/sqlite/batch.rs",
        required: &[
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
        }"#,
            r#"let inserted = write_statements::stage(
                        &transaction,
                        &staged,
                        account,
                        &self.quarantined,
                        check,
                    )?;
                    if inserted {
                        check()?;
                        metadata::advance_with_boundary(&transaction, check, &self.quarantined)?;
                    }"#,
            r#"let accepted = busy::with_zero(account, &mut connection, &self.quarantined, &mut || check_original(boundary, account, operation.as_deref()), |connection, progress, check| {"#,
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
            r#"let commit = busy::retry(&transaction, true, &self.quarantined, check, |_|"#,
        ],
        counts: &[("write_statements::stage(", 1)],
    },
];

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-cas",
    target: "src/content_store/sqlite/batch/write_statements",
    required: WRITE_STATEMENT_OBLIGATIONS,
    expressions: &[
        (
            r#"busy::retry(connection, true, quarantined, check, |_| {
            with_id_text(id, |encoded| {
                let result = self.presence.query_row([encoded], |row| row.get(0));
                // The API has reset its cursor. Free copied bindings before the
                // next row, duplicate authentication or a BUSY retry.
                self.presence.clear_bindings();
                result.map_err(|source| database_error("test-sqlite-batch-presence", source))
            })
        })"#,
            1,
        ),
        (
            r#"busy::retry(connection, true, quarantined, check, |_| {
            with_id_text(id, |encoded| {
                let result = statement.execute(params![encoded, bytes]);
                // Retain only the prepared program, not a previous row's copied
                // body. The original result remains owned across this cleanup.
                statement.clear_bindings();
                let rows =
                    result.map_err(|source| database_error("stage-sqlite-batch-object", source))?;
                #[cfg(test)]
                PREPARES.with(|counts| {
                    let mut value = counts.get();
                    value[2] = value[2].saturating_add(rows);
                    counts.set(value);
                });
                Ok(rows)
            })
        })"#,
            1,
        ),
        (
            r#"busy::retry(connection, true, quarantined, check, |_| {
        #[cfg(test)]
        PREPARES.with(|counts| {
            let mut value = counts.get();
            let slot = usize::from(sql == diagnostic::INSERT_SQL);
            value[slot] = value[slot].saturating_add(1);
            counts.set(value);
        });
        connection
            .prepare(sql)
            .map_err(|source| database_error(operation, source))
    })"#,
            1,
        ),
    ],
    companions: STATEMENT_CALLER_COMPANIONS,
};
