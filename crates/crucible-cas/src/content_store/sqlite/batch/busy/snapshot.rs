//! Read-snapshot scope with explicit original cleanup custody.
//!
//! Metadata and body consumption share the same SQLite snapshot. Exact busy
//! timeout restoration and explicit cleanup precede any accepted result. A
//! clean close can retain its unused failure credit for the same operation.

use super::*;

pub(in crate::content_store::sqlite) struct SnapshotScope<'a> {
    sentinel: CleanupSentinel<'a>,
    saved_timeout: u64,
    owns_transaction: bool,
    credit: Option<crate::owned_decode::DecodeScratch>,
}

impl<'a> SnapshotScope<'a> {
    pub(in crate::content_store::sqlite) fn prepare(
        original: &crate::owned_decode::DecodeBudget,
    ) -> Result<crate::owned_decode::DecodeScratch, StoreError> {
        let bytes = std::mem::size_of::<ScopeFailure>()
            .checked_add(42 + 8)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(StoreError::Quota)?;
        original
            .reserve_scratch_bytes(bytes)
            .map_err(|error| admission_under(original, error))
    }

    /// Returns state even when BEGIN fails, so its caller performs cleanup.
    pub(in crate::content_store::sqlite) fn begin(
        original: &crate::owned_decode::DecodeBudget,
        connection: &Connection,
        quarantined: &'a AtomicBool,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
        prepared: Option<crate::owned_decode::DecodeScratch>,
    ) -> Result<(Self, Result<(), StoreError>), StoreError> {
        original
            .verify_live()
            .map_err(|error| admission_under(original, error))?;
        checked(original, quarantined, boundary)?;
        if !connection.is_autocommit() {
            quarantined.store(true, Ordering::Release);
            return Err(StoreError::Unavailable);
        }

        let credit = match prepared {
            Some(credit) => credit,
            None => Self::prepare(original)?,
        };
        let saved: i64 = connection
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .map_err(|source| database_error("read-sqlite-busy-timeout", source))?;
        let saved_timeout = u64::try_from(saved)
            .ok()
            .filter(|value| *value <= i32::MAX as u64)
            .ok_or(StoreError::Quota)?;
        checked(original, quarantined, boundary)?;

        let mut scope = Self {
            sentinel: CleanupSentinel {
                quarantined,
                armed: true,
            },
            saved_timeout,
            owns_transaction: false,
            credit: Some(credit),
        };
        let mut check = || checked(original, quarantined, boundary);
        let begun = match connection.busy_timeout(Duration::ZERO) {
            Ok(()) => retry(connection, false, quarantined, &mut check, |_| {
                connection
                    .execute_batch("BEGIN DEFERRED")
                    .map_err(|source| database_error("begin-sqlite-read-snapshot", source))
            }),
            Err(source) => Err(database_error("disable-sqlite-busy-wait", source)),
        };
        scope.owns_transaction = begun.is_ok();
        Ok((scope, begun))
    }

    /// Closes native state before returning either credit or the owning error.
    pub(in crate::content_store::sqlite) fn finish<T>(
        mut self,
        original: &crate::owned_decode::DecodeBudget,
        connection: &Connection,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
        eof_refused: &mut bool,
        mut result: Result<T, StoreError>,
    ) -> Result<(T, crate::owned_decode::DecodeScratch), StoreError> {
        let quarantined = self.sentinel.quarantined;
        // Cleanup is unconditional after failure; no refused callback runs.
        let rollback = if connection.is_autocommit() {
            if self.owns_transaction {
                if result.is_ok() {
                    result = Err(StoreError::Unavailable);
                }
                quarantined.store(true, Ordering::Release);
            }
            None
        } else if self.owns_transaction {
            match connection.execute_batch("ROLLBACK") {
                Ok(()) if connection.is_autocommit() => None,
                Ok(()) => Some(rusqlite::Error::InvalidQuery),
                Err(error) => Some(error),
            }
        } else {
            Some(rusqlite::Error::InvalidQuery)
        };
        let restoration = connection
            .busy_timeout(Duration::from_millis(self.saved_timeout))
            .err();
        if rollback.is_some() || restoration.is_some() {
            quarantined.store(true, Ordering::Release);
        }

        let outcome = if rollback.is_some() {
            SqliteCommitOutcome::Uncertain
        } else {
            SqliteCommitOutcome::NotCommitted
        };
        if rollback.is_none() && restoration.is_none() {
            result = result.and_then(|value| {
                if let Err(error) = checked(original, quarantined, boundary) {
                    *eof_refused = true;
                    return Err(error);
                }
                Ok(value)
            });
            self.sentinel.armed = false;
        }
        let credit = match self.credit.take() {
            Some(credit) => credit,
            None => unreachable!("a snapshot retains its original failure credit until close"),
        };
        match result {
            Ok(value) if rollback.is_none() && restoration.is_none() => Ok((value, credit)),
            other => Err(scope_error(
                other.err(),
                rollback,
                restoration,
                outcome,
                credit,
                None,
            )),
        }
    }
}

fn checked(
    original: &crate::owned_decode::DecodeBudget,
    quarantined: &AtomicBool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    crate::content_store::checked_reader::check(original, boundary)?;
    healthy(quarantined)
}

pub(in crate::content_store::sqlite) fn refuse_after_clean(
    credit: crate::owned_decode::DecodeScratch,
    error: StoreError,
) -> StoreError {
    scope_error(
        Some(error),
        None,
        None,
        SqliteCommitOutcome::NotCommitted,
        credit,
        None,
    )
}

pub(in crate::content_store::sqlite) fn with_snapshot<T>(
    original: &crate::owned_decode::DecodeBudget,
    connection: &mut Connection,
    quarantined: &AtomicBool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    work: impl FnOnce(&Connection, &mut dyn FnMut() -> Result<(), StoreError>) -> Result<T, StoreError>,
) -> Result<Accepted<T>, StoreError> {
    let (scope, begun) = SnapshotScope::begin(original, connection, quarantined, boundary, None)?;
    let result = begun.and_then(|()| {
        let mut check = || checked(original, quarantined, boundary);
        work(connection, &mut check)
    });
    let mut eof_refused = false;
    let (value, credit) = scope.finish(original, connection, boundary, &mut eof_refused, result)?;
    Ok(Accepted {
        value,
        outcome: SqliteCommitOutcome::NotCommitted,
        diagnostic: None,
        credit,
    })
}
