//! Original-callback SQLite busy retries, explicit cleanup and connection quarantine.
//!
//! Checked operations temporarily disable the private connection's native busy
//! wait. Statements close before each retry; cleanup and exact timeout restoration
//! finish before a result escapes. An unwind quarantines without running SQL in Drop.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::*;

/// Distinguishes durable commit from failure before or during publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqliteCommitOutcome {
    /// No successful commit was observed.
    NotCommitted,
    /// COMMIT succeeded, even if a later callback or cleanup failed.
    Committed,
    /// A failed operation left transaction completion uncertain.
    Uncertain,
}

/// Retains checked work and cleanup failures with their original allocation loan.
///
/// Each accessor borrows the original typed cause. The carrier closes before the
/// loan; a failed restoration never reports already committed work as rolled back.
pub struct SqliteScopeError {
    body: Box<ScopeFailure>,
    _credit: crate::owned_decode::DecodeScratch,
}

struct ScopeFailure {
    work: Option<StoreError>,
    rollback: Option<rusqlite::Error>,
    restore: Option<rusqlite::Error>,
    outcome: SqliteCommitOutcome,
}

impl SqliteScopeError {
    /// Returns the original work failure, if work failed.
    #[must_use]
    pub fn work_failure(&self) -> Option<&StoreError> {
        self.body.work.as_ref()
    }

    /// Returns the original explicit rollback failure, if cleanup failed.
    #[must_use]
    pub fn rollback_failure(&self) -> Option<&rusqlite::Error> {
        self.body.rollback.as_ref()
    }

    /// Returns the original timeout restoration failure, if restoration failed.
    #[must_use]
    pub fn restoration_failure(&self) -> Option<&rusqlite::Error> {
        self.body.restore.as_ref()
    }

    /// Returns the observed durable outcome without detaching its causes.
    #[must_use]
    pub fn outcome(&self) -> SqliteCommitOutcome {
        self.body.outcome
    }
}

impl fmt::Debug for SqliteScopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteScopeError")
            .field("work", &self.body.work)
            .field("rollback", &self.body.rollback)
            .field("restore", &self.body.restore)
            .field("outcome", &self.body.outcome)
            .finish()
    }
}

impl fmt::Display for SqliteScopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "checked SQLite scope failed ({:?})",
            self.outcome()
        )
    }
}

impl std::error::Error for SqliteScopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.work_failure() {
            Some(error)
        } else if let Some(error) = self.rollback_failure() {
            Some(error)
        } else {
            self.restoration_failure().map(|error| error as _)
        }
    }
}

// The SQL scope restores its connection before returning this token. Its
// observed outcome and prepaid error carrier remain live through final receipt
// construction and the original operation's completion checks.
pub(super) struct Accepted<T> {
    value: T,
    outcome: SqliteCommitOutcome,
    credit: crate::owned_decode::DecodeScratch,
}

impl<T> Accepted<T> {
    pub(super) fn finish<U>(
        self,
        finish: impl FnOnce(T) -> Result<U, StoreError>,
    ) -> Result<U, StoreError> {
        let Self {
            value,
            outcome,
            credit,
        } = self;
        match finish(value) {
            Ok(value) => Ok(value),
            Err(error) => Err(scope_error(Some(error), None, None, outcome, credit)),
        }
    }
}

fn scope_error(
    work: Option<StoreError>,
    rollback: Option<rusqlite::Error>,
    restore: Option<rusqlite::Error>,
    outcome: SqliteCommitOutcome,
    credit: crate::owned_decode::DecodeScratch,
) -> StoreError {
    StoreError::SqliteScope {
        source: SqliteScopeError {
            body: Box::new(ScopeFailure {
                work,
                rollback,
                restore,
                outcome,
            }),
            _credit: credit,
        },
    }
}

pub(super) struct Progress {
    owns_transaction: bool,
    outcome: SqliteCommitOutcome,
}

impl Progress {
    pub(super) fn began(&mut self) {
        self.owns_transaction = true;
    }

    pub(super) fn committed(&mut self) {
        self.outcome = SqliteCommitOutcome::Committed;
    }

    pub(super) fn commit_failed(&mut self, connection: &Connection) {
        if connection.is_autocommit() {
            self.outcome = SqliteCommitOutcome::Uncertain;
        }
    }
}

struct CleanupSentinel<'a> {
    quarantined: &'a AtomicBool,
    armed: bool,
}

impl Drop for CleanupSentinel<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.quarantined.store(true, Ordering::Release);
        }
    }
}

pub(in super::super) fn healthy(quarantined: &AtomicBool) -> Result<(), StoreError> {
    if quarantined.load(Ordering::Acquire) {
        Err(StoreError::Unavailable)
    } else {
        Ok(())
    }
}

pub(in super::super) fn retry<T>(
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
}

pub(super) fn with_zero<T>(
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
        connection,
        quarantined,
        boundary,
        work,
        |connection| connection.execute_batch("ROLLBACK"),
        |connection, saved| connection.busy_timeout(saved),
    )
}

// Private closures allow deterministic cleanup refusal tests. Production calls
// above always use the fixed literal and the safe live-Connection restore API.
fn with_cleanup<T>(
    connection: &mut Connection,
    quarantined: &AtomicBool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    work: impl FnOnce(
        &mut Connection,
        &mut Progress,
        &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<T, StoreError>,
    rollback: impl FnOnce(&Connection) -> rusqlite::Result<()>,
    restore: impl FnOnce(&Connection, Duration) -> rusqlite::Result<()>,
) -> Result<Accepted<T>, StoreError> {
    healthy(quarantined)?;
    boundary()?;
    if !connection.is_autocommit() {
        quarantined.store(true, Ordering::Release);
        return Err(StoreError::Unavailable);
    }

    // The typed dual cleanup causes are inline in this exact boxed carrier.
    // Private ROLLBACK has at most 42 ASCII message bytes plus its 8-byte SQL
    // input. Live-Connection timeout restoration is allocation-free; its
    // test-only refusal uses InvalidQuery, with no copied payload.
    let bytes = std::mem::size_of::<ScopeFailure>()
        .checked_add(42 + 8)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(StoreError::Quota)?;
    let credit = account()?.reserve_scratch_bytes(bytes).map_err(admission)?;
    let saved: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(|source| database_error("read-sqlite-busy-timeout", source))?;
    let saved = u64::try_from(saved)
        .ok()
        .filter(|value| *value <= i32::MAX as u64)
        .ok_or(StoreError::Quota)?;
    boundary()?;

    // Arm before the first state change. Any unwind leaves all aliases unable
    // to use an active transaction or a connection with altered timeout.
    let mut sentinel = CleanupSentinel {
        quarantined,
        armed: true,
    };
    let mut progress = Progress {
        owns_transaction: false,
        outcome: SqliteCommitOutcome::NotCommitted,
    };
    let mut result = match connection.busy_timeout(Duration::ZERO) {
        Ok(()) => work(connection, &mut progress, boundary),
        Err(source) => Err(database_error("disable-sqlite-busy-wait", source)),
    };
    if result.is_ok()
        && progress.owns_transaction
        && (progress.outcome != SqliteCommitOutcome::Committed || !connection.is_autocommit())
    {
        // A successful body cannot acknowledge a transaction that cleanup
        // would subsequently roll back. Treat this private contract violation
        // as unavailable and prevent aliases from reusing the connection.
        quarantined.store(true, Ordering::Release);
        result = Err(StoreError::Unavailable);
    }
    // Work's Ignore token closes before returning. Cleanup runs despite an
    // expired callback and is not hidden in a transaction or sentinel Drop.
    let rollback = if connection.is_autocommit() {
        None
    } else if progress.owns_transaction {
        match rollback(connection) {
            Ok(()) if connection.is_autocommit() => None,
            Ok(()) => Some(rusqlite::Error::InvalidQuery),
            Err(source) => Some(source),
        }
    } else {
        Some(rusqlite::Error::InvalidQuery)
    };
    if rollback.is_some() && progress.outcome != SqliteCommitOutcome::Committed {
        progress.outcome = SqliteCommitOutcome::Uncertain;
    }
    let restoration = restore(connection, Duration::from_millis(saved)).err();
    if rollback.is_some() || restoration.is_some() {
        quarantined.store(true, Ordering::Release);
    }
    let result = if rollback.is_none() && restoration.is_none() {
        result.and_then(|value| {
            healthy(quarantined)?;
            boundary()?;
            Ok(value)
        })
    } else {
        result
    };
    if rollback.is_none() && restoration.is_none() {
        sentinel.armed = false;
    }
    match result {
        Ok(value) if rollback.is_none() && restoration.is_none() => Ok(Accepted {
            value,
            outcome: progress.outcome,
            credit,
        }),
        other => Err(scope_error(
            other.err(),
            rollback,
            restoration,
            progress.outcome,
            credit,
        )),
    }
}

#[cfg(test)]
mod tests;
