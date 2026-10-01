//! Bounded integrity, declared constraints and counts in the pinned source read.
//!
//! These checks attest only what this read transaction observes. They establish
//! no archive completeness, independent archive FK proof, application reference
//! closure, provider state, credential custody or activation authority.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{ensure, Result};

use super::{quote_identifier, SqliteSnapshotReader};

const PROGRESS_INTERVAL: i32 = 1_000;
const MAX_PROGRESS_CALLBACKS: u64 = 1_000_000;
const MAX_AUDIT_DURATION: Duration = Duration::from_secs(300);

/// Explicit work limits for a read-only source audit.
///
/// SQLite progress callbacks interrupt VM execution. They bound approximate
/// instruction work, rather than physical I/O bytes or a hard wall-clock SLA:
/// one blocking filesystem operation may outlast the elapsed-time budget.
#[derive(Debug, Clone, Copy)]
pub struct SqliteSnapshotAuditLimits {
    /// Maximum elapsed duration, greater than zero and at most five minutes.
    pub max_duration: Duration,
    /// Maximum callbacks, each after approximately 1,000 SQLite VM instructions.
    ///
    /// Must be between one and one million. A query that exhausts this budget
    /// rejects the entire audit; no successful partial report is returned.
    pub max_progress_callbacks: u64,
}

impl SqliteSnapshotAuditLimits {
    fn validate(self) -> Result<()> {
        ensure!(
            !self.max_duration.is_zero() && self.max_duration <= MAX_AUDIT_DURATION,
            "snapshot audit duration exceeds supported bounds"
        );
        ensure!(
            (1..=MAX_PROGRESS_CALLBACKS).contains(&self.max_progress_callbacks),
            "snapshot audit work exceeds supported bounds"
        );
        Ok(())
    }
}

/// Exact source row count for one schema-selected table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteSnapshotTableCount {
    /// Compiled production table identifier, without source row or key values.
    pub table: String,
    /// Number of rows visible in the reader's pinned transaction.
    pub rows: u64,
}

/// Successful source checks and counts from one consistent read transaction.
///
/// Construction is private: this report is returned only after SQLite's full
/// integrity check, compiled CHECK expressions and declared foreign keys pass,
/// and every validated table
/// is counted. It does not prove exported rows or application/provider closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteSnapshotSourceAudit {
    table_counts: Vec<SqliteSnapshotTableCount>,
    progress_callbacks: u64,
    checked_expressions: usize,
}

impl SqliteSnapshotSourceAudit {
    /// Returns the number of compiled CHECK expressions evaluated successfully.
    pub fn checked_expressions(&self) -> usize {
        self.checked_expressions
    }

    /// Borrows exact counts in the reader's validated catalogue order.
    pub fn table_counts(&self) -> &[SqliteSnapshotTableCount] {
        &self.table_counts
    }

    /// Returns observed progress callbacks for this audit's SQL work.
    ///
    /// This approximate VM-work measure is neither a provider byte counter nor
    /// a physical I/O or CPU accounting receipt.
    pub fn progress_callbacks(&self) -> u64 {
        self.progress_callbacks
    }
}

impl SqliteSnapshotReader {
    /// Checks source integrity, declared constraints and every table's row count.
    ///
    /// All queries use this reader's existing pinned transaction and contain no
    /// caller-supplied SQL. Integrity/constraint diagnostics are reduced to booleans in
    /// SQLite; source row/key values are never fetched into error messages.
    /// Successful return preserves the same reader and snapshot for enumeration.
    ///
    /// This consumes the reader so failure or future cancellation cannot leave
    /// a reusable partially checked source. Dropping the future signals the
    /// progress handler to interrupt pending VM execution and drops the pinned
    /// transaction. Blocking filesystem work may delay that interruption.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits, exhausted work/time budgets, source corruption,
    /// broken declared foreign keys, invalid counts or SQL/connection failures.
    /// Errors omit SQLite diagnostics and source values. No partial report is
    /// returned and the consumed reader is released on failure.
    pub async fn audit_source(
        mut self,
        limits: SqliteSnapshotAuditLimits,
    ) -> Result<(Self, SqliteSnapshotSourceAudit)> {
        limits.validate()?;
        let budget = AuditBudget::new(limits)?;
        {
            let mut handle = self
                .transaction
                .lock_handle()
                .await
                .map_err(|_| anyhow::anyhow!("snapshot audit connection is unavailable"))?;
            let active = Arc::clone(&budget.active);
            let callbacks = Arc::clone(&budget.callbacks);
            let deadline = budget.deadline;
            #[cfg(test)]
            let mut started = self.audit_progress_started.take();
            #[cfg(test)]
            let pause_at_progress = self.audit_pause_at_progress;
            handle.set_progress_handler(PROGRESS_INTERVAL, move || {
                #[cfg(test)]
                if let Some(started) = started.take() {
                    let _ = started.send(());
                    // The cancellation regression waits inside a real SQLite
                    // callback until its owning public future has been dropped.
                    if pause_at_progress {
                        while active.load(Ordering::Acquire) && Instant::now() < deadline {
                            std::thread::yield_now();
                        }
                    }
                }
                let previous = callbacks.fetch_add(1, Ordering::Relaxed);
                active.load(Ordering::Acquire)
                    && previous < limits.max_progress_callbacks
                    && Instant::now() < deadline
            });
        }

        budget.check()?;
        // The table-valued PRAGMA's argument selects a table, not an error cap.
        // Use its full-database form. Limit diagnostic rows in SQL; acceptance
        // still requires the single "ok" row from a complete successful scan.
        let integrity_ok: i64 = sqlx::query_scalar(
            "SELECT CASE WHEN COUNT(*) = 1
             AND COALESCE(MAX(integrity_check = 'ok' COLLATE BINARY), 0) = 1
             THEN 1 ELSE 0 END
             FROM (SELECT integrity_check FROM pragma_integrity_check LIMIT 2)",
        )
        .fetch_one(&mut *self.transaction)
        .await
        .map_err(|_| anyhow::anyhow!("snapshot source integrity check failed"))?;
        budget.check()?;
        ensure!(integrity_ok == 1, "snapshot source integrity check failed");

        // SQLite drops CHECK trees when parsing a read-only schema. Evaluate
        // expressions from the independently compiled catalogue instead; the
        // exact schema comparison has already rejected altered source DDL.
        let mut checked_expressions = 0usize;
        for (table, expressions) in &self.compiled_checks {
            budget.check()?;
            let predicates = expressions
                .iter()
                .map(|expression| format!("NOT(\n{expression}\n)"))
                .collect::<Vec<_>>()
                .join(" OR ");
            // NULL passes a CHECK. WHERE selects only false expressions via
            // NOT, and newlines keep trailing SQL comments inside the wrapper.
            let sql = format!(
                "SELECT EXISTS(SELECT 1 FROM {} WHERE {predicates} LIMIT 1)",
                quote_identifier(table)
            );
            let broken_check: i64 = sqlx::query_scalar(&sql)
                .fetch_one(&mut *self.transaction)
                .await
                .map_err(|_| anyhow::anyhow!("snapshot source integrity check failed"))?;
            budget.check()?;
            ensure!(broken_check == 0, "snapshot source integrity check failed");
            checked_expressions += expressions.len();
        }

        let broken_foreign_key: i64 =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check LIMIT 1)")
                .fetch_one(&mut *self.transaction)
                .await
                .map_err(|_| anyhow::anyhow!("snapshot source foreign-key check failed"))?;
        budget.check()?;
        ensure!(
            broken_foreign_key == 0,
            "snapshot source foreign-key check failed"
        );

        let mut table_counts = Vec::with_capacity(self.schema.tables.len());
        for table in &self.schema.tables {
            budget.check()?;
            let sql = format!("SELECT COUNT(*) FROM {}", quote_identifier(&table.name));
            let rows: i64 = sqlx::query_scalar(&sql)
                .fetch_one(&mut *self.transaction)
                .await
                .map_err(|_| anyhow::anyhow!("snapshot source count failed"))?;
            let rows = u64::try_from(rows)
                .map_err(|_| anyhow::anyhow!("snapshot source count is invalid"))?;
            table_counts.push(SqliteSnapshotTableCount {
                table: table.name.clone(),
                rows,
            });
        }
        budget.check()?;
        self.transaction
            .lock_handle()
            .await
            .map_err(|_| anyhow::anyhow!("snapshot audit connection is unavailable"))?
            .remove_progress_handler();

        let audit = SqliteSnapshotSourceAudit {
            table_counts,
            progress_callbacks: budget.callbacks.load(Ordering::Relaxed),
            checked_expressions,
        };
        Ok((self, audit))
    }
}

struct AuditBudget {
    active: Arc<AtomicBool>,
    callbacks: Arc<AtomicU64>,
    deadline: Instant,
    max_callbacks: u64,
}

impl AuditBudget {
    fn new(limits: SqliteSnapshotAuditLimits) -> Result<Self> {
        let deadline = Instant::now()
            .checked_add(limits.max_duration)
            .ok_or_else(|| anyhow::anyhow!("snapshot audit deadline is invalid"))?;
        Ok(Self {
            active: Arc::new(AtomicBool::new(true)),
            callbacks: Arc::new(AtomicU64::new(0)),
            deadline,
            max_callbacks: limits.max_progress_callbacks,
        })
    }

    fn check(&self) -> Result<()> {
        ensure!(
            self.callbacks.load(Ordering::Relaxed) <= self.max_callbacks
                && Instant::now() < self.deadline,
            "snapshot source audit budget exhausted"
        );
        Ok(())
    }
}

impl Drop for AuditBudget {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

#[cfg(test)]
#[path = "source_audit/tests.rs"]
mod tests;
