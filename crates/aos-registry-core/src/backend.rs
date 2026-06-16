//! The async database backend trait and the helpers its drivers share.
//!
//! [`Backend`] is the narrow waist between the hub's `Database` methods and the
//! SQL engines. It is **async** (RFC-0004 Phase 5): a concrete driver runs
//! every query over its own connection — `sqlx` pools for the native hub, the
//! Cloudflare D1 bindings for the Worker — so one `Database` implementation
//! serves sqlite, postgres, mysql, and D1. Each driver applies
//! [`Dialect::translate`](crate::dialect::Dialect::translate) (via [`prepare`])
//! before handing SQL to its engine.
//!
//! # Operations
//!
//! ```text
//! execute(sql, params).await        -> rows affected          (INSERT/UPDATE/DELETE)
//! execute_insert(sql, params).await -> last auto-increment id (INSERT into an `id` table)
//! query(sql, params).await          -> Vec<Row>               (SELECT, or *_RETURNING)
//! query_opt(sql, params).await      -> Option<Row>            (0-or-1-row SELECT)
//! execute_batch(ddl).await          -> ()                     (migration scripts)
//! batch(&[Statement]).await         -> ()                     (one atomic transaction)
//! ```
//!
//! `execute_insert` abstracts away sqlite's `last_insert_rowid()`: postgres
//! has no equivalent, so a driver appends `RETURNING id` (see
//! [`with_returning_id`]) and reads the value back (every hub auto-increment
//! table names its key `id`); mysql reads `last_insert_id()` from the result.
//!
//! [`Backend::batch`] runs a fixed statement list as one atomic unit, so the
//! multi-row writes (`apply_snapshot`, `record_validation_run`, `rotate_token`,
//! …) commit atomically on every engine. The few read-then-write sites that
//! sqlite/postgres express as a single guarded `RETURNING`/upsert run as
//! sequential claim-gated statements on mysql.
//!
//! This module is engine-neutral: it owns the trait, the [`Statement`] unit of
//! atomic work, and the [`split_statements`]/[`with_returning_id`]/[`prepare`]
//! helpers every driver reuses. The concrete drivers live in the deployment
//! crates (`SqlxBackend` in the native hub, the D1 backend in the Worker).

use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::dialect::{order_params, Dialect};
use crate::value::{Row, Value};

/// One statement in a [`Backend::batch`]: source SQL and its bound parameters.
///
/// A batch is the portable unit of atomic multi-statement work. The native
/// backends run it inside a SQL transaction; Cloudflare D1 runs it as
/// `batch().await` — its *only* atomicity primitive, since it has no interactive
/// transactions. Because a batch cannot read a value back mid-flight, every
/// statement must be self-contained: ids are assigned client-side rather than
/// read from `last_insert_rowid`, and any guard is encoded in a `WHERE` clause
/// rather than a read-then-branch. This is the seam the unified
/// native/Cloudflare runtime is built on (RFC-0004 Phase 5).
#[derive(Debug, Clone)]
pub struct Statement {
    /// The source SQL, in the sqlite dialect the `Database` methods write; each
    /// backend translates it via [`Dialect`] before running.
    pub sql: String,
    /// The parameters bound to `sql`, in `?1`/`?2`… order.
    pub params: Vec<Value>,
}

impl Statement {
    /// Builds a [`Statement`] from source SQL and its bound parameters.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let s = Statement::new("DELETE FROM sessions WHERE id = ?1", vals![id]);
    /// ```
    pub fn new(sql: impl Into<String>, params: Vec<Value>) -> Self {
        Self {
            sql: sql.into(),
            params,
        }
    }
}

/// An async handle to one SQL engine.
///
/// Implementors own their connection and translate the hub's source SQL with
/// their [`Backend::dialect`] before executing. All methods take the source
/// (sqlite-flavored) SQL the `Database` methods write.
///
/// The trait is **async** (RFC-0004 Phase 5): every query is a future driven on
/// the host runtime by the underlying engine.
#[async_trait]
pub trait Backend: Send + Sync {
    /// The SQL dialect this backend speaks.
    fn dialect(&self) -> Dialect;

    /// Runs a non-`SELECT` statement, returning the number of rows affected.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails.
    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64>;

    /// Runs an `INSERT` and returns the new row's auto-increment id.
    ///
    /// The target table must have an `id` integer primary key (every hub
    /// auto-increment table does); on postgres the driver appends
    /// `RETURNING id`.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails, or the id cannot
    /// be read back.
    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64>;

    /// Runs a `SELECT` (or a `… RETURNING`) statement, returning all rows.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails.
    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>>;

    /// Runs a statement expected to yield at most one row.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails, or if more than
    /// one row is returned.
    async fn query_opt(&self, sql: &str, params: &[Value]) -> Result<Option<Row>> {
        let mut rows = self.query(sql, params).await?;
        if rows.len() > 1 {
            anyhow::bail!("query_opt expected at most one row, got {}", rows.len());
        }
        Ok(rows.pop())
    }

    /// Applies a multi-statement DDL script (a migration), translating each
    /// statement for this dialect.
    ///
    /// # Errors
    ///
    /// Returns an error if any statement fails to translate or execute.
    async fn execute_batch(&self, sql: &str) -> Result<()>;

    /// Runs `stmts` as one atomic unit — either all commit, or none do.
    ///
    /// This is the *portable* transaction primitive: a fixed, self-contained
    /// statement list with no mid-flight reads or `last_insert_rowid`
    /// round-trips. The native backend runs it inside one real SQL transaction
    /// (`begin` / per-statement `execute` / `commit`); D1 runs it as a single
    /// `batch()`.
    ///
    /// # Errors
    ///
    /// Returns an error if any statement fails to translate or execute; the
    /// whole batch is then rolled back.
    async fn batch(&self, stmts: &[Statement]) -> Result<()>;
}

/// Splits a multi-statement DDL script into individual statements at
/// top-level semicolons.
///
/// Semicolons inside `'…'` string literals and `-- …` line comments are
/// ignored, since the hub's migration DDL carries `;` in both (a default
/// string value, a `--` comment). The migrations use no `BEGIN … END` blocks,
/// so statement-level `;` splitting is otherwise sufficient. Trailing
/// whitespace-only fragments are dropped.
pub fn split_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut in_line_comment = false;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if in_line_comment {
            current.push(c);
            if c == '\n' {
                in_line_comment = false;
            }
            continue;
        }
        if in_string {
            current.push(c);
            if c == '\'' {
                in_string = false;
            }
            continue;
        }
        match c {
            '\'' => {
                in_string = true;
                current.push(c);
            }
            '-' if chars.peek() == Some(&'-') => {
                in_line_comment = true;
                current.push(c);
            }
            ';' => {
                let stmt = current.trim();
                if !stmt.is_empty() {
                    out.push(stmt.to_string());
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    let tail = current.trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out
}

/// Appends `RETURNING id` to an `INSERT` that lacks an explicit `RETURNING`.
///
/// Used by the postgres driver's `execute_insert`. Idempotent: an `INSERT`
/// that already names a `RETURNING` clause is left untouched.
pub fn with_returning_id(sql: &str) -> String {
    if sql.to_ascii_uppercase().contains("RETURNING") {
        sql.to_string()
    } else {
        format!("{} RETURNING id", sql.trim_end().trim_end_matches(';'))
    }
}

/// Translates `sql` for `dialect` and returns `(translated_sql, ordered_params)`.
///
/// Shared by every driver: it applies
/// [`Dialect::translate`](crate::dialect::Dialect::translate) and reorders the
/// caller's parameters for positional (mysql) placeholders.
///
/// # Errors
///
/// Returns an error if translation fails.
pub fn prepare(dialect: Dialect, sql: &str, params: &[Value]) -> Result<(String, Vec<Value>)> {
    let translated = dialect
        .translate(sql)
        .with_context(|| format!("translating SQL for {dialect:?}"))?;
    // sqlite and postgres keep *numbered* placeholders, so the engine binds
    // each `?N`/`$N` to the caller's Nth parameter regardless of textual
    // order — the parameter slice is passed through unchanged. Only mysql's
    // positional `?` needs the placeholders' source indices materialized into
    // an ordered (and possibly reused-expanded) parameter list.
    let ordered = match dialect {
        Dialect::Mysql => order_params(params, &translated.param_order),
        Dialect::Sqlite | Dialect::Postgres => params.to_vec(),
    };
    Ok((translated.sql, ordered))
}
