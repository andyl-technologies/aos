//! The async database backend trait and its per-engine drivers.
//!
//! [`Backend`] is the narrow waist between the hub's
//! [`Database`](crate::db::Database) methods and the SQL engines. It is
//! **async** (RFC-0004 Phase 5): the single [`SqlxBackend`] implementation runs
//! every query over a concrete `sqlx` connection pool, so one `Database`
//! implementation serves sqlite, postgres, and mysql. Each engine arm applies
//! [`Dialect::translate`] before handing SQL to its pool.
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
//! has no equivalent, so the driver appends `RETURNING id` and reads the
//! value back (every hub auto-increment table names its key `id`); mysql reads
//! `last_insert_id()` from the result.
//!
//! [`Backend::batch`] runs a fixed statement list inside one real `sqlx`
//! transaction, so the multi-row writes (`apply_snapshot`,
//! `record_validation_run`, `rotate_token`, …) commit atomically on every
//! engine. The few read-then-write sites that sqlite/postgres express as a
//! single guarded `RETURNING`/upsert run as sequential claim-gated statements
//! on mysql (see [`Database`](crate::db::Database)).
//!
//! Only [`SqlxBackend::Sqlite`] is compiled by default; the postgres and mysql
//! arms are gated behind the `postgres` and `mysql` cargo features, keeping the
//! default build free of those `sqlx` drivers.

use anyhow::{Context, Result};
use async_trait::async_trait;

use super::dialect::{order_params, Dialect};
use super::value::{Row, Value};

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
    /// The source SQL, in the sqlite dialect the [`Database`](crate::db::Database)
    /// methods write; each backend translates it via [`Dialect`] before running.
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
/// Implementors own their connection pool and translate the hub's source SQL
/// with their [`Backend::dialect`] before executing. All methods take the
/// source (sqlite-flavored) SQL the [`Database`](crate::db::Database) methods
/// write.
///
/// The trait is **async** (RFC-0004 Phase 5): every query is a future driven on
/// the existing tokio runtime by the underlying `sqlx` pool.
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
    /// round-trips. [`SqlxBackend`] runs it inside one real `sqlx` transaction
    /// (`begin` / per-statement `execute` / `commit`).
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
#[cfg_attr(not(any(feature = "postgres", feature = "mysql")), allow(dead_code))]
pub(crate) fn split_statements(sql: &str) -> Vec<String> {
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

mod sqlx;
pub use sqlx::SqlxBackend;

/// Appends `RETURNING id` to an `INSERT` that lacks an explicit `RETURNING`.
///
/// Used by the postgres driver's `execute_insert`. Idempotent: an `INSERT`
/// that already names a `RETURNING` clause is left untouched.
#[cfg_attr(not(feature = "postgres"), allow(dead_code))]
pub(crate) fn with_returning_id(sql: &str) -> String {
    if sql.to_ascii_uppercase().contains("RETURNING") {
        sql.to_string()
    } else {
        format!("{} RETURNING id", sql.trim_end().trim_end_matches(';'))
    }
}

/// Redacts the password from a `postgres://`/`mysql://` connection URL so it
/// is safe to embed in an error chain or log line.
///
/// A connection URL is `scheme://user:PASSWORD@host:port/db?…`, and the
/// password is a long-lived database secret. Connection failures are logged
/// with the URL as context (`connecting to postgres …`), so the raw form would
/// leak the credential into the hub's logs. This replaces the password
/// component with `***` while preserving every other part (user, host, port,
/// database, query) so the redacted form remains diagnostically useful.
///
/// When the input does not parse as a URL — or carries no password — it is
/// returned unchanged, since there is no credential to strip. The fallback is
/// safe because a non-URL string never contains the `user:password@` userinfo
/// shape this guards against.
///
/// # Examples
///
/// ```no_run
/// # // Illustrative only; `redact_db_url` is crate-private.
/// // redact_db_url("postgresql://app:s3cret@db.internal/hub")
/// //   == "postgresql://app:***@db.internal/hub"
/// ```
#[cfg_attr(not(any(feature = "postgres", feature = "mysql")), allow(dead_code))]
pub(crate) fn redact_db_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) if parsed.password().is_some() => {
            // `set_password` only fails for URLs that cannot have credentials
            // (e.g. those without a host); for those we fall through to the
            // original string, which by construction carries no userinfo.
            if parsed.set_password(Some("***")).is_ok() {
                parsed.into()
            } else {
                url.to_string()
            }
        }
        _ => url.to_string(),
    }
}

/// Translates `sql` for `dialect` and returns `(translated_sql, ordered_params)`.
///
/// Shared by every driver: it applies [`Dialect::translate`] and reorders the
/// caller's parameters for positional (mysql) placeholders.
///
/// # Errors
///
/// Returns an error if translation fails.
pub(crate) fn prepare(
    dialect: Dialect,
    sql: &str,
    params: &[Value],
) -> Result<(String, Vec<Value>)> {
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

#[cfg(test)]
mod tests {
    use super::{redact_db_url, Backend, SqlxBackend, Statement};
    use crate::db::value::Value;

    /// An in-memory sqlite backend with a single `t(id, v)` table for batch tests.
    async fn batch_fixture() -> SqlxBackend {
        let backend = SqlxBackend::connect_sqlite(":memory:")
            .await
            .expect("open in-memory sqlite");
        backend
            .execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL);")
            .await
            .expect("create table");
        backend
    }

    #[tokio::test]
    async fn batch_commits_all_statements_atomically() {
        let backend = batch_fixture().await;
        backend
            .batch(&[
                Statement::new(
                    "INSERT INTO t (id, v) VALUES (?1, ?2)",
                    vec![Value::Int(1), Value::Text("a".into())],
                ),
                Statement::new(
                    "INSERT INTO t (id, v) VALUES (?1, ?2)",
                    vec![Value::Int(2), Value::Text("b".into())],
                ),
            ])
            .await
            .expect("batch commits");
        let rows = backend
            .query("SELECT id FROM t ORDER BY id", &[])
            .await
            .unwrap();
        assert_eq!(rows.len(), 2, "both rows committed");
    }

    #[tokio::test]
    async fn batch_rolls_back_on_a_failing_statement() {
        let backend = batch_fixture().await;
        let err = backend
            .batch(&[
                Statement::new(
                    "INSERT INTO t (id, v) VALUES (?1, ?2)",
                    vec![Value::Int(1), Value::Text("a".into())],
                ),
                // NOT NULL violation: the whole batch must roll back.
                Statement::new(
                    "INSERT INTO t (id, v) VALUES (?1, NULL)",
                    vec![Value::Int(2)],
                ),
            ])
            .await;
        assert!(err.is_err(), "a failing statement aborts the batch");
        let rows = backend.query("SELECT id FROM t", &[]).await.unwrap();
        assert!(rows.is_empty(), "the first insert was rolled back");
    }

    #[test]
    fn redact_db_url_strips_password() {
        let redacted = redact_db_url("postgresql://user:secret@host/db");
        assert!(
            !redacted.contains("secret"),
            "password must not survive redaction: {redacted}"
        );
        assert_eq!(redacted, "postgresql://user:***@host/db");
    }

    #[test]
    fn redact_db_url_preserves_non_secret_parts() {
        let redacted = redact_db_url("mysql://app:p%40ss@db.internal:3306/hub?ssl-mode=required");
        assert!(!redacted.contains("p%40ss") && !redacted.contains("p@ss"));
        assert!(redacted.contains("app@") || redacted.contains("app:***@"));
        assert!(redacted.contains("db.internal:3306"));
        assert!(redacted.contains("hub"));
        assert!(redacted.contains("ssl-mode=required"));
    }

    #[test]
    fn redact_db_url_passes_through_without_password() {
        // No userinfo password: nothing to strip, returned (parse-normalized)
        // without inventing a credential.
        let redacted = redact_db_url("postgres://host/db");
        assert!(!redacted.contains("***"));
        assert!(redacted.contains("host"));
        // A non-URL string is returned verbatim (no credential shape).
        assert_eq!(redact_db_url("not a url"), "not a url");
    }
}
