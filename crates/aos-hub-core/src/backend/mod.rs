//! The async database backend trait and the helpers its drivers share.
//!
//! [`Backend`] is the narrow waist between the hub's `Database` methods and the
//! SQL engines. It is **async** (RFC-0004 Phase 5): a concrete driver runs
//! every query over its own connection — `sqlx` pools for the native hub and
//! the `HubDb` Durable Object's colocated SQLite for the Worker — so one
//! `Database` implementation serves both runtimes. Each driver applies
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
//! checked_batch(&[CheckedStatement])-> ()                     (atomic row-count assertions)
//! ```
//!
//! `execute_insert` abstracts away sqlite's `last_insert_rowid()`: postgres
//! has no equivalent, so a driver appends `RETURNING id` (see
//! [`with_returning_id`]) and reads the value back (every hub auto-increment
//! table names its key `id`); mysql reads `last_insert_id()` from the result.
//!
//! [`Backend::batch`] runs a fixed statement list as one atomic unit, while
//! [`Backend::checked_batch`] additionally rolls the transaction back when a
//! guarded statement affects an unexpected number of rows. Multi-row writes
//! therefore commit atomically on every engine, including optimistic-CAS
//! workflows whose correctness depends on a one-row mutation.
//!
//! This module is engine-neutral: it owns the trait, the [`Statement`] unit of
//! atomic work, and the [`split_statements`]/[`with_returning_id`]/[`prepare`]
//! helpers every driver reuses. The concrete drivers live in the deployment
//! crates (`SqlxBackend` in the native hub, the `HubDb` bridge in the Worker).

use anyhow::{Context, Result};

use crate::dialect::{order_params, Dialect};
use crate::value::{Row, Value};

/// The marker bounds the [`Backend`] trait carries, which differ by target.
///
/// On a native build a `Backend` (and therefore the [`Database`](crate::db::Database)
/// that holds one) must be `Send + Sync` so the multi-threaded tokio server can
/// move request futures across worker threads. On `wasm32-unknown-unknown` the
/// Cloudflare Worker is single-threaded and its runtime futures are `!Send`, so the
/// bound is dropped there. This blanket-impl alias lets the one [`Backend`]
/// definition carry the right bound on each target.
#[cfg(not(target_arch = "wasm32"))]
pub trait BackendBounds: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> BackendBounds for T {}
/// See the native definition above — unbounded on wasm32 (single-threaded Worker).
#[cfg(target_arch = "wasm32")]
pub trait BackendBounds {}
#[cfg(target_arch = "wasm32")]
impl<T> BackendBounds for T {}

/// One statement in a [`Backend::batch`]: source SQL and its bound parameters.
///
/// A batch is the portable unit of atomic multi-statement work. The native
/// backends run it inside a SQL transaction; the Worker bridge sends the whole
/// batch to `HubDb` as one operation. Because a batch cannot read a value back
/// mid-flight, every
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

    /// Requires this statement to affect exactly `expected_rows` in a checked batch.
    #[must_use]
    pub fn expecting(self, expected_rows: u64) -> CheckedStatement {
        CheckedStatement {
            statement: self,
            expected_rows: Some(expected_rows),
        }
    }

    /// Includes this statement in a checked batch without a row-count assertion.
    #[must_use]
    pub fn unchecked(self) -> CheckedStatement {
        CheckedStatement {
            statement: self,
            expected_rows: None,
        }
    }
}

/// One atomic batch statement with an optional affected-row assertion.
///
/// A mismatch is a transaction error, not a post-commit diagnostic. Native
/// backends roll the transaction back and the Worker propagates the error from
/// its runtime-atomic database turn. CAS workflows use this type so a guarded
/// zero-row write cannot leave earlier statements committed.
#[derive(Debug, Clone)]
pub struct CheckedStatement {
    /// Statement to execute.
    pub statement: Statement,
    /// Required affected-row count, or `None` when the statement is auxiliary.
    pub expected_rows: Option<u64>,
}

impl CheckedStatement {
    /// Builds a statement that must affect exactly `expected_rows`.
    #[must_use]
    pub fn exact(sql: impl Into<String>, params: Vec<Value>, expected_rows: u64) -> Self {
        Statement::new(sql, params).expecting(expected_rows)
    }

    /// Builds an auxiliary statement without an affected-row assertion.
    #[must_use]
    pub fn unchecked(sql: impl Into<String>, params: Vec<Value>) -> Self {
        Statement::new(sql, params).unchecked()
    }
}

/// An async handle to one SQL engine.
///
/// Implementors own their connection and translate the hub's source SQL with
/// their [`Backend::dialect`] before executing. All methods take the source
/// (sqlite-flavored) SQL the `Database` methods write.
///
/// The trait is **async** (RFC-0004 Phase 5): every query is a future driven on
/// the host runtime by the underlying engine. It is `Send`-bounded on native
/// (via [`BackendBounds`]) and `?Send` on the single-threaded Worker.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait Backend: BackendBounds {
    /// The SQL dialect this backend speaks.
    fn dialect(&self) -> Dialect;

    /// Runs a non-`SELECT` statement, returning the number of rows affected.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails.
    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64>;

    /// Runs a non-`SELECT` statement without requiring its affected-row count.
    ///
    /// The default delegates to [`Backend::execute`]. Backends for which
    /// obtaining an exact row count requires another database statement may
    /// override this method to avoid that work. Callers must use
    /// [`Backend::execute`] or [`Backend::checked_batch`] whenever correctness
    /// depends on the number of affected rows.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails.
    async fn execute_discarding_count(&self, sql: &str, params: &[Value]) -> Result<()> {
        self.execute(sql, params).await?;
        Ok(())
    }

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
    /// (`begin` / per-statement `execute` / `commit`); HubDb runs it as a single
    /// `batch()`.
    ///
    /// # Errors
    ///
    /// Returns an error if any statement fails to translate or execute; the
    /// whole batch is then rolled back.
    async fn batch(&self, stmts: &[Statement]) -> Result<()>;

    /// Applies a version-guarded migration batch atomically.
    ///
    /// Backends that can have concurrent starters should override this to lock
    /// the schema-version row before deciding whether `stmts` still apply. The
    /// default is sufficient for single-writer transactional backends such as
    /// a Durable Object.
    ///
    /// # Errors
    ///
    /// Returns an error when the migration batch fails.
    async fn migration_batch(
        &self,
        _expected_current: i64,
        _target: i64,
        stmts: &[Statement],
    ) -> Result<()> {
        self.batch(stmts).await
    }

    /// Runs an atomic batch and rolls it back when an affected-row assertion fails.
    ///
    /// # Errors
    ///
    /// Returns an error when translation/execution fails or a statement's
    /// affected-row count differs from [`CheckedStatement::expected_rows`].
    async fn checked_batch(&self, stmts: &[CheckedStatement]) -> Result<()>;
}

/// Splits a multi-statement DDL script into individual statements at
/// top-level semicolons.
///
/// Semicolons inside `'…'` string literals and `-- …` line comments are
/// ignored, since the hub's migration DDL carries `;` in both (a default
/// string value, a `--` comment). The migrations use no `BEGIN … END` blocks,
/// so statement-level `;` splitting is otherwise sufficient. Fragments that
/// carry no executable SQL — only whitespace and `--` line comments, e.g. a
/// trailing inline comment left after the final `;` — are dropped, since a
/// backend such as Durable Object SQLite rejects a comment-only prepared statement ("SQL code did
/// not contain a statement").
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
                if has_sql(&current) {
                    out.push(current.trim().to_string());
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if has_sql(&current) {
        out.push(current.trim().to_string());
    }
    out
}

/// Returns `true` when `fragment` carries at least one character of executable
/// SQL — i.e. something other than whitespace and `--` line comments.
///
/// Used by [`split_statements`] to drop comment-only fragments (such as a
/// trailing inline comment after the final `;`) that a backend would
/// reject with "SQL code did not contain a statement". A `--` inside a string
/// literal can cause a false positive (the fragment is reported as having SQL),
/// which is harmless: a fragment containing a real statement is exactly what we
/// want to keep.
fn has_sql(fragment: &str) -> bool {
    fragment
        .lines()
        .any(|line| !line.split("--").next().unwrap_or("").trim().is_empty())
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

// The concrete native driver runs every query over a `sqlx` connection pool.
// It is the hub's backend (and the CLI's); the Cloudflare Worker supplies a HubDb
// `Backend` instead. `sqlx` is a native-only dependency — it does not build for
// `wasm32-unknown-unknown` — so the driver and its connection-URL helper are
// compiled out of the Worker target (RFC-0004 Phase 5).
#[cfg(not(target_arch = "wasm32"))]
mod sqlx;
#[cfg(not(target_arch = "wasm32"))]
pub use sqlx::SqlxBackend;

// Per-statement query timing (RFC-0004 ch.14 Phase A): a `Backend` decorator
// that records each statement's wall-clock duration for a `Server-Timing`
// header, so the per-request Worker database cost is measurable at the call site.
// Feature-gated (`query-timing`, off by default) so production pays nothing.
#[cfg(feature = "query-timing")]
mod timing;
#[cfg(feature = "query-timing")]
pub use timing::{QuerySpan, QueryTimings, TimingBackend};

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
/// ```text
/// // Illustrative only; `redact_db_url` is crate-private.
/// redact_db_url("postgresql://app:s3cret@db.internal/hub")
///   == "postgresql://app:***@db.internal/hub"
/// ```
#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{
        prepare, redact_db_url, split_statements, Backend, CheckedStatement, SqlxBackend, Statement,
    };
    use crate::dialect::Dialect;
    use crate::value::Value;

    #[test]
    fn split_statements_drops_trailing_inline_comment() {
        // An inline `--` comment carrying its own `;` after the statement's
        // terminator must not yield a comment-only fragment (HubDb rejects one with
        // "SQL code did not contain a statement"). Mirrors the v8 migration.
        let sql = "ALTER TABLE t ADD COLUMN c TEXT; -- a note (with; a semicolon)\n";
        let stmts = split_statements(sql);
        assert_eq!(stmts, vec!["ALTER TABLE t ADD COLUMN c TEXT".to_string()]);
    }

    #[test]
    fn split_statements_keeps_statements_with_embedded_comments() {
        // A comment *within* a real statement is retained (the statement still
        // has executable SQL); only purely-comment fragments are dropped.
        let sql = "CREATE TABLE t ( id INTEGER -- the id\n ); -- trailing\n";
        let stmts = split_statements(sql);
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("CREATE TABLE t"));
    }

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

    #[tokio::test]
    async fn checked_batch_rolls_back_on_an_affected_row_mismatch() {
        let backend = batch_fixture().await;
        let error = backend
            .checked_batch(&[
                CheckedStatement::exact(
                    "INSERT INTO t (id, v) VALUES (?1, ?2)",
                    vec![Value::Int(1), Value::Text("a".into())],
                    1,
                ),
                CheckedStatement::exact(
                    "UPDATE t SET v = ?2 WHERE id = ?1",
                    vec![Value::Int(99), Value::Text("missing".into())],
                    1,
                ),
            ])
            .await;
        assert!(error.is_err(), "a row-count mismatch aborts the batch");
        let rows = backend.query("SELECT id FROM t", &[]).await.unwrap();
        assert!(rows.is_empty(), "the earlier insert was rolled back");
    }

    #[test]
    fn checked_cas_statements_prepare_portably_for_every_dialect() {
        let sql = "UPDATE grants SET state = ?2, resource_version = resource_version + 1
                   WHERE id = ?1 AND resource_version = ?3 AND state = ?4";
        let params = vec![
            Value::Text("grant:one".into()),
            Value::Text("revoked".into()),
            Value::Int(7),
            Value::Text("active".into()),
        ];
        let (sqlite_sql, sqlite_params) = prepare(Dialect::Sqlite, sql, &params).unwrap();
        assert!(sqlite_sql.contains("state = ?2"));
        assert_eq!(sqlite_params, params);
        let (postgres_sql, postgres_params) = prepare(Dialect::Postgres, sql, &params).unwrap();
        assert!(postgres_sql.contains("state = $2"));
        assert_eq!(postgres_params, params);
        let (mysql_sql, mysql_params) = prepare(Dialect::Mysql, sql, &params).unwrap();
        assert!(!mysql_sql.contains("?1"));
        assert_eq!(
            mysql_params,
            vec![
                Value::Text("revoked".into()),
                Value::Text("grant:one".into()),
                Value::Int(7),
                Value::Text("active".into()),
            ]
        );
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
