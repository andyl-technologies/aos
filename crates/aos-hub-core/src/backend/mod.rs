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

use crate::dialect::{order_params, Dialect};
use crate::value::{Row, Value};

/// The marker bounds the [`Backend`] trait carries, which differ by target.
///
/// On a native build a `Backend` (and therefore the [`Database`](crate::db::Database)
/// that holds one) must be `Send + Sync` so the multi-threaded tokio server can
/// move request futures across worker threads. On `wasm32-unknown-unknown` the
/// Cloudflare Worker is single-threaded and its D1 futures are `!Send`, so the
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
/// so statement-level `;` splitting is otherwise sufficient. Fragments that
/// carry no executable SQL — only whitespace and `--` line comments, e.g. a
/// trailing inline comment left after the final `;` — are dropped, since a
/// backend such as D1 rejects a comment-only prepared statement ("SQL code did
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
/// trailing inline comment after the final `;`) that a backend like D1 would
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
// It is the hub's backend (and the CLI's); the Cloudflare Worker supplies a D1
// `Backend` instead. `sqlx` is a native-only dependency — it does not build for
// `wasm32-unknown-unknown` — so the driver and its connection-URL helper are
// compiled out of the Worker target (RFC-0004 Phase 5).
#[cfg(not(target_arch = "wasm32"))]
mod sqlx;
#[cfg(not(target_arch = "wasm32"))]
pub use sqlx::SqlxBackend;

// Per-statement query timing (RFC-0004 ch.14 Phase A): a `Backend` decorator
// that records each statement's wall-clock duration for a `Server-Timing`
// header, so the per-request D1 session cost is measurable at the call site.
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
    use super::{redact_db_url, split_statements, Backend, SqlxBackend, Statement};
    use crate::value::Value;

    #[test]
    fn split_statements_drops_trailing_inline_comment() {
        // An inline `--` comment carrying its own `;` after the statement's
        // terminator must not yield a comment-only fragment (D1 rejects one with
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
