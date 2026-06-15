//! The synchronous database backend trait and its per-engine drivers.
//!
//! [`Backend`] is the narrow waist between the hub's
//! [`Database`](crate::db::Database) methods and the three SQL engines. It is
//! deliberately **synchronous** — the hub's connection model is a
//! `Mutex<Connection>` and every caller is sync, so an async trait would
//! cascade through the whole crate for no benefit. Each driver owns its own
//! connection behind a `Mutex` and applies [`Dialect::translate`] before
//! handing SQL to the engine.
//!
//! # Operations
//!
//! ```text
//! execute(sql, params)        -> rows affected          (INSERT/UPDATE/DELETE)
//! execute_insert(sql, params) -> last auto-increment id (INSERT into an `id` table)
//! query(sql, params)          -> Vec<Row>               (SELECT, or *_RETURNING)
//! query_opt(sql, params)      -> Option<Row>            (0-or-1-row SELECT)
//! execute_batch(ddl)          -> ()                     (migration scripts)
//! with_tx(|tx| …)             -> T                      (a unit of atomic work)
//! ```
//!
//! `execute_insert` abstracts away sqlite's `last_insert_rowid()`: postgres
//! has no equivalent, so the driver appends `RETURNING id` and reads the
//! value back (every hub auto-increment table names its key `id`); mysql uses
//! `LAST_INSERT_ID()`.
//!
//! [`Tx`] mirrors the same operations inside a transaction, so the multi-row
//! writes (`apply_snapshot`, `record_validation_run`, `rotate_token`, …) run
//! atomically on every engine.
//!
//! Only [`SqliteBackend`] is compiled by default. [`PostgresBackend`] and
//! [`MysqlBackend`] are gated behind the `postgres` and `mysql` cargo
//! features respectively, keeping the default build free of their (pure-Rust)
//! driver crates.

use anyhow::{Context, Result};

use super::dialect::{order_params, Dialect};
use super::value::{Row, Value};

/// A synchronous handle to one SQL engine.
///
/// Implementors own their connection and translate the hub's source SQL with
/// their [`Backend::dialect`] before executing. All methods take the source
/// (sqlite-flavored) SQL the [`Database`](crate::db::Database) methods write.
pub trait Backend: Send + Sync {
    /// The SQL dialect this backend speaks.
    fn dialect(&self) -> Dialect;

    /// Runs a non-`SELECT` statement, returning the number of rows affected.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails.
    fn execute(&self, sql: &str, params: &[Value]) -> Result<u64>;

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
    fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64>;

    /// Runs a `SELECT` (or a `… RETURNING`) statement, returning all rows.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails.
    fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>>;

    /// Runs a statement expected to yield at most one row.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails, or if more than
    /// one row is returned.
    fn query_opt(&self, sql: &str, params: &[Value]) -> Result<Option<Row>> {
        let mut rows = self.query(sql, params)?;
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
    fn execute_batch(&self, sql: &str) -> Result<()>;

    /// Runs `f` inside one transaction, committing on `Ok` and rolling back
    /// on `Err`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot begin or commit, or if `f`
    /// returns one (after rollback).
    fn with_tx(&self, f: &mut dyn FnMut(&mut dyn Tx) -> Result<()>) -> Result<()>;

    /// Downcasts to the sqlite driver, for the in-module migration tests that
    /// need raw `rusqlite` access. Non-sqlite backends return `None`.
    #[cfg(test)]
    fn as_sqlite(&self) -> Option<&SqliteBackend> {
        None
    }
}

/// The transaction-scoped subset of [`Backend`] operations.
///
/// A `Tx` is handed to the closure passed to [`Backend::with_tx`]; its writes
/// commit or roll back atomically with the rest of the closure.
pub trait Tx {
    /// Runs a non-`SELECT` statement inside the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails.
    fn execute(&mut self, sql: &str, params: &[Value]) -> Result<u64>;

    /// Runs an `INSERT` inside the transaction, returning the new `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails, or the id cannot
    /// be read back.
    fn execute_insert(&mut self, sql: &str, params: &[Value]) -> Result<i64>;

    /// Runs a `SELECT` (or `… RETURNING`) inside the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails.
    fn query(&mut self, sql: &str, params: &[Value]) -> Result<Vec<Row>>;

    /// Runs a 0-or-1-row statement inside the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if translation or execution fails, or more than one
    /// row is returned.
    fn query_opt(&mut self, sql: &str, params: &[Value]) -> Result<Option<Row>> {
        let mut rows = self.query(sql, params)?;
        if rows.len() > 1 {
            anyhow::bail!("query_opt expected at most one row, got {}", rows.len());
        }
        Ok(rows.pop())
    }
}

/// Splits a multi-statement DDL script into individual statements at
/// top-level semicolons.
///
/// Semicolons inside `'…'` string literals and `-- …` line comments are
/// ignored, since the hub's migration DDL carries `;` in both (a default
/// string value, a `--` comment). The migrations use no `BEGIN … END` blocks,
/// so statement-level `;` splitting is otherwise sufficient. Trailing
/// whitespace-only fragments are dropped.
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

mod sqlite;
pub use sqlite::SqliteBackend;

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "postgres")]
pub use postgres::PostgresBackend;

#[cfg(feature = "mysql")]
mod mysql;
#[cfg(feature = "mysql")]
pub use mysql::MysqlBackend;

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
    use super::redact_db_url;

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
