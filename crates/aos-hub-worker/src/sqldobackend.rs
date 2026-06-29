//! [`SqlDoBackend`]: a [`Backend`] over a Durable Object's **colocated** SQLite
//! (wasm32-only) — the Phase E system-of-record substrate (RFC-0004 ch.14).
//!
//! Phase E moves the relational system of record off D1 (whose queries are *not*
//! colocated with the Worker — the ~120 ms per-request session cost) and into a
//! per-tenant Durable Object whose SQLite storage runs **in the same thread** as
//! the handler. `SqlStorage::exec` is synchronous and local: microsecond reads,
//! no network hop, full SQL, strict serializability. This type adapts that local
//! engine to the shared async [`Backend`] trait, so the *exact* `core::Database`
//! read/write logic the native hub and the D1 Worker run also runs inside the
//! tenant DO — no third reimplementation.
//!
//! It is constructed only **inside** a Durable Object, from
//! `state.storage().sql()`; the request Worker reaches it by routing tenant
//! operations to the DO (Phase E3). Because the engine is local and synchronous,
//! the `async` trait methods complete without awaiting — the future resolves
//! immediately.
//!
//! # Marshalling
//!
//! Parameters cross as [`SqlStorageValue`] (`Null`/`Integer`/`Float`/`String`/
//! `Blob`), the exact shape of a [`Value`]; result rows come back **positionally**
//! from the cursor's `raw()` iterator (a `Vec<SqlStorageValue>` per row) and map
//! column-by-column into a [`Row`]. `execute` reports `rows_written`; an insert's
//! id is read back with `SELECT last_insert_rowid()`; a [`Backend::batch`] runs
//! the statements directly and relies on the DO turn's implicit transaction
//! (Durable Object SQLite forbids an explicit `BEGIN`/`SAVEPOINT`), the
//! local-SQLite analog of D1's atomic `batch()`.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use worker::{SqlStorage, SqlStorageValue};

use aos_hub_core::backend::{prepare, split_statements, Backend, Statement};
use aos_hub_core::dialect::Dialect;
use aos_hub_core::value::{Row, Value};

/// A [`Backend`] over a Durable Object's local SQLite ([`SqlStorage`]).
///
/// Holds the DO's `SqlStorage` handle (obtained from `state.storage().sql()`);
/// every method runs the translated SQL through the local engine. One backend
/// serves one tenant DO's database.
pub struct SqlDoBackend {
    sql: SqlStorage,
}

impl SqlDoBackend {
    /// Wraps a Durable Object's [`SqlStorage`] handle as a [`Backend`].
    #[must_use]
    pub fn new(sql: SqlStorage) -> SqlDoBackend {
        SqlDoBackend { sql }
    }
}

/// Converts a bound [`Value`] into the [`SqlStorageValue`] the DO engine binds.
fn to_sql(value: &Value) -> SqlStorageValue {
    match value {
        Value::Null => SqlStorageValue::Null,
        Value::Int(n) => SqlStorageValue::Integer(*n),
        Value::Real(f) => SqlStorageValue::Float(*f),
        Value::Text(s) => SqlStorageValue::String(s.clone()),
        Value::Bytes(b) => SqlStorageValue::Blob(b.clone()),
    }
}

/// Converts a result-row [`SqlStorageValue`] back into a [`Value`].
fn from_sql(value: SqlStorageValue) -> Value {
    match value {
        SqlStorageValue::Null => Value::Null,
        SqlStorageValue::Integer(n) => Value::Int(n),
        SqlStorageValue::Float(f) => Value::Real(f),
        SqlStorageValue::String(s) => Value::Text(s),
        SqlStorageValue::Blob(b) => Value::Bytes(b),
        // SQLite has no native boolean, but the binding surfaces one; store it
        // as the 0/1 integer the schema uses (mirrors the D1 backend).
        SqlStorageValue::Boolean(b) => Value::Int(i64::from(b)),
    }
}

impl SqlDoBackend {
    /// Translates + binds `sql`/`params` and runs them on the local engine,
    /// returning the cursor.
    fn run(&self, sql: &str, params: &[Value]) -> Result<worker::SqlCursor> {
        let (translated, ordered) = prepare(Dialect::Sqlite, sql, params)?;
        // DO SQLite binds `?` positionally, not sqlite's numbered `?N`, and
        // corrupts a bound `NULL` (stored as `"[object Object]"`) — both are
        // handled by the shared [`crate::placeholder::numbered_to_positional`].
        let (positional_sql, positional_params) =
            crate::placeholder::numbered_to_positional(&translated, &ordered);
        let bindings: Vec<SqlStorageValue> = positional_params.iter().map(to_sql).collect();
        self.sql
            .exec(positional_sql.as_str(), bindings)
            .map_err(|err| anyhow!("DO sql exec: {err}"))
    }
}

#[async_trait(?Send)]
impl Backend for SqlDoBackend {
    fn dialect(&self) -> Dialect {
        // The DO storage is SQLite: the source dialect, no translation beyond
        // placeholders.
        Dialect::Sqlite
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64> {
        let cursor = self.run(sql, params)?;
        Ok(cursor.rows_written() as u64)
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64> {
        self.run(sql, params)?;
        // The local engine has no `last_row_id` on the cursor; read it back in
        // the same DO turn (single-threaded, so no interleaving write).
        let cursor = self
            .sql
            .exec("SELECT last_insert_rowid()", None)
            .map_err(|err| anyhow!("DO sql last_insert_rowid: {err}"))?;
        let row = cursor
            .raw()
            .next()
            .ok_or_else(|| anyhow!("last_insert_rowid returned no row"))?
            .map_err(|err| anyhow!("DO sql row: {err}"))?;
        match row.into_iter().next() {
            Some(SqlStorageValue::Integer(id)) => Ok(id),
            _ => Err(anyhow!("last_insert_rowid was not an integer")),
        }
    }

    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let cursor = self.run(sql, params)?;
        let mut rows = Vec::new();
        for row in cursor.raw() {
            let cols = row.map_err(|err| anyhow!("DO sql row: {err}"))?;
            rows.push(Row::new(cols.into_iter().map(from_sql).collect()));
        }
        Ok(rows)
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        for statement in split_statements(sql) {
            let (translated, _) = prepare(Dialect::Sqlite, &statement, &[])?;
            self.sql
                .exec(translated.as_str(), None)
                .map_err(|err| anyhow!("DO sql exec_batch: {err}"))?;
        }
        Ok(())
    }

    async fn batch(&self, stmts: &[Statement]) -> Result<()> {
        // Durable Object SQLite forbids `BEGIN`/`SAVEPOINT` (`SQLITE_AUTH`): the
        // DO runtime already wraps each turn's writes in one implicit
        // transaction that commits when the turn ends and rolls back if the turn
        // throws. Run the statements directly and let a failure propagate — the
        // enclosing turn's automatic rollback discards the partial batch, the
        // analog of D1's atomic `batch()` without an explicit (and illegal)
        // `BEGIN IMMEDIATE`.
        for statement in stmts {
            self.run(&statement.sql, &statement.params)?;
        }
        Ok(())
    }
}
