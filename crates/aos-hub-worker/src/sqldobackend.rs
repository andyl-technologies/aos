//! [`SqlDoBackend`]: a [`Backend`] over a Durable Object's **colocated** SQLite
//! (wasm32-only) — the Phase E system-of-record substrate (RFC-0004 ch.14).
//!
//! The relational system of record lives in a Durable Object whose SQLite
//! storage runs **in the same thread** as
//! the handler. `SqlStorage::exec` is synchronous and local: microsecond reads,
//! no network hop, full SQL, strict serializability. This type adapts that local
//! engine to the shared async [`Backend`] trait, so the *exact* `core::Database`
//! read/write logic the native hub runs also runs inside the
//! tenant DO — no third reimplementation.
//!
//! It is constructed only **inside** a Durable Object, from
//! `state.storage().sql()`; the request Worker reaches it by routing tenant
//! operations to the DO (Phase E3). Because the engine is local and synchronous,
//! ordinary `async` trait methods complete without yielding. Batch methods
//! await the promise returned by the Durable Object transaction wrapper so a
//! closure error is observed as a rollback before control returns.
//!
//! # Marshalling
//!
//! Parameters cross as [`SqlStorageValue`] (`Null`/`Integer`/`Float`/`String`/
//! `Blob`), the exact shape of a [`Value`]; result rows come back **positionally**
//! from the cursor's `raw()` iterator (a `Vec<SqlStorageValue>` per row) and map
//! column-by-column into a [`Row`]. `execute` reports SQLite `changes()` (the
//! direct row count, excluding index-write billing); an insert's
//! id is read back with `SELECT last_insert_rowid()`. Atomic batches use the
//! Durable Object storage transaction API because local SQLite forbids SQL
//! `BEGIN`/`SAVEPOINT`; a checked-batch row-count mismatch is returned from the
//! transaction closure and therefore rolls every preceding statement back.
//! Integer bindings outside JavaScript's exact safe-integer range are rejected
//! before crossing the wasm binding rather than silently rounded.
//! Cloudflare's SQLite-backed storage contract explicitly includes top-level
//! `ctx.storage.sql.exec()` calls in `ctx.storage.transaction()`, even though
//! the transaction callback's `txn` parameter is not used. `worker-rs` maps a
//! Rust callback error to a rejected JavaScript promise, which is the platform
//! rollback signal.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use worker::{SqlStorage, SqlStorageValue, Storage};

use aos_hub_core::backend::{prepare, split_statements, Backend, CheckedStatement, Statement};
use aos_hub_core::db::{MIGRATIONS, SCHEMA_IDENTITY};
use aos_hub_core::dialect::Dialect;
use aos_hub_core::value::{Row, Value};

const JS_SAFE_INTEGER_MAX: i64 = 9_007_199_254_740_991;

/// A [`Backend`] over a Durable Object's local SQLite ([`SqlStorage`]).
///
/// Holds the DO's `SqlStorage` handle (obtained from `state.storage().sql()`);
/// every method runs the translated SQL through the local engine. One backend
/// serves one tenant DO's database.
pub struct SqlDoBackend {
    storage: Storage,
    sql: SqlStorage,
}

impl SqlDoBackend {
    /// Wraps a Durable Object's storage handle as a [`Backend`].
    ///
    /// The parent [`Storage`] handle is retained so [`Backend::batch`] and
    /// [`Backend::checked_batch`] can use the platform transaction API. The
    /// [`SqlStorage`] facade alone cannot start a transaction.
    #[must_use]
    pub fn new(storage: Storage) -> SqlDoBackend {
        let sql = storage.sql();
        SqlDoBackend { storage, sql }
    }

    /// Proves indexed row counts and rollback against the real DO transaction binding.
    ///
    /// # Errors
    ///
    /// Returns an error if fixture setup, the expected mismatch, rollback, or
    /// the verification query does not behave as required.
    #[cfg(feature = "do-e2e")]
    pub(crate) async fn e2e_assert_checked_batch_row_counts_and_rollback(&self) -> Result<()> {
        let unsafe_bind = self
            .query("SELECT ?1", &[Value::Int(JS_SAFE_INTEGER_MAX + 1)])
            .await;
        anyhow::ensure!(
            unsafe_bind.is_err(),
            "unsafe JavaScript integer crossed the real SQL bind path"
        );
        let safe_row = self
            .query("SELECT ?1", &[Value::Int(JS_SAFE_INTEGER_MAX)])
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("safe-integer boundary query returned no row"))?;
        anyhow::ensure!(
            safe_row.get::<i64>(0)? == JS_SAFE_INTEGER_MAX,
            "safe-integer boundary did not round-trip exactly"
        );
        let unsafe_result = self
            .query("SELECT CAST(9007199254740992 AS INTEGER)", &[])
            .await;
        anyhow::ensure!(
            unsafe_result.is_err(),
            "database-generated unsafe integer crossed the real SQL result path"
        );
        self.execute_batch(
            "CREATE TABLE IF NOT EXISTS aos_checked_batch_probe (
               id INTEGER PRIMARY KEY, value TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS aos_checked_batch_probe_value
               ON aos_checked_batch_probe(value);
             DELETE FROM aos_checked_batch_probe;",
        )
        .await?;
        self.checked_batch(&[CheckedStatement::exact(
            "INSERT INTO aos_checked_batch_probe (id, value) VALUES (?1, ?2)",
            vec![Value::Int(10), Value::Text("indexed-success".to_owned())],
            1,
        )])
        .await?;
        let mismatch = self
            .checked_batch(&[
                CheckedStatement::exact(
                    "INSERT INTO aos_checked_batch_probe (id, value) VALUES (?1, ?2)",
                    vec![Value::Int(1), Value::Text("must-roll-back".to_owned())],
                    1,
                ),
                CheckedStatement::exact(
                    "UPDATE aos_checked_batch_probe SET value = ?2 WHERE id = ?1",
                    vec![Value::Int(99), Value::Text("missing".to_owned())],
                    1,
                ),
            ])
            .await;
        anyhow::ensure!(mismatch.is_err(), "checked batch unexpectedly committed");
        let row = self
            .query(
                "SELECT COUNT(*) FROM aos_checked_batch_probe WHERE id IN (?1, ?2)",
                &[Value::Int(1), Value::Int(10)],
            )
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("checked-batch probe returned no count"))?;
        let count: i64 = row.get(0)?;
        anyhow::ensure!(
            count == 1,
            "checked batch left {count} probe rows; expected only the indexed success row"
        );
        Ok(())
    }
}

/// Applies the shared schema to a fresh HubDb SQLite store exactly once.
///
/// Durable Object SQLite forbids `PRAGMA`, so a private one-row table records
/// the applied migration count. Every reopened store must also carry the exact
/// hard-cutover schema identity.
///
/// # Errors
///
/// Returns an error when migration SQL fails or the persisted schema identity
/// is absent or unsupported.
pub(crate) async fn ensure_migrated(backend: &SqlDoBackend) -> Result<()> {
    backend
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS _do_migrations (\
               id INTEGER PRIMARY KEY CHECK (id = 0), \
               applied INTEGER NOT NULL)",
        )
        .await?;
    let applied = backend
        .query("SELECT applied FROM _do_migrations WHERE id = 0", &[])
        .await?
        .first()
        .and_then(|row| row.get::<i64>(0).ok())
        .unwrap_or(0)
        .max(0) as usize;
    if applied != 0 {
        require_schema_identity(backend).await?;
    }
    if applied > MIGRATIONS.len() {
        anyhow::bail!(
            "HubDb schema {applied} is newer than this Worker supports ({})",
            MIGRATIONS.len()
        );
    }
    if applied == MIGRATIONS.len() {
        return Ok(());
    }
    for (offset, migration) in MIGRATIONS[applied..].iter().enumerate() {
        let next = applied + offset + 1;
        let mut statements = split_statements(migration)
            .into_iter()
            .map(|sql| Statement::new(sql, Vec::new()))
            .collect::<Vec<_>>();
        statements.push(Statement::new(
            "INSERT INTO _do_migrations (id, applied) VALUES (0, ?1) \
             ON CONFLICT(id) DO UPDATE SET applied = ?1",
            vec![Value::Int(next as i64)],
        ));
        // Durable Object eviction cannot split schema DDL from its ledger
        // advancement: the storage transaction either commits both or rolls
        // every statement back, leaving the migration safe to retry.
        backend.batch(&statements).await?;
    }
    require_schema_identity(backend).await?;
    Ok(())
}

async fn require_schema_identity(backend: &SqlDoBackend) -> Result<()> {
    let row = backend
        .query("SELECT identity FROM hub_schema_identity", &[])
        .await
        .map_err(|error| {
            anyhow!(
                "HubDb has no supported topology schema identity; restore a current backup: {error:#}"
            )
        })?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("topology schema identity row is missing"))?;
    let identity: String = row.get(0)?;
    anyhow::ensure!(
        identity == SCHEMA_IDENTITY,
        "unsupported Hub schema identity '{identity}'; expected '{SCHEMA_IDENTITY}'"
    );
    Ok(())
}

/// Converts a bound [`Value`] into the [`SqlStorageValue`] the DO engine binds.
fn to_sql(value: &Value) -> Result<SqlStorageValue> {
    Ok(match value {
        Value::Null => SqlStorageValue::Null,
        Value::Int(n) if (-JS_SAFE_INTEGER_MAX..=JS_SAFE_INTEGER_MAX).contains(n) => {
            SqlStorageValue::Integer(*n)
        }
        Value::Int(n) => {
            return Err(anyhow!(
                "DO SQL integer {n} is outside the exact JavaScript safe-integer range"
            ));
        }
        Value::Real(f)
            if f.is_finite() && !(f.fract() == 0.0 && f.abs() > JS_SAFE_INTEGER_MAX as f64) =>
        {
            SqlStorageValue::Float(*f)
        }
        Value::Real(f) => {
            return Err(anyhow!(
                "DO SQL bound number {f} cannot be represented exactly"
            ));
        }
        Value::Text(s) => SqlStorageValue::String(s.clone()),
        Value::Bytes(b) => SqlStorageValue::Blob(b.clone()),
    })
}

/// Converts a result-row [`SqlStorageValue`] back into an exact [`Value`].
fn from_sql(value: SqlStorageValue) -> Result<Value> {
    Ok(match value {
        SqlStorageValue::Null => Value::Null,
        SqlStorageValue::Integer(n)
            if (-JS_SAFE_INTEGER_MAX..=JS_SAFE_INTEGER_MAX).contains(&n) =>
        {
            Value::Int(n)
        }
        SqlStorageValue::Integer(n) => {
            return Err(anyhow!(
                "DO SQL result integer {n} is outside the exact JavaScript safe-integer range"
            ));
        }
        SqlStorageValue::Float(f)
            if !f.is_finite() || (f.fract() == 0.0 && f.abs() > JS_SAFE_INTEGER_MAX as f64) =>
        {
            return Err(anyhow!(
                "DO SQL result number {f} cannot be represented exactly"
            ));
        }
        SqlStorageValue::Float(f) => Value::Real(f),
        SqlStorageValue::String(s) => Value::Text(s),
        SqlStorageValue::Blob(b) => Value::Bytes(b),
        // SQLite has no native boolean, but the binding surfaces one; store it
        // as the schema's canonical 0/1 integer.
        SqlStorageValue::Boolean(b) => Value::Int(i64::from(b)),
    })
}

impl SqlDoBackend {
    /// Translates + binds `sql`/`params` and runs them on the local engine,
    /// returning the cursor.
    fn run(&self, sql: &str, params: &[Value]) -> Result<worker::SqlCursor> {
        run(&self.sql, sql, params)
    }
}

/// Executes one translated statement through a clonable SQL facade.
///
/// The free function form lets a `'static` Durable Object transaction closure
/// own the facade without borrowing the backend.
fn run(sql_storage: &SqlStorage, sql: &str, params: &[Value]) -> Result<worker::SqlCursor> {
    let (translated, ordered) = prepare(Dialect::Sqlite, sql, params)?;
    // DO SQLite binds `?` positionally, not sqlite's numbered `?N`, and
    // corrupts a bound `NULL` (stored as `"[object Object]"`) — both are
    // handled by the shared [`crate::placeholder::numbered_to_positional`].
    let (positional_sql, positional_params) =
        crate::placeholder::numbered_to_positional(&translated, &ordered);
    let bindings = positional_params
        .iter()
        .map(to_sql)
        .collect::<Result<Vec<_>>>()?;
    sql_storage
        .exec(positional_sql.as_str(), bindings)
        .map_err(|err| anyhow!("DO sql exec: {err}"))
}

/// Returns SQLite's direct affected-row count for the immediately preceding statement.
///
/// `SqlCursor::rows_written` is a billing counter and includes index writes;
/// SQLite's `changes()` is the portable one-row CAS count required by
/// [`Backend::execute`] and [`Backend::checked_batch`].
fn changes(sql_storage: &SqlStorage) -> Result<u64> {
    let cursor = sql_storage
        .exec("SELECT changes()", None)
        .map_err(|error| anyhow!("DO sql changes(): {error}"))?;
    let row = cursor
        .raw()
        .next()
        .ok_or_else(|| anyhow!("DO sql changes() returned no row"))?
        .map_err(|error| anyhow!("DO sql changes() row: {error}"))?;
    match row.into_iter().next() {
        Some(SqlStorageValue::Integer(value)) if value >= 0 => Ok(value as u64),
        value => Err(anyhow!(
            "DO sql changes() was not a non-negative integer: {value:?}"
        )),
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
        self.run(sql, params)?;
        changes(&self.sql)
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
            Some(SqlStorageValue::Integer(id))
                if (-JS_SAFE_INTEGER_MAX..=JS_SAFE_INTEGER_MAX).contains(&id) =>
            {
                Ok(id)
            }
            _ => Err(anyhow!("last_insert_rowid was not an integer")),
        }
    }

    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let cursor = self.run(sql, params)?;
        let mut rows = Vec::new();
        for row in cursor.raw() {
            let cols = row.map_err(|err| anyhow!("DO sql row: {err}"))?;
            rows.push(Row::new(
                cols.into_iter().map(from_sql).collect::<Result<Vec<_>>>()?,
            ));
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
        let sql = self.sql.clone();
        let statements = stmts.to_vec();
        self.storage
            .transaction(move |_transaction| async move {
                for statement in &statements {
                    run(&sql, &statement.sql, &statement.params)
                        .map_err(|error| worker::Error::RustError(error.to_string()))?;
                }
                Ok(())
            })
            .await
            .map_err(|error| anyhow!("DO SQL batch transaction: {error}"))
    }

    async fn checked_batch(&self, stmts: &[CheckedStatement]) -> Result<()> {
        let sql = self.sql.clone();
        let statements = stmts.to_vec();
        self.storage
            .transaction(move |_transaction| async move {
                for checked in &statements {
                    run(&sql, &checked.statement.sql, &checked.statement.params)
                        .map_err(|error| worker::Error::RustError(error.to_string()))?;
                    if let Some(expected) = checked.expected_rows {
                        let actual = changes(&sql)
                            .map_err(|error| worker::Error::RustError(error.to_string()))?;
                        if actual != expected {
                            return Err(worker::Error::RustError(format!(
                                "checked batch expected {expected} affected rows, got {actual}"
                            )));
                        }
                    }
                }
                Ok(())
            })
            .await
            .map_err(|error| anyhow!("DO SQL checked-batch transaction: {error}"))
    }
}
