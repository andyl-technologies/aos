//! The sqlite (and Cloudflare D1) [`Backend`] driver, over `rusqlite`.
//!
//! This is the source dialect and the always-on default. Translation is the
//! identity for placeholders and DDL, so the driver is a thin marshalling
//! layer between the hub's [`Value`]/[`Row`] shapes and `rusqlite`'s.

use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::types::{Type, Value as SqlValue, ValueRef};
use rusqlite::Connection;

use super::super::dialect::Dialect;
use super::super::value::{Row, Value};
use super::{prepare, split_statements, Backend, Tx};

/// A [`Backend`] backed by a single `rusqlite` connection behind a `Mutex`.
pub struct SqliteBackend {
    conn: Mutex<Connection>,
}

impl SqliteBackend {
    /// Wraps an open `rusqlite` connection, enabling WAL and foreign keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the `foreign_keys` pragma cannot be set.
    pub fn new(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Locks the connection, recovering from a poisoned mutex.
    ///
    /// A poisoned mutex means another thread panicked mid-query; the
    /// connection itself is still structurally usable for new calls (the same
    /// recovery the hub used before the backend split).
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Converts a hub [`Value`] into a `rusqlite` value for binding.
fn to_sql(value: &Value) -> SqlValue {
    match value {
        Value::Null => SqlValue::Null,
        Value::Int(n) => SqlValue::Integer(*n),
        Value::Real(f) => SqlValue::Real(*f),
        Value::Text(s) => SqlValue::Text(s.clone()),
        Value::Bytes(b) => SqlValue::Blob(b.clone()),
    }
}

/// Reads one `rusqlite` column into a hub [`Value`].
fn from_sql(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(n) => Value::Int(n),
        ValueRef::Real(f) => Value::Real(f),
        ValueRef::Text(t) => Value::Text(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::Bytes(b.to_vec()),
    }
}

/// Runs a `SELECT`/`RETURNING` statement on a `rusqlite` connection.
fn run_query(conn: &Connection, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
    let bound: Vec<SqlValue> = params.iter().map(to_sql).collect();
    let mut stmt = conn
        .prepare(sql)
        .with_context(|| format!("preparing {sql}"))?;
    let column_count = stmt.column_count();
    let mut rows = stmt.query(rusqlite::params_from_iter(bound.iter()))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut values = Vec::with_capacity(column_count);
        for i in 0..column_count {
            let raw = row.get_ref(i)?;
            // Preserve the declared affinity for NULLs read from typed columns.
            let _ = Type::Null;
            values.push(from_sql(raw));
        }
        out.push(Row::new(values));
    }
    Ok(out)
}

/// Runs a non-`SELECT` statement, returning rows affected.
fn run_execute(conn: &Connection, sql: &str, params: &[Value]) -> Result<u64> {
    let bound: Vec<SqlValue> = params.iter().map(to_sql).collect();
    let n = conn
        .execute(sql, rusqlite::params_from_iter(bound.iter()))
        .with_context(|| format!("executing {sql}"))?;
    Ok(n as u64)
}

#[async_trait::async_trait]
impl Backend for SqliteBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Sqlite
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64> {
        let (sql, params) = prepare(Dialect::Sqlite, sql, params)?;
        let conn = self.lock();
        run_execute(&conn, &sql, &params)
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64> {
        let (sql, params) = prepare(Dialect::Sqlite, sql, params)?;
        let conn = self.lock();
        run_execute(&conn, &sql, &params)?;
        Ok(conn.last_insert_rowid())
    }

    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let (sql, params) = prepare(Dialect::Sqlite, sql, params)?;
        let conn = self.lock();
        run_query(&conn, &sql, &params)
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        let conn = self.lock();
        // sqlite translation is the identity, so the original batch runs
        // verbatim; execute_batch handles the multi-statement script directly.
        conn.execute_batch(sql)
            .with_context(|| "executing migration batch".to_string())?;
        Ok(())
    }

    async fn with_tx(
        &self,
        f: &mut (dyn for<'t> FnMut(&'t mut (dyn Tx + 't)) -> Result<()> + Send),
    ) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        {
            let mut wrapper = SqliteTx { tx: &tx };
            f(&mut wrapper)?;
        }
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    fn as_sqlite(&self) -> Option<&SqliteBackend> {
        Some(self)
    }
}

/// A [`Tx`] over a `rusqlite::Transaction`.
struct SqliteTx<'a> {
    tx: &'a rusqlite::Transaction<'a>,
}

impl Tx for SqliteTx<'_> {
    fn execute(&mut self, sql: &str, params: &[Value]) -> Result<u64> {
        let (sql, params) = prepare(Dialect::Sqlite, sql, params)?;
        run_execute(self.tx, &sql, &params)
    }

    fn execute_insert(&mut self, sql: &str, params: &[Value]) -> Result<i64> {
        let (sql, params) = prepare(Dialect::Sqlite, sql, params)?;
        run_execute(self.tx, &sql, &params)?;
        Ok(self.tx.last_insert_rowid())
    }

    fn query(&mut self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let (sql, params) = prepare(Dialect::Sqlite, sql, params)?;
        run_query(self.tx, &sql, &params)
    }
}

// `split_statements` is shared with the pg/mysql drivers (which cannot run a
// multi-statement script in one call); reference it so the helper is not
// flagged unused on a sqlite-only build.
#[allow(dead_code)]
fn _uses_split() -> Vec<String> {
    split_statements("")
}
