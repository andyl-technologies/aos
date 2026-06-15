//! The MySQL [`Backend`] driver, over the pure-Rust sync `mysql` crate.
//!
//! Gated behind the `mysql` cargo feature. The `mysql` crate is a pure-Rust
//! synchronous client (no libmysqlclient), fitting the hub's `Mutex<Conn>`
//! model and the repo's no-host-tools principle.
//!
//! Translation rewrites `?N` to positional `?` (reordering parameters for any
//! reused placeholder), the DDL types to their mysql spellings (`BIGINT
//! AUTO_INCREMENT`, `LONGBLOB`, `VARCHAR(255)`), and `ON CONFLICT` upserts to
//! `ON DUPLICATE KEY UPDATE` / `INSERT IGNORE`. `execute_insert` reads
//! `LAST_INSERT_ID()`.
//!
//! MySQL does not support `UPDATE … RETURNING` / `DELETE … RETURNING`; the two
//! hub methods that use that pattern (`consume_magic_link`, `take_oidc_flow`)
//! branch on the dialect and fall back to a guarded select-then-write.

use std::sync::Mutex;

use anyhow::{Context, Result};
use mysql::prelude::Queryable;
use mysql::{Conn, OptsBuilder, Value as MyValue};

use super::super::dialect::Dialect;
use super::super::value::{Row, Value};
use super::{prepare, redact_db_url, split_statements, Backend, Tx};

/// A [`Backend`] backed by one synchronous mysql `Conn` behind a `Mutex`.
pub struct MysqlBackend {
    // SECURITY/TODO(transport): the connection is built from `Opts::from_url`
    // without explicit `ssl_opts`, so transport security depends entirely on
    // whatever `ssl-mode` the URL happens to carry — the hub does not *require*
    // TLS. The `mysql` crate is compiled with the `default-rustls` feature, so
    // a rustls `SslOpts` can be attached without a new dependency; the intended
    // fix is to default to `SslOpts` with verification on (root CA from the
    // platform store / a configured PEM), relaxing only for an explicit
    // disable. Deferred here (cert-source config) in favor of the credential
    // leak fix; the URL password is no longer logged in clear.
    //
    // SECURITY/TODO(resilience): the single `Conn` lives behind a `Mutex` with
    // no reconnect or health-check, so a dropped connection is a permanent
    // outage until restart. The intended fix is a reconnect-and-retry wrapper
    // (detect a broken-connection error, re-establish under the lock, retry the
    // statement once) or a pool. Deferred to keep the query path stable.
    conn: Mutex<Conn>,
}

impl MysqlBackend {
    /// Connects to a mysql server at `url` (e.g.
    /// `mysql://user:pass@host:port/db`).
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be parsed or the connection cannot
    /// be established.
    pub fn connect(url: &str) -> Result<Self> {
        // Redact the password before the URL reaches any error context: both
        // the parse and connect failures are logged with it, and the raw URL
        // carries the database password in its userinfo.
        let redacted = redact_db_url(url);
        let opts =
            mysql::Opts::from_url(url).with_context(|| format!("parsing mysql url {redacted}"))?;
        let conn = Conn::new(OptsBuilder::from_opts(opts))
            .with_context(|| format!("connecting to mysql {redacted}"))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Conn> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Converts a hub [`Value`] into a `mysql` bound value.
fn to_my(value: &Value) -> MyValue {
    match value {
        Value::Null => MyValue::NULL,
        Value::Int(n) => MyValue::Int(*n),
        Value::Real(f) => MyValue::Double(*f),
        Value::Text(s) => MyValue::Bytes(s.clone().into_bytes()),
        Value::Bytes(b) => MyValue::Bytes(b.clone()),
    }
}

/// Reads one `mysql` column value into a hub [`Value`].
fn from_my(value: &MyValue) -> Value {
    match value {
        MyValue::NULL => Value::Null,
        MyValue::Int(n) => Value::Int(*n),
        MyValue::UInt(n) => Value::Int(i64::try_from(*n).unwrap_or(i64::MAX)),
        MyValue::Float(f) => Value::Real(f64::from(*f)),
        MyValue::Double(f) => Value::Real(*f),
        MyValue::Bytes(b) => {
            // Text columns arrive as bytes; preserve UTF-8 text where possible
            // and keep raw bytes otherwise (BLOB columns).
            match std::str::from_utf8(b) {
                Ok(s) => Value::Text(s.to_string()),
                Err(_) => Value::Bytes(b.clone()),
            }
        }
        // Dates/times are not used by the hub schema; stringify defensively.
        other => Value::Text(format!("{other:?}")),
    }
}

/// Materializes a mysql result set into hub [`Row`]s.
///
/// Columns are read via `unwrap_raw`, which never panics: the hub never calls
/// `mysql::Row::take`, so no cell is moved out, but a taken cell would surface
/// here as a `NULL` rather than a panic on the live query path.
fn rows_from(rows: Vec<mysql::Row>) -> Vec<Row> {
    rows.into_iter()
        .map(|row| {
            let values = row
                .unwrap_raw()
                .iter()
                .map(|cell| cell.as_ref().map_or(Value::Null, from_my))
                .collect::<Vec<_>>();
            Row::new(values)
        })
        .collect()
}

#[async_trait::async_trait]
impl Backend for MysqlBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Mysql
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64> {
        let (sql, params) = prepare(Dialect::Mysql, sql, params)?;
        let bound: Vec<MyValue> = params.iter().map(to_my).collect();
        let mut conn = self.lock();
        conn.exec_drop(&sql, mysql::Params::Positional(bound))
            .with_context(|| format!("executing {sql}"))?;
        Ok(conn.affected_rows())
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64> {
        let (sql, params) = prepare(Dialect::Mysql, sql, params)?;
        let bound: Vec<MyValue> = params.iter().map(to_my).collect();
        let mut conn = self.lock();
        conn.exec_drop(&sql, mysql::Params::Positional(bound))
            .with_context(|| format!("executing {sql}"))?;
        Ok(i64::try_from(conn.last_insert_id()).unwrap_or(0))
    }

    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let (sql, params) = prepare(Dialect::Mysql, sql, params)?;
        let bound: Vec<MyValue> = params.iter().map(to_my).collect();
        let mut conn = self.lock();
        let rows: Vec<mysql::Row> = conn
            .exec(&sql, mysql::Params::Positional(bound))
            .with_context(|| format!("querying {sql}"))?;
        Ok(rows_from(rows))
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        let mut conn = self.lock();
        for stmt in split_statements(sql) {
            let translated = Dialect::Mysql.translate(&stmt)?;
            conn.query_drop(&translated.sql)
                .with_context(|| format!("migration statement: {}", translated.sql))?;
        }
        Ok(())
    }

    async fn with_tx(
        &self,
        f: &mut (dyn for<'t> FnMut(&'t mut (dyn Tx + 't)) -> Result<()> + Send),
    ) -> Result<()> {
        let mut conn = self.lock();
        let mut tx = conn.start_transaction(mysql::TxOpts::default())?;
        {
            let mut wrapper = MyTx { tx: &mut tx };
            f(&mut wrapper)?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// A [`Tx`] over a `mysql::Transaction`.
struct MyTx<'a, 'b> {
    tx: &'a mut mysql::Transaction<'b>,
}

impl Tx for MyTx<'_, '_> {
    fn execute(&mut self, sql: &str, params: &[Value]) -> Result<u64> {
        let (sql, params) = prepare(Dialect::Mysql, sql, params)?;
        let bound: Vec<MyValue> = params.iter().map(to_my).collect();
        self.tx
            .exec_drop(&sql, mysql::Params::Positional(bound))
            .with_context(|| format!("executing {sql}"))?;
        Ok(self.tx.affected_rows())
    }

    fn execute_insert(&mut self, sql: &str, params: &[Value]) -> Result<i64> {
        let (sql, params) = prepare(Dialect::Mysql, sql, params)?;
        let bound: Vec<MyValue> = params.iter().map(to_my).collect();
        self.tx
            .exec_drop(&sql, mysql::Params::Positional(bound))
            .with_context(|| format!("executing {sql}"))?;
        Ok(i64::try_from(self.tx.last_insert_id().unwrap_or(0)).unwrap_or(0))
    }

    fn query(&mut self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let (sql, params) = prepare(Dialect::Mysql, sql, params)?;
        let bound: Vec<MyValue> = params.iter().map(to_my).collect();
        let rows: Vec<mysql::Row> = self
            .tx
            .exec(&sql, mysql::Params::Positional(bound))
            .with_context(|| format!("querying {sql}"))?;
        Ok(rows_from(rows))
    }
}
