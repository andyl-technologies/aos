//! The PostgreSQL [`Backend`] driver, over the pure-Rust sync `postgres` crate.
//!
//! Gated behind the `postgres` cargo feature. The `postgres` crate is the
//! synchronous wrapper around `tokio-postgres`, with no libpq/system
//! dependency, so it fits the hub's sync `Mutex<Client>` model and the repo's
//! no-host-tools principle.
//!
//! Translation rewrites `?N` to `$N` and the DDL types to their postgres
//! spellings (`BIGSERIAL`, `BIGINT`, `BYTEA`); `INSERT … ON CONFLICT` and
//! `RETURNING` are native, so `execute_insert` simply appends `RETURNING id`.

use std::sync::Mutex;

use anyhow::{Context, Result};
use postgres::types::Type as PgType;
use postgres::{Client, NoTls};

use super::super::dialect::Dialect;
use super::super::value::{Row, Value};
use super::{prepare, redact_db_url, split_statements, with_returning_id, Backend, Tx};

/// A [`Backend`] backed by one synchronous postgres `Client` behind a `Mutex`.
pub struct PostgresBackend {
    // SECURITY/TODO(transport): the connection is established with `NoTls`, so
    // traffic to postgres — including the bearer of every query — is cleartext
    // on the wire. For a high-assurance multi-tenant hub this should be TLS
    // (verify-full) by default, opting out only for an explicit
    // `sslmode=disable` (local dev). The sync `postgres` 0.19 crate has no
    // built-in TLS connector; wiring it means adding a rustls-based connector
    // (`tokio-postgres-rustls` driving `postgres`'s `MakeTlsConnect`) plus a
    // root-cert source. That is a new workspace dependency and cert-config
    // surface, deliberately deferred from this pass; only the credential leak
    // (the password in connect-error logs) is fixed here.
    //
    // SECURITY/TODO(resilience): the single `Client` lives behind a `Mutex`
    // with no reconnect or health-check. If the server drops the connection
    // (restart, idle timeout, network blip) every subsequent query fails until
    // the hub process is restarted — a permanent outage from a transient fault.
    // The intended fix is a reconnect-and-retry wrapper around the query-exec
    // path (detect a broken-connection error, re-establish under the lock, and
    // retry the statement once) or a small connection pool. Deferred here to
    // keep the existing query path stable; tracked as an availability item.
    client: Mutex<Client>,
}

impl PostgresBackend {
    /// Connects to a postgres server at `url` (e.g.
    /// `postgresql://user:pass@host:port/db`).
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established.
    pub fn connect(url: &str) -> Result<Self> {
        // Redact the password from the URL before it lands in any error chain:
        // connection failures are logged with this context, and the raw URL
        // carries the database password in its userinfo.
        let redacted = redact_db_url(url);
        let client = Client::connect(url, NoTls)
            .with_context(|| format!("connecting to postgres {redacted}"))?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Client> {
        self.client.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// A `Value` wrapped so it can be bound as a `postgres` parameter.
///
/// `postgres`'s `ToSql` is implemented per-type, so we adapt our tagged union
/// by hand, encoding each variant as the postgres type the schema uses
/// (`int8` for integers/booleans, `float8`, `text`, `bytea`).
#[derive(Debug)]
struct PgParam<'a>(&'a Value);

impl postgres::types::ToSql for PgParam<'_> {
    fn to_sql(
        &self,
        ty: &PgType,
        out: &mut postgres::types::private::BytesMut,
    ) -> std::result::Result<postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
    {
        match self.0 {
            Value::Null => Ok(postgres::types::IsNull::Yes),
            Value::Int(n) => n.to_sql(ty, out),
            Value::Real(f) => f.to_sql(ty, out),
            Value::Text(s) => s.to_sql(ty, out),
            Value::Bytes(b) => b.to_sql(ty, out),
        }
    }

    fn accepts(_ty: &PgType) -> bool {
        // We bind dynamically; accept any target type and let the server
        // reconcile (the column types are fixed by the migrations).
        true
    }

    postgres::types::to_sql_checked!();
}

/// Reads one postgres column into a hub [`Value`], keyed on the column's type.
fn from_pg(row: &postgres::Row, idx: usize) -> Value {
    let col = &row.columns()[idx];
    match *col.type_() {
        PgType::INT2 => row
            .get::<_, Option<i16>>(idx)
            .map_or(Value::Null, |n| Value::Int(i64::from(n))),
        PgType::INT4 => row
            .get::<_, Option<i32>>(idx)
            .map_or(Value::Null, |n| Value::Int(i64::from(n))),
        PgType::INT8 => row
            .get::<_, Option<i64>>(idx)
            .map_or(Value::Null, Value::Int),
        PgType::BOOL => row
            .get::<_, Option<bool>>(idx)
            .map_or(Value::Null, |b| Value::Int(i64::from(b))),
        PgType::FLOAT4 => row
            .get::<_, Option<f32>>(idx)
            .map_or(Value::Null, |f| Value::Real(f64::from(f))),
        PgType::FLOAT8 => row
            .get::<_, Option<f64>>(idx)
            .map_or(Value::Null, Value::Real),
        PgType::BYTEA => row
            .get::<_, Option<Vec<u8>>>(idx)
            .map_or(Value::Null, Value::Bytes),
        // TEXT, VARCHAR, and anything else the schema produces is read as text.
        _ => row
            .get::<_, Option<String>>(idx)
            .map_or(Value::Null, Value::Text),
    }
}

/// Materializes a postgres result set into hub [`Row`]s.
fn rows_from(rows: &[postgres::Row]) -> Vec<Row> {
    rows.iter()
        .map(|row| {
            let values = (0..row.columns().len()).map(|i| from_pg(row, i)).collect();
            Row::new(values)
        })
        .collect()
}

/// Binds a slice of `Value`s as postgres parameters.
fn bind(params: &[Value]) -> Vec<PgParam<'_>> {
    params.iter().map(PgParam).collect()
}

#[async_trait::async_trait]
impl Backend for PostgresBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Postgres
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64> {
        let (sql, params) = prepare(Dialect::Postgres, sql, params)?;
        let bound = bind(&params);
        let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = bound
            .iter()
            .map(|p| p as &(dyn postgres::types::ToSql + Sync))
            .collect();
        let mut client = self.lock();
        client
            .execute(&sql, &refs)
            .await
            .with_context(|| format!("executing {sql}"))
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64> {
        let sql = with_returning_id(sql);
        let row = self
            .query_opt(&sql, params)
            .await?
            .context("INSERT … RETURNING id yielded no row")?;
        row.get::<i64>(0)
    }

    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let (sql, params) = prepare(Dialect::Postgres, sql, params)?;
        let bound = bind(&params);
        let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = bound
            .iter()
            .map(|p| p as &(dyn postgres::types::ToSql + Sync))
            .collect();
        let mut client = self.lock();
        let rows = client
            .query(&sql, &refs)
            .await
            .with_context(|| format!("querying {sql}"))?;
        Ok(rows_from(&rows))
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        let mut client = self.lock();
        for stmt in split_statements(sql) {
            let translated = Dialect::Postgres.translate(&stmt)?;
            client
                .batch_execute(&translated.sql)
                .with_context(|| format!("migration statement: {}", translated.sql))?;
        }
        Ok(())
    }

    async fn with_tx(
        &self,
        f: &mut (dyn for<'t> FnMut(&'t mut (dyn Tx + 't)) -> Result<()> + Send),
    ) -> Result<()> {
        let mut client = self.lock();
        let tx = client.transaction()?;
        {
            let mut wrapper = PgTx { tx };
            f(&mut wrapper)?;
            wrapper.tx.commit()?;
        }
        Ok(())
    }
}

/// A [`Tx`] over a `postgres::Transaction`.
struct PgTx<'a> {
    tx: postgres::Transaction<'a>,
}

impl Tx for PgTx<'_> {
    fn execute(&mut self, sql: &str, params: &[Value]) -> Result<u64> {
        let (sql, params) = prepare(Dialect::Postgres, sql, params)?;
        let bound = bind(&params);
        let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = bound
            .iter()
            .map(|p| p as &(dyn postgres::types::ToSql + Sync))
            .collect();
        self.tx
            .execute(&sql, &refs)
            .await
            .with_context(|| format!("executing {sql}"))
    }

    fn execute_insert(&mut self, sql: &str, params: &[Value]) -> Result<i64> {
        let sql = with_returning_id(sql);
        let row = self
            .query_opt(&sql, params)
            .await?
            .context("INSERT … RETURNING id yielded no row")?;
        row.get::<i64>(0)
    }

    fn query(&mut self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let (sql, params) = prepare(Dialect::Postgres, sql, params)?;
        let bound = bind(&params);
        let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = bound
            .iter()
            .map(|p| p as &(dyn postgres::types::ToSql + Sync))
            .collect();
        let rows = self
            .tx
            .query(&sql, &refs)
            .await
            .with_context(|| format!("querying {sql}"))?;
        Ok(rows_from(&rows))
    }
}
