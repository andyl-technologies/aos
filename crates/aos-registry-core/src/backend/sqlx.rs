//! The unified [`Backend`](crate::backend::Backend) driver, an enum over concrete `sqlx` pools.
//!
//! [`SqlxBackend`] is one type carrying a per-engine connection pool —
//! [`sqlx::SqlitePool`] always, `sqlx::PgPool` under the `postgres` feature,
//! `sqlx::MySqlPool` under `mysql`. It replaces the three hand-rolled
//! sync-driver backends with a single async one: every method matches on the
//! arm, translates the hub's sqlite-source SQL with [`Dialect`], binds the
//! caller's [`Value`]s onto a `sqlx::query`, and decodes result columns back
//! into [`Row`]s.
//!
//! Concrete pools are used in preference to `sqlx::Any`: `Any` erases the
//! database type and coerces every value through a lossy common encoding,
//! whereas the concrete pools give each engine its native binding and decoding
//! path — which the sqlite contract (the 461-test correctness gate) depends on.
//!
//! # Marshalling
//!
//! Binding maps each [`Value`] onto the engine's parameter encoding:
//!
//! ```text
//! Value::Null      -> a typed NULL (bound as Option::<i64>::None, etc.)
//! Value::Int(i64)  -> INTEGER / BIGINT
//! Value::Real(f64) -> REAL / DOUBLE
//! Value::Text(s)   -> TEXT / VARCHAR
//! Value::Bytes(b)  -> BLOB / BYTEA / LONGBLOB
//! ```
//!
//! Decoding reads each column generically from its runtime type info (sqlite's
//! storage class, postgres's OID, mysql's column type), then narrows to the
//! matching [`Value`] variant, so the drivers never need a compile-time schema.
//!
//! # In-memory sqlite
//!
//! `sqlite::memory:` databases are private to a single connection: a pool with
//! more than one connection would hand out *separate* empty databases. The
//! sqlite constructor therefore pins an in-memory pool to `max_connections(1)`
//! (file-backed pools keep the default size). Every sqlite pool enables WAL and
//! `foreign_keys = ON` to match the rusqlite backend the hub grew from.

use anyhow::{Context, Result};

use super::super::dialect::Dialect;
use super::super::value::{Row, Value};
use super::Statement;
// Multi-statement migration splitting is only needed by the postgres/mysql
// drivers (sqlite runs the whole script in one call via `raw_sql`).
#[cfg(any(feature = "postgres", feature = "mysql"))]
use super::split_statements;

/// One SQL engine, behind its concrete `sqlx` connection pool.
///
/// Only [`SqlxBackend::Sqlite`] is compiled by default; the postgres and mysql
/// arms are gated behind the matching cargo features so the default build pulls
/// in neither driver.
pub enum SqlxBackend {
    /// A pool of sqlite connections (the source dialect and default engine).
    Sqlite(sqlx::SqlitePool),
    /// A pool of postgres connections.
    #[cfg(feature = "postgres")]
    Postgres(sqlx::PgPool),
    /// A pool of mysql connections.
    #[cfg(feature = "mysql")]
    Mysql(sqlx::MySqlPool),
}

impl SqlxBackend {
    /// Opens a sqlite pool at `path`, or an in-memory database when `path` is
    /// empty or `:memory:`.
    ///
    /// WAL journaling and `foreign_keys = ON` are enabled, and missing files
    /// are created. An in-memory pool is pinned to a single connection so every
    /// query observes the same database (see the module-level note).
    ///
    /// # Errors
    ///
    /// Returns an error if the pool cannot be created or the file cannot be
    /// opened.
    pub async fn connect_sqlite(path: &str) -> Result<Self> {
        use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

        let in_memory = path.is_empty() || path == ":memory:";
        let options = if in_memory {
            SqliteConnectOptions::new().in_memory(true)
        } else {
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
        }
        .foreign_keys(true);

        let mut pool_options = SqlitePoolOptions::new();
        if in_memory {
            // A `:memory:` database lives in one connection; a larger pool would
            // hand out separate empty databases and break every query that
            // reads back what a prior one wrote.
            pool_options = pool_options.max_connections(1);
        }
        let pool = pool_options
            .connect_with(options)
            .await
            .with_context(|| format!("opening sqlite database {path:?}"))?;
        Ok(Self::Sqlite(pool))
    }

    /// Connects to a postgres server at `url` (e.g.
    /// `postgresql://user:pass@host:port/db`).
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established. The password
    /// is redacted from the URL before it reaches the error context.
    #[cfg(feature = "postgres")]
    pub async fn connect_postgres(url: &str) -> Result<Self> {
        let redacted = super::redact_db_url(url);
        let pool = sqlx::PgPool::connect(url)
            .await
            .with_context(|| format!("connecting to postgres {redacted}"))?;
        Ok(Self::Postgres(pool))
    }

    /// Connects to a mysql server at `url` (e.g.
    /// `mysql://user:pass@host:port/db`).
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established. The password
    /// is redacted from the URL before it reaches the error context.
    #[cfg(feature = "mysql")]
    pub async fn connect_mysql(url: &str) -> Result<Self> {
        let redacted = super::redact_db_url(url);
        let pool = sqlx::MySqlPool::connect(url)
            .await
            .with_context(|| format!("connecting to mysql {redacted}"))?;
        Ok(Self::Mysql(pool))
    }
}

#[async_trait::async_trait]
impl super::Backend for SqlxBackend {
    fn dialect(&self) -> Dialect {
        match self {
            Self::Sqlite(_) => Dialect::Sqlite,
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => Dialect::Postgres,
            #[cfg(feature = "mysql")]
            Self::Mysql(_) => Dialect::Mysql,
        }
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64> {
        match self {
            Self::Sqlite(pool) => sqlite::execute(pool, sql, params).await,
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => postgres::execute(pool, sql, params).await,
            #[cfg(feature = "mysql")]
            Self::Mysql(pool) => mysql::execute(pool, sql, params).await,
        }
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64> {
        match self {
            Self::Sqlite(pool) => sqlite::execute_insert(pool, sql, params).await,
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => postgres::execute_insert(self, pool, sql, params).await,
            #[cfg(feature = "mysql")]
            Self::Mysql(pool) => mysql::execute_insert(pool, sql, params).await,
        }
    }

    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        match self {
            Self::Sqlite(pool) => sqlite::query(pool, sql, params).await,
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => postgres::query(pool, sql, params).await,
            #[cfg(feature = "mysql")]
            Self::Mysql(pool) => mysql::query(pool, sql, params).await,
        }
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        match self {
            Self::Sqlite(pool) => {
                // sqlite translation is the identity, so the multi-statement
                // migration script runs verbatim in one `raw_sql` call.
                sqlx::raw_sql(sql)
                    .execute(pool)
                    .await
                    .context("executing migration batch")?;
                Ok(())
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => {
                for stmt in split_statements(sql) {
                    let translated = Dialect::Postgres.translate(&stmt)?;
                    sqlx::raw_sql(&translated.sql)
                        .execute(pool)
                        .await
                        .with_context(|| format!("migration statement: {}", translated.sql))?;
                }
                Ok(())
            }
            #[cfg(feature = "mysql")]
            Self::Mysql(pool) => {
                for stmt in split_statements(sql) {
                    let translated = Dialect::Mysql.translate(&stmt)?;
                    sqlx::raw_sql(&translated.sql)
                        .execute(pool)
                        .await
                        .with_context(|| format!("migration statement: {}", translated.sql))?;
                }
                Ok(())
            }
        }
    }

    async fn batch(&self, stmts: &[Statement]) -> Result<()> {
        match self {
            Self::Sqlite(pool) => sqlite::batch(pool, stmts).await,
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => postgres::batch(pool, stmts).await,
            #[cfg(feature = "mysql")]
            Self::Mysql(pool) => mysql::batch(pool, stmts).await,
        }
    }
}

/// The sqlite binding, decoding, and statement helpers.
///
/// Source dialect: translation is the identity, so each helper applies
/// [`prepare`](crate::backend::prepare) for parameter ordering and runs the SQL directly.
mod sqlite {
    use anyhow::{Context, Result};
    use sqlx::{Row as _, Sqlite, SqlitePool, TypeInfo, ValueRef};

    use super::super::super::dialect::Dialect;
    use super::super::super::value::{Row, Value};
    use super::super::{prepare, Statement};

    /// Binds `params` onto a sqlite query, encoding each [`Value`] in its
    /// native type.
    fn bind<'q>(
        mut query: sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
        params: &'q [Value],
    ) -> sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
        for value in params {
            query = match value {
                Value::Null => query.bind(Option::<i64>::None),
                Value::Int(n) => query.bind(*n),
                Value::Real(f) => query.bind(*f),
                Value::Text(s) => query.bind(s.as_str()),
                Value::Bytes(b) => query.bind(b.as_slice()),
            };
        }
        query
    }

    /// Decodes one sqlite row into a hub [`Row`], keyed on each column's
    /// storage class.
    fn decode(row: &sqlx::sqlite::SqliteRow) -> Result<Row> {
        let mut values = Vec::with_capacity(row.len());
        for i in 0..row.len() {
            let raw = row.try_get_raw(i)?;
            if raw.is_null() {
                values.push(Value::Null);
                continue;
            }
            // The column's declared/affinity type name selects the variant; the
            // hub schema only stores the five storage classes below.
            let value = match raw.type_info().name() {
                "INTEGER" | "BOOLEAN" => Value::Int(row.try_get::<i64, _>(i)?),
                "REAL" | "FLOAT" | "DOUBLE" => Value::Real(row.try_get::<f64, _>(i)?),
                "BLOB" => Value::Bytes(row.try_get::<Vec<u8>, _>(i)?),
                // TEXT, NULL-affinity, and anything else is read as text.
                _ => Value::Text(row.try_get::<String, _>(i)?),
            };
            values.push(value);
        }
        Ok(Row::new(values))
    }

    /// Runs a non-`SELECT` statement, returning rows affected.
    pub(super) async fn execute(pool: &SqlitePool, sql: &str, params: &[Value]) -> Result<u64> {
        let (sql, params) = prepare(Dialect::Sqlite, sql, params)?;
        let result = bind(sqlx::query(&sql), &params)
            .execute(pool)
            .await
            .with_context(|| format!("executing {sql}"))?;
        Ok(result.rows_affected())
    }

    /// Runs an `INSERT` and returns `last_insert_rowid()` from its result.
    pub(super) async fn execute_insert(
        pool: &SqlitePool,
        sql: &str,
        params: &[Value],
    ) -> Result<i64> {
        let (sql, params) = prepare(Dialect::Sqlite, sql, params)?;
        let result = bind(sqlx::query(&sql), &params)
            .execute(pool)
            .await
            .with_context(|| format!("executing {sql}"))?;
        Ok(result.last_insert_rowid())
    }

    /// Runs a `SELECT`/`RETURNING` statement, returning all rows.
    pub(super) async fn query(pool: &SqlitePool, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let (sql, params) = prepare(Dialect::Sqlite, sql, params)?;
        let rows = bind(sqlx::query(&sql), &params)
            .fetch_all(pool)
            .await
            .with_context(|| format!("querying {sql}"))?;
        rows.iter().map(decode).collect()
    }

    /// Runs `stmts` inside one sqlite transaction, committing on success.
    pub(super) async fn batch(pool: &SqlitePool, stmts: &[Statement]) -> Result<()> {
        let mut tx = pool.begin().await.context("beginning sqlite transaction")?;
        for stmt in stmts {
            let (sql, params) = prepare(Dialect::Sqlite, &stmt.sql, &stmt.params)?;
            bind(sqlx::query(&sql), &params)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("executing {sql}"))?;
        }
        tx.commit().await.context("committing sqlite transaction")?;
        Ok(())
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    //! The postgres binding, decoding, and statement helpers.
    //!
    //! Translation rewrites `?N` to `$N` and the DDL types to their postgres
    //! spellings; `execute_insert` appends `RETURNING id` and reads column 0.

    use anyhow::{Context, Result};
    use sqlx::{Column, PgPool, Postgres, Row as _, TypeInfo, ValueRef};

    use super::super::super::dialect::Dialect;
    use super::super::super::value::{Row, Value};
    use super::super::{prepare, with_returning_id, Statement};
    use super::SqlxBackend;

    /// Binds `params` onto a postgres query.
    fn bind<'q>(
        mut query: sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments>,
        params: &'q [Value],
    ) -> sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments> {
        for value in params {
            query = match value {
                Value::Null => query.bind(Option::<i64>::None),
                Value::Int(n) => query.bind(*n),
                Value::Real(f) => query.bind(*f),
                Value::Text(s) => query.bind(s.as_str()),
                Value::Bytes(b) => query.bind(b.as_slice()),
            };
        }
        query
    }

    /// Decodes one postgres row into a hub [`Row`], keyed on each column's type.
    fn decode(row: &sqlx::postgres::PgRow) -> Result<Row> {
        let mut values = Vec::with_capacity(row.len());
        for i in 0..row.len() {
            let raw = row.try_get_raw(i)?;
            if raw.is_null() {
                values.push(Value::Null);
                continue;
            }
            let value = match raw.type_info().name() {
                "INT2" | "INT4" | "INT8" => Value::Int(row.try_get::<i64, _>(i)?),
                "BOOL" => Value::Int(i64::from(row.try_get::<bool, _>(i)?)),
                "FLOAT4" | "FLOAT8" => Value::Real(row.try_get::<f64, _>(i)?),
                "BYTEA" => Value::Bytes(row.try_get::<Vec<u8>, _>(i)?),
                // TEXT, VARCHAR, and anything else the schema produces is text.
                _ => Value::Text(row.try_get::<String, _>(i)?),
            };
            values.push(value);
        }
        Ok(Row::new(values))
    }

    /// Runs a non-`SELECT` statement, returning rows affected.
    pub(super) async fn execute(pool: &PgPool, sql: &str, params: &[Value]) -> Result<u64> {
        let (sql, params) = prepare(Dialect::Postgres, sql, params)?;
        let result = bind(sqlx::query(&sql), &params)
            .execute(pool)
            .await
            .with_context(|| format!("executing {sql}"))?;
        Ok(result.rows_affected())
    }

    /// Runs an `INSERT … RETURNING id` and reads the new id from column 0.
    pub(super) async fn execute_insert(
        backend: &SqlxBackend,
        _pool: &PgPool,
        sql: &str,
        params: &[Value],
    ) -> Result<i64> {
        use super::super::Backend;
        let sql = with_returning_id(sql);
        let row = backend
            .query_opt(&sql, params)
            .await?
            .context("INSERT … RETURNING id yielded no row")?;
        row.get::<i64>(0)
    }

    /// Runs a `SELECT`/`RETURNING` statement, returning all rows.
    pub(super) async fn query(pool: &PgPool, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let (sql, params) = prepare(Dialect::Postgres, sql, params)?;
        let rows = bind(sqlx::query(&sql), &params)
            .fetch_all(pool)
            .await
            .with_context(|| format!("querying {sql}"))?;
        rows.iter().map(decode).collect()
    }

    /// Runs `stmts` inside one postgres transaction, committing on success.
    pub(super) async fn batch(pool: &PgPool, stmts: &[Statement]) -> Result<()> {
        let mut tx = pool
            .begin()
            .await
            .context("beginning postgres transaction")?;
        for stmt in stmts {
            let (sql, params) = prepare(Dialect::Postgres, &stmt.sql, &stmt.params)?;
            bind(sqlx::query(&sql), &params)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("executing {sql}"))?;
        }
        tx.commit()
            .await
            .context("committing postgres transaction")?;
        Ok(())
    }

    /// References `Column` so the import is not flagged unused.
    #[allow(dead_code)]
    fn _uses_column(row: &sqlx::postgres::PgRow) -> usize {
        row.columns().len()
    }
}

#[cfg(feature = "mysql")]
mod mysql {
    //! The mysql binding, decoding, and statement helpers.
    //!
    //! Translation rewrites `?N` to positional `?` (reordering reused
    //! placeholders) and the DDL/upsert syntax to mysql's; `execute_insert`
    //! reads `last_insert_id()` from the query result.

    use anyhow::{Context, Result};
    use sqlx::{Column, MySql, MySqlPool, Row as _, TypeInfo, ValueRef};

    use super::super::super::dialect::Dialect;
    use super::super::super::value::{Row, Value};
    use super::super::{prepare, Statement};

    /// Binds `params` onto a mysql query.
    fn bind<'q>(
        mut query: sqlx::query::Query<'q, MySql, sqlx::mysql::MySqlArguments>,
        params: &'q [Value],
    ) -> sqlx::query::Query<'q, MySql, sqlx::mysql::MySqlArguments> {
        for value in params {
            query = match value {
                Value::Null => query.bind(Option::<i64>::None),
                Value::Int(n) => query.bind(*n),
                Value::Real(f) => query.bind(*f),
                Value::Text(s) => query.bind(s.as_str()),
                Value::Bytes(b) => query.bind(b.as_slice()),
            };
        }
        query
    }

    /// Decodes one mysql row into a hub [`Row`], keyed on each column's type.
    fn decode(row: &sqlx::mysql::MySqlRow) -> Result<Row> {
        let mut values = Vec::with_capacity(row.len());
        for i in 0..row.len() {
            let raw = row.try_get_raw(i)?;
            if raw.is_null() {
                values.push(Value::Null);
                continue;
            }
            // mysql column type names are upper-case keywords; the hub schema
            // maps onto integer, floating-point, blob, and text classes.
            let value = match raw.type_info().name() {
                "TINYINT" | "SMALLINT" | "MEDIUMINT" | "INT" | "BIGINT" | "BOOLEAN" => {
                    Value::Int(row.try_get::<i64, _>(i)?)
                }
                "FLOAT" | "DOUBLE" => Value::Real(row.try_get::<f64, _>(i)?),
                "BLOB" | "TINYBLOB" | "MEDIUMBLOB" | "LONGBLOB" | "VARBINARY" | "BINARY" => {
                    Value::Bytes(row.try_get::<Vec<u8>, _>(i)?)
                }
                // TEXT/VARCHAR/CHAR and anything else is read as text.
                _ => Value::Text(row.try_get::<String, _>(i)?),
            };
            values.push(value);
        }
        Ok(Row::new(values))
    }

    /// Runs a non-`SELECT` statement, returning rows affected.
    pub(super) async fn execute(pool: &MySqlPool, sql: &str, params: &[Value]) -> Result<u64> {
        let (sql, params) = prepare(Dialect::Mysql, sql, params)?;
        let result = bind(sqlx::query(&sql), &params)
            .execute(pool)
            .await
            .with_context(|| format!("executing {sql}"))?;
        Ok(result.rows_affected())
    }

    /// Runs an `INSERT` and reads `last_insert_id()` from its result.
    pub(super) async fn execute_insert(
        pool: &MySqlPool,
        sql: &str,
        params: &[Value],
    ) -> Result<i64> {
        let (sql, params) = prepare(Dialect::Mysql, sql, params)?;
        let result = bind(sqlx::query(&sql), &params)
            .execute(pool)
            .await
            .with_context(|| format!("executing {sql}"))?;
        Ok(i64::try_from(result.last_insert_id()).unwrap_or(i64::MAX))
    }

    /// Runs a `SELECT` statement, returning all rows.
    pub(super) async fn query(pool: &MySqlPool, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let (sql, params) = prepare(Dialect::Mysql, sql, params)?;
        let rows = bind(sqlx::query(&sql), &params)
            .fetch_all(pool)
            .await
            .with_context(|| format!("querying {sql}"))?;
        rows.iter().map(decode).collect()
    }

    /// Runs `stmts` inside one mysql transaction, committing on success.
    pub(super) async fn batch(pool: &MySqlPool, stmts: &[Statement]) -> Result<()> {
        let mut tx = pool.begin().await.context("beginning mysql transaction")?;
        for stmt in stmts {
            let (sql, params) = prepare(Dialect::Mysql, &stmt.sql, &stmt.params)?;
            bind(sqlx::query(&sql), &params)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("executing {sql}"))?;
        }
        tx.commit().await.context("committing mysql transaction")?;
        Ok(())
    }

    /// References `Column` so the import is not flagged unused.
    #[allow(dead_code)]
    fn _uses_column(row: &sqlx::mysql::MySqlRow) -> usize {
        row.columns().len()
    }
}
