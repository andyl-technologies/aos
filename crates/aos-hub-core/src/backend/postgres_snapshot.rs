//! Held read-only PostgreSQL input for inert logical archives.
//!
//! PostgreSQL 18 and the exact current generation-eight semantic catalogue are
//! admitted. One REPEATABLE READ READ ONLY transaction owns catalogue checks,
//! source audit and bounded row pages. ACCESS SHARE locks prevent physical heap
//! rewriting while internal `ctid` locators enumerate the held snapshot. Neither
//! those locators nor source connection credentials enter exported logical rows.
//! This reader does not initialize, migrate, import or activate a Hub.

use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};

use super::sqlite_snapshot::{
    CompiledSqliteSnapshotCatalogue, CompiledSqliteSnapshotObjectKind, SqliteSnapshotPage,
    SqliteSnapshotSchema, SqliteSnapshotTableCount, SqliteSnapshotTableSchema,
};

#[path = "postgres_snapshot/audit.rs"]
mod audit;
#[path = "postgres_snapshot/catalogue.rs"]
mod catalogue;
#[path = "postgres_snapshot/paging.rs"]
mod paging;

pub use paging::PostgresSnapshotTable;

/// Bounds on source work for one held PostgreSQL capture.
#[derive(Debug, Clone, Copy)]
pub struct PostgresSnapshotLimits {
    /// Overall held-transaction duration, greater than zero and at most 300s.
    pub max_duration: Duration,
    /// Individual statement duration, at most 30s and at most the overall bound.
    pub statement_timeout: Duration,
    /// Maximum wait for acquiring catalogue/table locks, at most 5s.
    pub lock_timeout: Duration,
}

impl Default for PostgresSnapshotLimits {
    fn default() -> Self {
        Self {
            max_duration: Duration::from_secs(300),
            statement_timeout: Duration::from_secs(30),
            lock_timeout: Duration::from_secs(5),
        }
    }
}

impl PostgresSnapshotLimits {
    fn validate(self) -> Result<()> {
        ensure!(
            self.max_duration.as_millis() > 0
                && self.max_duration <= Duration::from_secs(300)
                && self.statement_timeout.as_millis() > 0
                && self.statement_timeout <= Duration::from_secs(30)
                && self.statement_timeout <= self.max_duration
                && self.lock_timeout.as_millis() > 0
                && self.lock_timeout <= Duration::from_secs(5)
                && self.lock_timeout <= self.max_duration,
            "PostgreSQL snapshot work limits exceed supported bounds"
        );
        Ok(())
    }
}

/// Successful exact-catalogue admission and held-snapshot row counts.
///
/// PostgreSQL has no SQLite integrity-check equivalent. This evidence declares
/// enforced, validated compiled constraints and exact counts, not disk integrity
/// or independent application/object closure. Construction remains private.
#[derive(Debug, Clone)]
pub struct PostgresSnapshotSourceAudit {
    table_counts: Vec<SqliteSnapshotTableCount>,
    catalogue_sha256: String,
    checked_expressions: usize,
}

impl PostgresSnapshotSourceAudit {
    /// Borrows all source table counts in trusted catalogue order.
    pub fn table_counts(&self) -> &[SqliteSnapshotTableCount] {
        &self.table_counts
    }

    /// Returns the number of CHECK and FK expressions checked against source rows.
    pub fn checked_expressions(&self) -> usize {
        self.checked_expressions
    }

    /// Borrows the normalized semantic catalogue commitment.
    pub fn catalogue_sha256(&self) -> &str {
        &self.catalogue_sha256
    }
}

/// One dedicated connection holding a bounded read-only source transaction.
pub struct PostgresSnapshotReader {
    transaction: Transaction<'static, Postgres>,
    pool: PgPool,
    schema: SqliteSnapshotSchema,
    deadline: Instant,
    statement_timeout: Duration,
    audit: PostgresSnapshotSourceAudit,
}

impl PostgresSnapshotReader {
    /// Opens and audits an existing current PostgreSQL source without writes.
    ///
    /// The connection string is used only for this dedicated pool. Errors omit
    /// connection/SQL diagnostics, which can otherwise contain private details.
    /// PostgreSQL major versions other than 18 fail closed before catalogue SQL.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits, unavailable connections, unsupported lineage or
    /// engine, altered schema, unvalidated constraints, denied reads and timeouts.
    pub async fn open(database_url: &str, limits: PostgresSnapshotLimits) -> Result<Self> {
        limits.validate()?;
        ensure!(
            crate::db::MIGRATIONS.len() == 8,
            "PostgreSQL capture contract requires explicit generation-eight support"
        );
        Self::open_inner(database_url, limits)
            .await
            .map_err(|_| anyhow::anyhow!("PostgreSQL snapshot source admission failed"))
    }

    async fn open_inner(database_url: &str, limits: PostgresSnapshotLimits) -> Result<Self> {
        let deadline = Instant::now()
            .checked_add(limits.max_duration)
            .ok_or_else(|| anyhow::anyhow!("snapshot deadline overflow"))?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .test_before_acquire(false)
            .acquire_timeout(limits.lock_timeout)
            .connect(database_url)
            .await?;
        let mut transaction = pool
            .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .await?;
        // Utility SET/SHOW and locks precede the first MVCC catalogue query.
        // Otherwise an intervening DDL commit could leave old catalogue facts
        // paired with a newly rewritten physical heap.
        sqlx::raw_sql(&format!(
            "SET LOCAL search_path TO pg_catalog, public; \
             SET LOCAL statement_timeout TO '{}ms'; \
             SET LOCAL lock_timeout TO '{}ms'; \
             SET LOCAL idle_in_transaction_session_timeout TO '{}ms'; \
             SET LOCAL transaction_timeout TO '{}ms'",
            limits.statement_timeout.as_millis(),
            limits.lock_timeout.as_millis(),
            limits.max_duration.as_millis(),
            limits.max_duration.as_millis()
        ))
        .execute(&mut *transaction)
        .await?;
        let version: String = sqlx::query_scalar("SHOW server_version_num")
            .fetch_one(&mut *transaction)
            .await?;
        ensure!(
            (180_000..190_000).contains(&version.parse::<u32>()?),
            "unsupported PostgreSQL major"
        );

        // Length-first budgets describe the bytes returned to the Rust client.
        // Cross-encoding conversion could expand text after octet_length checks.
        for setting in ["server_encoding", "client_encoding"] {
            let encoding: String = sqlx::query_scalar(&format!("SHOW {setting}"))
                .fetch_one(&mut *transaction)
                .await?;
            ensure!(
                encoding == "UTF8",
                "unsupported PostgreSQL source text encoding"
            );
        }

        let compiled = CompiledSqliteSnapshotCatalogue::load_generation(8).await?;
        let schema = compiled.schema().clone();
        // All names come from the compiled catalogue. These locks prohibit
        // concurrent rewrite/drop while ordinary DML and VACUUM remain allowed.
        let mut relations = compiled
            .definitions()
            .iter()
            .filter(|definition| {
                matches!(
                    definition.kind(),
                    CompiledSqliteSnapshotObjectKind::Table
                        | CompiledSqliteSnapshotObjectKind::View
                )
            })
            .map(|definition| definition.name())
            .collect::<Vec<_>>();
        relations.sort_unstable();
        let names = relations
            .into_iter()
            .map(|name| format!("public.{}", quote(name)))
            .collect::<Vec<_>>()
            .join(", ");
        sqlx::query(&format!("LOCK TABLE {names} IN ACCESS SHARE MODE"))
            .execute(&mut *transaction)
            .await?;
        let facts = catalogue::read(&mut transaction).await?;
        let catalogue_sha256 = catalogue::digest(&facts)?;
        ensure!(
            catalogue_sha256 == catalogue::expected_sha256(),
            "changed PostgreSQL semantic catalogue"
        );
        let version_matches: bool = sqlx::query_scalar(
            "SELECT count(*)=1 AND min(version)=8 AND max(version)=8 FROM public.schema_version",
        )
        .fetch_one(&mut *transaction)
        .await?;
        ensure!(version_matches, "unsupported PostgreSQL source generation");
        let identity_matches: bool = sqlx::query_scalar(
            "SELECT count(*)=1 AND bool_and(identity=$1) FROM public.hub_schema_identity",
        )
        .bind(&schema.identity)
        .fetch_one(&mut *transaction)
        .await?;
        ensure!(identity_matches, "source identity mismatch");

        let checked_expressions =
            audit::constraints(&mut transaction, &facts, deadline, limits.statement_timeout)
                .await?;
        let mut table_counts = Vec::with_capacity(schema.tables.len());
        for table in &schema.tables {
            refresh_timeout(&mut transaction, deadline, limits.statement_timeout).await?;
            let rows: i64 = sqlx::query_scalar(&format!(
                "SELECT count(*)::bigint FROM public.{}",
                quote(&table.name)
            ))
            .fetch_one(&mut *transaction)
            .await?;
            table_counts.push(SqliteSnapshotTableCount {
                table: table.name.clone(),
                rows: u64::try_from(rows)?,
            });
        }
        ensure!(
            Instant::now() < deadline,
            "snapshot source deadline exhausted"
        );
        Ok(Self {
            transaction,
            pool,
            schema,
            deadline,
            statement_timeout: limits.statement_timeout,
            audit: PostgresSnapshotSourceAudit {
                table_counts,
                catalogue_sha256,
                checked_expressions,
            },
        })
    }

    /// Borrows the exact logical schema shared with current archive classifiers.
    pub fn schema(&self) -> &SqliteSnapshotSchema {
        &self.schema
    }

    /// Borrows opaque successful source admission and row counts.
    pub fn audit(&self) -> &PostgresSnapshotSourceAudit {
        &self.audit
    }

    /// Starts bounded enumeration of a compiled source table.
    ///
    /// # Errors
    ///
    /// Rejects unknown tables and exhausted transaction duration.
    pub fn table(&mut self, name: &str) -> Result<PostgresSnapshotTable<'_>> {
        ensure!(
            Instant::now() < self.deadline,
            "snapshot source deadline exhausted"
        );
        let schema = self
            .schema
            .tables
            .iter()
            .find(|table| table.name == name)
            .ok_or_else(|| anyhow::anyhow!("table is not in the compiled source catalogue"))?
            .clone();
        Ok(PostgresSnapshotTable::new(
            &mut self.transaction,
            schema,
            self.deadline,
            self.statement_timeout,
        ))
    }

    /// Releases the held snapshot and closes its dedicated pool.
    ///
    /// # Errors
    ///
    /// Returns an error if rollback cannot be confirmed. No write is committed.
    pub async fn close(self) -> Result<()> {
        self.transaction
            .rollback()
            .await
            .map_err(|_| anyhow::anyhow!("snapshot source close failed"))?;
        self.pool.close().await;
        ensure!(
            Instant::now() < self.deadline,
            "snapshot source deadline exhausted"
        );
        Ok(())
    }
}

fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

async fn refresh_timeout(
    transaction: &mut Transaction<'static, Postgres>,
    deadline: Instant,
    limit: Duration,
) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| anyhow::anyhow!("snapshot source deadline exhausted"))?;
    let milliseconds = remaining.min(limit).as_millis();
    ensure!(milliseconds > 0, "snapshot source deadline exhausted");
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(format!("{milliseconds}ms"))
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

#[cfg(test)]
#[path = "postgres_snapshot/tests.rs"]
mod tests;
