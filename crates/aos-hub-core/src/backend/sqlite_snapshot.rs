//! Read-only, consistent SQLite input for a future logical Hub snapshot.
//!
//! The reader validates the exact current production schema before exposing
//! rows, then keeps one read transaction pinned across bounded table pages.
//! It neither creates nor migrates the source, changes its journal mode, nor
//! exposes arbitrary SQL. It returns the existing lossless [`Value`] classes.
//!
//! This is a database input seam, not a complete export: the caller must still
//! classify secrets and application references, authenticate the artifact, and
//! reconcile object closure and external guard authority. A read transaction
//! cannot quiesce provider work. SQLite may acquire its normal read locks and
//! coordinate through existing WAL shared memory; `immutable` mode is avoided
//! because it would ignore concurrent WAL changes and invalidate consistency.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Row as _, Sqlite, SqliteConnection, SqlitePool, Transaction, TypeInfo, ValueRef};

use crate::db::{MIGRATIONS, SCHEMA_IDENTITY};
use crate::value::{Row, Value};

#[path = "sqlite_snapshot/source_audit.rs"]
mod source_audit;

#[path = "sqlite_snapshot/compiled_checks.rs"]
mod compiled_checks;

mod catalogue;

pub use catalogue::{
    CompiledSqliteSnapshotCatalogue, CompiledSqliteSnapshotDefinition,
    CompiledSqliteSnapshotDisposition, CompiledSqliteSnapshotObjectKind,
};

pub use source_audit::{
    SqliteSnapshotAuditLimits, SqliteSnapshotSourceAudit, SqliteSnapshotTableCount,
};

const MAX_PAGE_ROWS: usize = 256;
const MAX_CELL_BYTES: usize = 1024 * 1024;
const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_SCHEMA_OBJECTS: i64 = 4096;
const MAX_SCHEMA_SQL_BYTES: i64 = 128 * 1024;
const MAX_SCHEMA_BYTES: i64 = 16 * 1024 * 1024;
const MAX_IDENTIFIER_BYTES: i64 = 255;

/// Limits applied before loading a page's variable-size cells.
#[derive(Debug, Clone, Copy)]
pub struct SqliteSnapshotLimits {
    /// Maximum rows in one page, between one and 256.
    pub max_rows: usize,
    /// Maximum bytes in one cell, between eight and one MiB.
    pub max_cell_bytes: usize,
    /// Maximum total value payload bytes in one page, at most eight MiB.
    ///
    /// Integers and reals account for eight bytes, null for zero, and text and
    /// bytes for their exact byte length. Fixed row/value overhead is also
    /// bounded by the row limit and the validated, finite source schema.
    pub max_page_bytes: usize,
}

impl Default for SqliteSnapshotLimits {
    fn default() -> Self {
        Self {
            max_rows: 128,
            max_cell_bytes: MAX_CELL_BYTES,
            max_page_bytes: MAX_PAGE_BYTES,
        }
    }
}

impl SqliteSnapshotLimits {
    fn validate(self) -> Result<()> {
        ensure!(
            (1..=MAX_PAGE_ROWS).contains(&self.max_rows)
                && (8..=MAX_CELL_BYTES).contains(&self.max_cell_bytes)
                && (8..=MAX_PAGE_BYTES).contains(&self.max_page_bytes),
            "snapshot page limits exceed the supported bounds"
        );
        Ok(())
    }
}

/// Exact column order for one schema-validated source table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteSnapshotTableSchema {
    /// Identifier obtained from the compiled production schema.
    pub name: String,
    /// Source columns in their declared order, excluding SQLite's hidden rowid.
    pub columns: Vec<String>,
}

/// Validated lineage and the compiled schema against which it was checked.
#[derive(Debug, Clone)]
pub struct SqliteSnapshotSchema {
    /// Exact production migration lineage.
    pub identity: String,
    /// Current, fully applied migration count.
    pub version: usize,
    /// SHA-256 of each compiled migration's original bytes, in order.
    ///
    /// The existing SQL ledger records versions, not historical script hashes.
    /// These hashes identify the schema definition used by this reader; they
    /// are not a fabricated provider attestation of past migration execution.
    pub migration_digests: Vec<String>,
    /// All application tables and the source version ledger.
    pub tables: Vec<SqliteSnapshotTableSchema>,
}

/// One bounded page of lossless SQL rows from a consistent read transaction.
#[derive(Debug)]
pub struct SqliteSnapshotPage {
    /// Rows in declared column order; classification has not been applied.
    pub rows: Vec<Row>,
    /// Total value payload bytes under [`SqliteSnapshotLimits`].
    pub payload_bytes: usize,
    /// Whether the table has been exhausted at this read snapshot.
    pub finished: bool,
}

/// A read-only SQLite connection with one transaction pinned until closed.
pub struct SqliteSnapshotReader {
    transaction: Transaction<'static, Sqlite>,
    pool: SqlitePool,
    schema: SqliteSnapshotSchema,
    compiled_checks: BTreeMap<String, Vec<String>>,
    #[cfg(test)]
    audit_progress_started: Option<tokio::sync::oneshot::Sender<()>>,
    #[cfg(test)]
    audit_pause_at_progress: bool,
}

impl SqliteSnapshotReader {
    /// Opens an existing file read-only and validates the complete current schema.
    ///
    /// The first validation query pins the read snapshot. No schema or journal
    /// PRAGMA is changed, and a missing path is never created. This deliberately
    /// does not use `Database::open` or the migrating native backend opener.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/non-file path, an unavailable read lock,
    /// unknown/incomplete/future lineage, changed schema objects, or SQL failure.
    pub async fn open(path: &Path) -> Result<Self> {
        ensure!(
            std::fs::metadata(path)
                .with_context(|| format!("opening snapshot source {}", path.display()))?
                .is_file(),
            "snapshot source must be an existing database file"
        );
        let options = SqliteConnectOptions::new()
            .filename(path)
            .read_only(true)
            .create_if_missing(false)
            .pragma("query_only", "ON")
            .row_buffer_size(1);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .test_before_acquire(false)
            .connect_with(options)
            .await
            .context("opening read-only snapshot connection")?;
        let mut transaction = pool.begin().await.context("pinning snapshot transaction")?;

        validate_lineage(&mut transaction).await?;
        let (expected_objects, tables) = compiled_schema().await?;
        let actual_objects = schema_objects(&mut transaction).await?;
        ensure!(
            actual_objects == expected_objects,
            "snapshot source schema differs from the compiled production migrations"
        );
        let compiled_checks = compiled_checks::extract_compiled_checks(&expected_objects)?;
        let schema = SqliteSnapshotSchema {
            identity: SCHEMA_IDENTITY.to_string(),
            version: MIGRATIONS.len(),
            migration_digests: MIGRATIONS
                .iter()
                .map(|migration| hex::encode(Sha256::digest(migration.as_bytes())))
                .collect(),
            tables,
        };
        Ok(Self {
            transaction,
            pool,
            schema,
            compiled_checks,
            #[cfg(test)]
            audit_progress_started: None,
            #[cfg(test)]
            audit_pause_at_progress: false,
        })
    }

    /// Borrows the validated source schema; this method performs no database I/O.
    #[must_use]
    pub fn schema(&self) -> &SqliteSnapshotSchema {
        &self.schema
    }

    /// Starts bounded enumeration of a schema-selected table.
    ///
    /// SQLite rowid orders the input pages only; it is not an exported logical
    /// identity. Original declared IDs remain in the returned row values.
    ///
    /// # Errors
    ///
    /// Returns an error when `name` is not in the validated production schema.
    pub fn table(&mut self, name: &str) -> Result<SqliteSnapshotTable<'_>> {
        let table = self
            .schema
            .tables
            .iter()
            .find(|table| table.name == name)
            .context("table is not part of the validated snapshot schema")?
            .clone();
        Ok(SqliteSnapshotTable {
            transaction: &mut self.transaction,
            schema: table,
            last_rowid: None,
            finished: false,
        })
    }

    /// Rolls back the read transaction and closes its pool.
    ///
    /// Dropping the reader also schedules rollback through SQLx. Explicit close
    /// waits until the connection and its read lock have been released.
    ///
    /// # Errors
    ///
    /// Returns an error if releasing the read transaction fails.
    pub async fn close(self) -> Result<()> {
        self.transaction.rollback().await?;
        self.pool.close().await;
        Ok(())
    }
}

/// A table cursor borrowing the reader's single pinned transaction.
pub struct SqliteSnapshotTable<'a> {
    transaction: &'a mut Transaction<'static, Sqlite>,
    schema: SqliteSnapshotTableSchema,
    last_rowid: Option<i64>,
    finished: bool,
}

impl SqliteSnapshotTable<'_> {
    /// Borrows the declared column order for the returned row values.
    #[must_use]
    pub fn schema(&self) -> &SqliteSnapshotTableSchema {
        &self.schema
    }

    /// Reads the next bounded page without changing the source or read snapshot.
    ///
    /// Cell sizes are checked inside the pinned transaction before variable
    /// payloads are fetched. An oversized first row is rejected rather than
    /// skipped; a failed page does not advance this cursor.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, oversized cells/rows, unsupported
    /// values, invalid UTF-8/nonfinite reals, or SQL failure.
    pub async fn next_page(&mut self, limits: SqliteSnapshotLimits) -> Result<SqliteSnapshotPage> {
        limits.validate()?;
        if self.finished {
            return Ok(SqliteSnapshotPage {
                rows: Vec::new(),
                payload_bytes: 0,
                finished: true,
            });
        }

        let table = quote_identifier(&self.schema.name);
        let columns: Vec<String> = self
            .schema
            .columns
            .iter()
            .map(|c| quote_identifier(c))
            .collect();
        let sizes: Vec<String> = columns
            .iter()
            .map(|column| {
                format!(
                    "CASE typeof({column}) WHEN 'null' THEN 0
                 WHEN 'integer' THEN 8 WHEN 'real' THEN 8
                 WHEN 'text' THEN octet_length({column})
                 WHEN 'blob' THEN length({column}) ELSE -1 END"
                )
            })
            .collect();
        let lower_bound = if self.last_rowid.is_some() {
            "WHERE _rowid_ > ?1"
        } else {
            ""
        };
        let metadata_sql = format!(
            "SELECT _rowid_, {} FROM {table} {lower_bound} ORDER BY _rowid_ LIMIT ?2",
            sizes.join(", ")
        );
        let metadata = sqlx::query(&metadata_sql)
            .bind(self.last_rowid)
            .bind(i64::try_from(limits.max_rows)?)
            .fetch_all(&mut **self.transaction)
            .await?;

        let mut payload_bytes = 0_usize;
        let mut count = 0_usize;
        for row in &metadata {
            let mut row_bytes = 0_usize;
            for column in 1..row.len() {
                let size = usize::try_from(row.try_get::<i64, _>(column)?)
                    .context("unsupported snapshot cell storage class")?;
                ensure!(
                    size <= limits.max_cell_bytes,
                    "snapshot cell exceeds the byte limit"
                );
                row_bytes = row_bytes
                    .checked_add(size)
                    .context("snapshot row size overflow")?;
            }
            let next_bytes = payload_bytes
                .checked_add(row_bytes)
                .context("snapshot page size overflow")?;
            if next_bytes > limits.max_page_bytes {
                ensure!(count > 0, "snapshot row exceeds the page byte limit");
                break;
            }
            payload_bytes = next_bytes;
            count += 1;
        }

        let Some(last) = metadata.get(count.saturating_sub(1)).filter(|_| count > 0) else {
            self.finished = true;
            return Ok(SqliteSnapshotPage {
                rows: Vec::new(),
                payload_bytes: 0,
                finished: true,
            });
        };
        let last_rowid: i64 = last.try_get(0)?;
        let range = if self.last_rowid.is_some() {
            "_rowid_ > ?1 AND _rowid_ <= ?2"
        } else {
            "_rowid_ <= ?2"
        };
        let sql = format!(
            "SELECT {} FROM {table} WHERE {range} ORDER BY _rowid_",
            columns.join(", ")
        );
        let fetched = sqlx::query(&sql)
            .bind(self.last_rowid)
            .bind(last_rowid)
            .fetch_all(&mut **self.transaction)
            .await?;
        ensure!(
            fetched.len() == count,
            "snapshot page changed inside its pinned transaction"
        );
        let rows = fetched.iter().map(decode_row).collect::<Result<Vec<_>>>()?;

        self.last_rowid = Some(last_rowid);
        self.finished = count == metadata.len() && metadata.len() < limits.max_rows;
        Ok(SqliteSnapshotPage {
            rows,
            payload_bytes,
            finished: self.finished,
        })
    }
}

async fn validate_lineage(connection: &mut SqliteConnection) -> Result<()> {
    // A rejected source can contain unbounded marker payloads even with an
    // otherwise valid catalogue. Project fixed-size metadata, never raw text
    // or blob cells, before schema validation and page limits have run.
    let versions = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT CASE WHEN typeof(version) = 'integer' THEN version ELSE NULL END
         FROM schema_version LIMIT 2",
    )
    .fetch_all(&mut *connection)
    .await
    .context("snapshot source has no production version ledger")?;
    ensure!(
        versions.len() == 1,
        "snapshot source requires one version ledger row"
    );
    let version = versions[0].context("invalid snapshot schema version type")?;
    ensure!(
        version == i64::try_from(MIGRATIONS.len())?,
        "snapshot source requires the exact current migration version"
    );

    let identities = sqlx::query_scalar::<_, i64>(
        "SELECT CASE WHEN typeof(identity) = 'text' AND octet_length(identity) = ?2
         THEN identity = ?1 COLLATE BINARY ELSE 0 END FROM hub_schema_identity LIMIT 2",
    )
    .bind(SCHEMA_IDENTITY)
    .bind(i64::try_from(SCHEMA_IDENTITY.len())?)
    .fetch_all(connection)
    .await
    .context("snapshot source has no production schema identity")?;
    ensure!(
        identities.len() == 1,
        "snapshot source requires one schema identity row"
    );
    ensure!(
        identities[0] == 1,
        "snapshot source belongs to an unsupported migration lineage"
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct SchemaObject {
    kind: String,
    name: String,
    table: String,
    sql: Option<String>,
}

async fn schema_objects(connection: &mut SqliteConnection) -> Result<Vec<SchemaObject>> {
    let metadata: (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(octet_length(name) + octet_length(tbl_name)
         + COALESCE(octet_length(sql), 0)), 0) FROM sqlite_schema",
    )
    .fetch_one(&mut *connection)
    .await?;
    ensure!(
        metadata.0 <= MAX_SCHEMA_OBJECTS && metadata.1 <= MAX_SCHEMA_BYTES,
        "snapshot schema metadata exceeds the aggregate bounds"
    );
    let oversized = sqlx::query(
        "SELECT 1 FROM sqlite_schema
         WHERE octet_length(name) > ?1 OR octet_length(tbl_name) > ?1
              OR octet_length(sql) > ?2 LIMIT 1",
    )
    .bind(MAX_IDENTIFIER_BYTES)
    .bind(MAX_SCHEMA_SQL_BYTES)
    .fetch_optional(&mut *connection)
    .await?;
    ensure!(
        oversized.is_none(),
        "snapshot schema metadata exceeds the supported bounds"
    );
    let rows = sqlx::query(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name LIMIT ?1",
    )
    .bind(MAX_SCHEMA_OBJECTS + 1)
    .fetch_all(connection)
    .await?;
    ensure!(
        rows.len() <= usize::try_from(MAX_SCHEMA_OBJECTS)?,
        "snapshot schema has too many objects"
    );
    rows.into_iter()
        .map(|row| {
            Ok(SchemaObject {
                kind: row.try_get(0)?,
                name: row.try_get(1)?,
                table: row.try_get(2)?,
                sql: row.try_get(3)?,
            })
        })
        .collect()
}

async fn compiled_schema() -> Result<(Vec<SchemaObject>, Vec<SqliteSnapshotTableSchema>)> {
    compiled_schema_for_generation(MIGRATIONS.len()).await
}

async fn compiled_schema_for_generation(
    version: usize,
) -> Result<(Vec<SchemaObject>, Vec<SqliteSnapshotTableSchema>)> {
    use crate::backend::Backend as _;

    // Only checked-in generations can select a migration slice. Historical
    // verification never compiles current DDL and calls it an older schema.
    crate::snapshot::SnapshotClassifier::for_supported_generation(version)?;
    let scripts = MIGRATIONS
        .get(..version)
        .ok_or_else(|| anyhow::anyhow!("snapshot compiled generation is absent"))?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().in_memory(true))
        .await?;
    let backend = super::SqlxBackend::Sqlite(pool.clone());
    backend.execute(crate::db::SCHEMA_VERSION_DDL, &[]).await?;
    let statements = scripts
        .iter()
        .flat_map(|script| super::split_statements(script))
        .map(|sql| super::Statement::new(sql, Vec::new()))
        .collect::<Vec<_>>();
    backend.batch(&statements).await?;
    let mut connection = pool.acquire().await?;
    let objects = schema_objects(&mut connection).await?;
    let mut tables = Vec::new();
    for object in objects.iter().filter(|object| object.kind == "table") {
        let sql = format!("PRAGMA table_info({})", quote_identifier(&object.name));
        let rows = sqlx::query(&sql).fetch_all(&mut *connection).await?;
        let columns = rows
            .iter()
            .map(|row| row.try_get::<String, _>(1))
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            !columns.iter().any(|column| matches!(
                column.to_lowercase().as_str(),
                "rowid" | "_rowid_" | "oid"
            )),
            "snapshot schema shadows SQLite rowid"
        );
        ensure!(
            object
                .sql
                .as_ref()
                .is_none_or(|sql| !sql.to_uppercase().contains("WITHOUT ROWID")),
            "snapshot table requires a SQLite rowid"
        );
        tables.push(SqliteSnapshotTableSchema {
            name: object.name.clone(),
            columns,
        });
    }
    drop(connection);
    drop(backend);
    pool.close().await;
    Ok((objects, tables))
}

fn quote_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn decode_row(row: &SqliteRow) -> Result<Row> {
    let mut values = Vec::with_capacity(row.len());
    for column in 0..row.len() {
        let raw = row.try_get_raw(column)?;
        let value = if raw.is_null() {
            Value::Null
        } else {
            match raw.type_info().name() {
                "INTEGER" | "BOOLEAN" => Value::Int(row.try_get(column)?),
                "REAL" | "FLOAT" | "DOUBLE" => {
                    let value: f64 = row.try_get(column)?;
                    ensure!(value.is_finite(), "snapshot contains a nonfinite real");
                    Value::Real(value)
                }
                "TEXT" => Value::Text(row.try_get(column)?),
                "BLOB" => Value::Bytes(row.try_get(column)?),
                name => bail!("unsupported snapshot SQLite storage class {name}"),
            }
        };
        values.push(value);
    }
    Ok(Row::new(values))
}

#[cfg(test)]
mod tests;
