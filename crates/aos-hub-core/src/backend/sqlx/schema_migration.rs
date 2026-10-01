//! Holds the actual driver migration lock across lineage admission and writes.

#[cfg(feature = "mysql")]
mod mysql;
#[cfg(feature = "postgres")]
mod postgres;

use anyhow::{ensure, Context, Result};
use sqlx::{Row as _, SqliteConnection};

use super::SqlxBackend;
use crate::backend::schema_lineage::{
    admit_sqlite, SchemaAdmission, SqliteMigrationLedger, SqliteSchemaObject, MAX_SCHEMA_BYTES,
    MAX_SCHEMA_DEFINITION_BYTES, MAX_SCHEMA_IDENTIFIER_BYTES, MAX_SCHEMA_OBJECTS, RESET_REQUIRED,
};
use crate::db::{HISTORICAL_SCHEMA_IDENTITY, MIGRATIONS, SCHEMA_IDENTITY, SCHEMA_VERSION_DDL};
use crate::dialect::Dialect;

pub(super) async fn migrate(backend: &SqlxBackend) -> Result<()> {
    match backend {
        SqlxBackend::Sqlite(pool) => {
            // This lock exists before the first schema-version row/table. The
            // SQLx transaction also queues rollback if this future is cancelled.
            let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
            let admission = inspect_sqlite(&mut transaction)
                .await
                .context(RESET_REQUIRED)?;
            if admission.applied < MIGRATIONS.len() {
                sqlx::query(SCHEMA_VERSION_DDL)
                    .execute(&mut *transaction)
                    .await?;
                for script in &MIGRATIONS[admission.applied..] {
                    for statement in crate::backend::split_statements(script) {
                        let translated = Dialect::Sqlite.translate(&statement)?;
                        sqlx::query(&translated.sql)
                            .execute(&mut *transaction)
                            .await?;
                    }
                }
                let stamped =
                    sqlx::query("UPDATE hub_schema_identity SET identity=?1 WHERE identity=?2")
                        .bind(SCHEMA_IDENTITY)
                        .bind(HISTORICAL_SCHEMA_IDENTITY)
                        .execute(&mut *transaction)
                        .await?;
                ensure!(
                    stamped.rows_affected() == 1,
                    "fresh serving identity did not settle"
                );
                sqlx::query("INSERT INTO schema_version(version) VALUES (?1)")
                    .bind(i64::try_from(MIGRATIONS.len())?)
                    .execute(&mut *transaction)
                    .await?;
            }
            let current = inspect_sqlite(&mut transaction)
                .await
                .context("validating the initialized serving singleton")?;
            ensure!(
                current.applied == MIGRATIONS.len(),
                "canonical schema migration did not settle"
            );
            transaction.commit().await?;
            Ok(())
        }
        #[cfg(feature = "postgres")]
        SqlxBackend::Postgres(pool) => postgres::migrate(pool).await,
        #[cfg(feature = "mysql")]
        SqlxBackend::Mysql(pool) => mysql::migrate(pool).await,
    }
}

async fn inspect_sqlite(connection: &mut SqliteConnection) -> Result<SchemaAdmission> {
    let (count, bytes): (i64,i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(length(CAST(type AS BLOB)) + length(CAST(name AS BLOB)) + length(CAST(tbl_name AS BLOB)) + COALESCE(length(CAST(sql AS BLOB)),0)),0) FROM sqlite_schema",
    ).fetch_one(&mut *connection).await?;
    ensure!(
        count >= 0
            && count <= i64::try_from(MAX_SCHEMA_OBJECTS)?
            && bytes >= 0
            && bytes <= i64::try_from(MAX_SCHEMA_BYTES)?,
        "{RESET_REQUIRED}"
    );
    let oversized = sqlx::query(
        "SELECT 1 FROM sqlite_schema WHERE length(CAST(name AS BLOB)) > ?1 OR length(CAST(tbl_name AS BLOB)) > ?1 OR length(CAST(sql AS BLOB)) > ?2 LIMIT 1",
    ).bind(i64::try_from(MAX_SCHEMA_IDENTIFIER_BYTES)?).bind(i64::try_from(MAX_SCHEMA_DEFINITION_BYTES)?).fetch_optional(&mut *connection).await?;
    ensure!(oversized.is_none(), "{RESET_REQUIRED}");
    let rows =
        sqlx::query("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name LIMIT ?1")
            .bind(i64::try_from(MAX_SCHEMA_OBJECTS + 1)?)
            .fetch_all(&mut *connection)
            .await?;
    let objects = rows
        .into_iter()
        .map(|row| {
            Ok(SqliteSchemaObject {
                kind: row.try_get(0)?,
                name: row.try_get(1)?,
                table: row.try_get(2)?,
                definition: row.try_get(3)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut versions = Vec::new();
    let mut identities = Vec::new();
    if objects
        .iter()
        .any(|object| object.kind == "table" && object.name == "schema_version")
    {
        versions = sqlx::query_scalar::<_, i64>("SELECT version FROM schema_version LIMIT 2")
            .fetch_all(&mut *connection)
            .await?;
    }
    if objects
        .iter()
        .any(|object| object.kind == "table" && object.name == "hub_schema_identity")
    {
        let lengths = sqlx::query_scalar::<_, i64>(
            "SELECT length(CAST(identity AS BLOB)) FROM hub_schema_identity LIMIT 2",
        )
        .fetch_all(&mut *connection)
        .await?;
        ensure!(
            lengths == [i64::try_from(crate::db::SCHEMA_IDENTITY.len())?],
            "{RESET_REQUIRED}"
        );
        identities =
            sqlx::query_scalar::<_, String>("SELECT identity FROM hub_schema_identity LIMIT 2")
                .fetch_all(&mut *connection)
                .await?;
    }
    admit_sqlite(
        &objects,
        SqliteMigrationLedger::Native,
        &versions,
        &[],
        &identities,
    )
}

#[cfg(test)]
mod tests;
