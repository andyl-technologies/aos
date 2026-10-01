//! PostgreSQL reset-only initialization under one transaction advisory lock.

use anyhow::{ensure, Context, Result};
use sqlx::{PgConnection, PgPool};

use crate::backend::schema_lineage::{admit_serving, SchemaAdmission, RESET_REQUIRED};
use crate::db::{HISTORICAL_SCHEMA_IDENTITY, MIGRATIONS, SCHEMA_IDENTITY, SCHEMA_VERSION_DDL};
use crate::dialect::Dialect;

// This application namespace exists before any schema bookkeeping table.
const MIGRATION_LOCK: i64 = 0x414f_535f_5343_484d;

pub(super) async fn migrate(pool: &PgPool) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(MIGRATION_LOCK)
        .execute(&mut *transaction)
        .await?;
    // Restrict unqualified DDL to the selected owned schema. Otherwise a
    // lower search-path schema could satisfy CREATE IF NOT EXISTS and be
    // stamped despite the first schema being empty.
    let selected: String = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(&mut *transaction)
        .await?;
    ensure!(
        !selected.is_empty() && selected.len() <= 255,
        "{RESET_REQUIRED}"
    );
    sqlx::query("SELECT set_config('search_path',quote_ident($1),true)")
        .bind(&selected)
        .execute(&mut *transaction)
        .await?;
    let admission = inspect(&mut transaction).await.context(RESET_REQUIRED)?;
    if admission.applied == 0 {
        sqlx::query(&Dialect::Postgres.translate(SCHEMA_VERSION_DDL)?.sql)
            .execute(&mut *transaction)
            .await?;
        for script in MIGRATIONS {
            for statement in crate::backend::split_statements(script) {
                sqlx::query(&Dialect::Postgres.translate(&statement)?.sql)
                    .execute(&mut *transaction)
                    .await?;
            }
        }
        let stamped = sqlx::query("UPDATE hub_schema_identity SET identity=$1 WHERE identity=$2")
            .bind(SCHEMA_IDENTITY)
            .bind(HISTORICAL_SCHEMA_IDENTITY)
            .execute(&mut *transaction)
            .await?;
        ensure!(
            stamped.rows_affected() == 1,
            "fresh serving identity did not settle"
        );
        sqlx::query("INSERT INTO schema_version(version) VALUES ($1)")
            .bind(i64::try_from(MIGRATIONS.len())?)
            .execute(&mut *transaction)
            .await?;
    }
    ensure!(
        inspect(&mut transaction).await?.applied == MIGRATIONS.len(),
        "fresh PostgreSQL initialization did not settle"
    );
    transaction.commit().await?;
    Ok(())
}

async fn inspect(connection: &mut PgConnection) -> Result<SchemaAdmission> {
    // Count every user relation, routine and type in the selected schema. A
    // relation-only check would incorrectly initialize over a function/type.
    let empty: bool = sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() UNION ALL SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=current_schema() UNION ALL SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname=current_schema())")
        .fetch_one(&mut *connection).await?;
    if empty {
        return admit_serving(true, &[], &[]);
    }
    let tables: Vec<String> = sqlx::query_scalar("SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind='r' AND c.relname IN ('schema_version','hub_schema_identity') ORDER BY c.relname LIMIT 3")
        .fetch_all(&mut *connection).await?;
    ensure!(
        tables == ["hub_schema_identity", "schema_version"],
        "{RESET_REQUIRED}"
    );
    let sizes: Vec<i32> =
        sqlx::query_scalar("SELECT octet_length(identity) FROM hub_schema_identity LIMIT 2")
            .fetch_all(&mut *connection)
            .await?;
    ensure!(
        sizes == [i32::try_from(SCHEMA_IDENTITY.len())?],
        "{RESET_REQUIRED}"
    );
    let identities: Vec<String> =
        sqlx::query_scalar("SELECT identity FROM hub_schema_identity LIMIT 2")
            .fetch_all(&mut *connection)
            .await?;
    let versions: Vec<i64> = sqlx::query_scalar("SELECT version FROM schema_version LIMIT 2")
        .fetch_all(&mut *connection)
        .await?;
    admit_serving(false, &versions, &identities)
}
