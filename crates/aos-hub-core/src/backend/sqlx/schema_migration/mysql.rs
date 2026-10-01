//! MySQL-family reset-only initialization with a same-connection named lock.
//!
//! DDL can commit implicitly. A detached connection owns the lock through every
//! statement; cancellation closes it rather than returning a held lock to the
//! pool. Interrupted DDL leaves a nonempty schema without the new serving stamp
//! and therefore requires explicit reset, never inferred prefix resumption.

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use sqlx::{Connection as _, MySqlConnection, MySqlPool, Row as _};

use crate::backend::schema_lineage::{admit_serving, SchemaAdmission, RESET_REQUIRED};
use crate::db::{HISTORICAL_SCHEMA_IDENTITY, MIGRATIONS, SCHEMA_IDENTITY, SCHEMA_VERSION_DDL};
use crate::dialect::Dialect;

pub(super) async fn migrate(pool: &MySqlPool) -> Result<()> {
    let mut connection = pool.acquire().await?.detach();
    let database: String = sqlx::query_scalar("SELECT DATABASE()")
        .fetch_one(&mut connection)
        .await?;
    let lock = format!(
        "aos-hub-schema:{}",
        &hex::encode(Sha256::digest(database.as_bytes()))[..48]
    );
    let acquired: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?,30)")
        .bind(&lock)
        .fetch_one(&mut connection)
        .await?;
    ensure!(
        acquired == Some(1),
        "Hub schema initialization lock was not acquired"
    );

    let result = migrate_held(&mut connection).await;
    let release = sqlx::query_scalar::<_, Option<i64>>("SELECT RELEASE_LOCK(?)")
        .bind(&lock)
        .fetch_one(&mut connection)
        .await;
    let close = connection.close().await;
    // Preserve the initialization error even if cleanup also fails. Closing the
    // detached connection remains the final lock-release fence in either case.
    result?;
    ensure!(
        release? == Some(1),
        "Hub schema initialization lock was not released"
    );
    close?;
    Ok(())
}

async fn migrate_held(connection: &mut MySqlConnection) -> Result<()> {
    if inspect(connection).await.context(RESET_REQUIRED)?.applied == 0 {
        for statement in [
            SCHEMA_VERSION_DDL,
            "CREATE TABLE hub_schema_version(id INTEGER PRIMARY KEY,version INTEGER NOT NULL)",
        ] {
            sqlx::query(&Dialect::Mysql.translate(statement)?.sql)
                .execute(&mut *connection)
                .await?;
        }
        for script in MIGRATIONS {
            for statement in crate::backend::split_statements(script) {
                sqlx::query(&Dialect::Mysql.translate(&statement)?.sql)
                    .execute(&mut *connection)
                    .await?;
            }
        }
        // The new identity is stamped last, atomically with both current
        // ledgers. A partially initialized implicit-DDL schema cannot reopen.
        let mut transaction = connection.begin().await?;
        sqlx::query("INSERT INTO schema_version(version) VALUES (?)")
            .bind(i64::try_from(MIGRATIONS.len())?)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO hub_schema_version(id,version) VALUES(1,?)")
            .bind(i64::try_from(MIGRATIONS.len())?)
            .execute(&mut *transaction)
            .await?;
        let stamped = sqlx::query("UPDATE hub_schema_identity SET identity=? WHERE identity=?")
            .bind(SCHEMA_IDENTITY)
            .bind(HISTORICAL_SCHEMA_IDENTITY)
            .execute(&mut *transaction)
            .await?;
        ensure!(
            stamped.rows_affected() == 1,
            "fresh serving identity did not settle"
        );
        transaction.commit().await?;
    }
    ensure!(
        inspect(connection).await?.applied == MIGRATIONS.len(),
        "fresh MySQL-family initialization did not settle"
    );
    Ok(())
}

async fn inspect(connection: &mut MySqlConnection) -> Result<SchemaAdmission> {
    let empty: i64 = sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() UNION ALL SELECT 1 FROM information_schema.routines WHERE routine_schema=DATABASE() UNION ALL SELECT 1 FROM information_schema.triggers WHERE trigger_schema=DATABASE() UNION ALL SELECT 1 FROM information_schema.events WHERE event_schema=DATABASE())")
        .fetch_one(&mut *connection).await?;
    if empty == 1 {
        return admit_serving(true, &[], &[]);
    }
    let tables: Vec<String> = sqlx::query_scalar("SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_type='BASE TABLE' AND table_name IN ('schema_version','hub_schema_identity','hub_schema_version') ORDER BY table_name LIMIT 4")
        .fetch_all(&mut *connection).await?;
    ensure!(
        tables
            == [
                "hub_schema_identity",
                "hub_schema_version",
                "schema_version"
            ],
        "{RESET_REQUIRED}"
    );
    let lengths: Vec<i64> = sqlx::query_scalar(
        "SELECT CAST(octet_length(identity) AS SIGNED) FROM hub_schema_identity LIMIT 2",
    )
    .fetch_all(&mut *connection)
    .await?;
    ensure!(
        lengths == [i64::try_from(SCHEMA_IDENTITY.len())?],
        "{RESET_REQUIRED}"
    );
    let identities: Vec<String> =
        sqlx::query_scalar("SELECT identity FROM hub_schema_identity LIMIT 2")
            .fetch_all(&mut *connection)
            .await?;
    let versions: Vec<i64> = sqlx::query_scalar("SELECT version FROM schema_version LIMIT 2")
        .fetch_all(&mut *connection)
        .await?;
    let keyed = sqlx::query("SELECT id,version FROM hub_schema_version LIMIT 2")
        .fetch_all(&mut *connection)
        .await?;
    ensure!(
        keyed.len() == 1
            && keyed[0].try_get::<i64, _>(0)? == 1
            && versions == [keyed[0].try_get::<i64, _>(1)?],
        "{RESET_REQUIRED}"
    );
    admit_serving(false, &versions, &identities)
}
