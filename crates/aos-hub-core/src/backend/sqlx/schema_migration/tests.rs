//! Actual SQLite migration admission, no-write refusal and concurrent startup.

use super::*;
use crate::backend::Backend as _;
use crate::db::SCHEMA_IDENTITY;

async fn seed(backend: &SqlxBackend, scripts: &[&str], version: i64) {
    backend.execute(SCHEMA_VERSION_DDL, &[]).await.unwrap();
    for script in scripts {
        let statements = crate::backend::split_statements(script)
            .into_iter()
            .map(|sql| crate::backend::Statement::new(sql, Vec::new()))
            .collect::<Vec<_>>();
        backend.batch(&statements).await.unwrap();
    }
    backend
        .execute(
            "INSERT INTO schema_version(version) VALUES (?1)",
            &[crate::value::Value::Int(version)],
        )
        .await
        .unwrap();
}

async fn fingerprint(backend: &SqlxBackend) -> String {
    let schema = backend
        .query(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name",
            &[],
        )
        .await
        .unwrap();
    let version = backend
        .query("SELECT version FROM schema_version", &[])
        .await
        .unwrap();
    let identity = backend
        .query("SELECT identity FROM hub_schema_identity", &[])
        .await
        .unwrap();
    let payload = backend
        .query("SELECT email FROM users ORDER BY id", &[])
        .await
        .unwrap();
    let changes = backend.query("SELECT total_changes()", &[]).await.unwrap();
    serde_json::to_string(&(schema, version, identity, payload, changes)).unwrap()
}

#[tokio::test]
async fn empty_initializes_and_current_reopens_without_writes() {
    let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
    backend.migrate_schema().await.unwrap();
    let current = backend
        .query("SELECT version FROM schema_version", &[])
        .await
        .unwrap();
    assert_eq!(current[0].get::<i64>(0).unwrap(), 13);
    let identity = backend
        .query("SELECT identity FROM hub_schema_identity", &[])
        .await
        .unwrap();
    assert_eq!(identity[0].get::<String>(0).unwrap(), SCHEMA_IDENTITY);
    let before = fingerprint(&backend).await;

    backend.migrate_schema().await.unwrap();

    assert_eq!(fingerprint(&backend).await, before);
}

#[tokio::test]
async fn feature_prefixes_refuse_without_any_write() {
    for version in 1..=7 {
        let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
        seed(
            &backend,
            &MIGRATIONS[..version],
            i64::try_from(version).unwrap(),
        )
        .await;
        let before = fingerprint(&backend).await;

        assert!(backend.migrate_schema().await.is_err());

        assert_eq!(fingerprint(&backend).await, before);
    }
}

#[tokio::test]
async fn divergent_master_two_refuses_without_any_write() {
    let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
    seed(&backend, &[MIGRATIONS[0], MIGRATIONS[7]], 2).await;
    let before = fingerprint(&backend).await;

    let error = backend.migrate_schema().await.unwrap_err();

    assert!(error
        .to_string()
        .contains("explicitly initialize a new canonical database"));
    assert_eq!(fingerprint(&backend).await, before);
}

#[tokio::test]
async fn missing_duplicate_or_foreign_identity_refuses_without_any_write() {
    for mutation in [
        "DELETE FROM hub_schema_identity",
        "UPDATE hub_schema_identity SET identity='foreign'",
        "INSERT INTO hub_schema_identity(identity) VALUES ('duplicate')",
        "DELETE FROM schema_version",
        "INSERT INTO schema_version(version) VALUES (8)",
    ] {
        let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
        backend.migrate_schema().await.unwrap();
        backend.execute(mutation, &[]).await.unwrap();
        let before = fingerprint(&backend).await;

        assert!(backend.migrate_schema().await.is_err());

        assert_eq!(
            fingerprint(&backend).await,
            before,
            "refused source changed after {mutation}"
        );
    }
}

#[tokio::test]
async fn canonical_startup_waits_beyond_the_statement_busy_timeout() {
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
    use std::time::Duration;

    let directory = tempfile::tempdir().unwrap();
    let options = SqliteConnectOptions::new()
        .filename(directory.path().join("shared.sqlite"))
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_millis(5));
    let pool = SqlitePoolOptions::new()
        .min_connections(2)
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap();

    let writer = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let release_writer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        writer.commit().await.unwrap();
    });
    let backend = SqlxBackend::Sqlite(pool.clone());

    backend.migrate_schema().await.unwrap();
    release_writer.await.unwrap();

    let versions = backend
        .query("SELECT version FROM schema_version", &[])
        .await
        .unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].get::<i64>(0).unwrap(), 13);
    pool.close().await;
}

#[tokio::test]
async fn concurrent_fresh_starters_share_actual_file_lock() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("shared.sqlite");
    let first = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let second = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();

    let (first_result, second_result) =
        tokio::join!(first.migrate_schema(), second.migrate_schema());

    first_result.unwrap();
    second_result.unwrap();
    let rows = first
        .query("SELECT version FROM schema_version", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<i64>(0).unwrap(), 13);
}

#[cfg(any(feature = "postgres", feature = "mysql"))]
mod dialects;
