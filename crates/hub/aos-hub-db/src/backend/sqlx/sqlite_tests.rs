//! Regression coverage for SQLite pool lifetime and concurrent migrations.

use std::task::Poll;
use std::time::Duration;

use super::SqlxBackend;
use crate::backend::{Backend as _, Statement};

#[tokio::test]
async fn cancelled_acquisitions_preserve_the_in_memory_database() {
    let pool = match SqlxBackend::connect_sqlite(":memory:").await.unwrap() {
        SqlxBackend::Sqlite(pool) => pool,
        #[cfg(any(feature = "postgres", feature = "mysql"))]
        _ => panic!("SQLite constructor returned a different backend"),
    };
    sqlx::query("CREATE TABLE sentinel (value INTEGER NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sentinel VALUES (73)")
        .execute(&pool)
        .await
        .unwrap();

    for _ in 0..64 {
        // Pool returns run in background tasks. Reach the idle-connection
        // boundary before polling, rather than cancelling a permit wait.
        tokio::time::timeout(Duration::from_secs(5), async {
            while pool.num_idle() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the sole in-memory connection must return to the pool");

        // Cancel after the first poll: the old health-check await
        // discarded the only connection at precisely this boundary.
        {
            let mut acquisition = std::pin::pin!(pool.acquire());
            if let Poll::Ready(connection) = futures_util::poll!(acquisition.as_mut()) {
                drop(connection.unwrap());
            }
        }
        tokio::task::yield_now().await;
    }

    let value: i64 = sqlx::query_scalar("SELECT value FROM sentinel")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(value, 73);
}

#[tokio::test]
async fn migrations_wait_for_a_writer_beyond_the_statement_busy_timeout() {
    let directory = tempfile::tempdir().unwrap();
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(directory.path().join("hub.db"))
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_millis(5));
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .min_connections(2)
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO schema_version VALUES (1)")
        .execute(&pool)
        .await
        .unwrap();

    let writer = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let release_writer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        writer.commit().await.unwrap();
    });
    let backend = SqlxBackend::Sqlite(pool.clone());
    backend
        .migration_batch(
            1,
            2,
            &[
                Statement::new("CREATE TABLE migration_applied (value INTEGER)", Vec::new()),
                Statement::new("UPDATE schema_version SET version = 2", Vec::new()),
            ],
        )
        .await
        .unwrap();
    release_writer.await.unwrap();

    let version: i64 = sqlx::query_scalar("SELECT version FROM schema_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 2);
    sqlx::query("SELECT value FROM migration_applied")
        .fetch_all(&pool)
        .await
        .unwrap();
    pool.close().await;
}
