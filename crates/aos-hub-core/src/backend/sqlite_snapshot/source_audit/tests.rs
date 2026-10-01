//! Source checks against production-initialized disposable SQLite databases.

use std::path::PathBuf;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tempfile::TempDir;

use super::*;
use crate::backend::sqlite_snapshot::SqliteSnapshotLimits;
use crate::backend::SqlxBackend;
use crate::db::Database;

async fn fixture() -> (TempDir, PathBuf, sqlx::SqlitePool) {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("hub.db");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal),
        )
        .await
        .unwrap();
    let db = Database::with_backend(Box::new(SqlxBackend::Sqlite(pool.clone())))
        .await
        .unwrap();
    drop(db);
    (directory, path, pool)
}

fn limits() -> SqliteSnapshotAuditLimits {
    SqliteSnapshotAuditLimits {
        max_duration: Duration::from_secs(30),
        max_progress_callbacks: 100_000,
    }
}

#[tokio::test]
async fn audit_and_enumeration_share_the_original_snapshot() {
    let (_directory, path, writer) = fixture().await;
    sqlx::query("INSERT INTO users(id, email, created_at) VALUES (1, 'original@example.test', 1)")
        .execute(&writer)
        .await
        .unwrap();
    let reader = SqliteSnapshotReader::open(&path).await.unwrap();
    sqlx::query("INSERT INTO users(id, email, created_at) VALUES (2, 'later@example.test', 1)")
        .execute(&writer)
        .await
        .unwrap();

    let (mut reader, audit) = reader.audit_source(limits()).await.unwrap();

    assert_eq!(audit.table_counts().len(), reader.schema().tables.len());
    assert!(audit.progress_callbacks() > 0);
    assert_eq!(audit.checked_expressions(), 683);
    for (count, table) in audit.table_counts().iter().zip(&reader.schema().tables) {
        assert_eq!(count.table, table.name);
    }
    assert_eq!(
        audit
            .table_counts()
            .iter()
            .find(|t| t.table == "users")
            .unwrap()
            .rows,
        1
    );
    let page = reader
        .table("users")
        .unwrap()
        .next_page(SqliteSnapshotLimits::default())
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(
        page.rows[0].get::<String>(1).unwrap(),
        "original@example.test"
    );
    reader.close().await.unwrap();

    let reader = SqliteSnapshotReader::open(&path).await.unwrap();
    let (reader, fresh) = reader.audit_source(limits()).await.unwrap();
    assert_eq!(
        fresh
            .table_counts()
            .iter()
            .find(|t| t.table == "users")
            .unwrap()
            .rows,
        2
    );
    reader.close().await.unwrap();
    writer.close().await;
}

#[tokio::test]
async fn successful_audit_does_not_write_database_or_wal() {
    let (_directory, path, writer) = fixture().await;
    let wal = path.with_file_name("hub.db-wal");
    let db_before = std::fs::read(&path).unwrap();
    let wal_before = std::fs::read(&wal).unwrap();

    let (reader, _) = SqliteSnapshotReader::open(&path)
        .await
        .unwrap()
        .audit_source(limits())
        .await
        .unwrap();
    reader.close().await.unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), db_before);
    assert_eq!(std::fs::read(&wal).unwrap(), wal_before);
    writer.close().await;
}

#[tokio::test]
async fn broken_declared_fk_rejects_without_exposing_source_values() {
    let (_directory, path, writer) = fixture().await;
    sqlx::raw_sql(
        "PRAGMA foreign_keys = OFF;
        INSERT INTO user_identities(user_id, issuer, subject)
        VALUES (999, 'private-issuer', 'private-subject');",
    )
    .execute(&writer)
    .await
    .unwrap();
    let reader = SqliteSnapshotReader::open(&path).await.unwrap();

    let error = reader.audit_source(limits()).await.err().unwrap();

    assert_eq!(
        format!("{error:#}"),
        "snapshot source foreign-key check failed"
    );
    assert!(!format!("{error:?}").contains("private-"));
    writer.close().await;
}

#[tokio::test]
async fn violated_check_constraint_is_an_integrity_failure() {
    let (_directory, path, writer) = fixture().await;
    sqlx::raw_sql(
        "PRAGMA ignore_check_constraints = ON;
        INSERT INTO route_oci_capabilities(route_id, serves_web, created_at)
        VALUES ('private-route', 8, 1);",
    )
    .execute(&writer)
    .await
    .unwrap();
    let reader = SqliteSnapshotReader::open(&path).await.unwrap();

    let error = reader.audit_source(limits()).await.err().unwrap();

    assert_eq!(
        format!("{error:#}"),
        "snapshot source integrity check failed"
    );
    assert!(!format!("{error:?}").contains("private-route"));
    writer.close().await;
}

#[tokio::test]
async fn real_sqlite_progress_exhaustion_returns_no_partial_report() {
    let (_directory, path, writer) = fixture().await;
    let reader = SqliteSnapshotReader::open(&path).await.unwrap();
    let limited = SqliteSnapshotAuditLimits {
        max_progress_callbacks: 1,
        ..limits()
    };

    let error = reader.audit_source(limited).await.err().unwrap();

    let message = format!("{error:#}");
    assert!(
        message == "snapshot source integrity check failed"
            || message == "snapshot source audit budget exhausted",
        "{message}"
    );
    writer.close().await;
}

#[tokio::test]
async fn expired_and_invalid_budgets_reject_before_returning_a_report() {
    let (_directory, path, writer) = fixture().await;
    for bad in [
        SqliteSnapshotAuditLimits {
            max_duration: Duration::ZERO,
            ..limits()
        },
        SqliteSnapshotAuditLimits {
            max_duration: Duration::from_secs(301),
            ..limits()
        },
        SqliteSnapshotAuditLimits {
            max_progress_callbacks: 0,
            ..limits()
        },
        SqliteSnapshotAuditLimits {
            max_progress_callbacks: MAX_PROGRESS_CALLBACKS + 1,
            ..limits()
        },
        SqliteSnapshotAuditLimits {
            max_duration: Duration::from_nanos(1),
            ..limits()
        },
    ] {
        let reader = SqliteSnapshotReader::open(&path).await.unwrap();
        assert!(reader.audit_source(bad).await.is_err());
    }
    writer.close().await;
}

#[tokio::test]
async fn dropping_audit_budget_interrupts_actual_pending_sql() {
    let (_directory, path, writer) = fixture().await;
    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();
    let budget = AuditBudget::new(limits()).unwrap();
    let active = Arc::clone(&budget.active);
    let (started, observed) = tokio::sync::oneshot::channel();
    let mut started = Some(started);
    reader
        .transaction
        .lock_handle()
        .await
        .unwrap()
        .set_progress_handler(100, move || {
            if let Some(started) = started.take() {
                let _ = started.send(());
            }
            active.load(Ordering::Acquire)
        });
    let query = tokio::spawn(async move {
        let result = sqlx::query_scalar::<_, i64>(
            "WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i + 1 FROM n WHERE i < 1000000000) SELECT SUM(i) FROM n",
        ).fetch_one(&mut *reader.transaction).await;
        assert!(result.is_err());
        drop(reader);
    });
    observed.await.unwrap();

    drop(budget);

    tokio::time::timeout(Duration::from_secs(2), query)
        .await
        .unwrap()
        .unwrap();
    writer.close().await;
}

#[tokio::test]
async fn cancelling_actual_audit_releases_the_source_read_lock() {
    let (_directory, path, writer) = fixture().await;
    sqlx::raw_sql("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;
        WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < 10000)
        INSERT INTO users(id, email, created_at) SELECT i, 'user-' || i || '@example.test', 1 FROM n;")
        .execute(&writer)
        .await
        .unwrap();
    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();
    let (started, observed) = tokio::sync::oneshot::channel();
    reader.audit_progress_started = Some(started);
    reader.audit_pause_at_progress = true;
    let task = tokio::spawn(async move { reader.audit_source(limits()).await });
    observed.await.unwrap();

    task.abort();

    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    let mut connection = writer.acquire().await.unwrap();
    sqlx::query("PRAGMA busy_timeout = 0")
        .execute(&mut *connection)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if sqlx::query("BEGIN EXCLUSIVE")
                .execute(&mut *connection)
                .await
                .is_ok()
            {
                sqlx::query("ROLLBACK")
                    .execute(&mut *connection)
                    .await
                    .unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cancelled audit must release its source lock");
    drop(connection);
    writer.close().await;
}

#[tokio::test]
async fn successful_audit_removes_the_handler_before_subsequent_enumeration() {
    let (_directory, path, writer) = fixture().await;
    sqlx::query("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i + 1 FROM n WHERE i < 1000)
        INSERT INTO users(id, email, created_at) SELECT i, 'user-' || i || '@example.test', 1 FROM n")
        .execute(&writer)
        .await
        .unwrap();
    let reader = SqliteSnapshotReader::open(&path).await.unwrap();
    let (mut reader, audit) = reader.audit_source(limits()).await.unwrap();
    assert!(audit.progress_callbacks() > 0);

    // The dropped audit budget rejects all later callbacks. A full enumeration
    // exceeds the callback interval and therefore proves handler removal.
    let mut cursor = reader.table("users").unwrap();
    let mut count = 0;
    loop {
        let page = cursor
            .next_page(SqliteSnapshotLimits::default())
            .await
            .unwrap();
        count += page.rows.len();
        if page.finished {
            break;
        }
    }

    assert_eq!(count, 1000);
    drop(cursor);
    reader.close().await.unwrap();
    writer.close().await;
}
