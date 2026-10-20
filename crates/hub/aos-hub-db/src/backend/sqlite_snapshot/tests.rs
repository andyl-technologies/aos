//! Disposable SQLite qualification for the read-only snapshot input seam.

use std::path::PathBuf;

use sqlx::sqlite::SqliteJournalMode;
use sqlx::Connection;
use tempfile::TempDir;

use super::*;
use crate::backend::SqlxBackend;
use crate::db::Database;

async fn fixture(mode: SqliteJournalMode) -> (TempDir, PathBuf, SqlitePool) {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("hub.db");
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(mode);
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap();
    let database = Database::with_backend(Box::new(SqlxBackend::Sqlite(pool.clone())))
        .await
        .unwrap();
    drop(database);
    (directory, path, pool)
}

async fn add_user(pool: &SqlitePool, id: i64, email: &str) {
    sqlx::query("INSERT INTO users(id, email, created_at) VALUES (?1, ?2, 1)")
        .bind(id)
        .bind(email)
        .execute(pool)
        .await
        .unwrap();
}

async fn rejected_without_source_change(sql: &str) {
    let (directory, path, pool) = fixture(SqliteJournalMode::Delete).await;
    sqlx::raw_sql(sql).execute(&pool).await.unwrap();
    pool.close().await;
    let before = std::fs::read(&path).unwrap();
    let before_files = std::fs::read_dir(directory.path()).unwrap().count();

    assert!(SqliteSnapshotReader::open(&path).await.is_err());

    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        std::fs::read_dir(directory.path()).unwrap().count(),
        before_files
    );
}

#[tokio::test]
async fn missing_source_is_never_created() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("absent.db");

    assert!(SqliteSnapshotReader::open(&path).await.is_err());
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    assert!(SqliteSnapshotReader::open(directory.path()).await.is_err());
}

#[tokio::test]
async fn incomplete_source_is_not_initialized() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("empty.db");
    std::fs::write(&path, []).unwrap();

    assert!(SqliteSnapshotReader::open(&path).await.is_err());
    assert!(std::fs::read(&path).unwrap().is_empty());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn future_old_duplicate_and_missing_version_are_rejected() {
    for sql in [
        "UPDATE schema_version SET version = 9999",
        "UPDATE schema_version SET version = 1",
        "INSERT INTO schema_version VALUES (3)",
        "DELETE FROM schema_version",
        "UPDATE schema_version SET version = 3.5",
    ] {
        rejected_without_source_change(sql).await;
    }
}

#[tokio::test]
async fn unknown_and_missing_lineage_are_rejected() {
    for sql in [
        "UPDATE hub_schema_identity SET identity = 'foreign-lineage'",
        "DELETE FROM hub_schema_identity",
        "INSERT INTO hub_schema_identity VALUES ('foreign-lineage')",
    ] {
        rejected_without_source_change(sql).await;
    }
}

#[tokio::test]
async fn oversized_and_binary_lineage_markers_are_rejected_without_changes() {
    for sql in [
        "UPDATE schema_version SET version = zeroblob(4 * 1024 * 1024)",
        "UPDATE schema_version SET version = CAST(zeroblob(4 * 1024 * 1024) AS TEXT)",
        "UPDATE hub_schema_identity SET identity = zeroblob(4 * 1024 * 1024)",
        "UPDATE hub_schema_identity SET identity = CAST(zeroblob(4 * 1024 * 1024) AS TEXT)",
        "UPDATE hub_schema_identity SET identity = CAST(identity AS BLOB)",
    ] {
        rejected_without_source_change(sql).await;
    }
}

async fn assert_released_read_lock(connection: &mut SqliteConnection) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
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
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("dropped snapshot must release its source read lock");
}

#[tokio::test]
async fn dropping_reader_releases_the_pinned_transaction() {
    let (_directory, path, writer) = fixture(SqliteJournalMode::Delete).await;
    let mut connection = writer.acquire().await.unwrap();
    sqlx::query("PRAGMA busy_timeout = 0")
        .execute(&mut *connection)
        .await
        .unwrap();
    let reader = SqliteSnapshotReader::open(&path).await.unwrap();
    assert!(sqlx::query("BEGIN EXCLUSIVE")
        .execute(&mut *connection)
        .await
        .is_err());

    drop(reader);
    assert_released_read_lock(&mut connection).await;
    drop(connection);
    writer.close().await;
}

#[tokio::test]
async fn cancelling_reader_owner_releases_the_pinned_transaction() {
    let (_directory, path, writer) = fixture(SqliteJournalMode::Delete).await;
    let (ready, opened) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let reader = SqliteSnapshotReader::open(&path).await.unwrap();
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
        drop(reader);
    });
    opened.await.unwrap();
    let mut connection = writer.acquire().await.unwrap();
    sqlx::query("PRAGMA busy_timeout = 0")
        .execute(&mut *connection)
        .await
        .unwrap();
    assert!(sqlx::query("BEGIN EXCLUSIVE")
        .execute(&mut *connection)
        .await
        .is_err());

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_released_read_lock(&mut connection).await;
    drop(connection);
    writer.close().await;
}

#[tokio::test]
async fn current_version_does_not_hide_schema_drift() {
    for sql in [
        "CREATE TABLE unexpected(payload BLOB)",
        "ALTER TABLE users ADD COLUMN unexpected TEXT",
        "DROP INDEX bindings_stable_idx",
        "CREATE TRIGGER unexpected AFTER INSERT ON users BEGIN DELETE FROM users; END",
    ] {
        rejected_without_source_change(sql).await;
    }
}

#[tokio::test]
async fn accepted_read_keeps_file_and_delete_journal_mode_unchanged() {
    let (directory, path, pool) = fixture(SqliteJournalMode::Delete).await;
    add_user(&pool, 1, "source@example.test").await;
    pool.close().await;
    let before = std::fs::read(&path).unwrap();

    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();
    assert_eq!(reader.schema().identity, SCHEMA_IDENTITY);
    assert_eq!(reader.schema().version, MIGRATIONS.len());
    assert_eq!(reader.schema().migration_digests.len(), MIGRATIONS.len());
    assert!(reader
        .schema()
        .tables
        .iter()
        .any(|table| table.name == "storage_authority_control_requests"));
    let page = reader
        .table("users")
        .unwrap()
        .next_page(SqliteSnapshotLimits::default())
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 1);
    reader.close().await.unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    let mut connection = SqliteConnection::connect_with(
        &SqliteConnectOptions::new().filename(&path).read_only(true),
    )
    .await
    .unwrap();
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(mode, "delete");
    connection.close().await.unwrap();
}

#[tokio::test]
async fn one_read_snapshot_survives_changes_from_another_connection() {
    let (_directory, path, writer) = fixture(SqliteJournalMode::Wal).await;
    add_user(&writer, 1, "one@example.test").await;
    add_user(&writer, 2, "two@example.test").await;
    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();
    let mut users = reader.table("users").unwrap();
    let limits = SqliteSnapshotLimits {
        max_rows: 1,
        ..Default::default()
    };
    let first = users.next_page(limits).await.unwrap();
    assert_eq!(first.rows[0].get::<String>(1).unwrap(), "one@example.test");

    sqlx::query("UPDATE users SET email = 'changed@example.test' WHERE id = 2")
        .execute(&writer)
        .await
        .unwrap();
    add_user(&writer, 3, "new@example.test").await;
    let live_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&writer)
        .await
        .unwrap();
    assert_eq!(live_count, 3);

    let second = users.next_page(limits).await.unwrap();
    assert_eq!(second.rows[0].get::<String>(1).unwrap(), "two@example.test");
    let end = users.next_page(limits).await.unwrap();
    assert!(end.finished);
    assert!(end.rows.is_empty());
    drop(users);
    reader.close().await.unwrap();
    writer.close().await;
}

#[tokio::test]
async fn wal_source_database_and_log_are_not_written_by_the_reader() {
    let (_directory, path, writer) = fixture(SqliteJournalMode::Wal).await;
    add_user(&writer, 1, "wal@example.test").await;
    let wal_path = path.with_file_name("hub.db-wal");
    let database_before = std::fs::read(&path).unwrap();
    let wal_before = std::fs::read(&wal_path).unwrap();

    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();
    let page = reader
        .table("users")
        .unwrap()
        .next_page(SqliteSnapshotLimits::default())
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 1);
    reader.close().await.unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), database_before);
    assert_eq!(std::fs::read(&wal_path).unwrap(), wal_before);
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&writer)
        .await
        .unwrap();
    assert_eq!(mode, "wal");
    writer.close().await;
}

#[tokio::test]
async fn native_values_keep_exact_integer_bytes_real_text_and_null() {
    let (_directory, path, writer) = fixture(SqliteJournalMode::Delete).await;
    let bytes = vec![0, 0xff, 0x80, 7];
    sqlx::query("INSERT INTO users(id, email, display_name, created_at) VALUES (?1, ?2, ?3, ?4)")
        .bind(i64::MAX)
        .bind("exact@example.test")
        .bind(&bytes)
        .bind(1.25_f64)
        .execute(&writer)
        .await
        .unwrap();
    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();

    let page = reader
        .table("users")
        .unwrap()
        .next_page(SqliteSnapshotLimits::default())
        .await
        .unwrap();
    let row = &page.rows[0];
    assert_eq!(row.value(0), Some(&Value::Int(i64::MAX)));
    assert_eq!(
        row.value(1),
        Some(&Value::Text("exact@example.test".to_string()))
    );
    assert_eq!(row.value(2), Some(&Value::Bytes(bytes)));
    assert_eq!(row.value(3), Some(&Value::Real(1.25)));
    assert_eq!(row.value(4), Some(&Value::Null));
    assert_eq!(row.value(5), Some(&Value::Null));
    assert!(page.finished);
    reader.close().await.unwrap();
    writer.close().await;
}

#[tokio::test]
async fn cell_and_page_bounds_fail_without_advancing_the_cursor() {
    let (_directory, path, writer) = fixture(SqliteJournalMode::Delete).await;
    add_user(&writer, 1, "bounds@example.test").await;
    sqlx::query("UPDATE users SET display_name = ?1 WHERE id = 1")
        .bind(vec![0xaa_u8; 64])
        .execute(&writer)
        .await
        .unwrap();
    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();
    let mut users = reader.table("users").unwrap();
    let cell_limit = SqliteSnapshotLimits {
        max_cell_bytes: 32,
        ..Default::default()
    };
    assert!(users.next_page(cell_limit).await.is_err());
    let page_limit = SqliteSnapshotLimits {
        max_page_bytes: 32,
        ..Default::default()
    };
    assert!(users.next_page(page_limit).await.is_err());

    let page = users
        .next_page(SqliteSnapshotLimits::default())
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].get::<i64>(0).unwrap(), 1);
    assert!(page.payload_bytes <= SqliteSnapshotLimits::default().max_page_bytes);
    drop(users);
    reader.close().await.unwrap();
    writer.close().await;
}

#[tokio::test]
async fn page_budget_splits_rows_and_negative_rowids_are_preserved() {
    let (_directory, path, writer) = fixture(SqliteJournalMode::Delete).await;
    for id in [-3, -1, 2] {
        add_user(&writer, id, &format!("row{id}@example.test")).await;
    }
    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();
    assert!(reader.table("users; DELETE FROM users").is_err());
    let mut users = reader.table("users").unwrap();
    let invalid = SqliteSnapshotLimits {
        max_rows: MAX_PAGE_ROWS + 1,
        ..Default::default()
    };
    assert!(users.next_page(invalid).await.is_err());
    let limits = SqliteSnapshotLimits {
        max_rows: 3,
        max_page_bytes: 48,
        ..Default::default()
    };
    let mut ids = Vec::new();
    loop {
        let page = users.next_page(limits).await.unwrap();
        assert!(page.rows.len() <= 1);
        assert!(page.payload_bytes <= limits.max_page_bytes);
        ids.extend(page.rows.iter().map(|row| row.get::<i64>(0).unwrap()));
        if page.finished {
            break;
        }
    }
    assert_eq!(ids, [-3, -1, 2]);
    drop(users);
    reader.close().await.unwrap();
    writer.close().await;
}

#[tokio::test]
async fn nonfinite_values_fail_without_skipping_the_row() {
    let (_directory, path, writer) = fixture(SqliteJournalMode::Delete).await;
    sqlx::query(
        "INSERT INTO users(id, email, created_at) VALUES (1, 'nonfinite@example.test', ?1)",
    )
    .bind(f64::INFINITY)
    .execute(&writer)
    .await
    .unwrap();
    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();
    let mut users = reader.table("users").unwrap();

    assert!(users
        .next_page(SqliteSnapshotLimits::default())
        .await
        .is_err());
    assert!(users
        .next_page(SqliteSnapshotLimits::default())
        .await
        .is_err());
    drop(users);
    reader.close().await.unwrap();
    writer.close().await;
}

#[tokio::test]
async fn text_cell_limit_counts_bytes_and_invalid_utf8_is_rejected() {
    let (_directory, path, writer) = fixture(SqliteJournalMode::Delete).await;
    add_user(&writer, 1, "utf8@example.test").await;
    sqlx::query("UPDATE users SET display_name = ?1 WHERE id = 1")
        .bind("é".repeat(20))
        .execute(&writer)
        .await
        .unwrap();
    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();
    let mut users = reader.table("users").unwrap();
    let limits = SqliteSnapshotLimits {
        max_cell_bytes: 32,
        ..Default::default()
    };
    assert!(users.next_page(limits).await.is_err());
    let page = users
        .next_page(SqliteSnapshotLimits::default())
        .await
        .unwrap();
    assert_eq!(page.rows[0].get::<String>(2).unwrap(), "é".repeat(20));
    drop(users);
    reader.close().await.unwrap();

    sqlx::query("UPDATE users SET display_name = CAST(x'FF' AS TEXT) WHERE id = 1")
        .execute(&writer)
        .await
        .unwrap();
    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();
    assert!(reader
        .table("users")
        .unwrap()
        .next_page(SqliteSnapshotLimits::default())
        .await
        .is_err());
    reader.close().await.unwrap();
    writer.close().await;
}
