//! Genuine PostgreSQL source snapshot, mutation, allocation and lock regressions.

use super::*;
use crate::backend::{Backend, SqlxBackend};
use crate::value::Value;
use sqlx::Row as _;

#[tokio::test]
#[ignore = "requires the dedicated disposable PostgreSQL 18 test source"]
async fn held_snapshot_covers_original_rows_and_refuses_mutation_schema_and_oversize() {
    let path = std::env::var_os("AOS_PG_SNAPSHOT_TEST_URL_FILE").expect("private scratch URL file");
    let url = std::fs::read_to_string(path).unwrap();
    let backend = SqlxBackend::connect_postgres(url.trim()).await.unwrap();
    backend.migrate_schema().await.unwrap();
    let SqlxBackend::Postgres(pool) = backend else {
        panic!("PostgreSQL required")
    };
    sqlx::query("DELETE FROM users WHERE id BETWEEN 17001 AND 17005 OR id BETWEEN 17100 AND 17107")
        .execute(&pool)
        .await
        .unwrap();
    let existing_users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        existing_users, 0,
        "the fixture requires its dedicated empty source"
    );

    // Place the originals at physical offsets 9-11. A text-projected tid named
    // `ctid` makes ORDER BY sort 10 before 9; both paging queries must instead
    // use physical tid order, including after HOT mutation and ordinary VACUUM.
    sqlx::query("VACUUM FULL users")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,email,created_at) SELECT n, n::text || '@padding.snapshot.invalid',1 FROM generate_series(17100,17107) n")
        .execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO users(id,email,display_name,created_at,password_hash) VALUES \
        (17001,'one@snapshot.invalid','original λ',1,'encrypted-original-one'), \
        (17002,'two@snapshot.invalid','original two',2,NULL), \
        (17003,'three@snapshot.invalid','original three',3,NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("DELETE FROM users WHERE id BETWEEN 17100 AND 17107")
        .execute(&pool)
        .await
        .unwrap();
    let numeric_order: Vec<i64> = sqlx::query_scalar("SELECT id FROM users ORDER BY ctid")
        .fetch_all(&pool)
        .await
        .unwrap();
    let lexical_order: Vec<i64> = sqlx::query("SELECT id,ctid::text FROM users ORDER BY ctid")
        .fetch_all(&pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(numeric_order, [17001, 17002, 17003]);
    assert_ne!(
        lexical_order, numeric_order,
        "the fixture must expose the projection ordering bug"
    );

    let mut source = PostgresSnapshotReader::open(url.trim(), PostgresSnapshotLimits::default())
        .await
        .unwrap();
    assert_eq!(source.schema().version, 8);
    assert_eq!(
        source.audit().catalogue_sha256(),
        catalogue::expected_sha256()
    );
    assert!(source.audit().checked_expressions() > 1_000);
    assert_eq!(
        source
            .audit()
            .table_counts()
            .iter()
            .find(|table| table.table == "users")
            .unwrap()
            .rows,
        3
    );
    sqlx::raw_sql(
        "UPDATE users SET display_name='new value' WHERE id=17001; \
        DELETE FROM users WHERE id=17002; \
        INSERT INTO users(id,email,created_at) VALUES (17004,'four@snapshot.invalid',4)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("VACUUM users").execute(&pool).await.unwrap();

    let mut cursor = source.table("users").unwrap();
    let mut original = Vec::new();
    loop {
        let page = cursor
            .next_page(super::super::sqlite_snapshot::SqliteSnapshotLimits {
                max_rows: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        original.extend(page.rows);
        if page.finished {
            break;
        }
    }
    assert_eq!(original.len(), 3);
    assert_eq!(original[0].value(0), Some(&Value::Int(17001)));
    assert_eq!(
        original[0].value(2),
        Some(&Value::Text("original λ".into()))
    );
    assert_eq!(original[1].value(0), Some(&Value::Int(17002)));
    assert_eq!(original[2].value(0), Some(&Value::Int(17003)));
    drop(cursor);

    // A separate backend waits on the reader's actual ACCESS SHARE lock. A
    // finite DDL timeout refuses rewrite instead of invalidating its locators.
    let mut writer = pool.acquire().await.unwrap();
    let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    sqlx::query("SET lock_timeout='500ms'")
        .execute(&mut *writer)
        .await
        .unwrap();
    let rewrite =
        tokio::spawn(async move { sqlx::query("VACUUM FULL users").execute(&mut *writer).await });
    let observation_deadline = Instant::now() + Duration::from_secs(2);
    let mut blocked = false;
    while Instant::now() < observation_deadline {
        blocked = sqlx::query_scalar::<_,bool>(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')"
        ).bind(writer_pid).fetch_one(&pool).await.unwrap();
        if blocked {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        blocked,
        "actual rewrite backend must wait on the held source lock"
    );
    let rewrite = rewrite.await.unwrap().unwrap_err();
    assert_eq!(
        rewrite.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    source.close().await.unwrap();

    let mut readonly = PostgresSnapshotReader::open(url.trim(), PostgresSnapshotLimits::default())
        .await
        .unwrap();
    let error = sqlx::query(
        "INSERT INTO users(id,email,created_at) VALUES (17005,'five@snapshot.invalid',5)",
    )
    .execute(&mut *readonly.transaction)
    .await
    .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("25006")
    );
    readonly.close().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE id=17005")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);

    sqlx::query("UPDATE users SET display_name=repeat('x',1048577) WHERE id=17001")
        .execute(&pool)
        .await
        .unwrap();
    let mut oversized = PostgresSnapshotReader::open(url.trim(), PostgresSnapshotLimits::default())
        .await
        .unwrap();
    let mut oversized_cursor = oversized.table("users").unwrap();
    assert!(oversized_cursor
        .next_page(Default::default())
        .await
        .is_err());
    assert!(oversized_cursor.last_locator_for_test().is_none());
    drop(oversized_cursor);
    oversized.close().await.unwrap();
    sqlx::query("UPDATE users SET display_name='restored' WHERE id=17001")
        .execute(&pool)
        .await
        .unwrap();

    // Renaming a physical index preserves admitted semantics.
    sqlx::query("ALTER INDEX users_email_key RENAME TO fixture_renamed_email_index")
        .execute(&pool)
        .await
        .unwrap();
    PostgresSnapshotReader::open(url.trim(), PostgresSnapshotLimits::default())
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    sqlx::query("ALTER INDEX fixture_renamed_email_index RENAME TO users_email_key")
        .execute(&pool)
        .await
        .unwrap();

    let mut exclusive = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE users IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *exclusive)
        .await
        .unwrap();
    assert!(PostgresSnapshotReader::open(
        url.trim(),
        PostgresSnapshotLimits {
            lock_timeout: Duration::from_millis(100),
            ..Default::default()
        }
    )
    .await
    .is_err());
    exclusive.rollback().await.unwrap();

    sqlx::query("ALTER TABLE sessions DISABLE TRIGGER ALL")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        PostgresSnapshotReader::open(url.trim(), PostgresSnapshotLimits::default())
            .await
            .is_err()
    );
    sqlx::query("ALTER TABLE sessions ENABLE TRIGGER ALL")
        .execute(&pool)
        .await
        .unwrap();

    let original_view: String =
        sqlx::query_scalar("SELECT pg_get_viewdef('surface_placement_effective'::regclass, false)")
            .fetch_one(&pool)
            .await
            .unwrap();
    let original_view = original_view.trim().trim_end_matches(';');
    let compiled = CompiledSqliteSnapshotCatalogue::load_generation(8)
        .await
        .unwrap();
    let compiled_view = compiled
        .definitions()
        .iter()
        .find(|definition| definition.name() == "surface_placement_effective")
        .unwrap()
        .sql()
        .unwrap();
    let restore_view = crate::dialect::Dialect::Postgres
        .translate(compiled_view)
        .unwrap()
        .sql
        .replacen("CREATE VIEW", "CREATE OR REPLACE VIEW", 1);
    sqlx::raw_sql(&format!("CREATE OR REPLACE VIEW surface_placement_effective AS SELECT * FROM ({original_view}) original WHERE false"))
        .execute(&pool).await.unwrap();
    assert!(
        PostgresSnapshotReader::open(url.trim(), PostgresSnapshotLimits::default())
            .await
            .is_err()
    );
    // Reparse the actual compiled original. pg_get_viewdef is a diagnostic
    // deparser whose output can change internal cast shape when reparsed.
    sqlx::raw_sql(&restore_view).execute(&pool).await.unwrap();

    PostgresSnapshotReader::open(url.trim(), PostgresSnapshotLimits::default())
        .await
        .unwrap()
        .close()
        .await
        .unwrap();

    sqlx::query("CREATE INDEX unknown_snapshot_index ON users(display_name)")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        PostgresSnapshotReader::open(url.trim(), PostgresSnapshotLimits::default())
            .await
            .is_err()
    );
    sqlx::query("DROP INDEX unknown_snapshot_index")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id BETWEEN 17001 AND 17005")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
