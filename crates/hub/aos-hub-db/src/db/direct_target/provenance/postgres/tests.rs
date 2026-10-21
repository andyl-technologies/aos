//! Real PostgreSQL checks for every typed tuple pin and nullable incarnation.

use anyhow::Result;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::*;
use crate::backend::{Backend, CheckedStatement, PostgresLockSql, SqlxBackend};
use crate::value::Value;

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL server via AOS_TEST_POSTGRES_SOCKET"]
async fn native_tuple_fences_check_each_copy_and_source_pin() -> Result<()> {
    let socket = std::env::var("AOS_TEST_POSTGRES_SOCKET")?;
    anyhow::ensure!(socket.starts_with('/'), "a local Unix socket is required");
    // Temporary tables shadow only this connection's retained-state names.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::new()
                .host(&socket)
                .username("postgres")
                .database("postgres"),
        )
        .await?;
    let backend = SqlxBackend::Postgres(pool.clone());
    let result = check_tuple_fences(&backend).await;
    pool.close().await;
    result
}

async fn check_tuple_fences(backend: &SqlxBackend) -> Result<()> {
    backend
        .execute_batch(
            "CREATE TEMP TABLE object_placements (
               surface_object_id BIGINT, placement_id BIGINT,
               direct_upload_session_id TEXT, observed_hash TEXT,
               observed_size BIGINT, etag TEXT, provider_version TEXT,
               observed_placement_resource_version BIGINT,
               observed_write_spec_version BIGINT, observed_binding_resource_version BIGINT,
               state TEXT, PRIMARY KEY (surface_object_id, placement_id));
             INSERT INTO object_placements VALUES
               (1, 2, 'session-a', 'hash-a', 3, 'etag-a', NULL, 4, 5, 6, 'present'),
               (7, 8, 'session-b', 'hash-b', 9, 'etag-b', 'version-b', 10, 11, 12, 'present');
             CREATE TEMP TABLE direct_upload_sessions (
               session_id TEXT PRIMARY KEY, logical_fingerprint TEXT,
               resource_version BIGINT, state TEXT);
             INSERT INTO direct_upload_sessions VALUES
               ('session-a', 'fingerprint-a', 13, 'committed'),
               ('session-b', 'fingerprint-b', 14, 'committed');
             CREATE TEMP TABLE direct_upload_completion_receipts (
               session_id TEXT PRIMARY KEY, evidence_digest TEXT);
             INSERT INTO direct_upload_completion_receipts VALUES
               ('session-a', 'receipt-a'), ('session-b', 'receipt-b');",
        )
        .await?;
    let copies = vals![
        1_i64,
        2_i64,
        "session-a",
        "hash-a",
        3_i64,
        "etag-a",
        Option::<String>::None,
        4_i64,
        5_i64,
        6_i64,
        7_i64,
        8_i64,
        "session-b",
        "hash-b",
        9_i64,
        "etag-b",
        "version-b",
        10_i64,
        11_i64,
        12_i64
    ];
    check_each_pin(backend, copy_locks(2), &copies).await?;
    let sources = vals![
        "session-a",
        "fingerprint-a",
        13_i64,
        "receipt-a",
        "session-b",
        "fingerprint-b",
        14_i64,
        "receipt-b"
    ];
    check_each_pin(backend, source_locks(2), &sources).await?;

    // Duplicate tuples must not count one physical row twice.
    let mut duplicates = copies[..10].to_vec();
    duplicates.extend_from_slice(&copies[..10]);
    assert!(backend
        .checked_batch(&[fence(copy_locks(2), duplicates)])
        .await
        .is_err());

    backend
        .execute(
            "UPDATE object_placements SET state = 'absent' WHERE surface_object_id = 1",
            &[],
        )
        .await?;
    assert!(backend
        .checked_batch(&[fence(copy_locks(2), copies)])
        .await
        .is_err());
    backend
        .execute(
            "UPDATE direct_upload_sessions SET state = 'admitted' WHERE session_id = 'session-a'",
            &[],
        )
        .await?;
    assert!(backend
        .checked_batch(&[fence(source_locks(2), sources)])
        .await
        .is_err());
    Ok(())
}

fn fence(sql: String, values: Vec<Value>) -> CheckedStatement {
    let mut checked = CheckedStatement::exact("SELECT 1", values, 2);
    checked.postgres_lock_sql = Some(PostgresLockSql::new(sql));
    checked
}

async fn check_each_pin(backend: &SqlxBackend, sql: String, values: &[Value]) -> Result<()> {
    backend
        .checked_batch(&[fence(sql.clone(), values.to_vec())])
        .await?;
    for index in 0..values.len() {
        let mut changed = values.to_vec();
        changed[index] = match &values[index] {
            Value::Int(value) => Value::Int(value + 100),
            Value::Text(value) => Value::Text(format!("{value}-different")),
            Value::Null => Value::Text("unexpected-version".into()),
            _ => panic!("tuple fixture uses only text, integers and null"),
        };
        assert!(
            backend
                .checked_batch(&[fence(sql.clone(), changed)])
                .await
                .is_err(),
            "changed tuple pin {index} must refuse"
        );
    }
    Ok(())
}
