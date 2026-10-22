//! Checks placeholder custody, bounded groups, and real PostgreSQL lock ordering.

use super::*;
use crate::backend::{Backend as _, SqlxBackend};

#[test]
fn rebasing_preserves_quoted_tokens_and_refuses_unsupported_forms() {
    assert_eq!(
        rebase(
            "SELECT '$1', 'it''s $2', \"$3\" WHERE id = $1 OR id = $12",
            20
        ),
        Some("SELECT '$1', 'it''s $2', \"$3\" WHERE id = $21 OR id = $32".into())
    );
    for sql in [
        "SELECT $$body$$",
        "SELECT $0",
        "SELECT 1 -- $1",
        "SELECT 1 /* $1 */",
        "SELECT E'\\n'",
        "SELECT 'unfinished",
    ] {
        assert!(rebase(sql, 20).is_none());
    }
}

#[test]
fn groups_stop_at_mutations_and_keep_parameter_and_statement_bounds() {
    let lock = CheckedStatement::point_lock("counters", "value", "id = ?1", vec![Value::Int(1)]);
    let mut statements = vec![lock.clone(); MAX_LOCKS + 1];
    let group = compile(&statements).unwrap().unwrap();
    assert_eq!(group.expected.len(), MAX_LOCKS);
    assert_eq!(group.parameters, vec![Value::Int(1); MAX_LOCKS]);

    statements[2] = CheckedStatement::exact("UPDATE counters SET value = 1", Vec::new(), 1);
    assert_eq!(compile(&statements).unwrap().unwrap().expected.len(), 2);

    let set_lock =
        CheckedStatement::row_lock("counters", "value", "value = ?1", vec![Value::Int(1)], 1);
    assert!(compile(&[lock.clone(), set_lock, lock.clone()])
        .unwrap()
        .is_none());

    let mut oversized = lock.clone();
    oversized.statement.params = vec![Value::Int(1); MAX_PARAMETERS];
    assert!(compile(&[oversized, lock]).unwrap().is_none());
}

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL server via AOS_TEST_POSTGRES_SOCKET"]
async fn ordered_groups_recheck_waited_rows_and_roll_back_before_later_locks() -> Result<()> {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    let socket = std::env::var("AOS_TEST_POSTGRES_SOCKET")?;
    anyhow::ensure!(socket.starts_with('/'), "a local Unix socket is required");
    let options = PgConnectOptions::new()
        .host(&socket)
        .username("postgres")
        .database("postgres");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options.clone())
        .await?;
    let runner = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    let schema = format!("ordered_locks_{}", uuid::Uuid::new_v4().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema};
         CREATE TABLE {schema}.counters (id BIGINT PRIMARY KEY, value BIGINT NOT NULL);
         INSERT INTO {schema}.counters VALUES (1, 0), (2, 0), (3, 0);"
    ))
    .execute(&pool)
    .await?;

    let result = check_ordered_groups(&pool, &runner, &schema).await;
    runner.close().await;
    let cleanup = sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await;
    pool.close().await;
    result?;
    cleanup?;
    Ok(())
}

async fn measure_point_lock_groups(
    pool: &sqlx::PgPool,
    runner: &sqlx::PgPool,
    table: &str,
) -> Result<()> {
    sqlx::query(&format!(
        "INSERT INTO {table} SELECT id, 0 FROM generate_series(4, 32) id"
    ))
    .execute(pool)
    .await?;
    let versions_sql = format!("SELECT xmin::text FROM {table} ORDER BY id");
    let backend = SqlxBackend::Postgres(runner.clone());

    for mode in ["legacy_updates", "individual_locks", "ordered_point_groups"] {
        let plan = (1..=32)
            .map(|id| {
                let values = vec![Value::Int(id), Value::Int(0)];
                match mode {
                    "legacy_updates" => CheckedStatement::exact(
                        format!("UPDATE {table} SET value = value WHERE id = ?1 AND value = ?2"),
                        values,
                        1,
                    ),
                    "individual_locks" => CheckedStatement::row_lock(
                        table,
                        "value",
                        "id = ?1 AND value = ?2",
                        values,
                        1,
                    ),
                    _ => CheckedStatement::point_lock(
                        table,
                        "value",
                        "id = ?1 AND value = ?2",
                        values,
                    ),
                }
            })
            .collect::<Vec<_>>();
        let before: Vec<String> = sqlx::query_scalar(&versions_sql).fetch_all(pool).await?;
        let started = std::time::Instant::now();
        for _ in 0..64 {
            backend.checked_batch(&plan).await?;
        }
        let micros = started.elapsed().as_micros();
        let after: Vec<String> = sqlx::query_scalar(&versions_sql).fetch_all(pool).await?;
        let changed = before.iter().zip(&after).filter(|(a, b)| a != b).count();
        assert_eq!(changed, if mode == "legacy_updates" { 32 } else { 0 });
        println!("point_lock_benchmark mode={mode} transactions=64 locks_per_transaction=32 elapsed_micros={micros} changed_tuple_versions={changed}");
    }
    Ok(())
}

async fn wait_for_blocker(pool: &sqlx::PgPool, waiter: i32) -> Result<Vec<i32>> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let blockers: Vec<i32> = sqlx::query_scalar("SELECT pg_blocking_pids($1)")
            .bind(waiter)
            .fetch_one(pool)
            .await?;
        if !blockers.is_empty() {
            return Ok(blockers);
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "lock wait was not observed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn check_ordered_groups(
    pool: &sqlx::PgPool,
    runner: &sqlx::PgPool,
    schema: &str,
) -> Result<()> {
    let table = format!("{schema}.counters");
    let locks = (1..=2)
        .map(|id| {
            CheckedStatement::point_lock(
                &table,
                "value",
                "id = ?1 AND value = ?2",
                vec![Value::Int(id), Value::Int(0)],
            )
        })
        .collect::<Vec<_>>();
    let waiter: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(runner)
        .await?;

    for change_first in [true, false] {
        let mut first = pool.begin().await?;
        let first_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *first)
            .await?;
        sqlx::query(&format!("SELECT 1 FROM {table} WHERE id = 1 FOR UPDATE"))
            .execute(&mut *first)
            .await?;
        let mut second = pool.begin().await?;
        let second_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *second)
            .await?;
        sqlx::query(&format!("SELECT 1 FROM {table} WHERE id = 2 FOR UPDATE"))
            .execute(&mut *second)
            .await?;

        let mut plan = vec![CheckedStatement::exact(
            format!("UPDATE {table} SET value = 1 WHERE id = 3"),
            Vec::new(),
            1,
        )];
        plan.extend(locks.clone());
        let backend = SqlxBackend::Postgres(runner.clone());
        let work = tokio::spawn(async move { backend.checked_batch(&plan).await });
        assert_eq!(wait_for_blocker(pool, waiter).await?, vec![first_pid]);

        if change_first {
            sqlx::query(&format!("UPDATE {table} SET value = 1 WHERE id = 1"))
                .execute(&mut *first)
                .await?;
        }
        first.commit().await?;

        if change_first {
            // A stale first predicate must reject without entering the second
            // lock, even while that row remains independently held.
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(5), work)
                    .await??
                    .is_err()
            );
        } else {
            assert_eq!(wait_for_blocker(pool, waiter).await?, vec![second_pid]);
            // The first lock must remain owned throughout the second wait.
            let blocked = sqlx::query(&format!(
                "SELECT 1 FROM {table} WHERE id = 1 FOR UPDATE NOWAIT"
            ))
            .execute(pool)
            .await
            .expect_err("the first row must remain locked");
            assert_eq!(
                blocked
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .as_deref(),
                Some("55P03")
            );
            second.commit().await?;
            work.await??;
            second = pool.begin().await?;
        }
        second.rollback().await?;

        let value: i64 = sqlx::query_scalar(&format!("SELECT value FROM {table} WHERE id = 3"))
            .fetch_one(pool)
            .await?;
        assert_eq!(value, if change_first { 0 } else { 1 });
        sqlx::query(&format!("UPDATE {table} SET value = 0"))
            .execute(pool)
            .await?;
    }
    measure_point_lock_groups(pool, runner, &table).await
}
