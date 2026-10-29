//! Checks idle PostgreSQL connections without a ping before every hot query.
//!
//! Query and transaction errors still propagate to the caller. This policy
//! never retries a statement or an uncertain commit; it only replaces idle
//! connections that fail the pool's acquisition health check.

use std::time::Duration;

use sqlx::{postgres::PgPoolOptions, Connection as _};

const HEALTH_CHECK_IDLE: Duration = Duration::from_secs(1);

pub(super) fn options() -> PgPoolOptions {
    PgPoolOptions::new()
        .test_before_acquire(false)
        .before_acquire(|connection, metadata| {
            Box::pin(async move {
                // A ping on each checkout doubles the wire exchanges for short
                // reads. Recently used connections already completed a protocol
                // exchange; idle connections still prove liveness before reuse.
                if metadata.idle_for >= HEALTH_CHECK_IDLE {
                    connection.ping().await?;
                }
                Ok(true)
            })
        })
}

#[cfg(test)]
mod tests {
    use anyhow::{ensure, Result};
    use sqlx::postgres::PgConnectOptions;

    use super::*;

    #[tokio::test]
    #[ignore = "requires an isolated PostgreSQL server via AOS_TEST_POSTGRES_SOCKET"]
    async fn idle_broken_connection_is_replaced_before_query_dispatch() -> Result<()> {
        let socket = std::env::var("AOS_TEST_POSTGRES_SOCKET")?;
        ensure!(socket.starts_with('/'), "a local Unix socket is required");
        let connect = PgConnectOptions::new()
            .host(&socket)
            .username("postgres")
            .database("postgres");
        let pool = options()
            .max_connections(1)
            .connect_with(connect.clone())
            .await?;
        let mut admin = sqlx::PgConnection::connect_with(&connect).await?;

        let original: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&pool)
            .await?;
        let killed: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(original)
            .fetch_one(&mut admin)
            .await?;
        ensure!(killed, "the isolated fixture connection must terminate");
        tokio::time::sleep(HEALTH_CHECK_IDLE + Duration::from_millis(100)).await;

        let replacement: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&pool)
            .await?;
        ensure!(replacement != original, "the dead connection was reused");

        pool.close().await;
        admin.close().await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires an isolated PostgreSQL server via AOS_TEST_POSTGRES_SOCKET"]
    async fn recent_connection_failure_cannot_acknowledge_or_replay_a_write() -> Result<()> {
        let socket = std::env::var("AOS_TEST_POSTGRES_SOCKET")?;
        ensure!(socket.starts_with('/'), "a local Unix socket is required");
        let connect = PgConnectOptions::new()
            .host(&socket)
            .username("postgres")
            .database("postgres");
        let pool = options()
            .max_connections(1)
            .connect_with(connect.clone())
            .await?;
        let mut admin = sqlx::PgConnection::connect_with(&connect).await?;
        let mut transaction = pool.begin().await?;
        let original: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *transaction)
            .await?;
        sqlx::query("CREATE TEMP TABLE unacknowledged_write (value BIGINT)")
            .execute(&mut *transaction)
            .await?;
        let killed: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(original)
            .fetch_one(&mut admin)
            .await?;
        ensure!(killed, "the isolated fixture connection must terminate");

        ensure!(
            sqlx::query("INSERT INTO unacknowledged_write VALUES (1)")
                .execute(&mut *transaction)
                .await
                .is_err(),
            "a disconnected write must not succeed"
        );
        ensure!(transaction.commit().await.is_err(), "commit must fail");

        pool.close().await;
        admin.close().await?;
        Ok(())
    }
}
