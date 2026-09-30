//! Regression coverage for SQLite pool cancellation and database lifetime.

use std::task::Poll;
use std::time::Duration;

use super::SqlxBackend;

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
