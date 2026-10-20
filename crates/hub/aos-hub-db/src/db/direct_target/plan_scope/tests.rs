//! Checks concurrent plan reuse against actual SQL and fresh-request rebuilding.

use std::sync::atomic::{AtomicUsize, Ordering};

use futures_util::future::join_all;

use super::*;
use crate::value::Value;

async fn database() -> Database {
    let db = Database::open_in_memory().await.unwrap();
    db.backend
        .execute_batch(
            "CREATE TABLE plan_original (id INTEGER PRIMARY KEY, version INTEGER NOT NULL);
             INSERT INTO plan_original VALUES (1, 1);",
        )
        .await
        .unwrap();
    db
}

async fn plan(db: &Database, calls: &AtomicUsize) -> Result<Vec<CheckedStatement>> {
    publication_plan(db, "publication", || async {
        calls.fetch_add(1, Ordering::SeqCst);
        tokio::task::yield_now().await;
        let version = db
            .backend
            .query_opt("SELECT version FROM plan_original WHERE id = 1", &[])
            .await?
            .ok_or_else(|| anyhow::anyhow!("test original absent"))?
            .get::<i64>(0)?;
        Ok(vec![CheckedStatement::exact(
            "UPDATE plan_original SET version = version WHERE id = 1 AND version = ?1",
            vec![Value::Int(version)],
            1,
        )])
    })
    .await
}

#[tokio::test]
async fn concurrent_items_share_reads_but_each_transaction_rechecks_originals() {
    let db = database().await;
    let calls = AtomicUsize::new(0);

    Database::with_direct_dependency_plan_scope(async {
        let plans = join_all((0..14).map(|_| plan(&db, &calls))).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        for statements in &plans {
            db.backend
                .checked_batch(statements.as_ref().unwrap())
                .await
                .unwrap();
        }

        db.backend
            .execute("UPDATE plan_original SET version = 2 WHERE id = 1", &[])
            .await
            .unwrap();
        let retained = plan(&db, &calls).await.unwrap();
        assert!(db.backend.checked_batch(&retained).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    })
    .await;

    let rebuilt = Database::with_direct_dependency_plan_scope(plan(&db, &calls))
        .await
        .unwrap();
    db.backend.checked_batch(&rebuilt).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn different_database_handles_and_unscoped_calls_do_not_share_a_plan() {
    let first = database().await;
    let second = database().await;
    let calls = AtomicUsize::new(0);

    Database::with_direct_dependency_plan_scope(async {
        plan(&first, &calls).await.unwrap();
        plan(&first, &calls).await.unwrap();
        plan(&second, &calls).await.unwrap();
        plan(&second, &calls).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    })
    .await;

    plan(&first, &calls).await.unwrap();
    plan(&first, &calls).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 5);
}
