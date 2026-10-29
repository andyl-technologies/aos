//! Checks bounded plan reuse against actual SQL and current transaction fences.

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
    plan_for(db, "publication", calls).await
}

async fn plan_for(
    db: &Database,
    publication: &str,
    calls: &AtomicUsize,
) -> Result<Vec<CheckedStatement>> {
    publication_plan(db, publication, || async {
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

    let retained = Database::with_direct_dependency_plan_scope(plan(&db, &calls))
        .await
        .unwrap();
    assert!(db.backend.checked_batch(&retained).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    db.invalidate_direct_dependency_plan();
    let rebuilt = Database::with_direct_dependency_plan_scope(plan(&db, &calls))
        .await
        .unwrap();
    db.backend.checked_batch(&rebuilt).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn concurrent_requests_share_one_build_and_expired_plans_rebuild() {
    let db = database().await;
    let calls = AtomicUsize::new(0);

    let plans =
        join_all((0..8).map(|_| Database::with_direct_dependency_plan_scope(plan(&db, &calls))))
            .await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    for statements in plans {
        db.backend
            .checked_batch(&statements.unwrap())
            .await
            .unwrap();
    }

    db.direct_dependency_plans
        .selected
        .lock()
        .unwrap()
        .first_mut()
        .unwrap()
        .created = tokio::time::Instant::now() - std::time::Duration::from_secs(30);
    Database::with_direct_dependency_plan_scope(plan(&db, &calls))
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn interleaved_publications_share_independent_plans_and_evict_the_least_recent() {
    let db = database().await;
    let calls = AtomicUsize::new(0);
    for _ in 0..8 {
        let plans = join_all(["first", "second"].map(|publication| {
            Database::with_direct_dependency_plan_scope(plan_for(&db, publication, &calls))
        }))
        .await;
        for statements in plans {
            db.backend
                .checked_batch(&statements.unwrap())
                .await
                .unwrap();
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    Database::with_direct_dependency_plan_scope(plan_for(&db, "first", &calls))
        .await
        .unwrap();
    Database::with_direct_dependency_plan_scope(plan_for(&db, "third", &calls))
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    Database::with_direct_dependency_plan_scope(plan_for(&db, "first", &calls))
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    Database::with_direct_dependency_plan_scope(plan_for(&db, "second", &calls))
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn failed_builds_are_not_retained_as_successful_plans() {
    let db = database().await;
    let calls = AtomicUsize::new(0);
    let failed = Database::with_direct_dependency_plan_scope(publication_plan(
        &db,
        "publication",
        || async { anyhow::bail!("original unavailable") },
    ))
    .await;
    assert!(failed.is_err());

    Database::with_direct_dependency_plan_scope(plan(&db, &calls))
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
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
