//! Cleanup readiness retains actual physical unknowns across SQLite restart.

use super::{
    state::Head,
    tests::{config, pending, receipt},
};
use aos_hub_core::{
    backend::{Backend, SqlxBackend},
    value::Value,
};

#[tokio::test]
async fn cleanup_readiness_refuses_persistent_unknown_and_requires_exact_positive_terminal() {
    let path = std::env::temp_dir().join(format!("frozen-unknown-{}.sqlite", uuid::Uuid::new_v4()));
    let config = config();
    let (head, _) = pending(&config, 0).await;
    assert!(head.require_cleanup_ready().is_err());
    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    db.execute_batch("CREATE TABLE physical (head TEXT NOT NULL)")
        .await
        .unwrap();
    db.execute(
        "INSERT INTO physical VALUES (?1)",
        &[Value::Text(serde_json::to_string(&head).unwrap())],
    )
    .await
    .unwrap();
    drop(db);

    let restarted = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let row = restarted
        .query_opt("SELECT head FROM physical", &[])
        .await
        .unwrap()
        .unwrap();
    let held: Head = serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap();
    assert!(held.require_cleanup_ready().is_err());
    assert!(held == head);
    let positive = receipt(&held);
    let mut changed = positive.clone();
    changed.turn.dispatch_nonce = "cc".repeat(32);
    assert!(held.terminal(&changed).is_err());
    let settled = held.terminal(&positive).unwrap();
    settled.require_cleanup_ready().unwrap();
    assert_eq!(settled.receipts.get(), held.receipts.get() + 1);
    drop(restarted);
    std::fs::remove_file(path).unwrap();
}
