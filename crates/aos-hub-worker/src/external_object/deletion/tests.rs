//! Fixture provider conditions and durable turn recovery use production classifiers.

use super::*;
use crate::external_object::{
    protocol::{self, Effect, GuardReply, Receipt},
    state::Head,
    tests::{clock, config, intent, token},
};
use aos_hub_core::{
    backend::{Backend, SqlxBackend},
    storage_authority::lease::{LeaseCohort, LeaseEffect, LeasePurpose},
    value::Value,
};

fn expected() -> ExternalDeletePrecondition {
    ExternalDeletePrecondition {
        provider_version: "upload-one".into(),
        etag: "\"same-content\"".into(),
        bytes: "12".into(),
        content_hash: None,
    }
}

#[test]
fn replacement_and_unsupported_provider_never_acknowledge_the_original() {
    let original = expected();
    assert!(condition_matches(
        &original,
        "objects/blob",
        Some("12"),
        Some("\"same-content\""),
        Some("upload-one")
    )
    .unwrap());
    assert!(!condition_matches(
        &original,
        "objects/blob",
        Some("12"),
        Some("\"same-content\""),
        Some("replacement")
    )
    .unwrap());
    assert!(!condition_matches(
        &original,
        "objects/blob",
        Some("12"),
        Some("\"same-content\""),
        None
    )
    .unwrap());
    assert!(!condition_matches(
        &original,
        "objects/blob",
        Some("12"),
        Some("\"replacement\""),
        Some("upload-one")
    )
    .unwrap());
    assert!(acknowledgement(&original, 204, Some("replacement"), None).is_err());
    assert!(acknowledgement(&original, 204, None, None).is_err());
    assert!(acknowledgement(&original, 204, Some("upload-one"), Some("true")).is_err());
    assert!(acknowledgement(&original, 500, None, None).is_err());
    assert!(matches!(
        acknowledgement(&original, 412, None, None).unwrap(),
        ExternalObjectOutcome::DeletePreconditionFailed
    ));

    // The reserved negative probe must reach DELETE with a wrong ETag for the
    // current version; otherwise a HEAD check would falsely qualify providers
    // that ignore If-Match. The exception grants no ordinary-object dispatch.
    let key = ".aos-internal/conditional-delete-probes/1-1";
    assert!(condition_matches(
        &original,
        key,
        Some("12"),
        Some("\"replacement\""),
        Some("upload-one")
    )
    .unwrap());
    assert!(!condition_matches(
        &original,
        key,
        Some("12"),
        Some("\"same-content\""),
        Some("replacement")
    )
    .unwrap());
}

#[tokio::test]
async fn lost_delete_reply_retains_one_dispatch_and_exact_receipt_survives_restart() {
    let path =
        std::env::temp_dir().join(format!("external-delete-{}.sqlite", uuid::Uuid::new_v4()));
    let mut config = config();
    let delete = LeaseCohort::from_publication(
        &config.publications[0],
        &config.executor_identity,
        "association-one",
        LeasePurpose::Delete,
        "managed/binding/objects",
        vec![LeaseEffect::ConditionalDelete],
    )
    .unwrap();
    config.cohorts.push(delete.clone());
    config.validate().unwrap();
    let mut original = intent(&config, 2, "delete-original");
    original.effect = Effect::Delete {
        expected: expected(),
    };
    let initial = Head::initialize(&config, &original, clock(100)).unwrap();
    let (pending, permit) = initial
        .begin(
            &config,
            original.clone(),
            &token(&config, 2, 0).await,
            "b".repeat(64),
            clock(101),
        )
        .unwrap();
    assert!(matches!(permit, GuardReply::Dispatch { .. }));
    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    db.execute_batch("CREATE TABLE retained (head TEXT NOT NULL, receipt TEXT)")
        .await
        .unwrap();
    db.execute(
        "INSERT INTO retained(head) VALUES(?1)",
        &[Value::Text(serde_json::to_string(&pending).unwrap())],
    )
    .await
    .unwrap();
    drop(db);

    let restarted = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let row = restarted
        .query_opt("SELECT head FROM retained", &[])
        .await
        .unwrap()
        .unwrap();
    let held: Head = serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap();
    // A later renewed lease cannot redispatch an unknown mutation.
    assert!(held
        .begin(
            &config,
            original.clone(),
            &token(&config, 2, 1).await,
            "c".repeat(64),
            clock(110)
        )
        .is_err());
    held.require_cleanup_ready().unwrap_err();
    let positive = Receipt {
        turn: held.pending.clone().unwrap(),
        outcome: acknowledgement(&expected(), 204, Some("upload-one"), None).unwrap(),
    };
    let mut changed = positive.clone();
    changed.turn.intent.effect = Effect::Delete {
        expected: ExternalDeletePrecondition {
            provider_version: "replacement".into(),
            ..expected()
        },
    };
    assert!(held.terminal(&changed).is_err());
    let settled = held.terminal(&positive).unwrap();
    assert!(settled.visible_receipt.is_none());
    restarted
        .execute(
            "UPDATE retained SET head=?1, receipt=?2",
            &[
                Value::Text(serde_json::to_string(&settled).unwrap()),
                Value::Text(serde_json::to_string(&positive).unwrap()),
            ],
        )
        .await
        .unwrap();
    drop(restarted);

    let cold = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let row = cold
        .query_opt("SELECT head,receipt FROM retained", &[])
        .await
        .unwrap()
        .unwrap();
    let settled: Head = serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap();
    let receipt: Receipt = serde_json::from_str(&row.get::<String>(1).unwrap()).unwrap();
    let (_, replay) = settled.replay(&original, &receipt).unwrap();
    assert!(matches!(replay, GuardReply::Terminal { .. }));
    assert_eq!(settled.receipts.get(), 1);
    assert_eq!(
        protocol::digest(&receipt).unwrap(),
        protocol::digest(&positive).unwrap()
    );
    drop(cold);
    std::fs::remove_file(path).unwrap();
}
