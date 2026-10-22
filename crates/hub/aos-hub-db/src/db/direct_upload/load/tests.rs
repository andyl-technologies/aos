//! Joined originals preserve scalar/document corruption refusal.

use super::*;
use crate::db::fixtures::direct_upload::{complete, original, stage};

#[tokio::test]
async fn joined_documents_reject_changed_complete_and_stage_scalars() {
    let db = Database::open_in_memory().await.unwrap();
    let admitted = original(&db).await;
    let intent = complete(&admitted);
    let retained = db
        .retain_direct_complete("deployment", &admitted.admission.session_id, &intent, 11)
        .await
        .unwrap();
    let evidence = stage(&retained, &intent);
    db.retain_direct_verified_stage(
        "deployment",
        &retained,
        &evidence,
        DirectDependencyPhase::Content,
        12,
    )
    .await
    .unwrap();

    let expected = db
        .direct_upload_session("deployment", &admitted.admission.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expected.complete_intent.as_ref(), Some(&intent));
    assert_eq!(expected.stage_evidence.as_ref(), Some(&evidence));

    for (table, column, valid, invalid) in [
        (
            "direct_upload_completion_intents",
            "intent_digest",
            crate::value::Value::Text(intent.fingerprint().unwrap()),
            crate::value::Value::Text("a".repeat(64)),
        ),
        (
            "direct_upload_completion_intents",
            "expected_resource_version",
            crate::value::Value::Int(1),
            crate::value::Value::Int(2),
        ),
        (
            "direct_upload_stage_receipts",
            "evidence_digest",
            crate::value::Value::Text(digest(&evidence).unwrap()),
            crate::value::Value::Text("b".repeat(64)),
        ),
    ] {
        let sql = format!("UPDATE {table} SET {column} = ?1 WHERE session_id = ?2");
        db.backend
            .execute(&sql, &vals![invalid, admitted.admission.session_id])
            .await
            .unwrap();
        assert!(db
            .direct_upload_session("deployment", &admitted.admission.session_id)
            .await
            .is_err());

        db.backend
            .execute(&sql, &vals![valid, admitted.admission.session_id])
            .await
            .unwrap();
        assert_eq!(
            db.direct_upload_session("deployment", &admitted.admission.session_id)
                .await
                .unwrap(),
            Some(expected.clone())
        );
    }
}
