//! Attention query scope, closed authority and reconnect heartbeat qualification.

use anyhow::Result;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::attention_control::*;
use aos_contract::Sha256Digest;
use serde_json::json;

#[test]
fn attention_continuations_require_scope_and_refuse_caller_authority() -> Result<()> {
    let mut alerts = json!({"schema":"aos.assessment-alert-query/v1", "limit":10});
    AlertQueryV1::from_slice(&serde_json::to_vec(&alerts)?)?;
    alerts["afterIssue"] = json!(Sha256Digest::of_bytes("issue"));
    assert!(AlertQueryV1::from_slice(&serde_json::to_vec(&alerts)?).is_err());
    alerts["resourceScope"] = json!("registry:fixture-incarnation");
    AlertQueryV1::from_slice(&serde_json::to_vec(&alerts)?)?;
    alerts["limit"] = json!(11);
    assert!(AlertQueryV1::from_slice(&serde_json::to_vec(&alerts)?).is_err());

    let mut events =
        json!({"schema":"aos.assessment-event-query/v1", "limit":10, "afterSequence":1});
    assert!(EventQueryV1::from_slice(&serde_json::to_vec(&events)?).is_err());
    events["resourceScope"] = json!("registry:fixture-incarnation");
    EventQueryV1::from_slice(&serde_json::to_vec(&events)?)?;
    events["afterSequence"] = json!(9_007_199_254_740_992_u64);
    assert!(EventQueryV1::from_slice(&serde_json::to_vec(&events)?).is_err());

    let request = json!({"schema":"aos.assessment-alert-acknowledgement/v1", "resourceScope":"registry:fixture-incarnation",
        "issueKey":Sha256Digest::of_bytes("issue"), "episode":1, "expectedSequence":2, "idempotencyKey":"review-1"});
    AlertAcknowledgementV1::from_slice(&serde_json::to_vec(&request)?)?;
    for (field, value) in [
        ("actorRef", json!("another-principal")),
        ("acknowledgedAt", json!("2026-10-09T00:00:00Z")),
        ("reason", serde_json::Value::Null),
    ] {
        let mut changed = request.clone();
        changed[field] = value;
        assert!(AlertAcknowledgementV1::from_slice(&serde_json::to_vec(&changed)?).is_err());
    }
    Ok(())
}

#[test]
fn idle_replay_preserves_the_reconnect_cursor_and_explicit_database_time() -> Result<()> {
    let page = EventPageV1 {
        schema: "aos.assessment-event-page/v1".into(),
        resource_scope: "registry:fixture-incarnation".into(),
        as_of: Timestamp::parse("2026-10-09T00:00:00Z")?,
        events: vec![],
        next_sequence: 12,
    };
    assert_eq!(EventPageV1::from_slice(&page.to_bytes()?)?, page);
    let mut changed = serde_json::to_value(&page)?;
    changed["nextSequence"] = json!(9_007_199_254_740_992_u64);
    assert!(EventPageV1::from_slice(&serde_json::to_vec(&changed)?).is_err());
    let alerts = AlertPageV1 {
        schema: "aos.assessment-alert-page/v1".into(),
        resource_scope: page.resource_scope,
        as_of: page.as_of,
        alerts: vec![],
        next_issue: Some(Sha256Digest::of_bytes("missing issue")),
    };
    assert!(alerts.to_bytes().is_err());
    Ok(())
}
