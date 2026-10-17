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
    alerts["afterIssue"] = json!(format!(
        "a1:{}:{}",
        Sha256Digest::of_bytes("capture").hex(),
        "0123456789abcdef0123456789abcdef"
    ));
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
        next_issue: Some(Sha256Digest::of_bytes("missing issue").to_string()),
    };
    assert!(alerts.to_bytes().is_err());
    Ok(())
}

fn event_page(sequences: &[u64], next: u64) -> Result<EventPageV1> {
    use aos_assessment_runtime::events::{AssessmentEventPayload, AssessmentEventV1};
    let now = Timestamp::parse("2026-10-09T00:00:00Z")?;
    Ok(EventPageV1 {
        schema: "aos.assessment-event-page/v1".into(),
        resource_scope: "registry:fixture-incarnation".into(),
        as_of: now.clone(),
        events: sequences
            .iter()
            .map(|sequence| AssessmentEventV1 {
                schema: "aos.assessment-event/v1".into(),
                event_id: format!("event-{sequence}"),
                sequence: *sequence,
                occurred_at: now.clone(),
                payload: AssessmentEventPayload::ScheduleChanged {
                    schedule_id: "fixture".into(),
                    revision: 1,
                    enabled: false,
                },
            })
            .collect(),
        next_sequence: next,
    })
}

#[test]
fn replay_consumers_refuse_unearned_positions_and_preserve_retained_prefix_restarts() -> Result<()>
{
    let mut query = EventQueryV1 {
        schema: "aos.assessment-event-query/v1".into(),
        limit: 2,
        after_sequence: 12,
        resource_scope: Some("registry:fixture-incarnation".into()),
    };
    event_page(&[13, 14], 14)?.validate_for_query(&query)?;
    event_page(&[], 12)?.validate_for_query(&query)?;

    for page in [
        event_page(&[14], 14)?,
        event_page(&[12], 12)?,
        event_page(&[], 13)?,
        event_page(&[], 11)?,
        event_page(&[13, 14, 15], 15)?,
    ] {
        assert!(page.validate_for_query(&query).is_err());
    }
    let mut foreign = event_page(&[13], 13)?;
    foreign.resource_scope = "registry:replacement".into();
    assert!(foreign.validate_for_query(&query).is_err());

    query.after_sequence = 0;
    query.resource_scope = None;
    event_page(&[90, 91], 91)?.validate_for_query(&query)?;
    event_page(&[], 0)?.validate_for_query(&query)?;
    assert!(event_page(&[], 91)?.validate_for_query(&query).is_err());
    query.limit = 0;
    assert!(event_page(&[90], 90)?.validate_for_query(&query).is_err());
    Ok(())
}

#[test]
fn unfiltered_replay_refuses_interior_gaps_before_consumer_publication() -> Result<()> {
    let page = event_page(&[13, 15], 15)?;
    assert!(page.to_bytes().is_err());
    assert!(EventPageV1::from_slice(&serde_json::to_vec(&page)?).is_err());
    let maximum = 9_007_199_254_740_991;
    let query = EventQueryV1 {
        schema: "aos.assessment-event-query/v1".into(),
        limit: 1,
        after_sequence: maximum,
        resource_scope: Some("registry:fixture-incarnation".into()),
    };
    event_page(&[], maximum)?.validate_for_query(&query)?;
    assert!(
        event_page(&[maximum], maximum)?
            .validate_for_query(&query)
            .is_err()
    );
    Ok(())
}
