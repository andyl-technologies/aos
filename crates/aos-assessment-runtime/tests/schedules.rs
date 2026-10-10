//! Closed recurring selectors and public projections never carry private authority.

use anyhow::Result;
use aos_assessment::input::{FreshnessMode, Profile};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::scan::ScanLimits;
use aos_assessment_runtime::schedules::{
    ScheduleConfigurationV1, SchedulePageV1, ScheduleQueryV1, ScheduleV1, ScheduleWriteV1,
};

fn configuration() -> Result<ScheduleConfigurationV1> {
    Ok(ScheduleConfigurationV1 {
        schema: "aos.assessment-schedule-configuration/v1".into(),
        packages: vec!["fixture/package".into()],
        profiles: vec![Profile::Updates, Profile::Vulnerabilities],
        freshness: FreshnessMode::RefreshStale,
        cadence_seconds: 3600,
        review_expires_at: Timestamp::parse("2026-10-10T00:00:00Z")?,
        limits: ScanLimits::default(),
    })
}

#[test]
fn recurring_review_rejects_implicit_all_duplicates_and_authority_injection() -> Result<()> {
    let write = ScheduleWriteV1 {
        schema: "aos.assessment-schedule-write/v1".into(),
        resource_scope: "registry-incarnation".into(),
        schedule_id: "daily".into(),
        expected_revision: 0,
        enabled: true,
        configuration: configuration()?,
    };
    let original = serde_json::to_value(write)?;
    ScheduleWriteV1::from_slice(&serde_json::to_vec(&original)?)?;
    for replacement in [
        serde_json::json!([]),
        serde_json::json!(["fixture/package", "fixture/package"]),
    ] {
        let mut changed = original.clone();
        changed["configuration"]["packages"] = replacement;
        assert!(ScheduleWriteV1::from_slice(&serde_json::to_vec(&changed)?).is_err());
    }
    for key in ["actorRef", "claims", "credentialRef"] {
        let mut changed = original.clone();
        changed[key] = serde_json::json!("injected");
        assert!(ScheduleWriteV1::from_slice(&serde_json::to_vec(&changed)?).is_err());
    }
    for cadence in [0, 59, 2_592_001] {
        let mut changed = original.clone();
        changed["configuration"]["cadenceSeconds"] = serde_json::json!(cadence);
        assert!(ScheduleWriteV1::from_slice(&serde_json::to_vec(&changed)?).is_err());
    }
    Ok(())
}

#[test]
fn public_schedule_pages_bind_scope_and_continuation() -> Result<()> {
    let now = Timestamp::parse("2026-10-09T00:00:00Z")?;
    let mut page = SchedulePageV1 {
        schema: "aos.assessment-schedule-page/v1".into(),
        resource_scope: "registry-incarnation".into(),
        as_of: now.clone(),
        schedules: vec![ScheduleV1 {
            schema: "aos.assessment-schedule/v1".into(),
            resource_scope: "registry-incarnation".into(),
            schedule_id: "daily".into(),
            revision: 1,
            enabled: true,
            authority_expires_at: configuration()?.review_expires_at,
            next_due_at: now,
            configuration: configuration()?,
        }],
        next_schedule: Some(format!("r1:{}:{}", "a".repeat(64), "b".repeat(32))),
    };
    assert_eq!(SchedulePageV1::from_slice(&page.to_bytes()?)?, page);
    page.schedules[0].resource_scope = "other".into();
    assert!(page.to_bytes().is_err());
    page.schedules[0].resource_scope = page.resource_scope.clone();
    page.next_schedule = Some("another".into());
    assert!(page.to_bytes().is_err());
    Ok(())
}

#[test]
fn schedule_change_events_round_trip_without_authority_metadata() -> Result<()> {
    use aos_assessment_runtime::events::{AssessmentEventPayload, AssessmentEventV1};
    let mut event = AssessmentEventV1 {
        schema: "aos.assessment-event/v1".into(),
        event_id: "review-event".into(),
        sequence: 1,
        occurred_at: Timestamp::parse("2026-10-09T00:00:00Z")?,
        payload: AssessmentEventPayload::ScheduleChanged {
            schedule_id: "daily".into(),
            revision: 1,
            enabled: false,
        },
    };
    assert_eq!(AssessmentEventV1::from_slice(&event.to_bytes()?)?, event);
    event.payload = AssessmentEventPayload::ScheduleChanged {
        schedule_id: "daily".into(),
        revision: 0,
        enabled: false,
    };
    assert!(event.to_bytes().is_err());
    Ok(())
}

#[test]
fn schedule_continuations_require_original_scope_and_opaque_cursor_kind() -> Result<()> {
    let token = format!("r1:{}:{}", "a".repeat(64), "b".repeat(32));
    let query = ScheduleQueryV1 {
        schema: "aos.assessment-schedule-query/v1".into(),
        limit: 1,
        resource_scope: Some("registry-incarnation".into()),
        schedule_id: None,
        after_schedule: Some(token.clone()),
    };
    ScheduleQueryV1::from_slice(&serde_json::to_vec(&query)?)?;
    for cursor in [
        "daily".to_string(),
        token.replacen("r1:", "a1:", 1),
        token.to_uppercase(),
    ] {
        let mut changed = query.clone();
        changed.after_schedule = Some(cursor);
        assert!(ScheduleQueryV1::from_slice(&serde_json::to_vec(&changed)?).is_err());
    }
    let mut changed = query.clone();
    changed.resource_scope = None;
    assert!(ScheduleQueryV1::from_slice(&serde_json::to_vec(&changed)?).is_err());
    let mut changed = query;
    changed.schedule_id = Some("daily".into());
    assert!(ScheduleQueryV1::from_slice(&serde_json::to_vec(&changed)?).is_err());
    Ok(())
}
