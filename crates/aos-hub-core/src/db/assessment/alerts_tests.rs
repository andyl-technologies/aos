//! Transactional event admission and independent exact-episode acknowledgements.

use anyhow::{Context as _, Result};
use aos_assessment::discovery::{ObservationCoverage, UpstreamObservationV1};
use aos_assessment::input::{EvaluationData, Profile, UpstreamBinding};
use aos_assessment_runtime::alerts::{Acknowledgement, AttentionState};
use aos_assessment_runtime::events::AssessmentEventPayload;
use aos_assessment_runtime::scan::ScanRequestV1;
use aos_contract::Sha256Digest;

use super::scans_tests::setup;
use crate::db::Database;

#[tokio::test]
async fn acknowledgement_replay_is_atomic_and_conflicting_or_revoked_retries_have_no_effect(
) -> Result<()> {
    let (db, registry_id, request) = setup().await?;
    commit_fixture(&db, registry_id, &request, None).await?;
    let opened = db
        .assessment_alert_page(registry_id, "", 1)
        .await?
        .remove(0);
    let resource = db
        .assessment_resource(registry_id)
        .await?
        .context("resource")?;
    let acknowledgement = Acknowledgement {
        idempotency_key: Some("review-episode-1".into()),
        issue_key: opened.issue_key,
        episode: opened.episode,
        actor_ref: request.actor_ref.clone(),
        acknowledged_at: db.assessment_database_time().await?,
        reason: Some("Investigating this exact episode".into()),
    };
    let acknowledged = db
        .acknowledge_assessment_alert_fenced(
            registry_id,
            resource.authorization_revision,
            opened.sequence,
            acknowledgement.clone(),
            &[],
        )
        .await?;
    let replay = db
        .acknowledge_assessment_alert_fenced(
            registry_id,
            resource.authorization_revision,
            opened.sequence,
            acknowledgement.clone(),
            &[],
        )
        .await?;
    assert_eq!(acknowledged, replay);
    assert_eq!(acknowledged.state, AttentionState::Open);
    assert_eq!(acknowledged.sequence, opened.sequence + 1);
    assert_eq!(
        db.assessment_event_page(registry_id, 0, 100).await?.len(),
        3
    );

    for conflict in ["reason", "episode"] {
        let mut changed = acknowledgement.clone();
        if conflict == "reason" {
            changed.reason = Some("Different acknowledgement".into());
        } else {
            changed.episode += 1;
        }
        assert!(db
            .acknowledge_assessment_alert_fenced(
                registry_id,
                resource.authorization_revision,
                acknowledged.sequence,
                changed,
                &[],
            )
            .await
            .is_err());
    }
    let refused = crate::backend::Statement::new(
        "UPDATE assessment_resources SET resource_version = resource_version WHERE registry_id = ?1",
        vals![registry_id + 1],
    ).expecting(1);
    // Both the first mutation and an otherwise valid idempotent receipt require
    // current authority in the checked transaction.
    assert!(db
        .acknowledge_assessment_alert_fenced(
            registry_id,
            resource.authorization_revision,
            opened.sequence,
            acknowledgement.clone(),
            std::slice::from_ref(&refused),
        )
        .await
        .is_err());
    let mut new_request = acknowledgement;
    new_request.idempotency_key = Some("second-review".into());
    assert!(db
        .acknowledge_assessment_alert_fenced(
            registry_id,
            resource.authorization_revision,
            acknowledged.sequence,
            new_request,
            &[refused],
        )
        .await
        .is_err());
    assert_eq!(
        db.assessment_alert(registry_id, opened.issue_key)
            .await?
            .context("alert")?,
        acknowledged
    );
    assert_eq!(
        db.assessment_event_page(registry_id, 0, 100).await?.len(),
        3
    );
    Ok(())
}

async fn commit_fixture(
    db: &Database,
    registry_id: i64,
    request: &ScanRequestV1,
    data: Option<EvaluationData>,
) -> Result<()> {
    let scan = db.request_assessment_scan(registry_id, request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 60)
        .await?;
    let data = match data {
        Some(data) => data,
        None => db.assessment_evaluation_base(registry_id, &claim).await?,
    };
    let input = db
        .freeze_assessment_evaluation(registry_id, &claim, &data)
        .await?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    db.commit_assessment_evaluation(registry_id, &claim, &result)
        .await?;
    db.commit_assessment_evaluation(registry_id, &claim, &result)
        .await?;
    Ok(())
}

#[tokio::test]
async fn assessment_events_and_episodes_preserve_acknowledgements_through_uncertainty() -> Result<()>
{
    let (db, registry_id, mut request) = setup().await?;
    commit_fixture(&db, registry_id, &request, None).await?;
    let first_events = db.assessment_event_page(registry_id, 0, 100).await?;
    assert_eq!(first_events.len(), 2);
    assert_eq!(first_events[0].sequence, 1);
    assert!(matches!(
        first_events[0].payload,
        AssessmentEventPayload::Alert { .. }
    ));
    assert!(matches!(
        first_events[1].payload,
        AssessmentEventPayload::ScanCompleted { .. }
    ));
    let opened = db
        .assessment_alert_page(registry_id, "", 100)
        .await?
        .remove(0);
    assert_eq!(opened.episode, 1);
    assert_eq!(opened.sequence, 1);
    assert_eq!(opened.state, AttentionState::Open);
    let resource = db
        .assessment_resource(registry_id)
        .await?
        .context("resource")?;
    let acknowledgement = Acknowledgement {
        idempotency_key: None,
        issue_key: opened.issue_key,
        episode: opened.episode,
        actor_ref: request.actor_ref.clone(),
        acknowledged_at: db.assessment_database_time().await?,
        reason: Some("Investigating the evidence gap".into()),
    };
    assert!(db
        .acknowledge_assessment_alert(
            registry_id,
            resource.authorization_revision + 1,
            opened.sequence,
            acknowledgement.clone(),
        )
        .await
        .is_err());
    assert_eq!(
        db.assessment_event_page(registry_id, 0, 100).await?.len(),
        2
    );
    assert_eq!(
        db.assessment_alert(registry_id, opened.issue_key)
            .await?
            .context("issue")?,
        opened
    );

    let acknowledged = db
        .acknowledge_assessment_alert(
            registry_id,
            resource.authorization_revision,
            opened.sequence,
            acknowledgement.clone(),
        )
        .await?;
    assert_eq!(acknowledged.state, AttentionState::Open);
    assert_eq!(acknowledged.acknowledgements.len(), 1);
    assert!(db
        .acknowledge_assessment_alert(
            registry_id,
            resource.authorization_revision,
            opened.sequence,
            acknowledgement,
        )
        .await
        .is_err());
    request.idempotency_key = "refresh-unknown".into();
    commit_fixture(&db, registry_id, &request, None).await?;
    let uncertain = db
        .assessment_alert(registry_id, opened.issue_key)
        .await?
        .context("issue")?;
    assert_eq!(uncertain.episode, 1);
    assert_eq!(uncertain.sequence, 3);
    assert_eq!(uncertain.acknowledgements, acknowledged.acknowledgements);
    assert!(uncertain.issue.uncertain);
    let events = db.assessment_event_page(registry_id, 2, 100).await?;
    assert_eq!(events.len(), 2);
    assert!(matches!(
        events[0].payload,
        AssessmentEventPayload::Acknowledged { .. }
    ));
    assert!(matches!(
        events[1].payload,
        AssessmentEventPayload::ScanCompleted { .. }
    ));
    assert!(db
        .assessment_event_page(registry_id, 4, 100)
        .await?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn fresh_complete_evidence_resolves_coverage_and_reopening_creates_an_independent_episode(
) -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    commit_fixture(&db, registry_id, &request, None).await?;
    let original = db
        .assessment_alert_page(registry_id, "", 100)
        .await?
        .remove(0);
    request.idempotency_key = "complete-refresh".into();
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 60)
        .await?;
    let mut data = db.assessment_evaluation_base(registry_id, &claim).await?;
    let now = db.assessment_database_time().await?;
    data.upstream.push(UpstreamBinding {
        source_refs: vec![],
        component_ref: "component".into(),
        response_byte_length: 2,
        observation: UpstreamObservationV1 {
            schema: aos_assessment::UPSTREAM_OBSERVATION_V1.into(),
            provider: "github-releases".into(),
            project: "example/fixture".into(),
            retrieved_at_unix: now.unix_seconds(),
            request_url: "https://api.github.com/repos/example/fixture/releases".into(),
            adapter_version: "fixture/v1".into(),
            coverage: ObservationCoverage::Complete,
            response_digest: Sha256Digest::of_bytes("[]"),
            candidates: vec![],
        },
    });
    let input = db
        .freeze_assessment_evaluation(registry_id, &claim, &data)
        .await?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    assert_eq!(
        result.subject_results[0].coverage[0].state,
        aos_assessment::security::CoverageState::Complete
    );
    db.commit_assessment_evaluation(registry_id, &claim, &result)
        .await?;
    let resolved = db
        .assessment_alert(registry_id, original.issue_key)
        .await?
        .context("issue")?;
    assert_eq!(resolved.state, AttentionState::Resolved);
    assert_eq!(resolved.episode, 1);
    request.idempotency_key = "lost-source".into();
    // An offline read now preserves committed source evidence. Reopening
    // requires an explicit failed-refresh observation rather than an empty read.
    data.upstream[0].observation.coverage = ObservationCoverage::Truncated {
        reason: "source-acquisition-incomplete".into(),
    };
    commit_fixture(&db, registry_id, &request, Some(data)).await?;
    let reopened = db
        .assessment_alert(registry_id, original.issue_key)
        .await?
        .context("issue")?;
    assert_eq!(reopened.state, AttentionState::Open);
    assert_eq!(reopened.episode, 2);
    Ok(())
}

#[tokio::test]
async fn an_unselected_profile_cannot_resolve_or_change_existing_attention() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    commit_fixture(&db, registry_id, &request, None).await?;
    let original = db
        .assessment_alert_page(registry_id, "", 100)
        .await?
        .remove(0);
    request.idempotency_key = "license-only".into();
    request.profiles = vec![Profile::LicenseSignals];
    commit_fixture(&db, registry_id, &request, None).await?;
    assert_eq!(
        db.assessment_alert(registry_id, original.issue_key)
            .await?
            .context("issue")?,
        original
    );
    assert_eq!(
        db.assessment_alert_page(registry_id, "", 100).await?.len(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn a_concurrent_acknowledgement_rolls_back_refresh_alerts_and_events() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    commit_fixture(&db, registry_id, &request, None).await?;
    let original = db
        .assessment_alert_page(registry_id, "", 100)
        .await?
        .remove(0);
    request.idempotency_key = "racing-refresh".into();
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 60)
        .await?;
    let data = db.assessment_evaluation_base(registry_id, &claim).await?;
    let input = db
        .freeze_assessment_evaluation(registry_id, &claim, &data)
        .await?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    let statements = db
        .assessment_attention_statements(
            registry_id,
            &scan.scan_id,
            &input,
            &data,
            &result,
            &db.assessment_database_time().await?,
        )
        .await?;
    let resource = db
        .assessment_resource(registry_id)
        .await?
        .context("resource")?;
    let acknowledged = db
        .acknowledge_assessment_alert(
            registry_id,
            resource.authorization_revision,
            original.sequence,
            Acknowledgement {
                idempotency_key: None,
                issue_key: original.issue_key,
                episode: original.episode,
                actor_ref: request.actor_ref,
                acknowledged_at: db.assessment_database_time().await?,
                reason: None,
            },
        )
        .await?;
    assert!(db.backend.checked_batch(&statements).await.is_err());
    assert_eq!(
        db.assessment_alert(registry_id, original.issue_key)
            .await?
            .context("issue")?,
        acknowledged
    );
    assert_eq!(
        db.assessment_event_page(registry_id, 0, 100).await?.len(),
        3
    );
    Ok(())
}
