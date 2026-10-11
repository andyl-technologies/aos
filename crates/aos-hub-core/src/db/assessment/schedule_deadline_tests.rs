//! Exact freshness selection, coalescing and persistent deadline watermarks.
//!
//! Results are committed through the real evaluator. Conservatively lowering
//! their indexed deadline models elapsed database time without rewriting any
//! immutable evidence or granting fresh coverage or public service authority.

use anyhow::{Context as _, Result};
use aos_assessment::input::{CandidateHistory, Profile, UpstreamBinding};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::scan::ScanState;
use aos_contract::Sha256Digest;

use super::schedule_key;
use crate::db::assessment::{AssessmentObjectKind, AssessmentScanRecord};
use crate::db::Database;

async fn complete_updates(db: &Database, registry: i64, scan: &AssessmentScanRecord) -> Result<()> {
    let claim = db
        .claim_assessment_scan(registry, &scan.scan_id, 900)
        .await?;
    let mut data = db.assessment_evaluation_base(registry, &claim).await?;
    let now = db.assessment_database_time().await?;
    let first_observed = if let Some(history) = data.history.iter().find(|history| {
        history.provider == "github-releases"
            && history.project == "example/fixture"
            && history.raw_id == "v1.3.0"
    }) {
        history.first_observed_at.clone()
    } else {
        data.history.push(CandidateHistory {
            provider: "github-releases".into(),
            project: "example/fixture".into(),
            raw_id: "v1.3.0".into(),
            first_observed_at: now.clone(),
        });
        now.clone()
    };
    data.history.sort_by(|left, right| {
        (&left.provider, &left.project, &left.raw_id).cmp(&(
            &right.provider,
            &right.project,
            &right.raw_id,
        ))
    });
    data.upstream
        .retain(|binding| binding.component_ref != "component");
    data.upstream.push(UpstreamBinding {
        page_observations: vec![],
        component_ref: "component".into(),
        response_byte_length: 2,
        source_refs: vec![],
        observation: aos_assessment::discovery::UpstreamObservationV1 {
            schema: aos_assessment::UPSTREAM_OBSERVATION_V1.into(),
            provider: "github-releases".into(),
            project: "example/fixture".into(),
            retrieved_at_unix: now.unix_seconds(),
            request_url: "https://api.github.com/repos/example/fixture/releases".into(),
            adapter_version: "fixture/v1".into(),
            coverage: aos_assessment::discovery::ObservationCoverage::Complete,
            response_digest: Sha256Digest::of_bytes("[]"),
            candidates: vec![aos_assessment::discovery::ObservationCandidate {
                raw_id: "v1.3.0".into(),
                raw_version: "1.3.0".into(),
                published_at_unix: Some(1_700_000_000),
                first_observed_at_unix: first_observed.unix_seconds(),
                prerelease: false,
                yanked: false,
                release_url: None,
                status: None,
                vulnerable: None,
                licenses: vec![],
            }],
        },
    });
    let input = db
        .freeze_assessment_evaluation(registry, &claim, &data)
        .await?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    db.commit_assessment_evaluation(registry, &claim, &result)
        .await?;
    assert_eq!(
        db.assessment_scan(registry, &scan.scan_id)
            .await?
            .context("completed scan")?
            .state,
        ScanState::Succeeded
    );
    Ok(())
}

/// Qualifies exact deadline selection and admission-clock coalescing on one backend.
///
/// # Errors
/// Returns an error for failed fixture admission, clock transition or persistence.
pub(in crate::db::assessment) async fn qualify_deadlines(database: Database) -> Result<i64> {
    let (db, registry, reviewer, fences, mut write) =
        super::tests::setup_database(database).await?;
    write.configuration.continuous = true;
    let created = db
        .write_assessment_schedule_fenced(registry, &write, &reviewer, &fences)
        .await?;
    let scope = &write.resource_scope;
    let first =
        super::trigger_tests::admit(&db, registry, scope, &write.schedule_id, &fences).await?;
    complete_updates(&db, registry, &first).await?;
    let resource = db
        .assessment_resource(registry)
        .await?
        .context("current resource")?;
    let status = db
        .assessment_status_page(registry, &[Profile::Updates], "", 1)
        .await?;
    let deadline = status.subjects[0].profiles[0]
        .validated_until
        .clone()
        .context("complete profile deadline")?;
    let before_deadline = Timestamp::from_unix_seconds(deadline.unix_seconds() - 1)?;
    assert_eq!(
        db.expired_assessment_schedule_deadline(&resource, &write.configuration, &before_deadline)
            .await?,
        None
    );
    assert_eq!(
        db.expired_assessment_schedule_deadline(&resource, &write.configuration, &deadline)
            .await?,
        Some(deadline)
    );
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);

    // Qualify a review retained by the previous producer, which acknowledged
    // input but did not yet carry an expiry-admission clock.
    let mut prior_reader = db
        .schedule_record(registry, &schedule_key(scope, &write.schedule_id)?)
        .await?
        .context("pre-deadline review")?;
    prior_reader.review.observed_expiry = None;
    db.backend.execute(
        "UPDATE assessment_schedules SET configuration_json = ?3 WHERE registry_id = ?1 AND schedule_id = ?2",
        &vals![@slice registry, prior_reader.key, aos_contract::canonical::to_vec(&prior_reader.review)?],
    ).await?;

    let now = db.assessment_database_time().await?;
    let elapsed = Timestamp::from_unix_seconds(
        now.unix_seconds()
            .checked_sub(2)
            .context("fixture time is too early")?,
    )?;
    db.backend.execute("UPDATE assessment_heads SET validated_until = ?2 WHERE registry_id = ?1 AND profile = 'updates'", &vals![@slice registry, elapsed.unix_seconds()]).await?;
    let before = db.assessment_resource(registry).await?;
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 1);
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);
    assert_eq!(db.assessment_resource(registry).await?, before);
    let record = db
        .schedule_record(registry, &schedule_key(scope, &write.schedule_id)?)
        .await?
        .context("pending expiry")?;
    assert!(record.review.pending_input.is_some());
    let result_digest = status.subjects[0].profiles[0]
        .assessment_digest
        .context("immutable result digest")?;
    let original = db
        .assessment_object(scope, AssessmentObjectKind::Assessment, result_digest)
        .await?
        .context("immutable result")?;

    let mut foreign = write.configuration.clone();
    foreign.packages = vec!["unrelated/package".into()];
    assert_eq!(
        db.expired_assessment_schedule_deadline(&resource, &foreign, &now)
            .await?,
        None
    );
    let mut foreign = write.configuration.clone();
    foreign.profiles = vec![Profile::Vulnerabilities];
    assert_eq!(
        db.expired_assessment_schedule_deadline(&resource, &foreign, &now)
            .await?,
        None
    );
    let mut foreign_resource = resource.clone();
    foreign_resource.policy_digest = Sha256Digest::of_bytes("unrelated policy");
    assert_eq!(
        db.expired_assessment_schedule_deadline(&foreign_resource, &write.configuration, &now)
            .await?,
        None
    );
    let mut chunked = write.configuration.clone();
    chunked.packages = (0..64).map(|index| format!("fixture/{index:03}")).collect();
    chunked.packages.push("fixture/example".into());
    assert_eq!(
        db.expired_assessment_schedule_deadline(&resource, &chunked, &now)
            .await?,
        Some(elapsed.clone())
    );

    db.backend.execute("UPDATE assessment_schedules SET next_due_at = ?3 WHERE registry_id = ?1 AND schedule_id = ?2", &vals![@slice registry, schedule_key(scope, &write.schedule_id)?, created.next_due_at.unix_seconds()]).await?;
    let second =
        super::trigger_tests::admit(&db, registry, scope, &write.schedule_id, &fences).await?;
    assert_ne!(first.scan_id, second.scan_id);
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);
    complete_updates(&db, registry, &second).await?;
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);
    assert_eq!(
        db.assessment_object(scope, AssessmentObjectKind::Assessment, result_digest)
            .await?,
        Some(original)
    );

    let observed = db
        .schedule_record(registry, &schedule_key(scope, &write.schedule_id)?)
        .await?
        .context("admitted expiry clock")?
        .review
        .observed_expiry
        .context("expiry admission clock")?;
    // This final transition qualifies the real database clock boundary. Wait
    // only if this fixture has not yet crossed its next whole UTC second.
    if db.assessment_database_time().await? <= observed {
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    }
    let later = db.assessment_database_time().await?;
    anyhow::ensure!(later > observed, "database clock did not advance");
    db.backend.execute("UPDATE assessment_heads SET validated_until = ?2 WHERE registry_id = ?1 AND profile = 'updates'", &vals![@slice registry, later.unix_seconds()]).await?;
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 1);
    let third =
        super::trigger_tests::admit(&db, registry, scope, &write.schedule_id, &fences).await?;
    assert_ne!(second.scan_id, third.scan_id);
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);
    let retained = db
        .assessment_schedule(registry, &write.schedule_id)
        .await?
        .context("retained review")?;
    assert_eq!(retained.revision, created.revision);
    assert_eq!(retained.authority_expires_at, created.authority_expires_at);
    let public = String::from_utf8(retained.to_bytes()?)?;
    assert!(!public.contains("observedExpiry"));
    Ok(registry)
}

#[tokio::test]
async fn selected_expiry_coalesces_without_refresh_feedback_and_survives_reopen() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("deadlines.db");
    let registry = qualify_deadlines(Database::open(&path).await?).await?;
    let reopened = Database::open(&path).await?;
    let before = reopened.assessment_resource(registry).await?;
    assert_eq!(
        reopened
            .wake_changed_assessment_schedules(registry, 10)
            .await?,
        0
    );
    assert_eq!(reopened.assessment_resource(registry).await?, before);
    let scope = before.context("retained resource")?.partition;
    let record = reopened
        .schedule_record(registry, &schedule_key(&scope, "daily-fixture")?)
        .await?
        .context("retained deadline watermark")?;
    assert!(record.review.observed_expiry.is_some());
    Ok(())
}
