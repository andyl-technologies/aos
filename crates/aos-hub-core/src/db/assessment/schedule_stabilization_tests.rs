//! Real-clock stabilization wakeups under the existing reviewed scan authority.
//!
//! Pure evaluation commits the exact policy horizon. The same retained source
//! closure matures without provider work, and historical result bytes stay fixed.

use anyhow::{Context as _, Result};
use aos_assessment::input::{FreshnessMode, Profile};
use aos_assessment::result::{PackageAssessmentV1, VersionDecision};
use aos_assessment::time::Timestamp;

use super::schedule_key;
use crate::db::assessment::AssessmentObjectKind;
use crate::db::Database;

/// Qualifies indexed maturation, one due admission and immutable evidence reuse.
///
/// The private fixture uses existing read fences; it establishes no public
/// assessment IAM permission or standing role assignment.
///
/// # Errors
/// Returns an error for failed admission, source custody, clock or persistence.
pub(in crate::db::assessment) async fn qualify_stabilization(database: Database) -> Result<i64> {
    let (db, registry, reviewer, fences, mut write) =
        super::tests::setup_database(database).await?;
    write.configuration.continuous = true;
    write.configuration.freshness = FreshnessMode::Offline;
    let created = db
        .write_assessment_schedule_fenced(registry, &write, &reviewer, &fences)
        .await?;
    let scope = &write.resource_scope;
    let first =
        super::trigger_tests::admit(&db, registry, scope, &write.schedule_id, &fences).await?;
    let now = db.assessment_database_time().await?;
    let eligible_at = Timestamp::from_unix_seconds(now.unix_seconds() + 5)?;
    let publication = eligible_at.unix_seconds() - 3 * 86_400;
    super::deadline_tests::complete_updates_with_publication(
        &db,
        registry,
        &first,
        Some(publication),
    )
    .await?;

    let status = db
        .assessment_status_page(registry, &[Profile::Updates], "", 1)
        .await?;
    let head = &status.subjects[0].profiles[0];
    assert_eq!(head.validated_until, Some(eligible_at.clone()));
    let digest = head.assessment_digest.context("stabilizing result")?;
    let original = db
        .assessment_object(scope, AssessmentObjectKind::Assessment, digest)
        .await?
        .context("original result custody")?;
    let original_result = PackageAssessmentV1::from_slice(&original)?;
    assert_eq!(
        original_result.subject_results[0].versions[0].decision,
        VersionDecision::Stabilizing
    );
    let (input, data) = db
        .assessment_frozen_evaluation(registry, &first.scan_id)
        .await?;
    let resource = db
        .assessment_resource(registry)
        .await?
        .context("stabilization resource")?;
    let before = Timestamp::from_unix_seconds(eligible_at.unix_seconds() - 1)?;
    assert_eq!(
        db.expired_assessment_schedule_deadline(&resource, &write.configuration, &before)
            .await?,
        None
    );
    assert_eq!(
        db.expired_assessment_schedule_deadline(&resource, &write.configuration, &eligible_at)
            .await?,
        Some(eligible_at.clone())
    );
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);

    // Cross this exact database-clock boundary without rewriting indexed heads.
    // Each fixture waits at most five whole seconds plus a small clock margin.
    let clock = db.assessment_database_time().await?;
    let remaining = eligible_at
        .unix_seconds()
        .saturating_sub(clock.unix_seconds());
    anyhow::ensure!(
        remaining <= 5,
        "stabilization fixture clock moved backwards"
    );
    if remaining > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(remaining * 1000 + 100)).await;
    }
    assert!(db.assessment_database_time().await? >= eligible_at);
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 1);
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);
    let stale = db
        .assessment_status_page(registry, &[Profile::Updates], "", 1)
        .await?;
    assert!(!stale.subjects[0].profiles[0].fresh);
    let second =
        super::trigger_tests::admit(&db, registry, scope, &write.schedule_id, &fences).await?;
    assert_ne!(first.scan_id, second.scan_id);
    assert_eq!(second.request.freshness, FreshnessMode::Offline);
    let claim = db
        .claim_assessment_scan(registry, &second.scan_id, 60)
        .await?;
    let matured_input = db
        .freeze_assessment_evaluation(registry, &claim, &data)
        .await?;
    let matured = aos_assessment::evaluator::evaluate(&matured_input, &data)?;
    assert_eq!(
        matured.subject_results[0].versions[0].decision,
        VersionDecision::UpdateAvailable
    );
    assert_eq!(matured_input.observation_digests, input.observation_digests);
    assert_eq!(matured_input.history_digest, input.history_digest);
    db.commit_assessment_evaluation(registry, &claim, &matured)
        .await?;
    let latest = db
        .assessment_status_page(registry, &[Profile::Updates], "", 1)
        .await?;
    assert!(latest.subjects[0].profiles[0].fresh);
    assert!(latest.subjects[0].profiles[0]
        .validated_until
        .as_ref()
        .is_some_and(|deadline| deadline > &eligible_at));
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);
    assert_eq!(
        db.assessment_object(scope, AssessmentObjectKind::Assessment, digest)
            .await?,
        Some(original)
    );
    let review = db
        .assessment_schedule(registry, &write.schedule_id)
        .await?
        .context("unchanged review")?;
    assert_eq!(review.revision, created.revision);
    assert_eq!(review.authority_expires_at, created.authority_expires_at);
    Ok(registry)
}

#[tokio::test]
async fn retained_candidate_maturation_wakes_once_without_provider_work_or_history_reset(
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("stabilization.db");
    let registry = qualify_stabilization(Database::open(&path).await?).await?;
    let reopened = Database::open(&path).await?;
    let resource = reopened
        .assessment_resource(registry)
        .await?
        .context("reopened resource")?;
    assert_eq!(
        reopened
            .wake_changed_assessment_schedules(registry, 10)
            .await?,
        0
    );
    let record = reopened
        .schedule_record(
            registry,
            &schedule_key(&resource.partition, "daily-fixture")?,
        )
        .await?
        .context("retained stabilization review")?;
    assert!(record.review.observed_expiry.is_some());
    let status = reopened
        .assessment_status_page(registry, &[Profile::Updates], "", 1)
        .await?;
    assert!(status.subjects[0].profiles[0].fresh);
    Ok(())
}

/// Qualifies one retained continuous-review catch-up after projection upgrade.
///
/// # Errors
/// Returns an error for failed fixture admission, private review or persistence.
pub(in crate::db::assessment) async fn qualify_epoch_catchup(database: Database) -> Result<i64> {
    let (db, registry, reviewer, fences, mut write) =
        super::tests::setup_database(database).await?;
    write.configuration.continuous = true;
    let created = db
        .write_assessment_schedule_fenced(registry, &write, &reviewer, &fences)
        .await?;
    let scope = &write.resource_scope;
    let first =
        super::trigger_tests::admit(&db, registry, scope, &write.schedule_id, &fences).await?;
    let resource = db
        .assessment_resource(registry)
        .await?
        .context("retained resource")?;
    let old_basis = aos_contract::Sha256Digest::of_canonical(
        "aos.assessment-recurring-input/v1",
        &(
            &resource.partition,
            resource.inventory_digest,
            resource.inventory_revision,
            resource.policy_digest,
            resource.resource_version - resource.next_generation,
            resource.authorization_revision,
        ),
    )?;
    let new_basis = super::triggers::input_basis(&resource)?;
    assert_ne!(old_basis, new_basis);
    let mut record = db
        .schedule_record(registry, &schedule_key(scope, &write.schedule_id)?)
        .await?
        .context("retained review")?;
    record.review.observed_input = Some(old_basis);
    db.backend.execute(
        "UPDATE assessment_schedules SET configuration_json = ?3 WHERE registry_id = ?1 AND schedule_id = ?2",
        &vals![@slice registry, record.key, aos_contract::canonical::to_vec(&record.review)?],
    ).await?;

    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 1);
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);
    let second =
        super::trigger_tests::admit(&db, registry, scope, &write.schedule_id, &fences).await?;
    assert_ne!(first.scan_id, second.scan_id);
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);
    let retained = db
        .schedule_record(registry, &schedule_key(scope, &write.schedule_id)?)
        .await?
        .context("admitted projection epoch")?;
    assert_eq!(retained.review.observed_input, Some(new_basis));
    assert!(retained.review.pending_input.is_none());
    assert_eq!(
        super::triggers::input_basis(
            &db.assessment_resource(registry)
                .await?
                .context("allocated resource")?
        )?,
        new_basis
    );
    let public = db
        .assessment_schedule(registry, &write.schedule_id)
        .await?
        .context("unchanged public review")?;
    assert_eq!(public.revision, created.revision);
    assert_eq!(public.authority_expires_at, created.authority_expires_at);
    Ok(registry)
}

#[tokio::test]
async fn older_projection_reviews_catch_up_once_without_generation_feedback() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lifetime-epoch.db");
    let registry = qualify_epoch_catchup(Database::open(&path).await?).await?;
    let reopened = Database::open(&path).await?;
    assert_eq!(
        reopened
            .wake_changed_assessment_schedules(registry, 10)
            .await?,
        0
    );
    Ok(())
}
