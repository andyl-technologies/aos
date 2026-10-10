//! Real PostgreSQL qualification of serving schema and assessment admission.

use anyhow::{Context as _, Result};
use aos_assessment::input::Profile;
use aos_assessment_runtime::alerts::{Acknowledgement, AttentionState};
use aos_assessment_runtime::scan::ScanState;

use crate::backend::SqlxBackend;
use crate::db::Database;

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn rejected_schedule_pages_rotate_fairly_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::schedules::queue_tests::qualify_queue(db).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn service_delivery_rechecks_current_credentials_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::notifications::service_tests::reviewed_service_delivery(db).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn serving_inventory_scan_heads_alerts_acknowledgements_and_events_are_atomic_on_postgresql(
) -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    let (db, registry_id, mut request) = super::scans_tests::setup_database(db).await?;
    request.profiles = vec![Profile::Updates, Profile::Vulnerabilities];
    let first = db.request_assessment_scan(registry_id, &request).await?;
    let retry = db.request_assessment_scan(registry_id, &request).await?;
    assert_eq!(first.scan_id, retry.scan_id);
    let claim = db
        .claim_assessment_scan(registry_id, &first.scan_id, 60)
        .await?;
    let data = db.assessment_evaluation_base(registry_id, &claim).await?;
    let input = db
        .freeze_assessment_evaluation(registry_id, &claim, &data)
        .await?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    db.commit_assessment_evaluation(registry_id, &claim, &result)
        .await?;
    db.commit_assessment_evaluation(registry_id, &claim, &result)
        .await?;
    let scan = db
        .assessment_scan(registry_id, &first.scan_id)
        .await?
        .context("completed scan")?;
    assert_eq!(scan.state, ScanState::Partial);
    let status = db
        .assessment_status_page(registry_id, &request.profiles, "", 100)
        .await?;
    assert_eq!(status.subjects.len(), 1);
    for profile in &status.subjects[0].profiles {
        assert_eq!(profile.committed_generation, first.generation);
        assert!(!profile.fresh && !profile.pending);
    }
    let alerts = db.assessment_alert_page(registry_id, "", 100).await?;
    assert_eq!(alerts.len(), 2);
    assert_eq!(
        db.assessment_event_page(registry_id, 0, 100).await?.len(),
        3
    );
    let resource = db
        .assessment_resource(registry_id)
        .await?
        .context("resource")?;
    let acknowledged = db
        .acknowledge_assessment_alert(
            registry_id,
            resource.authorization_revision,
            alerts[0].sequence,
            Acknowledgement {
                idempotency_key: None,
                issue_key: alerts[0].issue_key,
                episode: alerts[0].episode,
                actor_ref: request.actor_ref.clone(),
                acknowledged_at: db.assessment_database_time().await?,
                reason: Some("PostgreSQL fixture review".into()),
            },
        )
        .await?;
    assert_eq!(acknowledged.state, AttentionState::Open);
    assert_eq!(acknowledged.acknowledgements.len(), 1);
    assert_eq!(
        db.assessment_event_page(registry_id, 0, 100).await?.len(),
        4
    );
    assert!(db
        .check_assessment_scan_claim(registry_id, &claim)
        .await
        .is_err());
    assert!(db
        .assessment_object(
            "different-partition",
            super::AssessmentObjectKind::Assessment,
            result.digest()?
        )
        .await?
        .is_none());
    // PostgreSQL binds every original claim parameter through the guarded
    // INSERT, and yielding never converts refusal into quota or result authority.
    request.idempotency_key = "postgres-resumable-refusal".into();
    let resumed_scan = db.request_assessment_scan(registry_id, &request).await?;
    let first_claim = db
        .claim_assessment_scan(registry_id, &resumed_scan.scan_id, 90)
        .await?;
    let question = aos_assessment_runtime::provider::ProviderOperation::ObserveTags {
        repository: "fixture/unavailable".into(),
        tag_prefix: "v".into(),
        page: 1,
    };
    db.refuse_assessment_provider_question_fenced(registry_id, &first_claim, &question, &[])
        .await?;
    db.pause_assessment_scan_fenced(registry_id, &first_claim, &[])
        .await?;
    let next_claim = db
        .claim_assessment_scan(registry_id, &resumed_scan.scan_id, 90)
        .await?;
    assert!(matches!(
        db.assessment_provider_replay(registry_id, &next_claim, &question, None)
            .await?,
        Some(super::AssessmentProviderReplay::Failed)
    ));
    assert!(db
        .check_assessment_scan_claim(registry_id, &first_claim)
        .await
        .is_err());
    assert_eq!(
        db.assessment_scan(registry_id, &resumed_scan.scan_id)
            .await?
            .unwrap()
            .usage
            .provider_requests,
        0
    );
    let base = db
        .assessment_evaluation_base(registry_id, &next_claim)
        .await?;
    let progress = super::acquisition_progress::tests::initial_checkpoint(&base, &request)?;
    db.save_assessment_acquisition_checkpoint_fenced(registry_id, &next_claim, &progress, &[])
        .await?;
    db.pause_assessment_scan_fenced(registry_id, &next_claim, &[])
        .await?;
    let continued = db
        .claim_assessment_scan(registry_id, &resumed_scan.scan_id, 90)
        .await?;
    assert_eq!(continued.attempt, next_claim.attempt);
    assert_eq!(
        db.assessment_acquisition_checkpoint(registry_id, &continued)
            .await?
            .unwrap()
            .digest()?,
        progress.digest()?
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn retained_scan_pages_and_concurrent_snapshot_limits_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    let (db, registry_id, request) = super::scans_tests::setup_database(db).await?;
    super::read_snapshot_tests::retained_pages(&db, registry_id, request).await?;

    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    let (db, registry_id, mut request) = super::scans_tests::setup_database(db).await?;
    super::read_snapshot_tests::storage_bounds(&db, registry_id, &mut request).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn retained_public_subscription_pages_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    let (db, registry, request, identity, fences) =
        super::notifications_tests::fixture_database(db).await?;
    super::subscription_snapshot::tests::retained_reviews(db, registry, request, identity, fences)
        .await?;

    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::subscription_snapshot::tests::storage_bounds(db).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn retained_attention_revisions_and_capture_capacity_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::alert_snapshot::tests::retained_episodes(db).await?;

    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::alert_snapshot::tests::storage_bounds(db).await?;

    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::alert_snapshot::tests::oversized_capture(db).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn retained_schedule_reviews_and_capture_capacity_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::schedule_snapshot::tests::retained_reviews(db).await?;

    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::schedule_snapshot::tests::storage_bounds(db).await?;

    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::schedule_snapshot::tests::oversized_capture(db).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn retained_delivery_attempts_and_capture_capacity_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::delivery_snapshot::tests::retained_attempts(db).await?;

    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::delivery_snapshot::tests::storage_bounds(db).await?;

    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::delivery_snapshot::tests::oversized_capture(db).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn reviewed_service_schedule_credential_revocation_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    super::schedules::service_tests::reviewed_service_scan_survives_reviewer_revocation_and_fences_service_revocation(db).await
}
