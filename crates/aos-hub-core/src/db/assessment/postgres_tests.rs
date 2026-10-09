//! Real PostgreSQL qualification of serving schema and assessment admission.

use anyhow::{Context as _, Result};
use aos_assessment::input::Profile;
use aos_assessment_runtime::alerts::{Acknowledgement, AttentionState};
use aos_assessment_runtime::scan::ScanState;

use crate::backend::SqlxBackend;
use crate::db::Database;

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn serving_inventory_scan_heads_alerts_acknowledgements_and_events_are_atomic_on_postgresql()
-> Result<()> {
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
    assert!(
        db.check_assessment_scan_claim(registry_id, &claim)
            .await
            .is_err()
    );
    assert!(
        db.assessment_object(
            "different-partition",
            super::AssessmentObjectKind::Assessment,
            result.digest()?
        )
        .await?
        .is_none()
    );
    Ok(())
}
