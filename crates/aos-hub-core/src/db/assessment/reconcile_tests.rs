//! Recovery preserves committed heads while settling obsolete execution state.

use anyhow::{Context as _, Result};
use aos_assessment_runtime::scan::ScanState;

use super::scans_tests::setup;

#[tokio::test]
async fn supersession_settles_old_work_without_publishing_or_rewriting_new_work() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    let old = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &old.scan_id, 30)
        .await?;
    request.idempotency_key = "replacement".into();
    let next = db.request_assessment_scan(registry_id, &request).await?;

    db.reconcile_assessment_scans(registry_id, "", 100).await?;
    let settled = db
        .assessment_scan(registry_id, &old.scan_id)
        .await?
        .context("old scan")?;
    assert_eq!(settled.state, ScanState::Superseded);
    assert_eq!(
        settled.failure_code.as_deref(),
        Some("scan-scope-superseded")
    );
    assert!(settled.assessment_digest.is_none());
    assert!(db
        .check_assessment_scan_claim(registry_id, &claim)
        .await
        .is_err());
    assert_eq!(
        db.assessment_scan(registry_id, &next.scan_id)
            .await?
            .context("new scan")?
            .state,
        ScanState::Queued
    );

    db.reconcile_assessment_scans(registry_id, "", 100).await?;
    assert_eq!(
        db.assessment_scan(registry_id, &old.scan_id)
            .await?
            .context("settled scan")?
            .resource_version,
        settled.resource_version
    );
    db.claim_assessment_scan(registry_id, &next.scan_id, 30)
        .await?;
    Ok(())
}

#[tokio::test]
async fn wall_time_and_attempt_exhaustion_are_terminal_without_reclaiming_work() -> Result<()> {
    for wall_time in [true, false] {
        let (db, registry_id, request) = setup().await?;
        let scan = db.request_assessment_scan(registry_id, &request).await?;
        let expired = db.assessment_database_time().await?.unix_seconds() - 1;
        let created = expired - u64::from(request.limits.wall_seconds);
        if wall_time {
            db.backend
                .execute(
                    "UPDATE assessment_scans SET created_at = ?2 WHERE scan_id = ?1",
                    &vals![@slice scan.scan_id, created],
                )
                .await?;
        } else {
            db.backend.execute("UPDATE assessment_scans SET attempt = 100, lease_expires_at = ?2 WHERE scan_id = ?1", &vals![@slice scan.scan_id, expired]).await?;
        }

        db.reconcile_assessment_scans(registry_id, "", 1).await?;
        let settled = db
            .assessment_scan(registry_id, &scan.scan_id)
            .await?
            .context("settled scan")?;
        assert_eq!(settled.state, ScanState::Failed);
        assert_eq!(
            settled.failure_code.as_deref(),
            Some(if wall_time {
                "operation-wall-time-exhausted"
            } else {
                "operation-attempts-exhausted"
            })
        );
        assert!(settled.assessment_digest.is_none());
        assert!(db
            .claim_assessment_scan(registry_id, &scan.scan_id, 30)
            .await
            .is_err());
    }
    Ok(())
}

#[tokio::test]
async fn recovery_rejects_unbounded_pages_and_exposes_a_stable_continuation() -> Result<()> {
    let (db, registry_id, request) = setup().await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    assert!(db
        .reconcile_assessment_scans(registry_id, "", 0)
        .await
        .is_err());
    assert!(db
        .reconcile_assessment_scans(registry_id, "", 101)
        .await
        .is_err());
    assert!(db
        .reconcile_assessment_scans(registry_id, "\n", 1)
        .await
        .is_err());
    assert_eq!(
        db.reconcile_assessment_scans(registry_id, "", 1).await?,
        Some(scan.scan_id.clone())
    );
    assert_eq!(
        db.reconcile_assessment_scans(registry_id, &scan.scan_id, 1)
            .await?,
        None
    );
    assert_eq!(
        db.reconcile_assessment_scans(registry_id + 1, "", 1)
            .await?,
        None
    );
    Ok(())
}
