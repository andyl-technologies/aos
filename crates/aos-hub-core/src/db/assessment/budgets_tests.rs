//! Global quota races and conservative accounting across cancellation and rollover.

use anyhow::{Context as _, Result};
use aos_assessment_runtime::scan::ScanState;
use aos_contract::Sha256Digest;

use super::{AssessmentProviderWork, AssessmentSourceBudget};

fn work(
    task_id: &str,
    operation_digest: Sha256Digest,
    budget_key: &str,
    requests: u32,
) -> AssessmentProviderWork {
    AssessmentProviderWork {
        task_id: task_id.into(),
        operation_digest,
        budget_key: budget_key.into(),
        requests,
        deadline_seconds: 30,
    }
}

fn budget() -> AssessmentSourceBudget {
    AssessmentSourceBudget {
        key: "fixture/shared-provider".into(),
        window_seconds: 86400,
        allowance: 1,
        min_interval_seconds: 0,
    }
}

#[tokio::test]
async fn simultaneous_executors_cannot_multiply_shared_or_operation_allowance() -> Result<()> {
    let (db, registry_id, request) = super::scans_tests::setup().await?;
    db.install_assessment_source_budget(&budget()).await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 300)
        .await?;
    let operation = Sha256Digest::of_bytes("installed provider operation");
    let first_work = work("one", operation, &budget().key, 1);
    let second_work = work("two", operation, &budget().key, 1);
    let (one, two) = tokio::join!(
        db.reserve_assessment_provider_work(registry_id, &claim, &first_work),
        db.reserve_assessment_provider_work(registry_id, &claim, &second_work),
    );
    assert_ne!(one.is_ok(), two.is_ok());
    let reservation = one.or(two)?;
    db.check_assessment_provider_claim(registry_id, &reservation.claim)
        .await?;
    let consumed: u64 = db
        .backend
        .query_opt(
            "SELECT consumed FROM assessment_source_budgets WHERE budget_key = ?1",
            &vals![@slice budget().key],
        )
        .await?
        .context("quota row")?
        .get(0)?;
    assert_eq!(consumed, 1);
    let scan = db
        .assessment_scan(registry_id, &scan.scan_id)
        .await?
        .context("usage")?;
    assert_eq!(scan.usage.provider_requests, 1);
    assert_eq!(scan.usage.tasks, 1);
    let task_count: u64 = db
        .backend
        .query_opt("SELECT count(*) FROM assessment_tasks", &[])
        .await?
        .context("task count")?
        .get(0)?;
    assert_eq!(task_count, 1);
    Ok(())
}

#[tokio::test]
async fn cancellation_and_budget_reinstallation_never_refund_uncertain_requests() -> Result<()> {
    let (db, registry_id, mut request) = super::scans_tests::setup().await?;
    db.install_assessment_source_budget(&budget()).await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 300)
        .await?;
    let operation = Sha256Digest::of_bytes("installed provider operation");
    let child = db
        .reserve_assessment_provider_work(
            registry_id,
            &claim,
            &work("one", operation, &budget().key, 1),
        )
        .await?;
    let version = db
        .assessment_scan(registry_id, &scan.scan_id)
        .await?
        .context("running operation")?
        .resource_version;
    db.cancel_assessment_scan(registry_id, &scan.scan_id, version)
        .await?;
    assert_eq!(
        db.assessment_scan(registry_id, &scan.scan_id)
            .await?
            .context("draining scan")?
            .state,
        ScanState::Cancelling
    );
    db.settle_assessment_scan_cancellation(registry_id, &scan.scan_id)
        .await?;
    assert_eq!(
        db.assessment_scan(registry_id, &scan.scan_id)
            .await?
            .context("live physical attempt")?
            .state,
        ScanState::Cancelling
    );
    assert!(
        db.check_assessment_provider_claim(registry_id, &child.claim)
            .await
            .is_err()
    );
    let expired = db.assessment_database_time().await?.unix_seconds() - 1;
    db.backend.execute("UPDATE assessment_budget_reservations SET created_at = ?2, deadline = ?3 WHERE reservation_id = ?1",
        &vals![@slice child.budget.reservation_id, expired - 1, expired]).await?;
    db.settle_assessment_scan_cancellation(registry_id, &scan.scan_id)
        .await?;
    assert_eq!(
        db.assessment_scan(registry_id, &scan.scan_id)
            .await?
            .context("settled scan")?
            .state,
        ScanState::Cancelled
    );
    db.install_assessment_source_budget(&budget()).await?;
    request.idempotency_key = "after-cancellation".into();
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 300)
        .await?;
    assert!(
        db.reserve_assessment_provider_work(
            registry_id,
            &claim,
            &work("two", operation, &budget().key, 1)
        )
        .await
        .is_err()
    );
    assert_eq!(
        db.assessment_scan(registry_id, &scan.scan_id)
            .await?
            .context("new operation usage")?
            .usage
            .provider_requests,
        0
    );
    Ok(())
}

#[tokio::test]
async fn window_rollover_resets_only_elapsed_allowance_and_spaced_budgets_require_single_requests()
-> Result<()> {
    let (db, registry_id, request) = super::scans_tests::setup().await?;
    let mut spaced = budget();
    spaced.min_interval_seconds = 1;
    db.install_assessment_source_budget(&spaced).await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 300)
        .await?;
    let operation = Sha256Digest::of_bytes("installed provider operation");
    assert!(
        db.reserve_assessment_provider_work(
            registry_id,
            &claim,
            &work("too-many", operation, &spaced.key, 2)
        )
        .await
        .is_err()
    );
    let now = db.assessment_database_time().await?.unix_seconds();
    let previous = now / 86400 * 86400 - 86400;
    db.backend.execute("UPDATE assessment_source_budgets SET consumed = allowance, window_start = ?2 WHERE budget_key = ?1",
        &vals![@slice spaced.key, previous]).await?;
    db.reserve_assessment_provider_work(
        registry_id,
        &claim,
        &work("rollover", operation, &spaced.key, 1),
    )
    .await?;
    let row = db
        .backend
        .query_opt(
            "SELECT window_start, consumed FROM assessment_source_budgets WHERE budget_key = ?1",
            &vals![@slice spaced.key],
        )
        .await?
        .context("rolled quota")?;
    assert_eq!(row.get::<u64>(0)?, now / 86400 * 86400);
    assert_eq!(row.get::<u64>(1)?, 1);
    Ok(())
}
