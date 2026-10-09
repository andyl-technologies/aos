//! Shared execution through the real database journal and current-authority fences.

use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{bail, Context as _, Result};
use aos_assessment::input::{FreshnessMode, Profile};
use aos_assessment_runtime::ports::{EvidenceStore, ProviderTransport};
use aos_assessment_runtime::provider::{
    CapabilityChallenge, ProviderCapabilitiesV1, ProviderOperation, ProviderWorkPlanV1,
    ProviderWorkResultV1,
};
use aos_assessment_runtime::scan::ScanState;
use aos_contract::Sha256Digest;

use crate::assessment_execution::{
    run_scan, AssessmentAuthority, AssessmentSourceRoute, AssessmentSourceRoutes,
};
use crate::db::{AssessmentScanRecord, Database};

use super::scans_tests::setup;

struct NoEffects;

#[async_trait::async_trait]
impl ProviderTransport for NoEffects {
    async fn capabilities(&self, _: &CapabilityChallenge) -> Result<ProviderCapabilitiesV1> {
        panic!("offline scan attempted provider capability acquisition")
    }

    async fn execute(&self, _: &ProviderWorkPlanV1) -> Result<ProviderWorkResultV1> {
        panic!("offline scan attempted provider work")
    }
}

#[async_trait::async_trait]
impl EvidenceStore for NoEffects {
    async fn retain(&self, _: &str, _: &[u8]) -> Result<Sha256Digest> {
        panic!("offline scan attempted raw source retention")
    }

    async fn read(&self, _: &str, _: Sha256Digest, _: u64) -> Result<Vec<u8>> {
        panic!("offline scan attempted raw source acquisition")
    }
}

#[async_trait::async_trait]
impl AssessmentSourceRoutes for NoEffects {
    async fn route(
        &self,
        _: &AssessmentScanRecord,
        _: &ProviderOperation,
    ) -> Result<AssessmentSourceRoute> {
        panic!("offline scan attempted source route resolution")
    }
}

struct Authority<'a> {
    db: &'a Database,
    calls: AtomicUsize,
    deny: bool,
    cancel_at: Option<usize>,
}

#[async_trait::async_trait]
impl AssessmentAuthority for Authority<'_> {
    async fn require_current(&self, scan: &AssessmentScanRecord) -> Result<()> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.deny {
            bail!("fixture principal revoked")
        }
        if self.cancel_at == Some(call) {
            let current = self
                .db
                .assessment_scan(scan.registry_id, &scan.scan_id)
                .await?
                .unwrap();
            self.db
                .cancel_assessment_scan(scan.registry_id, &scan.scan_id, current.resource_version)
                .await?;
        }
        Ok(())
    }
}

#[tokio::test]
async fn offline_execution_reproduces_shared_results_without_resolving_any_source_effect(
) -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    request.freshness = FreshnessMode::Offline;
    request.profiles = vec![Profile::Vulnerabilities];
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let authority = Authority {
        db: &db,
        calls: AtomicUsize::new(0),
        deny: false,
        cancel_at: None,
    };
    let result = run_scan(
        &db,
        registry_id,
        &scan.scan_id,
        &authority,
        &NoEffects,
        &NoEffects,
        &NoEffects,
    )
    .await?;
    let (input, data) = db
        .assessment_frozen_evaluation(registry_id, &scan.scan_id)
        .await?;
    assert_eq!(result, aos_assessment::evaluator::evaluate(&input, &data)?);
    assert_eq!(
        db.assessment_scan(registry_id, &scan.scan_id)
            .await?
            .unwrap()
            .state,
        ScanState::Partial
    );
    assert_eq!(authority.calls.load(Ordering::SeqCst), 3);
    assert!(
        !db.assessment_status_page(registry_id, &request.profiles, "", 1)
            .await?
            .subjects[0]
            .profiles[0]
            .fresh
    );
    Ok(())
}

#[tokio::test]
async fn revoked_authority_prevents_claim_and_preserves_queued_operation() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    request.freshness = FreshnessMode::Offline;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let authority = Authority {
        db: &db,
        calls: AtomicUsize::new(0),
        deny: true,
        cancel_at: None,
    };
    assert!(run_scan(
        &db,
        registry_id,
        &scan.scan_id,
        &authority,
        &NoEffects,
        &NoEffects,
        &NoEffects
    )
    .await
    .is_err());
    let retained = db
        .assessment_scan(registry_id, &scan.scan_id)
        .await?
        .unwrap();
    assert_eq!(retained.state, ScanState::Queued);
    assert_eq!(retained.attempt, 0);
    assert_eq!(retained.usage.provider_requests, 0);
    Ok(())
}

#[tokio::test]
async fn cancellation_after_evaluation_fences_every_result_and_attention_commit() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    request.freshness = FreshnessMode::Offline;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let authority = Authority {
        db: &db,
        calls: AtomicUsize::new(0),
        deny: false,
        cancel_at: Some(3),
    };
    assert!(run_scan(
        &db,
        registry_id,
        &scan.scan_id,
        &authority,
        &NoEffects,
        &NoEffects,
        &NoEffects
    )
    .await
    .is_err());
    let retained = db
        .assessment_scan(registry_id, &scan.scan_id)
        .await?
        .unwrap();
    assert_eq!(retained.state, ScanState::Cancelled);
    assert!(retained.assessment_digest.is_none());
    assert!(db
        .assessment_alert_page(registry_id, "", 100)
        .await?
        .is_empty());
    assert_eq!(
        db.assessment_status_page(registry_id, &request.profiles, "", 1)
            .await?
            .subjects[0]
            .profiles[0]
            .committed_generation,
        0
    );
    Ok(())
}

#[tokio::test]
async fn reclaimed_frozen_refresh_reuses_the_checkpoint_without_provider_effects() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    request.freshness = FreshnessMode::Refresh;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let first_claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 900)
        .await?;
    let data = db
        .assessment_evaluation_base(registry_id, &first_claim)
        .await?;
    let input = db
        .freeze_assessment_evaluation(registry_id, &first_claim, &data)
        .await?;
    let expected = aos_assessment::evaluator::evaluate(&input, &data)?;
    db.backend
        .execute(
            "UPDATE assessment_scans SET lease_expires_at = 1 WHERE scan_id = ?1",
            &vals![@slice scan.scan_id],
        )
        .await?;

    let authority = Authority {
        db: &db,
        calls: AtomicUsize::new(0),
        deny: false,
        cancel_at: None,
    };
    let result = run_scan(
        &db,
        registry_id,
        &scan.scan_id,
        &authority,
        &NoEffects,
        &NoEffects,
        &NoEffects,
    )
    .await?;
    assert_eq!(result, expected);
    assert_eq!(
        db.assessment_frozen_evaluation(registry_id, &scan.scan_id)
            .await?
            .0,
        input
    );
    let retained = db
        .assessment_scan(registry_id, &scan.scan_id)
        .await?
        .unwrap();
    assert_eq!(retained.attempt, 2);
    assert_eq!(retained.usage.provider_requests, 0);
    assert_eq!(retained.state, ScanState::Partial);
    Ok(())
}

struct InvalidResultTransport;

#[async_trait::async_trait]
impl ProviderTransport for InvalidResultTransport {
    async fn capabilities(
        &self,
        challenge: &CapabilityChallenge,
    ) -> Result<ProviderCapabilitiesV1> {
        Ok(ProviderCapabilitiesV1 {
            schema: "aos.provider-capabilities/v1".into(),
            challenge: challenge.clone(),
            executor_build: "fixture/v1".into(),
            adapters: vec![aos_assessment_providers::osv::ADAPTER_VERSION.into()],
            limits: Default::default(),
        })
    }

    async fn execute(&self, plan: &ProviderWorkPlanV1) -> Result<ProviderWorkResultV1> {
        let mut result = super::provider_state_tests::failure(plan)?;
        result.usage.requests = plan.budget_reservation.requests + 1;
        Ok(result)
    }
}

#[async_trait::async_trait]
impl AssessmentSourceRoutes for InvalidResultTransport {
    async fn route(
        &self,
        _: &AssessmentScanRecord,
        _: &ProviderOperation,
    ) -> Result<AssessmentSourceRoute> {
        Ok(AssessmentSourceRoute {
            deployment_id: "fixture-deployment".into(),
            issuer: "fixture-coordinator".into(),
            audience: "fixture-executor".into(),
            budget_key: "fixture-osv".into(),
            credential_ref: None,
            limits: Default::default(),
        })
    }
}

#[tokio::test]
async fn refused_provider_results_settle_the_attempt_and_preserve_partial_status_without_refund(
) -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    request.freshness = FreshnessMode::Refresh;
    request.profiles = vec![Profile::Vulnerabilities];
    db.install_assessment_source_budget(&crate::db::AssessmentSourceBudget {
        key: "fixture-osv".into(),
        window_seconds: 3600,
        allowance: 10,
        min_interval_seconds: 0,
    })
    .await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let authority = Authority {
        db: &db,
        calls: AtomicUsize::new(0),
        deny: false,
        cancel_at: None,
    };
    run_scan(
        &db,
        registry_id,
        &scan.scan_id,
        &authority,
        &InvalidResultTransport,
        &NoEffects,
        &InvalidResultTransport,
    )
    .await?;

    let retained = db
        .assessment_scan(registry_id, &scan.scan_id)
        .await?
        .context("retained scan")?;
    assert_eq!(retained.state, ScanState::Partial);
    assert_eq!(retained.usage.provider_requests, 1);
    let task = db
        .backend
        .query_opt(
            "SELECT state, last_error_code FROM assessment_tasks WHERE scan_id = ?1",
            &vals![@slice scan.scan_id],
        )
        .await?
        .context("settled provider task")?;
    assert_eq!(task.get::<String>(0)?, "failed");
    assert_eq!(task.get::<String>(1)?, "source-result-refused");
    let budget = db
        .backend
        .query_opt(
            "SELECT consumed FROM assessment_source_budgets WHERE budget_key = ?1",
            &vals![@slice "fixture-osv"],
        )
        .await?
        .context("consumed quota")?;
    assert_eq!(budget.get::<u32>(0)?, 1);
    assert!(
        !db.assessment_status_page(registry_id, &request.profiles, "", 1)
            .await?
            .subjects[0]
            .profiles[0]
            .fresh
    );
    Ok(())
}
