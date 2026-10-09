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
    async fn commit_current(
        &self,
        db: &Database,
        scan: &AssessmentScanRecord,
        claim: &aos_assessment_runtime::scan::TaskClaim,
        assessment: &aos_assessment::result::PackageAssessmentV1,
    ) -> Result<()> {
        db.commit_assessment_evaluation(scan.registry_id, claim, assessment)
            .await
    }

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

struct RevocationAtCommit<'a> {
    db: &'a Database,
    claims: crate::auth::jwt::Claims,
    mutation: &'static str,
}

#[async_trait::async_trait]
impl AssessmentAuthority for RevocationAtCommit<'_> {
    async fn require_current(&self, _: &AssessmentScanRecord) -> Result<()> {
        anyhow::ensure!(
            self.db
                .current_authenticated_actor(&self.claims)
                .await?
                .is_some(),
            "fixture actor is absent"
        );
        Ok(())
    }

    async fn commit_current(
        &self,
        db: &Database,
        scan: &AssessmentScanRecord,
        claim: &aos_assessment_runtime::scan::TaskClaim,
        assessment: &aos_assessment::result::PackageAssessmentV1,
    ) -> Result<()> {
        // The existing read grant exercises the general transactional IAM
        // primitive. This fixture does not install assessment role permissions.
        let now = db.assessment_database_time().await?.unix_seconds() as i64;
        let fences = db
            .direct_iam_statements(
                &self.claims,
                &scan.request.resource_scope,
                crate::domain::Permission::Read,
                now,
            )
            .await?;
        match self.mutation {
            "membership" => {
                db.backend.execute("DELETE FROM memberships WHERE principal_kind = 'user' AND principal_id = ?1", &vals![@slice self.claims.owner_id]).await?;
            }
            "credential" => {
                db.backend
                    .execute(
                        "UPDATE tokens SET revoked_at = ?2 WHERE id = ?1",
                        &vals![@slice self.claims.sub, now],
                    )
                    .await?;
            }
            "incarnation" => {
                db.backend
                    .execute(
                        "UPDATE users SET principal_incarnation = ?2 WHERE id = ?1",
                        &vals![@slice self.claims.owner_id, uuid::Uuid::new_v4().to_string()],
                    )
                    .await?;
            }
            _ => bail!("unsupported revocation fixture"),
        }
        db.commit_assessment_evaluation_fenced(scan.registry_id, claim, assessment, fences)
            .await
    }
}

#[tokio::test]
async fn final_iam_revocation_rolls_back_scan_heads_alerts_and_events_together() -> Result<()> {
    use crate::auth::jwt::{Claims, AUTHORIZATION_CLAIMS_VERSION};
    use crate::domain::{Permission, Principal};

    for mutation in ["membership", "credential", "incarnation"] {
        let (db, registry_id, mut request) = setup().await?;
        request.profiles = vec![Profile::Vulnerabilities];
        let user = db
            .create_user("assessment-fence@fixture.invalid", None)
            .await?;
        db.grant_membership("user", user, "instance", "owner")
            .await?;
        let (token, _) = db
            .create_token(
                Principal::user(user),
                "instance",
                &[Permission::Read],
                None,
                None,
            )
            .await?;
        let now = db.assessment_database_time().await?.unix_seconds() as i64;
        let claims = Claims {
            sub: token,
            owner_kind: "user".into(),
            owner_id: user,
            owner_incarnation: db.principal_incarnation(Principal::user(user)).await?,
            browser_session_id_hash: None,
            scope: "instance".into(),
            perms: vec![Permission::Read.as_str().into()],
            authz_version: AUTHORIZATION_CLAIMS_VERSION.into(),
            iat: now,
            exp: now + 900,
        };
        let scan = db.request_assessment_scan(registry_id, &request).await?;
        let authority = RevocationAtCommit {
            db: &db,
            claims,
            mutation,
        };

        assert!(
            run_scan(
                &db,
                registry_id,
                &scan.scan_id,
                &authority,
                &NoEffects,
                &NoEffects,
                &NoEffects
            )
            .await
            .is_err(),
            "{mutation}"
        );
        let completed = db
            .assessment_scan(registry_id, &scan.scan_id)
            .await?
            .context("uncommitted scan")?;
        assert_eq!(completed.state, ScanState::Running, "{mutation}");
        assert!(completed.assessment_digest.is_none(), "{mutation}");
        let status = db
            .assessment_status_page(registry_id, &request.profiles, "", 100)
            .await?;
        assert_eq!(
            status.subjects[0].profiles[0].committed_generation, 0,
            "{mutation}"
        );
        assert!(
            db.assessment_alert_page(registry_id, "", 100)
                .await?
                .is_empty(),
            "{mutation}"
        );
        assert!(
            db.assessment_event_page(registry_id, 0, 100)
                .await?
                .is_empty(),
            "{mutation}"
        );
        let (input, data) = db
            .assessment_frozen_evaluation(registry_id, &scan.scan_id)
            .await?;
        let digest = aos_assessment::evaluator::evaluate(&input, &data)?.digest()?;
        assert!(
            !db.has_admitted_assessment(registry_id, digest).await?,
            "{mutation}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn cached_and_offline_scans_reuse_committed_observations_without_provider_effects(
) -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    let first = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &first.scan_id, 900)
        .await?;
    let mut data = db.assessment_evaluation_base(registry_id, &claim).await?;
    let observed_at = db.assessment_database_time().await?;
    let candidate = aos_assessment::discovery::ObservationCandidate {
        raw_id: "v1.3.0".into(),
        raw_version: "1.3.0".into(),
        published_at_unix: Some(1_700_000_000),
        first_observed_at_unix: observed_at.unix_seconds(),
        prerelease: false,
        yanked: false,
        release_url: None,
        status: None,
        vulnerable: None,
        licenses: vec![],
    };
    data.history.push(aos_assessment::input::CandidateHistory {
        provider: "github-releases".into(),
        project: "example/fixture".into(),
        raw_id: candidate.raw_id.clone(),
        first_observed_at: observed_at.clone(),
    });
    data.upstream.push(aos_assessment::input::UpstreamBinding {
        component_ref: "component".into(),
        response_byte_length: 2,
        source_refs: vec![],
        observation: aos_assessment::discovery::UpstreamObservationV1 {
            schema: aos_assessment::UPSTREAM_OBSERVATION_V1.into(),
            provider: "github-releases".into(),
            project: "example/fixture".into(),
            retrieved_at_unix: observed_at.unix_seconds(),
            request_url: "https://api.github.com/repos/example/fixture/releases".into(),
            adapter_version: "fixture/v1".into(),
            coverage: aos_assessment::discovery::ObservationCoverage::Complete,
            response_digest: Sha256Digest::of_bytes("[]"),
            candidates: vec![candidate],
        },
    });
    let input = db
        .freeze_assessment_evaluation(registry_id, &claim, &data)
        .await?;
    let assessment = aos_assessment::evaluator::evaluate(&input, &data)?;
    db.commit_assessment_evaluation(registry_id, &claim, &assessment)
        .await?;

    for (key, freshness) in [
        ("cached", FreshnessMode::Cached),
        ("offline", FreshnessMode::Offline),
    ] {
        request.idempotency_key = key.into();
        request.freshness = freshness;
        let next = db.request_assessment_scan(registry_id, &request).await?;
        let authority = Authority {
            db: &db,
            calls: AtomicUsize::new(0),
            deny: false,
            cancel_at: None,
        };
        let result = run_scan(
            &db,
            registry_id,
            &next.scan_id,
            &authority,
            &NoEffects,
            &NoEffects,
            &NoEffects,
        )
        .await?;
        let (_, reused) = db
            .assessment_frozen_evaluation(registry_id, &next.scan_id)
            .await?;
        assert_eq!(reused.upstream, data.upstream);
        assert_eq!(reused.history, data.history);
        assert_eq!(result.subject_results, assessment.subject_results);
        let completed = db
            .assessment_scan(registry_id, &next.scan_id)
            .await?
            .context("cached scan")?;
        assert_eq!(completed.state, ScanState::Succeeded);
        assert_eq!(completed.usage.provider_requests, 0);
    }
    Ok(())
}

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
