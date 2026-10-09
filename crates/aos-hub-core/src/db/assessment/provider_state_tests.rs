//! Durable provider authority, reservation binding and late-result rejection.

use anyhow::{Context as _, Result};
use aos_assessment::observation::ProviderCoverage;
use aos_assessment_runtime::provider::{
    PROVIDER_WORK_PLAN_V1, PROVIDER_WORK_RESULT_V1, ProviderLimits, ProviderOperation,
    ProviderUsage, ProviderWorkPlanV1, ProviderWorkResultV1, WorkOutcome,
};
use aos_contract::Sha256Digest;

use super::scans_tests::setup;
use super::{AssessmentProviderWork, AssessmentSourceBudget};
use crate::db::Database;

async fn planned() -> Result<(Database, i64, ProviderWorkPlanV1)> {
    planned_operation(ProviderOperation::ObserveReleases {
        repository: "example/fixture".into(),
        tag_prefix: "v".into(),
        page: 1,
    })
    .await
}

async fn planned_operation(
    operation: ProviderOperation,
) -> Result<(Database, i64, ProviderWorkPlanV1)> {
    let (db, registry_id, request) = setup().await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let coordinator = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 90)
        .await?;
    let budget = AssessmentSourceBudget {
        key: "installed-github-account".into(),
        window_seconds: 3600,
        allowance: 10,
        min_interval_seconds: 0,
    };
    db.install_assessment_source_budget(&budget).await?;
    let reservation = db
        .reserve_assessment_provider_work(
            registry_id,
            &coordinator,
            &AssessmentProviderWork {
                task_id: "github-page-1".into(),
                operation_digest: operation.digest()?,
                budget_key: budget.key,
                requests: 1,
                deadline_seconds: 60,
            },
        )
        .await?;
    let now = db.assessment_database_time().await?;
    let plan = ProviderWorkPlanV1 {
        schema: PROVIDER_WORK_PLAN_V1.into(),
        deployment_id: "fixture-deployment".into(),
        issuer: "fixture-coordinator".into(),
        audience: "fixture-executor".into(),
        plan_id: uuid::Uuid::new_v4().simple().to_string(),
        claim: reservation.claim,
        issued_at: now,
        expires_at: reservation.budget.deadline.clone(),
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        inventory_digest: request.inventory_digest,
        policy_digest: request.policy_digest,
        authorization_partition: request.authorization_partition,
        credential_ref: None,
        budget_reservation: reservation.budget,
        cache_ref: None,
        continuation: None,
        adapter_version: operation.adapter_version().into(),
        operation,
        limits: ProviderLimits {
            requests: 1,
            concurrency: 1,
            ..Default::default()
        },
    };
    Ok((db, registry_id, plan))
}

#[tokio::test]
async fn admitted_advisory_queries_publish_exact_indexes_without_related_id_equivalence()
-> Result<()> {
    use aos_assessment::observation::{
        PROVIDER_OBSERVATION_V1, ProviderObservationV1, SourceEvidenceRef,
    };
    use aos_assessment_runtime::provider::{NormalizedObject, ObjectProjection};
    let (db, registry_id, plan) = planned_operation(ProviderOperation::RetrieveAdvisories {
        project: "fixture-query".into(),
        ids: vec!["OSV-2026-1".into()],
    })
    .await?;
    db.admit_assessment_provider_plan(registry_id, &plan)
        .await?;
    let raw = br#"{"schema_version":"1.9.1","id":"OSV-2026-1","modified":"2026-10-09T12:00:00Z",
        "aliases":["CVE-2026-12345"],"related":["CVE-2026-98765"],"summary":"Fixture",
        "affected":[{"package":{"ecosystem":"crates.io","name":"fixture"},"versions":["1.2.0"]}]}"#;
    let record = aos_assessment_providers::osv::record(raw)?;
    let observation = ProviderObservationV1 {
        schema: PROVIDER_OBSERVATION_V1.into(),
        provider: "osv".into(),
        project: "fixture-query".into(),
        adapter_version: plan.adapter_version.clone(),
        request_identity_digest: plan.operation.digest()?,
        retrieved_at: plan.issued_at.clone(),
        validated_at: plan.issued_at.clone(),
        expires_at: aos_assessment::time::Timestamp::from_unix_seconds(
            plan.issued_at.unix_seconds() + 86400,
        )?,
        response_digest: Sha256Digest::of_bytes(raw),
        payload_digest: Sha256Digest::of_canonical(
            "aos.advisory-record-set/v1",
            &vec![record.digest()?],
        )?,
        validators: None,
        coverage: ProviderCoverage::Complete {
            proof: "requested-records-retained".into(),
        },
        source_refs: vec![SourceEvidenceRef {
            digest: Sha256Digest::of_bytes(raw),
            byte_length: raw.len() as u64,
            origin: "osv".into(),
        }],
    };
    let mut result = failure(&plan)?;
    result.outcome = WorkOutcome::Observed;
    result.coverage = observation.coverage.clone();
    result.diagnostics.clear();
    result.observation_refs = vec![observation.digest()?];
    result.normalized_objects = vec![
        ObjectProjection {
            digest: record.digest()?,
            object: NormalizedObject::Advisory(record.clone()),
        },
        ObjectProjection {
            digest: observation.digest()?,
            object: NormalizedObject::Observation(observation.clone()),
        },
    ];
    result
        .normalized_objects
        .sort_by_key(|projection| projection.digest);
    db.admit_assessment_provider_result(registry_id, &plan, &result)
        .await?;
    db.admit_assessment_provider_result(registry_id, &plan, &result)
        .await?;
    assert_eq!(
        db.assessment_advisory_revision_page(
            &plan.authorization_partition,
            "CVE-2026-12345",
            "",
            10,
        )
        .await?,
        vec![record.clone()]
    );
    assert!(
        db.assessment_advisory_revision_page(
            &plan.authorization_partition,
            "CVE-2026-98765",
            "",
            10,
        )
        .await?
        .is_empty()
    );
    assert!(
        db.assessment_advisory_revision_page("other-tenant", &record.id, "", 10)
            .await?
            .is_empty()
    );
    assert_eq!(
        db.assessment_observation_page(
            &plan.authorization_partition,
            "osv",
            "fixture-query",
            "",
            10,
        )
        .await?,
        vec![(plan.operation.digest()?, observation)]
    );
    assert!(
        db.assessment_observation_page(
            &plan.authorization_partition,
            "osv",
            "unrelated-query",
            "",
            10,
        )
        .await?
        .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn candidate_first_observation_uses_admitted_retrieval_and_replay_does_not_reset_it()
-> Result<()> {
    use aos_assessment::discovery::{ObservationCoverage, UpstreamObservationV1};
    use aos_assessment_runtime::provider::{NormalizedObject, ObjectProjection};
    let (db, registry_id, plan) = planned().await?;
    db.admit_assessment_provider_plan(registry_id, &plan)
        .await?;
    let raw = br#"[{"tag_name":"v1.3.0","published_at":"2020-01-01T00:00:00Z"}]"#;
    let observation = UpstreamObservationV1 {
        schema: aos_assessment::UPSTREAM_OBSERVATION_V1.into(),
        provider: "github-releases".into(),
        project: "example/fixture".into(),
        retrieved_at_unix: plan.issued_at.unix_seconds(),
        request_url: "https://api.github.com/repos/example/fixture/releases".into(),
        adapter_version: plan.adapter_version.clone(),
        coverage: ObservationCoverage::Complete,
        response_digest: Sha256Digest::of_bytes(raw),
        candidates: aos_assessment_providers::upstream::github_releases(
            raw,
            "v",
            plan.issued_at.unix_seconds(),
        )?,
    };
    let object = NormalizedObject::Upstream(observation);
    let mut result = failure(&plan)?;
    result.outcome = WorkOutcome::Observed;
    result.coverage = ProviderCoverage::Complete {
        proof: "pagination-exhausted".into(),
    };
    result.diagnostics.clear();
    result.observation_refs = vec![object.digest()?];
    result.normalized_objects = vec![ObjectProjection {
        digest: object.digest()?,
        object,
    }];
    db.admit_assessment_provider_result(registry_id, &plan, &result)
        .await?;
    let ids = vec!["v1.3.0".into()];
    let first = db
        .assessment_candidate_history(
            &plan.authorization_partition,
            "github-releases",
            "example/fixture",
            &ids,
        )
        .await?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].first_observed_at, plan.issued_at);
    db.admit_assessment_provider_result(registry_id, &plan, &result)
        .await?;
    assert_eq!(
        db.assessment_candidate_history(
            &plan.authorization_partition,
            "github-releases",
            "example/fixture",
            &ids,
        )
        .await?,
        first
    );
    assert!(
        db.assessment_candidate_history(
            &plan.authorization_partition,
            "github-tags",
            "example/fixture",
            &ids,
        )
        .await?
        .is_empty()
    );
    Ok(())
}

fn failure(plan: &ProviderWorkPlanV1) -> Result<ProviderWorkResultV1> {
    Ok(ProviderWorkResultV1 {
        schema: PROVIDER_WORK_RESULT_V1.into(),
        plan_digest: plan.digest()?,
        claim: plan.claim.clone(),
        executor_build: "fixture-executor-v1".into(),
        adapter_version: plan.adapter_version.clone(),
        outcome: WorkOutcome::Failed,
        normalized_objects: vec![],
        observation_refs: vec![],
        coverage: ProviderCoverage::Unknown {
            reason: "provider-unavailable".into(),
        },
        continuation: None,
        usage: ProviderUsage {
            requests: 1,
            ..Default::default()
        },
        completed_at: plan.issued_at.clone(),
        diagnostics: vec!["provider-unavailable".into()],
    })
}

#[tokio::test]
async fn plans_cannot_replace_an_operation_reservation_or_issued_identity() -> Result<()> {
    let (db, registry_id, plan) = planned().await?;
    let mut changed = plan.clone();
    changed.budget_reservation.source_budget = "different-account".into();
    assert!(
        db.admit_assessment_provider_plan(registry_id, &changed)
            .await
            .is_err()
    );
    changed = plan.clone();
    changed.inventory_digest = Sha256Digest::of_bytes("different inventory");
    assert!(
        db.admit_assessment_provider_plan(registry_id, &changed)
            .await
            .is_err()
    );
    db.admit_assessment_provider_plan(registry_id, &plan)
        .await?;
    db.admit_assessment_provider_plan(registry_id, &plan)
        .await?;
    changed = plan.clone();
    changed.nonce = uuid::Uuid::new_v4().simple().to_string();
    assert!(
        db.admit_assessment_provider_plan(registry_id, &changed)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn source_failure_is_durable_without_refunding_or_asserting_completeness() -> Result<()> {
    let (db, registry_id, plan) = planned().await?;
    db.admit_assessment_provider_plan(registry_id, &plan)
        .await?;
    let failure = failure(&plan)?;
    db.admit_assessment_provider_result(registry_id, &plan, &failure)
        .await?;
    db.admit_assessment_provider_result(registry_id, &plan, &failure)
        .await?;
    let task = db.backend.query_opt(
        "SELECT state, result_digest, result_json FROM assessment_tasks WHERE scan_id = ?1 AND task_id = ?2",
        &vals![@slice plan.claim.scan_id, plan.claim.task_id],
    ).await?.context("failed provider task")?;
    assert_eq!(task.get::<String>(0)?, "failed");
    assert!(task.get::<Option<String>>(1)?.is_some());
    let result: ProviderWorkResultV1 = serde_json::from_slice(&task.get::<Vec<u8>>(2)?)?;
    assert!(!result.coverage.is_complete());
    let quota = db
        .backend
        .query_opt(
            "SELECT consumed FROM assessment_source_budgets WHERE budget_key = ?1",
            &vals![@slice plan.budget_reservation.source_budget],
        )
        .await?
        .context("consumed source quota")?;
    assert_eq!(quota.get::<u32>(0)?, 1);
    assert!(
        db.check_assessment_provider_claim(registry_id, &plan.claim)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_operations_reject_results_without_changing_usage_or_task_receipts() -> Result<()>
{
    let (db, registry_id, plan) = planned().await?;
    db.admit_assessment_provider_plan(registry_id, &plan)
        .await?;
    let scan = db
        .assessment_scan(registry_id, &plan.claim.scan_id)
        .await?
        .context("scan")?;
    db.cancel_assessment_scan(registry_id, &plan.claim.scan_id, scan.resource_version)
        .await?;
    assert!(
        db.admit_assessment_provider_result(registry_id, &plan, &failure(&plan)?)
            .await
            .is_err()
    );
    let task = db
        .backend
        .query_opt(
            "SELECT result_digest FROM assessment_tasks WHERE scan_id = ?1 AND task_id = ?2",
            &vals![@slice plan.claim.scan_id, plan.claim.task_id],
        )
        .await?
        .context("cancelled task")?;
    assert_eq!(task.get::<Option<String>>(0)?, None);
    assert_eq!(
        db.assessment_scan(registry_id, &plan.claim.scan_id)
            .await?
            .context("scan")?
            .usage
            .normalized_bytes,
        scan.usage.normalized_bytes
    );
    Ok(())
}
