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

pub(super) async fn planned() -> Result<(Database, i64, ProviderWorkPlanV1)> {
    planned_operation(ProviderOperation::ObserveReleases {
        repository: "example/fixture".into(),
        tag_prefix: "v".into(),
        page: 1,
    })
    .await
}

#[tokio::test]
async fn failed_physical_attempt_settles_without_refunding_and_allows_incomplete_evaluation(
) -> Result<()> {
    let (db, registry_id, plan) = planned().await?;
    db.admit_assessment_provider_plan(registry_id, &plan)
        .await?;
    db.fail_assessment_provider_work(registry_id, &plan.claim, "source-transport-failed")
        .await?;

    assert!(db
        .check_assessment_provider_claim(registry_id, &plan.claim)
        .await
        .is_err());
    assert!(db
        .fail_assessment_provider_work(registry_id, &plan.claim, "source-transport-failed")
        .await
        .is_err());
    let scan = db
        .assessment_scan(registry_id, &plan.claim.scan_id)
        .await?
        .context("scan")?;
    assert_eq!(scan.usage.provider_requests, 1);
    assert_eq!(scan.usage.tasks, 1);

    let mut coordinator = plan.claim.clone();
    coordinator.task_id = "coordinator".into();
    let data = db
        .assessment_evaluation_base(registry_id, &coordinator)
        .await?;
    let input = db
        .freeze_assessment_evaluation(registry_id, &coordinator, &data)
        .await?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    assert!(result
        .subject_results
        .iter()
        .flat_map(|subject| &subject.coverage)
        .any(|coverage| coverage.state != aos_assessment::security::CoverageState::Complete));
    db.commit_assessment_evaluation(registry_id, &coordinator, &result)
        .await?;
    Ok(())
}

async fn planned_operation(
    operation: ProviderOperation,
) -> Result<(Database, i64, ProviderWorkPlanV1)> {
    planned_database(Database::open_in_memory().await?, operation).await
}

pub(super) async fn planned_database(
    db: Database,
    operation: ProviderOperation,
) -> Result<(Database, i64, ProviderWorkPlanV1)> {
    let (db, registry_id, request) = super::scans_tests::setup_database(db).await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let coordinator = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 90)
        .await?;
    let budget = AssessmentSourceBudget {
        key: format!("installed-github-account/{}", request.resource_scope),
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
        continuation_ref: None,
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
    let cooldown = db.assessment_database_time().await?.unix_seconds() + 300;
    db.backend.execute("UPDATE assessment_source_budgets SET failure_count = 5, circuit_until = ?2, next_eligible_at = ?2 WHERE budget_key = ?1",
        &vals![@slice plan.budget_reservation.source_budget, cooldown]).await?;
    db.admit_assessment_provider_result(registry_id, &plan, &result)
        .await?;
    db.admit_assessment_provider_result(registry_id, &plan, &result)
        .await?;
    let health = db.backend.query_opt("SELECT failure_count, circuit_until, next_eligible_at, consumed FROM assessment_source_budgets WHERE budget_key = ?1",
        &vals![@slice plan.budget_reservation.source_budget]).await?.context("provider health")?;
    assert_eq!(health.get::<u32>(0)?, 0);
    assert_eq!(health.get::<u64>(1)?, cooldown);
    assert_eq!(health.get::<u64>(2)?, cooldown);
    assert_eq!(health.get::<u64>(3)?, 1);
    let query = aos_assessment_runtime::advisories::AdvisoryQueryV1 {
        schema: "aos.assessment-advisory-query/v1".into(),
        advisory_id: "CVE-2026-12345".into(),
        resource_scope: Some(plan.authorization_partition.clone()),
        assessment_digest: None,
        subject_ref: None,
        after_record: None,
        limit: 1,
    };
    let usage_before = db
        .assessment_scan(registry_id, &plan.claim.scan_id)
        .await?
        .context("scan")?
        .usage;
    let page = db
        .assessment_advisory_page(registry_id, &query)
        .await?
        .context("advisory page")?;
    page.validate_for(&query)?;
    assert_eq!(page.revisions.len(), 1);
    assert_eq!(page.revisions[0].record, record);
    assert!(page.assessment_context.is_none());
    assert!(page.revisions[0].finding_links.is_empty());
    assert_eq!(
        db.assessment_scan(registry_id, &plan.claim.scan_id)
            .await?
            .context("scan")?
            .usage,
        usage_before
    );
    let mut after = query.clone();
    after.after_record = Some(record.digest()?);
    assert!(db
        .assessment_advisory_page(registry_id, &after)
        .await?
        .context("continued page")?
        .revisions
        .is_empty());
    let mut related = query.clone();
    related.advisory_id = "CVE-2026-98765".into();
    assert!(db
        .assessment_advisory_page(registry_id, &related)
        .await?
        .context("related query")?
        .revisions
        .is_empty());
    let foreign_registry = db
        .register_registry("foreign-advisory-read", &[], false)
        .await?;
    assert!(db
        .assessment_advisory_page(foreign_registry, &query)
        .await?
        .is_none());
    let mut foreign = query.clone();
    foreign.resource_scope = None;
    assert!(db
        .assessment_advisory_page(foreign_registry, &foreign)
        .await?
        .context("foreign page")?
        .revisions
        .is_empty());
    let mut unadmitted = query.clone();
    unadmitted.assessment_digest = Some(Sha256Digest::of_bytes("unadmitted assessment"));
    assert!(db
        .assessment_advisory_page(registry_id, &unadmitted)
        .await?
        .is_none());
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

pub(super) fn failure(plan: &ProviderWorkPlanV1) -> Result<ProviderWorkResultV1> {
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

#[tokio::test]
async fn yielding_reclaims_one_scan_and_replays_settled_questions_without_new_quota() -> Result<()>
{
    use super::AssessmentProviderReplay;
    let (db, registry_id, plan) = planned().await?;
    db.admit_assessment_provider_plan(registry_id, &plan)
        .await?;
    let mut coordinator = plan.claim.clone();
    coordinator.task_id = "coordinator".into();

    // An in-flight physical effect cannot be abandoned by a cooperative yield.
    assert!(
        db.pause_assessment_scan_fenced(registry_id, &coordinator, &[])
            .await
            .is_err()
    );
    let result = failure(&plan)?;
    db.admit_assessment_provider_result(registry_id, &plan, &result)
        .await?;
    let usage = db
        .assessment_scan(registry_id, &plan.claim.scan_id)
        .await?
        .unwrap()
        .usage;
    db.pause_assessment_scan_fenced(registry_id, &coordinator, &[])
        .await?;
    assert!(
        db.check_assessment_scan_claim(registry_id, &coordinator)
            .await
            .is_err()
    );
    assert!(
        db.assessment_evaluation_checkpoint(registry_id, &coordinator)
            .await
            .is_err()
    );

    let resumed = db
        .claim_assessment_scan(registry_id, &plan.claim.scan_id, 90)
        .await?;
    assert_eq!(resumed.attempt, coordinator.attempt + 1);
    assert_ne!(resumed.claim_token, coordinator.claim_token);
    assert!(
        matches!(db.assessment_provider_replay(registry_id, &resumed,
        &plan.operation, None).await?, Some(AssessmentProviderReplay::Admitted(value)) if *value == result)
    );
    assert_eq!(
        db.assessment_scan(registry_id, &plan.claim.scan_id)
            .await?
            .unwrap()
            .usage,
        usage
    );
    assert!(
        db.assessment_provider_replay(registry_id, &coordinator, &plan.operation, None)
            .await
            .is_err()
    );
    let current = db
        .assessment_scan(registry_id, &plan.claim.scan_id)
        .await?
        .unwrap();
    db.cancel_assessment_scan(registry_id, &plan.claim.scan_id, current.resource_version)
        .await?;
    assert!(
        db.assessment_provider_replay(registry_id, &resumed, &plan.operation, None)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn transport_failure_replays_incomplete_without_reissuing_a_physical_attempt() -> Result<()> {
    let (db, registry_id, plan) = planned().await?;
    db.admit_assessment_provider_plan(registry_id, &plan)
        .await?;
    db.fail_assessment_provider_work(registry_id, &plan.claim, "source-transport-failed")
        .await?;
    let mut coordinator = plan.claim.clone();
    coordinator.task_id = "coordinator".into();
    db.pause_assessment_scan_fenced(registry_id, &coordinator, &[])
        .await?;
    let resumed = db
        .claim_assessment_scan(registry_id, &plan.claim.scan_id, 90)
        .await?;
    assert!(matches!(
        db.assessment_provider_replay(registry_id, &resumed, &plan.operation, None)
            .await?,
        Some(super::AssessmentProviderReplay::Failed)
    ));
    assert_eq!(
        db.assessment_scan(registry_id, &plan.claim.scan_id)
            .await?
            .unwrap()
            .usage
            .provider_requests,
        1
    );
    Ok(())
}

#[tokio::test]
async fn pre_dispatch_refusal_is_replayable_but_does_not_consume_source_quota() -> Result<()> {
    let (db, registry_id, request) = setup().await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 90)
        .await?;
    let operation = ProviderOperation::ObserveTags {
        repository: "fixture/unavailable".into(),
        tag_prefix: "v".into(),
        page: 1,
    };
    db.refuse_assessment_provider_question_fenced(registry_id, &claim, &operation, &[])
        .await?;
    db.refuse_assessment_provider_question_fenced(registry_id, &claim, &operation, &[])
        .await?;
    assert!(matches!(
        db.assessment_provider_replay(registry_id, &claim, &operation, None)
            .await?,
        Some(super::AssessmentProviderReplay::Failed)
    ));
    let current = db
        .assessment_scan(registry_id, &scan.scan_id)
        .await?
        .unwrap();
    assert_eq!(current.usage.provider_requests, 0);
    assert_eq!(current.usage.tasks, 1);
    db.pause_assessment_scan_fenced(registry_id, &claim, &[])
        .await?;
    let resumed = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 90)
        .await?;
    assert!(matches!(
        db.assessment_provider_replay(registry_id, &resumed, &operation, None)
            .await?,
        Some(super::AssessmentProviderReplay::Failed)
    ));
    Ok(())
}
