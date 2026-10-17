//! Atomic provider-directed cooldown, denied settlement and exact receipt replay.

use anyhow::{Context as _, Result};
use aos_assessment::observation::{
    ProviderCoverage, ProviderObservationV1, SourceEvidenceRef, PROVIDER_OBSERVATION_V1,
};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::provider::{
    NormalizedObject, ObjectProjection, ProviderOperation, ProviderRetryV1, ProviderWorkPlanV1,
    ProviderWorkResultV1,
};
use aos_contract::Sha256Digest;

use super::*;
use crate::db::assessment::provider_state_tests::{failure, planned_database};

fn throttled(plan: &ProviderWorkPlanV1) -> Result<ProviderWorkResultV1> {
    let mut result = failure(plan)?;
    let observed_at = plan.issued_at.clone();
    let source = Sha256Digest::of_bytes("rate limited");
    let observation = ProviderObservationV1 {
        schema: PROVIDER_OBSERVATION_V1.into(),
        provider: plan.operation.provider().into(),
        project: "example/fixture".into(),
        adapter_version: plan.adapter_version.clone(),
        request_identity_digest: plan.operation.digest()?,
        retrieved_at: observed_at.clone(),
        validated_at: observed_at.clone(),
        expires_at: Timestamp::from_unix_seconds(observed_at.unix_seconds() + 3600)?,
        response_digest: source,
        payload_digest: Sha256Digest::of_bytes("no records"),
        validators: None,
        coverage: ProviderCoverage::Unknown {
            reason: "source-http-403".into(),
        },
        source_refs: vec![SourceEvidenceRef {
            digest: source,
            byte_length: 12,
            origin: plan.operation.provider().into(),
        }],
    };
    let digest = observation.digest()?;
    result.normalized_objects = vec![ObjectProjection {
        digest,
        object: NormalizedObject::Observation(observation),
    }];
    result.observation_refs = vec![digest];
    result.retry = Some(ProviderRetryV1 {
        status: 403,
        source_digest: source,
        observed_at: observed_at.clone(),
        not_before: Timestamp::from_unix_seconds(observed_at.unix_seconds() + 7200)?,
    });
    result.diagnostics = vec!["provider-rate-limited".into(), "source-http-403".into()];
    result.coverage = ProviderCoverage::Unknown {
        reason: "source-http-403".into(),
    };
    Ok(result)
}

async fn qualify_cooldown(db: Database) -> Result<()> {
    let (db, registry, plan) = planned_database(
        db,
        ProviderOperation::ObserveTags {
            repository: "example/fixture".into(),
            tag_prefix: "v".into(),
            page: 1,
        },
    )
    .await?;
    db.admit_assessment_provider_plan(registry, &plan).await?;
    let result = throttled(&plan)?;
    let key = &plan.budget_reservation.source_budget;
    let read = "SELECT failure_count, consumed, resource_version, next_eligible_at FROM assessment_source_budgets WHERE budget_key = ?1";
    let before = db
        .backend
        .query_opt(read, &vals![@slice key])
        .await?
        .context("installed budget")?;

    let mut forged = result.clone();
    forged.retry.as_mut().context("retry fact")?.source_digest =
        Sha256Digest::of_bytes("different response");
    assert!(db
        .admit_assessment_provider_result(registry, &plan, &forged)
        .await
        .is_err());
    let denial = Statement::new(
        "UPDATE registries SET scope_key = scope_key WHERE id = -1",
        vec![],
    )
    .expecting(1);
    assert!(db
        .admit_assessment_provider_result_fenced(registry, &plan, &result, &[denial])
        .await
        .is_err());
    let denied = db
        .backend
        .query_opt(read, &vals![@slice key])
        .await?
        .context("denied budget")?;
    assert_eq!(denied.get::<u64>(2)?, before.get::<u64>(2)?);
    assert_eq!(denied.get::<u64>(3)?, before.get::<u64>(3)?);
    db.check_assessment_provider_claim(registry, &plan.claim)
        .await?;

    db.admit_assessment_provider_result(registry, &plan, &result)
        .await?;
    let admitted = db
        .backend
        .query_opt(read, &vals![@slice key])
        .await?
        .context("admitted budget")?;
    assert_eq!(admitted.get::<u32>(0)?, 1);
    assert_eq!(admitted.get::<u64>(1)?, 1);
    assert_eq!(admitted.get::<u64>(2)?, before.get::<u64>(2)? + 1);
    assert_eq!(
        admitted.get::<u64>(3)?,
        result
            .retry
            .as_ref()
            .context("retry fact")?
            .not_before
            .unix_seconds()
    );

    db.admit_assessment_provider_result(registry, &plan, &result)
        .await?;
    let replay = db
        .backend
        .query_opt(read, &vals![@slice key])
        .await?
        .context("replayed budget")?;
    assert_eq!(replay.get::<u64>(2)?, admitted.get::<u64>(2)?);
    assert_eq!(replay.get::<u64>(3)?, admitted.get::<u64>(3)?);
    let mut parent = plan.claim.clone();
    parent.task_id = "coordinator".into();
    assert!(db
        .reserve_assessment_provider_work(
            registry,
            &parent,
            &crate::db::AssessmentProviderWork {
                task_id: "blocked-during-source-cooldown".into(),
                operation_digest: Sha256Digest::of_bytes("new question"),
                budget_key: key.clone(),
                requests: 1,
                deadline_seconds: 30,
            }
        )
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn source_cooldown_and_receipt_commit_atomically_without_replay_extension() -> Result<()> {
    qualify_cooldown(Database::open_in_memory().await?).await
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn source_cooldown_and_receipt_are_atomic_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
    qualify_cooldown(Database::with_backend(Box::new(backend)).await?).await
}

#[tokio::test]
async fn source_hint_cannot_shorten_a_concurrent_cooldown() -> Result<()> {
    let (db, registry, plan) = planned_database(
        Database::open_in_memory().await?,
        ProviderOperation::ObserveTags {
            repository: "example/fixture".into(),
            tag_prefix: "v".into(),
            page: 1,
        },
    )
    .await?;
    db.admit_assessment_provider_plan(registry, &plan).await?;
    let result = throttled(&plan)?;
    let key = &plan.budget_reservation.source_budget;
    let later = plan.issued_at.unix_seconds() + 10800;
    db.backend
        .execute(
            "UPDATE assessment_source_budgets SET next_eligible_at = ?2 WHERE budget_key = ?1",
            &vals![@slice key, later],
        )
        .await?;
    db.admit_assessment_provider_result(registry, &plan, &result)
        .await?;
    let row = db
        .backend
        .query_opt(
            "SELECT next_eligible_at FROM assessment_source_budgets WHERE budget_key = ?1",
            &vals![@slice key],
        )
        .await?
        .context("concurrent cooldown")?;
    assert_eq!(row.get::<u64>(0)?, later);
    Ok(())
}
