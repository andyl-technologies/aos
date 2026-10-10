//! Source failure facts commit with physical settlement and survive exact replay.

use anyhow::{Context as _, Result};
use aos_assessment_runtime::events::{AssessmentEventPayload, SourceFailureCode};
use aos_assessment_runtime::provider::ProviderOperation;
use aos_contract::Sha256Digest;

use crate::backend::Statement;
use crate::db::Database;

#[tokio::test]
async fn source_failure_events_commit_atomically_and_replay_once() -> Result<()> {
    failure_case(Database::open_in_memory().await?).await
}

#[tokio::test]
#[cfg(feature = "postgres")]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to disposable PostgreSQL"]
async fn source_failure_events_commit_atomically_on_postgresql() -> Result<()> {
    let path =
        std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE").context("disposable PostgreSQL URL file")?;
    let url = std::fs::read_to_string(path)?;
    let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
    failure_case(Database::with_backend(Box::new(backend)).await?).await
}

async fn failure_case(db: Database) -> Result<()> {
    let (db, registry, plan) = super::provider_state_tests::planned_database(
        db,
        ProviderOperation::ObserveReleases {
            repository: "example/fixture".into(),
            tag_prefix: "v".into(),
            page: 1,
        },
    )
    .await?;
    db.admit_assessment_provider_plan(registry, &plan).await?;
    let mut result = super::provider_state_tests::failure(&plan)?;
    result.diagnostics = vec!["source-request-incomplete".into()];
    let refusal = [Statement::new(
        "UPDATE assessment_tasks SET state = state WHERE 1 = 0",
        vec![],
    )
    .expecting(1)];

    assert!(db
        .admit_assessment_provider_result_fenced(registry, &plan, &result, &refusal)
        .await
        .is_err());
    assert!(db.assessment_event_page(registry, 0, 100).await?.is_empty());
    db.check_assessment_provider_claim(registry, &plan.claim)
        .await?;
    db.admit_assessment_provider_result(registry, &plan, &result)
        .await?;
    db.admit_assessment_provider_result(registry, &plan, &result)
        .await?;

    let events = db.assessment_event_page(registry, 0, 100).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sequence, 1);
    let AssessmentEventPayload::SourceFailed { failure } = &events[0].payload else {
        anyhow::bail!("source failure event was not retained");
    };
    assert_eq!(failure.code, SourceFailureCode::SourceUnavailable);
    assert_eq!(failure.provider, "github-releases");
    assert_eq!(failure.scan_id, plan.claim.scan_id);
    assert_eq!(failure.attempt, plan.claim.attempt);
    assert_eq!(failure.plan_digest, plan.digest()?);
    assert_eq!(failure.operation_digest, plan.operation.digest()?);
    assert_eq!(
        failure.receipt_digest,
        Some(Sha256Digest::of_canonical(
            "aos.provider-work-result/v1",
            &result
        )?)
    );
    let encoded = String::from_utf8(events[0].to_bytes()?)?;
    for private in [
        "example/fixture",
        "sourceBudget",
        "claimToken",
        "credentialRef",
        "provider-unavailable",
    ] {
        assert!(
            !encoded.contains(private),
            "failure event disclosed {private}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn uncertain_execution_reports_only_an_admitted_plan_without_response_receipt() -> Result<()>
{
    for admit_plan in [false, true] {
        let (db, registry, plan) = super::provider_state_tests::planned().await?;
        if admit_plan {
            db.admit_assessment_provider_plan(registry, &plan).await?;
        }
        let refusal = [Statement::new(
            "UPDATE assessment_tasks SET state = state WHERE 1 = 0",
            vec![],
        )
        .expecting(1)];
        assert!(db
            .fail_assessment_provider_work_fenced(
                registry,
                &plan.claim,
                "source-transport-failed",
                &refusal
            )
            .await
            .is_err());
        assert!(db.assessment_event_page(registry, 0, 100).await?.is_empty());

        db.fail_assessment_provider_work(registry, &plan.claim, "source-transport-failed")
            .await?;
        assert!(db
            .fail_assessment_provider_work(registry, &plan.claim, "source-transport-failed")
            .await
            .is_err());
        let events = db.assessment_event_page(registry, 0, 100).await?;
        assert_eq!(events.len(), usize::from(admit_plan));
        if let Some(event) = events.first() {
            let AssessmentEventPayload::SourceFailed { failure } = &event.payload else {
                anyhow::bail!("uncertain execution payload differs");
            };
            assert_eq!(event.sequence, 1);
            assert_eq!(failure.code, SourceFailureCode::ExecutionFailed);
            assert_eq!(failure.plan_digest, plan.digest()?);
            assert!(failure.receipt_digest.is_none());
        }
        assert_eq!(
            db.assessment_scan(registry, &plan.claim.scan_id)
                .await?
                .context("scan")?
                .usage
                .provider_requests,
            1
        );
    }
    Ok(())
}
