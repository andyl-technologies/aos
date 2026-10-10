//! Real parser-to-evaluator acquisition tests with source revision and failure fences.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use anyhow::{Context as _, Result};
use aos_assessment::input::Profile;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::acquisition::{
    AcquisitionPort, acquire, acquire_stale, plan_acquisition,
};
use aos_assessment_runtime::ports::{Clock, EvidenceStore};
use aos_assessment_runtime::provider::*;
use aos_assessment_runtime::scan::TaskClaim;
use aos_contract::Sha256Digest;
use serde_json::json;

#[path = "../../aos-assessment/tests/common/mod.rs"]
mod common;

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Result<Timestamp> {
        common::evaluated_at()
    }
}

#[derive(Default)]
struct Custody(Mutex<BTreeMap<Sha256Digest, Vec<u8>>>);

#[async_trait::async_trait]
impl EvidenceStore for Custody {
    async fn retain(&self, _: &str, bytes: &[u8]) -> Result<Sha256Digest> {
        let digest = Sha256Digest::of_bytes(bytes);
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("custody lock"))?
            .insert(digest, bytes.to_vec());
        Ok(digest)
    }
    async fn read(&self, _: &str, digest: Sha256Digest, limit: u64) -> Result<Vec<u8>> {
        let bytes = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("custody lock"))?
            .get(&digest)
            .context("custody absent")?
            .clone();
        anyhow::ensure!(bytes.len() as u64 <= limit, "custody exceeds limit");
        Ok(bytes)
    }
}

struct Source {
    responses: Mutex<VecDeque<Vec<u8>>>,
}

#[async_trait::async_trait]
impl SourceTransport for Source {
    async fn fetch(&self, _: &ProviderWorkPlanV1, _: &SourceRequest) -> Result<SourceResponse> {
        let bytes = self
            .responses
            .lock()
            .map_err(|_| anyhow::anyhow!("source lock"))?
            .pop_front()
            .context("source unavailable")?;
        Ok(SourceResponse {
            status: 200,
            transferred_bytes: bytes.len() as u64,
            body: bytes,
            validators: None,
            throttle: Default::default(),
        })
    }
}

struct Port {
    source: Source,
    custody: Custody,
    operations: Mutex<Vec<ProviderOperation>>,
}

impl Port {
    fn new(responses: Vec<serde_json::Value>) -> Result<Self> {
        Ok(Self {
            source: Source {
                responses: Mutex::new(
                    responses
                        .iter()
                        .map(serde_json::to_vec)
                        .collect::<std::result::Result<VecDeque<_>, _>>()?,
                ),
            },
            custody: Custody::default(),
            operations: Mutex::new(vec![]),
        })
    }
}

#[async_trait::async_trait]
impl AcquisitionPort for Port {
    async fn invoke(
        &self,
        operation: &ProviderOperation,
        previous: Option<&ProviderPageV1>,
    ) -> Result<ProviderWorkResultV1> {
        self.operations
            .lock()
            .map_err(|_| anyhow::anyhow!("operation lock"))?
            .push(operation.clone());
        let now = FixedClock.now()?;
        let expires = Timestamp::from_unix_seconds(now.unix_seconds() + 60)?;
        let requests = operation.source_requests()?.len() as u32;
        let plan = ProviderWorkPlanV1 {
            schema: PROVIDER_WORK_PLAN_V1.into(),
            deployment_id: "fixture".into(),
            issuer: "fixture-coordinator".into(),
            audience: "fixture-executor".into(),
            plan_id: "fixture-plan".into(),
            claim: TaskClaim {
                scan_id: "scan".into(),
                task_id: "task".into(),
                request_digest: Sha256Digest::of_bytes("request"),
                generation: 1,
                inventory_revision: 1,
                claim_token: "00000000000000000000000000000001".into(),
                expires_at: expires.clone(),
                attempt: 1,
            },
            issued_at: now,
            expires_at: expires.clone(),
            nonce: "00000000000000000000000000000002".into(),
            inventory_digest: Sha256Digest::of_bytes("inventory"),
            policy_digest: Sha256Digest::of_bytes("policy"),
            authorization_partition: "fixture".into(),
            credential_ref: None,
            budget_reservation: BudgetReservation {
                source_budget: "fixture-source".into(),
                reservation_id: "reservation".into(),
                requests,
                deadline: expires,
            },
            cache_ref: None,
            continuation: previous.map(ProviderPageV1::digest).transpose()?,
            continuation_ref: previous.cloned(),
            operation: operation.clone(),
            adapter_version: operation.adapter_version().into(),
            limits: ProviderLimits {
                requests,
                concurrency: 1,
                ..Default::default()
            },
        };
        execute_source(
            &self.source,
            &self.custody,
            &FixedClock,
            &plan,
            "fixture/v1",
            3600,
        )
        .await
    }
}

fn osv_record(modified: &str) -> serde_json::Value {
    json!({ "id":"GHSA-fixture-one", "modified":modified, "aliases":["CVE-2026-10001"], "affected":[{
        "package":{"ecosystem":"crates.io", "name":"fixture"},
        "ranges":[{"type":"SEMVER", "events":[{"introduced":"0"},{"fixed":"1.3.0"}]}]
    }]})
}

#[tokio::test]
async fn interrupted_upstream_pages_retain_new_and_cached_candidates_without_complete_coverage()
-> Result<()> {
    let mut data = common::fixture("1.2.0")?;
    let subjects = vec!["subject".into()];
    let profiles = vec![Profile::Updates];
    let cached = Port::new(vec![
        json!([{"tag_name":"v1.3.0", "published_at":"2026-10-01T00:00:00Z"}]),
    ])?;
    acquire(
        &cached,
        &cached.custody,
        "fixture",
        &mut data,
        &subjects,
        &profiles,
    )
    .await?;
    let prior_history = data.history[0].clone();
    let page = (4..24)
        .map(|minor| {
            json!({
                "tag_name":format!("v1.{minor}.0"), "published_at":"2026-10-01T00:00:00Z"
            })
        })
        .collect::<Vec<_>>();
    let interrupted = Port::new(vec![json!(page)])?;

    let diagnostics = acquire(
        &interrupted,
        &interrupted.custody,
        "fixture",
        &mut data,
        &subjects,
        &profiles,
    )
    .await?;
    assert_eq!(diagnostics, ["source-acquisition-incomplete"]);
    assert_eq!(
        interrupted
            .operations
            .lock()
            .map_err(|_| anyhow::anyhow!("operation lock"))?
            .len(),
        2
    );
    let binding = &data.upstream[0];
    assert_eq!(binding.observation.candidates.len(), 21);
    assert!(
        binding
            .observation
            .candidates
            .iter()
            .any(|candidate| candidate.raw_id == "v1.3.0")
    );
    assert!(
        binding
            .observation
            .candidates
            .iter()
            .any(|candidate| candidate.raw_id == "v1.23.0")
    );
    assert!(matches!(
        binding.observation.coverage,
        aos_assessment::discovery::ObservationCoverage::Truncated { .. }
    ));
    assert!(data.history.contains(&prior_history));
    let input = data.freeze_selected(profiles, subjects, FixedClock.now()?)?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    assert_ne!(
        result.coverage,
        aos_assessment::security::CoverageState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn positional_pages_and_exact_full_records_produce_an_evaluable_finding() -> Result<()> {
    let mut data = common::fixture("1.2.0")?;
    data.advisory_snapshot = None;
    data.advisories.clear();
    let modified = "2026-10-09T01:00:00Z";
    let port = Port::new(vec![
        json!({"results":[{"vulns":[{"id":"GHSA-fixture-one", "modified":modified}], "next_page_token":"retained-token"}]}),
        json!({"results":[{}]}),
        osv_record(modified),
    ])?;
    let subjects = vec!["subject".into()];
    let profiles = vec![Profile::Vulnerabilities];

    let diagnostics = acquire(
        &port,
        &port.custody,
        "fixture",
        &mut data,
        &subjects,
        &profiles,
    )
    .await?;
    let input = data.freeze_selected(profiles, subjects, FixedClock.now()?)?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;

    assert!(diagnostics.is_empty());
    assert!(
        data.advisory_snapshot.as_ref().context("snapshot")?.sources[0]
            .observation
            .coverage
            .is_complete()
    );
    assert_eq!(result.subject_results[0].findings.len(), 1);
    assert!(
        result.subject_results[0].findings[0]
            .advisory_ids
            .contains(&"CVE-2026-10001".into())
    );
    assert_eq!(
        port.operations
            .lock()
            .map_err(|_| anyhow::anyhow!("operation lock"))?
            .len(),
        3
    );
    Ok(())
}

#[tokio::test]
async fn changed_full_revision_preserves_cached_positive_and_refuses_clean_coverage() -> Result<()>
{
    let mut data = common::fixture("1.2.0")?;
    let port = Port::new(vec![
        json!({"results":[{"vulns":[{"id":"GHSA-fixture-one", "modified":"2026-10-09T01:00:00Z"}]}]}),
        osv_record("2026-10-09T02:00:00Z"),
    ])?;
    let subjects = vec!["subject".into()];
    let profiles = vec![Profile::Vulnerabilities];

    let diagnostics = acquire(
        &port,
        &port.custody,
        "fixture",
        &mut data,
        &subjects,
        &profiles,
    )
    .await?;
    let input = data.freeze_selected(profiles, subjects, FixedClock.now()?)?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;

    assert_eq!(diagnostics, vec!["source-acquisition-incomplete"]);
    assert_eq!(result.subject_results[0].findings.len(), 1);
    assert!(
        !data.advisory_snapshot.as_ref().context("snapshot")?.sources[0]
            .observation
            .coverage
            .is_complete()
    );
    Ok(())
}

#[test]
fn planning_is_metadata_bound_and_rejects_an_unknown_subject() -> Result<()> {
    let data = common::fixture("1.2.0")?;
    let jobs = plan_acquisition(
        &data,
        &["subject".into()],
        &[Profile::Updates, Profile::Vulnerabilities],
    )?;
    assert_eq!(jobs.len(), 2);
    assert!(jobs.iter().any(|job| matches!(&job.operation, ProviderOperation::ObserveReleases { repository, .. } if repository == "example/fixture")));
    assert!(plan_acquisition(&data, &["absent".into()], &[Profile::Vulnerabilities]).is_err());
    Ok(())
}

#[tokio::test]
async fn newly_acquired_positive_records_survive_a_later_failed_retrieval_batch() -> Result<()> {
    let mut data = common::fixture("1.2.0")?;
    data.advisory_snapshot = None;
    data.advisories.clear();
    let modified = "2026-10-09T01:00:00Z";
    let ids = (0..11)
        .map(|index| format!("GHSA-fixture-{index:02}"))
        .collect::<Vec<_>>();
    let mut responses = vec![json!({"results":[{"vulns":ids.iter()
        .map(|id| json!({"id":id,"modified":modified})).collect::<Vec<_>>()}]})];
    for id in ids.iter().take(10) {
        let mut record = osv_record(modified);
        record["id"] = json!(id);
        responses.push(record);
    }
    let port = Port::new(responses)?;
    let subjects = vec!["subject".into()];
    let profiles = vec![Profile::Vulnerabilities];
    let diagnostics = acquire(
        &port,
        &port.custody,
        "fixture",
        &mut data,
        &subjects,
        &profiles,
    )
    .await?;
    assert_eq!(diagnostics, vec!["source-acquisition-incomplete"]);
    assert_eq!(data.advisories.len(), 10);
    assert!(
        !data.advisory_snapshot.as_ref().context("snapshot")?.sources[0]
            .observation
            .coverage
            .is_complete()
    );
    let input = data.freeze_selected(profiles, subjects, FixedClock.now()?)?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    assert!(!result.subject_results[0].findings.is_empty());
    assert!(
        result.subject_results[0]
            .findings
            .iter()
            .any(|finding| finding.advisory_ids.contains(&"CVE-2026-10001".into()))
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_request_inside_one_batch_preserves_its_prior_complete_records() -> Result<()> {
    let mut data = common::fixture("1.2.0")?;
    data.advisory_snapshot = None;
    data.advisories.clear();
    let modified = "2026-10-09T01:00:00Z";
    let mut first = osv_record(modified);
    first["id"] = json!("GHSA-fixture-first");
    let port = Port::new(vec![
        json!({"results":[{"vulns":[
            {"id":"GHSA-fixture-first", "modified":modified},
            {"id":"GHSA-fixture-second", "modified":modified}
        ]}]}),
        first,
    ])?;
    let subjects = vec!["subject".into()];
    let profiles = vec![Profile::Vulnerabilities];
    let diagnostics = acquire(
        &port,
        &port.custody,
        "fixture",
        &mut data,
        &subjects,
        &profiles,
    )
    .await?;
    assert_eq!(diagnostics, vec!["source-acquisition-incomplete"]);
    assert_eq!(data.advisories.len(), 1);
    let input = data.freeze_selected(profiles, subjects, FixedClock.now()?)?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    assert_eq!(result.subject_results[0].findings.len(), 1);
    assert!(
        !data.advisory_snapshot.as_ref().context("snapshot")?.sources[0]
            .observation
            .coverage
            .is_complete()
    );
    Ok(())
}

#[tokio::test]
async fn refresh_stale_skips_complete_fresh_queries_and_refreshes_expired_evidence() -> Result<()> {
    let mut data = common::fixture("1.2.0")?;
    let port = Port::new(vec![])?;
    let subjects = vec!["subject".into()];
    let profiles = vec![Profile::Vulnerabilities];
    let diagnostics = acquire_stale(
        &port,
        &port.custody,
        "fixture",
        &mut data,
        &subjects,
        &profiles,
        &FixedClock.now()?,
    )
    .await?;
    assert!(diagnostics.is_empty());
    assert!(
        port.operations
            .lock()
            .map_err(|_| anyhow::anyhow!("operation lock"))?
            .is_empty()
    );

    let expired = Timestamp::from_unix_seconds(FixedClock.now()?.unix_seconds() + 86400)?;
    let diagnostics = acquire_stale(
        &port,
        &port.custody,
        "fixture",
        &mut data,
        &subjects,
        &profiles,
        &expired,
    )
    .await?;
    assert_eq!(diagnostics, vec!["source-acquisition-incomplete"]);
    assert_eq!(
        port.operations
            .lock()
            .map_err(|_| anyhow::anyhow!("operation lock"))?
            .len(),
        1
    );
    assert!(
        !data.advisory_snapshot.as_ref().context("snapshot")?.sources[0]
            .observation
            .coverage
            .is_complete()
    );
    Ok(())
}

struct YieldingPort;

#[async_trait::async_trait]
impl AcquisitionPort for YieldingPort {
    async fn save_acquisition_checkpoint(
        &self,
        checkpoint: &aos_assessment_runtime::acquisition::AcquisitionCheckpointV1,
    ) -> Result<()> {
        checkpoint.encoded()?;
        Ok(())
    }

    async fn invoke(
        &self,
        _: &ProviderOperation,
        _: Option<&ProviderPageV1>,
    ) -> Result<ProviderWorkResultV1> {
        Err(aos_assessment_runtime::acquisition::AcquisitionPaused.into())
    }
}

#[tokio::test]
async fn a_host_quantum_yield_never_becomes_partial_source_coverage() -> Result<()> {
    let mut data = common::fixture("1.2.0")?;
    let subjects = data
        .inventory
        .subjects
        .iter()
        .map(|subject| subject.subject_ref.clone())
        .collect::<Vec<_>>();
    let error = acquire(
        &YieldingPort,
        &Custody::default(),
        "fixture",
        &mut data,
        &subjects,
        &[Profile::Updates],
    )
    .await
    .unwrap_err();
    assert!(error.is::<aos_assessment_runtime::acquisition::AcquisitionPaused>());
    assert!(data.upstream.is_empty());
    Ok(())
}

struct RestartingPort {
    port: Port,
    checkpoint: Mutex<Option<Vec<u8>>>,
    remaining: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl AcquisitionPort for RestartingPort {
    async fn acquisition_checkpoint(
        &self,
    ) -> Result<Option<aos_assessment_runtime::acquisition::AcquisitionCheckpointV1>> {
        self.checkpoint
            .lock()
            .map_err(|_| anyhow::anyhow!("checkpoint lock"))?
            .as_deref()
            .map(aos_assessment_runtime::acquisition::AcquisitionCheckpointV1::from_slice)
            .transpose()
    }

    async fn save_acquisition_checkpoint(
        &self,
        checkpoint: &aos_assessment_runtime::acquisition::AcquisitionCheckpointV1,
    ) -> Result<()> {
        *self
            .checkpoint
            .lock()
            .map_err(|_| anyhow::anyhow!("checkpoint lock"))? = Some(checkpoint.encoded()?);
        Ok(())
    }

    async fn invoke(
        &self,
        operation: &ProviderOperation,
        previous: Option<&ProviderPageV1>,
    ) -> Result<ProviderWorkResultV1> {
        if self
            .remaining
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |remaining| remaining.checked_sub(1),
            )
            .is_err()
        {
            return Err(aos_assessment_runtime::acquisition::AcquisitionPaused.into());
        }
        self.port.invoke(operation, previous).await
    }
}

#[tokio::test]
async fn persisted_source_cursor_resumes_the_next_page_without_reinvoking_its_prefix() -> Result<()>
{
    let page = (3..23)
        .map(|minor| {
            json!({"tag_name":format!("v1.{minor}.0"),
        "published_at":"2026-10-01T00:00:00Z"})
        })
        .collect::<Vec<_>>();
    let port = RestartingPort {
        port: Port::new(vec![
            json!(page),
            json!([{ "tag_name":"v1.23.0", "published_at":"2026-10-01T00:00:00Z" }]),
        ])?,
        checkpoint: Mutex::new(None),
        remaining: std::sync::atomic::AtomicUsize::new(1),
    };
    let mut data = common::fixture("1.2.0")?;
    let subjects = vec!["subject".into()];
    let error = acquire(
        &port,
        &port.port.custody,
        "fixture",
        &mut data,
        &subjects,
        &[Profile::Updates],
    )
    .await
    .unwrap_err();
    assert!(error.is::<aos_assessment_runtime::acquisition::AcquisitionPaused>());
    assert!(data.upstream.is_empty());

    // Recreate the closure, as a new process/lease does, and load only persisted progress.
    let mut restarted = common::fixture("1.2.0")?;
    port.remaining.store(1, std::sync::atomic::Ordering::SeqCst);
    acquire(
        &port,
        &port.port.custody,
        "fixture",
        &mut restarted,
        &subjects,
        &[Profile::Updates],
    )
    .await?;
    let operations = port.port.operations.lock().unwrap();
    assert_eq!(operations.len(), 2);
    assert!(matches!(
        operations[0],
        ProviderOperation::ObserveReleases { page: 1, .. }
    ));
    assert!(matches!(
        operations[1],
        ProviderOperation::ObserveReleases { page: 2, .. }
    ));
    assert_eq!(restarted.upstream[0].observation.candidates.len(), 21);
    assert_eq!(
        restarted.upstream[0].observation.coverage,
        aos_assessment::discovery::ObservationCoverage::Complete
    );
    Ok(())
}

#[tokio::test]
async fn persisted_osv_cursor_resumes_full_record_retrieval_without_requerying_ids() -> Result<()> {
    let port = RestartingPort {
        port: Port::new(vec![
            json!({"results":[{"vulns":[{"id":"GHSA-fixture-one", "modified":"2026-10-09T01:00:00Z"}]}]}),
            osv_record("2026-10-09T01:00:00Z"),
        ])?,
        checkpoint: Mutex::new(None),
        remaining: std::sync::atomic::AtomicUsize::new(1),
    };
    let mut data = common::fixture("1.2.0")?;
    let subjects = vec!["subject".into()];
    let error = acquire(
        &port,
        &port.port.custody,
        "fixture",
        &mut data,
        &subjects,
        &[Profile::Vulnerabilities],
    )
    .await
    .unwrap_err();
    assert!(error.is::<aos_assessment_runtime::acquisition::AcquisitionPaused>());
    let mut restarted = common::fixture("1.2.0")?;
    port.remaining.store(1, std::sync::atomic::Ordering::SeqCst);
    acquire(
        &port,
        &port.port.custody,
        "fixture",
        &mut restarted,
        &subjects,
        &[Profile::Vulnerabilities],
    )
    .await?;
    let operations = port.port.operations.lock().unwrap();
    assert_eq!(operations.len(), 2);
    assert!(matches!(operations[0], ProviderOperation::QueryOsv { .. }));
    assert!(matches!(
        operations[1],
        ProviderOperation::RetrieveAdvisories { .. }
    ));
    assert!(
        restarted.advisory_snapshot.as_ref().unwrap().sources[0]
            .observation
            .coverage
            .is_complete()
    );
    let input =
        restarted.freeze_selected(vec![Profile::Vulnerabilities], subjects, FixedClock.now()?)?;
    let result = aos_assessment::evaluator::evaluate(&input, &restarted)?;
    assert_eq!(result.subject_results[0].findings.len(), 1);
    Ok(())
}
