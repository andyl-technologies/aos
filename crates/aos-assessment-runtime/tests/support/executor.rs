//! Shared source execution tests with exact byte custody and captured requests.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use anyhow::{Context as _, Result};
use aos_assessment::observation::{HttpValidators, ProviderCoverage};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::ports::{Clock, EvidenceStore};
use aos_assessment_runtime::provider::*;
use aos_contract::Sha256Digest;
use serde_json::json;

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Result<Timestamp> {
        super::now()
    }
}

#[derive(Default)]
struct Custody(Mutex<BTreeMap<(String, Sha256Digest), Vec<u8>>>);

#[async_trait::async_trait]
impl EvidenceStore for Custody {
    async fn retain(&self, partition: &str, bytes: &[u8]) -> Result<Sha256Digest> {
        let digest = Sha256Digest::of_bytes(bytes);
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture custody lock"))?
            .insert((partition.into(), digest), bytes.to_vec());
        Ok(digest)
    }

    async fn read(&self, partition: &str, digest: Sha256Digest, max_bytes: u64) -> Result<Vec<u8>> {
        let bytes = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture custody lock"))?
            .get(&(partition.into(), digest))
            .context("fixture evidence is unavailable")?
            .clone();
        anyhow::ensure!(bytes.len() as u64 <= max_bytes, "fixture custody size");
        Ok(bytes)
    }
}

struct Source {
    responses: Mutex<VecDeque<SourceResponse>>,
    requests: Mutex<Vec<SourceRequest>>,
}

struct RemainingBudgetSource {
    first: Vec<u8>,
    ceilings: Mutex<Vec<u64>>,
}

#[async_trait::async_trait]
impl SourceTransport for RemainingBudgetSource {
    async fn fetch(&self, plan: &ProviderWorkPlanV1, _: &SourceRequest) -> Result<SourceResponse> {
        let mut ceilings = self
            .ceilings
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture ceiling lock"))?;
        ceilings.push(plan.limits.response_bytes);
        if ceilings.len() != 1 {
            anyhow::bail!("fixture source became unavailable");
        }
        Ok(SourceResponse {
            status: 200,
            body: self.first.clone(),
            transferred_bytes: self.first.len() as u64,
            validators: None,
        })
    }
}

#[tokio::test]
async fn source_reads_are_tightened_to_the_remaining_aggregate_budget_before_dispatch() -> Result<()>
{
    let mut plan = super::plan()?;
    plan.operation = ProviderOperation::RetrieveAdvisories {
        project: "fixture-query".into(),
        ids: vec!["OSV-2026-1".into(), "OSV-2026-2".into()],
    };
    plan.adapter_version = plan.operation.adapter_version().into();
    plan.budget_reservation.requests = 2;
    plan.limits.requests = 2;
    plan.limits.concurrency = 1;
    let raw = br#"{"schema_version":"1.9.1","id":"OSV-2026-1","modified":"2026-10-09T01:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"fixture"},"versions":["1.2.0"]}]}"#.to_vec();
    let size = raw.len() as u64;
    plan.limits.source_bytes = size + 8;
    plan.limits.response_bytes = size + 8;
    let source = RemainingBudgetSource {
        first: raw,
        ceilings: Mutex::new(vec![]),
    };
    let result = execute_source(
        &source,
        &Custody::default(),
        &FixedClock,
        &plan,
        "fixture-build",
        3600,
    )
    .await?;
    assert_eq!(
        *source
            .ceilings
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture ceiling lock"))?,
        vec![size + 8, 8]
    );
    assert_eq!(result.outcome, WorkOutcome::Partial);
    assert_eq!(result.usage.requests, 2);
    assert_eq!(result.usage.decompressed_bytes, size);
    assert_eq!(result.diagnostics, vec!["source-request-incomplete"]);
    assert!(result.normalized_objects.iter().any(|projection| matches!(&projection.object, NormalizedObject::Advisory(record) if record.id == "OSV-2026-1")));
    result.validate_for(&plan, &FixedClock.now()?)?;
    Ok(())
}

impl Source {
    fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from([SourceResponse {
                status,
                transferred_bytes: body.len() as u64,
                body,
                validators: None,
            }])),
            requests: Mutex::new(vec![]),
        }
    }
}

#[async_trait::async_trait]
impl SourceTransport for Source {
    async fn fetch(
        &self,
        plan: &ProviderWorkPlanV1,
        request: &SourceRequest,
    ) -> Result<SourceResponse> {
        assert!(plan.operation.source_requests()?.contains(request));
        self.requests
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture request lock"))?
            .push(request.clone());
        self.responses
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture response lock"))?
            .pop_front()
            .context("unexpected fixture request")
    }
}

#[tokio::test]
async fn osv_ids_never_become_full_record_or_clean_coverage() -> Result<()> {
    let plan = super::plan()?;
    let raw =
        br#"{"results":[{"vulns":[{"id":"CVE-2026-10001","modified":"2026-10-09T01:00:00Z"}]}]}"#
            .to_vec();
    let custody = Custody::default();
    let result = execute_source(
        &Source::new(200, raw.clone()),
        &custody,
        &FixedClock,
        &plan,
        "fixture-build",
        3600,
    )
    .await?;
    assert_eq!(result.outcome, WorkOutcome::Partial);
    assert!(
        matches!(result.coverage, ProviderCoverage::Partial { ref reason, continuation: None } if reason == "osv-full-records-required")
    );
    assert!(
        !result
            .normalized_objects
            .iter()
            .any(|object| matches!(object.object, NormalizedObject::Advisory(_)))
    );
    let page = result
        .normalized_objects
        .iter()
        .find_map(|object| match &object.object {
            NormalizedObject::Page(page) => Some(page),
            _ => None,
        })
        .context("query page")?;
    assert_eq!(page.records[0].id, "CVE-2026-10001");
    assert_eq!(page.source_digest, Sha256Digest::of_bytes(&raw));
    assert_eq!(
        custody
            .read(&plan.authorization_partition, page.source_digest, 1024)
            .await?,
        raw
    );
    Ok(())
}

#[tokio::test]
async fn github_prefix_filtering_cannot_hide_remaining_pages() -> Result<()> {
    let mut plan = super::plan()?;
    plan.operation = ProviderOperation::ObserveTags {
        repository: "example/fixture".into(),
        tag_prefix: "component-".into(),
        page: 1,
    };
    plan.adapter_version = plan.operation.adapter_version().into();
    let raw = serde_json::to_vec(
        &(0..20)
            .map(|index| json!({"name":format!("unrelated-{index}")}))
            .collect::<Vec<_>>(),
    )?;
    let result = execute_source(
        &Source::new(200, raw),
        &Custody::default(),
        &FixedClock,
        &plan,
        "fixture-build",
        3600,
    )
    .await?;
    assert_eq!(result.outcome, WorkOutcome::Partial);
    let anchor = result.continuation.context("retained continuation")?;
    let page = result
        .normalized_objects
        .iter()
        .find_map(|object| match &object.object {
            NormalizedObject::Page(page) if object.digest == anchor => Some(page),
            _ => None,
        })
        .context("continuation page")?;
    assert!(matches!(
        page.next,
        Some(ProviderOperation::ObserveTags { page: 2, .. })
    ));
    assert!(result.normalized_objects.iter().any(|object| matches!(&object.object, NormalizedObject::Upstream(upstream) if upstream.candidates.is_empty())));
    Ok(())
}

#[tokio::test]
async fn source_failure_is_unknown_with_sanitized_diagnostics_and_retained_custody() -> Result<()> {
    let plan = super::plan()?;
    let raw = b"private diagnostic body never becomes output".to_vec();
    let custody = Custody::default();
    let result = execute_source(
        &Source::new(429, raw.clone()),
        &custody,
        &FixedClock,
        &plan,
        "fixture-build",
        3600,
    )
    .await?;
    assert_eq!(result.outcome, WorkOutcome::Failed);
    assert_eq!(result.diagnostics, ["source-http-429"]);
    assert!(matches!(result.coverage, ProviderCoverage::Unknown { .. }));
    assert!(!String::from_utf8(serde_json::to_vec(&result)?)?.contains("private diagnostic"));
    assert_eq!(
        custody
            .read(
                &plan.authorization_partition,
                Sha256Digest::of_bytes(&raw),
                1024
            )
            .await?,
        raw
    );
    Ok(())
}

#[tokio::test]
async fn per_response_overflow_is_rejected_before_retaining_bytes() -> Result<()> {
    let mut plan = super::plan()?;
    plan.limits.response_bytes = 8;
    let custody = Custody::default();
    assert!(
        execute_source(
            &Source::new(200, vec![0; 9]),
            &custody,
            &FixedClock,
            &plan,
            "fixture-build",
            3600
        )
        .await
        .is_err()
    );
    assert!(
        custody
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture custody lock"))?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn conditional_upstream_revalidation_reparses_original_bytes_and_preserves_original_time()
-> Result<()> {
    let mut plan = super::plan()?;
    plan.operation = ProviderOperation::ObserveTags {
        repository: "example/fixture".into(),
        tag_prefix: "v".into(),
        page: 1,
    };
    plan.adapter_version = plan.operation.adapter_version().into();
    let raw = br#"[{"name":"v1.3.0"}]"#.to_vec();
    let custody = Custody::default();
    let first = execute_source(
        &Source::new(200, raw),
        &custody,
        &FixedClock,
        &plan,
        "fixture-build",
        3600,
    )
    .await?;
    let mut observation = first
        .normalized_objects
        .iter()
        .find_map(|object| match &object.object {
            NormalizedObject::Observation(observation) => Some(observation.clone()),
            _ => None,
        })
        .context("prior observation")?;
    observation.retrieved_at = Timestamp::from_unix_seconds(super::now()?.unix_seconds() - 120)?;
    observation.validated_at = Timestamp::from_unix_seconds(super::now()?.unix_seconds() - 60)?;
    let validators = HttpValidators {
        etag: Some("fixture-exact-etag".into()),
        last_modified: None,
    };
    observation.validators = Some(validators.clone());
    plan.cache_ref = Some(CachedResponse {
        evidence: observation.source_refs[0].clone(),
        validators,
        observation_digest: observation.digest()?,
        observation: observation.clone(),
    });
    let result = execute_source(
        &Source::new(304, vec![]),
        &custody,
        &FixedClock,
        &plan,
        "fixture-build",
        3600,
    )
    .await?;
    assert_eq!(result.outcome, WorkOutcome::NotModified);
    assert!(result.normalized_objects.iter().any(|object| matches!(&object.object, NormalizedObject::Upstream(upstream) if upstream.retrieved_at_unix == observation.retrieved_at.unix_seconds() && upstream.response_digest == observation.response_digest)));
    assert!(
        execute_source(
            &Source::new(304, vec![]),
            &Custody::default(),
            &FixedClock,
            &plan,
            "fixture-build",
            3600
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn full_osv_retrieval_cannot_substitute_another_admitted_batch_id() -> Result<()> {
    let mut plan = super::plan()?;
    plan.operation = ProviderOperation::RetrieveAdvisories {
        project: "fixture-query".into(),
        ids: vec!["CVE-2026-10001".into(), "CVE-2026-10002".into()],
    };
    plan.adapter_version = plan.operation.adapter_version().into();
    let raw = serde_json::to_vec(
        &json!({"id":"CVE-2026-10002", "modified":"2026-10-09T01:00:00Z", "affected":[]}),
    )?;
    assert!(
        execute_source(
            &Source::new(200, raw),
            &Custody::default(),
            &FixedClock,
            &plan,
            "fixture-build",
            3600
        )
        .await
        .is_err()
    );
    Ok(())
}
