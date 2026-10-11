//! Local physical acquisition settlement, recovery and host-wide quota tests.

use std::sync::Mutex;

use aos_assessment_runtime::ports::{Clock, EvidenceStore};
use aos_assessment_runtime::provider::{
    BudgetReservation, PROVIDER_WORK_PLAN_V1, ProviderLimits, ProviderOperation, SourceRequest,
    SourceResponse, SourceThrottleHeaders, SourceTransport, execute_source,
};
use aos_assessment_runtime::scan::TaskClaim;

use super::*;

struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Result<Timestamp> {
        Ok(self.0.clone())
    }
}

#[derive(Default)]
struct Evidence(Mutex<BTreeMap<Sha256Digest, Vec<u8>>>);

#[async_trait::async_trait]
impl EvidenceStore for Evidence {
    async fn retain(&self, _: &str, bytes: &[u8]) -> Result<Sha256Digest> {
        let digest = Sha256Digest::of_bytes(bytes);
        self.0
            .lock()
            .expect("fixture evidence")
            .insert(digest, bytes.to_vec());
        Ok(digest)
    }

    async fn read(&self, _: &str, digest: Sha256Digest, _: u64) -> Result<Vec<u8>> {
        self.0
            .lock()
            .expect("fixture evidence")
            .get(&digest)
            .cloned()
            .context("fixture source")
    }
}

struct Response(u16, Option<String>);

#[async_trait::async_trait]
impl SourceTransport for Response {
    async fn fetch(&self, _: &ProviderWorkPlanV1, _: &SourceRequest) -> Result<SourceResponse> {
        let body = if self.0 == 200 {
            b"[]".to_vec()
        } else {
            b"upstream failure".to_vec()
        };
        Ok(SourceResponse {
            status: self.0,
            transferred_bytes: body.len() as u64,
            body,
            validators: Some(aos_assessment::observation::HttpValidators {
                etag: Some("fixture-etag".into()),
                last_modified: None,
            }),
            throttle: SourceThrottleHeaders {
                retry_after: self.1.clone(),
                ..Default::default()
            },
        })
    }
}

fn store() -> Result<(tempfile::TempDir, StateStore)> {
    let root = tempfile::tempdir()?;
    let repository = root.path().join("repository");
    secure_directory(&repository)?;
    let store = StateStore {
        root: root.path().into(),
        repository,
    };
    Ok((root, store))
}

fn timestamp(seconds: u64) -> Result<Timestamp> {
    Timestamp::from_unix_seconds(seconds)
}

fn plan(id: &str, seconds: u64) -> Result<ProviderWorkPlanV1> {
    let issued_at = timestamp(seconds)?;
    let expires_at = timestamp(seconds + 60)?;
    let operation = ProviderOperation::ObserveTags {
        repository: "example/fixture".into(),
        tag_prefix: "v".into(),
        page: 1,
    };
    Ok(ProviderWorkPlanV1 {
        schema: PROVIDER_WORK_PLAN_V1.into(),
        deployment_id: "local".into(),
        issuer: "local-coordinator".into(),
        audience: "local-provider".into(),
        plan_id: id.into(),
        claim: TaskClaim {
            scan_id: "scan-one".into(),
            task_id: id.into(),
            request_digest: Sha256Digest::of_bytes("request"),
            generation: 1,
            inventory_revision: 1,
            claim_token: "00000000000000000000000000000001".into(),
            expires_at: expires_at.clone(),
            attempt: 1,
        },
        issued_at,
        expires_at: expires_at.clone(),
        nonce: "00000000000000000000000000000002".into(),
        inventory_digest: Sha256Digest::of_bytes("inventory"),
        policy_digest: Sha256Digest::of_bytes("policy"),
        authorization_partition: "local-fixture".into(),
        credential_ref: None,
        budget_reservation: BudgetReservation {
            source_budget: "local-github".into(),
            reservation_id: id.into(),
            requests: 1,
            deadline: expires_at,
        },
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
    })
}

async fn result(
    plan: &ProviderWorkPlanV1,
    status: u16,
    hint: Option<&str>,
) -> Result<ProviderWorkResultV1> {
    execute_source(
        &Response(status, hint.map(str::to_owned)),
        &Evidence::default(),
        &FixedClock(plan.issued_at.clone()),
        plan,
        "local-test/v1",
        86400,
    )
    .await
}

#[tokio::test]
async fn exact_receipts_preserve_longer_concurrent_cooldowns_and_survive_restart() -> Result<()> {
    let (root, store) = store()?;
    let failed = plan("failed", 100_000)?;
    let healthy = plan("healthy", 100_000)?;
    store.claim_assessment_source(&failed, &failed.issued_at)?;
    store.claim_assessment_source(&healthy, &healthy.issued_at)?;
    assert!(
        store
            .claim_assessment_source(&failed, &failed.issued_at)
            .is_err()
    );
    let failure = result(&failed, 429, Some("7200")).await?;
    let success = result(&healthy, 200, None).await?;
    store.settle_assessment_source(&failed, Some(&failure), &failed.issued_at)?;
    store.settle_assessment_source(&healthy, Some(&success), &healthy.issued_at)?;
    let bytes = fs::read(root.path().join("assessment-budget-github.json"))?;
    let before: SourceBudget = canonical::from_slice(&bytes, "budget")?;
    assert_eq!(
        (
            before.failure_count,
            before.requests,
            before.next_eligible_at
        ),
        (0, 2, 107_200)
    );

    let reopened = StateStore {
        root: root.path().into(),
        repository: store.repository.clone(),
    };
    reopened.settle_assessment_source(&failed, Some(&failure), &timestamp(100_120)?)?;
    assert_eq!(
        fs::read(root.path().join("assessment-budget-github.json"))?,
        bytes
    );
    let mut changed = failure.clone();
    changed.executor_build = "changed-build".into();
    assert!(
        reopened
            .settle_assessment_source(&failed, Some(&changed), &timestamp(100_120)?)
            .is_err()
    );
    let mut changed_plan = failed.clone();
    changed_plan.nonce = "00000000000000000000000000000003".into();
    assert!(
        reopened
            .settle_assessment_source(&changed_plan, None, &failed.issued_at)
            .is_err()
    );
    let next = plan("too-early", 100_121)?;
    assert!(
        reopened
            .claim_assessment_source(&next, &next.issued_at)
            .is_err()
    );
    assert_eq!(
        fs::read(root.path().join("assessment-budget-github.json"))?,
        bytes
    );
    Ok(())
}

#[tokio::test]
async fn midnight_resets_allowance_without_erasing_source_throttle_or_receipts() -> Result<()> {
    let (_root, store) = store()?;
    let old = plan("before-midnight", 172_790)?;
    store.claim_assessment_source(&old, &old.issued_at)?;
    let failure = result(&old, 429, Some("3600")).await?;
    store.settle_assessment_source(&old, Some(&failure), &old.issued_at)?;
    let early = plan("after-midnight", 172_801)?;
    assert!(
        store
            .claim_assessment_source(&early, &early.issued_at)
            .is_err()
    );
    let next = plan("after-cooldown", 176_390)?;
    store.claim_assessment_source(&next, &next.issued_at)?;
    let budget = store.read_source_budget("assessment-budget-github.json")?;
    assert_eq!(
        (budget.day, budget.requests, budget.failure_count),
        (2, 1, 1)
    );
    assert!(budget.attempts.contains_key(&attempt_key(&old)));
    store.settle_assessment_source(&old, Some(&failure), &next.issued_at)?;
    assert_eq!(
        store
            .read_source_budget("assessment-budget-github.json")?
            .requests,
        1
    );
    Ok(())
}

#[tokio::test]
async fn crashed_execution_is_failed_once_and_cannot_admit_a_late_success() -> Result<()> {
    let (_root, store) = store()?;
    let lost = plan("lost", 100_000)?;
    store.claim_assessment_source(&lost, &lost.issued_at)?;
    let next = plan("next", 100_060)?;
    assert!(
        store
            .claim_assessment_source(&next, &next.issued_at)
            .is_err()
    );
    let recovered = store.read_source_budget("assessment-budget-github.json")?;
    assert_eq!((recovered.failure_count, recovered.requests), (1, 1));
    assert!((100_080..=100_100).contains(&recovered.next_eligible_at));
    let success = result(&lost, 200, None).await?;
    assert!(
        store
            .settle_assessment_source(&lost, Some(&success), &next.issued_at)
            .is_err()
    );
    assert!(
        store
            .claim_assessment_source(&next, &next.issued_at)
            .is_err()
    );
    assert_eq!(
        store
            .read_source_budget("assessment-budget-github.json")?
            .failure_count,
        1
    );
    let permitted = plan("permitted", recovered.next_eligible_at)?;
    store.claim_assessment_source(&permitted, &permitted.issued_at)?;
    assert_eq!(
        store
            .read_source_budget("assessment-budget-github.json")?
            .requests,
        2
    );
    Ok(())
}

#[tokio::test]
async fn legacy_repology_cannot_bypass_shared_assessment_cooldowns() -> Result<()> {
    let (_root, store) = store()?;
    let mut work = plan("repology", 100_000)?;
    work.operation = ProviderOperation::ObserveRepology {
        project: "fixture".into(),
    };
    work.adapter_version = work.operation.adapter_version().into();
    store.claim_assessment_source(&work, &work.issued_at)?;
    let failure = result(&work, 429, Some("120")).await?;
    store.settle_assessment_source(&work, Some(&failure), &work.issued_at)?;
    assert!(store.claim_repology_request(100_001).is_err());
    let budget: RepologyBudget =
        read_required(&store.root.join("repology-budget.json"), "legacy budget")?;
    assert_eq!(budget.requests, 1);
    store.claim_repology_request(100_120)?;
    let budget: RepologyBudget =
        read_required(&store.root.join("repology-budget.json"), "legacy budget")?;
    assert_eq!(budget.requests, 2);
    Ok(())
}

#[test]
fn uncertain_attempts_open_a_bounded_circuit_without_refunding_allowance() -> Result<()> {
    let (_root, store) = store()?;
    let mut now = 100_000;
    for index in 0..24 {
        let work = plan(&format!("uncertain-{index}"), now)?;
        store.claim_assessment_source(&work, &work.issued_at)?;
        store.settle_assessment_source(&work, None, &work.issued_at)?;
        let budget = store.read_source_budget("assessment-budget-github.json")?;
        assert_eq!(budget.requests, index + 1);
        assert_eq!(budget.failure_count, (index + 1).min(20));
        assert!((20..=3600).contains(&(budget.next_eligible_at - now)));
        if index >= 4 {
            assert!(budget.circuit_until >= now + 300);
        }
        let early = plan(&format!("early-{index}"), now)?;
        assert!(
            store
                .claim_assessment_source(&early, &early.issued_at)
                .is_err()
        );
        now = budget.next_eligible_at.max(budget.circuit_until);
    }
    Ok(())
}

#[test]
fn legacy_budget_upgrade_preserves_cooldown_and_refuses_symlinked_state() -> Result<()> {
    let (root, store) = store()?;
    fs::write(
        root.path().join("assessment-budget-github.json"),
        br#"{"day":1,"requests":999,"nextEligibleAt":100100}"#,
    )?;
    let work = plan("legacy", 100_000)?;
    assert!(
        store
            .claim_assessment_source(&work, &work.issued_at)
            .is_err()
    );
    let upgraded = plan("upgrade", 100_100)?;
    store.claim_assessment_source(&upgraded, &upgraded.issued_at)?;
    assert_eq!(
        store
            .read_source_budget("assessment-budget-github.json")?
            .requests,
        1000
    );
    let exhausted = plan("exhausted", 100_101)?;
    assert!(
        store
            .claim_assessment_source(&exhausted, &exhausted.issued_at)
            .is_err()
    );
    fs::rename(
        root.path().join("assessment-budget-github.json"),
        root.path().join("real.json"),
    )?;
    std::os::unix::fs::symlink(
        root.path().join("real.json"),
        root.path().join("assessment-budget-github.json"),
    )?;
    assert!(
        store
            .claim_assessment_source(&exhausted, &exhausted.issued_at)
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn conditional_index_requires_settlement_exact_partition_and_query_and_never_rolls_back()
-> Result<()> {
    let (_root, store) = store()?;
    let work = plan("conditional-old", 100_000)?;
    let observed = result(&work, 200, None).await?;
    store.retain_assessment_source(&work.authorization_partition, b"[]")?;
    store.claim_assessment_source(&work, &work.issued_at)?;
    assert!(
        store
            .retain_local_conditional_response(&work, &observed)
            .is_err()
    );
    store.settle_assessment_source(&work, Some(&observed), &observed.completed_at)?;
    store.retain_local_conditional_response(&work, &observed)?;
    let cache = store
        .local_conditional_response(
            &work.authorization_partition,
            &work.operation,
            &timestamp(100_001)?,
            1024,
        )?
        .context("conditional cache")?;
    assert_eq!(cache.evidence.digest, Sha256Digest::of_bytes(b"[]"));
    assert_eq!(cache.validators.etag.as_deref(), Some("fixture-etag"));
    assert!(
        store
            .local_conditional_response(
                "other-partition",
                &work.operation,
                &timestamp(100_001)?,
                1024
            )?
            .is_none()
    );
    assert!(
        store
            .local_conditional_response(
                &work.authorization_partition,
                &work.operation,
                &timestamp(99_999)?,
                1024
            )
            .is_err()
    );
    assert!(
        store
            .local_conditional_response(
                &work.authorization_partition,
                &work.operation,
                &timestamp(100_001)?,
                1
            )?
            .is_none()
    );
    let different = ProviderOperation::ObserveTags {
        repository: "example/other".into(),
        tag_prefix: "v".into(),
        page: 1,
    };
    assert!(
        store
            .local_conditional_response(
                &work.authorization_partition,
                &different,
                &timestamp(100_001)?,
                1024
            )?
            .is_none()
    );

    let newer = plan("conditional-new", 100_100)?;
    let refreshed = result(&newer, 200, None).await?;
    store.claim_assessment_source(&newer, &newer.issued_at)?;
    store.settle_assessment_source(&newer, Some(&refreshed), &refreshed.completed_at)?;
    store.retain_local_conditional_response(&newer, &refreshed)?;
    store.retain_local_conditional_response(&work, &observed)?;
    let head = store
        .local_conditional_response(
            &work.authorization_partition,
            &work.operation,
            &timestamp(100_101)?,
            1024,
        )?
        .context("newest cache")?;
    assert_eq!(head.observation.validated_at, newer.issued_at);
    assert_ne!(head.observation_digest, cache.observation_digest);
    assert_eq!(head.evidence, cache.evidence);

    let path = store
        .assessment_source_directory(&work.authorization_partition)?
        .join("observations")
        .join(work.operation.digest()?.hex());
    let mut corrupted = head.observation;
    corrupted.project = "example/foreign".into();
    fs::write(path, serde_json::to_vec(&corrupted)?)?;
    assert!(
        store
            .local_conditional_response(
                &work.authorization_partition,
                &work.operation,
                &timestamp(100_101)?,
                1024
            )
            .is_err()
    );
    Ok(())
}
