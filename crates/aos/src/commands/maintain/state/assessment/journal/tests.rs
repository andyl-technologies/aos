//! Local journal publication, cancellation, recovery and immutable custody tests.

use aos_assessment::evaluator::evaluate;
use aos_assessment_runtime::provider::{
    BudgetReservation, PROVIDER_WORK_PLAN_V1, ProviderLimits, ProviderOperation, ProviderWorkPlanV1,
};
use aos_assessment_runtime::scan::TaskClaim;

use super::*;

#[path = "../../../../../../../aos-assessment/tests/common/mod.rs"]
mod common;

fn store() -> Result<(tempfile::TempDir, StateStore)> {
    let root = tempfile::tempdir()?;
    let repository = root
        .path()
        .join(Sha256Digest::of_bytes("fixture repository").hex());
    secure_directory(&repository)?;
    let store = StateStore {
        root: root.path().into(),
        repository,
    };
    Ok((root, store))
}

fn id(number: u32) -> String {
    format!("00000000-0000-4000-8000-{number:012}")
}

fn admit(store: &StateStore, number: u32, data: &EvaluationData) -> Result<ScanReceiptV1> {
    let (receipt, fresh) = store.admit_local_assessment_scan(
        &id(number),
        data,
        vec!["subject".into()],
        vec![Profile::Vulnerabilities],
        FreshnessMode::Offline,
        &format!("request-{number}"),
        common::evaluated_at()?,
    )?;
    assert!(fresh);
    Ok(receipt)
}

fn semantic(data: &EvaluationData) -> Result<(ScanInputV1, PackageAssessmentV1)> {
    let input = data.freeze_selected(
        vec![Profile::Vulnerabilities],
        vec!["subject".into()],
        common::evaluated_at()?,
    )?;
    let result = evaluate(&input, data)?;
    Ok((input, result))
}

fn work(receipt: &ScanReceiptV1) -> Result<ProviderWorkPlanV1> {
    let issued_at = common::evaluated_at()?;
    let expires_at = Timestamp::from_unix_seconds(issued_at.unix_seconds() + 60)?;
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
        plan_id: format!("provider-{}", receipt.scan_id),
        claim: TaskClaim {
            scan_id: receipt.scan_id.clone(),
            task_id: "source-task".into(),
            request_digest: receipt.request_digest,
            generation: receipt.generation,
            inventory_revision: receipt.request.inventory_revision,
            claim_token: "00000000000000000000000000000001".into(),
            expires_at: expires_at.clone(),
            attempt: 1,
        },
        issued_at,
        expires_at: expires_at.clone(),
        nonce: "00000000000000000000000000000002".into(),
        inventory_digest: receipt.request.inventory_digest,
        policy_digest: receipt.request.policy_digest,
        authorization_partition: receipt.request.authorization_partition.clone(),
        credential_ref: None,
        budget_reservation: BudgetReservation {
            source_budget: "local-github".into(),
            reservation_id: "reservation".into(),
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

#[test]
fn idempotency_reuses_only_an_identical_frozen_request_and_canonical_identity() -> Result<()> {
    let (_root, store) = store()?;
    let data = common::fixture("1.2.0")?;
    let original = admit(&store, 1, &data)?;
    let (replay, fresh) = store.admit_local_assessment_scan(
        &id(2),
        &data,
        original.request.subjects.clone(),
        original.request.profiles.clone(),
        FreshnessMode::Offline,
        "request-1",
        common::evaluated_at()?,
    )?;
    assert!(!fresh);
    assert_eq!(replay, original);
    assert!(
        store
            .admit_local_assessment_scan(
                &id(2),
                &data,
                vec!["subject".into()],
                vec![Profile::Updates],
                FreshnessMode::Offline,
                "request-1",
                common::evaluated_at()?
            )
            .is_err()
    );
    assert!(
        store
            .inspect_local_assessment_scan("../private-state")
            .is_err()
    );
    assert_eq!(store.local_journal()?.generation, 1);
    let changed = admit(&store, 2, &common::fixture("1.3.0")?)?;
    assert_eq!(
        (changed.generation, changed.request.inventory_revision),
        (2, 2)
    );
    Ok(())
}

#[test]
fn terminal_receipt_and_current_closure_publish_under_one_atomic_index() -> Result<()> {
    let (_root, store) = store()?;
    let data = common::fixture("1.2.0")?;
    let admitted = admit(&store, 1, &data)?;
    assert!(store.local_committed_assessment_closure()?.is_none());
    let running = store.start_local_assessment_scan(&admitted.scan_id)?;
    assert_eq!(running.resource_version, 2);
    let (input, result) = semantic(&data)?;
    let committed = store.commit_local_assessment_scan(
        &admitted.scan_id,
        &input,
        &data,
        &result,
        &ScanUsage::default(),
    )?;
    assert_eq!(committed.state, ScanState::Succeeded);
    assert_eq!(committed.assessment_digest, Some(result.digest()?));
    let before = fs::read(store.repository.join("assessments/journal.json"))?;
    assert_eq!(
        store.inspect_local_assessment_scan(&admitted.scan_id)?,
        committed
    );
    assert_eq!(
        store
            .local_committed_assessment_closure()?
            .expect("retained closure")
            .inventory
            .digest()?,
        data.inventory.digest()?
    );
    assert_eq!(
        store.commit_local_assessment_scan(
            &admitted.scan_id,
            &input,
            &data,
            &result,
            &ScanUsage::default()
        )?,
        committed
    );
    assert_eq!(
        fs::read(store.repository.join("assessments/journal.json"))?,
        before
    );
    let mut changed = result;
    changed.input_digest = Sha256Digest::of_bytes("different input");
    assert!(
        store
            .commit_local_assessment_scan(
                &admitted.scan_id,
                &input,
                &data,
                &changed,
                &ScanUsage::default()
            )
            .is_err()
    );
    let input_path = store
        .repository
        .join("assessments")
        .join(format!("input-{}.json", input.digest()?.hex()));
    fs::remove_file(input_path)?;
    assert!(store.local_committed_assessment_closure().is_err());
    Ok(())
}

#[test]
fn cancellation_fences_new_source_work_and_preserves_the_previous_assessment_head() -> Result<()> {
    let (_root, store) = store()?;
    let previous = common::fixture("1.2.0")?;
    let first = admit(&store, 1, &previous)?;
    store.start_local_assessment_scan(&first.scan_id)?;
    let (input, result) = semantic(&previous)?;
    store.commit_local_assessment_scan(
        &first.scan_id,
        &input,
        &previous,
        &result,
        &ScanUsage::default(),
    )?;
    let previous_assessment = result.digest()?;
    let data = common::fixture("1.3.0")?;
    let second = admit(&store, 2, &data)?;
    let running = store.start_local_assessment_scan(&second.scan_id)?;
    let mut cancel = ScanCancellationV1 {
        schema: "aos.assessment-scan-cancellation/v1".into(),
        scan_id: second.scan_id.clone(),
        expected_revision: 1,
    };
    assert!(store.cancel_local_assessment_scan(&cancel).is_err());
    assert_eq!(
        store.inspect_local_assessment_scan(&second.scan_id)?,
        running
    );
    cancel.expected_revision = running.resource_version;
    let cancelling = store.cancel_local_assessment_scan(&cancel)?;
    assert_eq!(cancelling.state, ScanState::Cancelling);
    assert!(store.cancel_local_assessment_scan(&cancel).is_err());
    let plan = work(&running)?;
    assert!(
        store
            .reserve_local_assessment_source(&plan, &plan.issued_at)
            .is_err()
    );
    assert!(!store.root.join("assessment-budget-github.json").exists());
    let (input, result) = semantic(&data)?;
    let cancelled = store.commit_local_assessment_scan(
        &second.scan_id,
        &input,
        &data,
        &result,
        &ScanUsage::default(),
    )?;
    assert_eq!(
        (cancelled.state, cancelled.assessment_digest),
        (ScanState::Cancelled, None)
    );
    assert_eq!(
        store
            .local_committed_assessment_closure()?
            .expect("previous head")
            .inventory
            .digest()?,
        previous.inventory.digest()?
    );
    assert_eq!(
        store
            .inspect_local_assessment_scan(&first.scan_id)?
            .assessment_digest,
        Some(previous_assessment)
    );
    Ok(())
}

#[test]
fn a_new_admission_supersedes_older_results_without_replacing_their_evidence() -> Result<()> {
    let (_root, store) = store()?;
    let data = common::fixture("1.2.0")?;
    let old = admit(&store, 1, &data)?;
    store.start_local_assessment_scan(&old.scan_id)?;
    let newer = admit(&store, 2, &data)?;
    assert!(
        store
            .require_local_assessment_running(&old.scan_id)
            .is_err()
    );
    let old_plan = work(&store.inspect_local_assessment_scan(&old.scan_id)?)?;
    assert!(
        store
            .reserve_local_assessment_source(&old_plan, &old_plan.issued_at)
            .is_err()
    );
    assert!(!store.root.join("assessment-budget-github.json").exists());
    let (input, result) = semantic(&data)?;
    let stale = store.commit_local_assessment_scan(
        &old.scan_id,
        &input,
        &data,
        &result,
        &ScanUsage::default(),
    )?;
    assert_eq!(stale.state, ScanState::Superseded);
    assert!(store.local_committed_assessment_closure()?.is_none());
    store.start_local_assessment_scan(&newer.scan_id)?;
    let committed = store.commit_local_assessment_scan(
        &newer.scan_id,
        &input,
        &data,
        &result,
        &ScanUsage::default(),
    )?;
    assert_eq!(committed.state, ScanState::Succeeded);
    assert_eq!(committed.generation, 2);
    Ok(())
}

#[test]
fn source_reservations_and_usage_are_fenced_before_physical_execution() -> Result<()> {
    let (_root, store) = store()?;
    let data = common::fixture("1.2.0")?;
    let queued = admit(&store, 1, &data)?;
    let running = store.start_local_assessment_scan(&queued.scan_id)?;
    let plan = work(&running)?;
    let mut wrong = plan.clone();
    wrong.claim.generation += 1;
    assert!(
        store
            .reserve_local_assessment_source(&wrong, &wrong.issued_at)
            .is_err()
    );
    assert!(!store.root.join("assessment-budget-github.json").exists());
    store.reserve_local_assessment_source(&plan, &plan.issued_at)?;
    let spent = store.inspect_local_assessment_scan(&running.scan_id)?;
    assert_eq!((spent.usage.provider_requests, spent.usage.tasks), (1, 1));
    assert!(
        store
            .reserve_local_assessment_source(&plan, &plan.issued_at)
            .is_err()
    );
    assert_eq!(
        store.inspect_local_assessment_scan(&running.scan_id)?,
        spent
    );
    store.consume_local_assessment_bytes(&running.scan_id, 128)?;
    let consumed = store.inspect_local_assessment_scan(&running.scan_id)?;
    assert_eq!(consumed.usage.normalized_bytes, 128);
    assert!(
        store
            .consume_local_assessment_bytes(&running.scan_id, u64::MAX)
            .is_err()
    );
    assert_eq!(
        store.inspect_local_assessment_scan(&running.scan_id)?,
        consumed
    );
    let (input, result) = semantic(&data)?;
    assert!(
        store
            .commit_local_assessment_scan(
                &running.scan_id,
                &input,
                &data,
                &result,
                &ScanUsage::default()
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn explicit_recovery_requires_a_released_process_lease_and_replays_no_mutation() -> Result<()> {
    let (_root, store) = store()?;
    let scan_id = id(1);
    let lease = store.acquire_operation_lease(&scan_id)?;
    let receipt = admit(&store, 1, &common::fixture("1.2.0")?)?;
    store.start_local_assessment_scan(&receipt.scan_id)?;
    assert!(store.recover_local_assessment_scans(100)?.is_empty());
    drop(lease);
    let recovered = store.recover_local_assessment_scans(100)?;
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].state, ScanState::Failed);
    assert_eq!(
        recovered[0].failure_code.as_deref(),
        Some("local-process-interrupted")
    );
    let bytes = fs::read(store.repository.join("assessments/journal.json"))?;
    assert!(store.recover_local_assessment_scans(100)?.is_empty());
    assert_eq!(
        fs::read(store.repository.join("assessments/journal.json"))?,
        bytes
    );
    assert!(store.recover_local_assessment_scans(101).is_err());
    let page = store.list_local_assessment_scans(
        &ScanListQueryV1 {
            schema: "aos.assessment-scan-list-query/v1".into(),
            limit: 1,
            after_scan: None,
        },
        common::evaluated_at()?,
    )?;
    assert_eq!(page.scans[0].state, ScanState::Failed);
    assert_eq!(
        fs::read(store.repository.join("assessments/journal.json"))?,
        bytes
    );
    Ok(())
}
