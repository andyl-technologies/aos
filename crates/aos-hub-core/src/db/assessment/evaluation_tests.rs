//! Frozen replay, result reproduction and atomic profile-head authority tests.

use anyhow::{Context as _, Result};
use aos_assessment::input::Profile;
use aos_assessment_runtime::scan::ScanState;

use super::scans_tests::setup;

#[tokio::test]
async fn offline_vulnerability_acquisition_pins_absent_sources_as_unknown_coverage() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    request.profiles = vec![Profile::Vulnerabilities];
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 60)
        .await?;
    let data = db.assessment_evaluation_base(registry_id, &claim).await?;
    assert!(
        data.advisory_snapshot
            .as_ref()
            .context("explicit missing-source snapshot")?
            .sources
            .is_empty()
    );
    let input = db
        .freeze_assessment_evaluation(registry_id, &claim, &data)
        .await?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    assert_eq!(
        result.coverage,
        aos_assessment::security::CoverageState::Unknown
    );
    assert!(result.subject_results[0].findings.is_empty());
    db.commit_assessment_evaluation(registry_id, &claim, &result)
        .await?;
    let status = db
        .assessment_status_page(registry_id, &request.profiles, "", 100)
        .await?;
    assert!(!status.subjects[0].profiles[0].fresh);
    assert_eq!(
        db.assessment_alert_page(registry_id, "", 100).await?.len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn pinned_evaluation_replays_and_unknown_coverage_is_not_a_clean_result() -> Result<()> {
    let (db, registry_id, request) = setup().await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 60)
        .await?;
    let data = db.assessment_evaluation_base(registry_id, &claim).await?;
    let input = db
        .freeze_assessment_evaluation(registry_id, &claim, &data)
        .await?;
    assert_eq!(
        db.freeze_assessment_evaluation(registry_id, &claim, &data)
            .await?,
        input
    );
    assert_eq!(
        db.assessment_frozen_evaluation(registry_id, &scan.scan_id)
            .await?,
        (input.clone(), data.clone())
    );
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    assert_eq!(
        result.coverage,
        aos_assessment::security::CoverageState::Unknown
    );
    assert_eq!(
        aos_assessment_runtime::status::profile_freshness_deadline(
            &input,
            &data,
            &result.subject_results[0].coverage[0]
        )?,
        None
    );
    let attention = aos_assessment_runtime::attention::project(&input, &data, &result)?;
    assert_eq!(attention.len(), 1);
    assert_eq!(attention[0].issues.len(), 1);
    assert_eq!(
        attention[0].issues[0].family,
        aos_assessment_runtime::alerts::IssueFamily::Coverage
    );
    assert!(attention[0].issues[0].uncertain);
    assert!(attention[0].proofs.is_empty());
    assert!(
        aos_assessment::evaluator::ScopeGraph::new(&data)?
            .components("absent")
            .is_err()
    );
    db.commit_assessment_evaluation(registry_id, &claim, &result)
        .await?;
    db.commit_assessment_evaluation(registry_id, &claim, &result)
        .await?;
    let completed = db
        .assessment_scan(registry_id, &scan.scan_id)
        .await?
        .context("completed scan")?;
    assert_eq!(completed.state, ScanState::Partial);
    assert_eq!(completed.assessment_digest, Some(result.digest()?));
    assert!(db.has_admitted_assessment(registry_id, result.digest()?).await?);
    let head = db
        .backend
        .query_opt(
            "SELECT desired_generation, committed_generation, assessment_digest, validated_until
         FROM assessment_heads WHERE registry_id = ?1 AND profile = 'updates'",
            &vals![@slice registry_id],
        )
        .await?
        .context("profile head")?;
    assert_eq!(head.get::<u64>(0)?, scan.generation);
    assert_eq!(head.get::<u64>(1)?, scan.generation);
    assert_eq!(head.get::<String>(2)?, result.digest()?.to_string());
    assert_eq!(head.get::<Option<i64>>(3)?, None);
    assert!(
        db.check_assessment_scan_claim(registry_id, &claim)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn forged_result_and_changed_frozen_evidence_cannot_advance_heads() -> Result<()> {
    let (db, registry_id, request) = setup().await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 60)
        .await?;
    let mut data = db.assessment_evaluation_base(registry_id, &claim).await?;
    let input = db
        .freeze_assessment_evaluation(registry_id, &claim, &data)
        .await?;
    let mut result = aos_assessment::evaluator::evaluate(&input, &data)?;
    result.diagnostics.clear();
    assert!(
        db.commit_assessment_evaluation(registry_id, &claim, &result)
            .await
            .is_err()
    );
    data.history.push(aos_assessment::input::CandidateHistory {
        provider: "github-releases".into(),
        project: "example/fixture".into(),
        raw_id: "v1.2.0".into(),
        first_observed_at: input.evaluated_at.clone(),
    });
    assert!(
        db.freeze_assessment_evaluation(registry_id, &claim, &data)
            .await
            .is_err()
    );
    let head = db
        .backend
        .query_opt(
            "SELECT committed_generation FROM assessment_heads WHERE registry_id = ?1",
            &vals![@slice registry_id],
        )
        .await?
        .context("uncommitted head")?;
    assert_eq!(head.get::<u64>(0)?, 0);
    Ok(())
}

#[tokio::test]
async fn one_superseded_profile_rolls_back_all_profile_heads() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    request.profiles = vec![Profile::LicenseSignals, Profile::Updates];
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 60)
        .await?;
    let data = db.assessment_evaluation_base(registry_id, &claim).await?;
    let input = db
        .freeze_assessment_evaluation(registry_id, &claim, &data)
        .await?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    request.idempotency_key = "newer-updates-only".into();
    request.profiles = vec![Profile::Updates];
    db.request_assessment_scan(registry_id, &request).await?;
    assert!(
        db.commit_assessment_evaluation(registry_id, &claim, &result)
            .await
            .is_err()
    );
    let rows = db
        .backend
        .query(
            "SELECT committed_generation FROM assessment_heads WHERE registry_id = ?1",
            &vals![@slice registry_id],
        )
        .await?;
    assert_eq!(rows.len(), 2);
    for head in rows {
        assert_eq!(head.get::<u64>(0)?, 0);
    }
    assert_eq!(
        db.assessment_scan(registry_id, &scan.scan_id)
            .await?
            .context("uncommitted operation")?
            .state,
        ScanState::Running
    );
    Ok(())
}

#[tokio::test]
async fn vulnerability_attention_retains_partial_positive_evidence_without_unrelated_query_support()
-> Result<()> {
    use aos_assessment::advisory::{
        ADVISORY_SNAPSHOT_V1, AdvisorySnapshotSource, AdvisorySnapshotV1,
    };
    use aos_assessment::observation::{
        PROVIDER_OBSERVATION_V1, ProviderCoverage, ProviderObservationV1, SourceEvidenceRef,
    };
    use aos_assessment::time::Timestamp;
    use aos_contract::Sha256Digest;

    let (db, registry_id, mut request) = setup().await?;
    request.profiles = vec![Profile::Vulnerabilities];
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 60)
        .await?;
    let mut data = db.assessment_evaluation_base(registry_id, &claim).await?;
    let raw = serde_json::to_vec(&serde_json::json!({
        "schema_version":"1.9.1", "id":"OSV-2026-1", "modified":"2026-10-08T12:00:00Z",
        "aliases":["CVE-2026-12345"], "summary":"Fixture affected release",
        "affected":[{"package":{"ecosystem":"crates.io", "name":"fixture"},
            "ranges":[{"type":"SEMVER", "events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]
    }))?;
    let record = aos_assessment_providers::osv::record(&raw)?;
    let now = db.assessment_database_time().await?;
    let payload_digest =
        Sha256Digest::of_canonical("aos.advisory-record-set/v1", &[record.digest()?])?;
    let sources = ["fixture", "unrelated-fixture"]
        .into_iter()
        .map(|project| {
            Ok(AdvisorySnapshotSource {
                provider: "osv".into(),
                project: project.into(),
                record_digests: vec![record.digest()?],
                observation: ProviderObservationV1 {
                    schema: PROVIDER_OBSERVATION_V1.into(),
                    provider: "osv".into(),
                    project: project.into(),
                    adapter_version: aos_assessment_providers::osv::ADAPTER_VERSION.into(),
                    request_identity_digest: Sha256Digest::of_bytes(project),
                    retrieved_at: now.clone(),
                    validated_at: now.clone(),
                    expires_at: Timestamp::from_unix_seconds(now.unix_seconds() + 86400)?,
                    response_digest: Sha256Digest::of_bytes(&raw),
                    payload_digest,
                    validators: None,
                    coverage: ProviderCoverage::Complete {
                        proof: "exhausted-query".into(),
                    },
                    source_refs: vec![SourceEvidenceRef {
                        digest: Sha256Digest::of_bytes(&raw),
                        byte_length: raw.len() as u64,
                        origin: "osv".into(),
                    }],
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    data.advisories = vec![record];
    data.advisory_snapshot = Some(AdvisorySnapshotV1 {
        schema: ADVISORY_SNAPSHOT_V1.into(),
        sources,
        exploit_catalog: None,
    });
    let input = data.freeze_selected(request.profiles, request.subjects, now)?;
    let assessment = aos_assessment::evaluator::evaluate(&input, &data)?;
    assert_eq!(assessment.subject_results[0].findings.len(), 1);
    let projected = aos_assessment_runtime::attention::project(&input, &data, &assessment)?;
    let issue = projected[0]
        .issues
        .iter()
        .find(|issue| issue.family == aos_assessment_runtime::alerts::IssueFamily::Vulnerability)
        .context("positive vulnerability attention")?;
    assert!(issue.uncertain);
    assert_eq!(
        issue.source_keys,
        vec![aos_assessment_runtime::attention::source_key(
            "osv", "fixture"
        )?]
    );
    assert_eq!(issue.lineage_ids, vec!["CVE-2026-12345", "OSV-2026-1"]);
    assert!(
        !projected[0]
            .proofs
            .iter()
            .any(|proof| proof.context_digest == issue.context_digest)
    );
    Ok(())
}
