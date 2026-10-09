//! Database-clock leases, profile isolation and rejected selector/idempotency fences.

use anyhow::{Context as _, Result};
use aos_assessment::input::{EvaluationData, FreshnessMode, Profile};
use aos_assessment_runtime::scan::{SCAN_REQUEST_V1, ScanLimits, ScanRequestV1, ScanState};
use aos_contract::Sha256Digest;
use serde_json::json;

use super::AssessmentInventoryAdmission;
use crate::db::Database;

fn fixture() -> Result<EvaluationData> {
    let source = Sha256Digest::of_bytes("exact admitted source");
    let security = json!({"identities":[{"kind":"ecosystem", "ecosystem":"crates.io", "name":"fixture"}],
        "advisorySources":[{"provider":"osv", "project":"fixture"}], "versionScheme":"semver",
        "dependencyCoverage":{"state":"unknown", "basis":"Source-only inventory"}});
    let current = json!({"upstreamId":"v1.2.0", "comparisonVersion":"1.2.0"});
    let definition: aos_assessment::definition::PackageScanDefinitionV1 = serde_json::from_value(
        json!({
            "schema":aos_assessment::definition::PACKAGE_SCAN_DEFINITION_V1, "unitId":"fixture-1", "family":"fixture", "stream":"1",
            "classification":"automatic", "lifecycle":"supported", "members":["fixture"], "metadataOrigins":["admitted-source"],
            "versionProjection":{"kind":"component-field", "component":"main", "field":"comparisonVersion"},
            "components":[{"componentId":"main", "current":current, "security":security,
                "discovery":{"primary":{"provider":"github-releases", "repository":"example/fixture", "tagPrefix":"v"}, "advisors":[]},
                "releasePolicy":{"strategy":"latest-in-series", "versionScheme":"semver", "seriesMajor":1, "minimumAgeDays":3}}]
        }),
    )?;
    let definition_digest = definition.digest()?;
    let component: aos_assessment::scan_inventory::ComponentInstance = serde_json::from_value(
        json!({
            "componentRef":"component", "componentId":"main", "subjectRef":"subject", "current":current,
            "security":security, "scanDefinitionDigest":definition_digest, "sourceContentDigest":source
        }),
    )?;
    Ok(EvaluationData {
        inventory: serde_json::from_value(
            json!({"schema":aos_assessment::scan_inventory::SCAN_INVENTORY_V1,
            "subjects":[{"subjectRef":"subject", "packageCoordinate":"fixture/example", "version":"1.2.0",
                "platform":"x86_64-linux", "output":"source", "kind":"source", "sourceContentDigest":source,
                "scanDefinitionDigest":definition_digest, "componentInventoryDigest":component.digest()?}],
            "components":[component], "relationships":[{"fromRef":"subject", "kind":"contains", "toRef":"component"}],
            "coverage":{"state":"unknown", "basis":"Source-only inventory"}}),
        )?,
        definitions: vec![definition],
        upstream: vec![],
        advisory_snapshot: None,
        advisories: vec![],
        dispositions: vec![],
        history: vec![],
        policy: serde_json::from_value(
            json!({"schema":aos_assessment::input::ASSESSMENT_POLICY_V1,
            "upstreamMaxAgeSeconds":86400, "advisoryMaxAgeSeconds":86400,
            "requiredAdvisorySources":[], "requireDependencyCoverage":true}),
        )?,
    })
}

pub(super) async fn setup() -> Result<(Database, i64, ScanRequestV1)> {
    let db = Database::open_in_memory().await?;
    setup_database(db).await
}

pub(super) async fn setup_database(db: Database) -> Result<(Database, i64, ScanRequestV1)> {
    let slug = format!("assessment-fixture-{}", uuid::Uuid::new_v4().simple());
    let registry_id = db.register_registry(&slug, &[], false).await?;
    let registry = db
        .registry_by_id(registry_id)
        .await?
        .context("fixture registry")?;
    let data = fixture()?;
    let resource = db
        .admit_assessment_inventory(
            &AssessmentInventoryAdmission {
                registry_id,
                partition: registry.scope_key.clone(),
                provenance_digest: Sha256Digest::of_bytes("source provenance"),
                admission_digest: Sha256Digest::of_bytes("verified admission"),
                expected_resource_version: 0,
            },
            &data,
        )
        .await?;
    Ok((
        db,
        registry_id,
        ScanRequestV1 {
            schema: SCAN_REQUEST_V1.into(),
            resource_scope: registry.scope_key,
            authorization_partition: resource.partition,
            inventory_revision: resource.inventory_revision,
            inventory_digest: resource.inventory_digest,
            policy_digest: resource.policy_digest,
            subjects: vec!["subject".into()],
            profiles: vec![Profile::Updates],
            freshness: FreshnessMode::Offline,
            trigger: "manual".into(),
            actor_ref: "fixture-authenticated-actor".into(),
            idempotency_key: "first".into(),
            limits: ScanLimits::default(),
        },
    ))
}

#[tokio::test]
async fn simultaneous_identical_requests_replay_one_committed_operation() -> Result<()> {
    let (db, registry_id, request) = setup().await?;
    let (left, right) = tokio::join!(
        db.request_assessment_scan(registry_id, &request),
        db.request_assessment_scan(registry_id, &request),
    );
    let left = left?;
    let right = right?;
    assert_eq!(left.scan_id, right.scan_id);
    assert!(left.admission_complete && right.admission_complete);
    assert_eq!(
        db.assessment_resource(registry_id)
            .await?
            .context("resource")?
            .next_generation,
        2
    );
    Ok(())
}

#[tokio::test]
async fn immutable_request_replay_does_not_allocate_a_new_generation_and_changed_content_conflicts()
-> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    let first = db.request_assessment_scan(registry_id, &request).await?;
    let replay = db.request_assessment_scan(registry_id, &request).await?;
    assert_eq!(first.scan_id, replay.scan_id);
    assert_eq!(first.generation, replay.generation);
    assert!(replay.admission_complete);
    assert_eq!(
        db.assessment_resource(registry_id)
            .await?
            .context("resource")?
            .next_generation,
        2
    );
    request.profiles = vec![Profile::Vulnerabilities];
    assert!(
        db.request_assessment_scan(registry_id, &request)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn invalid_selector_and_cross_registry_scope_do_not_allocate_generations() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    request.subjects = vec!["not-in-the-admitted-inventory".into()];
    assert!(
        db.request_assessment_scan(registry_id, &request)
            .await
            .is_err()
    );
    request.subjects = vec!["subject".into()];
    request.resource_scope = "registry:00000000000000000000000000000000".into();
    assert!(
        db.request_assessment_scan(registry_id, &request)
            .await
            .is_err()
    );
    assert_eq!(
        db.assessment_resource(registry_id)
            .await?
            .context("resource")?
            .next_generation,
        1
    );
    Ok(())
}

#[tokio::test]
async fn newer_request_supersedes_only_the_same_subject_profile() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    let updates = db.request_assessment_scan(registry_id, &request).await?;
    request.profiles = vec![Profile::Vulnerabilities];
    request.idempotency_key = "vulnerability-first".into();
    let vulnerabilities = db.request_assessment_scan(registry_id, &request).await?;
    let updates_claim = db
        .claim_assessment_scan(registry_id, &updates.scan_id, 30)
        .await?;
    assert_eq!(updates_claim.generation, updates.generation);
    request.idempotency_key = "vulnerability-next".into();
    let next = db.request_assessment_scan(registry_id, &request).await?;
    assert!(
        db.claim_assessment_scan(registry_id, &vulnerabilities.scan_id, 30)
            .await
            .is_err()
    );
    assert_eq!(
        db.claim_assessment_scan(registry_id, &next.scan_id, 30)
            .await?
            .generation,
        next.generation
    );
    Ok(())
}

#[tokio::test]
async fn exclusive_lease_rejects_a_second_claim_and_cancellation_is_terminal() -> Result<()> {
    let (db, registry_id, request) = setup().await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 30)
        .await?;
    claim.validate_at(&db.assessment_database_time().await?)?;
    db.check_assessment_scan_claim(registry_id, &claim).await?;
    assert!(
        db.claim_assessment_scan(registry_id, &scan.scan_id, 30)
            .await
            .is_err()
    );
    let running = db
        .assessment_scan(registry_id, &scan.scan_id)
        .await?
        .context("running scan")?;
    assert!(
        db.cancel_assessment_scan(registry_id, &scan.scan_id, scan.resource_version)
            .await
            .is_err()
    );
    db.cancel_assessment_scan(registry_id, &scan.scan_id, running.resource_version)
        .await?;
    assert!(
        db.check_assessment_scan_claim(registry_id, &claim)
            .await
            .is_err()
    );
    assert_eq!(
        db.assessment_scan(registry_id, &scan.scan_id)
            .await?
            .context("cancelled scan")?
            .state,
        ScanState::Cancelled
    );
    assert!(
        db.claim_assessment_scan(registry_id, &scan.scan_id, 30)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn reclaimed_operation_rejects_the_old_attempt_even_when_its_client_deadline_is_later()
-> Result<()> {
    let (db, registry_id, request) = setup().await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let old = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 30)
        .await?;
    let expired = db.assessment_database_time().await?.unix_seconds() - 1;
    db.backend
        .execute(
            "UPDATE assessment_scans SET lease_expires_at = ?2 WHERE scan_id = ?1",
            &vals![@slice scan.scan_id, expired],
        )
        .await?;
    assert!(
        db.check_assessment_scan_claim(registry_id, &old)
            .await
            .is_err()
    );
    let current = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 30)
        .await?;
    assert_eq!(current.attempt, old.attempt + 1);
    assert_ne!(current.claim_token, old.claim_token);
    assert!(
        db.check_assessment_scan_claim(registry_id, &old)
            .await
            .is_err()
    );
    db.check_assessment_scan_claim(registry_id, &current)
        .await?;
    db.backend.execute("UPDATE assessment_resources SET authorization_revision = authorization_revision + 1 WHERE registry_id = ?1",
        &vals![@slice registry_id]).await?;
    assert!(
        db.check_assessment_scan_claim(registry_id, &current)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn policy_replacement_fences_old_work_without_rewriting_inventory_or_history() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let claim = db
        .claim_assessment_scan(registry_id, &scan.scan_id, 300)
        .await?;
    let previous = db
        .assessment_resource(registry_id)
        .await?
        .context("previous policy")?;
    let mut policy = fixture()?.policy;
    policy.upstream_max_age_seconds = 3600;
    let current = db
        .set_assessment_policy(
            registry_id,
            &previous.partition,
            previous.resource_version,
            &policy,
        )
        .await?;
    assert_eq!(current.inventory_digest, previous.inventory_digest);
    assert_eq!(current.inventory_revision, previous.inventory_revision);
    assert_eq!(current.next_generation, previous.next_generation);
    assert_ne!(current.policy_digest, previous.policy_digest);
    assert!(
        db.check_assessment_scan_claim(registry_id, &claim)
            .await
            .is_err()
    );
    assert!(
        db.set_assessment_policy(
            registry_id,
            &previous.partition,
            previous.resource_version,
            &policy
        )
        .await
        .is_err()
    );
    assert_eq!(
        db.request_assessment_scan(registry_id, &request)
            .await?
            .scan_id,
        scan.scan_id
    );
    request.policy_digest = current.policy_digest;
    request.idempotency_key = "new-policy".into();
    let next = db.request_assessment_scan(registry_id, &request).await?;
    db.claim_assessment_scan(registry_id, &next.scan_id, 300)
        .await?;
    assert_eq!(
        db.assessment_scan(registry_id, &scan.scan_id)
            .await?
            .context("immutable old request")?
            .request
            .policy_digest,
        previous.policy_digest
    );
    Ok(())
}
