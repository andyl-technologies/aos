//! Real assessment heads retained across generation changes and database reopen.

use anyhow::{Context as _, Result};
use aos_assessment::input::Profile;
use aos_assessment::scan_inventory::{InventoryRelationship, RelationshipKind};
use aos_assessment_runtime::application::retained::{parse_status_cursor, StatusQueryV2};
use aos_assessment_runtime::read_snapshot::ScanPageError;
use aos_contract::Sha256Digest;

use super::{AssessmentInventoryAdmission, AssessmentObjectKind};
use crate::db::Database;

pub(super) async fn setup(
    db: Database,
) -> Result<(Database, i64, aos_assessment_runtime::scan::ScanRequestV1)> {
    let (db, registry, mut request) = super::scans_tests::setup_database(db).await?;
    let resource = db
        .assessment_resource(registry)
        .await?
        .context("fixture resource")?;
    let mut data = super::scans_tests::fixture()?;
    let subject = data.inventory.subjects[0].clone();
    let component = data.inventory.components[0].clone();
    data.inventory.subjects.clear();
    data.inventory.components.clear();
    data.inventory.relationships.clear();
    for index in 0..3 {
        let mut subject = subject.clone();
        let mut component = component.clone();
        subject.subject_ref = format!("subject-{index}");
        component.subject_ref = subject.subject_ref.clone();
        component.component_ref = format!("component-{index}");
        subject.component_inventory_digest = component.digest()?;
        data.inventory.relationships.push(InventoryRelationship {
            from_ref: subject.subject_ref.clone(),
            kind: RelationshipKind::Contains,
            to_ref: component.component_ref.clone(),
        });
        data.inventory.subjects.push(subject);
        data.inventory.components.push(component);
    }
    let admitted = db
        .admit_assessment_inventory(
            &AssessmentInventoryAdmission {
                registry_id: registry,
                partition: request.resource_scope.clone(),
                provenance_digest: Sha256Digest::of_bytes("source provenance"),
                admission_digest: Sha256Digest::of_bytes(
                    "three-subject verified fixture admission",
                ),
                expected_resource_version: resource.resource_version,
            },
            &data,
        )
        .await?;
    request.inventory_digest = admitted.inventory_digest;
    request.inventory_revision = admitted.inventory_revision;
    request.policy_digest = admitted.policy_digest;
    request.subjects = data
        .inventory
        .subjects
        .iter()
        .map(|subject| subject.subject_ref.clone())
        .collect();
    Ok((db, registry, request))
}

/// Qualifies immutable capture against genuine committed partial and pending heads.
///
/// # Errors
/// Returns an error for failed fixture admission, evaluation, custody or persistence.
pub(super) async fn retained_heads(
    db: Database,
) -> Result<(
    i64,
    StatusQueryV2,
    aos_assessment_runtime::application::retained::StatusPageV2,
)> {
    let (db, registry, mut request) = setup(db).await?;
    let scan = db.request_assessment_scan(registry, &request).await?;
    let claim = db
        .claim_assessment_scan(registry, &scan.scan_id, 900)
        .await?;
    let data = db.assessment_evaluation_base(registry, &claim).await?;
    let input = db
        .freeze_assessment_evaluation(registry, &claim, &data)
        .await?;
    let assessment = aos_assessment::evaluator::evaluate(&input, &data)?;
    db.commit_assessment_evaluation(registry, &claim, &assessment)
        .await?;
    request.idempotency_key = "pending-generation".into();
    let pending = db.request_assessment_scan(registry, &request).await?;
    let mut query = StatusQueryV2 {
        schema: "aos.assessment-status-query/v2".into(),
        resource_scope: Some(request.resource_scope.clone()),
        profiles: vec![Profile::Updates, Profile::Vulnerabilities],
        limit: 1,
        inventory_digest: None,
        policy_digest: None,
        cursor: None,
    };
    let first = db
        .assessment_retained_status_page(registry, &query)
        .await?
        .context("first capture page")?;
    assert!(first.page.subjects[0].profiles[0].pending);
    assert_eq!(
        first.page.subjects[0].profiles[0].assessment_digest,
        Some(assessment.digest()?)
    );
    assert!(first.page.subjects[0].profiles[1]
        .assessment_digest
        .is_none());
    assert!(!first.page.subjects[0].profiles[1].pending);
    let cursor = first.next_cursor.clone().context("status continuation")?;
    let (digest, _) = parse_status_cursor(&cursor)?;

    db.cancel_assessment_scan(registry, &pending.scan_id, pending.resource_version)
        .await?;
    let mut all = query.clone();
    all.limit = 100;
    let current = db
        .assessment_retained_status_page(registry, &all)
        .await?
        .context("current status")?;
    assert!(current
        .page
        .subjects
        .iter()
        .all(|subject| !subject.profiles[0].pending));
    let mut page = first.clone();
    let mut retained = vec![];
    loop {
        assert_eq!(page.page.as_of, first.page.as_of);
        retained.extend(page.page.subjects.clone());
        let Some(cursor) = page.next_cursor else {
            break;
        };
        query.cursor = Some(cursor);
        page = db
            .assessment_retained_status_page(registry, &query)
            .await?
            .context("retained continuation")?;
    }
    assert_eq!(retained.len(), 3);
    assert!(retained.iter().all(|subject| subject.profiles[0].pending));
    for changed in [
        StatusQueryV2 {
            limit: 2,
            ..query.clone()
        },
        StatusQueryV2 {
            profiles: vec![Profile::Updates],
            ..query.clone()
        },
        StatusQueryV2 {
            resource_scope: Some("foreign".into()),
            ..query.clone()
        },
    ] {
        assert!(db
            .assessment_retained_status_page(registry, &changed)
            .await
            .is_err());
    }
    query.cursor = Some(format!("t1:{}:{}", digest.hex(), "0".repeat(32)));
    assert!(db
        .assessment_retained_status_page(registry, &query)
        .await
        .is_err());
    query.cursor = Some(cursor);
    assert!(db
        .assessment_object(
            &request.resource_scope,
            AssessmentObjectKind::StatusReadSnapshot,
            digest
        )
        .await?
        .is_some());
    Ok((registry, query, first))
}

#[tokio::test]
async fn status_capture_retains_real_heads_across_cancellation_and_reopen() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("status.db");
    let (registry, query, first) = retained_heads(Database::open(&path).await?).await?;
    let reopened = Database::open(&path).await?;
    let page = reopened
        .assessment_retained_status_page(registry, &query)
        .await?
        .context("reopened capture")?;
    assert_eq!(page.page.as_of, first.page.as_of);
    assert!(page.page.subjects[0].profiles[0].pending);
    let (digest, _) = parse_status_cursor(query.cursor.as_deref().context("cursor")?)?;
    reopened
        .backend
        .execute(
            "DELETE FROM assessment_objects WHERE partition_key = ?1 AND object_digest = ?2",
            &vals![@slice query.resource_scope.context("scope")?, digest.to_string()],
        )
        .await?;
    let error = reopened
        .assessment_retained_status_page(
            registry,
            &StatusQueryV2 {
                resource_scope: Some(first.page.resource_scope),
                ..query
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CursorExpired)
    );
    Ok(())
}

#[tokio::test]
async fn pending_unassessed_heads_keep_null_evidence_and_independent_profiles() -> Result<()> {
    let (db, registry, request) = setup(Database::open_in_memory().await?).await?;
    db.request_assessment_scan(registry, &request).await?;
    let query = StatusQueryV2 {
        schema: "aos.assessment-status-query/v2".into(),
        profiles: vec![Profile::Updates, Profile::Vulnerabilities],
        limit: 100,
        resource_scope: None,
        inventory_digest: None,
        policy_digest: None,
        cursor: None,
    };
    let page = db
        .assessment_retained_status_page(registry, &query)
        .await?
        .context("unassessed head capture")?;
    assert_eq!(page.page.subjects.len(), 3);
    assert!(page
        .page
        .subjects
        .iter()
        .all(|subject| subject.profiles[0].pending
            && subject.profiles[0].assessment_digest.is_none()
            && subject.profiles[0].input_digest.is_none()
            && !subject.profiles[0].fresh
            && !subject.profiles[1].pending));
    assert!(page.next_cursor.is_none());
    Ok(())
}

/// Qualifies finite captures and byte admission before corrupt text projection.
///
/// # Errors
/// Returns an error for failed fixture admission or unavailable persistence.
pub(super) async fn storage_bounds(db: Database) -> Result<()> {
    let (db, registry, request) = setup(db).await?;
    let query = StatusQueryV2 {
        schema: "aos.assessment-status-query/v2".into(),
        profiles: vec![Profile::Updates],
        limit: 1,
        resource_scope: Some(request.resource_scope),
        inventory_digest: None,
        policy_digest: None,
        cursor: None,
    };
    for _ in 0..15 {
        db.assessment_retained_status_page(registry, &query)
            .await?
            .context("finite capture")?;
    }
    let (left, right) = tokio::join!(
        db.assessment_retained_status_page(registry, &query),
        db.assessment_retained_status_page(registry, &query)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let exhausted = db
        .assessment_retained_status_page(registry, &query)
        .await
        .unwrap_err();
    assert_eq!(
        exhausted.downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CapacityExceeded)
    );

    // Every cell fits PostgreSQL's character limits and index tuple allowance.
    // Aggregate UTF-8 bytes exceed admission while character counts still fit.
    // Repeated indexed rows simulate corrupt imported metadata; capture must
    // reject the aggregate before interpreting any of those coordinates.
    for first in (0..2200).step_by(50) {
        let statements = (first..first + 50)
            .map(|index| {
                crate::backend::Statement::new(
                    "INSERT INTO assessment_subjects (
                    registry_id, inventory_digest, subject_ref, definition_digest,
                    component_inventory_digest, package_coordinate, package_version,
                    platform, output_name, subject_kind, artifact_digest, source_content_digest)
                 SELECT registry_id, inventory_digest, ?2, definition_digest,
                    component_inventory_digest, ?3, ?4, platform, output_name,
                    subject_kind, artifact_digest, source_content_digest
                 FROM assessment_subjects WHERE registry_id = ?1 AND subject_ref = 'subject-0'",
                    vals![
                        registry,
                        format!("size-bound-{index:04}"),
                        "😀".repeat(400),
                        "v".repeat(400)
                    ],
                )
            })
            .collect::<Vec<_>>();
        db.backend.batch(&statements).await?;
    }
    let oversized = db
        .assessment_retained_status_page(registry, &query)
        .await
        .unwrap_err();
    assert_eq!(
        oversized.downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CapacityExceeded)
    );
    Ok(())
}

#[tokio::test]
async fn status_captures_bound_concurrent_storage_and_multibyte_metadata() -> Result<()> {
    storage_bounds(Database::open_in_memory().await?).await
}
