//! Stable advisory history across new revisions and persistent database reopen.

use anyhow::{Context as _, Result};
use aos_assessment::advisory::{AdvisoryRecordV1, ADVISORY_RECORD_V1};
use aos_assessment_runtime::advisories::retained::{AdvisoryPageV2, AdvisoryQueryV2};
use aos_assessment_runtime::read_snapshot::ScanPageError;
use aos_contract::Sha256Digest;

use super::super::{scans_tests, AssessmentObjectKind};
use crate::db::Database;

async fn add_revision(db: &Database, scope: &str, identity: &str, index: usize) -> Result<()> {
    let record = AdvisoryRecordV1 {
        schema: ADVISORY_RECORD_V1.into(),
        provider: "osv".into(),
        id: format!("OSV-fixture-{index}"),
        modified: "2026-10-08T12:00:00Z".into(),
        withdrawn: Some("2026-10-09T12:00:00Z".into()),
        aliases: vec![identity.into()],
        related: vec![],
        upstream: vec![],
        summary: "Exact retained revision".into(),
        affected: vec![],
        configuration: None,
        severity: vec![],
        references: vec![],
        source_digest: Sha256Digest::of_bytes(format!("raw {index}")),
    };
    let digest = record.digest()?;
    let now = db.assessment_database_time().await?;
    db.put_assessment_object(
        scope,
        AssessmentObjectKind::AdvisoryRecord,
        digest,
        &record.to_bytes()?,
        i64::try_from(now.unix_seconds())?,
    )
    .await?;
    let identity = Sha256Digest::of_canonical("aos.advisory-identity/v1", &identity)?;
    db.backend.execute(
        "INSERT INTO assessment_advisory_identity_index(partition_key, identity_digest, record_digest) VALUES(?1, ?2, ?3)",
        &vals![@slice scope, identity.to_string(), digest.to_string()],
    ).await?;
    Ok(())
}

pub(in crate::db::assessment) async fn qualify_capture(
    database: Database,
) -> Result<(i64, AdvisoryQueryV2, AdvisoryPageV2)> {
    let (db, registry, scan) = scans_tests::setup_database(database).await?;
    let query = AdvisoryQueryV2 {
        schema: "aos.assessment-advisory-query/v2".into(),
        advisory_id: "CVE-2026-12345".into(),
        resource_scope: Some(scan.resource_scope.clone()),
        assessment_digest: None,
        subject_ref: None,
        cursor: None,
        limit: 1,
    };
    for index in 0..3 {
        add_revision(&db, &scan.resource_scope, &query.advisory_id, index).await?;
    }
    let original = db
        .assessment_advisory_capture_records(&scan.resource_scope, &query.advisory_id)
        .await?;
    let first = db
        .assessment_retained_advisory_page(registry, &query)
        .await?
        .context("first advisory page")?;
    assert_eq!(first.page.revisions, original[..1]);
    add_revision(&db, &scan.resource_scope, &query.advisory_id, 99).await?;
    let mut continuation = query.clone();
    continuation.cursor = first.next_cursor.clone();
    let second = db
        .assessment_retained_advisory_page(registry, &continuation)
        .await?
        .context("second advisory page")?;
    assert_eq!(second.page.revisions, original[1..2]);
    assert_eq!(second.page.as_of, first.page.as_of);
    let mut last_query = continuation.clone();
    last_query.cursor = second.next_cursor.clone();
    let last = db
        .assessment_retained_advisory_page(registry, &last_query)
        .await?
        .context("last advisory page")?;
    assert_eq!(last.page.revisions, original[2..]);
    assert!(last.next_cursor.is_none());
    assert!(last.page.revisions[0].record.withdrawn.is_some());
    let mut changed = continuation.clone();
    changed.limit = 2;
    assert!(db
        .assessment_retained_advisory_page(registry, &changed)
        .await
        .is_err());
    let mut changed = continuation.clone();
    changed.advisory_id = "CVE-2026-98765".into();
    assert!(db
        .assessment_retained_advisory_page(registry, &changed)
        .await
        .is_err());
    let mut changed = continuation.clone();
    changed.resource_scope = Some("foreign-incarnation".into());
    assert!(db
        .assessment_retained_advisory_page(registry, &changed)
        .await
        .is_err());
    let current = db
        .assessment_advisory_capture_records(&scan.resource_scope, &query.advisory_id)
        .await?;
    assert_eq!(current.len(), 4);
    Ok((registry, continuation, second))
}

#[tokio::test]
async fn retained_advisory_pages_survive_new_revisions_and_database_reopen() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("advisory.db");
    let (registry, continuation, expected) = qualify_capture(Database::open(&path).await?).await?;
    let reopened = Database::open(&path).await?;
    assert_eq!(
        reopened
            .assessment_retained_advisory_page(registry, &continuation)
            .await?,
        Some(expected)
    );
    Ok(())
}

#[tokio::test]
async fn revision_and_byte_bounds_are_checked_before_advisory_object_reads() -> Result<()> {
    for excessive_rows in [false, true] {
        let (db, registry, request) = scans_tests::setup().await?;
        let advisory = "CVE-2026-12345";
        let identity = Sha256Digest::of_canonical("aos.advisory-identity/v1", &advisory)?;
        for index in 0..if excessive_rows { 129 } else { 1 } {
            let digest = Sha256Digest::of_bytes(format!("uncopied fixture {index}"));
            db.backend.execute(
                "INSERT INTO assessment_advisory_identity_index(partition_key, identity_digest, record_digest) VALUES(?1, ?2, ?3)",
                &vals![@slice request.resource_scope, identity.to_string(), digest.to_string()],
            ).await?;
            if !excessive_rows {
                // Oversized metadata alone must fail before an absent shard is read.
                db.backend.execute(
                    "INSERT INTO assessment_objects(partition_key, object_digest, object_kind, byte_length, shard_count, admitted_at) VALUES(?1, ?2, ?3, ?4, 1, 1)",
                    &vals![@slice request.resource_scope, digest.to_string(), AssessmentObjectKind::AdvisoryRecord.domain(), 9u64 * 1024 * 1024],
                ).await?;
            }
        }
        let query = AdvisoryQueryV2 {
            schema: "aos.assessment-advisory-query/v2".into(),
            advisory_id: advisory.into(),
            resource_scope: Some(request.resource_scope),
            assessment_digest: None,
            subject_ref: None,
            cursor: None,
            limit: 1,
        };
        let error = db
            .assessment_retained_advisory_page(registry, &query)
            .await
            .err()
            .context("capture must refuse its bound")?;
        assert_eq!(
            error.downcast_ref::<ScanPageError>(),
            Some(&ScanPageError::CapacityExceeded)
        );
    }
    Ok(())
}
