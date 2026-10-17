//! Stable advisory history across new revisions and persistent database reopen.

use anyhow::{ensure, Context as _, Result};
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
        &serde_json::to_vec(&record)?,
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

/// Uses an isolated transport; public service IAM is qualified independently.
#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_CLI pointing to the packaged aos binary"]
async fn actual_cli_retains_advisory_revisions_across_database_reopen() -> Result<()> {
    use aos_proto_types as pb;
    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[derive(Clone)]
    struct Fixture {
        db: Arc<RwLock<Arc<Database>>>,
        registry: i64,
        scope: String,
    }

    async fn read(
        State(fixture): State<Fixture>,
        Json(request): Json<pb::AssessmentControlRequest>,
    ) -> std::result::Result<
        Json<pb::AssessmentDocumentResponse>,
        (StatusCode, Json<serde_json::Value>),
    > {
        let result = async {
            ensure!(
                request.registry_slug == "fixture",
                "foreign fixture registry"
            );
            let query = AdvisoryQueryV2::from_slice(&request.document_json)?;
            ensure!(
                query.resource_scope.as_ref() == Some(&fixture.scope),
                "foreign fixture scope"
            );
            let db = fixture.db.read().await.clone();
            let page = db
                .assessment_retained_advisory_page(fixture.registry, &query)
                .await?
                .context("fixture advisory selection")?;
            Ok::<_, anyhow::Error>(Json(pb::AssessmentDocumentResponse {
                document_json: page.to_bytes()?,
            }))
        }
        .await;
        result.map_err(|error| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "failed_precondition", "message": error.to_string()
                })),
            )
        })
    }

    async fn cli(
        binary: &std::ffi::OsStr,
        hub: &str,
        scope: &str,
        cursor: Option<&str>,
        limit: &str,
        okay: bool,
    ) -> Result<Option<AdvisoryPageV2>> {
        let mut command = tokio::process::Command::new(binary);
        command.args([
            "--json",
            "hub",
            "maintain",
            "cve",
            "CVE-2026-12345",
            "--hub",
            hub,
            "--token",
            "public-fixture-token",
            "--registry",
            "fixture",
            "--resource-scope",
            scope,
            "--retained",
            "--limit",
            limit,
        ]);
        if let Some(cursor) = cursor {
            command.args(["--cursor", cursor]);
        }
        let output = command.output().await?;
        ensure!(
            output.status.success() == okay,
            "CLI status differed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if !okay {
            return Ok(None);
        }
        let wrapper: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        ensure!(
            wrapper["schema_version"] == "aos.hub.cli/v1"
                && wrapper["kind"] == "assessment-advisory",
            "CLI wrapper changed"
        );
        let bytes = serde_json::to_vec(&wrapper["data"])?;
        Ok(Some(AdvisoryPageV2::from_slice(&bytes)?))
    }

    let binary = std::env::var_os("AOS_ASSESSMENT_CLI").context("packaged aos CLI required")?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("advisory-cli.db");
    let (db, registry, scan) = scans_tests::setup_database(Database::open(&path).await?).await?;
    for index in 0..3 {
        add_revision(&db, &scan.resource_scope, "CVE-2026-12345", index).await?;
    }
    let original = db
        .assessment_advisory_capture_records(&scan.resource_scope, "CVE-2026-12345")
        .await?;
    let fixture = Fixture {
        db: Arc::new(RwLock::new(Arc::new(db))),
        registry,
        scope: scan.resource_scope.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hub = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route(pb::ASSESSMENT_SERVICE_GET_ADVISORY_PATH, post(read))
        .with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await });

    let first = cli(&binary, &hub, &fixture.scope, None, "1", true)
        .await?
        .context("first CLI page")?;
    assert_eq!(first.page.revisions, original[..1]);
    let cursor = first
        .next_cursor
        .as_deref()
        .context("retained CLI cursor")?;
    {
        let db = fixture.db.read().await.clone();
        add_revision(&db, &fixture.scope, "CVE-2026-12345", 99).await?;
    }
    *fixture.db.write().await = Arc::new(Database::open(&path).await?);
    let second = cli(&binary, &hub, &fixture.scope, Some(cursor), "1", true)
        .await?
        .context("second CLI page")?;
    assert_eq!(second.page.revisions, original[1..2]);
    assert_eq!(second.page.as_of, first.page.as_of);
    assert_eq!(second.expires_at, first.expires_at);
    let last = cli(
        &binary,
        &hub,
        &fixture.scope,
        second.next_cursor.as_deref(),
        "1",
        true,
    )
    .await?
    .context("last CLI page")?;
    assert_eq!(last.page.revisions, original[2..]);
    assert!(last.next_cursor.is_none());
    assert!(last.page.revisions[0].record.withdrawn.is_some());
    cli(&binary, &hub, &fixture.scope, Some(cursor), "2", false).await?;
    cli(
        &binary,
        &hub,
        "foreign-incarnation",
        Some(cursor),
        "1",
        false,
    )
    .await?;
    let mut forged = cursor.to_owned();
    forged.replace_range(68..100, "00000000000000000000000000000000");
    cli(&binary, &hub, &fixture.scope, Some(&forged), "1", false).await?;
    let (digest, _) = aos_assessment_runtime::advisories::retained::parse_advisory_cursor(cursor)?;
    fixture
        .db
        .read()
        .await
        .backend
        .execute(
            "DELETE FROM assessment_objects WHERE partition_key = ?1 AND object_digest = ?2",
            &vals![@slice fixture.scope, digest.to_string()],
        )
        .await?;
    cli(&binary, &hub, &fixture.scope, Some(cursor), "1", false).await?;
    server.abort();
    println!(
        "PASS: actual CLI retained advisory revisions survive new evidence and database reopen"
    );
    Ok(())
}
