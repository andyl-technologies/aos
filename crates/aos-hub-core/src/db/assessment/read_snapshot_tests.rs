//! Retained pagination across concurrent scan mutation and bounded storage.

use anyhow::{Context as _, Result};
use aos_assessment_runtime::control::ScanListV1;
use aos_assessment_runtime::read_snapshot::{parse_scan_cursor, SCAN_READ_SNAPSHOT_V1};
use aos_assessment_runtime::scan::ScanState;

use super::scans_tests::setup;
use crate::db::Database;

#[tokio::test]
async fn scan_pages_retain_mutated_and_new_rows_without_cross_scope_replay() -> Result<()> {
    let (db, registry_id, request) = setup().await?;
    retained_pages(&db, registry_id, request).await
}

pub(super) async fn retained_pages(
    db: &Database,
    registry_id: i64,
    mut request: aos_assessment_runtime::scan::ScanRequestV1,
) -> Result<()> {
    for key in ["snapshot-a", "snapshot-b", "snapshot-c"] {
        request.idempotency_key = key.into();
        db.request_assessment_scan(registry_id, &request).await?;
    }
    let scope = request.resource_scope.clone();
    let initial = db.assessment_scan_summaries(registry_id, "", 100).await?;
    let first = db
        .assessment_retained_scan_page(registry_id, &scope, 1, None)
        .await?;
    let cursor = first.next_scan.clone().context("first continuation")?;
    let (digest, _) = parse_scan_cursor(&cursor)?;

    // A new scan and changed existing states must not affect this capture.
    request.idempotency_key = "snapshot-new".into();
    db.request_assessment_scan(registry_id, &request).await?;
    db.backend.execute("UPDATE assessment_scans SET state = 'cancelled', completed_at = created_at, resource_version = resource_version + 1 WHERE registry_id = ?1", &vals![@slice registry_id]).await?;
    let mut page = first.clone();
    let mut retained = Vec::new();
    loop {
        assert_eq!(page.as_of, first.as_of);
        retained.extend(page.scans.clone());
        let Some(cursor) = page.next_scan else {
            break;
        };
        page = db
            .assessment_retained_scan_page(registry_id, &scope, 1, Some(&cursor))
            .await?;
        assert_eq!(ScanListV1::from_slice(&page.to_bytes()?)?, page);
    }
    assert_eq!(retained.len(), initial.len());
    for (row, expected) in retained.iter().zip(initial) {
        assert_eq!(row.scan_id, expected.scan_id);
        assert_eq!(row.state, ScanState::Queued);
        assert_eq!(row.resource_version, expected.resource_version);
    }
    let current = db
        .assessment_retained_scan_page(registry_id, &scope, 100, None)
        .await?;
    assert_eq!(current.scans.len(), retained.len() + 1);
    assert!(current
        .scans
        .iter()
        .all(|row| row.state == ScanState::Cancelled));
    assert!(db
        .assessment_retained_scan_page(registry_id, &scope, 2, Some(&cursor))
        .await
        .is_err());
    assert!(db
        .assessment_retained_scan_page(registry_id, "foreign", 1, Some(&cursor))
        .await
        .is_err());
    assert!(db
        .assessment_retained_scan_page(registry_id, &scope, 1, Some("raw-operation-id"))
        .await
        .is_err());
    let mut forged = cursor.clone();
    forged.replace_range(68..100, "00000000000000000000000000000000");
    assert!(db
        .assessment_retained_scan_page(registry_id, &scope, 1, Some(&forged))
        .await
        .is_err());

    db.backend
        .execute(
            "DELETE FROM assessment_objects WHERE partition_key = ?1 AND object_digest = ?2",
            &vals![@slice scope, digest.to_string()],
        )
        .await?;
    let error = db
        .assessment_retained_scan_page(registry_id, &scope, 1, Some(&cursor))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("cursor-expired"));
    Ok(())
}

#[tokio::test]
async fn retained_scan_storage_is_bounded_and_prunes_expired_custody() -> Result<()> {
    let (db, registry_id, mut request) = setup().await?;
    storage_bounds(&db, registry_id, &mut request).await
}

pub(super) async fn storage_bounds(
    db: &Database,
    registry_id: i64,
    request: &mut aos_assessment_runtime::scan::ScanRequestV1,
) -> Result<()> {
    db.request_assessment_scan(registry_id, &request).await?;
    request.idempotency_key = "second-scan".into();
    db.request_assessment_scan(registry_id, &request).await?;
    let scope = request.resource_scope.clone();
    for _ in 0..14 {
        db.assessment_retained_scan_page(registry_id, &scope, 1, None)
            .await?;
    }
    let results = tokio::join!(
        db.assessment_retained_scan_page(registry_id, &scope, 1, None),
        db.assessment_retained_scan_page(registry_id, &scope, 1, None),
        db.assessment_retained_scan_page(registry_id, &scope, 1, None),
        db.assessment_retained_scan_page(registry_id, &scope, 1, None)
    );
    assert_eq!(
        [results.0, results.1, results.2, results.3]
            .into_iter()
            .filter(Result::is_ok)
            .count(),
        2
    );
    assert!(db
        .assessment_retained_scan_page(registry_id, &scope, 1, None)
        .await
        .is_err());
    let count = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
            &vals![@slice scope, SCAN_READ_SNAPSHOT_V1],
        )
        .await?
        .context("count")?
        .get::<u64>(0)?;
    assert_eq!(count, 16);
    db.backend.execute("UPDATE assessment_objects SET admitted_at = 0 WHERE partition_key = ?1 AND object_kind = ?2", &vals![@slice scope, SCAN_READ_SNAPSHOT_V1]).await?;
    db.assessment_retained_scan_page(registry_id, &scope, 1, None)
        .await?;
    let count = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
            &vals![@slice scope, SCAN_READ_SNAPSHOT_V1],
        )
        .await?
        .context("count")?
        .get::<u64>(0)?;
    assert_eq!(count, 1);
    Ok(())
}

/// Uses a closed transport fixture because production assessment IAM is separately gated.
#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_CLI pointing to the packaged aos binary"]
async fn actual_cli_retains_scan_pages_across_database_reopen() -> Result<()> {
    use aos_proto_types as pb;
    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[derive(Clone)]
    struct Fixture {
        db: Arc<RwLock<Arc<Database>>>,
        registry_id: i64,
        scope: String,
    }

    async fn list(
        State(fixture): State<Fixture>,
        Json(request): Json<pb::AssessmentControlRequest>,
    ) -> std::result::Result<
        Json<pb::AssessmentDocumentResponse>,
        (StatusCode, Json<serde_json::Value>),
    > {
        let result = async {
            anyhow::ensure!(
                request.registry_slug == "fixture",
                "foreign fixture registry"
            );
            let query = aos_assessment_runtime::control::ScanListQueryV1::from_slice(
                &request.document_json,
            )?;
            let db = fixture.db.read().await.clone();
            let page = db
                .assessment_retained_scan_page(
                    fixture.registry_id,
                    &fixture.scope,
                    query.limit,
                    query.after_scan.as_deref(),
                )
                .await?;
            Ok::<_, anyhow::Error>(Json(pb::AssessmentDocumentResponse {
                document_json: page.to_bytes()?,
            }))
        }
        .await;
        result.map_err(|error| {
            (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"code":"failed_precondition", "message":error.to_string()}),
                ),
            )
        })
    }

    async fn cli(
        binary: &std::ffi::OsStr,
        hub: &str,
        cursor: Option<&str>,
        okay: bool,
    ) -> Result<serde_json::Value> {
        let mut command = tokio::process::Command::new(binary);
        command.args([
            "--json",
            "hub",
            "maintain",
            "scans",
            "list",
            "--hub",
            hub,
            "--token",
            "public-fixture-token",
            "--registry",
            "fixture",
            "--limit",
            "1",
        ]);
        if let Some(cursor) = cursor {
            command.args(["--after-scan", cursor]);
        }
        let output = command.output().await?;
        anyhow::ensure!(
            output.status.success() == okay,
            "CLI status differed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if !okay {
            return Ok(serde_json::Value::Null);
        }
        Ok(serde_json::from_slice(&output.stdout)?)
    }

    let binary = std::env::var_os("AOS_ASSESSMENT_CLI").context("packaged aos CLI required")?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("hub.db");
    let (db, registry_id, mut request) =
        super::scans_tests::setup_database(Database::open(&path).await?).await?;
    for key in ["cli-page-a", "cli-page-b", "cli-page-c"] {
        request.idempotency_key = key.into();
        db.request_assessment_scan(registry_id, &request).await?;
    }
    let original = db.assessment_scan_summaries(registry_id, "", 100).await?;
    let fixture = Fixture {
        db: Arc::new(RwLock::new(Arc::new(db))),
        registry_id,
        scope: request.resource_scope.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hub = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route("/aos.hub.v1.ScanService/ListScans", post(list))
        .with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result = async {
        let first = cli(&binary, &hub, None, true).await?;
        let first_data = &first["data"];
        let cursor = first_data["nextScan"].as_str().context("opaque continuation")?.to_owned();
        parse_scan_cursor(&cursor)?;
        {
            let current = fixture.db.read().await.clone();
            current.backend.execute("UPDATE assessment_scans SET state = 'cancelled', completed_at = created_at, resource_version = resource_version + 1 WHERE registry_id = ?1", &vals![@slice registry_id]).await?;
            request.idempotency_key = "cli-after-capture".into();
            current.request_assessment_scan(registry_id, &request).await?;
        }
        // Reopening proves the continuation belongs to SQL custody, rather
        // than an HTTP process's heap or a re-executed moving query.
        *fixture.db.write().await = Arc::new(Database::open(&path).await?);
        let mut ids = vec![first_data["scans"][0]["scanId"].as_str().context("first ID")?.to_owned()];
        let mut next = Some(cursor.clone());
        while let Some(cursor) = next {
            let page = cli(&binary, &hub, Some(&cursor), true).await?;
            assert_eq!(page["data"]["asOf"], first_data["asOf"]);
            assert_eq!(page["data"]["scans"][0]["state"], "queued");
            ids.push(page["data"]["scans"][0]["scanId"].as_str().context("retained ID")?.to_owned());
            next = page["data"]["nextScan"].as_str().map(str::to_owned);
        }
        assert_eq!(ids, original.into_iter().map(|row| row.scan_id).collect::<Vec<_>>());
        cli(&binary, &hub, Some("raw-operation-id"), false).await?;
        let (digest, _) = parse_scan_cursor(&cursor)?;
        fixture.db.read().await.backend.execute("DELETE FROM assessment_objects WHERE partition_key = ?1 AND object_digest = ?2", &vals![@slice request.resource_scope, digest.to_string()]).await?;
        cli(&binary, &hub, Some(&cursor), false).await?;
        println!("PASS: actual CLI retained scan pages survive scan mutation and database reopen");
        Ok::<_, anyhow::Error>(())
    }.await;
    server.abort();
    result
}
