//! Actual CLI retained status reads through isolated HTTP and real SQL custody.
//!
//! This test transport grants no production assessment IAM. Public API and
//! browser permission qualification remains independent of these wire fixtures.

use anyhow::{ensure, Context as _, Result};
use aos_assessment_runtime::application::retained::{
    parse_status_cursor, StatusPageV2, StatusQueryV2,
};
use aos_proto_types as pb;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::db::Database;

#[derive(Clone)]
struct Fixture {
    db: Arc<RwLock<Arc<Database>>>,
    registry: i64,
}

async fn read(
    State(fixture): State<Fixture>,
    Json(request): Json<pb::AssessmentStatusRequest>,
) -> std::result::Result<Json<pb::AssessmentDocumentResponse>, (StatusCode, Json<serde_json::Value>)>
{
    let result = async {
        ensure!(
            request.registry_slug == "fixture",
            "foreign fixture registry"
        );
        let query = StatusQueryV2::from_slice(&request.query_json)?;
        let db = fixture.db.read().await.clone();
        let page = db
            .assessment_retained_status_page(fixture.registry, &query)
            .await?
            .context("fixture status")?;
        Ok::<_, anyhow::Error>(Json(pb::AssessmentDocumentResponse {
            document_json: page.to_bytes()?,
        }))
    }
    .await;
    result.map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"code":"failed_precondition","message":error.to_string()})),
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
) -> Result<Option<StatusPageV2>> {
    let mut command = tokio::process::Command::new(binary);
    command.args([
        "--json",
        "hub",
        "maintain",
        "status",
        "--hub",
        hub,
        "--token",
        "public-fixture-token",
        "--registry",
        "fixture",
        "--retained",
        "--resource-scope",
        scope,
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
        wrapper["schema_version"] == "aos.hub.cli/v1" && wrapper["kind"] == "assessment-status",
        "CLI wrapper changed"
    );
    Ok(Some(StatusPageV2::from_slice(&serde_json::to_vec(
        &wrapper["data"],
    )?)?))
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_CLI pointing to the packaged aos binary"]
async fn actual_cli_retains_status_heads_across_cancellation_and_database_reopen() -> Result<()> {
    let binary = std::env::var_os("AOS_ASSESSMENT_CLI").context("packaged aos CLI required")?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("status-cli.db");
    let (db, registry, request) =
        super::status_snapshot_tests::setup(Database::open(&path).await?).await?;
    let pending = db.request_assessment_scan(registry, &request).await?;
    let fixture = Fixture {
        db: Arc::new(RwLock::new(Arc::new(db))),
        registry,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hub = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route(pb::ASSESSMENT_SERVICE_GET_STATUS_PATH, post(read))
        .with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result = async {
        let first = cli(&binary, &hub, &request.resource_scope, None, "1", true)
            .await?
            .context("first CLI page")?;
        assert!(first.page.subjects[0].profiles[0].pending);
        let cursor = first.next_cursor.clone().context("opaque continuation")?;
        {
            let db = fixture.db.read().await.clone();
            db.cancel_assessment_scan(registry, &pending.scan_id, pending.resource_version)
                .await?;
        }
        *fixture.db.write().await = Arc::new(Database::open(&path).await?);
        let second = cli(
            &binary,
            &hub,
            &request.resource_scope,
            Some(&cursor),
            "1",
            true,
        )
        .await?
        .context("second CLI page")?;
        assert_eq!(second.page.as_of, first.page.as_of);
        assert_eq!(second.expires_at, first.expires_at);
        assert!(second.page.subjects[0].profiles[0].pending);
        let last = cli(
            &binary,
            &hub,
            &request.resource_scope,
            second.next_cursor.as_deref(),
            "1",
            true,
        )
        .await?
        .context("last CLI page")?;
        assert_eq!(last.page.as_of, first.page.as_of);
        assert!(last.page.subjects[0].profiles[0].pending);
        assert!(last.next_cursor.is_none());
        let current = cli(&binary, &hub, &request.resource_scope, None, "100", true)
            .await?
            .context("current CLI status")?;
        assert_eq!(current.page.subjects.len(), 3);
        assert!(current
            .page
            .subjects
            .iter()
            .all(|subject| !subject.profiles[0].pending));
        cli(
            &binary,
            &hub,
            &request.resource_scope,
            Some(&cursor),
            "2",
            false,
        )
        .await?;
        cli(
            &binary,
            &hub,
            "foreign-incarnation",
            Some(&cursor),
            "1",
            false,
        )
        .await?;
        let (digest, _) = parse_status_cursor(&cursor)?;
        let forged = format!("t1:{}:{}", digest.hex(), "0".repeat(32));
        cli(
            &binary,
            &hub,
            &request.resource_scope,
            Some(&forged),
            "1",
            false,
        )
        .await?;
        fixture
            .db
            .read()
            .await
            .backend
            .execute(
                "DELETE FROM assessment_objects WHERE partition_key = ?1 AND object_digest = ?2",
                &vals![@slice request.resource_scope, digest.to_string()],
            )
            .await?;
        cli(
            &binary,
            &hub,
            &request.resource_scope,
            Some(&cursor),
            "1",
            false,
        )
        .await?;
        println!("PASS: actual CLI retained status heads survive cancellation and database reopen");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.abort();
    result
}
