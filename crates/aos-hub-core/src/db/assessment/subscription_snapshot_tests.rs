//! Public review mutation, retained custody, cursor scope and finite capacity tests.

use super::super::notifications_tests::{fixture, fixture_database};
use super::*;
use aos_assessment_runtime::notifications::SubscriptionPageV1;

#[tokio::test]
async fn public_review_pages_retain_replaced_reviews_and_exclude_new_subscriptions() -> Result<()> {
    let (db, registry, request, identity, fences) = fixture().await?;
    retained_reviews(db, registry, request, identity, fences).await
}

pub(in crate::db::assessment) async fn retained_reviews(
    db: Database,
    registry: i64,
    mut request: aos_assessment_runtime::notifications::SubscriptionWriteV1,
    identity: crate::auth::jwt::Claims,
    fences: Vec<crate::backend::CheckedStatement>,
) -> Result<()> {
    for id in ["a", "b", "c"] {
        request.subscription_id = id.into();
        db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
            .await?;
    }
    let scope = request.resource_scope.clone();
    let first = db
        .assessment_retained_subscription_page(registry, &scope, 1, None)
        .await?;
    let cursor = first
        .next_subscription
        .clone()
        .context("subscription continuation")?;
    let (digest, _) = parse_subscription_cursor(&cursor)?;
    let captured = db
        .assessment_object(
            &scope,
            AssessmentObjectKind::SubscriptionReadSnapshot,
            digest,
        )
        .await?
        .context("public snapshot custody")?;
    let captured = String::from_utf8(captured)?;
    for private in [
        "claims",
        "browserSessionIdHash",
        "test://",
        "receiver.example",
        &identity.sub,
    ] {
        assert!(!captured.contains(private));
    }

    request.subscription_id = "b".into();
    request.expected_revision = 1;
    request.enabled = false;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    request.subscription_id = "d".into();
    request.expected_revision = 0;
    request.enabled = true;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;

    let next = db
        .assessment_retained_subscription_page(registry, &scope, 1, Some(&cursor))
        .await?;
    assert_eq!(next.as_of, first.as_of);
    assert_eq!(next.subscriptions[0].subscription_id, "b");
    assert_eq!(next.subscriptions[0].revision, 1);
    assert!(next.subscriptions[0].enabled);
    assert_eq!(SubscriptionPageV1::from_slice(&next.to_bytes()?)?, next);
    let last = db
        .assessment_retained_subscription_page(
            registry,
            &scope,
            1,
            next.next_subscription.as_deref(),
        )
        .await?;
    assert_eq!(last.subscriptions[0].subscription_id, "c");
    assert!(last.next_subscription.is_none());
    let current = db
        .assessment_retained_subscription_page(registry, &scope, 10, None)
        .await?;
    assert_eq!(current.subscriptions.len(), 4);
    assert!(!current.subscriptions[1].enabled);
    assert!(db
        .assessment_retained_subscription_page(registry, &scope, 2, Some(&cursor))
        .await
        .is_err());
    assert!(db
        .assessment_retained_subscription_page(registry, "foreign", 1, Some(&cursor))
        .await
        .is_err());
    assert!(db
        .assessment_retained_subscription_page(registry, &scope, 1, Some("a"))
        .await
        .is_err());
    let mut forged = cursor.clone();
    forged.replace_range(68..100, "00000000000000000000000000000000");
    assert!(db
        .assessment_retained_subscription_page(registry, &scope, 1, Some(&forged))
        .await
        .is_err());
    db.backend
        .execute(
            "DELETE FROM assessment_objects WHERE partition_key = ?1 AND object_digest = ?2",
            &vals![@slice scope, digest.to_string()],
        )
        .await?;
    assert!(db
        .assessment_retained_subscription_page(registry, &scope, 1, Some(&cursor))
        .await
        .unwrap_err()
        .to_string()
        .contains("cursor-expired"));
    Ok(())
}

#[tokio::test]
async fn subscription_capture_quota_is_atomic_and_expired_custody_is_pruned() -> Result<()> {
    storage_bounds(Database::open_in_memory().await?).await
}

pub(in crate::db::assessment) async fn storage_bounds(db: Database) -> Result<()> {
    let (db, registry, mut request, identity, fences) = fixture_database(db).await?;
    for id in ["a", "b"] {
        request.subscription_id = id.into();
        db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
            .await?;
    }
    let scope = &request.resource_scope;
    for _ in 0..14 {
        db.assessment_retained_subscription_page(registry, scope, 1, None)
            .await?;
    }
    let results = tokio::join!(
        db.assessment_retained_subscription_page(registry, scope, 1, None),
        db.assessment_retained_subscription_page(registry, scope, 1, None),
        db.assessment_retained_subscription_page(registry, scope, 1, None),
        db.assessment_retained_subscription_page(registry, scope, 1, None),
    );
    let results = [results.0, results.1, results.2, results.3];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    for error in results.iter().filter_map(|result| result.as_ref().err()) {
        assert!(matches!(
            error.downcast_ref::<ScanPageError>(),
            Some(ScanPageError::CapacityExceeded)
        ));
    }
    db.backend.execute("UPDATE assessment_objects SET admitted_at = 0 WHERE partition_key = ?1 AND object_kind = ?2",
        &vals![@slice scope, SUBSCRIPTION_READ_SNAPSHOT_V1]).await?;
    db.assessment_retained_subscription_page(registry, scope, 1, None)
        .await?;
    let count = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
            &vals![@slice scope, SUBSCRIPTION_READ_SNAPSHOT_V1],
        )
        .await?
        .context("capture count")?
        .get::<u64>(0)?;
    assert_eq!(count, 1);
    Ok(())
}

/// Qualifies the packaged client and durable custody through an isolated transport.
#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_CLI pointing to the packaged aos binary"]
async fn actual_cli_retains_subscription_pages_across_database_reopen() -> Result<()> {
    use aos_assessment_runtime::notifications::SubscriptionQueryV1;
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

    async fn list(
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
            let query = SubscriptionQueryV1::from_slice(&request.document_json)?;
            ensure!(
                query.subscription_id.is_none()
                    && query
                        .resource_scope
                        .as_ref()
                        .is_none_or(|scope| scope == &fixture.scope),
                "foreign fixture selector"
            );
            let db = fixture.db.read().await.clone();
            let page = db
                .assessment_retained_subscription_page(
                    fixture.registry,
                    &fixture.scope,
                    query.limit,
                    query.after_subscription.as_deref(),
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
                Json(serde_json::json!({
            "code":"failed_precondition", "message":error.to_string()})),
            )
        })
    }

    async fn cli(
        binary: &std::ffi::OsStr,
        hub: &str,
        scope: &str,
        cursor: Option<&str>,
        okay: bool,
    ) -> Result<serde_json::Value> {
        let mut command = tokio::process::Command::new(binary);
        command.args([
            "--json",
            "hub",
            "maintain",
            "subscriptions",
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
            command.args(["--after-subscription", cursor, "--resource-scope", scope]);
        }
        let output = command.output().await?;
        ensure!(
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
    let (db, registry, mut request, identity, fences) =
        fixture_database(Database::open(&path).await?).await?;
    for id in ["a", "b", "c"] {
        request.subscription_id = id.into();
        db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
            .await?;
    }
    let fixture = Fixture {
        db: Arc::new(RwLock::new(Arc::new(db))),
        registry,
        scope: request.resource_scope.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hub = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route(
            "/aos.hub.v1.AssessmentService/ListSubscriptions",
            post(list),
        )
        .with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result = async {
        let first = cli(&binary, &hub, &fixture.scope, None, true).await?;
        let cursor = first["data"]["nextSubscription"].as_str().context("opaque continuation")?.to_owned();
        let (digest, _) = parse_subscription_cursor(&cursor)?;
        {
            let current = fixture.db.read().await.clone();
            request.subscription_id = "b".into(); request.expected_revision = 1; request.enabled = false;
            current.write_assessment_subscription_fenced(registry, &request, &identity, &fences).await?;
            request.subscription_id = "d".into(); request.expected_revision = 0; request.enabled = true;
            current.write_assessment_subscription_fenced(registry, &request, &identity, &fences).await?;
        }
        *fixture.db.write().await = Arc::new(Database::open(&path).await?);
        let next = cli(&binary, &hub, &fixture.scope, Some(&cursor), true).await?;
        assert_eq!(next["data"]["asOf"], first["data"]["asOf"]);
        assert_eq!(next["data"]["subscriptions"][0]["subscriptionId"], "b");
        assert_eq!(next["data"]["subscriptions"][0]["revision"], 1);
        assert_eq!(next["data"]["subscriptions"][0]["enabled"], true);
        let last = cli(&binary, &hub, &fixture.scope, next["data"]["nextSubscription"].as_str(), true).await?;
        assert_eq!(last["data"]["subscriptions"][0]["subscriptionId"], "c");
        assert!(last["data"].get("nextSubscription").is_none());
        cli(&binary, &hub, &fixture.scope, Some("b"), false).await?;
        fixture.db.read().await.backend.execute("DELETE FROM assessment_objects WHERE partition_key = ?1 AND object_digest = ?2",
            &vals![@slice fixture.scope, digest.to_string()]).await?;
        cli(&binary, &hub, &fixture.scope, Some(&cursor), false).await?;
        println!("PASS: actual CLI retained subscription pages survive review replacement and database reopen");
        Ok::<_, anyhow::Error>(())
    }.await;
    server.abort();
    result
}
