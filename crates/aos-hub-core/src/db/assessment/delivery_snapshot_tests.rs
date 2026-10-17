//! Retained delivery attempts, selectors, capacity and actual CLI acceptance.

use super::*;
use aos_assessment_runtime::events::AssessmentEventPayload;
use aos_assessment_runtime::notifications::{
    DeliveryOutcome, NotificationIntentState, NotificationWorkReceiptV1,
};
use aos_contract::Sha256Digest;

async fn emit(db: &Database, registry: i64, count: usize) -> Result<()> {
    let statements = db
        .assessment_event_statements(
            registry,
            (0..count)
                .map(|index| AssessmentEventPayload::ScanCompleted {
                    scan_id: format!("fixture-{index}"),
                    assessment_digest: Sha256Digest::of_bytes(format!("fixture-{index}")),
                })
                .collect(),
            &db.assessment_database_time().await?,
        )
        .await?;
    db.backend.checked_batch(&statements).await
}

async fn fixture(database: Database, count: usize) -> Result<(Database, i64, String, String)> {
    let (db, registry, request, identity, fences) =
        super::super::notifications_tests::fixture_database(database).await?;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    emit(&db, registry, count).await?;
    Ok((
        db,
        registry,
        request.resource_scope,
        request.subscription_id,
    ))
}

#[tokio::test]
async fn delivery_pages_preserve_attempts_across_physical_settlement() -> Result<()> {
    retained_attempts(Database::open_in_memory().await?).await
}

pub(in crate::db::assessment) async fn retained_attempts(database: Database) -> Result<()> {
    let (db, registry, request, identity, fences) =
        super::super::notifications_tests::fixture_database(database).await?;
    let scope = &request.resource_scope;
    let subscription = Some(request.subscription_id.as_str());
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    emit(&db, registry, 3).await?;
    let first = db
        .assessment_retained_delivery_page(registry, scope, 1, subscription, None)
        .await?;
    let cursor = first
        .next_delivery
        .clone()
        .context("delivery continuation")?;
    let second = db
        .assessment_retained_delivery_page(registry, scope, 1, subscription, Some(&cursor))
        .await?;
    let original = second.deliveries[0].clone();
    assert_eq!(original.state, NotificationIntentState::Pending);
    let (digest, _) = parse_delivery_cursor(&cursor)?;
    let stored = db
        .assessment_object(scope, AssessmentObjectKind::DeliveryReadSnapshot, digest)
        .await?
        .context("delivery capture custody")?;
    let captured = String::from_utf8(stored)?;
    for private in [
        "claims",
        "claimToken",
        "callbackBody",
        "secretVersionReference",
        &identity.sub,
    ] {
        assert!(!captured.contains(private));
    }

    let placement = super::super::AssessmentNotificationPlacement {
        deployment_id: "deployment".into(),
        issuer: "coordinator".into(),
        audience: "executor".into(),
        budget_key: format!("notification:delivery-{}", uuid::Uuid::new_v4().simple()),
    };
    db.install_assessment_source_budget(&super::super::AssessmentSourceBudget {
        key: placement.budget_key.clone(),
        window_seconds: 86400,
        allowance: 100,
        min_interval_seconds: 0,
    })
    .await?;
    let destination = db
        .assessment_notification_destination(
            registry,
            &request.configuration.destination_reference,
            &request.configuration.review_expires_at,
        )
        .await?;
    let work = db
        .claim_assessment_notification_work_fenced(
            registry,
            &original.delivery_id,
            &placement,
            &destination,
            &fences,
        )
        .await?;
    let receipt = NotificationWorkReceiptV1 {
        schema: "aos.assessment-notification-receipt/v1".into(),
        plan_digest: work.plan.digest()?,
        body_digest: work.plan.body_digest,
        claim_token: work.plan.claim_token.clone(),
        outcome: DeliveryOutcome::Accepted,
        status: Some(204),
        retry_after_seconds: None,
        completed_at: db.assessment_database_time().await?,
    };
    db.admit_assessment_notification_receipt_fenced(&work, &receipt, &fences)
        .await?;
    emit(&db, registry, 1).await?;

    let retained = db
        .assessment_retained_delivery_page(registry, scope, 1, subscription, Some(&cursor))
        .await?;
    assert_eq!(retained, second);
    let current = db
        .assessment_notification_delivery_page(
            registry,
            "",
            subscription,
            Some(&original.delivery_id),
            1,
        )
        .await?
        .remove(0);
    assert_eq!(current.state, NotificationIntentState::Delivered);
    assert_eq!(current.attempt, 1);
    assert!(current.body_digest.is_some() && current.receipt_digest.is_some());
    assert_eq!(retained.as_of, first.as_of);
    let last = db
        .assessment_retained_delivery_page(
            registry,
            scope,
            1,
            subscription,
            retained.next_delivery.as_deref(),
        )
        .await?;
    assert_eq!(last.deliveries.len(), 1);
    assert!(last.next_delivery.is_none());

    for (selected_scope, limit, filter, token) in [
        ("other", 1, subscription, cursor.clone()),
        (scope.as_str(), 2, subscription, cursor.clone()),
        (scope.as_str(), 1, None, cursor.clone()),
        (scope.as_str(), 1, Some("other"), cursor.clone()),
        (
            scope.as_str(),
            1,
            subscription,
            original.delivery_id.clone(),
        ),
        (
            scope.as_str(),
            1,
            subscription,
            cursor.replacen("d1:", "r1:", 1),
        ),
    ] {
        assert!(db
            .assessment_retained_delivery_page(
                registry,
                selected_scope,
                limit,
                filter,
                Some(&token),
            )
            .await
            .is_err());
    }
    let mut forged = cursor.clone();
    forged.replace_range(68..100, "00000000000000000000000000000000");
    assert!(db
        .assessment_retained_delivery_page(registry, scope, 1, subscription, Some(&forged),)
        .await
        .is_err());
    db.backend
        .execute(
            "DELETE FROM assessment_objects WHERE partition_key = ?1 AND object_digest = ?2",
            &vals![@slice scope, digest.to_string()],
        )
        .await?;
    assert_eq!(
        db.assessment_retained_delivery_page(registry, scope, 1, subscription, Some(&cursor),)
            .await
            .unwrap_err()
            .downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CursorExpired)
    );
    Ok(())
}

#[tokio::test]
async fn delivery_capture_capacity_is_atomic_and_expired_custody_is_pruned() -> Result<()> {
    storage_bounds(Database::open_in_memory().await?).await
}

pub(in crate::db::assessment) async fn storage_bounds(database: Database) -> Result<()> {
    let (db, registry, scope, _) = fixture(database, 3).await?;
    for _ in 0..14 {
        db.assessment_retained_delivery_page(registry, &scope, 1, None, None)
            .await?;
    }
    let results = tokio::join!(
        db.assessment_retained_delivery_page(registry, &scope, 1, None, None),
        db.assessment_retained_delivery_page(registry, &scope, 1, None, None),
        db.assessment_retained_delivery_page(registry, &scope, 1, None, None),
        db.assessment_retained_delivery_page(registry, &scope, 1, None, None),
    );
    let results = [results.0, results.1, results.2, results.3];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    for result in results.into_iter().filter(Result::is_err) {
        assert_eq!(
            result.unwrap_err().downcast_ref::<ScanPageError>(),
            Some(&ScanPageError::CapacityExceeded)
        );
    }
    db.backend.execute(
        "UPDATE assessment_objects SET admitted_at = admitted_at - 900 WHERE partition_key = ?1 AND object_kind = ?2",
        &vals![@slice scope, DELIVERY_READ_SNAPSHOT_V1],
    ).await?;
    db.assessment_retained_delivery_page(registry, &scope, 1, None, None)
        .await?;
    let count = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
            &vals![@slice scope, DELIVERY_READ_SNAPSHOT_V1],
        )
        .await?
        .context("capture count")?
        .get::<u64>(0)?;
    assert_eq!(count, 1);
    Ok(())
}

#[tokio::test]
async fn oversized_delivery_sets_fail_before_returning_intent_bytes() -> Result<()> {
    oversized_capture(Database::open_in_memory().await?).await
}

pub(in crate::db::assessment) async fn oversized_capture(database: Database) -> Result<()> {
    let (db, registry, scope, _) = fixture(database, 129).await?;
    assert_eq!(
        db.assessment_retained_delivery_page(registry, &scope, 10, None, None)
            .await
            .unwrap_err()
            .downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CapacityExceeded)
    );
    Ok(())
}

#[tokio::test]
async fn corrupted_sqlite_delivery_rows_hit_the_byte_bound_before_decoding() -> Result<()> {
    let (db, registry, scope, _) = fixture(Database::open_in_memory().await?, 1).await?;
    // SQLite does not enforce VARCHAR lengths. A corrupted row must hit the
    // read allowance before semantic decoding; PostgreSQL rejects this write.
    db.backend
        .execute(
            "UPDATE assessment_notification_outbox SET last_error_code = ?2 WHERE registry_id = ?1",
            &vals![@slice registry, "x".repeat(8 * 1024 * 1024)],
        )
        .await?;
    assert_eq!(
        db.assessment_retained_delivery_page(registry, &scope, 10, None, None)
            .await
            .unwrap_err()
            .downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CapacityExceeded)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_CLI pointing to the packaged aos binary"]
async fn actual_cli_retains_delivery_attempts_across_database_reopen() -> Result<()> {
    use aos_assessment_runtime::notifications::NotificationDeliveryQueryV1;
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
            let query = NotificationDeliveryQueryV1::from_slice(&request.document_json)?;
            ensure!(
                query.delivery_id.is_none()
                    && query.subscription_id.is_none()
                    && query
                        .resource_scope
                        .as_ref()
                        .is_none_or(|scope| scope == &fixture.scope),
                "foreign fixture selector"
            );
            let db = fixture.db.read().await.clone();
            let page = db
                .assessment_retained_delivery_page(
                    fixture.registry,
                    &fixture.scope,
                    query.limit,
                    query.subscription_id.as_deref(),
                    query.after_delivery.as_deref(),
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
            "deliveries",
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
            command.args(["--after-delivery", cursor, "--resource-scope", scope]);
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
    let (db, registry, mut write, claims, fences) =
        super::super::notifications_tests::fixture_database(Database::open(&path).await?).await?;
    db.write_assessment_subscription_fenced(registry, &write, &claims, &fences)
        .await?;
    emit(&db, registry, 3).await?;
    let original = db
        .assessment_notification_delivery_page(registry, "", None, None, 10)
        .await?;
    let fixture = Fixture {
        db: Arc::new(RwLock::new(Arc::new(db))),
        registry,
        scope: write.resource_scope.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hub = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route(
            "/aos.hub.v1.AssessmentService/ListNotificationDeliveries",
            post(list),
        )
        .with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result = async {
        let first = cli(&binary, &hub, &fixture.scope, None, true).await?;
        let cursor = first["data"]["nextDelivery"]
            .as_str()
            .context("opaque delivery continuation")?
            .to_owned();
        let (digest, _) = parse_delivery_cursor(&cursor)?;
        write.expected_revision = 1;
        write.enabled = false;
        fixture
            .db
            .read()
            .await
            .write_assessment_subscription_fenced(registry, &write, &claims, &fences)
            .await?;
        *fixture.db.write().await = Arc::new(Database::open(&path).await?);
        let second = cli(&binary, &hub, &fixture.scope, Some(&cursor), true).await?;
        assert_eq!(second["data"]["asOf"], first["data"]["asOf"]);
        assert_eq!(
            second["data"]["deliveries"][0],
            serde_json::to_value(&original[1])?
        );
        let last = cli(
            &binary,
            &hub,
            &fixture.scope,
            second["data"]["nextDelivery"].as_str(),
            true,
        )
        .await?;
        assert_eq!(
            last["data"]["deliveries"][0],
            serde_json::to_value(&original[2])?
        );
        assert!(last["data"].get("nextDelivery").is_none());
        cli(
            &binary,
            &hub,
            &fixture.scope,
            Some(&original[0].delivery_id),
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
                &vals![@slice fixture.scope, digest.to_string()],
            )
            .await?;
        cli(&binary, &hub, &fixture.scope, Some(&cursor), false).await?;
        println!(
            "PASS: actual CLI retained delivery attempts survive review replacement and database reopen"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.abort();
    result
}
