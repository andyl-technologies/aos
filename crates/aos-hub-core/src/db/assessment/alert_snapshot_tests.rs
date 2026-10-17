//! Immutable episode pagination across acknowledgement, mutation and custody expiry.

use super::*;
use aos_assessment_runtime::alerts::{Acknowledgement, AssessmentAlertV1};
use aos_contract::Sha256Digest;

async fn fixture(db: Database) -> Result<(Database, i64, String, Vec<AssessmentAlertV1>)> {
    let (db, registry, request) = super::super::scans_tests::setup_database(db).await?;
    super::super::alerts_tests::commit_fixture(&db, registry, &request, None).await?;
    let original = db.assessment_alert_page(registry, "", 100).await?.remove(0);
    let mut alerts = Vec::new();
    for id in ["additional-a", "additional-b"] {
        let mut alert = original.clone();
        alert.issue_key = Sha256Digest::of_bytes(id);
        alert.issue.issue_key = alert.issue_key;
        alert.validate()?;
        db.backend.execute(
            "INSERT INTO assessment_alerts
             (registry_id, issue_key, subject_ref, profile, context_digest, family, attention_state,
              episode, transition_sequence, alert_json, assessment_digest, updated_at)
             SELECT registry_id, ?2, subject_ref, profile, context_digest, family, attention_state,
                    episode, transition_sequence, ?3, assessment_digest, updated_at
             FROM assessment_alerts WHERE registry_id = ?1 AND issue_key = ?4",
            &vals![@slice registry, alert.issue_key.to_string(), serde_json::to_vec(&alert)?, original.issue_key.to_string()],
        ).await?;
        alerts.push(alert);
    }
    alerts.push(original);
    alerts.sort_by_key(|alert| alert.issue_key);
    Ok((db, registry, request.resource_scope, alerts))
}

#[tokio::test]
async fn attention_pages_preserve_original_episodes_after_acknowledgement() -> Result<()> {
    retained_episodes(Database::open_in_memory().await?).await
}

pub(in crate::db::assessment) async fn retained_episodes(database: Database) -> Result<()> {
    let (db, registry, scope, alerts) = fixture(database).await?;
    let first = db
        .assessment_retained_alert_page(registry, &scope, 1, None)
        .await?;
    let cursor = first
        .next_issue
        .clone()
        .context("alert page continuation")?;
    let (digest, _) = parse_alert_cursor(&cursor)?;
    let resource = db
        .assessment_resource(registry)
        .await?
        .context("assessment resource")?;

    let acknowledged = db
        .acknowledge_assessment_alert(
            registry,
            resource.authorization_revision,
            alerts[1].sequence,
            Acknowledgement {
                idempotency_key: Some("attention-capture-test".into()),
                issue_key: alerts[1].issue_key,
                episode: alerts[1].episode,
                actor_ref: "authorized-fixture-reviewer".into(),
                acknowledged_at: db.assessment_database_time().await?,
                reason: None,
            },
        )
        .await?;
    assert_eq!(acknowledged.acknowledgements.len(), 1);

    let next = db
        .assessment_retained_alert_page(registry, &scope, 1, Some(&cursor))
        .await?;
    assert_eq!(next.as_of, first.as_of);
    assert_eq!(next.alerts, alerts[1..2]);
    assert!(next.alerts[0].acknowledgements.is_empty());
    let current = db
        .assessment_retained_alert_page(registry, &scope, 10, None)
        .await?;
    assert_eq!(current.alerts[1], acknowledged);
    let last = db
        .assessment_retained_alert_page(registry, &scope, 1, next.next_issue.as_deref())
        .await?;
    assert_eq!(last.alerts, alerts[2..3]);
    assert!(last.next_issue.is_none());
    assert_eq!(AlertPageV1::from_slice(&next.to_bytes()?)?, next);
    for (selector, limit, token) in [
        ("foreign", 1, cursor.clone()),
        (scope.as_str(), 2, cursor.clone()),
        (scope.as_str(), 1, alerts[0].issue_key.to_string()),
        (scope.as_str(), 1, cursor.replacen("a1:", "n1:", 1)),
    ] {
        assert!(db
            .assessment_retained_alert_page(registry, selector, limit, Some(&token))
            .await
            .is_err());
    }
    let mut forged = cursor.clone();
    forged.replace_range(68..100, "00000000000000000000000000000000");
    assert!(db
        .assessment_retained_alert_page(registry, &scope, 1, Some(&forged))
        .await
        .is_err());
    db.backend
        .execute(
            "DELETE FROM assessment_objects WHERE partition_key = ?1 AND object_digest = ?2",
            &vals![@slice scope.as_str(), digest.to_string()],
        )
        .await?;
    assert_eq!(
        db.assessment_retained_alert_page(registry, &scope, 1, Some(&cursor))
            .await
            .unwrap_err()
            .downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CursorExpired)
    );
    Ok(())
}

#[tokio::test]
async fn attention_capture_quota_is_atomic_and_expired_custody_is_pruned() -> Result<()> {
    storage_bounds(Database::open_in_memory().await?).await
}

pub(in crate::db::assessment) async fn storage_bounds(database: Database) -> Result<()> {
    let (db, registry, scope, _) = fixture(database).await?;
    for _ in 0..14 {
        db.assessment_retained_alert_page(registry, &scope, 1, None)
            .await?;
    }
    let results = tokio::join!(
        db.assessment_retained_alert_page(registry, &scope, 1, None),
        db.assessment_retained_alert_page(registry, &scope, 1, None),
        db.assessment_retained_alert_page(registry, &scope, 1, None),
        db.assessment_retained_alert_page(registry, &scope, 1, None),
    );
    let results = [results.0, results.1, results.2, results.3];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    for error in results.into_iter().filter_map(Result::err) {
        assert_eq!(
            error.downcast_ref::<ScanPageError>(),
            Some(&ScanPageError::CapacityExceeded)
        );
    }
    db.backend.execute(
        "UPDATE assessment_objects SET admitted_at = 0 WHERE partition_key = ?1 AND object_kind = ?2",
        &vals![@slice scope.as_str(), ALERT_READ_SNAPSHOT_V1],
    ).await?;
    db.assessment_retained_alert_page(registry, &scope, 1, None)
        .await?;
    let count = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
            &vals![@slice scope.as_str(), ALERT_READ_SNAPSHOT_V1],
        )
        .await?
        .context("capture count")?
        .get::<u64>(0)?;
    assert_eq!(count, 1);
    Ok(())
}

#[tokio::test]
async fn oversized_attention_captures_return_capacity_without_projecting_partial_history(
) -> Result<()> {
    oversized_capture(Database::open_in_memory().await?).await
}

pub(in crate::db::assessment) async fn oversized_capture(database: Database) -> Result<()> {
    let (db, registry, scope, alerts) = fixture(database).await?;
    let original = &alerts[0];
    for index in 0..126 {
        insert_alert(&db, registry, original, &format!("row-{index}"), vec![]).await?;
    }
    assert_eq!(
        db.assessment_retained_alert_page(registry, &scope, 10, None)
            .await
            .unwrap_err()
            .downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CapacityExceeded)
    );

    db.backend
        .execute(
            "DELETE FROM assessment_alerts WHERE registry_id = ?1 AND issue_key != ?2",
            &vals![@slice registry, original.issue_key.to_string()],
        )
        .await?;
    for index in 0..35 {
        let key = Sha256Digest::of_bytes(format!("bytes-{index}"));
        let mut acknowledgements = (0..60)
            .map(|review| Acknowledgement {
                idempotency_key: Some(format!("review-{review:03}")),
                issue_key: key,
                episode: 1,
                actor_ref: "authorized-fixture-reviewer".into(),
                acknowledged_at: original.updated_at.clone(),
                reason: Some("r".repeat(4096)),
            })
            .collect::<Vec<_>>();
        acknowledgements.sort();
        insert_alert(
            &db,
            registry,
            original,
            &format!("bytes-{index}"),
            acknowledgements,
        )
        .await?;
    }
    assert_eq!(
        db.assessment_retained_alert_page(registry, &scope, 10, None)
            .await
            .unwrap_err()
            .downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CapacityExceeded)
    );
    let captures = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
            &vals![@slice scope.as_str(), ALERT_READ_SNAPSHOT_V1],
        )
        .await?
        .context("capture count")?
        .get::<u64>(0)?;
    assert_eq!(captures, 0);
    Ok(())
}

async fn insert_alert(
    db: &Database,
    registry: i64,
    original: &AssessmentAlertV1,
    id: &str,
    acknowledgements: Vec<Acknowledgement>,
) -> Result<()> {
    let mut alert = original.clone();
    alert.issue_key = Sha256Digest::of_bytes(id);
    alert.issue.issue_key = alert.issue_key;
    alert.sequence = acknowledgements.len() as u64 + 1;
    alert.acknowledgements = acknowledgements;
    alert.validate()?;
    let bytes = serde_json::to_vec(&alert)?;
    assert!(bytes.len() <= 262_144);
    db.backend.execute(
        "INSERT INTO assessment_alerts
         (registry_id, issue_key, subject_ref, profile, context_digest, family, attention_state,
          episode, transition_sequence, alert_json, assessment_digest, updated_at)
         SELECT registry_id, ?2, subject_ref, profile, context_digest, family, attention_state,
                episode, ?3, ?4, assessment_digest, updated_at
         FROM assessment_alerts WHERE registry_id = ?1 AND issue_key = ?5",
        &vals![@slice registry, alert.issue_key.to_string(), alert.sequence, bytes, original.issue_key.to_string()],
    ).await?;
    Ok(())
}

/// Qualifies the CLI contract and persistent custody through an isolated test
/// transport. This fixture does not grant or exercise production service IAM.
#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_CLI pointing to the packaged aos binary"]
async fn actual_cli_retains_alert_revisions_across_database_reopen() -> Result<()> {
    use aos_assessment_runtime::attention_control::AlertQueryV1;
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
            let query = AlertQueryV1::from_slice(&request.document_json)?;
            ensure!(
                query
                    .resource_scope
                    .as_ref()
                    .is_none_or(|scope| scope == &fixture.scope),
                "foreign fixture scope"
            );
            let db = fixture.db.read().await.clone();
            let page = db
                .assessment_retained_alert_page(
                    fixture.registry,
                    &fixture.scope,
                    query.limit,
                    query.after_issue.as_deref(),
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
            "alerts",
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
            command.args(["--after-issue", cursor, "--resource-scope", scope]);
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
    let (db, registry, scope, alerts) = fixture(Database::open(&path).await?).await?;
    let fixture = Fixture {
        db: Arc::new(RwLock::new(Arc::new(db))),
        registry,
        scope,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hub = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route("/aos.hub.v1.AssessmentService/ListAlerts", post(list))
        .with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result = async {
        let first = cli(&binary, &hub, &fixture.scope, None, true).await?;
        let cursor = first["data"]["nextIssue"]
            .as_str()
            .context("opaque alert continuation")?
            .to_owned();
        let (digest, _) = parse_alert_cursor(&cursor)?;
        {
            let current = fixture.db.read().await.clone();
            let resource = current
                .assessment_resource(registry)
                .await?
                .context("resource")?;
            current
                .acknowledge_assessment_alert(
                    registry,
                    resource.authorization_revision,
                    alerts[1].sequence,
                    Acknowledgement {
                        idempotency_key: Some("actual-cli-capture".into()),
                        issue_key: alerts[1].issue_key,
                        episode: alerts[1].episode,
                        actor_ref: "authorized-fixture-reviewer".into(),
                        acknowledged_at: current.assessment_database_time().await?,
                        reason: None,
                    },
                )
                .await?;
        }
        *fixture.db.write().await = Arc::new(Database::open(&path).await?);
        let next = cli(&binary, &hub, &fixture.scope, Some(&cursor), true).await?;
        assert_eq!(next["data"]["asOf"], first["data"]["asOf"]);
        assert_eq!(next["data"]["alerts"][0], serde_json::to_value(&alerts[1])?);
        let last = cli(
            &binary,
            &hub,
            &fixture.scope,
            next["data"]["nextIssue"].as_str(),
            true,
        )
        .await?;
        assert_eq!(last["data"]["alerts"][0], serde_json::to_value(&alerts[2])?);
        assert!(last["data"].get("nextIssue").is_none());
        cli(
            &binary,
            &hub,
            &fixture.scope,
            Some(&alerts[0].issue_key.to_string()),
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
            "PASS: actual CLI retained alert revisions survive acknowledgement and database reopen"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.abort();
    result
}
