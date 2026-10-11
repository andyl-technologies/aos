//! Real SQL watch positions, custody gaps and immutable event admission.
//!
//! Private journal fixtures grant no production assessment permission. The
//! public read service independently reauthorizes every bounded observation.

use anyhow::{Context as _, Result};
use aos_assessment_runtime::attention_control::EventPageV1;
use aos_assessment_runtime::events::{AssessmentEventPayload, AssessmentEventV1};
use aos_assessment_runtime::read_snapshot::ScanPageError;

use crate::db::Database;

async fn append(db: &Database, registry: i64, count: usize) -> Result<()> {
    let now = db.assessment_database_time().await?;
    let events = (0..count)
        .map(|index| AssessmentEventPayload::ScheduleChanged {
            schedule_id: format!("watch-fixture-{index}"),
            revision: 1,
            enabled: false,
        })
        .collect();
    let statements = db
        .assessment_event_statements(registry, events, &now)
        .await?;
    db.backend.checked_batch(&statements).await
}

async fn expect_error(
    db: &Database,
    registry: i64,
    scope: &str,
    after: u64,
    expected: ScanPageError,
) -> Result<()> {
    let error = db
        .assessment_event_replay_page(registry, scope, after, 10)
        .await
        .unwrap_err();
    assert_eq!(error.downcast_ref::<ScanPageError>(), Some(&expected));
    Ok(())
}

/// Qualifies committed windows, scope binding and lost-custody restart on SQL.
///
/// # Errors
/// Returns an error for fixture admission, event custody or unavailable storage.
pub(in crate::db::assessment) async fn qualify_replay(database: Database) -> Result<i64> {
    let (db, registry, request) = super::super::scans_tests::setup_database(database).await?;
    let scope = &request.resource_scope;
    let empty = db
        .assessment_event_replay_page(registry, scope, 0, 2)
        .await?;
    assert!(empty.events.is_empty());
    assert_eq!(empty.next_sequence, 0);
    EventPageV1::from_slice(&empty.to_bytes()?)?;
    expect_error(
        &db,
        registry,
        "different-incarnation",
        0,
        ScanPageError::SelectorChanged,
    )
    .await?;
    expect_error(&db, registry, scope, 1, ScanPageError::InvalidCursor).await?;

    append(&db, registry, 3).await?;
    let first = db
        .assessment_event_replay_page(registry, scope, 0, 2)
        .await?;
    assert_eq!(first.events.len(), 2);
    assert_eq!(first.next_sequence, 2);
    let original = first.events[0].to_bytes()?;
    append(&db, registry, 1).await?;
    let second = db
        .assessment_event_replay_page(registry, scope, 2, 2)
        .await?;
    assert_eq!(
        second
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        [3, 4]
    );
    let heartbeat = db
        .assessment_event_replay_page(registry, scope, 4, 2)
        .await?;
    assert!(heartbeat.events.is_empty());
    assert_eq!(heartbeat.next_sequence, 4);
    assert!(heartbeat.as_of >= first.as_of);
    assert_eq!(first.events[0].to_bytes()?, original);
    expect_error(&db, registry, scope, 5, ScanPageError::InvalidCursor).await?;
    assert!(db
        .assessment_event_replay_page(registry, scope, 0, 11)
        .await
        .is_err());

    // Prefix retirement permits an explicit retained-history restart at zero.
    // An older nonzero reconnect position cannot skip an unobserved successor.
    db.backend
        .execute(
            "DELETE FROM assessment_events WHERE registry_id = ?1 AND event_sequence <= 2",
            &vals![@slice registry],
        )
        .await?;
    expect_error(&db, registry, scope, 1, ScanPageError::CursorExpired).await?;
    let restarted = db
        .assessment_event_replay_page(registry, scope, 0, 10)
        .await?;
    assert_eq!(restarted.events[0].sequence, 3);
    assert_eq!(restarted.next_sequence, 4);

    // A lost committed tail cannot masquerade as a heartbeat below the end.
    db.backend
        .execute(
            "DELETE FROM assessment_events WHERE registry_id = ?1 AND event_sequence = 4",
            &vals![@slice registry],
        )
        .await?;
    expect_error(&db, registry, scope, 2, ScanPageError::CursorExpired).await?;
    assert!(db
        .assessment_event_replay_page(registry, scope, 4, 10)
        .await?
        .events
        .is_empty());
    let row = db.backend.query_opt("SELECT payload_json FROM assessment_events WHERE registry_id = ?1 AND event_sequence = 3", &vals![@slice registry]).await?.context("retained fixture event")?;
    let body: Vec<u8> = row.get(0)?;
    let mut event = AssessmentEventV1::from_slice(&body)?;
    event.sequence = 4;
    db.backend.execute("UPDATE assessment_events SET payload_json = ?2 WHERE registry_id = ?1 AND event_sequence = 3", &vals![@slice registry, event.to_bytes()?]).await?;
    expect_error(&db, registry, scope, 2, ScanPageError::CursorExpired).await?;
    db.backend.execute("UPDATE assessment_events SET payload_json = ?2 WHERE registry_id = ?1 AND event_sequence = 3", &vals![@slice registry, body]).await?;

    // Restoring event rows without their allocator must not hide the stream.
    db.backend
        .execute(
            "DELETE FROM assessment_event_sequences WHERE registry_id = ?1",
            &vals![@slice registry],
        )
        .await?;
    expect_error(&db, registry, scope, 0, ScanPageError::CursorExpired).await?;
    Ok(registry)
}

#[tokio::test]
async fn committed_replay_requires_contiguous_successor_custody() -> Result<()> {
    qualify_replay(Database::open_in_memory().await?)
        .await
        .map(|_| ())
}

#[tokio::test]
async fn replay_position_and_expired_custody_survive_database_reopen() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("event-replay.sqlite");
    let registry = qualify_replay(Database::open(&path).await?).await?;
    let reopened = Database::open(&path).await?;
    let scope = reopened
        .registry_by_id(registry)
        .await?
        .context("retained registry")?
        .scope_key;
    expect_error(&reopened, registry, &scope, 0, ScanPageError::CursorExpired).await
}

#[tokio::test]
async fn an_interior_gap_is_not_filtered_event_replay() -> Result<()> {
    let (db, registry, request) =
        super::super::scans_tests::setup_database(Database::open_in_memory().await?).await?;
    append(&db, registry, 4).await?;
    db.backend
        .execute(
            "DELETE FROM assessment_events WHERE registry_id = ?1 AND event_sequence = 2",
            &vals![@slice registry],
        )
        .await?;
    expect_error(
        &db,
        registry,
        &request.resource_scope,
        0,
        ScanPageError::CursorExpired,
    )
    .await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_CLI pointing to the packaged aos binary"]
async fn actual_cli_watch_refuses_lost_successor_without_false_heartbeat() -> Result<()> {
    qualify_cli_watch(false).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_CLI pointing to the packaged aos binary"]
async fn actual_cli_watch_refuses_unearned_heartbeat_position() -> Result<()> {
    qualify_cli_watch(true).await
}

async fn qualify_cli_watch(forge_heartbeat: bool) -> Result<()> {
    use aos_assessment_runtime::attention_control::EventQueryV1;
    use aos_proto_types as pb;
    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    use std::sync::Arc;

    #[derive(Clone)]
    struct Fixture {
        db: Arc<Database>,
        registry: i64,
        scope: String,
        forge_heartbeat: bool,
    }

    async fn read(
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
            let query = EventQueryV1::from_slice(&request.document_json)?;
            if query.after_sequence == 2 {
                anyhow::ensure!(
                    query.resource_scope.as_deref() == Some(fixture.scope.as_str()),
                    "watch scope changed"
                );
                if !fixture.forge_heartbeat {
                    fixture
                        .db
                        .backend
                        .execute(
                            "DELETE FROM assessment_events WHERE registry_id = ?1 AND event_sequence = 3",
                            &vals![@slice fixture.registry],
                        )
                        .await?;
                }
            }
            let mut page = fixture
                .db
                .assessment_event_replay_page(
                    fixture.registry,
                    &fixture.scope,
                    query.after_sequence,
                    query.limit,
                )
                .await?;
            if fixture.forge_heartbeat && query.after_sequence == 2 {
                // Keep the real journal intact. Simulate a faulty adapter that
                // supplies an empty successful response at an unearned position.
                page.events.clear();
            }
            Ok::<_, anyhow::Error>(Json(pb::AssessmentDocumentResponse {
                document_json: page.to_bytes()?,
            }))
        }
        .await;
        result.map_err(|error| {
            (
                StatusCode::PRECONDITION_FAILED,
                Json(serde_json::json!({"code":"failed_precondition","message":error.to_string()})),
            )
        })
    }

    let binary = std::env::var_os("AOS_ASSESSMENT_CLI").context("packaged aos CLI required")?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("watch-cli.sqlite");
    let (db, registry, request) =
        super::super::scans_tests::setup_database(Database::open(&path).await?).await?;
    append(&db, registry, 3).await?;
    drop(db);
    let fixture = Fixture {
        db: Arc::new(Database::open(&path).await?),
        registry,
        scope: request.resource_scope,
        forge_heartbeat,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hub = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route(pb::ASSESSMENT_SERVICE_LIST_EVENTS_PATH, post(read))
        .with_state(fixture);
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result = async {
        let mut command = tokio::process::Command::new(binary);
        command.kill_on_drop(true).args([
            "--json",
            "hub",
            "maintain",
            "events",
            "--hub",
            &hub,
            "--token",
            "public-fixture-token",
            "--registry",
            "fixture",
            "--limit",
            "2",
            "--watch",
        ]);
        let output =
            tokio::time::timeout(std::time::Duration::from_secs(30), command.output()).await??;
        assert!(!output.status.success());
        let stdout = String::from_utf8(output.stdout)?;
        let expected = if forge_heartbeat {
            "event replay"
        } else {
            "cursor-expired"
        };
        assert!(
            stdout.contains(expected) || String::from_utf8_lossy(&output.stderr).contains(expected)
        );
        let mut pages = Vec::new();
        for line in stdout.lines() {
            let envelope: serde_json::Value = serde_json::from_str(line)?;
            if envelope["kind"] == "assessment-events" {
                assert_eq!(envelope["schema_version"], "aos.hub.cli/v1");
                pages.push(EventPageV1::from_slice(&serde_json::to_vec(
                    &envelope["data"],
                )?)?);
            }
        }
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].events.len(), 2);
        assert_eq!(pages[0].next_sequence, 2);
        if forge_heartbeat {
            println!("PASS: actual CLI watch refuses an unearned heartbeat position");
        } else {
            println!("PASS: actual CLI watch refuses lost successor without a false heartbeat");
        }
        Ok(())
    }
    .await;
    server.abort();
    result
}
