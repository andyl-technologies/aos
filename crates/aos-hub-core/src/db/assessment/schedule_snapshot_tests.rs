//! Schedule replacement, due-time advancement and retained-custody capacity tests.

use super::*;
use crate::auth::jwt::Claims;
use crate::backend::CheckedStatement;
use crate::domain::Permission;
use aos_assessment::input::{FreshnessMode, Profile};
use aos_assessment_runtime::scan::ScanLimits;
use aos_assessment_runtime::schedules::{ScheduleConfigurationV1, ScheduleV1, ScheduleWriteV1};

async fn fixture(
    database: Database,
) -> Result<(
    Database,
    i64,
    Claims,
    Vec<CheckedStatement>,
    ScheduleWriteV1,
    Vec<ScheduleV1>,
)> {
    let (db, registry, selection) = super::super::scans_tests::setup_database(database).await?;
    let claims = super::super::authority_tests::claims(&db).await?;
    let fences = db
        .assessment_iam_statements(&claims, &selection.resource_scope, Permission::Read)
        .await?;
    let mut write = ScheduleWriteV1 {
        service_credential_id: None,
        schema: "aos.assessment-schedule-write/v1".into(),
        resource_scope: selection.resource_scope,
        schedule_id: "a".into(),
        expected_revision: 0,
        enabled: true,
        configuration: ScheduleConfigurationV1 {
            continuous: false,
            schema: "aos.assessment-schedule-configuration/v1".into(),
            packages: vec!["fixture/example".into()],
            profiles: vec![Profile::Updates],
            freshness: FreshnessMode::Offline,
            cadence_seconds: 60,
            review_expires_at: Timestamp::from_unix_seconds(u64::try_from(claims.exp)? + 3600)?,
            limits: ScanLimits::default(),
        },
    };
    let mut schedules = Vec::new();
    for id in ["a", "b", "c"] {
        write.schedule_id = id.into();
        schedules.push(
            db.write_assessment_schedule_fenced(registry, &write, &claims, &fences)
                .await?,
        );
    }
    schedules.sort_by_cached_key(|schedule| {
        aos_contract::Sha256Digest::of_canonical(
            "aos.assessment-schedule-key/v1",
            &(&schedule.resource_scope, &schedule.schedule_id),
        )
        .unwrap()
    });
    Ok((db, registry, claims, fences, write, schedules))
}

#[tokio::test]
async fn schedule_pages_retain_original_reviews_and_due_times_after_replacement() -> Result<()> {
    retained_reviews(Database::open_in_memory().await?).await
}

pub(in crate::db::assessment) async fn retained_reviews(database: Database) -> Result<()> {
    let (db, registry, claims, fences, mut write, original) = fixture(database).await?;
    let scope = write.resource_scope.clone();
    let first = db
        .assessment_retained_schedule_page(registry, &scope, 1, None)
        .await?;
    assert_eq!(first.schedules, original[..1]);
    let cursor = first
        .next_schedule
        .clone()
        .context("schedule continuation")?;
    let (digest, _) = parse_schedule_cursor(&cursor)?;
    let captured = db
        .assessment_object(&scope, AssessmentObjectKind::ScheduleReadSnapshot, digest)
        .await?
        .context("public schedule custody")?;
    let captured = String::from_utf8(captured)?;
    for private in ["claims", "actorRef", "browserSessionIdHash", &claims.sub] {
        assert!(!captured.contains(private));
    }

    write.schedule_id = original[1].schedule_id.clone();
    write.expected_revision = 1;
    write.enabled = false;
    let replaced = db
        .write_assessment_schedule_fenced(registry, &write, &claims, &fences)
        .await?;
    assert_eq!(replaced.revision, 2);
    let key = aos_contract::Sha256Digest::of_canonical(
        "aos.assessment-schedule-key/v1",
        &(&scope, &original[2].schedule_id),
    )?;
    db.backend.execute("UPDATE assessment_schedules SET next_due_at = next_due_at + 60 WHERE registry_id = ?1 AND schedule_id = ?2",
        &vals![@slice registry, key.to_string()]).await?;
    write.schedule_id = "new-review".into();
    write.expected_revision = 0;
    write.enabled = true;
    db.write_assessment_schedule_fenced(registry, &write, &claims, &fences)
        .await?;

    let second = db
        .assessment_retained_schedule_page(registry, &scope, 1, Some(&cursor))
        .await?;
    assert_eq!(second.schedules, original[1..2]);
    assert_eq!(second.as_of, first.as_of);
    let last = db
        .assessment_retained_schedule_page(registry, &scope, 1, second.next_schedule.as_deref())
        .await?;
    assert_eq!(last.schedules, original[2..3]);
    assert!(last.next_schedule.is_none());
    let current = db
        .assessment_retained_schedule_page(registry, &scope, 10, None)
        .await?;
    assert_eq!(current.schedules.len(), 4);
    assert!(current.schedules.contains(&replaced));
    assert!(current
        .schedules
        .iter()
        .any(|schedule| schedule.schedule_id == original[2].schedule_id
            && schedule.next_due_at.unix_seconds() == original[2].next_due_at.unix_seconds() + 60));
    assert_eq!(SchedulePageV1::from_slice(&second.to_bytes()?)?, second);
    for (selector, limit, token) in [
        ("foreign", 1, cursor.clone()),
        (scope.as_str(), 2, cursor.clone()),
        (scope.as_str(), 1, original[0].schedule_id.clone()),
        (scope.as_str(), 1, cursor.replacen("r1:", "n1:", 1)),
    ] {
        assert!(db
            .assessment_retained_schedule_page(registry, selector, limit, Some(&token))
            .await
            .is_err());
    }
    let mut forged = cursor.clone();
    forged.replace_range(68..100, "00000000000000000000000000000000");
    assert!(db
        .assessment_retained_schedule_page(registry, &scope, 1, Some(&forged))
        .await
        .is_err());
    db.backend
        .execute(
            "DELETE FROM assessment_objects WHERE partition_key = ?1 AND object_digest = ?2",
            &vals![@slice scope, digest.to_string()],
        )
        .await?;
    assert_eq!(
        db.assessment_retained_schedule_page(registry, &scope, 1, Some(&cursor))
            .await
            .unwrap_err()
            .downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CursorExpired)
    );
    Ok(())
}

#[tokio::test]
async fn schedule_capture_quota_is_atomic_and_expired_custody_is_pruned() -> Result<()> {
    storage_bounds(Database::open_in_memory().await?).await
}

pub(in crate::db::assessment) async fn storage_bounds(database: Database) -> Result<()> {
    let (db, registry, _, _, write, _) = fixture(database).await?;
    let scope = &write.resource_scope;
    for _ in 0..14 {
        db.assessment_retained_schedule_page(registry, scope, 1, None)
            .await?;
    }
    let results = tokio::join!(
        db.assessment_retained_schedule_page(registry, scope, 1, None),
        db.assessment_retained_schedule_page(registry, scope, 1, None),
        db.assessment_retained_schedule_page(registry, scope, 1, None),
        db.assessment_retained_schedule_page(registry, scope, 1, None),
    );
    let results = [results.0, results.1, results.2, results.3];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    for error in results.into_iter().filter_map(Result::err) {
        assert_eq!(
            error.downcast_ref::<ScanPageError>(),
            Some(&ScanPageError::CapacityExceeded)
        );
    }
    db.backend.execute("UPDATE assessment_objects SET admitted_at = 0 WHERE partition_key = ?1 AND object_kind = ?2",
        &vals![@slice scope.as_str(), SCHEDULE_READ_SNAPSHOT_V1]).await?;
    db.assessment_retained_schedule_page(registry, scope, 1, None)
        .await?;
    let count = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
            &vals![@slice scope.as_str(), SCHEDULE_READ_SNAPSHOT_V1],
        )
        .await?
        .context("capture count")?
        .get::<u64>(0)?;
    assert_eq!(count, 1);
    Ok(())
}

#[tokio::test]
async fn schedule_capture_refuses_excessive_reviews_before_projecting_partial_results() -> Result<()>
{
    oversized_capture(Database::open_in_memory().await?).await
}

pub(in crate::db::assessment) async fn oversized_capture(database: Database) -> Result<()> {
    let (db, registry, claims, fences, mut write, _) = fixture(database).await?;
    for index in 0..62 {
        write.schedule_id = format!("row-{index}");
        db.write_assessment_schedule_fenced(registry, &write, &claims, &fences)
            .await?;
    }
    assert_eq!(
        db.assessment_retained_schedule_page(registry, &write.resource_scope, 10, None)
            .await
            .unwrap_err()
            .downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CapacityExceeded)
    );

    db.backend
        .execute(
            "DELETE FROM assessment_schedules WHERE registry_id = ?1",
            &vals![@slice registry],
        )
        .await?;
    write.configuration.packages = (0..380)
        .map(|index| format!("fixture/{index:04}/{}", "p".repeat(480)))
        .collect();
    for index in 0..45 {
        write.schedule_id = format!("large-{index}");
        db.write_assessment_schedule_fenced(registry, &write, &claims, &fences)
            .await?;
    }
    assert_eq!(
        db.assessment_retained_schedule_page(registry, &write.resource_scope, 10, None)
            .await
            .unwrap_err()
            .downcast_ref::<ScanPageError>(),
        Some(&ScanPageError::CapacityExceeded)
    );
    let count = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM assessment_objects WHERE partition_key = ?1 AND object_kind = ?2",
            &vals![@slice write.resource_scope, SCHEDULE_READ_SNAPSHOT_V1],
        )
        .await?
        .context("snapshot count")?
        .get::<u64>(0)?;
    assert_eq!(count, 0);
    Ok(())
}

/// Qualifies actual CLI pagination over isolated transport and persistent custody.
/// This fixture does not grant or exercise production service IAM.
#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_CLI pointing to the packaged aos binary"]
async fn actual_cli_retains_schedule_reviews_across_database_reopen() -> Result<()> {
    use aos_assessment_runtime::schedules::ScheduleQueryV1;
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
            let query = ScheduleQueryV1::from_slice(&request.document_json)?;
            ensure!(
                query.schedule_id.is_none()
                    && query
                        .resource_scope
                        .as_ref()
                        .is_none_or(|scope| scope == &fixture.scope),
                "foreign fixture selector"
            );
            let db = fixture.db.read().await.clone();
            let page = db
                .assessment_retained_schedule_page(
                    fixture.registry,
                    &fixture.scope,
                    query.limit,
                    query.after_schedule.as_deref(),
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
            "schedules",
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
            command.args(["--after-schedule", cursor, "--resource-scope", scope]);
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
    let (db, registry, claims, fences, mut write, original) =
        fixture(Database::open(&path).await?).await?;
    let fixture = Fixture {
        db: Arc::new(RwLock::new(Arc::new(db))),
        registry,
        scope: write.resource_scope.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hub = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route("/aos.hub.v1.AssessmentService/ListSchedules", post(list))
        .with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result = async {
        let first = cli(&binary, &hub, &fixture.scope, None, true).await?;
        let cursor = first["data"]["nextSchedule"]
            .as_str()
            .context("opaque schedule continuation")?
            .to_owned();
        let (digest, _) = parse_schedule_cursor(&cursor)?;
        write.schedule_id = original[1].schedule_id.clone();
        write.expected_revision = 1;
        write.enabled = false;
        fixture
            .db
            .read()
            .await
            .write_assessment_schedule_fenced(registry, &write, &claims, &fences)
            .await?;
        *fixture.db.write().await = Arc::new(Database::open(&path).await?);
        let second = cli(&binary, &hub, &fixture.scope, Some(&cursor), true).await?;
        assert_eq!(second["data"]["asOf"], first["data"]["asOf"]);
        assert_eq!(
            second["data"]["schedules"][0],
            serde_json::to_value(&original[1])?
        );
        let last = cli(
            &binary,
            &hub,
            &fixture.scope,
            second["data"]["nextSchedule"].as_str(),
            true,
        )
        .await?;
        assert_eq!(
            last["data"]["schedules"][0],
            serde_json::to_value(&original[2])?
        );
        assert!(last["data"].get("nextSchedule").is_none());
        cli(
            &binary,
            &hub,
            &fixture.scope,
            Some(&original[0].schedule_id),
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
            "PASS: actual CLI retained schedule reviews survive replacement and database reopen"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.abort();
    result
}
