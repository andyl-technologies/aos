//! Existing service credentials, independent review lifetime and revocation races.

use super::*;
use crate::db::assessment::{authority_tests, scans_tests, AssessmentInventoryAdmission};
use crate::domain::{Principal, PrincipalKind};
use aos_assessment::input::{FreshnessMode, Profile};
use aos_assessment_runtime::scan::ScanLimits;

async fn setup(db: Database) -> Result<(Database, i64, Claims, ScheduleWriteV1)> {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    let org = db
        .create_org(
            &format!("assessment-service-{unique}"),
            "Service review fixture",
        )
        .await?;
    let registry_id = db
        .create_managed_registry(org, "", "packages", "private", &[], false)
        .await?;
    let registry = db
        .registry_by_id(registry_id)
        .await?
        .context("managed registry")?;
    let data = scans_tests::fixture()?;
    db.admit_assessment_inventory(
        &AssessmentInventoryAdmission {
            registry_id,
            partition: registry.scope_key.clone(),
            provenance_digest: Sha256Digest::of_bytes("service source provenance"),
            admission_digest: Sha256Digest::of_bytes("service verified admission"),
            expected_resource_version: 0,
        },
        &data,
    )
    .await?;
    let service = db.create_service_account(org, "assessment-service").await?;
    db.grant_membership("service_account", service, &registry.scope_key, "viewer")
        .await?;
    // The production assessment role assignments remain unavailable. These
    // internal fixtures exercise the same real current credential/IAM fences
    // with an existing read grant; no public assessment permission is bypassed.
    let (credential, _) = db
        .create_token(
            Principal {
                kind: PrincipalKind::ServiceAccount,
                id: service,
            },
            &registry.scope_key,
            &[Permission::Read],
            None,
            None,
        )
        .await?;
    let mut reviewer = authority_tests::claims(&db).await?;
    let now = db.assessment_database_time().await?;
    reviewer.exp = i64::try_from(now.unix_seconds())? + 60;
    let write = ScheduleWriteV1 {
        schema: "aos.assessment-schedule-write/v1".into(),
        resource_scope: registry.scope_key,
        schedule_id: "service-schedule".into(),
        expected_revision: 0,
        enabled: true,
        service_credential_id: Some(credential),
        configuration: ScheduleConfigurationV1 {
            schema: "aos.assessment-schedule-configuration/v1".into(),
            packages: vec!["fixture/example".into()],
            profiles: vec![Profile::Updates],
            freshness: FreshnessMode::Offline,
            cadence_seconds: 60,
            review_expires_at: Timestamp::from_unix_seconds(now.unix_seconds() + 3600)?,
            limits: ScanLimits::default(),
        },
    };
    Ok((db, registry_id, reviewer, write))
}

pub(in crate::db::assessment) async fn reviewed_service_scan_survives_reviewer_revocation_and_fences_service_revocation(
    db: Database,
) -> Result<()> {
    let (db, registry, reviewer, write) = setup(db).await?;
    let credential = write
        .service_credential_id
        .as_deref()
        .context("service credential")?;
    let (authority, mut fences) = db
        .prepare_assessment_service_authority(
            registry,
            credential,
            &write.configuration.review_expires_at,
            &reviewer,
            &[Permission::Read],
        )
        .await?;
    let reviewer_fences = db
        .assessment_iam_statements(&reviewer, &write.resource_scope, Permission::Read)
        .await?;
    fences.extend(reviewer_fences.clone());
    let fences = distinct_authority_fences(fences)?;
    let created = db
        .write_prepared_assessment_schedule(
            registry,
            &write,
            &reviewer,
            &fences,
            None,
            Some(authority.clone()),
        )
        .await?;
    assert!(created.authority_expires_at.unix_seconds() > u64::try_from(reviewer.exp)?);
    assert_eq!(created.service_authority, Some(authority.receipt.clone()));
    let projection = String::from_utf8(created.to_bytes()?)?;
    assert!(!projection.contains(credential));
    assert!(!projection.contains(&reviewer.sub));
    assert!(!projection.contains("ownerIncarnation"));

    db.revoke_token(&reviewer.sub).await?;
    assert!(db.backend.checked_batch(&reviewer_fences).await.is_err());
    let key = schedule_key(&write.resource_scope, &write.schedule_id)?;
    let record = db
        .schedule_record(registry, &key)
        .await?
        .context("review")?;
    let mut due_fences = db
        .assessment_iam_statements(
            &authority.principal,
            &write.resource_scope,
            Permission::Read,
        )
        .await?;
    due_fences.push(db.assessment_service_owner_guard(registry, &authority));
    due_fences.push(db.schedule_revision_guard(registry, &record, true));
    let scan = db
        .admit_due_schedule_fenced(registry, &write.resource_scope, record, &due_fences)
        .await?;
    let retained = db.assessment_scan_authority(&scan).await?;
    assert_eq!(retained.sub, credential);
    assert_eq!(
        scan.request.actor_ref,
        authority.receipt.actor_ref.to_string()
    );
    assert!(db.assessment_scan_service_guards(&scan).await?.is_some());
    let mut effect = due_fences;
    effect.push(db.assessment_job_authority_guard(&scan).await?);
    db.backend.checked_batch(&effect).await?;
    let claim = db
        .claim_assessment_scan(registry, &scan.scan_id, 60)
        .await?;
    let data = db.assessment_evaluation_base(registry, &claim).await?;
    let input = db
        .freeze_assessment_evaluation(registry, &claim, &data)
        .await?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    db.revoke_token(credential).await?;
    assert!(db.backend.checked_batch(&effect).await.is_err());
    assert!(db
        .commit_assessment_evaluation_fenced(registry, &claim, &result, effect)
        .await
        .is_err());
    assert!(db
        .assessment_scan(registry, &scan.scan_id)
        .await?
        .context("uncommitted service scan")?
        .assessment_digest
        .is_none());
    assert!(db.assessment_scan_authority(&scan).await.is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_CLI pointing to the packaged aos binary"]
async fn actual_cli_reads_service_review_after_database_reopen() -> Result<()> {
    use aos_assessment_runtime::schedules::ScheduleQueryV1;
    use aos_proto_types as pb;
    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    use std::sync::Arc;

    #[derive(Clone)]
    struct Fixture {
        db: Arc<Database>,
        registry: i64,
        scope: String,
        reader: Claims,
    }

    async fn list(
        State(fixture): State<Fixture>,
        Json(request): Json<pb::AssessmentControlRequest>,
    ) -> std::result::Result<Json<pb::AssessmentDocumentResponse>, (StatusCode, String)> {
        let result = async {
            ensure!(
                request.registry_slug == "fixture",
                "foreign fixture registry"
            );
            let query = ScheduleQueryV1::from_slice(&request.document_json)?;
            ensure!(
                query.schedule_id.is_none()
                    && query.after_schedule.is_none()
                    && query
                        .resource_scope
                        .as_ref()
                        .is_none_or(|scope| scope == &fixture.scope),
                "foreign fixture selector"
            );
            // This isolated transport uses real existing read authority. It is
            // not the public assessment permission path, which remains denied
            // until the reviewed role policy is installed.
            let fences = fixture
                .db
                .assessment_iam_statements(&fixture.reader, &fixture.scope, Permission::Read)
                .await?;
            fixture.db.backend.checked_batch(&fences).await?;
            let page = fixture
                .db
                .assessment_retained_schedule_page(
                    fixture.registry,
                    &fixture.scope,
                    query.limit,
                    None,
                )
                .await?;
            fixture.db.backend.checked_batch(&fences).await?;
            Ok::<_, anyhow::Error>(Json(pb::AssessmentDocumentResponse {
                document_json: page.to_bytes()?,
            }))
        }
        .await;
        result.map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))
    }

    let binary = std::env::var_os("AOS_ASSESSMENT_CLI").context("packaged aos CLI required")?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("hub.db");
    let (db, registry, reviewer, write) = setup(Database::open(&path).await?).await?;
    let credential = write
        .service_credential_id
        .as_deref()
        .context("credential")?;
    let (authority, mut fences) = db
        .prepare_assessment_service_authority(
            registry,
            credential,
            &write.configuration.review_expires_at,
            &reviewer,
            &[Permission::Read],
        )
        .await?;
    fences.extend(
        db.assessment_iam_statements(&reviewer, &write.resource_scope, Permission::Read)
            .await?,
    );
    let fences = distinct_authority_fences(fences)?;
    let receipt = db
        .write_prepared_assessment_schedule(
            registry,
            &write,
            &reviewer,
            &fences,
            None,
            Some(authority),
        )
        .await?;
    db.revoke_token(&reviewer.sub).await?;
    let reader = authority_tests::claims(&db).await?;
    drop(db);
    let fixture = Fixture {
        db: Arc::new(Database::open(&path).await?),
        registry,
        scope: write.resource_scope,
        reader,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hub = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route("/aos.hub.v1.AssessmentService/ListSchedules", post(list))
        .with_state(fixture);
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let outcome = async {
        let output = tokio::process::Command::new(binary).args(["--json", "hub", "maintain", "schedules",
            "--hub", &hub, "--token", "isolated-service-review-fixture", "--registry", "fixture", "--limit", "1"]).output().await?;
        ensure!(output.status.success(), "actual CLI service review failed: {}", String::from_utf8_lossy(&output.stderr));
        let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(document["data"]["schedules"][0], serde_json::to_value(&receipt)?);
        assert!(document["data"].get("nextSchedule").is_none());
        assert!(!String::from_utf8(output.stdout)?.contains(credential));
        println!("PASS: actual CLI service review survives reviewing credential revocation and database reopen");
        Ok::<_, anyhow::Error>(())
    }.await;
    server.abort();
    outcome
}

#[tokio::test]
async fn service_scan_rechecks_exact_credential_after_reviewing_session_ends() -> Result<()> {
    reviewed_service_scan_survives_reviewer_revocation_and_fences_service_revocation(
        Database::open_in_memory().await?,
    )
    .await
}

#[tokio::test]
async fn service_review_refuses_foreign_human_expired_and_excessive_authority() -> Result<()> {
    let (db, registry, reviewer, mut write) = setup(Database::open_in_memory().await?).await?;
    let credential = write
        .service_credential_id
        .as_deref()
        .context("credential")?
        .to_owned();
    let deadline = write.configuration.review_expires_at.clone();
    assert!(db
        .prepare_assessment_service_authority(
            registry,
            &reviewer.sub,
            &deadline,
            &reviewer,
            &[Permission::Read]
        )
        .await
        .is_err());
    let other_org = db
        .create_org(
            &format!("foreign-service-{}", uuid::Uuid::new_v4().simple()),
            "Foreign fixture",
        )
        .await?;
    let other_registry = db
        .create_managed_registry(other_org, "", "packages", "private", &[], false)
        .await?;
    assert!(db
        .prepare_assessment_service_authority(
            other_registry,
            &credential,
            &deadline,
            &reviewer,
            &[Permission::Read]
        )
        .await
        .is_err());
    let now = db.assessment_database_time().await?;
    for expires in [now.unix_seconds(), now.unix_seconds() + 2_592_001] {
        assert!(db
            .prepare_assessment_service_authority(
                registry,
                &credential,
                &Timestamp::from_unix_seconds(expires)?,
                &reviewer,
                &[Permission::Read]
            )
            .await
            .is_err());
    }
    db.backend
        .execute(
            "UPDATE tokens SET expires_at = ?2 WHERE id = ?1",
            &vals![@slice credential, now.unix_seconds() + 120],
        )
        .await?;
    let (authority, fences) = db
        .prepare_assessment_service_authority(
            registry,
            &credential,
            &deadline,
            &reviewer,
            &[Permission::Read],
        )
        .await?;
    assert_eq!(
        authority.receipt.expires_at.unix_seconds(),
        now.unix_seconds() + 120
    );
    db.backend.execute("DELETE FROM memberships WHERE principal_kind = 'service_account' AND principal_id = ?1", &vals![@slice authority.principal.owner_id]).await?;
    assert!(db.backend.checked_batch(&fences).await.is_err());
    write.service_credential_id = None;
    let reviewer_fences = db
        .assessment_iam_statements(&reviewer, &write.resource_scope, Permission::Read)
        .await?;
    let legacy = db
        .write_assessment_schedule_fenced(registry, &write, &reviewer, &reviewer_fences)
        .await?;
    assert_eq!(
        legacy.authority_expires_at.unix_seconds(),
        u64::try_from(reviewer.exp)?
    );
    assert!(legacy.service_authority.is_none());
    Ok(())
}
