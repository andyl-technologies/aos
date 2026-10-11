//! Revoked granting authority and credential expiry cannot authorize scan effects.

use anyhow::{Context as _, Result};

use super::scans_tests::setup;
use crate::auth::jwt::{Claims, AUTHORIZATION_CLAIMS_VERSION};
use crate::db::Database;
use crate::domain::{Permission, Principal};

#[tokio::test]
async fn private_job_provenance_is_immutable_scoped_and_does_not_extend_expiry() -> Result<()> {
    qualify_private_job(Database::open_in_memory().await?).await
}

/// Qualifies immutable admission and expiry through the selected actual backend.
///
/// # Errors
/// Returns an error for unavailable persistence or failed scoped admission.
pub(super) async fn qualify_private_job(database: Database) -> Result<()> {
    let (db, registry_id, mut request) = super::scans_tests::setup_database(database).await?;
    let original = claims(&db).await?;
    request.actor_ref = super::assessment_actor_ref(&original)?;
    let scan = db.request_assessment_scan(registry_id, &request).await?;
    let fences = db
        .assessment_iam_statements(&original, &request.resource_scope, Permission::Read)
        .await?;

    assert!(db
        .admit_assessment_scan_authority(&scan, &original, &[])
        .await
        .is_err());
    db.admit_assessment_scan_authority(&scan, &original, &fences)
        .await?;
    let mut replacement = original.clone();
    replacement.exp += 3600;
    let new_fences = db
        .assessment_iam_statements(&replacement, &request.resource_scope, Permission::Read)
        .await?;
    db.admit_assessment_scan_authority(&scan, &replacement, &new_fences)
        .await?;
    assert_eq!(db.assessment_scan_authority(&scan).await?.exp, original.exp);
    let row = db
        .backend
        .query_opt(
            "SELECT expires_at, authority_json FROM assessment_scan_authorities WHERE scan_id = ?1",
            &vals![@slice scan.scan_id],
        )
        .await?
        .context("private job")?;
    assert_eq!(
        row.get::<u64>(0)?,
        (original.exp as u64)
            .min(scan.created_at.unix_seconds() + u64::from(request.limits.wall_seconds))
    );
    assert!(!String::from_utf8(row.get::<Vec<u8>>(1)?)?.contains("Bearer"));

    let mut wrong = scan.clone();
    wrong.registry_id += 1;
    assert!(db.assessment_scan_authority(&wrong).await.is_err());
    wrong = scan.clone();
    wrong.request.actor_ref = "different-actor".into();
    assert!(db.assessment_scan_authority(&wrong).await.is_err());
    let guard = db.assessment_job_authority_guard(&scan).await?;
    let expired = db.assessment_database_time().await?.unix_seconds() - 1;
    db.backend.execute("UPDATE assessment_scan_authorities SET expires_at = ?2, admitted_at = ?2 - 1 WHERE scan_id = ?1", &vals![@slice scan.scan_id, expired]).await?;
    assert!(db.backend.checked_batch(&[guard]).await.is_err());
    assert!(db.assessment_scan_authority(&scan).await.is_err());
    assert!(db
        .assessment_controller_scan_page(registry_id, "", 1)
        .await?
        .is_empty());
    db.reconcile_assessment_scans(registry_id, "", 1).await?;
    let settled = db
        .assessment_scan(registry_id, &scan.scan_id)
        .await?
        .context("expired authority scan")?;
    assert_eq!(
        settled.state,
        aos_assessment_runtime::scan::ScanState::Failed
    );
    assert_eq!(
        settled.failure_code.as_deref(),
        Some("job-authority-expired")
    );
    assert!(settled.assessment_digest.is_none());
    assert!(db
        .admit_assessment_scan_authority(&scan, &replacement, &new_fences)
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn revoked_job_admission_cannot_create_private_authority() -> Result<()> {
    for mutation in ["membership", "credential", "incarnation", "expiry"] {
        let (db, registry_id, mut request) = setup().await?;
        let identity = claims(&db).await?;
        request.actor_ref = super::assessment_actor_ref(&identity)?;
        let scan = db.request_assessment_scan(registry_id, &request).await?;
        let fences = db
            .assessment_iam_statements(&identity, &request.resource_scope, Permission::Read)
            .await?;
        revoke(&db, &identity, mutation).await?;

        assert!(db
            .admit_assessment_scan_authority(&scan, &identity, &fences)
            .await
            .is_err());
        assert!(db
            .backend
            .query_opt(
                "SELECT 1 FROM assessment_scan_authorities WHERE scan_id = ?1",
                &vals![@slice scan.scan_id]
            )
            .await?
            .is_none());
    }
    Ok(())
}

pub(super) async fn claims(db: &Database) -> Result<Claims> {
    let email = format!(
        "assessment-admission-{}@fixture.invalid",
        uuid::Uuid::new_v4().simple()
    );
    let user = db.create_user(&email, None).await?;
    db.grant_membership("user", user, "instance", "owner")
        .await?;
    // Existing read grants exercise the shared authority primitive without
    // installing or changing the pending assessment default role policy.
    let (token, _) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::Read],
            None,
            None,
        )
        .await?;
    let now = i64::try_from(db.assessment_database_time().await?.unix_seconds())?;
    Ok(Claims {
        sub: token,
        owner_kind: "user".into(),
        owner_id: user,
        owner_incarnation: db.principal_incarnation(Principal::user(user)).await?,
        browser_session_id_hash: None,
        scope: "instance".into(),
        perms: vec![Permission::Read.as_str().into()],
        authz_version: AUTHORIZATION_CLAIMS_VERSION.into(),
        iat: now,
        exp: now + 3600,
    })
}

pub(super) async fn revoke(db: &Database, claims: &Claims, mutation: &str) -> Result<()> {
    let now = i64::try_from(db.assessment_database_time().await?.unix_seconds())?;
    match mutation {
        "membership" => {
            db.backend
                .execute(
                    "DELETE FROM memberships WHERE principal_kind = 'user' AND principal_id = ?1",
                    &vals![@slice claims.owner_id],
                )
                .await?;
        }
        "credential" => {
            db.backend
                .execute(
                    "UPDATE tokens SET revoked_at = ?2 WHERE id = ?1",
                    &vals![@slice claims.sub, now],
                )
                .await?;
        }
        "incarnation" => {
            db.backend
                .execute(
                    "UPDATE users SET principal_incarnation = ?2 WHERE id = ?1",
                    &vals![@slice claims.owner_id, uuid::Uuid::new_v4().to_string()],
                )
                .await?;
        }
        "expiry" => {
            db.backend
                .execute(
                    "UPDATE tokens SET expires_at = ?2 WHERE id = ?1",
                    &vals![@slice claims.sub, now - 1],
                )
                .await?;
        }
        _ => anyhow::bail!("unknown authority fixture mutation"),
    }
    Ok(())
}

#[tokio::test]
async fn revoked_admission_authority_cannot_allocate_a_generation_or_scan() -> Result<()> {
    for mutation in ["membership", "credential", "incarnation", "expiry"] {
        let (db, registry_id, request) = setup().await?;
        let claims = claims(&db).await?;
        let fences = db
            .assessment_iam_statements(&claims, &request.resource_scope, Permission::Read)
            .await?;
        let resource = db
            .assessment_resource(registry_id)
            .await?
            .context("fixture resource")?;

        revoke(&db, &claims, mutation).await?;
        assert!(
            db.request_assessment_scan_fenced(registry_id, &request, &fences)
                .await
                .is_err(),
            "{mutation}"
        );

        assert_eq!(
            db.assessment_resource(registry_id)
                .await?
                .context("retained resource")?,
            resource,
            "{mutation}"
        );
        assert!(
            db.assessment_scan_summaries(registry_id, "", 100)
                .await?
                .is_empty(),
            "{mutation}"
        );
        let heads = db
            .assessment_status_page(registry_id, &request.profiles, "", 100)
            .await?;
        assert_eq!(
            heads.subjects[0].profiles[0].desired_generation, 0,
            "{mutation}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn revoked_cancellation_authority_cannot_change_the_scan_revision() -> Result<()> {
    for mutation in ["membership", "credential", "incarnation", "expiry"] {
        let (db, registry_id, request) = setup().await?;
        let claims = claims(&db).await?;
        let fences = db
            .assessment_iam_statements(&claims, &request.resource_scope, Permission::Read)
            .await?;
        let scan = db
            .request_assessment_scan_fenced(registry_id, &request, &fences)
            .await?;

        revoke(&db, &claims, mutation).await?;
        assert!(
            db.cancel_assessment_scan_fenced(
                registry_id,
                &scan.scan_id,
                scan.resource_version,
                &fences
            )
            .await
            .is_err(),
            "{mutation}"
        );

        let retained = db
            .assessment_scan(registry_id, &scan.scan_id)
            .await?
            .context("retained scan")?;
        assert_eq!(
            retained.resource_version, scan.resource_version,
            "{mutation}"
        );
        assert_eq!(retained.state, scan.state, "{mutation}");
    }
    Ok(())
}
