//! Revoked granting authority and credential expiry cannot authorize scan effects.

use anyhow::{Context as _, Result};

use super::scans_tests::setup;
use crate::auth::jwt::{Claims, AUTHORIZATION_CLAIMS_VERSION};
use crate::db::Database;
use crate::domain::{Permission, Principal};

async fn claims(db: &Database) -> Result<Claims> {
    let user = db
        .create_user("assessment-admission@fixture.invalid", None)
        .await?;
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

async fn revoke(db: &Database, claims: &Claims, mutation: &str) -> Result<()> {
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
