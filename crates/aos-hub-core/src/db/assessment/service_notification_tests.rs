//! Delivery qualification for separately reviewed finite service authority.

use anyhow::{Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::events::AssessmentEventPayload;
use aos_assessment_runtime::notifications::{DeliveryOutcome, NotificationWorkReceiptV1};
use aos_contract::Sha256Digest;

use crate::db::assessment::{AssessmentNotificationPlacement, AssessmentSourceBudget};
use crate::db::Database;
use crate::domain::{Permission, Principal, PrincipalKind};

/// Exercises real credential fences using the existing read permission in a
/// private fixture. Public assessment IAM remains independently fail-closed.
pub(in crate::db::assessment) async fn reviewed_service_delivery(db: Database) -> Result<()> {
    let (db, registry_id, mut request, mut reviewer, reviewer_fences) =
        crate::db::assessment::notifications_tests::fixture_database(db).await?;
    let registry = db.registry_by_id(registry_id).await?.context("registry")?;
    let organization = registry.org_id.context("managed organization")?;
    let service = db
        .create_service_account(organization, "delivery-service")
        .await?;
    db.grant_membership("service_account", service, &registry.scope_key, "viewer")
        .await?;
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
    let now = db.assessment_database_time().await?;
    reviewer.exp = i64::try_from(now.unix_seconds())? + 60;
    request.service_credential_id = Some(credential.clone());
    request.configuration.review_expires_at =
        Timestamp::from_unix_seconds(now.unix_seconds() + 3600)?;
    let destination = db
        .assessment_notification_destination(
            registry_id,
            &request.configuration.destination_reference,
            &request.configuration.review_expires_at,
        )
        .await?;
    request.configuration.destination_digest = destination.digest()?;
    let (authority, mut write_fences) = db
        .prepare_assessment_service_authority(
            registry_id,
            &credential,
            &request.configuration.review_expires_at,
            &reviewer,
            &[Permission::Read],
        )
        .await?;
    write_fences.extend(reviewer_fences.clone());
    let write_fences =
        crate::db::assessment::service_authority::distinct_authority_fences(write_fences)?;

    let created = db
        .write_prepared_assessment_subscription(
            registry_id,
            &request,
            &reviewer,
            &write_fences,
            None,
            Some(authority.clone()),
        )
        .await?;
    assert!(created.authority_expires_at.unix_seconds() > u64::try_from(reviewer.exp)?);
    assert_eq!(created.service_authority, Some(authority.receipt.clone()));
    let public = String::from_utf8(created.to_bytes()?)?;
    assert!(!public.contains(&credential));
    assert!(!public.contains(&reviewer.sub));
    assert!(!public.contains("ownerIncarnation"));

    db.revoke_token(&reviewer.sub).await?;
    assert!(db.backend.checked_batch(&reviewer_fences).await.is_err());
    let mut execution = db
        .assessment_iam_statements(&authority.principal, &registry.scope_key, Permission::Read)
        .await?;
    execution.push(db.assessment_service_owner_guard(registry_id, &authority));
    let execution = crate::db::assessment::service_authority::distinct_authority_fences(execution)?;
    let statements = db
        .assessment_event_statements(
            registry_id,
            (0..2)
                .map(|index| AssessmentEventPayload::ScanCompleted {
                    scan_id: format!("service-delivery-{index}"),
                    assessment_digest: Sha256Digest::of_bytes(format!("service-result-{index}")),
                })
                .collect(),
            &now,
        )
        .await?;
    db.backend.checked_batch(&statements).await?;
    let budget_key = format!("notification:service-{}", uuid::Uuid::new_v4().simple());
    db.install_assessment_source_budget(&AssessmentSourceBudget {
        key: budget_key.clone(),
        window_seconds: 86400,
        allowance: 10,
        min_interval_seconds: 0,
    })
    .await?;
    let placement = AssessmentNotificationPlacement {
        deployment_id: "service-fixture".into(),
        issuer: "coordinator".into(),
        audience: "executor".into(),
        budget_key,
    };
    let due = db.assessment_notification_due_page(registry_id, 2).await?;
    assert_eq!(due.len(), 2);
    let first = db
        .claim_assessment_notification_work_fenced(
            registry_id,
            &due[0],
            &placement,
            &destination,
            &execution,
        )
        .await?;
    let accepted = NotificationWorkReceiptV1 {
        schema: "aos.assessment-notification-receipt/v1".into(),
        plan_digest: first.plan.digest()?,
        body_digest: first.plan.body_digest,
        claim_token: first.plan.claim_token.clone(),
        outcome: DeliveryOutcome::Accepted,
        status: Some(204),
        retry_after_seconds: None,
        completed_at: db.assessment_database_time().await?,
    };
    db.admit_assessment_notification_receipt_fenced(&first, &accepted, &execution)
        .await?;

    let held = db
        .claim_assessment_notification_work_fenced(
            registry_id,
            &due[1],
            &placement,
            &destination,
            &execution,
        )
        .await?;
    db.revoke_token(&credential).await?;
    assert!(db
        .check_assessment_notification_work_fenced(&held, &execution)
        .await
        .is_err());
    let stale = NotificationWorkReceiptV1 {
        plan_digest: held.plan.digest()?,
        body_digest: held.plan.body_digest,
        claim_token: held.plan.claim_token.clone(),
        ..accepted
    };
    assert!(db
        .admit_assessment_notification_receipt_fenced(&held, &stale, &execution)
        .await
        .is_err());
    let consumed: u64 = db
        .backend
        .query_opt(
            "SELECT consumed FROM assessment_source_budgets WHERE budget_key = ?1",
            &vals![@slice placement.budget_key],
        )
        .await?
        .context("budget")?
        .get(0)?;
    assert_eq!(consumed, 2);
    let delivered: u64 = db.backend.query_opt("SELECT COUNT(*) FROM assessment_notification_outbox WHERE registry_id = ?1 AND state = 'delivered'", &vals![@slice registry_id]).await?.context("deliveries")?.get(0)?;
    assert_eq!(delivered, 1);
    Ok(())
}

#[tokio::test]
async fn service_delivery_survives_reviewer_revocation_and_refuses_revoked_service_receipts(
) -> Result<()> {
    reviewed_service_delivery(Database::open_in_memory().await?).await
}
