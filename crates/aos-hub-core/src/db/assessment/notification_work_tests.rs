//! Exact outbox claims, quota rollback, digest retry and stale receipt qualification.

use anyhow::{Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::events::AssessmentEventPayload;
use aos_assessment_runtime::notifications::{
    DeliveryOutcome, NotificationDestinationV1, NotificationFailureCode, NotificationFrequency,
    NotificationIntentState, NotificationWorkReceiptV1,
};
use aos_contract::Sha256Digest;

use super::{AssessmentNotificationPlacement, AssessmentNotificationWork, AssessmentSourceBudget};
use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;

async fn emit(db: &Database, registry_id: i64, count: usize, occurred: &Timestamp) -> Result<()> {
    let payloads = (0..count)
        .map(|index| AssessmentEventPayload::ScanCompleted {
            scan_id: format!("fixture-{index}"),
            assessment_digest: Sha256Digest::of_bytes(format!("result-{index}")),
        })
        .collect();
    let statements = db
        .assessment_event_statements(registry_id, payloads, occurred)
        .await?;
    db.backend.checked_batch(&statements).await
}

async fn install(db: &Database) -> Result<AssessmentNotificationPlacement> {
    let budget_key = format!("notification:fixture-{}", uuid::Uuid::new_v4().simple());
    db.install_assessment_source_budget(&AssessmentSourceBudget {
        key: budget_key.clone(),
        window_seconds: 86400,
        allowance: 100,
        min_interval_seconds: 0,
    })
    .await?;
    Ok(AssessmentNotificationPlacement {
        deployment_id: "deployment".into(),
        issuer: "coordinator".into(),
        audience: "executor".into(),
        budget_key,
    })
}

async fn consumed(db: &Database, placement: &AssessmentNotificationPlacement) -> Result<u64> {
    db.backend
        .query_opt(
            "SELECT consumed FROM assessment_source_budgets WHERE budget_key = ?1",
            &vals![@slice placement.budget_key],
        )
        .await?
        .context("budget")?
        .get(0)
}

async fn states(db: &Database, registry_id: i64, state: &str) -> Result<u64> {
    db.backend.query_opt("SELECT COUNT(*) FROM assessment_notification_outbox WHERE registry_id = ?1 AND state = ?2", &vals![@slice registry_id, state]).await?.context("state count")?.get(0)
}

fn receipt(
    work: &AssessmentNotificationWork,
    now: Timestamp,
    outcome: DeliveryOutcome,
) -> Result<NotificationWorkReceiptV1> {
    Ok(NotificationWorkReceiptV1 {
        schema: "aos.assessment-notification-receipt/v1".into(),
        plan_digest: work.plan.digest()?,
        body_digest: work.plan.body_digest,
        claim_token: work.plan.claim_token.clone(),
        outcome,
        status: Some(match outcome {
            DeliveryOutcome::Accepted => 204,
            DeliveryOutcome::Retryable => 503,
            DeliveryOutcome::PermanentFailure => 401,
        }),
        retry_after_seconds: None,
        completed_at: now,
    })
}

async fn destination(
    db: &Database,
    registry: i64,
    request: &aos_assessment_runtime::notifications::SubscriptionWriteV1,
) -> Result<NotificationDestinationV1> {
    db.assessment_notification_destination(
        registry,
        &request.configuration.destination_reference,
        &request.configuration.review_expires_at,
    )
    .await
}

#[tokio::test]
async fn claims_consume_quota_once_and_current_attempt_receipts_settle_atomically() -> Result<()> {
    let (db, registry, request, identity, fences) = super::notifications_tests::fixture().await?;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    let placement = install(&db).await?;
    let destination = destination(&db, registry, &request).await?;
    emit(&db, registry, 1, &db.assessment_database_time().await?).await?;
    let id = db
        .assessment_notification_due_page(registry, 1)
        .await?
        .remove(0);
    let work = db
        .claim_assessment_notification_work_fenced(registry, &id, &placement, &destination, &fences)
        .await?;
    db.check_assessment_notification_work_fenced(&work, &fences)
        .await?;
    assert_eq!(consumed(&db, &placement).await?, 1);
    assert!(db
        .claim_assessment_notification_work_fenced(registry, &id, &placement, &destination, &fences)
        .await
        .is_err());
    assert_eq!(consumed(&db, &placement).await?, 1);
    let accepted = receipt(
        &work,
        db.assessment_database_time().await?,
        DeliveryOutcome::Accepted,
    )?;
    db.admit_assessment_notification_receipt_fenced(&work, &accepted, &fences)
        .await?;
    db.admit_assessment_notification_receipt_fenced(&work, &accepted, &fences)
        .await?;
    assert_eq!(states(&db, registry, "delivered").await?, 1);
    assert_eq!(consumed(&db, &placement).await?, 1);
    let altered = receipt(
        &work,
        db.assessment_database_time().await?,
        DeliveryOutcome::PermanentFailure,
    )?;
    assert!(db
        .admit_assessment_notification_receipt_fenced(&work, &altered, &fences)
        .await
        .is_err());
    assert_eq!(states(&db, registry, "delivered").await?, 1);
    Ok(())
}

#[tokio::test]
async fn delivery_inspection_pages_status_without_claiming_or_disclosing_execution_authority(
) -> Result<()> {
    let (db, registry, mut request, identity, fences) =
        super::notifications_tests::fixture().await?;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    let placement = install(&db).await?;
    let destination = destination(&db, registry, &request).await?;
    emit(&db, registry, 3, &db.assessment_database_time().await?).await?;

    let first = db
        .assessment_notification_delivery_page(
            registry,
            "",
            Some(&request.subscription_id),
            None,
            1,
        )
        .await?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].state, NotificationIntentState::Pending);
    assert_eq!(first[0].attempt, 0);
    assert!(first[0].body_digest.is_none());
    let rest = db
        .assessment_notification_delivery_page(
            registry,
            &first[0].delivery_id,
            Some(&request.subscription_id),
            None,
            11,
        )
        .await?;
    assert_eq!(rest.len(), 2);
    assert!(rest
        .iter()
        .all(|delivery| delivery.delivery_id > first[0].delivery_id));
    assert!(db
        .assessment_notification_delivery_page(registry, "", Some("other-subscription"), None, 10)
        .await?
        .is_empty());
    assert!(db
        .assessment_notification_delivery_page(registry, "", None, None, 12)
        .await
        .is_err());
    assert!(db
        .assessment_notification_delivery_page(registry, "", None, Some(""), 1)
        .await
        .is_err());
    assert_eq!(consumed(&db, &placement).await?, 0);
    assert_eq!(states(&db, registry, "pending").await?, 3);

    let id = &first[0].delivery_id;
    let work = db
        .claim_assessment_notification_work_fenced(registry, id, &placement, &destination, &fences)
        .await?;
    let leased = db
        .assessment_notification_delivery_page(registry, "", None, Some(id), 1)
        .await?
        .remove(0);
    assert_eq!(leased.state, NotificationIntentState::Leased);
    assert_eq!(leased.attempt, 1);
    assert_eq!(leased.lease_expires_at, Some(work.plan.deadline.clone()));
    assert_eq!(leased.batch_delivery_id.as_deref(), Some(id.as_str()));
    assert_eq!(leased.body_digest, Some(work.plan.body_digest));
    assert!(leased.receipt_digest.is_none());
    let encoded = String::from_utf8(aos_contract::canonical::to_vec(&leased)?)?;
    for private in [
        work.plan.claim_token.as_str(),
        destination.url.as_str(),
        identity.sub.as_str(),
    ] {
        assert!(!encoded.contains(private));
    }

    let accepted = receipt(
        &work,
        db.assessment_database_time().await?,
        DeliveryOutcome::Accepted,
    )?;
    db.admit_assessment_notification_receipt_fenced(&work, &accepted, &fences)
        .await?;
    let delivered = db
        .assessment_notification_delivery_page(registry, "", None, Some(id), 1)
        .await?
        .remove(0);
    assert_eq!(delivered.state, NotificationIntentState::Delivered);
    assert!(delivered.lease_expires_at.is_none());
    assert!(delivered.receipt_digest.is_some());
    assert_eq!(consumed(&db, &placement).await?, 1);

    // An inconsistent retained lease must fail the read contract, rather than
    // being silently omitted from a successful delivered projection.
    db.backend.execute("UPDATE assessment_notification_outbox SET lease_expires_at = ?3 WHERE registry_id = ?1 AND delivery_id = ?2", &vals![@slice registry, id, work.plan.deadline.unix_seconds()]).await?;
    assert!(db
        .assessment_notification_delivery_page(registry, "", None, Some(id), 1)
        .await
        .is_err());
    db.backend.execute("UPDATE assessment_notification_outbox SET lease_expires_at = NULL WHERE registry_id = ?1 AND delivery_id = ?2", &vals![@slice registry, id]).await?;

    request.enabled = false;
    request.expected_revision = 1;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    let page = db
        .assessment_notification_delivery_page(registry, "", None, None, 10)
        .await?;
    assert_eq!(
        page.iter()
            .filter(|delivery| delivery.state == NotificationIntentState::Delivered)
            .count(),
        1
    );
    assert_eq!(
        page.iter()
            .filter(
                |delivery| delivery.state == NotificationIntentState::Revoked
                    && delivery.last_error_code
                        == Some(NotificationFailureCode::SubscriptionReviewReplaced)
            )
            .count(),
        2
    );
    assert_eq!(consumed(&db, &placement).await?, 1);
    Ok(())
}

#[tokio::test]
async fn denied_claims_roll_back_quota_and_revocation_fences_prepared_receipts() -> Result<()> {
    let (db, registry, mut request, identity, fences) =
        super::notifications_tests::fixture().await?;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    let placement = install(&db).await?;
    let destination = destination(&db, registry, &request).await?;
    emit(&db, registry, 1, &db.assessment_database_time().await?).await?;
    let id = db
        .assessment_notification_due_page(registry, 1)
        .await?
        .remove(0);
    let refused: CheckedStatement = Statement::new(
        "UPDATE registries SET scope_key = scope_key WHERE id = ?1",
        vals![registry + 1],
    )
    .expecting(1);
    assert!(db
        .claim_assessment_notification_work_fenced(
            registry,
            &id,
            &placement,
            &destination,
            std::slice::from_ref(&refused)
        )
        .await
        .is_err());
    assert_eq!(consumed(&db, &placement).await?, 0);
    assert_eq!(states(&db, registry, "pending").await?, 1);

    let work = db
        .claim_assessment_notification_work_fenced(registry, &id, &placement, &destination, &fences)
        .await?;
    let accepted = receipt(
        &work,
        db.assessment_database_time().await?,
        DeliveryOutcome::Accepted,
    )?;
    request.enabled = false;
    request.expected_revision = 1;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    assert!(db
        .admit_assessment_notification_receipt_fenced(&work, &accepted, &fences)
        .await
        .is_err());
    assert_eq!(states(&db, registry, "revoked").await?, 1);
    assert_eq!(states(&db, registry, "delivered").await?, 0);
    assert_eq!(consumed(&db, &placement).await?, 1);
    Ok(())
}

#[tokio::test]
async fn digest_claims_pin_fifty_members_and_retries_never_include_newer_events() -> Result<()> {
    let (db, registry, mut request, identity, fences) =
        super::notifications_tests::fixture().await?;
    request.configuration.frequency = NotificationFrequency::Digest { window_seconds: 60 };
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    let placement = install(&db).await?;
    let destination = destination(&db, registry, &request).await?;
    let occurred =
        Timestamp::from_unix_seconds(db.assessment_database_time().await?.unix_seconds() - 120)?;
    emit(&db, registry, 60, &occurred).await?;
    let id = db
        .assessment_notification_due_page(registry, 1)
        .await?
        .remove(0);
    let first = db
        .claim_assessment_notification_work_fenced(registry, &id, &placement, &destination, &fences)
        .await?;
    assert_eq!(first.plan.body.events.len(), 50);
    assert_eq!(states(&db, registry, "leased").await?, 50);
    assert_eq!(states(&db, registry, "pending").await?, 10);
    let member = db.backend.query_opt("SELECT delivery_id FROM assessment_notification_outbox WHERE registry_id = ?1 AND state = 'leased' AND delivery_id != ?2 ORDER BY delivery_id LIMIT 1", &vals![@slice registry, id]).await?.context("digest member")?.get::<String>(0)?;
    let projected = db
        .assessment_notification_delivery_page(registry, "", None, Some(&member), 1)
        .await?
        .remove(0);
    assert_eq!(projected.batch_delivery_id.as_deref(), Some(id.as_str()));
    assert_eq!(projected.body_digest, Some(first.plan.body_digest));
    assert_eq!(consumed(&db, &placement).await?, 1);
    let retryable = receipt(
        &first,
        db.assessment_database_time().await?,
        DeliveryOutcome::Retryable,
    )?;
    db.admit_assessment_notification_receipt_fenced(&first, &retryable, &fences)
        .await?;
    assert_eq!(states(&db, registry, "pending").await?, 60);

    emit(&db, registry, 5, &occurred).await?;
    // Advance the fixture's due rows without waiting for the physical backoff.
    db.backend.execute("UPDATE assessment_notification_outbox SET not_before = 0 WHERE registry_id = ?1 AND payload_digest = ?2", &vals![@slice registry, first.plan.body_digest.to_string()]).await?;
    let due = db.assessment_notification_due_page(registry, 2).await?;
    assert_eq!(due.first(), Some(&id));
    // The next claim must be a new digest root, rather than another member of
    // the already pinned fifty-event retry group.
    let newer = db
        .claim_assessment_notification_work_fenced(
            registry,
            &due[1],
            &placement,
            &destination,
            &fences,
        )
        .await?;
    assert_eq!(newer.plan.body.events.len(), 15);
    assert_ne!(newer.plan.body.delivery_id, first.plan.body.delivery_id);
    let second = db
        .claim_assessment_notification_work_fenced(registry, &id, &placement, &destination, &fences)
        .await?;
    assert_eq!(second.plan.body.to_bytes()?, first.plan.body.to_bytes()?);
    assert_eq!(second.plan.attempt, 2);
    assert_ne!(second.plan.claim_token, first.plan.claim_token);
    assert!(db
        .admit_assessment_notification_receipt_fenced(&first, &retryable, &fences)
        .await
        .is_err());
    let accepted = receipt(
        &second,
        db.assessment_database_time().await?,
        DeliveryOutcome::Accepted,
    )?;
    db.admit_assessment_notification_receipt_fenced(&second, &accepted, &fences)
        .await?;
    assert_eq!(states(&db, registry, "delivered").await?, 50);
    assert_eq!(states(&db, registry, "leased").await?, 15);
    let accepted_newer = receipt(
        &newer,
        db.assessment_database_time().await?,
        DeliveryOutcome::Accepted,
    )?;
    db.admit_assessment_notification_receipt_fenced(&newer, &accepted_newer, &fences)
        .await?;
    assert_eq!(states(&db, registry, "delivered").await?, 65);
    assert_eq!(states(&db, registry, "pending").await?, 0);
    assert_eq!(consumed(&db, &placement).await?, 3);
    Ok(())
}

#[tokio::test]
async fn uncertain_expired_attempts_keep_consumed_quota_and_old_receipts_cannot_settle_new_claims(
) -> Result<()> {
    let (db, registry, request, identity, fences) = super::notifications_tests::fixture().await?;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    let placement = install(&db).await?;
    let destination = destination(&db, registry, &request).await?;
    emit(&db, registry, 1, &db.assessment_database_time().await?).await?;
    let id = db
        .assessment_notification_due_page(registry, 1)
        .await?
        .remove(0);
    let first = db
        .claim_assessment_notification_work_fenced(registry, &id, &placement, &destination, &fences)
        .await?;
    let accepted = receipt(
        &first,
        db.assessment_database_time().await?,
        DeliveryOutcome::Accepted,
    )?;
    db.backend
        .execute(
            "UPDATE assessment_notification_outbox SET lease_expires_at = 0 WHERE registry_id = ?1",
            &vals![@slice registry],
        )
        .await?;
    let second = db
        .claim_assessment_notification_work_fenced(registry, &id, &placement, &destination, &fences)
        .await?;
    assert_eq!(consumed(&db, &placement).await?, 2);
    assert_eq!(second.plan.body_digest, first.plan.body_digest);
    assert_ne!(second.plan.claim_token, first.plan.claim_token);
    assert!(db
        .admit_assessment_notification_receipt_fenced(&first, &accepted, &fences)
        .await
        .is_err());
    assert_eq!(states(&db, registry, "leased").await?, 1);
    Ok(())
}

#[tokio::test]
async fn uncertain_receipts_cannot_admit_an_overlapping_retry() -> Result<()> {
    let (db, registry, request, identity, fences) = super::notifications_tests::fixture().await?;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    let placement = install(&db).await?;
    let destination = destination(&db, registry, &request).await?;
    emit(&db, registry, 1, &db.assessment_database_time().await?).await?;
    let id = db
        .assessment_notification_due_page(registry, 1)
        .await?
        .remove(0);
    let work = db
        .claim_assessment_notification_work_fenced(registry, &id, &placement, &destination, &fences)
        .await?;

    let mut uncertain = receipt(
        &work,
        db.assessment_database_time().await?,
        DeliveryOutcome::Retryable,
    )?;
    uncertain.status = None;
    db.admit_assessment_notification_receipt_fenced(&work, &uncertain, &fences)
        .await?;

    let row = db.backend.query_opt(
        "SELECT not_before FROM assessment_notification_outbox WHERE registry_id = ?1 AND delivery_id = ?2",
        &vals![@slice registry, id],
    ).await?.context("notification intent disappeared")?;
    assert!(row.get::<u64>(0)? >= work.plan.deadline.unix_seconds());
    assert!(db
        .assessment_notification_due_page(registry, 1)
        .await?
        .is_empty());
    assert!(
        db.claim_assessment_notification_work_fenced(
            registry,
            &id,
            &placement,
            &destination,
            &fences,
        )
        .await
        .is_err()
    );
    assert_eq!(consumed(&db, &placement).await?, 1);
    assert_eq!(states(&db, registry, "pending").await?, 1);
    Ok(())
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn notification_admission_claims_quota_and_receipts_are_atomic_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
    let db = Database::with_backend(Box::new(backend)).await?;
    let (db, registry, mut request, identity, fences) =
        super::notifications_tests::fixture_database(db).await?;
    request.configuration.frequency = NotificationFrequency::Digest { window_seconds: 60 };
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    let placement = install(&db).await?;
    let destination = destination(&db, registry, &request).await?;
    let occurred =
        Timestamp::from_unix_seconds(db.assessment_database_time().await?.unix_seconds() - 120)?;
    emit(&db, registry, 3, &occurred).await?;
    let id = db
        .assessment_notification_due_page(registry, 1)
        .await?
        .remove(0);
    let work = db
        .claim_assessment_notification_work_fenced(registry, &id, &placement, &destination, &fences)
        .await?;
    assert_eq!(work.plan.body.events.len(), 3);
    db.check_assessment_notification_work_fenced(&work, &fences)
        .await?;
    let accepted = receipt(
        &work,
        db.assessment_database_time().await?,
        DeliveryOutcome::Accepted,
    )?;
    db.admit_assessment_notification_receipt_fenced(&work, &accepted, &fences)
        .await?;
    assert_eq!(states(&db, registry, "delivered").await?, 3);
    let projected = db
        .assessment_notification_delivery_page(
            registry,
            "",
            Some(&request.subscription_id),
            None,
            10,
        )
        .await?;
    assert_eq!(projected.len(), 3);
    assert!(projected.iter().all(
        |delivery| delivery.state == NotificationIntentState::Delivered
            && delivery.batch_delivery_id.as_deref() == Some(id.as_str())
            && delivery.body_digest == Some(work.plan.body_digest)
            && delivery.receipt_digest.is_some()
    ));
    assert!(db
        .assessment_notification_delivery_page(registry, "", Some("other-subscription"), None, 1)
        .await?
        .is_empty());
    request.expected_revision = 1;
    request.enabled = false;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    assert!(db
        .check_assessment_notification_work_fenced(&work, &fences)
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn recovery_settles_only_its_bounded_page_and_keeps_consumed_quota() -> Result<()> {
    let (db, registry, request, identity, fences) = super::notifications_tests::fixture().await?;
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    let placement = install(&db).await?;
    emit(&db, registry, 5, &db.assessment_database_time().await?).await?;
    db.backend
        .execute(
            "UPDATE assessment_notification_outbox SET attempt = 20 WHERE registry_id = ?1",
            &vals![@slice registry],
        )
        .await?;
    db.reconcile_assessment_notifications(registry, 2).await?;
    assert_eq!(states(&db, registry, "dead-letter").await?, 2);
    assert_eq!(states(&db, registry, "pending").await?, 3);
    db.reconcile_assessment_notifications(registry, 2).await?;
    assert_eq!(states(&db, registry, "dead-letter").await?, 4);
    assert_eq!(consumed(&db, &placement).await?, 0);

    // Fixture-only expiry shortens the original grant; it never extends a JWT.
    let row = db
        .backend
        .query_opt(
            "SELECT configuration_json FROM assessment_subscriptions WHERE registry_id = ?1",
            &vals![@slice registry],
        )
        .await?
        .context("review")?;
    let mut review: super::notifications::PrivateReview =
        serde_json::from_slice(&row.get::<Vec<u8>>(0)?)?;
    review.authority_expires_at = Timestamp::from_unix_seconds(0)?;
    db.backend
        .execute(
            "UPDATE assessment_subscriptions SET configuration_json = ?2 WHERE registry_id = ?1",
            &vals![@slice registry, aos_contract::canonical::to_vec(&review)?],
        )
        .await?;
    db.reconcile_assessment_notifications(registry, 1).await?;
    assert_eq!(states(&db, registry, "revoked").await?, 1);
    assert_eq!(states(&db, registry, "pending").await?, 0);
    assert_eq!(consumed(&db, &placement).await?, 0);
    Ok(())
}
