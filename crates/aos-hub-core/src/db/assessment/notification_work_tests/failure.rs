//! Operational failure events, physical receipt atomicity and nonrecursive fanout.

use super::*;
use aos_assessment_runtime::events::AssessmentEventV1;
use aos_assessment_runtime::notifications::NotificationSummaryV1;

async fn failure_count(db: &Database, registry: i64) -> Result<u64> {
    db.backend.query_opt(
        "SELECT COUNT(*) FROM assessment_events WHERE registry_id = ?1 AND event_kind = 'delivery.failed'",
        &vals![@slice registry],
    ).await?.context("failure count")?.get(0)
}

async fn qualify_failures(db: Database) -> Result<()> {
    let (db, registry, mut request, identity, fences) =
        super::super::notifications_tests::fixture_database(db).await?;
    request.configuration.frequency = NotificationFrequency::Digest { window_seconds: 60 };
    db.write_assessment_subscription_fenced(registry, &request, &identity, &fences)
        .await?;
    let placement = install(&db).await?;
    let destination = destination(&db, registry, &request).await?;
    let now = db.assessment_database_time().await?;
    emit(
        &db,
        registry,
        3,
        &Timestamp::from_unix_seconds(now.unix_seconds() - 120)?,
    )
    .await?;
    let id = db
        .assessment_notification_due_page(registry, 1)
        .await?
        .remove(0);
    let work = db
        .claim_assessment_notification_work_fenced(registry, &id, &placement, &destination, &fences)
        .await?;
    assert_eq!(work.plan.body.events.len(), 3);
    let failure = receipt(
        &work,
        db.assessment_database_time().await?,
        DeliveryOutcome::Retryable,
    )?;

    let mut denied = fences.clone();
    denied.push(
        Statement::new(
            "UPDATE registries SET scope_key = scope_key WHERE id = -1",
            vec![],
        )
        .expecting(1),
    );
    assert!(db
        .admit_assessment_notification_receipt_fenced(&work, &failure, &denied)
        .await
        .is_err());
    assert_eq!(failure_count(&db, registry).await?, 0);
    assert_eq!(states(&db, registry, "leased").await?, 3);
    db.check_assessment_notification_work_fenced(&work, &fences)
        .await?;

    db.admit_assessment_notification_receipt_fenced(&work, &failure, &fences)
        .await?;
    assert_eq!(failure_count(&db, registry).await?, 1);
    assert_eq!(states(&db, registry, "pending").await?, 3);
    assert_eq!(consumed(&db, &placement).await?, 1);
    let row = db.backend.query_opt(
        "SELECT payload_json FROM assessment_events WHERE registry_id = ?1 AND event_kind = 'delivery.failed'",
        &vals![@slice registry],
    ).await?.context("committed failure event")?;
    let event = AssessmentEventV1::from_slice(&row.get::<Vec<u8>>(0)?)?;
    let AssessmentEventPayload::DeliveryFailed { failure: facts } = &event.payload else {
        anyhow::bail!("failure event has a different payload");
    };
    assert_eq!(facts.delivery_id, work.plan.body.delivery_id);
    assert_eq!(facts.subscription_id, request.subscription_id);
    assert_eq!(
        facts.subscription_revision,
        work.plan.body.subscription_revision
    );
    assert_eq!(facts.receipt_digest, failure.digest()?);
    assert_eq!(facts.attempt, 1);
    assert!(!facts.terminal && facts.retry_at.is_some());
    assert!(NotificationSummaryV1::from_event(&event).is_err());
    assert!(db
        .assessment_notification_intent_statements(registry, &event)
        .await?
        .is_empty());

    db.admit_assessment_notification_receipt_fenced(&work, &failure, &fences)
        .await?;
    assert_eq!(failure_count(&db, registry).await?, 1);
    assert_eq!(states(&db, registry, "pending").await?, 3);
    assert_eq!(consumed(&db, &placement).await?, 1);
    // Advance only fixture eligibility, preserving all actual review and attempt
    // authority, to qualify a second physical receipt without sleeping.
    db.backend
        .execute(
            "UPDATE assessment_notification_outbox SET not_before = 0 WHERE registry_id = ?1",
            &vals![@slice registry],
        )
        .await?;
    let next = db
        .claim_assessment_notification_work_fenced(registry, &id, &placement, &destination, &fences)
        .await?;
    assert_eq!(next.plan.body, work.plan.body);
    assert_eq!(next.plan.attempt, 2);
    let permanent = receipt(
        &next,
        db.assessment_database_time().await?,
        DeliveryOutcome::PermanentFailure,
    )?;
    db.admit_assessment_notification_receipt_fenced(&next, &permanent, &fences)
        .await?;
    assert_eq!(failure_count(&db, registry).await?, 2);
    assert_eq!(states(&db, registry, "dead-letter").await?, 3);
    assert_eq!(states(&db, registry, "pending").await?, 0);
    assert_eq!(consumed(&db, &placement).await?, 2);
    assert!(db
        .assessment_notification_due_page(registry, 10)
        .await?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn failure_events_settle_one_batch_atomically_and_never_generate_callbacks() -> Result<()> {
    qualify_failures(Database::open_in_memory().await?).await
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn failure_events_and_receipts_are_atomic_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
    qualify_failures(Database::with_backend(Box::new(backend)).await?).await
}

#[tokio::test]
async fn accepted_receipts_do_not_allocate_failure_events() -> Result<()> {
    let (db, registry, request, identity, fences) =
        super::super::notifications_tests::fixture().await?;
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
    let accepted = receipt(
        &work,
        db.assessment_database_time().await?,
        DeliveryOutcome::Accepted,
    )?;
    db.admit_assessment_notification_receipt_fenced(&work, &accepted, &fences)
        .await?;
    assert_eq!(failure_count(&db, registry).await?, 0);
    assert_eq!(states(&db, registry, "delivered").await?, 1);
    Ok(())
}
