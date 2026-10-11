//! Atomic notification admission, revocation and independently scoped destination review.

use anyhow::{Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::alerts::IssueFamily;
use aos_assessment_runtime::events::AssessmentEventPayload;
use aos_assessment_runtime::notifications::{
    NotificationBodyV1, NotificationConfigurationV1, NotificationEventKind, NotificationFrequency,
    NotificationThreshold, SubscriptionWriteV1,
};
use aos_contract::Sha256Digest;

use super::{authority_tests::claims, AssessmentInventoryAdmission, AssessmentObjectKind};
use crate::auth::jwt::Claims;
use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;
use crate::domain::Permission;

pub(super) async fn fixture() -> Result<(
    Database,
    i64,
    SubscriptionWriteV1,
    Claims,
    Vec<CheckedStatement>,
)> {
    fixture_database(Database::open_in_memory().await?).await
}

pub(super) async fn fixture_database(
    db: Database,
) -> Result<(
    Database,
    i64,
    SubscriptionWriteV1,
    Claims,
    Vec<CheckedStatement>,
)> {
    let slug = format!("notification-fixture-{}", uuid::Uuid::new_v4().simple());
    let organization = db.create_org(&slug, "Notification fixture").await?;
    let registry_id = db
        .create_managed_registry(organization, "", "packages", "private", &[], false)
        .await?;
    let registry = db
        .registry_by_id(registry_id)
        .await?
        .context("managed notification registry")?;
    db.admit_assessment_inventory(
        &AssessmentInventoryAdmission {
            registry_id,
            partition: registry.scope_key.clone(),
            provenance_digest: Sha256Digest::of_bytes(b"verified source"),
            admission_digest: Sha256Digest::of_bytes(b"verified admission"),
            expected_resource_version: 0,
        },
        &super::scans_tests::fixture()?,
    )
    .await?;
    let webhook = db
        .seed_webhook_for_test(
            organization,
            "https://receiver.example/callback",
            "test://assessment/notification-key/v1",
            &Sha256Digest::of_bytes([7; 32]).hex(),
            &[],
        )
        .await?;
    let identity = claims(&db).await?;
    let expiry = Timestamp::from_unix_seconds(u64::try_from(identity.exp)?)?;
    let destination = db
        .assessment_notification_destination(registry_id, &format!("webhook:{webhook}"), &expiry)
        .await?;
    let request = SubscriptionWriteV1 {
        service_credential_id: None,
        schema: "aos.assessment-subscription-write/v1".into(),
        resource_scope: registry.scope_key,
        subscription_id: "security-updates".into(),
        expected_revision: 0,
        enabled: true,
        configuration: NotificationConfigurationV1 {
            schema: "aos.assessment-notification-configuration/v1".into(),
            events: vec![NotificationEventKind::ScanCompleted],
            families: vec![
                IssueFamily::Vulnerability,
                IssueFamily::PackageUpdate,
                IssueFamily::Coverage,
                IssueFamily::SourceHealth,
            ],
            threshold: NotificationThreshold::AllAttention,
            package_coordinates: Vec::new(),
            severity: None,
            suppressions: Vec::new(),
            frequency: NotificationFrequency::Immediate {},
            destination_reference: destination.destination_reference.clone(),
            destination_revision: destination.revision,
            destination_digest: destination.digest()?,
            review_expires_at: expiry,
        },
    };
    // Existing read grants qualify the current-credential primitive without
    // installing the separate assessment default-role policy awaiting approval.
    let fences = db
        .assessment_iam_statements(&identity, &request.resource_scope, Permission::Read)
        .await?;
    Ok((db, registry_id, request, identity, fences))
}

async fn event_statements(db: &Database, registry_id: i64) -> Result<Vec<CheckedStatement>> {
    db.assessment_event_statements(
        registry_id,
        vec![AssessmentEventPayload::ScanCompleted {
            scan_id: "fixture-scan".into(),
            assessment_digest: Sha256Digest::of_bytes(b"fixture-assessment"),
        }],
        &db.assessment_database_time().await?,
    )
    .await
}

async fn outbox_count(db: &Database, registry_id: i64, state: &str) -> Result<u64> {
    db.backend.query_opt("SELECT COUNT(*) FROM assessment_notification_outbox WHERE registry_id = ?1 AND state = ?2", &vals![@slice registry_id, state]).await?.context("outbox count")?.get(0)
}

#[tokio::test]
async fn generic_webhook_wildcards_never_implicitly_receive_assessment_events() -> Result<()> {
    let (db, registry_id, _, _, _) = fixture().await?;
    db.backend
        .checked_batch(&event_statements(&db, registry_id).await?)
        .await?;
    assert_eq!(outbox_count(&db, registry_id, "pending").await?, 0);
    Ok(())
}

#[tokio::test]
async fn subscription_replays_preserve_original_authority_and_public_projection_hides_claims(
) -> Result<()> {
    let (db, registry_id, request, identity, fences) = fixture().await?;
    let first = db
        .write_assessment_subscription_fenced(registry_id, &request, &identity, &fences)
        .await?;
    let mut longer = identity.clone();
    longer.exp += 3600;
    let replay = db
        .write_assessment_subscription_fenced(registry_id, &request, &longer, &fences)
        .await?;
    assert_eq!(first, replay);
    assert_eq!(
        first.authority_expires_at.unix_seconds(),
        u64::try_from(identity.exp)?
    );
    let projection = String::from_utf8(first.to_bytes()?)?;
    for private in [
        &identity.sub,
        "ownerId",
        "browserSessionIdHash",
        "claims",
        "test://assessment/notification-key/v1",
    ] {
        assert!(!projection.contains(private));
    }
    assert_eq!(db.assessment_event_page(registry_id, 0, 10).await?.len(), 1);
    let mut changed = request;
    changed.configuration.threshold = NotificationThreshold::ConfirmedAttention;
    assert!(db
        .write_assessment_subscription_fenced(registry_id, &changed, &identity, &fences)
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn event_and_compact_outbox_intent_commit_or_roll_back_together() -> Result<()> {
    let (db, registry_id, request, identity, fences) = fixture().await?;
    db.write_assessment_subscription_fenced(registry_id, &request, &identity, &fences)
        .await?;
    let mut rejected = event_statements(&db, registry_id).await?;
    rejected.push(
        Statement::new(
            "UPDATE registries SET scope_key = scope_key WHERE id = ?1",
            vals![registry_id + 1],
        )
        .expecting(1),
    );
    assert!(db.backend.checked_batch(&rejected).await.is_err());
    assert_eq!(outbox_count(&db, registry_id, "pending").await?, 0);
    assert_eq!(db.assessment_event_page(registry_id, 0, 10).await?.len(), 1);

    db.backend
        .checked_batch(&event_statements(&db, registry_id).await?)
        .await?;
    assert_eq!(outbox_count(&db, registry_id, "pending").await?, 1);
    let row = db
        .backend
        .query_opt(
            "SELECT payload_digest FROM assessment_notification_outbox WHERE registry_id = ?1",
            &vals![@slice registry_id],
        )
        .await?
        .context("intent")?;
    let digest = Sha256Digest::parse(&row.get::<String>(0)?)?;
    let body = db
        .assessment_object(
            &request.resource_scope,
            AssessmentObjectKind::NotificationBody,
            digest,
        )
        .await?
        .context("compact body")?;
    let body = NotificationBodyV1::from_slice(&body)?;
    assert_eq!(body.events.len(), 1);
    assert_eq!(body.events[0].sequence, 2);
    assert_eq!(body.subscription_revision, 1);
    Ok(())
}

#[tokio::test]
async fn notification_filters_bind_historical_alert_facts_and_preserve_atomic_journal() -> Result<()>
{
    selector_transaction(Database::open_in_memory().await?).await
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn postgres_notification_filters_bind_historical_alert_facts() -> Result<()> {
    let path =
        std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE").context("PostgreSQL fixture URL file")?;
    let url = std::fs::read_to_string(path)?;
    let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
    selector_transaction(Database::with_backend(Box::new(backend)).await?).await
}

async fn selector_transaction(database: Database) -> Result<()> {
    use aos_assessment::input::Profile;
    use aos_assessment_runtime::alerts::{
        AlertTransitionKind, AssessmentAlertV1, AttentionState, IssueObservation,
    };
    use aos_assessment_runtime::attention_selection::{AttentionSelectionContext, SeverityBand};
    use aos_assessment_runtime::notifications::{
        NotificationSeverityFilter, NotificationSuppression,
    };

    let (db, registry_id, mut request, identity, fences) = fixture_database(database).await?;
    let now = db.assessment_database_time().await?;
    let issue_key = Sha256Digest::of_bytes(b"scoped exact historical issue");
    request.configuration.events = vec![NotificationEventKind::AlertOpened];
    request.configuration.package_coordinates = vec!["publisher/selected".into()];
    request.configuration.severity = Some(NotificationSeverityFilter {
        minimum: SeverityBand::High,
        include_unknown: false,
    });
    request.configuration.suppressions = vec![NotificationSuppression {
        issue_key,
        until: now.clone(),
    }];
    db.write_assessment_subscription_fenced(registry_id, &request, &identity, &fences)
        .await?;

    let mut alert = AssessmentAlertV1 {
        schema: "aos.assessment-alert/v1".into(),
        issue_key,
        issue: IssueObservation {
            issue_key,
            context_digest: Sha256Digest::of_bytes(b"subject-component-context"),
            family: IssueFamily::Vulnerability,
            profile: Profile::Vulnerabilities,
            lineage_ids: vec!["CVE-2026-10001".into()],
            source_keys: vec![Sha256Digest::of_bytes(b"osv-query")],
            material_digest: Sha256Digest::of_bytes(b"material"),
            uncertain: false,
            selection_context: Some(AttentionSelectionContext {
                package_coordinate: "publisher/selected".into(),
                severity_bands: vec![SeverityBand::Critical],
                unknown_severity: false,
            }),
        },
        state: AttentionState::Open,
        episode: 1,
        sequence: 1,
        assessment_digest: Sha256Digest::of_bytes(b"retained assessment"),
        updated_at: now.clone(),
        acknowledgements: Vec::new(),
        lineage_keys: Vec::new(),
    };
    alert.validate()?;

    // The current inventory contains a different coordinate. Selection must use
    // the event's immutable facts, and must not read a moving assessment head.
    let payload = |alert: &AssessmentAlertV1| AssessmentEventPayload::Alert {
        transition: AlertTransitionKind::Opened,
        alert: Box::new(alert.clone()),
    };
    let selected = db
        .assessment_event_statements(registry_id, vec![payload(&alert)], &now)
        .await?;
    let mut rejected = selected.clone();
    rejected.push(
        Statement::new(
            "UPDATE registries SET scope_key = scope_key WHERE id = ?1",
            vals![registry_id + 1],
        )
        .expecting(1),
    );
    assert!(db.backend.checked_batch(&rejected).await.is_err());
    assert_eq!(outbox_count(&db, registry_id, "pending").await?, 0);
    assert_eq!(db.assessment_event_page(registry_id, 0, 10).await?.len(), 1);

    db.backend.checked_batch(&selected).await?;
    assert_eq!(outbox_count(&db, registry_id, "pending").await?, 1);
    alert
        .issue
        .selection_context
        .as_mut()
        .context("selection facts")?
        .package_coordinate = "other-publisher/selected".into();
    db.backend
        .checked_batch(
            &db.assessment_event_statements(registry_id, vec![payload(&alert)], &now)
                .await?,
        )
        .await?;
    alert
        .issue
        .selection_context
        .as_mut()
        .context("selection facts")?
        .package_coordinate = "publisher/selected".into();
    alert
        .issue
        .selection_context
        .as_mut()
        .context("selection facts")?
        .severity_bands = vec![SeverityBand::Low];
    db.backend
        .checked_batch(
            &db.assessment_event_statements(registry_id, vec![payload(&alert)], &now)
                .await?,
        )
        .await?;
    assert_eq!(outbox_count(&db, registry_id, "pending").await?, 1);
    assert_eq!(db.assessment_event_page(registry_id, 0, 10).await?.len(), 4);

    request.expected_revision = 1;
    request.configuration.suppressions[0].until = request.configuration.review_expires_at.clone();
    db.write_assessment_subscription_fenced(registry_id, &request, &identity, &fences)
        .await?;
    alert
        .issue
        .selection_context
        .as_mut()
        .context("selection facts")?
        .severity_bands = vec![SeverityBand::Critical];
    db.backend
        .checked_batch(
            &db.assessment_event_statements(registry_id, vec![payload(&alert)], &now)
                .await?,
        )
        .await?;
    // Re-review revokes the old pending intent; suppression leaves the new event
    // visible in the durable inbox instead of changing or dropping the finding.
    assert_eq!(outbox_count(&db, registry_id, "pending").await?, 0);
    assert_eq!(outbox_count(&db, registry_id, "revoked").await?, 1);
    assert_eq!(db.assessment_event_page(registry_id, 0, 10).await?.len(), 6);
    Ok(())
}

#[tokio::test]
async fn replacing_or_disabling_reviews_revokes_pending_and_leased_private_work() -> Result<()> {
    let (db, registry_id, mut request, identity, fences) = fixture().await?;
    db.write_assessment_subscription_fenced(registry_id, &request, &identity, &fences)
        .await?;
    db.backend
        .checked_batch(&event_statements(&db, registry_id).await?)
        .await?;
    db.backend.execute("UPDATE assessment_notification_outbox SET state = 'leased', claim_token = 'old-token', lease_expires_at = ?2 WHERE registry_id = ?1", &vals![@slice registry_id, identity.exp]).await?;
    // Disabling still works after the independent destination was disabled/rotated.
    db.backend
        .execute(
            "UPDATE webhooks SET active = 0, resource_version = resource_version + 1",
            &[],
        )
        .await?;
    request.expected_revision = 1;
    request.enabled = false;
    let disabled = db
        .write_assessment_subscription_fenced(registry_id, &request, &identity, &fences)
        .await?;
    assert!(!disabled.enabled);
    assert_eq!(disabled.revision, 2);
    assert_eq!(outbox_count(&db, registry_id, "revoked").await?, 1);
    assert_eq!(outbox_count(&db, registry_id, "leased").await?, 0);
    db.backend
        .checked_batch(&event_statements(&db, registry_id).await?)
        .await?;
    assert_eq!(outbox_count(&db, registry_id, "pending").await?, 0);
    let replay = db
        .write_assessment_subscription_fenced(registry_id, &request, &identity, &fences)
        .await?;
    assert_eq!(replay, disabled);
    request.enabled = true;
    assert!(db
        .write_assessment_subscription_fenced(registry_id, &request, &identity, &fences)
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn prepared_fanout_is_fenced_by_concurrent_review_replacement() -> Result<()> {
    let (db, registry_id, mut request, identity, fences) = fixture().await?;
    db.write_assessment_subscription_fenced(registry_id, &request, &identity, &fences)
        .await?;
    let prepared = event_statements(&db, registry_id).await?;
    request.expected_revision = 1;
    request.enabled = false;
    db.write_assessment_subscription_fenced(registry_id, &request, &identity, &fences)
        .await?;
    assert!(db.backend.checked_batch(&prepared).await.is_err());
    assert_eq!(outbox_count(&db, registry_id, "pending").await?, 0);
    assert_eq!(db.assessment_event_page(registry_id, 0, 10).await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn revoked_credentials_and_cross_organization_destinations_cannot_create_reviews(
) -> Result<()> {
    let (db, registry_id, request, identity, fences) = fixture().await?;
    let organization = db
        .create_org("other-organization", "Other organization")
        .await?;
    let unrelated = db
        .seed_webhook_for_test(
            organization,
            "https://other-receiver.example/callback",
            "test://assessment/notification-other/v1",
            &Sha256Digest::of_bytes([8; 32]).hex(),
            &[],
        )
        .await?;
    assert!(db
        .assessment_notification_destination(
            registry_id,
            &format!("webhook:{unrelated}"),
            &request.configuration.review_expires_at
        )
        .await
        .is_err());
    assert!(db
        .write_assessment_subscription_fenced(registry_id, &request, &identity, &[])
        .await
        .is_err());
    db.backend
        .execute(
            "UPDATE tokens SET revoked_at = ?2 WHERE id = ?1",
            &vals![@slice identity.sub, identity.iat],
        )
        .await?;
    assert!(db
        .write_assessment_subscription_fenced(registry_id, &request, &identity, &fences)
        .await
        .is_err());
    assert!(db
        .assessment_subscription_page(registry_id, "", 10)
        .await?
        .is_empty());
    assert!(db
        .assessment_event_page(registry_id, 0, 10)
        .await?
        .is_empty());
    Ok(())
}
