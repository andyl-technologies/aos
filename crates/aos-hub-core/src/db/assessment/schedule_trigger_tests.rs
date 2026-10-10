//! Continuous input coalescing and same-second retry identity qualification.

use anyhow::{Context as _, Result};
use aos_contract::Sha256Digest;

use super::{schedule_key, triggers::input_basis};
use crate::backend::CheckedStatement;
use crate::db::assessment::{AssessmentInventoryAdmission, AssessmentScanRecord};
use crate::db::Database;

async fn admit(
    db: &Database,
    registry: i64,
    scope: &str,
    identity: &str,
    fences: &[CheckedStatement],
) -> Result<AssessmentScanRecord> {
    let key = schedule_key(scope, identity)?;
    let record = db
        .schedule_record(registry, &key)
        .await?
        .context("due review")?;
    let mut fences = fences.to_vec();
    fences.push(db.schedule_revision_guard(registry, &record, true));
    // This private fixture uses real existing read authority. Public scan
    // permissions and role assignments remain independently fail-closed.
    db.admit_due_schedule_fenced(registry, scope, record, &fences)
        .await
}

pub(in crate::db::assessment) async fn qualify_wakeups(database: Database) -> Result<()> {
    let (db, registry, reviewer, fences, mut write) =
        super::tests::setup_database(database).await?;
    write.configuration.continuous = true;
    let created = db
        .write_assessment_schedule_fenced(registry, &write, &reviewer, &fences)
        .await?;
    let identity = write.schedule_id.clone();
    let scope = write.resource_scope.clone();
    let initial_basis = input_basis(
        &db.assessment_resource(registry)
            .await?
            .context("initial resource")?,
    )?;
    let first = admit(&db, registry, &scope, &identity, &fences).await?;
    assert_eq!(
        input_basis(
            &db.assessment_resource(registry)
                .await?
                .context("allocated resource")?
        )?,
        initial_basis
    );

    write.schedule_id = "legacy-cadence".into();
    write.configuration.continuous = false;
    db.write_assessment_schedule_fenced(registry, &write, &reviewer, &fences)
        .await?;
    db.backend.execute("UPDATE assessment_schedules SET next_due_at = ?3 WHERE registry_id = ?1 AND schedule_id = ?2", &vals![@slice registry, schedule_key(&scope, &write.schedule_id)?, created.next_due_at.unix_seconds() + 3600]).await?;
    let legacy = db
        .assessment_schedule(registry, &write.schedule_id)
        .await?
        .context("legacy review")?;
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);

    let original_policy = super::super::scans_tests::fixture()?.policy;
    let mut changed_policy = original_policy.clone();
    changed_policy.upstream_max_age_seconds += 1;
    for policy in [&changed_policy, &original_policy] {
        let resource = db
            .assessment_resource(registry)
            .await?
            .context("policy resource")?;
        db.set_assessment_policy_fenced(
            registry,
            &scope,
            resource.resource_version,
            policy,
            &fences,
        )
        .await?;
    }
    let restored = db
        .assessment_resource(registry)
        .await?
        .context("restored policy")?;
    assert_eq!(restored.policy_digest, original_policy.digest()?);
    assert_ne!(input_basis(&restored)?, initial_basis);
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 1);
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);

    // Force the original due second to qualify retry identity independently of
    // wall-clock scheduling. A reactive wake must admit a distinct scan.
    db.backend.execute("UPDATE assessment_schedules SET next_due_at = ?3 WHERE registry_id = ?1 AND schedule_id = ?2", &vals![@slice registry, schedule_key(&scope, &identity)?, created.next_due_at.unix_seconds()]).await?;
    let second = admit(&db, registry, &scope, &identity, &fences).await?;
    assert_ne!(first.scan_id, second.scan_id);
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);
    let latest = db
        .assessment_schedule(registry, &identity)
        .await?
        .context("continuous review")?;
    assert_eq!(latest.revision, created.revision);
    assert_eq!(latest.authority_expires_at, created.authority_expires_at);
    let public = String::from_utf8(latest.to_bytes()?)?;
    assert!(!public.contains("observedInput"));
    assert!(!public.contains("pendingInput"));

    let mut changed_inventory = super::super::scans_tests::fixture()?;
    changed_inventory.inventory.subjects[0].platform = "aarch64-linux".into();
    let resource = db
        .assessment_resource(registry)
        .await?
        .context("inventory resource")?;
    db.admit_assessment_inventory_fenced(
        &AssessmentInventoryAdmission {
            registry_id: registry,
            partition: scope.clone(),
            expected_resource_version: resource.resource_version,
            provenance_digest: Sha256Digest::of_bytes("new verified inventory"),
            admission_digest: Sha256Digest::of_bytes("new verified admission"),
        },
        &changed_inventory,
        &fences,
    )
    .await?;
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 1);
    let third = admit(&db, registry, &scope, &identity, &fences).await?;
    assert_ne!(second.scan_id, third.scan_id);
    assert_eq!(
        third.request.inventory_digest,
        changed_inventory.inventory.digest()?
    );
    assert_eq!(
        db.assessment_schedule(registry, &write.schedule_id).await?,
        Some(legacy)
    );
    assert_eq!(db.wake_changed_assessment_schedules(registry, 10).await?, 0);
    assert!(db
        .wake_changed_assessment_schedules(registry, 0)
        .await
        .is_err());
    assert!(db
        .wake_changed_assessment_schedules(registry, 11)
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn input_changes_coalesce_without_scan_feedback_or_same_second_slot_collisions() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("continuous.db");
    qualify_wakeups(Database::open(&path).await?).await?;

    // Reopening the persistent database must retain the admitted watermark.
    // It must neither allocate a generation nor repeat a reactive wake.
    let reopened = Database::open(&path).await?;
    let registry: i64 = reopened
        .backend
        .query_opt("SELECT registry_id FROM assessment_resources", &[])
        .await?
        .context("retained resource")?
        .get(0)?;
    let before = reopened.assessment_resource(registry).await?;
    assert_eq!(
        reopened
            .wake_changed_assessment_schedules(registry, 10)
            .await?,
        0
    );
    assert_eq!(reopened.assessment_resource(registry).await?, before);
    let review = reopened
        .assessment_schedule(registry, "daily-fixture")
        .await?
        .context("retained continuous review")?;
    assert!(review.configuration.continuous);
    let record = reopened
        .schedule_record(
            registry,
            &schedule_key(&review.resource_scope, &review.schedule_id)?,
        )
        .await?
        .context("retained private watermark")?;
    assert!(record.review.pending_input.is_none());
    assert_eq!(
        record.review.observed_input,
        Some(input_basis(&before.context("retained input")?)?)
    );
    Ok(())
}
