//! Fair bounded due enumeration without changing scan retry or review authority.

use crate::db::Database;
use anyhow::{Context as _, Result};

#[tokio::test]
async fn revoked_reviews_rotate_without_advancing_due_slots_or_granting_authority() -> Result<()> {
    qualify_queue(Database::open_in_memory().await?).await
}

pub(in crate::db::assessment) async fn qualify_queue(database: Database) -> Result<()> {
    let (db, registry, reviewer, fences, mut write) =
        super::tests::setup_database(database).await?;
    for index in 0..11 {
        write.schedule_id = format!("revoked-{index:02}");
        db.write_assessment_schedule_fenced(registry, &write, &reviewer, &fences)
            .await?;
    }
    db.backend
        .execute(
            "UPDATE assessment_schedules SET updated_at = 1 WHERE registry_id = ?1",
            &vals![@slice registry],
        )
        .await?;
    let before = db
        .assessment_schedule_capture(registry, &write.resource_scope)
        .await?;
    db.revoke_token(&reviewer.sub).await?;

    assert_eq!(db.admit_due_assessment_schedules(registry, 10).await?, 0);
    let remaining: u64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM assessment_schedules WHERE registry_id = ?1 AND updated_at = 1",
            &vals![@slice registry],
        )
        .await?
        .context("unexamined review count")?
        .get(0)?;
    assert_eq!(remaining, 1);

    // The eleventh review is examined on the next finite page even when the
    // earlier ten reviews remain due and all attempts share a clock second.
    assert_eq!(db.admit_due_assessment_schedules(registry, 10).await?, 0);
    let remaining: u64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM assessment_schedules WHERE registry_id = ?1 AND updated_at = 1",
            &vals![@slice registry],
        )
        .await?
        .context("remaining reviews")?
        .get(0)?;
    assert_eq!(remaining, 0);
    assert_eq!(
        db.assessment_schedule_capture(registry, &write.resource_scope)
            .await?,
        before
    );
    let scans: u64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM assessment_scans WHERE registry_id = ?1",
            &vals![@slice registry],
        )
        .await?
        .context("scan count")?
        .get(0)?;
    assert_eq!(scans, 0);
    assert!(db
        .admit_due_assessment_schedules(registry, 0)
        .await
        .is_err());
    assert!(db
        .admit_due_assessment_schedules(registry, 11)
        .await
        .is_err());
    Ok(())
}
