//! Real MySQL-backend qualification against disposable server/database custody.
//!
//! These tests reuse the SQLite/PostgreSQL admission and race fixtures through
//! the production MySQL backend. They establish no public assessment IAM grants.

use anyhow::{Context as _, Result};

use crate::backend::SqlxBackend;
use crate::db::Database;

async fn database() -> Result<Database> {
    let path = std::env::var_os("AOS_ASSESSMENT_MYSQL_URL_FILE")
        .context("disposable MySQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = SqlxBackend::connect_mysql(url.trim()).await?;
    Database::with_backend(Box::new(backend)).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn retained_status_heads_on_mysql() -> Result<()> {
    super::status_snapshot_tests::retained_heads(database().await?).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn retained_status_byte_and_capture_limits_on_mysql() -> Result<()> {
    super::status_snapshot_tests::storage_bounds(database().await?).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn retained_candidate_stabilization_on_mysql() -> Result<()> {
    super::schedules::stabilization_tests::qualify_stabilization(database().await?).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn older_projection_catchup_on_mysql() -> Result<()> {
    super::schedules::stabilization_tests::qualify_epoch_catchup(database().await?).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn continuous_inventory_and_policy_wakeups_on_mysql() -> Result<()> {
    super::schedules::trigger_tests::qualify_wakeups(database().await?).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn continuous_expiry_coalescing_on_mysql() -> Result<()> {
    super::schedules::deadline_tests::qualify_deadlines(database().await?).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn rejected_schedule_pages_rotate_fairly_on_mysql() -> Result<()> {
    super::schedules::queue_tests::qualify_queue(database().await?).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn retained_advisory_revisions_on_mysql() -> Result<()> {
    super::advisory_snapshot::tests::qualify_capture(database().await?).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn retained_scan_pages_and_concurrent_limits_on_mysql() -> Result<()> {
    let (db, registry, request) = super::scans_tests::setup_database(database().await?).await?;
    super::read_snapshot_tests::retained_pages(&db, registry, request).await?;

    let (db, registry, mut request) = super::scans_tests::setup_database(database().await?).await?;
    super::read_snapshot_tests::storage_bounds(&db, registry, &mut request).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn retained_public_subscription_pages_on_mysql() -> Result<()> {
    let (db, registry, request, identity, fences) =
        super::notifications_tests::fixture_database(database().await?).await?;
    super::subscription_snapshot::tests::retained_reviews(db, registry, request, identity, fences)
        .await?;
    super::subscription_snapshot::tests::storage_bounds(database().await?).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn retained_attention_revisions_and_capture_limits_on_mysql() -> Result<()> {
    super::alert_snapshot::tests::retained_episodes(database().await?).await?;
    super::alert_snapshot::tests::storage_bounds(database().await?).await?;
    super::alert_snapshot::tests::oversized_capture(database().await?).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn retained_schedule_reviews_and_capture_limits_on_mysql() -> Result<()> {
    super::schedule_snapshot::tests::retained_reviews(database().await?).await?;
    super::schedule_snapshot::tests::storage_bounds(database().await?).await?;
    super::schedule_snapshot::tests::oversized_capture(database().await?).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn retained_delivery_attempts_and_capture_limits_on_mysql() -> Result<()> {
    super::delivery_snapshot::tests::retained_attempts(database().await?).await?;
    super::delivery_snapshot::tests::storage_bounds(database().await?).await?;
    super::delivery_snapshot::tests::oversized_capture(database().await?).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn reviewed_service_schedule_credential_revocation_on_mysql() -> Result<()> {
    super::schedules::service_tests::reviewed_service_scan_survives_reviewer_revocation_and_fences_service_revocation(database().await?).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn reviewed_service_delivery_credential_revocation_on_mysql() -> Result<()> {
    super::notifications::service_tests::reviewed_service_delivery(database().await?).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn binary_serving_identity_reopens_and_refuses_invalid_utf8_without_writes() -> Result<()> {
    use crate::backend::Backend as _;

    let path = std::env::var_os("AOS_ASSESSMENT_MYSQL_URL_FILE")
        .context("disposable MySQL URL file required")?;
    let raw_url = std::fs::read_to_string(path)?;
    let mut url = url::Url::parse(raw_url.trim())?;
    let admin = SqlxBackend::connect_mysql(url.as_str()).await?;
    // The fixed prefix and hexadecimal UUID form a trusted SQL identifier.
    // Only the explicitly selected disposable server receives this fixture.
    let name = format!("assessment_identity_{}", uuid::Uuid::new_v4().simple());
    admin
        .execute(
            &format!("CREATE DATABASE {name} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"),
            &[],
        )
        .await?;
    url.set_path(&format!("/{name}"));
    let first = SqlxBackend::connect_mysql(url.as_str()).await?;
    let second = SqlxBackend::connect_mysql(url.as_str()).await?;

    let (left, right) = tokio::join!(first.migrate_schema(), second.migrate_schema());
    left?;
    right?;
    let identity = first
        .query("SELECT identity FROM hub_schema_identity", &[])
        .await?;
    assert_eq!(identity.len(), 1);
    assert_eq!(identity[0].get::<String>(0)?, crate::db::SCHEMA_IDENTITY);
    second.migrate_schema().await?;

    // A nonbinary text collation also exposes the same exact identity bytes.
    first.execute(
        "ALTER TABLE hub_schema_identity MODIFY identity VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL",
        &[],
    ).await?;
    second.migrate_schema().await?;

    // Only this malformed disposable schema admits non-UTF-8 identity bytes.
    // Preserve the valid byte length; refusal must leave both bookkeeping
    // ledgers and the invalid identity untouched.
    first
        .execute(
            "ALTER TABLE hub_schema_identity MODIFY identity VARBINARY(255) NOT NULL",
            &[],
        )
        .await?;
    first
        .execute(
            "UPDATE hub_schema_identity SET identity = ?1",
            &vals![vec![0xff_u8; crate::db::SCHEMA_IDENTITY.len()]],
        )
        .await?;
    let query = "SELECT identity, schema_version.version, keyed.version FROM hub_schema_identity, schema_version, hub_schema_version AS keyed";
    let before = first.query(query, &[]).await?;
    assert!(second.migrate_schema().await.is_err());
    assert_eq!(first.query(query, &[]).await?, before);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn immutable_job_authority_and_original_expiry_on_mysql() -> Result<()> {
    super::authority_tests::qualify_private_job(database().await?).await
}

#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_MYSQL_URL_FILE pointing to a disposable MySQL database"]
async fn committed_event_replay_and_lost_custody_on_mysql() -> Result<()> {
    super::event_replay::tests::qualify_replay(database().await?).await?;
    Ok(())
}
