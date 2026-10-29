//! Real PostgreSQL coverage for quota and OCI-state lock ordering.

use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use aos_oci_types::{RepositoryName, Sha256Digest};
use sha2::Digest as _;
use tokio::sync::Barrier;
use tokio::task::JoinSet;
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber as _;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

use crate::backend::SqlxBackend;
use crate::db::AppendOciUploadChunk;
use crate::db::BeginOciUpload;
use crate::db::Database;
use crate::db::OciSha256State;
use crate::db::OciUploadChunkRecord;

#[derive(Default)]
struct Deadlocks {
    retries: AtomicUsize,
    next_span: AtomicU64,
}

#[derive(Default)]
struct DeadlockMessage(bool);

impl Visit for DeadlockMessage {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.0 |= format!("{value:?}").contains("retrying rolled-back postgres deadlock");
        }
    }
}

impl Subscriber for Deadlocks {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
        Id::from_u64(self.next_span.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut message = DeadlockMessage::default();
        event.record(&mut message);
        if message.0 {
            self.retries.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in AOS_HUB_OCI_UPLOAD_TEST_PG_URL"]
async fn parallel_managed_chunks_follow_authorized_upload_quota_lock_order() -> Result<()> {
    let url = std::env::var("AOS_HUB_OCI_UPLOAD_TEST_PG_URL")
        .context("dedicated PostgreSQL database is required")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(24)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET deadlock_timeout = '20ms'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await?;
    let database = Database::with_backend(Box::new(SqlxBackend::Postgres(pool.clone()))).await?;
    let (database, registry, placement) =
        super::tests::catalog_database_with_backend(database).await;
    let database = Arc::new(database);
    let owner = database
        .registry_by_id(registry)
        .await?
        .context("registry is absent")?;
    let organization = owner.org_id.context("registry must have an organization")?;
    let placement = database
        .surface_placement(placement)
        .await?
        .context("placement is absent")?;
    let revision = database
        .placement_publication_write_revision(placement.id)
        .await?
        .context("write revision is absent")?;
    let now = 1_700_000_100;
    let repository = database
        .ensure_oci_repository(registry, &RepositoryName::parse("parallel")?, now)
        .await?;
    let baseline = database.org_usage(organization).await?;

    // Briefly widen overlap around real quota row locks. Both paths still run
    // their original checked batches, including every ownership and CAS fence.
    sqlx::raw_sql(
        "CREATE FUNCTION pause_upload_quota() RETURNS trigger LANGUAGE plpgsql AS $$
           BEGIN PERFORM pg_sleep(0.002); RETURN NEW; END $$;
         CREATE TRIGGER pause_upload_quota BEFORE UPDATE ON org_usage
           FOR EACH ROW EXECUTE FUNCTION pause_upload_quota()",
    )
    .execute(&pool)
    .await?;

    let deadlocks = Arc::new(Deadlocks::default());
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = JoinSet::new();
    for worker in 0..16 {
        let database = Arc::clone(&database);
        let barrier = Arc::clone(&barrier);
        let placement = placement.clone();
        let subscriber = Arc::clone(&deadlocks);
        let repository = repository.id;
        let revision = revision.revision;
        tasks.spawn(
            async move {
                barrier.wait().await;
                for attempt in 0..4 {
                    let identity = format!("parallel-{worker}-{attempt}");
                    let bytes = identity.as_bytes();
                    let digest = Sha256Digest::parse(&format!(
                        "sha256:{}",
                        hex::encode(sha2::Sha256::digest(bytes))
                    ))?;
                    // The authorization path owns quota rows before entering
                    // OCI code. Managed chunk receipts have no extra IAM list.
                    let upload = database
                        .begin_oci_upload_checked(
                            &BeginOciUpload {
                                registry_id: registry,
                                repository_id: repository,
                                publication_id: None,
                                writer_id: identity.clone(),
                                token_id: identity.clone(),
                                idempotency_key: identity.clone(),
                                expected_digest: Some(digest),
                                expected_size: Some(bytes.len() as u64),
                                maximum_size: 1024,
                                now,
                                expires_at: now + 60,
                            },
                            Database::verified_registry_accounting_owner_locks(Some(organization)),
                        )
                        .await?;
                    let mut hash = OciSha256State::initial();
                    hash.update(bytes)?;
                    let advanced = database
                        .append_oci_upload_chunk(&AppendOciUploadChunk {
                            upload_id: upload.id.clone(),
                            writer_id: identity.clone(),
                            token_id: identity.clone(),
                            expected_resource_version: upload.resource_version,
                            staging_placement_id: placement.id,
                            staging_placement_resource_version: placement.resource_version,
                            staging_binding_id: placement.binding_id,
                            staging_binding_write_revision: revision,
                            chunk: OciUploadChunkRecord {
                                ordinal: 0,
                                byte_offset: 0,
                                byte_size: bytes.len() as u64,
                                digest,
                                staging_object_key: format!("oci/uploads/{}/chunk-0", upload.id),
                                created_at: now,
                            },
                            next_sha256: hash,
                            now,
                        })
                        .await?;
                    database
                        .cancel_oci_upload(
                            &upload.id,
                            &identity,
                            &identity,
                            advanced.resource_version,
                            now + 1,
                        )
                        .await?;
                }
                Ok::<(), anyhow::Error>(())
            }
            .with_subscriber(subscriber),
        );
    }
    let mut failures = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result? {
            failures.push(format!("{error:#}"));
        }
    }
    assert_eq!(
        deadlocks.retries.load(Ordering::Relaxed),
        0,
        "upload paths deadlocked"
    );
    assert!(failures.is_empty(), "parallel uploads failed: {failures:?}");
    let usage = database.org_usage(organization).await?;
    assert_eq!(usage.used_bytes, baseline.used_bytes);
    assert_eq!(usage.object_count, baseline.object_count);
    Ok(())
}
