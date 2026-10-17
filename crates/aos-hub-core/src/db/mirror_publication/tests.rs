//! Logical accounting and current-copy fences through real checked SQL batches.

mod accounting;

use super::*;
use crate::backend::{Backend, SqlxBackend, Statement};
use crate::db::{
    NewRegistryPublication, OrgQuota, RegistryPublicationManifestObject,
    SetRegistryPublicationPlacement,
};
use crate::mirror_guard::{
    sign_mirror_guard_reply, verify_mirror_guard_reply, MirrorGuardExecution, MirrorGuardIssuer,
    MirrorGuardLookup, MirrorGuardReply,
};
use crate::storage_work::StorageWorkKey;
use crate::value::{Row, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use super::super::mirror_imports::tests::{original, progress as build_progress};

fn proof(
    original: &MirrorOriginal,
    progress: &MirrorProgress,
    now: i64,
) -> VerifiedMirrorGuardProof {
    proof_with_lifetime(original, progress, now, 30)
}

fn proof_with_lifetime(
    original: &MirrorOriginal,
    progress: &MirrorProgress,
    now: i64,
    lifetime: u64,
) -> VerifiedMirrorGuardProof {
    let key = StorageWorkKey::new("mirror-publication-independent-guard-role-0001").unwrap();
    let issued_at = u64::try_from(now).unwrap();
    let request = MirrorGuardLookup {
        version: 1,
        deployment_id: "mirror-publication-sql-fixture".into(),
        execution: MirrorGuardExecution::Hosted,
        issuer: MirrorGuardIssuer {
            source_digest: "a".repeat(64),
            script_version: "fixture-script".into(),
        },
        clock_uncertainty_seconds: 1,
        original: original.clone(),
        expected: progress.clone(),
        request_nonce: "b".repeat(64),
        issued_at,
        expires_at: issued_at + lifetime,
    };
    let reply = MirrorGuardReply {
        version: 1,
        request_digest: digest(&request).unwrap(),
        request_nonce: request.request_nonce.clone(),
        original_digest: digest(original).unwrap(),
        issuer: request.issuer.clone(),
        progress: progress.clone(),
        observed_at: issued_at + 1,
    };
    let signed = sign_mirror_guard_reply(&key, &reply, &request).unwrap();
    verify_mirror_guard_reply(
        &key,
        &signed.signature,
        &signed.body,
        &request,
        issued_at + 1,
    )
    .unwrap()
}

async fn owned_original(db: &Database) -> (MirrorOriginal, i64) {
    let mut original = original(db).await;
    let org = db
        .create_org("mirror-billing", "Mirror billing")
        .await
        .unwrap();
    let registry_id = db
        .create_managed_registry(org, "", "billing", "public", &[], false)
        .await
        .unwrap();
    db.create_mirror_source(registry_id, &original.upstream_base, "full", true, 3600)
        .await
        .unwrap();
    let binding = db.binding(original.binding_id).await.unwrap().unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    db.grant_consumer_scope(
        crate::db::GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        &registry.owner_scope_key,
        "explicit",
        "mirror-sql-fixture",
        "billing-grant",
    )
    .await
    .unwrap();
    let placement = db
        .create_surface_placement(&crate::db::NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "billing-mirror".into(),
            binding_id: original.binding_id,
            prefix: "billing-mirror".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let placement = db
        .observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    let revision = db
        .binding_write_state(original.binding_id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    db.bind_surface_placement_write_capability(placement.id, revision)
        .await
        .unwrap();
    db.create_surface_write_authority(
        SurfaceTarget::Registry(registry_id),
        "billing-authority",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        revision,
    )
    .await
    .unwrap();
    let placement = db
        .reconciled_surface_writer(SurfaceTarget::Registry(registry_id))
        .await
        .unwrap();
    original.registry_id = registry_id;
    original.registry_resource_version = db
        .registry_by_id(registry_id)
        .await
        .unwrap()
        .unwrap()
        .resource_version;
    original.placement_id = placement.id;
    original.placement_resource_version = placement.resource_version;
    original.write_spec_version = placement.write_spec_version;
    original.placement_prefix = placement.prefix;
    original.job_id = original.identity().unwrap();
    (original, org)
}

async fn retain(db: &Database, original: &MirrorOriginal, progress: &MirrorProgress, now: i64) {
    db.admit_mirror_import(original, now).await.unwrap();
    db.record_mirror_import_progress(original, progress, false, now + 1)
        .await
        .unwrap();
}

async fn accounting_contract(db: &Database) {
    let (original, org) = owned_original(db).await;
    let progress = build_progress(&original);
    retain(db, &original, &progress, 100).await;
    db.set_org_quota(
        org,
        &OrgQuota {
            max_bytes: Some(10),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(db
        .commit_mirror_import(
            &original,
            &progress,
            &proof(&original, &progress, 101),
            None,
            101
        )
        .await
        .is_err());
    assert!(db
        .surface_object_named(
            SurfaceTarget::Registry(original.registry_id),
            &original.path
        )
        .await
        .unwrap()
        .is_none());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 0);
    assert_eq!(
        db.mirror_import(&original.job_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "published"
    );

    db.set_org_quota(
        org,
        &OrgQuota {
            max_bytes: Some(11),
            max_objects: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let first = db
        .commit_mirror_import(
            &original,
            &progress,
            &proof(&original, &progress, 102),
            None,
            102,
        )
        .await
        .unwrap();
    assert_eq!(first.publication_commit_version, Some(7));
    let object = db
        .surface_object_named(
            SurfaceTarget::Registry(original.registry_id),
            &original.path,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        db.surface_object_usage(object.id)
            .await
            .unwrap()
            .unwrap()
            .accounted_bytes,
        11
    );
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (11, 1));
    assert!(db
        .mirror_committed_catalogue_matches(&original, &progress)
        .await
        .unwrap());

    // Expired proof is sufficient only for an exact already-committed replay.
    let replay = db
        .commit_mirror_import(
            &original,
            &progress,
            &proof(&original, &progress, 102),
            None,
            1000,
        )
        .await
        .unwrap();
    assert_eq!(replay.commit_digest, first.commit_digest);
    assert_eq!(replay.updated_at, first.updated_at);
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 11);
    db.backend
        .execute(
            "DELETE FROM object_placements WHERE surface_object_id = ?1",
            &vals![object.id],
        )
        .await
        .unwrap();
    assert!(!db
        .mirror_committed_catalogue_matches(&original, &progress)
        .await
        .unwrap());
    db.retire_acknowledged_mirror_import(&original, &progress)
        .await
        .unwrap();
    let mut next = original.clone();
    next.copy_operation_id = Some("5".repeat(32));
    next.job_id = next.identity().unwrap();
    let next_progress = build_progress(&next);
    retain(db, &next, &next_progress, 104).await;
    db.commit_mirror_import(
        &next,
        &next_progress,
        &proof(&next, &next_progress, 105),
        None,
        105,
    )
    .await
    .unwrap();
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (11, 1));
}

#[tokio::test]
async fn quota_rollback_exact_replay_and_reimport_do_not_rebill_sqlite() {
    accounting_contract(&Database::open_in_memory().await.unwrap()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn quota_rollback_exact_replay_and_reimport_do_not_rebill_postgres() {
    let Ok(url) = std::env::var("AOS_MIRROR_PUBLICATION_TEST_DATABASE_URL") else {
        return;
    };
    accounting_contract(&Database::connect(&url).await.unwrap()).await;
}

#[tokio::test]
async fn long_original_is_retained_but_refuses_new_publication_before_mutation() {
    let db = Database::open_in_memory().await.unwrap();
    let mut original = original(&db).await;
    original.path = format!("nar/{}.nar", "x".repeat(1800));
    original.job_id = original.identity().unwrap();
    let progress = build_progress(&original);
    retain(&db, &original, &progress, 100).await;
    assert!(db
        .validate_mirror_publication_dispatch(&original, &progress, None, 101)
        .await
        .is_err());
    assert!(db
        .commit_mirror_import(
            &original,
            &progress,
            &proof(&original, &progress, 101),
            None,
            101
        )
        .await
        .is_err());
    assert_eq!(
        db.mirror_import(&original.job_id)
            .await
            .unwrap()
            .unwrap()
            .original
            .path,
        original.path
    );
    assert_eq!(
        db.backend
            .query("SELECT id FROM surface_objects", &[])
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        db.backend
            .query("SELECT surface_object_id FROM surface_object_usage", &[])
            .await
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn legacy_terminal_is_readable_but_cannot_attest_generation7_commit() {
    let db = Database::open_in_memory().await.unwrap();
    let original = original(&db).await;
    let progress = build_progress(&original);
    retain(&db, &original, &progress, 100).await;
    db.backend
        .execute(
            "UPDATE mirror_import_objects SET state='committed',commit_digest=?2 WHERE job_id=?1",
            &vals![original.job_id, progress.commit_digest(&original).unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(
        db.mirror_import(&original.job_id)
            .await
            .unwrap()
            .unwrap()
            .publication_commit_version,
        None
    );
    assert!(!db
        .mirror_committed_catalogue_matches(&original, &progress)
        .await
        .unwrap());
    assert!(db
        .commit_mirror_import(
            &original,
            &progress,
            &proof(&original, &progress, 101),
            None,
            101
        )
        .await
        .is_err());
}

async fn publication(db: &Database, original: &MirrorOriginal, pointer: &MirrorOriginal) {
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: "mirror-atomic-publication".into(),
        registry_id: original.registry_id,
        generation: "mirror-generation".into(),
        manifest_digest: "c".repeat(64),
        refs_digest: "d".repeat(64),
        default_commit: None,
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.begin_registry_publication_manifest_session(
        "mirror-atomic-publication",
        original.registry_id,
        &"c".repeat(64),
        2,
        "mirror-lease",
        100,
    )
    .await
    .unwrap();
    db.append_registry_publication_manifest_chunk(
        "mirror-atomic-publication",
        "mirror-lease",
        0,
        &"e".repeat(64),
        &[
            RegistryPublicationManifestObject {
                object_key: original.path.clone(),
                expected_hash: "1".repeat(64),
                expected_size: 11,
                object_kind: "immutable".into(),
            },
            RegistryPublicationManifestObject {
                object_key: pointer.path.clone(),
                expected_hash: "1".repeat(64),
                expected_size: 11,
                object_kind: "mutable_pointer".into(),
            },
        ],
        101,
    )
    .await
    .unwrap();
    db.seal_registry_publication_manifest_session(
        "mirror-atomic-publication",
        "mirror-lease",
        &[original.placement_id],
        102,
    )
    .await
    .unwrap();
    db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
        publication_id: "mirror-atomic-publication".into(),
        placement_id: original.placement_id,
        required: true,
        state: "preparing".into(),
        observed_at: 102,
    })
    .await
    .unwrap();
}

async fn barrier_contract(db: &Database) {
    let (original, org) = owned_original(db).await;
    let mut pointer = original.clone();
    pointer.path = "HEAD".into();
    pointer.copy_operation_id = Some("6".repeat(32));
    pointer.job_id = pointer.identity().unwrap();
    let leaf_progress = build_progress(&original);
    let pointer_progress = build_progress(&pointer);
    retain(db, &original, &leaf_progress, 100).await;
    retain(db, &pointer, &pointer_progress, 100).await;
    publication(db, &original, &pointer).await;
    let id = Some("mirror-atomic-publication");
    assert_eq!(
        db.org_usage(org).await.unwrap().used_bytes,
        0,
        "manifest placeholders are uncharged"
    );
    assert!(db
        .validate_mirror_publication_dispatch(&pointer, &pointer_progress, id, 103)
        .await
        .is_err());
    db.validate_mirror_publication_dispatch(&original, &leaf_progress, id, 103)
        .await
        .unwrap();
    db.commit_mirror_import(
        &original,
        &leaf_progress,
        &proof(&original, &leaf_progress, 103),
        id,
        103,
    )
    .await
    .unwrap();
    assert!(db
        .advance_registry_publication(
            "mirror-atomic-publication",
            "preparing",
            "writing_pointers",
            104
        )
        .await
        .unwrap());
    let placement = db
        .surface_placement(original.placement_id)
        .await
        .unwrap()
        .unwrap();
    db.begin_registry_pointer_advance(
        "mirror-atomic-publication",
        placement.id,
        placement.resource_version,
        placement.watermark_resource_version.unwrap(),
        104,
    )
    .await
    .unwrap();
    db.validate_mirror_publication_dispatch(&pointer, &pointer_progress, id, 104)
        .await
        .unwrap();

    let leaf = db
        .surface_object_named(
            SurfaceTarget::Registry(original.registry_id),
            &original.path,
        )
        .await
        .unwrap()
        .unwrap();
    db.backend
        .execute(
            "UPDATE surface_objects SET content_hash=?2 WHERE id=?1",
            &vals![leaf.id, "2".repeat(64)],
        )
        .await
        .unwrap();
    assert!(db
        .validate_mirror_publication_dispatch(&pointer, &pointer_progress, id, 104)
        .await
        .is_err());
    db.backend
        .execute(
            "UPDATE surface_objects SET content_hash=?2 WHERE id=?1",
            &vals![leaf.id, "1".repeat(64)],
        )
        .await
        .unwrap();

    // A legacy or changed copy cannot satisfy a current pointer barrier even
    // when its hash and size still match the manifest.
    db.backend
        .execute(
            "UPDATE object_placements SET observed_write_spec_version = NULL WHERE placement_id=?1",
            &vals![original.placement_id],
        )
        .await
        .unwrap();
    assert!(db
        .validate_mirror_publication_dispatch(&pointer, &pointer_progress, id, 104)
        .await
        .is_err());
    assert!(db
        .commit_mirror_import(
            &pointer,
            &pointer_progress,
            &proof(&pointer, &pointer_progress, 104),
            id,
            104
        )
        .await
        .is_err());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 11);
    let pointer_object = db
        .surface_object_named(SurfaceTarget::Registry(original.registry_id), "HEAD")
        .await
        .unwrap()
        .unwrap();
    assert!(db
        .surface_object_usage(pointer_object.id)
        .await
        .unwrap()
        .is_none());

    db.backend
        .execute(
            "UPDATE object_placements SET observed_write_spec_version=?2 WHERE placement_id=?1",
            &vals![original.placement_id, original.write_spec_version],
        )
        .await
        .unwrap();
    db.commit_mirror_import(
        &pointer,
        &pointer_progress,
        &proof(&pointer, &pointer_progress, 105),
        id,
        105,
    )
    .await
    .unwrap();
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (22, 2));
    assert_eq!(
        db.surface_object_named(SurfaceTarget::Registry(original.registry_id), "HEAD")
            .await
            .unwrap()
            .unwrap()
            .mutable_publication_id
            .as_deref(),
        id
    );

    db.retire_acknowledged_mirror_import(&pointer, &pointer_progress)
        .await
        .unwrap();
    db.backend.execute("UPDATE surface_placements SET prefix='rotated-mirror',resource_version=resource_version+1 WHERE id=?1",
        &vals![original.placement_id]).await.unwrap();
    let current = db
        .reconciled_surface_writer(SurfaceTarget::Registry(original.registry_id))
        .await
        .unwrap();
    let mut next = pointer.clone();
    next.copy_operation_id = Some("7".repeat(32));
    next.placement_prefix = current.prefix;
    next.placement_resource_version = current.resource_version;
    next.job_id = next.identity().unwrap();
    let mut next_progress = build_progress(&next);
    next_progress.destination_upload_id = None;
    next_progress.destination_parts.clear();
    next_progress.destination = None;
    retain(db, &next, &next_progress, 106).await;
    // Exact content in the former namespace is not a current required copy.
    assert!(db
        .validate_mirror_publication_dispatch(&next, &next_progress, id, 107)
        .await
        .is_err());
    assert_eq!(
        db.mirror_import(&next.job_id).await.unwrap().unwrap().state,
        "staged_verified"
    );
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 22);
}

#[tokio::test]
async fn manifest_placeholders_and_pointer_barrier_require_current_copy_pins_sqlite() {
    barrier_contract(&Database::open_in_memory().await.unwrap()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn manifest_placeholders_and_pointer_barrier_require_current_copy_pins_postgres() {
    let Ok(url) = std::env::var("AOS_MIRROR_PUBLICATION_BARRIER_TEST_DATABASE_URL") else {
        return;
    };
    barrier_contract(&Database::connect(&url).await.unwrap()).await;
}

struct PublicationBackend {
    inner: SqlxBackend,
    armed: Arc<AtomicBool>,
    pause_sql: Option<&'static str>,
    delay: Option<std::time::Duration>,
}

#[async_trait::async_trait]
impl Backend for PublicationBackend {
    fn dialect(&self) -> crate::dialect::Dialect {
        self.inner.dialect()
    }
    async fn migrate_schema(&self) -> anyhow::Result<()> {
        self.inner.migrate_schema().await
    }

    async fn execute(&self, sql: &str, values: &[Value]) -> Result<u64> {
        self.inner.execute(sql, values).await
    }
    async fn execute_insert(&self, sql: &str, values: &[Value]) -> Result<i64> {
        self.inner.execute_insert(sql, values).await
    }
    async fn query(&self, sql: &str, values: &[Value]) -> Result<Vec<Row>> {
        self.inner.query(sql, values).await
    }
    async fn execute_batch(&self, sql: &str) -> Result<()> {
        self.inner.execute_batch(sql).await
    }
    async fn batch(&self, statements: &[Statement]) -> Result<()> {
        self.inner.batch(statements).await
    }
    async fn checked_batch(&self, statements: &[CheckedStatement]) -> Result<()> {
        let publication = statements.iter().position(|statement| {
            statement
                .statement
                .sql
                .starts_with("INSERT INTO surface_objects")
                || statement
                    .statement
                    .sql
                    .starts_with("UPDATE surface_objects SET content_hash")
        });
        if let Some(index) = publication.filter(|_| self.armed.swap(false, Ordering::SeqCst)) {
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
                return self.inner.checked_batch(statements).await;
            }
            if let Some(sql) = self.pause_sql {
                let mut paused = statements.to_vec();
                paused.insert(index, CheckedStatement::unchecked(sql, Vec::new()));
                return self.inner.checked_batch(&paused).await;
            }
            self.inner
                .execute(
                    "UPDATE bindings SET resource_version=resource_version+1",
                    &[],
                )
                .await?;
        }
        self.inner.checked_batch(statements).await
    }
}

#[tokio::test]
async fn authority_change_after_reads_rolls_back_catalogue_accounting_and_terminal() {
    let armed = Arc::new(AtomicBool::new(false));
    let db = Database::with_backend(Box::new(PublicationBackend {
        inner: SqlxBackend::connect_sqlite(":memory:").await.unwrap(),
        armed: Arc::clone(&armed),
        pause_sql: None,
        delay: None,
    }))
    .await
    .unwrap();
    let (original, org) = owned_original(&db).await;
    let progress = build_progress(&original);
    retain(&db, &original, &progress, 100).await;
    armed.store(true, Ordering::SeqCst);
    assert!(db
        .commit_mirror_import(
            &original,
            &progress,
            &proof(&original, &progress, 101),
            None,
            101
        )
        .await
        .is_err());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 0);
    assert!(db
        .surface_object_named(
            SurfaceTarget::Registry(original.registry_id),
            &original.path
        )
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.mirror_import(&original.job_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "published"
    );
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_binding_revocation_waits_for_the_actual_publication_transaction() {
    let Ok(url) = std::env::var("AOS_MIRROR_PUBLICATION_LOCK_TEST_DATABASE_URL") else {
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .unwrap();
    let armed = Arc::new(AtomicBool::new(false));
    let db = Arc::new(
        Database::with_backend(Box::new(PublicationBackend {
            inner: SqlxBackend::Postgres(pool.clone()),
            armed: Arc::clone(&armed),
            pause_sql: Some("SELECT pg_advisory_xact_lock(7230507)"),
            delay: None,
        }))
        .await
        .unwrap(),
    );
    let (original, org) = owned_original(&db).await;
    let progress = build_progress(&original);
    let now = super::super::unix_now();
    retain(&db, &original, &progress, now - 1).await;
    let mut barrier = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(7230507)")
        .execute(&mut *barrier)
        .await
        .unwrap();
    armed.store(true, Ordering::SeqCst);
    let commit_db = Arc::clone(&db);
    let commit_original = original.clone();
    let commit_progress = progress.clone();
    let commit = tokio::spawn(async move {
        commit_db
            .commit_mirror_import(
                &commit_original,
                &commit_progress,
                &proof(&commit_original, &commit_progress, now),
                None,
                now,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=7230507 AND NOT granted)").fetch_one(&pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }).await.unwrap();

    let mut revoke_connection = pool.acquire().await.unwrap();
    let revoke_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *revoke_connection)
        .await
        .unwrap();
    let binding_id = original.binding_id;
    let revoke = tokio::spawn(async move {
        sqlx::query("UPDATE bindings SET resource_version=resource_version+1 WHERE id=$1")
            .bind(binding_id)
            .execute(&mut *revoke_connection)
            .await
    });
    // Observe the captured revocation backend waiting in PostgreSQL itself.
    // A delayed task alone must not pass this concurrency regression.
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_locks
                WHERE pid=$1 AND NOT granted AND locktype IN ('transactionid','tuple'))",
            )
            .bind(revoke_pid)
            .fetch_one(&pool)
            .await
            .unwrap();
            if blocked {
                break;
            }
            assert!(
                !revoke.is_finished(),
                "binding revocation bypassed the publication row lock"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    sqlx::query("SELECT pg_advisory_unlock(7230507)")
        .execute(&mut *barrier)
        .await
        .unwrap();
    assert_eq!(
        commit.await.unwrap().unwrap().publication_commit_version,
        Some(7)
    );
    assert_eq!(revoke.await.unwrap().unwrap().rows_affected(), 1);
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 11);
    assert!(!db
        .mirror_committed_catalogue_matches(&original, &progress)
        .await
        .unwrap());
    drop(barrier);
    pool.close().await;
}

#[tokio::test]
async fn cold_terminal_replay_uses_retained_commit_without_rebilling_or_fresh_effect() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mirror.db");
    let db = Database::open(&path).await.unwrap();
    let (original, org) = owned_original(&db).await;
    let progress = build_progress(&original);
    retain(&db, &original, &progress, 100).await;
    let committed = db
        .commit_mirror_import(
            &original,
            &progress,
            &proof(&original, &progress, 101),
            None,
            101,
        )
        .await
        .unwrap();
    drop(db);

    let reopened = Database::open(&path).await.unwrap();
    let replay = reopened
        .commit_mirror_import(
            &original,
            &progress,
            &proof(&original, &progress, 101),
            None,
            1000,
        )
        .await
        .unwrap();
    assert_eq!(replay.commit_digest, committed.commit_digest);
    assert_eq!(replay.publication_commit_version, Some(7));
    let usage = reopened.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (11, 1));
}

#[tokio::test]
async fn guard_deadline_cancels_delayed_sql_without_ack_or_fabricated_settlement() {
    let armed = Arc::new(AtomicBool::new(false));
    let db = Database::with_backend(Box::new(PublicationBackend {
        inner: SqlxBackend::connect_sqlite(":memory:").await.unwrap(),
        armed: Arc::clone(&armed),
        pause_sql: None,
        delay: Some(std::time::Duration::from_secs(3)),
    }))
    .await
    .unwrap();
    let (original, org) = owned_original(&db).await;
    let progress = build_progress(&original);
    let now = super::super::unix_now();
    retain(&db, &original, &progress, now - 1).await;
    armed.store(true, Ordering::SeqCst);
    let error = db
        .commit_mirror_import(
            &original,
            &progress,
            &proof_with_lifetime(&original, &progress, now, 3),
            None,
            now,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("unknown SQL outcome"));
    let retained = db.mirror_import(&original.job_id).await.unwrap().unwrap();
    assert_eq!(retained.state, "published");
    assert_eq!(retained.publication_commit_version, None);
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 0);
    assert!(db
        .surface_object_named(
            SurfaceTarget::Registry(original.registry_id),
            &original.path
        )
        .await
        .unwrap()
        .is_none());
}

async fn refund_contract(db: &Database) {
    let (original, org) = owned_original(db).await;
    let progress = build_progress(&original);
    let now = super::super::unix_now();
    retain(db, &original, &progress, now - 1).await;
    db.commit_mirror_import(
        &original,
        &progress,
        &proof(&original, &progress, now),
        None,
        now,
    )
    .await
    .unwrap();
    db.retire_acknowledged_mirror_import(&original, &progress)
        .await
        .unwrap();
    let object = db
        .surface_object_named(
            SurfaceTarget::Registry(original.registry_id),
            &original.path,
        )
        .await
        .unwrap()
        .unwrap();
    db.backend
        .execute(
            "UPDATE org_usage SET used_bytes=10 WHERE org_id=?1",
            &vals![org],
        )
        .await
        .unwrap();
    assert!(db
        .mirror_usage_retirement_statements(original.registry_id, Some(org), now)
        .await
        .is_err());
    assert!(db.surface_object_usage(object.id).await.unwrap().is_some());
    db.backend
        .execute(
            "UPDATE org_usage SET used_bytes=11 WHERE org_id=?1",
            &vals![org],
        )
        .await
        .unwrap();

    // The existing helper executes the real purge/empty inventory and registry
    // deletion API, including its complete restrictive FK graph.
    super::super::mirror_imports::tests::delete_after_existing_gc_fences(db, &original).await;
    assert!(db
        .registry_by_id(original.registry_id)
        .await
        .unwrap()
        .is_none());
    assert!(db.surface_object_usage(object.id).await.unwrap().is_none());
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (0, 0));
}

#[tokio::test]
async fn settled_registry_deletion_refunds_exact_ledger_and_refuses_underflow_sqlite() {
    refund_contract(&Database::open_in_memory().await.unwrap()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn settled_registry_deletion_refunds_exact_ledger_and_refuses_underflow_postgres() {
    let Ok(url) = std::env::var("AOS_MIRROR_PUBLICATION_RETIREMENT_TEST_DATABASE_URL") else {
        return;
    };
    refund_contract(&Database::connect(&url).await.unwrap()).await;
}

async fn pointer_manifest(
    db: &Database,
    original: &MirrorOriginal,
    id: &str,
    hash: &str,
    size: i64,
    now: i64,
) {
    let manifest_digest = hex::encode(Sha256::digest(format!(
        "{id}:{}:{hash}:{size}",
        original.path
    )));
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: id.into(),
        registry_id: original.registry_id,
        generation: id.into(),
        manifest_digest: manifest_digest.clone(),
        refs_digest: "d".repeat(64),
        default_commit: None,
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.begin_registry_publication_manifest_session(
        id,
        original.registry_id,
        &manifest_digest,
        1,
        "pointer-lease",
        now,
    )
    .await
    .unwrap();
    db.append_registry_publication_manifest_chunk(
        id,
        "pointer-lease",
        0,
        &"e".repeat(64),
        &[RegistryPublicationManifestObject {
            object_key: original.path.clone(),
            expected_hash: hash.into(),
            expected_size: size,
            object_kind: "mutable_pointer".into(),
        }],
        now,
    )
    .await
    .unwrap();
    db.seal_registry_publication_manifest_session(
        id,
        "pointer-lease",
        &[original.placement_id],
        now,
    )
    .await
    .unwrap();
    assert!(db
        .advance_registry_publication(id, "preparing", "writing_pointers", now)
        .await
        .unwrap());
    let placement = db
        .surface_placement(original.placement_id)
        .await
        .unwrap()
        .unwrap();
    db.begin_registry_pointer_advance(
        id,
        placement.id,
        placement.resource_version,
        placement.watermark_resource_version.unwrap(),
        now,
    )
    .await
    .unwrap();
}

async fn resize_contract(db: &Database) {
    let (mut original, org) = owned_original(db).await;
    original.path = "HEAD".into();
    original.job_id = original.identity().unwrap();
    let progress = build_progress(&original);
    retain(db, &original, &progress, 100).await;
    pointer_manifest(db, &original, "pointer-first", &"1".repeat(64), 11, 102).await;
    db.commit_mirror_import(
        &original,
        &progress,
        &proof(&original, &progress, 103),
        Some("pointer-first"),
        103,
    )
    .await
    .unwrap();
    let placement = db
        .surface_placement(original.placement_id)
        .await
        .unwrap()
        .unwrap();
    db.finalize_registry_pointer_advance(
        "pointer-first",
        placement.id,
        placement.resource_version,
        placement.watermark_resource_version.unwrap(),
        104,
    )
    .await
    .unwrap();
    db.retire_acknowledged_mirror_import(&original, &progress)
        .await
        .unwrap();

    let mut next = original.clone();
    next.copy_operation_id = Some("8".repeat(32));
    next.verification = crate::mirror_work::MirrorVerification::Sha256 {
        sha256: "2".repeat(64),
        size: 13,
    };
    next.job_id = next.identity().unwrap();
    let mut resized = build_progress(&next);
    for part in resized
        .stage_parts
        .iter_mut()
        .chain(&mut resized.destination_parts)
    {
        part.size = 13;
        part.sha256 = "2".repeat(64);
    }
    resized.stage_object.as_mut().unwrap().size = 13;
    for verified in [
        resized.verified.as_mut().unwrap(),
        resized.destination.as_mut().unwrap(),
    ] {
        verified.object.size = 13;
        verified.sha256 = "2".repeat(64);
    }
    retain(db, &next, &resized, 105).await;
    pointer_manifest(db, &next, "pointer-resized", &"2".repeat(64), 13, 107).await;
    db.set_org_quota(
        org,
        &OrgQuota {
            max_bytes: Some(12),
            max_objects: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(db
        .commit_mirror_import(
            &next,
            &resized,
            &proof(&next, &resized, 108),
            Some("pointer-resized"),
            108
        )
        .await
        .is_err());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 11);
    let object = db
        .surface_object_named(SurfaceTarget::Registry(next.registry_id), "HEAD")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        db.surface_object_usage(object.id)
            .await
            .unwrap()
            .unwrap()
            .accounted_bytes,
        11
    );
    assert_eq!(
        db.mirror_import(&next.job_id).await.unwrap().unwrap().state,
        "published"
    );

    db.set_org_quota(
        org,
        &OrgQuota {
            max_bytes: Some(13),
            max_objects: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    db.commit_mirror_import(
        &next,
        &resized,
        &proof(&next, &resized, 109),
        Some("pointer-resized"),
        109,
    )
    .await
    .unwrap();
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (13, 1));
    let charge = db.surface_object_usage(object.id).await.unwrap().unwrap();
    assert_eq!((charge.accounted_bytes, charge.resource_version), (13, 2));
}

#[tokio::test]
async fn mutable_resize_accounts_only_verified_delta_and_rolls_back_quota_refusal_sqlite() {
    resize_contract(&Database::open_in_memory().await.unwrap()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn mutable_resize_accounts_only_verified_delta_and_rolls_back_quota_refusal_postgres() {
    let Ok(url) = std::env::var("AOS_MIRROR_PUBLICATION_RESIZE_TEST_DATABASE_URL") else {
        return;
    };
    resize_contract(&Database::connect(&url).await.unwrap()).await;
}
