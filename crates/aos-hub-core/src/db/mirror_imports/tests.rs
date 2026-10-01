//! Actual SQL fences, retained originals and acknowledged retirement.

use super::*;
use crate::db::NewSurfacePlacementSpec;
use crate::mirror_work::{MirrorPart, MirrorVerification, MirrorVerifiedObject};
use crate::storage_work::StorageObjectIdentity;

use crate::backend::{Backend, SqlxBackend, Statement};
use crate::dialect::Dialect;
use crate::value::{Row, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct InterleavingBackend {
    inner: SqlxBackend,
    invalidate_before_progress: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl Backend for InterleavingBackend {
    fn dialect(&self) -> Dialect {
        self.inner.dialect()
    }

    async fn migrate_schema(&self) -> anyhow::Result<()> {
        self.inner.migrate_schema().await
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64> {
        self.inner.execute(sql, params).await
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64> {
        self.inner.execute_insert(sql, params).await
    }

    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        self.inner.query(sql, params).await
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        self.inner.execute_batch(sql).await
    }

    async fn batch(&self, statements: &[Statement]) -> Result<()> {
        self.inner.batch(statements).await
    }

    async fn checked_batch(&self, statements: &[CheckedStatement]) -> Result<()> {
        if statements.iter().any(|statement| {
            statement
                .statement
                .sql
                .starts_with("UPDATE mirror_import_objects SET progress_json")
        }) && self
            .invalidate_before_progress
            .swap(false, Ordering::SeqCst)
        {
            self.inner
                .execute(
                    "UPDATE bindings SET resource_version = resource_version + 1",
                    &[],
                )
                .await?;
        }
        self.inner.checked_batch(statements).await
    }
}

pub(crate) async fn original(db: &Database) -> MirrorOriginal {
    let registry_id = db
        .register_registry("mirror-tests", &[], false)
        .await
        .unwrap();
    db.create_mirror_source(
        registry_id,
        "https://upstream.example.invalid/registry/",
        "full",
        true,
        3600,
    )
    .await
    .unwrap();
    let binding = db
        .ensure_instance_default_binding(
            "deployment_r2",
            None,
            Some(crate::binding::DEPLOYMENT_R2_ATTACHMENT),
        )
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "mirror".into(),
            binding_id: binding.id,
            prefix: "mirror-tests".into(),
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
        .binding_write_state(binding.id)
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
        "mirror-test-authority",
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
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: Some("4".repeat(32)),
        registry_id,
        registry_resource_version: registry.resource_version,
        mirror_resource_version: 1,
        upstream_base: "https://upstream.example.invalid/registry/".into(),
        path: "nar/source.nar".into(),
        placement_id: placement.id,
        placement_resource_version: placement.resource_version,
        write_spec_version: placement.write_spec_version,
        binding_id: binding.id,
        binding_resource_version: binding.resource_version,
        placement_prefix: placement.prefix,
        protected_profile_digest: "3".repeat(64),
        verification: MirrorVerification::Sha256 {
            sha256: "1".repeat(64),
            size: 11,
        },
    };
    original.job_id = original.identity().unwrap();
    original
}

pub(crate) fn progress(original: &MirrorOriginal) -> MirrorProgress {
    let part = MirrorPart {
        part_number: 1,
        size: 11,
        sha256: "1".repeat(64),
        etag: "\"part\"".into(),
    };
    let object = StorageObjectIdentity {
        key: original.stage_key(),
        size: 11,
        etag: "\"stage\"".into(),
        provider_version: Some("stage-version".into()),
    };
    let verified = MirrorVerifiedObject {
        object: object.clone(),
        sha256: "1".repeat(64),
        nar_sha256: None,
        nar_size: None,
    };
    MirrorProgress {
        original_digest: digest(original).unwrap(),
        upstream_etag: Some("\"upstream\"".into()),
        stage_upload_id: Some("stage-upload".into()),
        stage_parts: vec![part.clone()],
        stage_object: Some(object),
        verified: Some(verified.clone()),
        destination_upload_id: Some("destination-upload".into()),
        destination_parts: vec![part],
        destination: Some(MirrorVerifiedObject {
            object: StorageObjectIdentity {
                key: crate::keymap::r2_key(&original.placement_prefix, &original.path),
                size: 11,
                etag: "\"final\"".into(),
                provider_version: Some("final-version".into()),
            },
            ..verified
        }),
    }
}

// This fixture authenticates a full guard-role reply. It establishes the SQL
// consumer's proof requirements; actual provider/readback behavior is exercised
// separately through the controlled Worker runtime.
async fn commit_positive(
    db: &Database,
    original: &MirrorOriginal,
    progress: &MirrorProgress,
    now: i64,
) -> Result<MirrorImportRecord> {
    use crate::mirror_guard::{
        sign_mirror_guard_reply, verify_mirror_guard_reply, MirrorGuardExecution,
        MirrorGuardIssuer, MirrorGuardLookup, MirrorGuardReply,
    };
    use crate::storage_work::StorageWorkKey;

    db.record_mirror_import_progress(original, progress, false, now)
        .await?;
    let issued_at = u64::try_from(now)?;
    let key = StorageWorkKey::new("mirror-test-independent-guard-role-0001")?;
    let request = MirrorGuardLookup {
        version: 1,
        deployment_id: "mirror-sql-fixture".into(),
        execution: MirrorGuardExecution::Hosted,
        issuer: MirrorGuardIssuer {
            source_digest: "a".repeat(64),
            script_version: "sql-fixture-script".into(),
        },
        clock_uncertainty_seconds: 1,
        original: original.clone(),
        expected: progress.clone(),
        request_nonce: "b".repeat(64),
        issued_at,
        expires_at: issued_at + 30,
    };
    let latest_now = issued_at + 1;
    let reply = MirrorGuardReply {
        version: 1,
        request_digest: digest(&request)?,
        request_nonce: request.request_nonce.clone(),
        original_digest: digest(original)?,
        issuer: request.issuer.clone(),
        progress: progress.clone(),
        observed_at: latest_now,
    };
    let signed = sign_mirror_guard_reply(&key, &reply, &request)?;
    let proof =
        verify_mirror_guard_reply(&key, &signed.signature, &signed.body, &request, latest_now)?;
    db.commit_mirror_import(original, progress, &proof, None, now)
        .await
}

pub(crate) async fn delete_after_existing_gc_fences(db: &Database, original: &MirrorOriginal) {
    use crate::db::{
        AppendOciProviderInventoryPage, BeginOciProviderInventory, CompleteOciProviderInventory,
    };

    let now = super::super::unix_now() - 3;
    db.begin_oci_registry_purge_fence(
        original.registry_id,
        original.registry_resource_version,
        "mirror-test",
        "mirror-purge",
        now,
    )
    .await
    .unwrap();
    let placement = db
        .surface_placement(original.placement_id)
        .await
        .unwrap()
        .unwrap();
    let generation = db
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id: original.registry_id,
            placement_id: placement.id,
            expected_placement_resource_version: placement.resource_version,
            expected_placement_observation_version: placement.observation_version.unwrap(),
            collector_id: "mirror-test".into(),
            collector_claim_token: "mirror-claim".into(),
            collector_lease_seconds: 100,
            idempotency_key: "mirror-empty-inventory".into(),
            now: now + 1,
        })
        .await
        .unwrap();
    db.append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
        generation_id: generation.id.clone(),
        collector_id: "mirror-test".into(),
        collector_claim_token: "mirror-claim".into(),
        expected_checkpoint_ordinal: 0,
        expected_provider_cursor: None,
        next_provider_cursor: None,
        last_listed_key: None,
        entries: Vec::new(),
        now: now + 2,
        lease_seconds: 100,
    })
    .await
    .unwrap();
    db.complete_oci_provider_inventory(&CompleteOciProviderInventory {
        generation_id: generation.id,
        collector_id: "mirror-test".into(),
        collector_claim_token: "mirror-claim".into(),
        expected_checkpoint_ordinal: 1,
        observed_at: now + 2,
        now: now + 3,
    })
    .await
    .unwrap();
    assert!(db
        .delete_registry_at_version(
            original.registry_id,
            original.registry_resource_version,
            "mirror-positive-retirement",
            "system",
            None,
            "test"
        )
        .await
        .unwrap());
}

#[tokio::test]
async fn retains_original_across_restart_and_rejects_substitution() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mirror.db");
    let db = Database::open(&path).await.unwrap();
    let original = original(&db).await;
    db.admit_mirror_import(&original, 1).await.unwrap();
    let mut substituted = original.clone();
    substituted.upstream_base = "https://other.example.invalid/registry/".into();
    assert!(db.admit_mirror_import(&substituted, 2).await.is_err());
    drop(db);

    let db = Database::open(&path).await.unwrap();
    let retained = db.mirror_import(&original.job_id).await.unwrap().unwrap();
    assert_eq!(retained.original, original);
    assert_eq!(retained.state, "admitted");
    assert!(retained.progress.is_none());
    // Clock and scheduler age do not reclaim the retained unknown-capable original.
    assert_eq!(
        db.admit_mirror_import(&original, 1_000_000)
            .await
            .unwrap()
            .created_at,
        1
    );
}

#[tokio::test]
async fn refuses_changed_source_policy_destination_and_regressing_proofs() {
    let db = Database::open_in_memory().await.unwrap();
    let original = original(&db).await;
    db.admit_mirror_import(&original, 1).await.unwrap();
    let progress = progress(&original);
    db.record_mirror_import_progress(&original, &progress, false, 2)
        .await
        .unwrap();
    let empty = MirrorProgress {
        original_digest: digest(&original).unwrap(),
        ..Default::default()
    };
    assert!(db
        .record_mirror_import_progress(&original, &empty, false, 3)
        .await
        .is_err());
    db.backend
        .execute(
            "UPDATE mirror_sources SET resource_version = resource_version + 1 WHERE registry_id = ?1",
            &vals![original.registry_id],
        )
        .await
        .unwrap();
    assert!(commit_positive(&db, &original, &progress, 3).await.is_err());
    assert_eq!(
        db.mirror_import(&original.job_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "published"
    );
    db.backend
        .execute(
            "UPDATE mirror_sources SET resource_version = resource_version - 1 WHERE registry_id = ?1",
            &vals![original.registry_id],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "UPDATE bindings SET resource_version = resource_version + 1 WHERE id = ?1",
            &vals![original.binding_id],
        )
        .await
        .unwrap();
    assert!(commit_positive(&db, &original, &progress, 3).await.is_err());
    assert_eq!(
        db.mirror_import(&original.job_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "published"
    );
}

#[tokio::test]
async fn registry_fk_retains_lost_ack_and_exact_positive_retirement_unblocks_deletion() {
    let db = Database::open_in_memory().await.unwrap();
    let original = original(&db).await;
    let progress = progress(&original);
    db.admit_mirror_import(&original, 1).await.unwrap();
    assert!(db
        .retire_acknowledged_mirror_import(&original, &progress)
        .await
        .is_err());
    commit_positive(&db, &original, &progress, 2).await.unwrap();
    let refusal = db
        .delete_registry_at_version(
            original.registry_id,
            original.registry_resource_version,
            "mirror-delete",
            "system",
            None,
            "test",
        )
        .await
        .unwrap_err();
    assert!(refusal.to_string().contains("retains a mirror original"));
    assert!(db
        .backend
        .execute(
            "DELETE FROM registries WHERE id = ?1",
            &vals![original.registry_id]
        )
        .await
        .is_err());
    assert!(db.mirror_import(&original.job_id).await.unwrap().is_some());

    let mut different = progress.clone();
    different
        .destination
        .as_mut()
        .unwrap()
        .object
        .provider_version = Some("other-version".into());
    assert!(db
        .retire_acknowledged_mirror_import(&original, &different)
        .await
        .is_err());
    // This argument represents the exact positively returned guard ACK; the
    // actual guard archive/dispatch test belongs to the runtime integration gate.
    db.retire_acknowledged_mirror_import(&original, &progress)
        .await
        .unwrap();
    assert!(db.mirror_import(&original.job_id).await.unwrap().is_none());
    db.retire_acknowledged_mirror_import(&original, &progress)
        .await
        .unwrap();
    delete_after_existing_gc_fences(&db, &original).await;
}

#[tokio::test]
async fn committed_replay_keeps_exact_proof_when_current_configuration_changes() {
    let db = Database::open_in_memory().await.unwrap();
    let original = original(&db).await;
    let progress = progress(&original);
    db.admit_mirror_import(&original, 1).await.unwrap();
    let committed = commit_positive(&db, &original, &progress, 2).await.unwrap();
    db.backend
        .execute(
            "UPDATE mirror_sources SET resource_version = resource_version + 1 WHERE registry_id = ?1",
            &vals![original.registry_id],
        )
        .await
        .unwrap();
    assert!(db
        .validate_mirror_import_authority(&original)
        .await
        .is_err());
    assert_eq!(
        db.record_mirror_import_progress(&original, &progress, true, 3)
            .await
            .unwrap()
            .commit_digest,
        committed.commit_digest
    );
}

#[tokio::test]
async fn actual_source_delete_recreate_and_policy_changes_cannot_recycle_authority() {
    let db = Database::open_in_memory().await.unwrap();
    let original = original(&db).await;
    db.admit_mirror_import(&original, 1).await.unwrap();
    assert!(db.delete_mirror_source(original.registry_id).await.is_err());
    assert!(db
        .delete_registry_mirror_at_version(original.registry_id, 1)
        .await
        .is_err());
    assert_eq!(
        db.registry_mirror(original.registry_id)
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        1
    );

    let changed = db
        .set_registry_mirror(
            original.registry_id,
            &original.upstream_base,
            "refs/heads/stable",
            "secret://mirror/test",
            "pull_through",
            "allow_unsigned",
            0,
            Some(1),
        )
        .await
        .unwrap();
    assert_eq!(changed.resource_version, 2);
    db.create_mirror_source(
        original.registry_id,
        &original.upstream_base,
        "full",
        true,
        3600,
    )
    .await
    .unwrap();
    assert_eq!(
        db.registry_mirror(original.registry_id)
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        3
    );
    assert!(db
        .validate_mirror_import_authority(&original)
        .await
        .is_err());
}

#[tokio::test]
async fn actual_progress_update_reasserts_authority_after_async_preflight() {
    let interference = Arc::new(AtomicBool::new(false));
    let db = Database::with_backend(Box::new(InterleavingBackend {
        inner: SqlxBackend::connect_sqlite(":memory:").await.unwrap(),
        invalidate_before_progress: Arc::clone(&interference),
    }))
    .await
    .unwrap();
    let original = original(&db).await;
    let progress = progress(&original);
    db.admit_mirror_import(&original, 1).await.unwrap();
    interference.store(true, Ordering::SeqCst);

    assert!(commit_positive(&db, &original, &progress, 2).await.is_err());
    let retained = db.mirror_import(&original.job_id).await.unwrap().unwrap();
    assert_eq!(retained.state, "admitted");
    assert!(retained.progress.is_none());
    assert!(retained.commit_digest.is_none());
    assert_eq!(retained.original, original);
}

#[tokio::test]
async fn acknowledged_retirement_allows_source_delete_but_parent_pin_survives_recreate() {
    let db = Database::open_in_memory().await.unwrap();
    let original = original(&db).await;
    let progress = progress(&original);
    db.admit_mirror_import(&original, 1).await.unwrap();
    commit_positive(&db, &original, &progress, 2).await.unwrap();
    assert!(db.delete_mirror_source(original.registry_id).await.is_err());
    db.retire_acknowledged_mirror_import(&original, &progress)
        .await
        .unwrap();
    assert!(db
        .delete_registry_mirror_at_version(original.registry_id, 1)
        .await
        .unwrap());
    db.create_mirror_source(
        original.registry_id,
        &original.upstream_base,
        "pullthrough",
        false,
        10,
    )
    .await
    .unwrap();
    assert_eq!(
        db.registry_mirror(original.registry_id)
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        1
    );
    assert!(
        db.registry_by_id(original.registry_id)
            .await
            .unwrap()
            .unwrap()
            .resource_version
            > original.registry_resource_version
    );
    assert!(db
        .validate_mirror_import_authority(&original)
        .await
        .is_err());
    assert!(db.admit_mirror_import(&original, 3).await.is_err());
}

#[test]
fn rejects_orphan_progress_and_unsupported_sources_before_dispatch() {
    let invalid = MirrorVerification::Nar {
        file_sha256: None,
        file_size: 1,
        compression: "xz".into(),
        nar_sha256: "1".repeat(64),
        nar_size: 1,
    };
    assert!(invalid.validate().is_err());
    let too_large = MirrorVerification::Sha256 {
        sha256: "1".repeat(64),
        size: crate::mirror_work::MIRROR_MAX_OBJECT_BYTES + 1,
    };
    assert!(too_large.validate().is_err());
    let decoded_too_large = MirrorVerification::Nar {
        file_sha256: None,
        file_size: 1,
        compression: "zstd".into(),
        nar_sha256: "1".repeat(64),
        nar_size: crate::mirror_work::MIRROR_MAX_OBJECT_BYTES + 1,
    };
    assert!(decoded_too_large.validate().is_err());
}

async fn initialize_generation_four(backend: &dyn crate::backend::Backend) {
    backend
        .execute(super::super::SCHEMA_VERSION_DDL, &[])
        .await
        .unwrap();
    for migration in &super::super::MIGRATIONS[..4] {
        backend.execute_batch(migration).await.unwrap();
    }
    backend
        .execute("INSERT INTO schema_version(version) VALUES (4)", &[])
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite_generation_four_serving_refuses_without_changing_old_rows() {
    let backend = crate::backend::SqlxBackend::connect_sqlite(":memory:")
        .await
        .unwrap();
    initialize_generation_four(&backend).await;
    backend
        .execute(
            "INSERT INTO users(email,created_at) VALUES ('retained@example.test',1)",
            &[],
        )
        .await
        .unwrap();
    let before = legacy_database_fingerprint(&backend).await;
    let retained_backend = cloned_sqlite_backend(&backend);

    let error = match Database::with_backend(Box::new(backend)).await {
        Ok(_) => panic!("generation four must refuse serving"),
        Err(error) => error,
    };

    assert!(format!("{error:#}").contains(crate::backend::schema_lineage::RESET_REQUIRED));
    assert_eq!(legacy_database_fingerprint(&retained_backend).await, before);
}

fn cloned_sqlite_backend(backend: &SqlxBackend) -> SqlxBackend {
    // Keep the same actual database observable after the initializer consumes it.
    match backend {
        SqlxBackend::Sqlite(pool) => SqlxBackend::Sqlite(pool.clone()),
        #[cfg(feature = "postgres")]
        SqlxBackend::Postgres(_) => panic!("fixture requires SQLite"),
        #[cfg(feature = "mysql")]
        SqlxBackend::Mysql(_) => panic!("fixture requires SQLite"),
    }
}

async fn legacy_database_fingerprint(backend: &dyn Backend) -> String {
    let schema = backend
        .query(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name",
            &[],
        )
        .await
        .unwrap();
    let tables = backend
        .query(
            "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name",
            &[],
        )
        .await
        .unwrap();
    let mut payloads = Vec::new();
    for table in tables {
        let name: String = table.get(0).unwrap();
        let sql = format!("SELECT * FROM \"{}\"", name.replace('"', "\"\""));
        let mut rows = backend
            .query(&sql, &[])
            .await
            .unwrap()
            .iter()
            .map(|row| serde_json::to_string(row).unwrap())
            .collect::<Vec<_>>();
        rows.sort();
        payloads.push((name, rows));
    }
    let changes = backend.query("SELECT total_changes()", &[]).await.unwrap();
    serde_json::to_string(&(schema, payloads, changes)).unwrap()
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires an isolated source-built PostgreSQL server and explicit test URL"]
async fn live_postgres_generation_four_upgrade_and_exact_mirror_lifecycle() {
    let url = std::env::var("AOS_MIRROR_TEST_POSTGRES_URL")
        .expect("explicit isolated PostgreSQL test URL");
    let backend = crate::backend::SqlxBackend::connect_postgres(&url)
        .await
        .unwrap();
    initialize_generation_four(&backend).await;
    let db = Database::with_backend(Box::new(backend)).await.unwrap();
    let version: i64 = db
        .backend
        .query_opt("SELECT version FROM schema_version", &[])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(version, 7);
    let original = original(&db).await;
    let progress = progress(&original);
    db.admit_mirror_import(&original, 1).await.unwrap();
    db.record_mirror_import_progress(&original, &progress, false, 2)
        .await
        .unwrap();
    let original_before = db.mirror_import(&original.job_id).await.unwrap().unwrap();
    db.backend
        .execute(
            "UPDATE mirror_sources SET resource_version = resource_version + 1 WHERE registry_id = ?1",
            &vals![original.registry_id],
        )
        .await
        .unwrap();
    assert!(commit_positive(&db, &original, &progress, 3).await.is_err());
    assert_eq!(
        db.mirror_import(&original.job_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        original_before.state
    );
    db.backend
        .execute(
            "UPDATE mirror_sources SET resource_version = resource_version - 1 WHERE registry_id = ?1",
            &vals![original.registry_id],
        )
        .await
        .unwrap();
    commit_positive(&db, &original, &progress, 3).await.unwrap();
    assert!(db
        .backend
        .execute(
            "DELETE FROM registries WHERE id = ?1",
            &vals![original.registry_id]
        )
        .await
        .is_err());
    db.retire_acknowledged_mirror_import(&original, &progress)
        .await
        .unwrap();
    delete_after_existing_gc_fences(&db, &original).await;
}

#[tokio::test]
async fn unresolved_path_reuses_its_operation_and_positive_retirement_allows_a_new_one() {
    let db = Database::open_in_memory().await.unwrap();
    let first = original(&db).await;
    db.admit_mirror_import(&first, 1).await.unwrap();
    let mut next = first.clone();
    next.copy_operation_id = Some("5".repeat(32));
    next.job_id = next.identity().unwrap();

    assert_ne!(first.job_id, next.job_id);
    assert!(db.admit_mirror_import(&next, 2).await.is_err());
    assert_eq!(
        db.mirror_import_for_path(first.registry_id, &first.path)
            .await
            .unwrap()
            .unwrap()
            .original,
        first
    );
    let final_progress = progress(&first);
    commit_positive(&db, &first, &final_progress, 3)
        .await
        .unwrap();
    db.retire_acknowledged_mirror_import(&first, &final_progress)
        .await
        .unwrap();

    db.admit_mirror_import(&next, 4).await.unwrap();
    assert_eq!(
        db.mirror_import_for_path(next.registry_id, &next.path)
            .await
            .unwrap()
            .unwrap()
            .original,
        next
    );
    assert!(db.mirror_import(&first.job_id).await.unwrap().is_none());
}

#[tokio::test]
async fn indexed_identity_preserves_long_legacy_paths_and_rejects_changed_scalars() {
    let db = Database::open_in_memory().await.unwrap();
    let mut legacy = original(&db).await;
    legacy.copy_operation_id = None;
    legacy.path = format!("nar/{}.nar", "a".repeat(1800));
    legacy.job_id = legacy.identity().unwrap();
    let canonical = serde_json::to_string(&legacy).unwrap();
    assert!(!canonical.contains("copy_operation_id"));
    assert!(db.admit_mirror_import(&legacy, 1).await.is_err());
    db.backend
        .execute(
            "INSERT INTO mirror_import_objects (job_id,registry_id,original_digest,original_json,state,created_at,updated_at) VALUES (?1,?2,?3,?4,'admitted',1,1)",
            &vals![
                legacy.job_id,
                legacy.registry_id,
                digest(&legacy).unwrap(),
                canonical
            ],
        )
        .await
        .unwrap();

    db.backfill_mirror_import_index().await.unwrap();
    let record = db
        .mirror_import_for_path(legacy.registry_id, &legacy.path)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.original, legacy);
    record
        .validate_index(Some(&legacy.path), Some(&legacy.source_path_digest()), None)
        .unwrap();
    assert!(record
        .validate_index(
            Some("nar/other.nar"),
            Some(&legacy.source_path_digest()),
            None
        )
        .is_err());
    assert!(record
        .validate_index(Some(&legacy.path), Some(&"0".repeat(64)), None)
        .is_err());
    assert!(record
        .validate_index(
            Some(&legacy.path),
            Some(&legacy.source_path_digest()),
            Some(&"4".repeat(32))
        )
        .is_err());
    assert_eq!(serde_json::to_string(&record.original).unwrap(), canonical);
}

#[tokio::test]
async fn generation_five_serving_refuses_and_isolated_backfill_preserves_original() {
    let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
    initialize_generation_four(&backend).await;
    backend
        .execute_batch(super::super::MIGRATIONS[4])
        .await
        .unwrap();
    backend
        .execute("UPDATE schema_version SET version = 5", &[])
        .await
        .unwrap();
    let retained_backend = cloned_sqlite_backend(&backend);
    let legacy_db = Database {
        backend: Box::new(backend),
    };
    // Create the binding using the genuine generation-five row contract.
    // Current registration reserves stable identities in generation seven;
    // invoking it here would silently require a future table in this fixture.
    legacy_db
        .backend
        .checked_batch(&[
            Statement::new(
                "INSERT INTO bindings
               (id, org_id, name, kind, is_instance_default, instance_default_key,
                created_at, stable_id, owner_scope_key, object_bucket,
                object_prefix, resource_version, updated_at)
             VALUES (1, NULL, 'default', 'deployment_r2', 1, 'singleton', 1,
                     'instance-default', 'instance', ?1, '', 1, 1)",
                vals![crate::binding::DEPLOYMENT_R2_ATTACHMENT],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO binding_consumer_scopes
               (binding_id, consumer_scope_key, grant_generation, grant_kind,
                state, granted_by, granted_at, resource_version)
             VALUES (1, 'instance', 1, 'owner', 'active', 'fixture', 1, 1)",
                vec![],
            )
            .expecting(1),
        ])
        .await
        .unwrap();
    let mut legacy = original(&legacy_db).await;
    legacy.copy_operation_id = None;
    legacy.job_id = legacy.identity().unwrap();
    let canonical = serde_json::to_string(&legacy).unwrap();
    legacy_db.backend
        .execute(
            "INSERT INTO mirror_import_objects (job_id,registry_id,original_digest,original_json,state,created_at,updated_at) VALUES (?1,?2,?3,?4,'admitted',1,1)",
            &vals![
                legacy.job_id,
                legacy.registry_id,
                digest(&legacy).unwrap(),
                canonical
            ],
        )
        .await
        .unwrap();

    let before = legacy_database_fingerprint(legacy_db.backend.as_ref()).await;

    let error = match Database::with_backend(Box::new(retained_backend)).await {
        Ok(_) => panic!("generation five must refuse serving"),
        Err(error) => error,
    };

    assert!(format!("{error:#}").contains(crate::backend::schema_lineage::RESET_REQUIRED));
    assert_eq!(
        legacy_database_fingerprint(legacy_db.backend.as_ref()).await,
        before
    );

    // Exercise the immutable legacy script and typed backfill in isolation.
    // This does not admit the old schema through the serving initializer.
    legacy_db
        .backend
        .execute_batch(include_str!("../006-mirror-import-generations.sql"))
        .await
        .unwrap();
    legacy_db.backfill_mirror_import_index().await.unwrap();
    // Read the historical generation-six projection, without requiring the
    // later publication qualifier used by the current serving reader.
    let row = legacy_db
        .backend
        .query_opt(
            "SELECT job_id,registry_id,original_digest,original_json,progress_json,
                    state,commit_digest,created_at,updated_at,
                    source_path,source_path_digest,copy_operation_id
             FROM mirror_import_objects WHERE registry_id = ?1 AND source_path_digest = ?2",
            &vals![legacy.registry_id, legacy.source_path_digest()],
        )
        .await
        .unwrap()
        .unwrap();
    let retained = MirrorImportRecord::decode(
        &row.get::<String>(0).unwrap(),
        row.get(1).unwrap(),
        &row.get::<String>(2).unwrap(),
        &row.get::<String>(3).unwrap(),
        row.get::<Option<String>>(4).unwrap().as_deref(),
        &row.get::<String>(5).unwrap(),
        row.get::<Option<String>>(6).unwrap().as_deref(),
        row.get(7).unwrap(),
        row.get(8).unwrap(),
    )
    .unwrap();
    retained
        .validate_index(
            row.get::<Option<String>>(9).unwrap().as_deref(),
            row.get::<Option<String>>(10).unwrap().as_deref(),
            row.get::<Option<String>>(11).unwrap().as_deref(),
        )
        .unwrap();
    assert_eq!(retained.original, legacy);
    assert_eq!(
        serde_json::to_string(&retained.original).unwrap(),
        canonical
    );
    assert!(retained.original.copy_operation_id.is_none());
    let version = legacy_db
        .backend
        .query("SELECT version FROM schema_version", &[])
        .await
        .unwrap();
    assert_eq!(version[0].get::<i64>(0).unwrap(), 5);
    retained
        .validate_index(Some(&legacy.path), Some(&legacy.source_path_digest()), None)
        .unwrap();
}
