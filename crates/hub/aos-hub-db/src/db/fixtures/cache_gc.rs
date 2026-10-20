//! Exact cache inventory setup shared by SQL and deletion-controller regressions.

use crate::backend::Statement;
use crate::db::*;

/// Constructs the retained gc fixture fixture.
///
/// # Panics
///
/// Panics if fixture setup or the expected fixture record is invalid.
pub async fn gc_fixture() -> Database {
    let db = Database::open_in_memory().await.unwrap();
    db.backend
        .execute(
            "INSERT INTO authorization_scopes
             (scope_key, kind, org_id, parent_scope_key, resource_stable_id, created_at)
             VALUES ('cache:00000000000000000000000000000001', 'binary_cache',
                     NULL, 'instance', 'cache:00000000000000000000000000000001', 1)",
            &[],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO authorization_scope_ancestors
             (descendant_scope_key, ancestor_scope_key, depth)
             VALUES
               ('cache:00000000000000000000000000000001',
                'cache:00000000000000000000000000000001', 0),
               ('cache:00000000000000000000000000000001', 'instance', 1)",
            &[],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO binary_caches
             (id, stable_id, slug, name, visibility, created_at,
              scope_key, owner_scope_key)
             VALUES (1, 'cache:00000000000000000000000000000001',
                     'test/cache', 'Cache', 'private', 1,
                     'cache:00000000000000000000000000000001', 'instance')",
            &[],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO cache_inventory_generations
             (cache_id, generation, owner_token, lease_expires_at,
              state, content_digest, published_at, created_at)
             VALUES (1, 1, 'bootstrap', 2,
               'published', 'inventory-1', 1, 1)",
            &[],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO cache_gc_policies
             (cache_id, unreferenced_grace_secs, deletion_concurrency,
              retry_initial_secs, retry_max_secs, retry_max_attempts,
              tombstone_retention_secs)
             VALUES (1, 3600, 2, 5, 300, 5, 86400)",
            &[],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO cache_gc_deletion_capacity (cache_id, running_count)
             VALUES (1, 0)",
            &[],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO cache_gc_state
             (cache_id, epoch, epoch_owner_token, inventory_generation)
             VALUES (1, 0, 'bootstrap', 1)",
            &[],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO cache_gc_heads
             (cache_id, resource_version, updated_at)
             VALUES (1, 1, 1)",
            &[],
        )
        .await
        .unwrap();
    db
}

/// Constructs the retained install inventory placement fixture.
///
/// # Panics
///
/// Panics if fixture setup or the expected fixture record is invalid.
pub async fn install_inventory_placement(db: &Database) {
    db.backend
        .checked_batch(&[
            Statement::new(
                "INSERT INTO bindings
                 (id, name, kind, is_instance_default, instance_default_key,
                  created_at, stable_id, owner_scope_key, local_root_path,
                  resource_version, updated_at)
                 VALUES (1, 'inventory-store', 'local_fs', 1, 'singleton',
                   1, 'inventory-store', 'instance', '/inventory', 1, 1)",
                vec![],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO binding_consumer_scopes
                 (binding_id, consumer_scope_key, grant_generation,
                  grant_kind, state, granted_by, granted_at, resource_version)
                 VALUES (1, 'instance', 1, 'owner', 'active', 'test', 1, 1)",
                vec![],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO surface_placements
                 (id, cache_id, name, binding_id, consumer_scope_key,
                  binding_grant_generation, binding_grant_state, prefix, kind,
                  desired_state, desired_read_enabled, write_spec_version,
                  requires_conditional_writes, created_at, updated_at)
                 VALUES (1, 1, 'primary', 1, 'instance', 1, 'active', '',
                   'complete', 'active', 1, 1, 1, 1, 1)",
                vec![],
            )
            .expecting(1),
        ])
        .await
        .unwrap();
}

/// Constructs the retained deletion fixture fixture.
///
/// # Panics
///
/// Panics if fixture setup or the expected fixture record is invalid.
pub async fn deletion_fixture() -> Database {
    let db = gc_fixture().await;
    db.backend
        .checked_batch(&[
            Statement::new(
                "INSERT INTO bindings
                 (id, name, kind, is_instance_default, instance_default_key,
                  created_at, stable_id, owner_scope_key, local_root_path,
                  resource_version, updated_at)
                 VALUES (1, 'delete-store', 'local_fs', 1, 'singleton',
                   1, 'instance-default', 'instance', '/delete-store', 1, 1)",
                vec![],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO binding_credential_revisions
                 (binding_id, purpose, generation, secret_version_ref,
                  validation_state, validated_at, credential_fingerprint,
                  created_by, created_at)
                 VALUES (1, 'delete', 1, 'test-delete-secret', 'valid', 1,
                   'test-delete-fingerprint', 'test', 1)",
                vec![],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO binding_consumer_scopes
                 (binding_id, consumer_scope_key, grant_generation,
                  grant_kind, state, granted_by, granted_at, resource_version)
                 VALUES (1, 'instance', 1, 'owner', 'active', 'test', 1, 1)",
                vec![],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO surface_placements
                 (id, cache_id, name, binding_id, consumer_scope_key,
                  binding_grant_generation, binding_grant_state, prefix, kind,
                  desired_state, desired_read_enabled, write_spec_version,
                  requires_conditional_writes, created_at, updated_at)
                 VALUES (1, 1, 'primary', 1, 'instance', 1, 'active', '',
                   'complete', 'active', 1, 1, 1, 1, 1)",
                vec![],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO surface_objects
                 (id, cache_id, object_key, object_kind, partition_key,
                  content_hash, size, lifecycle_state, tombstoned_at,
                  created_at, updated_at)
                 VALUES (1, 1, 'nar/object.nar', 'immutable', zeroblob(32),
                   'sha256-object', 12, 'tombstoned', 10, 1, 10)",
                vec![],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO object_placements
                 (surface_object_id, cache_id, placement_id, state,
                  observed_hash, observed_size, etag,
                  observed_inventory_generation, observed_at)
                 VALUES (1, 1, 1, 'deleting', 'sha256-object', 12,
                   'etag-1', 1, 10)",
                vec![],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO topology_operations
                 (operation_id, operation_kind, authorization_scope_key,
                  control_permission, primary_target_kind, primary_target_stable_id,
                  state, progress_total, created_at)
                 VALUES ('gc-operation', 'cache_gc', 'instance',
                   'cache.gc.execute', 'binary_cache',
                   'cache:00000000000000000000000000000001',
                   'pending', 1, 10)",
                vec![],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO object_deletion_jobs
                 (job_id, cache_id, originating_operation_id,
                  operation_target_kind, operation_target_stable_id,
                  surface_object_id, placement_id, phase, expected_etag,
                  expected_hash, expected_size, expected_inventory_generation,
                  binding_id, binding_resource_version,
                  delete_credential_generation,
                  state, active_slot, max_attempts, next_attempt_at, created_at)
                 VALUES ('delete-job', 1, 'gc-operation', 'binary_cache',
                   'cache:00000000000000000000000000000001', 1, 1, 'nar',
                   'etag-1', 'sha256-object', 12, 1, 1, 1, 1,
                   'pending', 1, 3, 10, 10)",
                vec![],
            )
            .expecting(1),
        ])
        .await
        .unwrap();
    db
}

/// Constructs the retained stage test inventory candidate with version fixture.
///
/// # Panics
///
/// Panics if fixture setup or the expected fixture record is invalid.
pub async fn stage_test_inventory_candidate_with_version(
    db: &Database,
    generation: i64,
    placement_id: i64,
    narinfo_hash: &str,
    provider_version: Option<&str>,
) {
    let owner_token = "inventory-owner";
    let text = "StorePath: /nix/store/abc123-demo-1.0\n\
                URL: nar/demo.nar.zst\n\
                Compression: zstd\n\
                FileHash: file-demo\n\
                FileSize: 20\n\
                NarHash: nar-demo\n\
                NarSize: 40\n";
    let parsed = aos_hub_model::cache::parse_cache_narinfo(1, "abc123", text, 20).unwrap();
    db.stage_cache_surface_object_identity(
        1,
        generation,
        placement_id,
        owner_token,
        "abc123.narinfo",
        narinfo_hash,
        i64::try_from(text.len()).unwrap(),
    )
    .await
    .unwrap();
    db.stage_cache_surface_object_identity(
        1,
        generation,
        placement_id,
        owner_token,
        &parsed.nar_url,
        &parsed.file_hash,
        parsed.file_size,
    )
    .await
    .unwrap();
    for (key, hash, size) in [
        (
            "abc123.narinfo",
            narinfo_hash,
            i64::try_from(text.len()).unwrap(),
        ),
        (
            parsed.nar_url.as_str(),
            parsed.file_hash.as_str(),
            parsed.file_size,
        ),
    ] {
        db.stage_cache_object_presence(
            owner_token,
            &CacheObjectPresenceObservation {
                cache_id: 1,
                object_key: key.to_string(),
                placement_id,
                state: "present".into(),
                observed_hash: Some(hash.to_string()),
                observed_size: Some(size),
                etag: Some(format!("etag-{key}")),
                provider_version: provider_version.map(str::to_string),
                inventory_generation: generation,
                observed_at: 20,
            },
        )
        .await
        .unwrap();
    }
    db.stage_cache_inventory_narinfo_candidate(
        owner_token,
        &CacheInventoryNarinfoCandidate {
            cache_id: 1,
            generation,
            placement_id,
            store_hash: parsed.store_hash,
            store_name: parsed.store_name,
            identity_digest: "a".repeat(64),
            narinfo_object_key: "abc123.narinfo".into(),
            nar_object_key: parsed.nar_url,
            nar_hash: parsed.nar_hash,
            nar_size: parsed.nar_size,
            file_hash: parsed.file_hash,
            file_size: parsed.file_size,
            compression: parsed.compression,
            deriver: parsed.deriver,
            signature: parsed.signature,
            content_address: parsed.content_address,
            references: parsed.references,
            published_at: parsed.published_at,
        },
    )
    .await
    .unwrap();
    db.stage_cache_inventory_manifest(
        1,
        generation,
        placement_id,
        owner_token,
        &format!("placement-{placement_id}-digest"),
        2,
        20,
    )
    .await
    .unwrap();
}
