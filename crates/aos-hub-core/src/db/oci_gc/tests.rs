//! Focused invariants for Phase 7 OCI GC canonical evidence and schema.

use super::{
    oci_gc_deletion_evidence_digest, AppendOciProviderInventoryPage, ApplyOciGc,
    ApplyOciRegistryPurgeFence, ApplyOciUntrackedRepair, BeginOciProviderInventory,
    CompleteOciProviderInventory, OciGcDeleteOutcome, OciProviderInventoryEntryInput,
    OciRegistryPurgeFenceAction, OciUntrackedRepairKind, PlanOciGc, PlanOciRegistryPurgeFence,
    PlanOciUntrackedRepair, RecordOciConditionalDeleteCapability, RecordOciGcDeletionSuccess,
    RecordOciUntrackedRepairSuccess, RequeueOciGcPlacementAction,
};
use aos_oci_types::{
    Annotations, Descriptor, ImageManifest, MediaType, RepositoryName, Sha256Digest, Tag,
};

use crate::db::{
    oci_catalog_declaration_digest, AddOciPublicationObject, AppendOciUploadChunk,
    BeginOciPublication, BeginOciUpload, ClaimOciUpload, CompleteOciUpload, Database,
    IndexOciRepositoryCatalog, NewBindingWriteRevision, NewSurfacePlacementSpec,
    OciBlobClaimOutcome, OciCatalogObject, OciCatalogProjection, OciPublicationRequiredPlacement,
    OciSha256State, OciUploadChunkRecord, SurfaceTarget, MIGRATIONS,
};
use crate::dialect::Dialect;

#[test]
fn v23_schema_contains_transactional_gc_evidence_and_fences() {
    let migration = MIGRATIONS.get(22).expect("v23 migration is present");
    for table in [
        "oci_provider_inventory_generations",
        "oci_provider_inventory_entries",
        "oci_provider_inventory_heads",
        "oci_gc_runs",
        "oci_gc_registry_locks",
        "oci_gc_candidates",
        "oci_gc_placement_snapshots",
        "oci_gc_credential_holds",
        "oci_gc_placement_actions",
        "oci_gc_deletion_evidence",
        "oci_gc_snapshot_lease_holds",
    ] {
        assert!(
            migration.contains(&format!("CREATE TABLE {table}")),
            "v23 omits {table}"
        );
    }
    assert!(migration.contains("UNIQUE(placement_id, active_slot)"));
    assert!(migration.contains("inventory_entry_present"));
}

#[test]
fn v24_schema_contains_review_remediation_authorities() {
    let migration = MIGRATIONS.get(23).expect("v24 migration is present");
    for identity in [
        "unreferenced_since",
        "oci_registry_purge_fences",
        "oci_registry_purge_fence_plans",
        "purge_fence_resource_version",
        "oci_untracked_repair_plans",
        "oci_untracked_repair_evidence",
    ] {
        assert!(migration.contains(identity), "v24 omits {identity}");
    }
}

#[test]
fn v24_schema_statements_translate_for_postgres_and_mysql() {
    let migration = MIGRATIONS.get(23).expect("v24 migration is present");
    for dialect in [Dialect::Postgres, Dialect::Mysql] {
        for sql in crate::backend::split_statements(migration) {
            dialect
                .translate(&sql)
                .unwrap_or_else(|error| panic!("{dialect:?} rejected v24 SQL: {error:#}"));
        }
    }
}

#[test]
fn v23_schema_statements_translate_for_postgres_and_mysql() {
    let migration = MIGRATIONS.get(22).expect("v23 migration is present");
    for statement in crate::backend::split_statements(migration) {
        for dialect in [Dialect::Postgres, Dialect::Mysql] {
            dialect
                .translate(&statement)
                .unwrap_or_else(|error| panic!("{dialect:?} rejected v23 SQL: {error:#}"));
        }
    }
}

#[test]
fn operations_metrics_query_translates_for_postgres_and_mysql() {
    let source = include_str!("read.rs");
    let method = source
        .split("pub async fn oci_operations_metrics")
        .nth(1)
        .expect("operations metrics method is present");
    let query = method
        .split_once("\"SELECT")
        .and_then(|(_, tail)| {
            tail.split_once("\",\n                &vals![now, stuck_before]")
                .map(|(sql, _)| format!("SELECT{sql}"))
        })
        .expect("operations metrics SQL is extractable");
    for dialect in [Dialect::Postgres, Dialect::Mysql] {
        dialect
            .translate(&query)
            .unwrap_or_else(|error| panic!("{dialect:?} rejected metrics SQL: {error:#}"));
    }
}

#[test]
fn live_graph_identity_query_translates_for_postgres_and_mysql() {
    let source = include_str!("plan.rs");
    let method = source
        .split("async fn traverse_oci_gc_live_graph")
        .nth(1)
        .expect("live graph traversal is present");
    let query = method
        .split_once("\"SELECT")
        .and_then(|(_, tail)| {
            tail.split_once("\",\n                &vals![")
                .map(|(sql, _)| format!("SELECT{sql}"))
        })
        .expect("live graph identity SQL is extractable");
    for dialect in [Dialect::Postgres, Dialect::Mysql] {
        dialect
            .translate(&query)
            .unwrap_or_else(|error| panic!("{dialect:?} rejected identity SQL: {error:#}"));
    }
}

#[test]
fn deletion_evidence_digest_binds_every_response_field() {
    let baseline = oci_gc_deletion_evidence_digest(
        "action",
        "retry",
        OciGcDeleteOutcome::Deleted,
        Some("\"etag\""),
        Some("provider-request"),
        42,
    )
    .unwrap();
    let changed_request = oci_gc_deletion_evidence_digest(
        "action",
        "retry",
        OciGcDeleteOutcome::Deleted,
        Some("\"etag\""),
        Some("other-request"),
        42,
    )
    .unwrap();
    let changed_time = oci_gc_deletion_evidence_digest(
        "action",
        "retry",
        OciGcDeleteOutcome::Deleted,
        Some("\"etag\""),
        Some("provider-request"),
        43,
    )
    .unwrap();

    assert_ne!(baseline, changed_request);
    assert_ne!(baseline, changed_time);
}

async fn seed_registry(database: &Database) {
    const REGISTRY_SCOPE: &str = "registry:00000000000000000000000000000001";
    database
        .backend
        .execute(
            "INSERT INTO authorization_scopes
               (scope_key, kind, parent_scope_key, resource_stable_id, created_at)
             VALUES(?1, 'registry', 'instance', ?1, 1)",
            &vals![REGISTRY_SCOPE],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO registries
               (id, stable_id, slug, trust_keys, require_signatures,
                created_at, updated_at, scope_key, owner_scope_key)
             VALUES(1, ?1, 'test', '[]', 1, 1, 1, ?1, 'instance')",
            &vals![REGISTRY_SCOPE],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_registry_state
               (registry_id, mutation_epoch, charged_bytes, charged_objects, updated_at)
             VALUES(1, 0, 0, 0, 1)",
            &[],
        )
        .await
        .unwrap();
}

fn descriptor(media_type: MediaType, bytes: &[u8]) -> Descriptor {
    Descriptor {
        media_type,
        digest: Sha256Digest::digest(bytes),
        size: u64::try_from(bytes.len()).unwrap(),
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: None,
    }
}

async fn seed_run(database: &Database, id: &str, state: &str, expires_at: i64) {
    seed_run_for_registry(database, 1, id, state, expires_at).await;
}

async fn seed_run_for_registry(
    database: &Database,
    registry_id: i64,
    id: &str,
    state: &str,
    expires_at: i64,
) {
    let digest = Sha256Digest::digest(b"reviewed").to_string();
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_runs
               (id, registry_id, actor_id, plan_idempotency_key,
                apply_idempotency_key, state, captured_mutation_epoch,
                applied_mutation_epoch, policy_resource_version, policy_digest,
                root_set_digest, placement_inventory_digest, topology_digest,
                plan_digest, confirmation_hash, inventory_object_count,
                inventory_byte_size, reachable_object_count, planned_bytes,
                planned_objects, deleted_object_count, deleted_byte_size,
                placement_action_count, expires_at, created_at, applied_at,
                finished_at, last_error, resource_version)
             VALUES(?1, ?2, 'actor', ?1, ?3, ?4, 0, ?5, 0, ?6, ?6, ?6,
                    ?6, ?6, ?6, 0, 0, 0, 0, 0, 0, 0, 0, ?7, 1, ?8,
                    ?9, NULL, 1)",
            &vals![
                id,
                registry_id,
                (state == "applying").then_some("apply"),
                state,
                (state == "applying").then_some(0_i64),
                digest,
                expires_at,
                (state == "applying").then_some(2_i64),
                matches!(state, "complete" | "aborted" | "failed").then_some(2_i64)
            ],
        )
        .await
        .unwrap();
}

async fn seed_inventory_topology(database: &Database) -> (i64, crate::db::SurfacePlacementRecord) {
    let org_id = database.create_org("oci-gc", "OCI GC").await.unwrap();
    let owner = database.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = database
        .create_topology_binding(
            Some(org_id),
            "oci-gc-binding",
            &owner.stable_id,
            "primary",
            "r2",
            None,
            Some("oci-gc-test"),
            Some("objects"),
            Some("https"),
            Some("dns"),
            Some(b"storage.example.invalid"),
            Some(443),
            Some("auto"),
            Some("private"),
        )
        .await
        .unwrap();
    let credential = database
        .set_binding_credential_revision(
            binding_id,
            "write",
            "secret://oci-gc/write/v1",
            0,
            &"0".repeat(64),
            "test",
        )
        .await
        .unwrap();
    let credential = database
        .validate_binding_credential_revision(
            binding_id,
            "write",
            credential.generation,
            "valid",
            None,
            credential.head_resource_version,
        )
        .await
        .unwrap();
    let revision = database
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id,
            write_credential_generation: credential.generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "oci-gc-write-revision".to_string(),
            capability_fingerprint: "conditional-write-v1".to_string(),
        })
        .await
        .unwrap();
    database
        .observe_binding_write_revision(binding_id, revision.revision, "valid", None, None)
        .await
        .unwrap();
    let state = database
        .binding_write_state(binding_id)
        .await
        .unwrap()
        .unwrap();
    database
        .set_current_binding_write_revision(binding_id, revision.revision, state.resource_version)
        .await
        .unwrap();

    let registry_id = database
        .create_managed_registry(org_id, "", "oci-gc", "public", &[], false)
        .await
        .unwrap();
    let placement = database
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".to_string(),
            binding_id,
            prefix: "registry".to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: true,
        })
        .await
        .unwrap();
    let placement = database
        .observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    database
        .bind_surface_placement_write_capability(placement.id, revision.revision)
        .await
        .unwrap();
    (registry_id, placement)
}

async fn seal_inventory_for_digests(
    database: &Database,
    registry_id: i64,
    placement: &crate::db::SurfacePlacementRecord,
    digests: &[(Sha256Digest, u64)],
    clock: i64,
) {
    let binding = database
        .binding(placement.binding_id)
        .await
        .unwrap()
        .unwrap();
    let write_revision = database
        .binding_write_state(placement.binding_id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    let delete_credential = database
        .set_binding_credential_revision(
            placement.binding_id,
            "delete",
            "secret://oci-gc/delete/v1",
            0,
            &"7".repeat(64),
            "test",
        )
        .await
        .unwrap();
    let delete_credential = database
        .validate_binding_credential_revision(
            placement.binding_id,
            "delete",
            delete_credential.generation,
            "valid",
            None,
            delete_credential.head_resource_version,
        )
        .await
        .unwrap();
    database
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            binding_id: placement.binding_id,
            binding_write_revision: write_revision,
            binding_resource_version: binding.resource_version,
            delete_credential_purpose: Some("delete".to_string()),
            delete_credential_generation: Some(delete_credential.generation),
            capability_fingerprint: "conditional-delete-helper".to_string(),
            state: "valid".to_string(),
            expected_resource_version: None,
            observed_at: clock,
        })
        .await
        .unwrap();
    let generation = database
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id,
            placement_id: placement.id,
            expected_placement_resource_version: placement.resource_version,
            expected_placement_observation_version: placement.observation_version.unwrap(),
            collector_id: "fixture-collector".to_string(),
            collector_claim_token: "fixture-claim".to_string(),
            collector_lease_seconds: 100,
            idempotency_key: format!("fixture-inventory-{clock}"),
            now: clock,
        })
        .await
        .unwrap();
    let mut entries = digests
        .iter()
        .map(|(digest, byte_size)| OciProviderInventoryEntryInput {
            object_key: crate::db::oci_blob_object_key(*digest),
            object_digest: *digest,
            observed_hash: *digest,
            byte_size: *byte_size,
            strong_etag: format!("\"{}\"", digest.encoded()),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.object_key.cmp(&right.object_key));
    database
        .append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
            generation_id: generation.id.clone(),
            collector_id: "fixture-collector".to_string(),
            collector_claim_token: "fixture-claim".to_string(),
            expected_checkpoint_ordinal: 0,
            expected_provider_cursor: None,
            next_provider_cursor: None,
            last_listed_key: entries.last().map(|entry| entry.object_key.clone()),
            entries,
            now: clock + 1,
            lease_seconds: 100,
        })
        .await
        .unwrap();
    database
        .complete_oci_provider_inventory(&CompleteOciProviderInventory {
            generation_id: generation.id,
            collector_id: "fixture-collector".to_string(),
            collector_claim_token: "fixture-claim".to_string(),
            expected_checkpoint_ordinal: 1,
            observed_at: clock + 1,
            now: clock + 2,
        })
        .await
        .unwrap();
}

async fn seal_empty_inventory(
    database: &Database,
    registry_id: i64,
    placement: &crate::db::SurfacePlacementRecord,
    key: &str,
    now: i64,
) -> super::OciProviderInventoryGenerationRecord {
    let generation = database
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id,
            placement_id: placement.id,
            expected_placement_resource_version: placement.resource_version,
            expected_placement_observation_version: placement.observation_version.unwrap(),
            collector_id: key.to_string(),
            collector_claim_token: format!("{key}-claim"),
            collector_lease_seconds: 100,
            idempotency_key: format!("{key}-inventory"),
            now,
        })
        .await
        .unwrap();
    database
        .append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
            generation_id: generation.id.clone(),
            collector_id: key.to_string(),
            collector_claim_token: format!("{key}-claim"),
            expected_checkpoint_ordinal: 0,
            expected_provider_cursor: None,
            next_provider_cursor: None,
            last_listed_key: None,
            entries: Vec::new(),
            now: now + 1,
            lease_seconds: 100,
        })
        .await
        .unwrap();
    database
        .complete_oci_provider_inventory(&CompleteOciProviderInventory {
            generation_id: generation.id,
            collector_id: key.to_string(),
            collector_claim_token: format!("{key}-claim"),
            expected_checkpoint_ordinal: 1,
            observed_at: now + 1,
            now: now + 2,
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn purge_requires_post_fence_empty_head_and_rejects_failed_newer_scan() {
    let database = Database::open_in_memory().await.unwrap();
    let (registry_id, placement) = seed_inventory_topology(&database).await;
    let now = crate::db::unix_now();
    let delete_credential = database
        .set_binding_credential_revision(
            placement.binding_id,
            "delete",
            "secret://oci-gc/purge-delete/v1",
            0,
            &"8".repeat(64),
            "test",
        )
        .await
        .unwrap();
    let delete_credential = database
        .validate_binding_credential_revision(
            placement.binding_id,
            "delete",
            delete_credential.generation,
            "valid",
            None,
            delete_credential.head_resource_version,
        )
        .await
        .unwrap();
    let binding = database
        .binding(placement.binding_id)
        .await
        .unwrap()
        .unwrap();
    let write_revision = database
        .binding_write_state(placement.binding_id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    database
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            binding_id: placement.binding_id,
            binding_write_revision: write_revision,
            binding_resource_version: binding.resource_version,
            delete_credential_purpose: Some("delete".to_string()),
            delete_credential_generation: Some(delete_credential.generation),
            capability_fingerprint: "purge-conditional-delete".to_string(),
            state: "valid".to_string(),
            expected_resource_version: None,
            observed_at: now,
        })
        .await
        .unwrap();
    let registry = database.registry_by_id(registry_id).await.unwrap().unwrap();
    let begin = PlanOciRegistryPurgeFence {
        registry_id,
        action: OciRegistryPurgeFenceAction::Begin,
        actor_id: "purge-operator".to_string(),
        idempotency_key: "review-purge-begin".to_string(),
        expected_resource_version: registry.resource_version,
        now,
    };
    let begin_plan = database
        .plan_oci_registry_purge_fence(&begin)
        .await
        .unwrap();
    assert_eq!(
        database
            .plan_oci_registry_purge_fence(&begin)
            .await
            .unwrap(),
        begin_plan,
        "lost Plan response must replay the exact reviewed identity"
    );
    assert!(database
        .oci_registry_purge_fence_plan_for_actor(&begin_plan.id, "other-actor")
        .await
        .unwrap()
        .is_none());
    let begin_apply = ApplyOciRegistryPurgeFence {
        plan_id: begin_plan.id.clone(),
        actor_id: "purge-operator".to_string(),
        idempotency_key: "apply-purge-begin".to_string(),
        confirmation_hash: begin_plan.confirmation_hash,
        expected_resource_version: begin_plan.resource_version,
        now: now + 1,
    };
    let applied_begin = database
        .apply_oci_registry_purge_fence(&begin_apply)
        .await
        .unwrap();
    assert_eq!(
        database
            .apply_oci_registry_purge_fence(&begin_apply)
            .await
            .unwrap(),
        applied_begin,
        "lost Apply response must replay the exact fence transition"
    );
    let first_status = database
        .oci_registry_purge_fence_status_for_actor(&begin_plan.id, "purge-operator", now + 1)
        .await
        .unwrap()
        .unwrap();
    let first_fence = first_status.fence.unwrap();
    assert_eq!(first_fence.state, "collecting");

    let abort_plan = database
        .plan_oci_registry_purge_fence(&PlanOciRegistryPurgeFence {
            registry_id,
            action: OciRegistryPurgeFenceAction::Abort,
            actor_id: "purge-operator".to_string(),
            idempotency_key: "review-purge-abort".to_string(),
            expected_resource_version: first_fence.resource_version,
            now: now + 2,
        })
        .await
        .unwrap();
    database
        .apply_oci_registry_purge_fence(&ApplyOciRegistryPurgeFence {
            plan_id: abort_plan.id,
            actor_id: "purge-operator".to_string(),
            idempotency_key: "apply-purge-abort".to_string(),
            confirmation_hash: abort_plan.confirmation_hash,
            expected_resource_version: abort_plan.resource_version,
            now: now + 3,
        })
        .await
        .unwrap();
    assert_eq!(
        database
            .oci_registry_purge_fence(registry_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "aborted"
    );

    let begin_again = database
        .plan_oci_registry_purge_fence(&PlanOciRegistryPurgeFence {
            idempotency_key: "review-purge-begin-again".to_string(),
            now: now + 4,
            ..begin
        })
        .await
        .unwrap();
    database
        .apply_oci_registry_purge_fence(&ApplyOciRegistryPurgeFence {
            plan_id: begin_again.id,
            actor_id: "purge-operator".to_string(),
            idempotency_key: "apply-purge-begin-again".to_string(),
            confirmation_hash: begin_again.confirmation_hash,
            expected_resource_version: begin_again.resource_version,
            now: now + 5,
        })
        .await
        .unwrap();
    assert!(database
        .ensure_oci_repository(
            registry_id,
            &RepositoryName::parse("blocked-by-purge").unwrap(),
            now + 6,
        )
        .await
        .is_err());

    let untracked = Sha256Digest::digest(b"out-of-band-provider-key");
    let nonempty = database
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id,
            placement_id: placement.id,
            expected_placement_resource_version: placement.resource_version,
            expected_placement_observation_version: placement.observation_version.unwrap(),
            collector_id: "purge-nonempty".to_string(),
            collector_claim_token: "purge-nonempty-claim".to_string(),
            collector_lease_seconds: 100,
            idempotency_key: "purge-nonempty-scan".to_string(),
            now: now + 7,
        })
        .await
        .unwrap();
    database
        .append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
            generation_id: nonempty.id.clone(),
            collector_id: "purge-nonempty".to_string(),
            collector_claim_token: "purge-nonempty-claim".to_string(),
            expected_checkpoint_ordinal: 0,
            expected_provider_cursor: None,
            next_provider_cursor: None,
            last_listed_key: Some(crate::db::oci_blob_object_key(untracked)),
            entries: vec![OciProviderInventoryEntryInput {
                object_key: crate::db::oci_blob_object_key(untracked),
                object_digest: untracked,
                observed_hash: untracked,
                byte_size: 21,
                strong_etag: "\"out-of-band\"".to_string(),
            }],
            now: now + 8,
            lease_seconds: 100,
        })
        .await
        .unwrap();
    database
        .complete_oci_provider_inventory(&CompleteOciProviderInventory {
            generation_id: nonempty.id.clone(),
            collector_id: "purge-nonempty".to_string(),
            collector_claim_token: "purge-nonempty-claim".to_string(),
            expected_checkpoint_ordinal: 1,
            observed_at: now + 8,
            now: now + 9,
        })
        .await
        .unwrap();
    assert_eq!(
        database
            .oci_registry_purge_blockers(registry_id, now + 9)
            .await
            .unwrap()
            .untracked_provider_objects,
        1
    );
    assert!(database
        .delete_registry_at_version(
            registry_id,
            registry.resource_version,
            "purge-too-early",
            "user",
            None,
            "purge-operator",
        )
        .await
        .is_err());

    let page = database
        .list_untracked_oci_provider_inventory(registry_id, None, 100)
        .await
        .unwrap();
    let reviewed = page.items.first().unwrap();
    let repair = database
        .plan_oci_untracked_repair(&PlanOciUntrackedRepair {
            registry_id,
            placement_id: reviewed.placement_id,
            inventory_generation_id: reviewed.inventory_generation_id.clone(),
            object_key: reviewed.object_key.clone(),
            repair_kind: OciUntrackedRepairKind::Delete,
            adopt_media_type: None,
            actor_id: "purge-operator".to_string(),
            idempotency_key: "review-purge-untracked".to_string(),
            expected_mutation_epoch: page.captured_mutation_epoch,
            now: now + 10,
        })
        .await
        .unwrap();
    let repair = database
        .apply_oci_untracked_repair(&ApplyOciUntrackedRepair {
            plan_id: repair.id,
            actor_id: "purge-operator".to_string(),
            idempotency_key: "apply-purge-untracked".to_string(),
            confirmation_hash: repair.confirmation_hash,
            expected_resource_version: repair.resource_version,
            now: now + 11,
        })
        .await
        .unwrap();
    let claim = database
        .claim_oci_untracked_repair("purge-repair-worker", "purge-repair-claim", now + 12, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.repair.id, repair.id);
    let evidence_digest = oci_gc_deletion_evidence_digest(
        &repair.id,
        "purge-repair-response",
        OciGcDeleteOutcome::Deleted,
        Some("\"out-of-band\""),
        Some("provider-delete-request"),
        now + 13,
    )
    .unwrap();
    database
        .record_oci_untracked_repair_success(&RecordOciUntrackedRepairSuccess {
            plan_id: repair.id,
            claim_token: "purge-repair-claim".to_string(),
            response_idempotency_key: "purge-repair-response".to_string(),
            outcome: OciGcDeleteOutcome::Deleted,
            conditional_etag: Some("\"out-of-band\"".to_string()),
            provider_request_id: Some("provider-delete-request".to_string()),
            evidence_digest,
            confirmed_at: now + 13,
        })
        .await
        .unwrap();
    assert!(
        database
            .oci_registry_purge_blockers(registry_id, now + 13)
            .await
            .unwrap()
            .stale_or_missing_inventories
            > 0
    );
    seal_empty_inventory(
        &database,
        registry_id,
        &placement,
        "purge-empty-1",
        now + 14,
    )
    .await;
    assert_eq!(
        database
            .oci_registry_purge_blockers(registry_id, now + 16)
            .await
            .unwrap()
            .stale_or_missing_inventories,
        0
    );

    let failed = database
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id,
            placement_id: placement.id,
            expected_placement_resource_version: placement.resource_version,
            expected_placement_observation_version: placement.observation_version.unwrap(),
            collector_id: "purge-failed".to_string(),
            collector_claim_token: "purge-failed-claim".to_string(),
            collector_lease_seconds: 100,
            idempotency_key: "purge-failed-scan".to_string(),
            now: now + 17,
        })
        .await
        .unwrap();
    database
        .fail_oci_provider_inventory(
            &failed.id,
            "purge-failed",
            "purge-failed-claim",
            failed.resource_version,
            "provider enumeration failed",
            now + 18,
        )
        .await
        .unwrap();
    assert!(
        database
            .oci_registry_purge_blockers(registry_id, now + 18)
            .await
            .unwrap()
            .stale_or_missing_inventories
            > 0
    );
    seal_empty_inventory(
        &database,
        registry_id,
        &placement,
        "purge-empty-2",
        now + 19,
    )
    .await;
    assert!(!database
        .oci_registry_purge_blockers(registry_id, now + 21)
        .await
        .unwrap()
        .any());
    assert!(database
        .delete_registry_at_version(
            registry_id,
            registry.resource_version,
            "purge-complete",
            "user",
            None,
            "purge-operator",
        )
        .await
        .unwrap());
    assert!(database
        .registry_by_id(registry_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn clean_registry_lists_empty_untracked_inventory_at_epoch_zero() {
    let database = Database::open_in_memory().await.unwrap();
    let org_id = database
        .create_org("empty-untracked", "Empty")
        .await
        .unwrap();
    let registry_id = database
        .create_managed_registry(org_id, "", "empty-untracked", "public", &[], false)
        .await
        .unwrap();

    assert!(database
        .backend
        .query_opt(
            "SELECT 1 FROM oci_registry_state WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap()
        .is_none());
    let page = database
        .list_untracked_oci_provider_inventory(registry_id, None, 100)
        .await
        .unwrap();
    assert!(page.items.is_empty());
    assert!(page.next_cursor.is_none());
    assert_eq!(page.captured_mutation_epoch, 0);
}

#[tokio::test]
async fn bounded_candidate_frontier_and_expired_history_compaction_make_progress() {
    let database = Database::open_in_memory().await.unwrap();
    let (registry_id, placement) = seed_inventory_topology(&database).await;
    let repository = database
        .ensure_oci_repository(
            registry_id,
            &RepositoryName::parse("bounded-frontier").unwrap(),
            1,
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_retention_policies
               (registry_id, untagged_grace_seconds, tag_history_limit,
                deleted_tag_history_seconds, recent_manual_tag_revisions,
                retain_referrers, resource_version, updated_at)
             VALUES(?1, 0, 0, 0, 0, 0, 1, 1)",
            &vals![registry_id],
        )
        .await
        .unwrap();

    let mut digests = Vec::new();
    for ordinal in 0_i64..101 {
        let digest = Sha256Digest::digest(format!("frontier-object-{ordinal:03}").as_bytes());
        let object_id = 10_000 + ordinal;
        database
            .backend
            .execute(
                "INSERT INTO surface_objects
                   (id, registry_id, object_key, object_kind, partition_key,
                    content_hash, size, lifecycle_state, created_at, updated_at,
                    resource_version)
                 VALUES(?1, ?2, ?3, 'immutable', zeroblob(32), ?4, 1,
                        'active', 1, 1, 1)",
                &vals![
                    object_id,
                    registry_id,
                    crate::db::oci_blob_object_key(digest),
                    digest.encoded()
                ],
            )
            .await
            .unwrap();
        database
            .backend
            .execute(
                "INSERT INTO oci_blobs
                   (registry_id, digest, byte_size, media_type, surface_object_id,
                    quota_bytes, lifecycle_state, created_at, updated_at,
                    unreferenced_since)
                 VALUES(?1, ?2, 1, 'application/octet-stream', ?3, 1,
                        'active', 1, 1, 1)",
                &vals![registry_id, digest.to_string(), object_id],
            )
            .await
            .unwrap();
        digests.push((digest, 1_u64));
    }
    database
        .backend
        .execute(
            "WITH RECURSIVE sequence(value) AS (
               SELECT 1 UNION ALL SELECT value + 1 FROM sequence WHERE value < 2501
             )
             INSERT INTO oci_tag_history
               (id, repository_id, registry_id, name, prior_digest, next_digest,
                source_kind, actor_id, changed_at)
             SELECT printf('expired-history-%04d', value), ?1, ?2, 'old', ?3,
                    NULL, 'release', 'fixture', 1
             FROM sequence",
            &vals![repository.id, registry_id, digests[0].0.to_string()],
        )
        .await
        .unwrap();
    seal_inventory_for_digests(&database, registry_id, &placement, &digests, 9_999_990).await;

    let first = database
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "frontier-operator".to_string(),
            idempotency_key: "frontier-first".to_string(),
            expected_resource_version: 1,
            now: 10_000_000,
        })
        .await
        .unwrap();
    assert_eq!(
        (
            first.state.as_str(),
            first.planned_objects,
            first.placement_action_count
        ),
        ("planned", 100, 100),
        "one synchronous plan must persist a bounded reverse-topological frontier"
    );
    let selected = database
        .backend
        .query(
            "SELECT digest, surface_object_id FROM oci_gc_candidates
             WHERE run_id = ?1 ORDER BY digest",
            &vals![first.id],
        )
        .await
        .unwrap();
    assert_eq!(selected.len(), 100);
    for row in &selected {
        let digest: String = row.get(0).unwrap();
        let surface_object_id: i64 = row.get(1).unwrap();
        database
            .backend
            .execute(
                "DELETE FROM oci_blobs WHERE registry_id = ?1 AND digest = ?2",
                &vals![registry_id, digest],
            )
            .await
            .unwrap();
        database
            .backend
            .execute(
                "DELETE FROM surface_objects WHERE id = ?1 AND registry_id = ?2",
                &vals![surface_object_id, registry_id],
            )
            .await
            .unwrap();
    }

    let second = database
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "frontier-operator".to_string(),
            idempotency_key: "frontier-second".to_string(),
            expected_resource_version: 1,
            now: 10_000_001,
        })
        .await
        .unwrap();
    assert_eq!(
        (
            second.state.as_str(),
            second.planned_objects,
            second.placement_action_count
        ),
        ("planned", 1, 1),
        "later reviewed generations must advance beyond the first bounded frontier"
    );
}

#[tokio::test]
async fn grace_root_protects_forward_closure_and_apply_rejects_new_survivor_edge() {
    let database = Database::open_in_memory().await.unwrap();
    let (registry_id, placement) = seed_inventory_topology(&database).await;
    let repository = RepositoryName::parse("grace").unwrap();
    let repository = database
        .ensure_oci_repository(registry_id, &repository, 10)
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_retention_policies
               (registry_id, untagged_grace_seconds, tag_history_limit,
                deleted_tag_history_seconds, recent_manual_tag_revisions,
                retain_referrers, resource_version, updated_at)
             VALUES(?1, 100, 0, 0, 0, 0, 1, 10)",
            &vals![registry_id],
        )
        .await
        .unwrap();
    let grace_manifest = Sha256Digest::digest(b"grace-manifest");
    let old_manifest = Sha256Digest::digest(b"old-manifest");
    let config = Sha256Digest::digest(b"grace-config");
    let shared_layer = Sha256Digest::digest(b"shared-layer");
    let unrelated = Sha256Digest::digest(b"unrelated");
    let objects = [
        (401_i64, grace_manifest, 11_u64, 950_i64),
        (402, old_manifest, 12, 1),
        (403, config, 13, 1),
        (404, shared_layer, 14, 1),
        (405, unrelated, 15, 1),
    ];
    for (id, digest, size, unreferenced_since) in objects {
        database
            .backend
            .execute(
                "INSERT INTO surface_objects
                   (id, registry_id, object_key, object_kind, partition_key,
                    content_hash, size, lifecycle_state, created_at, updated_at,
                    resource_version)
                 VALUES(?1, ?2, ?3, 'immutable', zeroblob(32), ?4, ?5,
                        'active', 1, 1, 1)",
                &vals![
                    id,
                    registry_id,
                    crate::db::oci_blob_object_key(digest),
                    digest.encoded(),
                    i64::try_from(size).unwrap()
                ],
            )
            .await
            .unwrap();
        database
            .backend
            .execute(
                "INSERT INTO oci_blobs
                   (registry_id, digest, byte_size, media_type, surface_object_id,
                    quota_bytes, lifecycle_state, created_at, updated_at,
                    unreferenced_since)
                 VALUES(?1, ?2, ?3, 'application/octet-stream', ?4, ?3,
                        'active', 1, 1, ?5)",
                &vals![
                    registry_id,
                    digest.to_string(),
                    i64::try_from(size).unwrap(),
                    id,
                    unreferenced_since
                ],
            )
            .await
            .unwrap();
    }
    for (digest, size, descriptor_count) in [(grace_manifest, 11_i64, 2_i64), (old_manifest, 12, 1)]
    {
        database
            .backend
            .execute(
                "INSERT INTO oci_repository_objects
                   (repository_id, registry_id, digest, object_kind, media_type, linked_at)
                 VALUES(?1, ?2, ?3, 'manifest', 'application/test.manifest', 1)",
                &vals![repository.id, registry_id, digest.to_string()],
            )
            .await
            .unwrap();
        database
            .backend
            .execute(
                "INSERT INTO oci_manifests
                   (registry_id, digest, media_type, byte_size, schema_version,
                    artifact_type, annotations_json, descriptor_count, created_at)
                 VALUES(?1, ?2, 'application/test.manifest', ?3, 2,
                        'application/test.artifact', '{}', ?4, 1)",
                &vals![registry_id, digest.to_string(), size, descriptor_count],
            )
            .await
            .unwrap();
    }
    for (manifest, role, ordinal, target, size) in [
        (grace_manifest, "config", 0_i64, config, 13_i64),
        (grace_manifest, "layer", 0, shared_layer, 14),
        (old_manifest, "layer", 0, shared_layer, 14),
    ] {
        database
            .backend
            .execute(
                "INSERT INTO oci_descriptor_edges
                   (registry_id, manifest_digest, edge_role, ordinal,
                    target_digest, media_type, byte_size, annotations_json)
                 VALUES(?1, ?2, ?3, ?4, ?5, 'application/octet-stream', ?6, '{}')",
                &vals![
                    registry_id,
                    manifest.to_string(),
                    role,
                    ordinal,
                    target.to_string(),
                    size
                ],
            )
            .await
            .unwrap();
    }
    database
        .backend
        .execute(
            "UPDATE oci_registry_state SET charged_bytes = 65, charged_objects = 5
             WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap();
    seal_inventory_for_digests(
        &database,
        registry_id,
        &placement,
        &objects.map(|(_, digest, size, _)| (digest, size)),
        990,
    )
    .await;

    let plan = database
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "grace-operator".to_string(),
            idempotency_key: "grace-plan".to_string(),
            expected_resource_version: 1,
            now: 1_000,
        })
        .await
        .unwrap();
    let candidates = database
        .list_oci_gc_candidates(&plan.id, 100, None)
        .await
        .unwrap();
    let candidate_digests = candidates
        .items
        .iter()
        .map(|candidate| candidate.digest)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(candidate_digests.len(), 2);
    assert!(candidate_digests.contains(&old_manifest));
    assert!(candidate_digests.contains(&unrelated));
    assert!(!candidate_digests.contains(&config));
    assert!(!candidate_digests.contains(&shared_layer));

    database
        .backend
        .execute(
            "UPDATE oci_manifests SET descriptor_count = descriptor_count + 1
             WHERE registry_id = ?1 AND digest = ?2",
            &vals![registry_id, grace_manifest.to_string()],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_descriptor_edges
               (registry_id, manifest_digest, edge_role, ordinal,
                target_digest, media_type, byte_size, annotations_json)
             VALUES(?1, ?2, 'payload', 0, ?3,
                    'application/octet-stream', 15, '{}')",
            &vals![
                registry_id,
                grace_manifest.to_string(),
                unrelated.to_string()
            ],
        )
        .await
        .unwrap();
    assert!(database
        .apply_oci_gc(&ApplyOciGc {
            generation_id: plan.id,
            actor_id: "grace-operator".to_string(),
            idempotency_key: "grace-apply".to_string(),
            confirmation_hash: plan.confirmation_hash,
            now: 1_001,
        })
        .await
        .is_err());
    assert_eq!(
        database
            .backend
            .query_opt(
                "SELECT lifecycle_state FROM oci_blobs
                 WHERE registry_id = ?1 AND digest = ?2",
                &vals![registry_id, unrelated.to_string()],
            )
            .await
            .unwrap()
            .unwrap()
            .get::<String>(0)
            .unwrap(),
        "active"
    );
}

#[tokio::test]
async fn fresh_untag_and_retained_unlinked_history_protect_manifest_closure() {
    let database = Database::open_in_memory().await.unwrap();
    let (registry_id, placement) = seed_inventory_topology(&database).await;
    let repository_name = RepositoryName::parse("history-grace").unwrap();
    let repository = database
        .ensure_oci_repository(registry_id, &repository_name, 10)
        .await
        .unwrap();
    let manifest = Sha256Digest::digest(b"history-manifest");
    let payload = Sha256Digest::digest(b"history-payload");
    for (id, digest, size, unreferenced_since) in [
        (451_i64, manifest, 17_i64, None),
        (452, payload, 19, Some(1_i64)),
    ] {
        database
            .backend
            .execute(
                "INSERT INTO surface_objects
                   (id, registry_id, object_key, object_kind, partition_key,
                    content_hash, size, lifecycle_state, created_at, updated_at,
                    resource_version)
                 VALUES(?1, ?2, ?3, 'immutable', zeroblob(32), ?4, ?5,
                        'active', 1, 1, 1)",
                &vals![
                    id,
                    registry_id,
                    crate::db::oci_blob_object_key(digest),
                    digest.encoded(),
                    size
                ],
            )
            .await
            .unwrap();
        database
            .backend
            .execute(
                "INSERT INTO oci_blobs
                   (registry_id, digest, byte_size, media_type, surface_object_id,
                    quota_bytes, lifecycle_state, created_at, updated_at,
                    unreferenced_since)
                 VALUES(?1, ?2, ?3, 'application/octet-stream', ?4, ?3,
                        'active', 1, 1, ?5)",
                &vals![
                    registry_id,
                    digest.to_string(),
                    size,
                    id,
                    unreferenced_since
                ],
            )
            .await
            .unwrap();
    }
    database
        .backend
        .execute(
            "INSERT INTO oci_repository_objects
               (repository_id, registry_id, digest, object_kind, media_type, linked_at)
             VALUES(?1, ?2, ?3, 'manifest', 'application/test.manifest', 1)",
            &vals![repository.id, registry_id, manifest.to_string()],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_manifests
               (registry_id, digest, media_type, byte_size, schema_version,
                artifact_type, annotations_json, descriptor_count, created_at)
             VALUES(?1, ?2, 'application/test.manifest', 17, 2,
                    'application/test.artifact', '{}', 1, 1)",
            &vals![registry_id, manifest.to_string()],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_descriptor_edges
               (registry_id, manifest_digest, edge_role, ordinal,
                target_digest, media_type, byte_size, annotations_json)
             VALUES(?1, ?2, 'payload', 0, ?3,
                    'application/octet-stream', 19, '{}')",
            &vals![registry_id, manifest.to_string(), payload.to_string()],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_tags
               (repository_id, registry_id, name, digest, source_kind,
                resource_version, updated_at, created_at)
             VALUES(?1, ?2, 'latest', ?3, 'manual', 1, 10, 10)",
            &vals![repository.id, registry_id, manifest.to_string()],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_retention_policies
               (registry_id, untagged_grace_seconds, tag_history_limit,
                deleted_tag_history_seconds, recent_manual_tag_revisions,
                retain_referrers, resource_version, updated_at)
             VALUES(?1, 10, 0, 100, 0, 0, 1, 10)",
            &vals![registry_id],
        )
        .await
        .unwrap();
    database
        .delete_oci_manual_tag(
            repository.id,
            &Tag::parse("latest").unwrap(),
            1,
            "operator",
            100,
        )
        .await
        .unwrap();
    database
        .delete_oci_repository_manifest(repository.id, manifest, 101)
        .await
        .unwrap();
    assert_eq!(
        database
            .backend
            .query_opt(
                "SELECT unreferenced_since FROM oci_blobs
                 WHERE registry_id = ?1 AND digest = ?2",
                &vals![registry_id, manifest.to_string()],
            )
            .await
            .unwrap()
            .unwrap()
            .get::<Option<i64>>(0)
            .unwrap(),
        Some(101)
    );
    database
        .backend
        .execute(
            "UPDATE oci_registry_state SET charged_bytes = 36, charged_objects = 2
             WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap();
    seal_inventory_for_digests(
        &database,
        registry_id,
        &placement,
        &[(manifest, 17), (payload, 19)],
        102,
    )
    .await;
    let retained = database
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "operator".to_string(),
            idempotency_key: "history-retained".to_string(),
            expected_resource_version: 1,
            now: 105,
        })
        .await
        .unwrap();
    assert_eq!(retained.planned_objects, 0);

    database
        .backend
        .execute(
            "UPDATE oci_retention_policies
             SET deleted_tag_history_seconds = 0, resource_version = 2, updated_at = 106
             WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap();
    let grace = database
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "operator".to_string(),
            idempotency_key: "history-expired-still-grace".to_string(),
            expected_resource_version: 2,
            now: 109,
        })
        .await
        .unwrap();
    assert_eq!(grace.planned_objects, 0);
    let eligible = database
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "operator".to_string(),
            idempotency_key: "history-expired-after-grace".to_string(),
            expected_resource_version: 2,
            now: 112,
        })
        .await
        .unwrap();
    assert_eq!((eligible.planned_objects, eligible.planned_bytes), (1, 17));
    assert_eq!(
        database
            .list_oci_gc_candidates(&eligible.id, 100, None)
            .await
            .unwrap()
            .items
            .iter()
            .map(|candidate| candidate.digest)
            .collect::<Vec<_>>(),
        vec![manifest],
        "the active manifest edge must protect its payload until the source is retired"
    );
    database
        .backend
        .execute(
            "DELETE FROM oci_blobs WHERE registry_id = ?1 AND digest = ?2",
            &vals![registry_id, manifest.to_string()],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "DELETE FROM surface_objects WHERE id = 451 AND registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap();
    let payload_frontier = database
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "operator".to_string(),
            idempotency_key: "history-expired-payload-frontier".to_string(),
            expected_resource_version: 2,
            now: 113,
        })
        .await
        .unwrap();
    assert_eq!(
        (
            payload_frontier.planned_objects,
            payload_frontier.planned_bytes
        ),
        (1, 19)
    );
}

#[tokio::test]
async fn gc_lock_fences_every_upload_phase_and_publication_add_commit() {
    let database = Database::open_in_memory().await.unwrap();
    let (registry_id, placement) = seed_inventory_topology(&database).await;
    let repository_name = RepositoryName::parse("producer-races").unwrap();
    let repository = database
        .ensure_oci_repository(registry_id, &repository_name, 10)
        .await
        .unwrap();
    seed_run_for_registry(&database, registry_id, "producer-fence", "applying", 10_000).await;

    let bytes = b"x";
    let digest = Sha256Digest::digest(bytes);
    let upload = database
        .begin_oci_upload(&BeginOciUpload {
            registry_id,
            repository_id: repository.id,
            publication_id: None,
            writer_id: "upload-writer".to_string(),
            token_id: "upload-token".to_string(),
            idempotency_key: "upload-before-lock".to_string(),
            expected_digest: Some(digest),
            expected_size: Some(1),
            maximum_size: 1,
            now: 20,
            expires_at: 500,
        })
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_registry_locks(registry_id, run_id, acquired_at)
             VALUES(?1, 'producer-fence', 21)",
            &vals![registry_id],
        )
        .await
        .unwrap();
    assert!(database
        .begin_oci_upload(&BeginOciUpload {
            idempotency_key: "begin-during-gc".to_string(),
            now: 21,
            expires_at: 501,
            ..BeginOciUpload {
                registry_id,
                repository_id: repository.id,
                publication_id: None,
                writer_id: "upload-writer".to_string(),
                token_id: "upload-token".to_string(),
                idempotency_key: String::new(),
                expected_digest: Some(digest),
                expected_size: Some(1),
                maximum_size: 1,
                now: 0,
                expires_at: 0,
            }
        })
        .await
        .is_err());
    let mut sha = OciSha256State::initial();
    sha.update(bytes).unwrap();
    let append = AppendOciUploadChunk {
        upload_id: upload.id.clone(),
        writer_id: "upload-writer".to_string(),
        token_id: "upload-token".to_string(),
        expected_resource_version: upload.resource_version,
        staging_placement_id: placement.id,
        staging_placement_resource_version: placement.resource_version,
        staging_binding_id: placement.binding_id,
        staging_binding_write_revision: database
            .binding_write_state(placement.binding_id)
            .await
            .unwrap()
            .unwrap()
            .current_write_revision
            .unwrap(),
        chunk: OciUploadChunkRecord {
            ordinal: 0,
            byte_offset: 0,
            byte_size: 1,
            digest,
            staging_object_key: "oci/staging/upload/chunk-0".to_string(),
            created_at: 21,
        },
        next_sha256: sha.clone(),
        now: 21,
    };
    assert!(database.append_oci_upload_chunk(&append).await.is_err());
    assert!(database
        .record_oci_uploaded_object(registry_id, placement.id, digest, 1, "\"upload-etag\"", 21,)
        .await
        .is_err());
    database
        .backend
        .execute(
            "DELETE FROM oci_gc_registry_locks WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap();
    let upload = database.append_oci_upload_chunk(&append).await.unwrap();
    let claim = ClaimOciUpload {
        upload_id: upload.id.clone(),
        writer_id: "upload-writer".to_string(),
        token_id: "upload-token".to_string(),
        expected_resource_version: upload.resource_version,
        materialization_placement_id: placement.id,
        materialization_placement_resource_version: placement.resource_version,
        materialization_binding_id: placement.binding_id,
        materialization_binding_write_revision: append.staging_binding_write_revision,
        digest,
        now: 22,
        lease_expires_at: 500,
    };
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_registry_locks(registry_id, run_id, acquired_at)
             VALUES(?1, 'producer-fence', 22)",
            &vals![registry_id],
        )
        .await
        .unwrap();
    assert!(database.claim_oci_upload(&claim).await.is_err());
    database
        .backend
        .execute(
            "DELETE FROM oci_gc_registry_locks WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap();
    assert_eq!(
        database.claim_oci_upload(&claim).await.unwrap(),
        OciBlobClaimOutcome::Claimed
    );
    let completing = database
        .oci_upload(&upload.id, "upload-writer", "upload-token", 23)
        .await
        .unwrap()
        .unwrap();
    let evidence = database
        .record_oci_uploaded_object(registry_id, placement.id, digest, 1, "\"upload-etag\"", 23)
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_registry_locks(registry_id, run_id, acquired_at)
             VALUES(?1, 'producer-fence', 24)",
            &vals![registry_id],
        )
        .await
        .unwrap();
    assert!(database
        .complete_oci_upload(&CompleteOciUpload {
            upload_id: upload.id,
            writer_id: "upload-writer".to_string(),
            token_id: "upload-token".to_string(),
            expected_resource_version: completing.resource_version,
            digest,
            byte_size: 1,
            surface_object_id: evidence.surface_object_id,
            placement_id: placement.id,
            now: 24,
        })
        .await
        .is_err());

    let layer = descriptor(MediaType::OciLayerGzip, b"publication-layer");
    let config = descriptor(MediaType::OciImageConfig, b"{}");
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: Some(MediaType::OciImageManifest),
        artifact_type: None,
        config: config.clone(),
        layers: vec![layer.clone()],
        subject: None,
        annotations: Annotations::new(),
    };
    let manifest_bytes = aos_oci_types::to_canonical_json(&manifest).unwrap();
    let manifest_descriptor = descriptor(MediaType::OciImageManifest, &manifest_bytes);
    let objects = vec![
        OciCatalogObject {
            descriptor: manifest_descriptor.clone(),
            projection: Some(OciCatalogProjection::Manifest {
                document: manifest.clone(),
                platform: None,
                image_config: None,
            }),
        },
        OciCatalogObject {
            descriptor: config.clone(),
            projection: None,
        },
        OciCatalogObject {
            descriptor: layer.clone(),
            projection: None,
        },
    ];
    let catalog_digest =
        oci_catalog_declaration_digest(manifest_descriptor.digest, &objects).unwrap();
    let write_revision = database
        .binding_write_state(placement.binding_id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    let revision = database
        .binding_write_revision(placement.binding_id, write_revision)
        .await
        .unwrap()
        .unwrap();
    let required = OciPublicationRequiredPlacement {
        placement_id: placement.id,
        placement_resource_version: placement.resource_version,
        placement_write_spec_version: placement.write_spec_version,
        placement_observation_version: placement.observation_version.unwrap(),
        binding_id: placement.binding_id,
        binding_write_revision: write_revision,
        revision_fingerprint: revision.revision_fingerprint,
        capability_fingerprint: revision.capability_fingerprint,
    };
    assert!(database
        .begin_oci_publication(&BeginOciPublication {
            registry_id,
            repository_id: repository.id,
            writer_id: "publication-writer".to_string(),
            token_id: "publication-token".to_string(),
            target_tag: None,
            expected_tag_version: None,
            expected_tag_digest: None,
            root_digest: manifest_descriptor.digest,
            catalog_digest,
            release_tag: None,
            sidecar_sha256_hex: None,
            required_placements: vec![required.clone()],
            source_kind: "manual".to_string(),
            idempotency_key: "publication-during-gc".to_string(),
            now: 25,
            expires_at: 500,
        })
        .await
        .is_err());
    database
        .backend
        .execute(
            "DELETE FROM oci_gc_registry_locks WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap();
    let mut publication = database
        .begin_oci_publication(&BeginOciPublication {
            registry_id,
            repository_id: repository.id,
            writer_id: "publication-writer".to_string(),
            token_id: "publication-token".to_string(),
            target_tag: None,
            expected_tag_version: None,
            expected_tag_digest: None,
            root_digest: manifest_descriptor.digest,
            catalog_digest,
            release_tag: None,
            sidecar_sha256_hex: None,
            required_placements: vec![required],
            source_kind: "manual".to_string(),
            idempotency_key: "publication-before-gc".to_string(),
            now: 26,
            expires_at: 500,
        })
        .await
        .unwrap();
    let mut frozen = Vec::new();
    for object in &objects {
        let observed = database
            .record_oci_uploaded_object(
                registry_id,
                placement.id,
                object.descriptor.digest,
                object.descriptor.size,
                &format!("\"{}\"", object.descriptor.digest.encoded()),
                27,
            )
            .await
            .unwrap();
        frozen.push((object.clone(), observed));
    }
    let first = &frozen[0];
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_registry_locks(registry_id, run_id, acquired_at)
             VALUES(?1, 'producer-fence', 28)",
            &vals![registry_id],
        )
        .await
        .unwrap();
    assert!(database
        .add_oci_publication_object(
            &AddOciPublicationObject {
                publication_id: publication.id.clone(),
                writer_id: "publication-writer".to_string(),
                token_id: "publication-token".to_string(),
                expected_resource_version: publication.resource_version,
                descriptor: first.0.descriptor.clone(),
                object_kind: "manifest".to_string(),
                object_key: crate::db::oci_blob_object_key(first.0.descriptor.digest),
                projection_json: Some(
                    serde_json::to_string(&serde_json::json!({
                        "document": manifest,
                        "platform": null
                    }))
                    .unwrap(),
                ),
                surface_object_id: first.1.surface_object_id,
                placement_id: placement.id,
                object_resource_version: first.1.object_resource_version,
                placement_resource_version: first.1.placement_resource_version,
                placement_observation_version: first.1.placement_observation_version,
                observed_inventory_generation: first.1.observed_inventory_generation,
                observed_etag: first.1.observed_etag.clone(),
                observed_at: first.1.observed_at,
            },
            28
        )
        .await
        .is_err());
    database
        .backend
        .execute(
            "DELETE FROM oci_gc_registry_locks WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap();
    for (object, observed) in frozen {
        let is_manifest = object.descriptor.media_type == MediaType::OciImageManifest;
        let object_digest = object.descriptor.digest;
        publication = database
            .add_oci_publication_object(
                &AddOciPublicationObject {
                    publication_id: publication.id.clone(),
                    writer_id: "publication-writer".to_string(),
                    token_id: "publication-token".to_string(),
                    expected_resource_version: publication.resource_version,
                    descriptor: object.descriptor,
                    object_kind: if is_manifest { "manifest" } else { "blob" }.to_string(),
                    object_key: crate::db::oci_blob_object_key(object_digest),
                    projection_json: is_manifest.then(|| {
                        serde_json::to_string(&serde_json::json!({
                            "document": manifest,
                            "platform": null
                        }))
                        .unwrap()
                    }),
                    surface_object_id: observed.surface_object_id,
                    placement_id: placement.id,
                    object_resource_version: observed.object_resource_version,
                    placement_resource_version: observed.placement_resource_version,
                    placement_observation_version: observed.placement_observation_version,
                    observed_inventory_generation: observed.observed_inventory_generation,
                    observed_etag: observed.observed_etag,
                    observed_at: observed.observed_at,
                },
                29,
            )
            .await
            .unwrap();
    }
    let catalog = IndexOciRepositoryCatalog {
        registry_id,
        placement_id: placement.id,
        repository: repository_name,
        objects,
        root_digest: manifest_descriptor.digest,
        tag: None,
        source_kind: "manual".to_string(),
        actor_id: "publication-writer".to_string(),
        observed_at: 30,
    };
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_registry_locks(registry_id, run_id, acquired_at)
             VALUES(?1, 'producer-fence', 30)",
            &vals![registry_id],
        )
        .await
        .unwrap();
    assert!(database
        .commit_oci_publication(
            &publication.id,
            "publication-writer",
            "publication-token",
            publication.resource_version,
            "publication-commit",
            publication.confirmation_hash,
            &catalog,
            30,
        )
        .await
        .is_err());
}

#[tokio::test]
async fn fresh_v24_migration_and_expired_plan_recovery_execute_on_sqlite() {
    let database = Database::open_in_memory().await.unwrap();
    seed_registry(&database).await;
    seed_run(&database, "expired", "planned", 2).await;

    assert_eq!(database.abort_expired_oci_gc_plans(3, 10).await.unwrap(), 1);
    let run = database
        .oci_gc_generation(1, "expired")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.state, "aborted");
    assert_eq!(run.finished_at, Some(3));
}

#[tokio::test]
async fn applying_registry_lock_blocks_first_push_repository_admission() {
    let database = Database::open_in_memory().await.unwrap();
    seed_registry(&database).await;
    seed_run(&database, "applying", "applying", 100).await;
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_registry_locks(registry_id, run_id, acquired_at)
             VALUES(1, 'applying', 2)",
            &[],
        )
        .await
        .unwrap();

    let repository = RepositoryName::parse("blocked").unwrap();
    let error = database
        .ensure_oci_repository(1, &repository, 3)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("checked batch"), "{error:#}");
    assert!(database
        .oci_repository(1, &repository)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn snapshot_lease_acquisition_cannot_race_an_applying_candidate() {
    let database = Database::open_in_memory().await.unwrap();
    let (registry_id, placement) = seed_inventory_topology(&database).await;
    seed_run_for_registry(
        &database,
        registry_id,
        "snapshot-race",
        "applying",
        i64::MAX,
    )
    .await;
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_registry_locks(registry_id, run_id, acquired_at)
             VALUES(?1, 'snapshot-race', 2)",
            &vals![registry_id],
        )
        .await
        .unwrap();

    let digest = Sha256Digest::digest(b"snapshot-race");
    let snapshot_digest = digest.encoded();
    let object_key = crate::db::oci_blob_object_key(digest);
    database
        .backend
        .execute(
            "INSERT INTO image_snapshots(digest, byte_size, state, created_at)
             VALUES(?1, 13, 'live', 1)",
            &vals![snapshot_digest],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO image_snapshot_references
               (digest, registry_id, placement_id, object_key)
             VALUES(?1, ?2, ?3, ?4)",
            &vals![snapshot_digest, registry_id, placement.id, object_key],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_candidates
               (run_id, registry_id, digest, media_type, byte_size, object_key,
                surface_object_id, catalog_object_resource_version,
                repository_count, eligible_at, state, resource_version)
             VALUES('snapshot-race', ?1, ?2, 'application/octet-stream', 13,
                    ?3, 1, 1, 0, 1, 'deleting', 1)",
            &vals![registry_id, digest.to_string(), object_key],
        )
        .await
        .unwrap();

    assert!(database
        .lease_image_snapshot(
            "late-reader",
            &snapshot_digest,
            13,
            crate::db::unix_now() + 60,
        )
        .await
        .is_err());
    assert!(database
        .backend
        .query_opt(
            "SELECT 1 FROM image_snapshot_leases WHERE lease_id = 'late-reader'",
            &[],
        )
        .await
        .unwrap()
        .is_none());

    database
        .backend
        .execute(
            "UPDATE oci_gc_candidates SET state = 'complete'
             WHERE run_id = 'snapshot-race' AND digest = ?1",
            &vals![digest.to_string()],
        )
        .await
        .unwrap();
    database
        .lease_image_snapshot(
            "after-terminal",
            &snapshot_digest,
            13,
            crate::db::unix_now() + 60,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn v23_concurrent_start_from_v22_applies_once_and_reopens() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("v22-to-v23.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    for migration in &MIGRATIONS[..22] {
        connection.execute_batch(migration).unwrap();
    }
    connection
        .execute_batch(
            "CREATE TABLE schema_version(version INTEGER NOT NULL);
             INSERT INTO schema_version(version) VALUES(22);",
        )
        .unwrap();
    drop(connection);

    let (left, right) = tokio::join!(Database::open(&path), Database::open(&path));
    drop(left.unwrap());
    drop(right.unwrap());
    let reopened = Database::open(&path).await.unwrap();
    let version: i64 = reopened
        .backend
        .query_opt("SELECT version FROM schema_version", &[])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(version, 24);
}

#[tokio::test]
async fn applying_run_reports_planned_partial_and_atomic_final_counters() {
    let database = Database::open_in_memory().await.unwrap();
    seed_registry(&database).await;
    seed_run(&database, "finalize", "applying", 100).await;
    database
        .backend
        .execute(
            "UPDATE oci_gc_runs SET planned_objects = 2, planned_bytes = 7
             WHERE id = 'finalize'",
            &[],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "UPDATE oci_registry_state SET charged_objects = 2, charged_bytes = 7
             WHERE registry_id = 1",
            &[],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_registry_locks(registry_id, run_id, acquired_at)
             VALUES(1, 'finalize', 2)",
            &[],
        )
        .await
        .unwrap();

    for (ordinal, bytes, state) in [
        (10_i64, b"one".as_slice(), "physically_absent"),
        (11, b"four".as_slice(), "deleting"),
    ] {
        let digest = Sha256Digest::digest(bytes);
        database
            .backend
            .execute(
                "INSERT INTO surface_objects
                   (id, registry_id, object_key, object_kind, partition_key,
                    content_hash, size, lifecycle_state, tombstoned_at,
                    created_at, updated_at, resource_version)
                 VALUES(?1, 1, ?2, 'immutable', zeroblob(32), ?3, ?4,
                        'tombstoned', 2, 1, 2, 1)",
                &vals![
                    ordinal,
                    crate::db::oci_blob_object_key(digest),
                    digest.encoded(),
                    i64::try_from(bytes.len()).unwrap()
                ],
            )
            .await
            .unwrap();
        database
            .backend
            .execute(
                "INSERT INTO oci_blobs
                   (registry_id, digest, byte_size, media_type, surface_object_id,
                    quota_bytes, lifecycle_state, created_at, updated_at)
                 VALUES(1, ?1, ?2, 'application/octet-stream', ?3, ?2,
                        'deleting', 1, 2)",
                &vals![
                    digest.to_string(),
                    i64::try_from(bytes.len()).unwrap(),
                    ordinal
                ],
            )
            .await
            .unwrap();
        database
            .backend
            .execute(
                "INSERT INTO oci_gc_candidates
                   (run_id, registry_id, digest, media_type, byte_size, object_key,
                    surface_object_id, catalog_object_resource_version,
                    repository_count, eligible_at, state, finalized_at,
                    last_error, resource_version)
                 VALUES('finalize', 1, ?1, 'application/octet-stream', ?2, ?3,
                        ?4, 1, 0, 1, ?5, NULL, NULL, 1)",
                &vals![
                    digest.to_string(),
                    i64::try_from(bytes.len()).unwrap(),
                    crate::db::oci_blob_object_key(digest),
                    ordinal,
                    state
                ],
            )
            .await
            .unwrap();
    }

    let planned = database
        .oci_gc_generation(1, "finalize")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((planned.planned_objects, planned.planned_bytes), (2, 7));
    assert_eq!(
        (planned.deleted_object_count, planned.deleted_byte_size),
        (0, 0)
    );

    let second = Sha256Digest::digest(b"four");
    database
        .finalize_oci_gc_candidate("finalize", second, 3)
        .await
        .unwrap();
    let partial = database
        .oci_gc_generation(1, "finalize")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (partial.deleted_object_count, partial.deleted_byte_size),
        (0, 0)
    );

    let complete = database
        .finalize_oci_gc_generation("finalize", 4)
        .await
        .unwrap();
    assert_eq!(complete.state, "complete");
    assert_eq!(
        (complete.deleted_object_count, complete.deleted_byte_size),
        (2, 7)
    );
    assert_eq!(
        database
            .finalize_oci_gc_generation("finalize", 5)
            .await
            .unwrap(),
        complete,
        "response-loss replay changed completed history"
    );
}

#[tokio::test]
async fn finalization_sweep_skips_a_drifted_earlier_run_and_completes_later_work() {
    let database = Database::open_in_memory().await.unwrap();
    let (first_registry_id, _) = seed_inventory_topology(&database).await;
    let org_id: i64 = database
        .backend
        .query_opt(
            "SELECT org_id FROM registries WHERE id = ?1",
            &vals![first_registry_id],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    let second_registry_id = database
        .create_managed_registry(org_id, "", "finalize-later", "public", &[], false)
        .await
        .unwrap();
    for registry_id in [first_registry_id, second_registry_id] {
        database
            .backend
            .execute(
                "INSERT INTO oci_registry_state
                   (registry_id, mutation_epoch, charged_bytes,
                    charged_objects, updated_at)
                 VALUES(?1, 0, 0, 0, 1)
                 ON CONFLICT(registry_id) DO NOTHING",
                &vals![registry_id],
            )
            .await
            .unwrap();
    }
    database
        .backend
        .execute(
            "INSERT INTO org_usage(org_id, used_bytes, object_count, updated_at)
             VALUES(?1, 0, 0, 1) ON CONFLICT(org_id) DO NOTHING",
            &vals![org_id],
        )
        .await
        .unwrap();
    seed_run_for_registry(&database, first_registry_id, "a-drifted", "applying", 100).await;
    seed_run_for_registry(&database, second_registry_id, "z-ready", "applying", 100).await;
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_registry_locks(registry_id, run_id, acquired_at)
             VALUES(?1, 'a-drifted', 2), (?2, 'z-ready', 2)",
            &vals![first_registry_id, second_registry_id],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "UPDATE oci_registry_state SET mutation_epoch = 1
             WHERE registry_id = ?1",
            &vals![first_registry_id],
        )
        .await
        .unwrap();

    let sweep = database.finalize_ready_oci_gc(3, 10).await.unwrap();
    assert_eq!(sweep.finalized_candidates, 0);
    assert_eq!(sweep.finalized_generations, 1);
    assert_eq!(
        database
            .oci_gc_generation(first_registry_id, "a-drifted")
            .await
            .unwrap()
            .unwrap()
            .state,
        "applying"
    );
    assert_eq!(
        database
            .oci_gc_generation(second_registry_id, "z-ready")
            .await
            .unwrap()
            .unwrap()
            .state,
        "complete"
    );
}

#[tokio::test]
async fn maintenance_requeue_is_actor_request_and_response_loss_idempotent() {
    let database = Database::open_in_memory().await.unwrap();
    seed_registry(&database).await;
    seed_run(&database, "requeue", "applying", 100).await;
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_registry_locks(registry_id, run_id, acquired_at)
             VALUES(1, 'requeue', 2)",
            &[],
        )
        .await
        .unwrap();
    let digest = Sha256Digest::digest(b"requeue-object");
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_candidates
               (run_id, registry_id, digest, media_type, byte_size, object_key,
                surface_object_id, catalog_object_resource_version,
                repository_count, eligible_at, state, resource_version)
             VALUES('requeue', 1, ?1, 'application/octet-stream', 1, ?2,
                    1, 1, 0, 1, 'deleting', 1)",
            &vals![digest.to_string(), crate::db::oci_blob_object_key(digest)],
        )
        .await
        .unwrap();
    let identity = Sha256Digest::digest(b"inventory").to_string();
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_placement_snapshots
               (run_id, registry_id, placement_id, placement_name,
                placement_prefix, placement_resource_version,
                placement_write_spec_version, placement_observation_version,
                binding_id, binding_resource_version, binding_write_revision,
                delete_credential_purpose, delete_credential_generation,
                delete_capability_fingerprint,
                delete_capability_resource_version,
                delete_capability_observed_at, inventory_generation_id,
                inventory_digest, inventory_observed_at)
             VALUES('requeue', 1, 9, 'primary', 'prefix', 2, 3, 4,
                    5, 6, 7, NULL, NULL, 'local-if-match', 8, 1,
                    'inventory', ?1, 1)",
            &vals![identity],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_gc_placement_actions
               (id, run_id, registry_id, digest, placement_id, object_key,
                expected_hash, expected_size, expected_strong_etag,
                inventory_generation_id, inventory_entry_present, state,
                attempt_count, max_attempts, next_attempt_at, last_error,
                resource_version)
             VALUES('action', 'requeue', 1, ?1, 9, ?2, ?3, 1, '\"etag\"',
                    'inventory', 1, 'failed', 8, 8, 2, 'exhausted', 1)",
            &vals![
                digest.to_string(),
                crate::db::oci_blob_object_key(digest),
                digest.to_string()
            ],
        )
        .await
        .unwrap();

    let request = RequeueOciGcPlacementAction {
        action_id: "action".to_string(),
        actor_id: "operator".to_string(),
        idempotency_key: "repair-1".to_string(),
        expected_resource_version: 1,
        now: 3,
    };
    let pending = database
        .requeue_oci_gc_placement_action(&request)
        .await
        .unwrap();
    assert_eq!(
        (pending.state.as_str(), pending.resource_version),
        ("pending", 2)
    );
    assert_eq!(
        database
            .requeue_oci_gc_placement_action(&request)
            .await
            .unwrap(),
        pending
    );

    database
        .backend
        .execute(
            "UPDATE oci_gc_placement_actions
             SET state = 'claimed', worker_id = 'worker', claim_token = 'claim',
                 lease_expires_at = 20, attempt_count = 1,
                 resource_version = resource_version + 1
             WHERE id = 'action' AND state = 'pending'",
            &[],
        )
        .await
        .unwrap();
    let advanced_replay = database
        .requeue_oci_gc_placement_action(&request)
        .await
        .unwrap();
    assert_eq!(
        (
            advanced_replay.state.as_str(),
            advanced_replay.resource_version
        ),
        ("claimed", 3)
    );

    for conflicting in [
        RequeueOciGcPlacementAction {
            idempotency_key: "repair-2".to_string(),
            expected_resource_version: 3,
            ..request.clone()
        },
        RequeueOciGcPlacementAction {
            actor_id: "other-operator".to_string(),
            expected_resource_version: 3,
            ..request.clone()
        },
        RequeueOciGcPlacementAction {
            expected_resource_version: 999,
            ..request.clone()
        },
    ] {
        assert!(database
            .requeue_oci_gc_placement_action(&conflicting)
            .await
            .is_err());
    }
    assert_eq!(
        database
            .oci_gc_placement_action("action")
            .await
            .unwrap()
            .unwrap(),
        advanced_replay
    );
    assert_eq!(
        database
            .oci_operations_metrics(4)
            .await
            .unwrap()
            .gc_requeue_count,
        1
    );
}

#[tokio::test]
async fn provider_inventory_checkpoints_survive_takeover_and_seal_tracked_and_untracked() {
    let database = Database::open_in_memory().await.unwrap();
    let (registry_id, placement) = seed_inventory_topology(&database).await;
    assert_eq!(
        database
            .list_due_oci_conditional_delete_placements(1, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    let binding = database
        .binding(placement.binding_id)
        .await
        .unwrap()
        .unwrap();
    let write_revision = database
        .binding_write_state(placement.binding_id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    assert!(database
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            binding_id: placement.binding_id,
            binding_write_revision: write_revision,
            binding_resource_version: binding.resource_version,
            delete_credential_purpose: None,
            delete_credential_generation: None,
            capability_fingerprint: "credentialless-external-delete".to_string(),
            state: "valid".to_string(),
            expected_resource_version: None,
            observed_at: 1,
        })
        .await
        .is_err());
    let invalid_capability = database
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            binding_id: placement.binding_id,
            binding_write_revision: write_revision,
            binding_resource_version: binding.resource_version,
            delete_credential_purpose: None,
            delete_credential_generation: None,
            capability_fingerprint: "conditional-delete-v1".to_string(),
            state: "invalid".to_string(),
            expected_resource_version: None,
            observed_at: 1,
        })
        .await
        .unwrap();
    assert!(database
        .list_due_oci_conditional_delete_placements(2, 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        database
            .list_due_oci_conditional_delete_placements(1_000, 1)
            .await
            .unwrap()
            .len(),
        1
    );
    let delete_credential = database
        .set_binding_credential_revision(
            placement.binding_id,
            "delete",
            "secret://oci-gc/delete-due/v1",
            0,
            &"3".repeat(64),
            "test",
        )
        .await
        .unwrap();
    let stale_delete_credential = database
        .validate_binding_credential_revision(
            placement.binding_id,
            "delete",
            delete_credential.generation,
            "valid",
            None,
            delete_credential.head_resource_version,
        )
        .await
        .unwrap();
    let delete_credential = database
        .set_binding_credential_revision(
            placement.binding_id,
            "delete",
            "secret://oci-gc/delete/v2",
            stale_delete_credential.generation,
            &"4".repeat(64),
            "test",
        )
        .await
        .unwrap();
    let delete_credential = database
        .validate_binding_credential_revision(
            placement.binding_id,
            "delete",
            delete_credential.generation,
            "valid",
            None,
            delete_credential.head_resource_version,
        )
        .await
        .unwrap();
    assert!(database
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            binding_id: placement.binding_id,
            binding_write_revision: write_revision,
            binding_resource_version: binding.resource_version,
            delete_credential_purpose: Some("delete".to_string()),
            delete_credential_generation: Some(stale_delete_credential.generation),
            capability_fingerprint: "conditional-delete-stale".to_string(),
            state: "valid".to_string(),
            expected_resource_version: None,
            observed_at: 999_992,
        })
        .await
        .is_err());
    database
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            state: "valid".to_string(),
            expected_resource_version: Some(invalid_capability.resource_version),
            observed_at: 1_000,
            ..RecordOciConditionalDeleteCapability {
                binding_id: placement.binding_id,
                binding_write_revision: write_revision,
                binding_resource_version: binding.resource_version,
                delete_credential_purpose: Some("delete".to_string()),
                delete_credential_generation: Some(delete_credential.generation),
                capability_fingerprint: "conditional-delete-v1".to_string(),
                state: "invalid".to_string(),
                expected_resource_version: None,
                observed_at: 1,
            }
        })
        .await
        .unwrap();
    assert!(database
        .list_due_oci_conditional_delete_placements(1_001, 10)
        .await
        .unwrap()
        .is_empty());
    let tracked = Sha256Digest::digest(b"tracked");
    database
        .backend
        .execute(
            "INSERT INTO surface_objects
               (id, registry_id, object_key, object_kind, partition_key,
                content_hash, size, lifecycle_state, created_at, updated_at,
                resource_version)
             VALUES(101, ?1, ?2, 'immutable', zeroblob(32), ?3, 7,
                    'active', 1, 1, 1)",
            &vals![
                registry_id,
                crate::db::oci_blob_object_key(tracked),
                tracked.encoded()
            ],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_blobs
               (registry_id, digest, byte_size, media_type, surface_object_id,
                quota_bytes, lifecycle_state, created_at, updated_at)
             VALUES(?1, ?2, 7, 'application/octet-stream', 101, 7,
                    'active', 1, 1)",
            &vals![registry_id, tracked.to_string()],
        )
        .await
        .unwrap();

    let generation = database
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id,
            placement_id: placement.id,
            expected_placement_resource_version: placement.resource_version,
            expected_placement_observation_version: placement.observation_version.unwrap(),
            collector_id: "collector-a".to_string(),
            collector_claim_token: "claim-a".to_string(),
            collector_lease_seconds: 2,
            idempotency_key: "scan-1".to_string(),
            now: 1,
        })
        .await
        .unwrap();
    let first_page = AppendOciProviderInventoryPage {
        generation_id: generation.id.clone(),
        collector_id: "collector-a".to_string(),
        collector_claim_token: "claim-a".to_string(),
        expected_checkpoint_ordinal: 0,
        expected_provider_cursor: None,
        next_provider_cursor: Some("cursor-1".to_string()),
        last_listed_key: Some("non-oci-prefix".to_string()),
        entries: Vec::new(),
        now: 2,
        lease_seconds: 1,
    };
    let checkpoint = database
        .append_oci_provider_inventory_page(&first_page)
        .await
        .unwrap();
    assert_eq!(
        (
            checkpoint.checkpoint_ordinal,
            checkpoint.provider_cursor.as_deref()
        ),
        (1, Some("cursor-1"))
    );
    assert!(database
        .list_recoverable_oci_provider_inventories(2, 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        database
            .list_recoverable_oci_provider_inventories(3, 10)
            .await
            .unwrap()
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        vec![generation.id.as_str()]
    );
    let takeover = database
        .claim_oci_provider_inventory(&generation.id, "collector-b", "claim-b", 3, 10)
        .await
        .unwrap();
    assert_eq!(
        (takeover.collector_id.as_str(), takeover.checkpoint_ordinal),
        ("collector-b", 1)
    );

    let untracked = Sha256Digest::digest(b"untracked");
    let mut entries = vec![
        OciProviderInventoryEntryInput {
            object_key: crate::db::oci_blob_object_key(tracked),
            object_digest: tracked,
            observed_hash: tracked,
            byte_size: 7,
            strong_etag: "\"tracked-etag\"".to_string(),
        },
        OciProviderInventoryEntryInput {
            object_key: crate::db::oci_blob_object_key(untracked),
            object_digest: untracked,
            observed_hash: untracked,
            byte_size: 9,
            strong_etag: "\"untracked-etag\"".to_string(),
        },
    ];
    entries.sort_by(|left, right| left.object_key.cmp(&right.object_key));
    let terminal_page = AppendOciProviderInventoryPage {
        generation_id: generation.id.clone(),
        collector_id: "collector-b".to_string(),
        collector_claim_token: "claim-b".to_string(),
        expected_checkpoint_ordinal: 1,
        expected_provider_cursor: Some("cursor-1".to_string()),
        next_provider_cursor: None,
        last_listed_key: Some(entries.last().unwrap().object_key.clone()),
        entries,
        now: 4,
        lease_seconds: 10,
    };
    assert!(database
        .append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
            collector_id: "collector-a".to_string(),
            collector_claim_token: "claim-a".to_string(),
            ..terminal_page.clone()
        })
        .await
        .is_err());
    let checkpoint = database
        .append_oci_provider_inventory_page(&terminal_page)
        .await
        .unwrap();
    assert_eq!(
        (
            checkpoint.checkpoint_ordinal,
            checkpoint.object_count,
            checkpoint.byte_count
        ),
        (2, 2, 16)
    );
    assert!(checkpoint.provider_cursor.is_none());
    assert_eq!(
        database
            .append_oci_provider_inventory_page(&terminal_page)
            .await
            .unwrap(),
        checkpoint,
        "committed provider page did not replay exactly"
    );

    let complete = database
        .complete_oci_provider_inventory(&CompleteOciProviderInventory {
            generation_id: generation.id.clone(),
            collector_id: "collector-b".to_string(),
            collector_claim_token: "claim-b".to_string(),
            expected_checkpoint_ordinal: 2,
            observed_at: 4,
            now: 5,
        })
        .await
        .unwrap();
    assert_eq!(
        (
            complete.state.as_str(),
            complete.object_count,
            complete.byte_count,
            complete.untracked_object_count
        ),
        ("complete", 2, 16, 1)
    );
    let classifications = database
        .backend
        .query(
            "SELECT classification FROM oci_provider_inventory_entries
             WHERE generation_id = ?1 ORDER BY classification",
            &vals![generation.id],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<String>(0).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(classifications, vec!["tracked", "untracked"]);
    assert!(database
        .backend
        .query_opt(
            "SELECT 1 FROM oci_provider_inventory_heads
             WHERE placement_id = ?1 AND generation_id = ?2",
            &vals![placement.id, generation.id],
        )
        .await
        .unwrap()
        .is_some());

    let page = database
        .list_untracked_oci_provider_inventory(registry_id, None, 1)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    let reviewed = &page.items[0];
    assert_eq!(
        (
            reviewed.object_digest,
            reviewed.observed_hash,
            reviewed.byte_size,
            reviewed.strong_etag.as_str()
        ),
        (untracked, untracked, 9, "\"untracked-etag\"")
    );
    let repair = database
        .plan_oci_untracked_repair(&PlanOciUntrackedRepair {
            registry_id,
            placement_id: reviewed.placement_id,
            inventory_generation_id: reviewed.inventory_generation_id.clone(),
            object_key: reviewed.object_key.clone(),
            repair_kind: OciUntrackedRepairKind::Delete,
            adopt_media_type: None,
            actor_id: "inventory-operator".to_string(),
            idempotency_key: "review-untracked".to_string(),
            expected_mutation_epoch: page.captured_mutation_epoch,
            now: 5,
        })
        .await
        .unwrap();
    assert_eq!(
        (repair.state.as_str(), repair.resource_version),
        ("planned", 1)
    );
    let pending = database
        .apply_oci_untracked_repair(&ApplyOciUntrackedRepair {
            plan_id: repair.id.clone(),
            actor_id: "inventory-operator".to_string(),
            idempotency_key: "apply-untracked".to_string(),
            confirmation_hash: repair.confirmation_hash,
            expected_resource_version: repair.resource_version,
            now: 6,
        })
        .await
        .unwrap();
    assert_eq!(
        (pending.state.as_str(), pending.resource_version),
        ("pending", 2)
    );
    assert_eq!(
        database
            .apply_oci_untracked_repair(&ApplyOciUntrackedRepair {
                plan_id: repair.id,
                actor_id: "inventory-operator".to_string(),
                idempotency_key: "apply-untracked".to_string(),
                confirmation_hash: repair.confirmation_hash,
                expected_resource_version: repair.resource_version,
                now: 7,
            })
            .await
            .unwrap(),
        pending
    );
    let claim = database
        .claim_oci_untracked_repair("repair-worker", "repair-claim", 7, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            claim.repair.id.as_str(),
            claim.repair.object_digest,
            claim.repair.strong_etag.as_str(),
            claim.attempt_count,
        ),
        (pending.id.as_str(), untracked, "\"untracked-etag\"", 1)
    );
    let repair_evidence = oci_gc_deletion_evidence_digest(
        &pending.id,
        "repair-response",
        OciGcDeleteOutcome::Deleted,
        Some("\"untracked-etag\""),
        Some("provider-repair-request"),
        8,
    )
    .unwrap();
    let success = RecordOciUntrackedRepairSuccess {
        plan_id: pending.id.clone(),
        claim_token: "repair-claim".to_string(),
        response_idempotency_key: "repair-response".to_string(),
        outcome: OciGcDeleteOutcome::Deleted,
        conditional_etag: Some("\"untracked-etag\"".to_string()),
        provider_request_id: Some("provider-repair-request".to_string()),
        evidence_digest: repair_evidence,
        confirmed_at: 8,
    };
    let repaired = database
        .record_oci_untracked_repair_success(&success)
        .await
        .unwrap();
    assert_eq!(repaired.state, "confirmed_absent");
    assert_eq!(repaired.evidence_digest, Some(repair_evidence));
    assert_eq!(
        database
            .record_oci_untracked_repair_success(&success)
            .await
            .unwrap(),
        repaired,
        "provider response-loss replay changed exact repair evidence"
    );
    assert!(database
        .list_untracked_oci_provider_inventory(registry_id, None, 100)
        .await
        .unwrap()
        .items
        .is_empty());
    assert_eq!(
        database
            .list_due_oci_provider_inventory_placements(9, 100)
            .await
            .unwrap()
            .iter()
            .map(|placement| placement.placement_id)
            .collect::<Vec<_>>(),
        vec![placement.id],
        "terminal repair must require a fresh complete provider inventory"
    );

    for (id, name) in [(201_i64, "one"), (202, "two")] {
        database
            .backend
            .execute(
                "INSERT INTO oci_repositories
                   (id, registry_id, name, visibility, lifecycle_state,
                    resource_version, created_at, updated_at)
                 VALUES(?1, ?2, ?3, 'inherit', 'active', 1, 1, 1)",
                &vals![id, registry_id, name],
            )
            .await
            .unwrap();
        database
            .backend
            .execute(
                "INSERT INTO oci_repository_objects
                   (repository_id, registry_id, digest, object_kind, linked_at)
                 VALUES(?1, ?2, ?3, 'blob', 1)",
                &vals![id, registry_id, tracked.to_string()],
            )
            .await
            .unwrap();
    }
    database
        .begin_oci_upload(&BeginOciUpload {
            registry_id,
            repository_id: 201,
            publication_id: None,
            writer_id: "metrics-writer".to_string(),
            token_id: "metrics-token".to_string(),
            idempotency_key: "metrics-upload".to_string(),
            expected_digest: None,
            expected_size: None,
            maximum_size: 32,
            now: 10,
            expires_at: 20,
        })
        .await
        .unwrap();
    let identity = Sha256Digest::digest(b"publication-metrics").to_string();
    for (id, state, created_at, committed_at) in [
        ("publication-preparing", "preparing", 1_i64, None),
        ("publication-ready", "ready", 4_i64, Some(10_i64)),
    ] {
        database
            .backend
            .execute(
                "INSERT INTO oci_publication_sessions
                   (id, registry_id, repository_id, writer_id, token_id,
                    root_digest, catalog_digest, confirmation_hash,
                    topology_digest, required_placement_count, source_kind,
                    state, idempotency_key, expires_at, created_at,
                    committed_at, resource_version)
                 VALUES(?1, ?2, 201, ?1, ?1, ?3, ?3, ?3, ?3, 1,
                        'manual', ?4, ?1, 3000, ?5, ?6, 1)",
                &vals![id, registry_id, identity, state, created_at, committed_at],
            )
            .await
            .unwrap();
    }
    database
        .backend
        .execute(
            "UPDATE oci_provider_inventory_entries
             SET observed_hash = ?2
             WHERE generation_id = ?1 AND classification = 'tracked'",
            &vals![generation.id, Sha256Digest::digest(b"mismatch").to_string()],
        )
        .await
        .unwrap();
    let missing_inventory = database
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "missing-inventory".to_string(),
            binding_id: placement.binding_id,
            prefix: "missing-inventory".to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 1,
            requires_conditional_writes: true,
        })
        .await
        .unwrap();
    database
        .observe_surface_placement(missing_inventory.id, "ready", "complete", 1)
        .await
        .unwrap();
    let metrics = database.oci_operations_metrics(2_000).await.unwrap();
    assert_eq!(
        (
            metrics.catalog_logical_objects,
            metrics.catalog_logical_bytes
        ),
        (2, 14)
    );
    assert_eq!(
        (metrics.catalog_unique_objects, metrics.catalog_unique_bytes),
        (1, 7)
    );
    assert_eq!(
        (
            metrics.provider_inventory_objects,
            metrics.provider_inventory_bytes
        ),
        (1, 7)
    );
    assert_eq!(
        (metrics.uploads_active, metrics.uploads_expired_nonterminal),
        (1, 1)
    );
    assert_eq!(
        (metrics.publications_preparing, metrics.publications_ready),
        (1, 1)
    );
    assert_eq!(
        (
            metrics.publications_stuck_nonterminal,
            metrics.publication_ready_latency_seconds_sum,
            metrics.publication_ready_latency_count
        ),
        (1, 6, 1)
    );
    assert_eq!(
        (metrics.placements_ready, metrics.placements_unhealthy),
        (1, 1)
    );
    assert_eq!(
        (
            metrics.max_inventory_age_seconds,
            metrics.inventory_takeover_count,
            metrics.digest_mismatches
        ),
        (1_996, 1, 1)
    );
}

#[tokio::test]
async fn reviewed_plan_apply_claim_evidence_and_atomic_accounting_complete() {
    let database = Database::open_in_memory().await.unwrap();
    let (registry_id, placement) = seed_inventory_topology(&database).await;
    let replica = database
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "replica".to_string(),
            binding_id: placement.binding_id,
            prefix: "registry-replica".to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 1,
            requires_conditional_writes: true,
        })
        .await
        .unwrap();
    let replica = database
        .observe_surface_placement(replica.id, "ready", "complete", 1)
        .await
        .unwrap();
    let write_revision = database
        .binding_write_state(replica.binding_id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    database
        .bind_surface_placement_write_capability(replica.id, write_revision)
        .await
        .unwrap();
    let digest = Sha256Digest::digest(b"collect-me");
    let byte_size = 10_i64;
    let repository = database
        .ensure_oci_repository(
            registry_id,
            &RepositoryName::parse("late-finalizer-root").unwrap(),
            999_980,
        )
        .await
        .unwrap();
    let latent_upload = database
        .begin_oci_upload(&BeginOciUpload {
            registry_id,
            repository_id: repository.id,
            publication_id: None,
            writer_id: "late-root-writer".to_string(),
            token_id: "late-root-token".to_string(),
            idempotency_key: "late-root-upload".to_string(),
            expected_digest: None,
            expected_size: None,
            maximum_size: 10,
            now: 999_980,
            expires_at: 1_000_100,
        })
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO surface_objects
               (id, registry_id, object_key, object_kind, partition_key,
                content_hash, size, lifecycle_state, created_at, updated_at,
                resource_version)
             VALUES(301, ?1, ?2, 'immutable', zeroblob(32), ?3, ?4,
                    'active', 1, 1, 1)",
            &vals![
                registry_id,
                crate::db::oci_blob_object_key(digest),
                digest.encoded(),
                byte_size
            ],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_blobs
               (registry_id, digest, byte_size, media_type, surface_object_id,
                quota_bytes, lifecycle_state, created_at, updated_at,
                unreferenced_since)
             VALUES(?1, ?2, ?3, 'application/octet-stream', 301, ?3,
                    'active', 1, 1, 1)",
            &vals![registry_id, digest.to_string(), byte_size],
        )
        .await
        .unwrap();
    let org_id: i64 = database
        .backend
        .query_opt(
            "SELECT org_id FROM registries WHERE id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    database
        .backend
        .execute(
            "INSERT INTO oci_registry_state
               (registry_id, mutation_epoch, charged_bytes, charged_objects, updated_at)
             VALUES(?1, 0, ?2, 1, 1)
             ON CONFLICT(registry_id) DO UPDATE
             SET charged_objects = 1, charged_bytes = excluded.charged_bytes",
            &vals![registry_id, byte_size],
        )
        .await
        .unwrap();
    database
        .backend
        .execute(
            "UPDATE org_usage SET object_count = 1, used_bytes = ?2
             WHERE org_id = ?1",
            &vals![org_id, byte_size],
        )
        .await
        .unwrap();
    let catalog_reservation_id = format!("q-catalog:{registry_id}:{digest}");
    let catalog_owner_id = format!("catalog:{registry_id}:{digest}");
    database
        .backend
        .execute(
            "INSERT INTO oci_quota_reservations
               (id, registry_id, org_id, owner_kind, owner_id,
                reserved_bytes, reserved_objects, state, created_at, updated_at)
             VALUES(?1, ?2, ?3, 'catalog', ?4, ?5, 1, 'committed', 1, 1)",
            &vals![
                catalog_reservation_id,
                registry_id,
                org_id,
                catalog_owner_id,
                byte_size
            ],
        )
        .await
        .unwrap();

    let inventory = database
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id,
            placement_id: placement.id,
            expected_placement_resource_version: placement.resource_version,
            expected_placement_observation_version: placement.observation_version.unwrap(),
            collector_id: "lifecycle-collector".to_string(),
            collector_claim_token: "lifecycle-claim".to_string(),
            collector_lease_seconds: 100,
            idempotency_key: "lifecycle-inventory".to_string(),
            now: 999_990,
        })
        .await
        .unwrap();
    database
        .append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
            generation_id: inventory.id.clone(),
            collector_id: "lifecycle-collector".to_string(),
            collector_claim_token: "lifecycle-claim".to_string(),
            expected_checkpoint_ordinal: 0,
            expected_provider_cursor: None,
            next_provider_cursor: None,
            last_listed_key: Some(crate::db::oci_blob_object_key(digest)),
            entries: vec![OciProviderInventoryEntryInput {
                object_key: crate::db::oci_blob_object_key(digest),
                object_digest: digest,
                observed_hash: digest,
                byte_size: u64::try_from(byte_size).unwrap(),
                strong_etag: "\"collect-etag\"".to_string(),
            }],
            now: 999_991,
            lease_seconds: 100,
        })
        .await
        .unwrap();
    database
        .complete_oci_provider_inventory(&CompleteOciProviderInventory {
            generation_id: inventory.id,
            collector_id: "lifecycle-collector".to_string(),
            collector_claim_token: "lifecycle-claim".to_string(),
            expected_checkpoint_ordinal: 1,
            observed_at: 999_991,
            now: 999_992,
        })
        .await
        .unwrap();
    let replica_inventory = database
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id,
            placement_id: replica.id,
            expected_placement_resource_version: replica.resource_version,
            expected_placement_observation_version: replica.observation_version.unwrap(),
            collector_id: "replica-collector".to_string(),
            collector_claim_token: "replica-claim".to_string(),
            collector_lease_seconds: 100,
            idempotency_key: "replica-inventory".to_string(),
            now: 999_990,
        })
        .await
        .unwrap();
    database
        .append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
            generation_id: replica_inventory.id.clone(),
            collector_id: "replica-collector".to_string(),
            collector_claim_token: "replica-claim".to_string(),
            expected_checkpoint_ordinal: 0,
            expected_provider_cursor: None,
            next_provider_cursor: None,
            last_listed_key: Some(crate::db::oci_blob_object_key(digest)),
            entries: vec![OciProviderInventoryEntryInput {
                object_key: crate::db::oci_blob_object_key(digest),
                object_digest: digest,
                observed_hash: digest,
                byte_size: u64::try_from(byte_size).unwrap(),
                strong_etag: "\"replica-etag\"".to_string(),
            }],
            now: 999_991,
            lease_seconds: 100,
        })
        .await
        .unwrap();
    database
        .complete_oci_provider_inventory(&CompleteOciProviderInventory {
            generation_id: replica_inventory.id,
            collector_id: "replica-collector".to_string(),
            collector_claim_token: "replica-claim".to_string(),
            expected_checkpoint_ordinal: 1,
            observed_at: 999_991,
            now: 999_992,
        })
        .await
        .unwrap();
    let binding = database
        .binding(placement.binding_id)
        .await
        .unwrap()
        .unwrap();
    let write_revision = database
        .binding_write_state(placement.binding_id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    let delete_credential = database
        .set_binding_credential_revision(
            placement.binding_id,
            "delete",
            "secret://oci-gc/delete/v1",
            0,
            &"1".repeat(64),
            "test",
        )
        .await
        .unwrap();
    let delete_credential = database
        .validate_binding_credential_revision(
            placement.binding_id,
            "delete",
            delete_credential.generation,
            "valid",
            None,
            delete_credential.head_resource_version,
        )
        .await
        .unwrap();
    let delete_capability = database
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            binding_id: placement.binding_id,
            binding_write_revision: write_revision,
            binding_resource_version: binding.resource_version,
            delete_credential_purpose: Some("delete".to_string()),
            delete_credential_generation: Some(delete_credential.generation),
            capability_fingerprint: "conditional-delete-lifecycle".to_string(),
            state: "valid".to_string(),
            expected_resource_version: None,
            observed_at: 999_992,
        })
        .await
        .unwrap();

    let plan = database
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "gc-operator".to_string(),
            idempotency_key: "plan-lifecycle".to_string(),
            expected_resource_version: 0,
            now: 999_993,
        })
        .await
        .unwrap();
    assert_eq!(
        (
            plan.state.as_str(),
            plan.planned_objects,
            plan.planned_bytes,
            plan.placement_action_count,
        ),
        ("planned", 1, 10, 2)
    );
    assert!(database
        .list_oci_gc_blockers(&plan.id)
        .await
        .unwrap()
        .is_empty());

    let revoked_delete_credential = database
        .validate_binding_credential_revision(
            placement.binding_id,
            "delete",
            delete_credential.generation,
            "invalid",
            Some("provider revoked the exact delete credential"),
            delete_credential.head_resource_version,
        )
        .await
        .unwrap();
    assert!(database
        .apply_oci_gc(&ApplyOciGc {
            generation_id: plan.id.clone(),
            actor_id: "gc-operator".to_string(),
            idempotency_key: "apply-lifecycle".to_string(),
            confirmation_hash: plan.confirmation_hash,
            now: 999_994,
        })
        .await
        .is_err());
    assert_eq!(
        database
            .backend
            .query_opt(
                "SELECT lifecycle_state FROM oci_blobs
                 WHERE registry_id = ?1 AND digest = ?2",
                &vals![registry_id, digest.to_string()],
            )
            .await
            .unwrap()
            .unwrap()
            .get::<String>(0)
            .unwrap(),
        "active"
    );
    database
        .validate_binding_credential_revision(
            placement.binding_id,
            "delete",
            delete_credential.generation,
            "valid",
            None,
            revoked_delete_credential.head_resource_version,
        )
        .await
        .unwrap();

    let delete_credential = database
        .set_binding_credential_revision(
            placement.binding_id,
            "delete",
            "secret://oci-gc/delete/v2",
            delete_credential.generation,
            &"4".repeat(64),
            "test",
        )
        .await
        .unwrap();
    let delete_credential = database
        .validate_binding_credential_revision(
            placement.binding_id,
            "delete",
            delete_credential.generation,
            "valid",
            None,
            delete_credential.head_resource_version,
        )
        .await
        .unwrap();
    assert!(database
        .apply_oci_gc(&ApplyOciGc {
            generation_id: plan.id.clone(),
            actor_id: "gc-operator".to_string(),
            idempotency_key: "apply-lifecycle".to_string(),
            confirmation_hash: plan.confirmation_hash,
            now: 999_994,
        })
        .await
        .is_err());
    let delete_capability = database
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            binding_id: placement.binding_id,
            binding_write_revision: write_revision,
            binding_resource_version: binding.resource_version,
            delete_credential_purpose: Some("delete".to_string()),
            delete_credential_generation: Some(delete_credential.generation),
            capability_fingerprint: "conditional-delete-lifecycle".to_string(),
            state: "valid".to_string(),
            expected_resource_version: Some(delete_capability.resource_version),
            observed_at: 999_994,
        })
        .await
        .unwrap();
    let plan = database
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "gc-operator".to_string(),
            idempotency_key: "plan-lifecycle-after-credential-rotation".to_string(),
            expected_resource_version: 0,
            now: 999_994,
        })
        .await
        .unwrap();
    assert!(database
        .list_oci_gc_blockers(&plan.id)
        .await
        .unwrap()
        .is_empty());

    let applied = database
        .apply_oci_gc(&ApplyOciGc {
            generation_id: plan.id.clone(),
            actor_id: "gc-operator".to_string(),
            idempotency_key: "apply-lifecycle".to_string(),
            confirmation_hash: plan.confirmation_hash,
            now: 999_994,
        })
        .await
        .unwrap();
    assert_eq!(applied.state, "applying");
    assert_eq!(
        database
            .apply_oci_gc(&ApplyOciGc {
                generation_id: plan.id.clone(),
                actor_id: "gc-operator".to_string(),
                idempotency_key: "apply-lifecycle".to_string(),
                confirmation_hash: plan.confirmation_hash,
                now: 999_995,
            })
            .await
            .unwrap(),
        applied
    );
    let rotated_delete_credential = database
        .set_binding_credential_revision(
            placement.binding_id,
            "delete",
            "secret://oci-gc/delete/v3",
            delete_credential.generation,
            &"5".repeat(64),
            "test",
        )
        .await
        .unwrap();
    let rotated_delete_credential = database
        .validate_binding_credential_revision(
            placement.binding_id,
            "delete",
            rotated_delete_credential.generation,
            "valid",
            None,
            rotated_delete_credential.head_resource_version,
        )
        .await
        .unwrap();
    database
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            binding_id: placement.binding_id,
            binding_write_revision: write_revision,
            binding_resource_version: binding.resource_version,
            delete_credential_purpose: Some("delete".to_string()),
            delete_credential_generation: Some(rotated_delete_credential.generation),
            capability_fingerprint: "conditional-delete-lifecycle".to_string(),
            state: "valid".to_string(),
            expected_resource_version: Some(delete_capability.resource_version),
            observed_at: 999_995,
        })
        .await
        .unwrap();
    assert!(database
        .backend
        .execute(
            "DELETE FROM binding_credential_revisions
             WHERE binding_id = ?1 AND purpose = 'delete' AND generation = ?2",
            &vals![placement.binding_id, delete_credential.generation],
        )
        .await
        .is_err());
    let degraded = database
        .observe_surface_placement(
            placement.id,
            "degraded",
            "partial",
            placement.observation_version.unwrap(),
        )
        .await
        .unwrap();
    let replica_claim = database
        .claim_oci_gc_placement_action("gc-worker", "degraded-claim", 999_996, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replica_claim.placement_id, replica.id);
    database
        .observe_surface_placement(
            placement.id,
            "ready",
            "complete",
            degraded.observation_version.unwrap(),
        )
        .await
        .unwrap();

    let rotated_write_credential = database
        .set_binding_credential_revision(
            placement.binding_id,
            "write",
            "secret://oci-gc/write/v2",
            1,
            &"2".repeat(64),
            "test",
        )
        .await
        .unwrap();
    let rotated_write_credential = database
        .validate_binding_credential_revision(
            placement.binding_id,
            "write",
            rotated_write_credential.generation,
            "valid",
            None,
            rotated_write_credential.head_resource_version,
        )
        .await
        .unwrap();
    let rotated_write_revision = database
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id: placement.binding_id,
            write_credential_generation: rotated_write_credential.generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "oci-gc-write-revision-rotated".to_string(),
            capability_fingerprint: "conditional-write-v1".to_string(),
        })
        .await
        .unwrap();
    database
        .observe_binding_write_revision(
            placement.binding_id,
            rotated_write_revision.revision,
            "valid",
            None,
            None,
        )
        .await
        .unwrap();
    let binding_write_state = database
        .binding_write_state(placement.binding_id)
        .await
        .unwrap()
        .unwrap();
    database
        .set_current_binding_write_revision(
            placement.binding_id,
            rotated_write_revision.revision,
            binding_write_state.resource_version,
        )
        .await
        .unwrap();
    assert!(database
        .retire_binding_write_revision(placement.binding_id, write_revision)
        .await
        .is_err());

    let primary_claim = database
        .claim_oci_gc_placement_action("gc-worker", "gc-claim", 999_996, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            primary_claim.digest,
            primary_claim.inventory_entry_present,
            primary_claim.placement_id,
        ),
        (digest, true, placement.id)
    );
    for (ordinal, (claim, claim_token)) in [
        (replica_claim, "degraded-claim"),
        (primary_claim, "gc-claim"),
    ]
    .into_iter()
    .enumerate()
    {
        let response_idempotency_key = format!("delete-response-{ordinal}");
        let provider_request_id = format!("provider-request-{ordinal}");
        let evidence_digest = oci_gc_deletion_evidence_digest(
            &claim.action_id,
            &response_idempotency_key,
            OciGcDeleteOutcome::Deleted,
            claim.expected_strong_etag.as_deref(),
            Some(&provider_request_id),
            999_997,
        )
        .unwrap();
        let success = RecordOciGcDeletionSuccess {
            action_id: claim.action_id.clone(),
            claim_token: claim_token.to_string(),
            response_idempotency_key,
            outcome: OciGcDeleteOutcome::Deleted,
            conditional_etag: claim.expected_strong_etag,
            provider_request_id: Some(provider_request_id),
            evidence_digest,
            confirmed_at: 999_997,
        };
        let confirmed = database
            .record_oci_gc_placement_action_success(&success)
            .await
            .unwrap();
        assert_eq!(confirmed.state, "confirmed_absent");
        assert_eq!(
            database
                .record_oci_gc_placement_action_success(&success)
                .await
                .unwrap(),
            confirmed
        );
    }
    let candidate = database
        .finalize_oci_gc_candidate(&plan.id, digest, 999_998)
        .await
        .unwrap();
    assert_eq!(candidate.state, "physically_absent");
    assert_eq!(
        database
            .finalize_oci_gc_candidate(&plan.id, digest, 999_999)
            .await
            .unwrap(),
        candidate
    );
    database
        .backend
        .execute(
            "INSERT INTO oci_leases(id, registry_id, digest, lease_kind, expires_at, created_at)
             VALUES('late-finalizer-lease', ?1, ?2, 'operator', 1000100, 999999)",
            &vals![registry_id, digest.to_string()],
        )
        .await
        .unwrap();
    assert!(database
        .finalize_oci_gc_generation(&plan.id, 1_000_000)
        .await
        .is_err());
    database
        .backend
        .execute(
            "DELETE FROM oci_leases WHERE id = 'late-finalizer-lease'",
            &[],
        )
        .await
        .unwrap();

    database
        .backend
        .execute(
            "UPDATE oci_upload_sessions SET expected_digest = ?2
             WHERE id = ?1 AND state = 'active'",
            &vals![latent_upload.id, digest.to_string()],
        )
        .await
        .unwrap();
    assert!(database
        .finalize_oci_gc_generation(&plan.id, 1_000_000)
        .await
        .is_err());
    database
        .backend
        .execute(
            "UPDATE oci_upload_sessions SET expected_digest = NULL WHERE id = ?1",
            &vals![latent_upload.id],
        )
        .await
        .unwrap();

    database
        .backend
        .execute(
            "INSERT INTO oci_publication_sessions
               (id, registry_id, repository_id, writer_id, token_id,
                target_tag, expected_tag_version, expected_tag_digest,
                root_digest, catalog_digest, release_tag, sidecar_sha256,
                confirmation_hash, topology_digest, required_placement_count,
                source_kind, state, idempotency_key, commit_idempotency_key,
                abort_idempotency_key, expires_at, created_at, committed_at,
                resource_version)
             VALUES('late-finalizer-publication', ?1, ?2, 'late-root-writer',
                    'late-root-token', NULL, NULL, NULL, ?3, ?3, NULL, NULL,
                    ?3, ?3, 1, 'manual', 'preparing', 'late-publication',
                    NULL, NULL, 1000100, 999999, NULL, 1)",
            &vals![registry_id, repository.id, digest.to_string()],
        )
        .await
        .unwrap();
    assert!(database
        .finalize_oci_gc_generation(&plan.id, 1_000_000)
        .await
        .is_err());
    database
        .backend
        .execute(
            "DELETE FROM oci_publication_sessions WHERE id = 'late-finalizer-publication'",
            &[],
        )
        .await
        .unwrap();

    database
        .backend
        .execute(
            "UPDATE org_usage SET used_bytes = 0, object_count = 0 WHERE org_id = ?1",
            &vals![org_id],
        )
        .await
        .unwrap();
    assert!(database
        .finalize_oci_gc_generation(&plan.id, 1_000_000)
        .await
        .is_err());
    assert!(database
        .backend
        .query_opt(
            "SELECT 1 FROM oci_blobs WHERE registry_id = ?1 AND digest = ?2",
            &vals![registry_id, digest.to_string()],
        )
        .await
        .unwrap()
        .is_some());
    database
        .backend
        .execute(
            "UPDATE org_usage SET used_bytes = ?2, object_count = 1 WHERE org_id = ?1",
            &vals![org_id, byte_size],
        )
        .await
        .unwrap();
    let complete = database
        .finalize_oci_gc_generation(&plan.id, 1_000_001)
        .await
        .unwrap();
    assert_eq!(
        (
            complete.state.as_str(),
            complete.deleted_object_count,
            complete.deleted_byte_size
        ),
        ("complete", 1, 10)
    );
    let usage = database
        .backend
        .query_opt(
            "SELECT used_bytes, object_count FROM org_usage WHERE org_id = ?1",
            &vals![org_id],
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (usage.get::<i64>(0).unwrap(), usage.get::<i64>(1).unwrap()),
        (0, 0)
    );
    let registry_usage = database
        .backend
        .query_opt(
            "SELECT charged_bytes, charged_objects FROM oci_registry_state
             WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            registry_usage.get::<i64>(0).unwrap(),
            registry_usage.get::<i64>(1).unwrap()
        ),
        (0, 0)
    );
    assert!(database
        .backend
        .query_opt(
            "SELECT 1 FROM oci_blobs WHERE registry_id = ?1 AND digest = ?2",
            &vals![registry_id, digest.to_string()],
        )
        .await
        .unwrap()
        .is_none());
    assert!(database
        .backend
        .query_opt(
            "SELECT 1 FROM oci_quota_reservations WHERE id = ?1",
            &vals![catalog_reservation_id],
        )
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        database
            .backend
            .execute(
                "INSERT INTO oci_quota_reservations
                   (id, registry_id, org_id, owner_kind, owner_id,
                    reserved_bytes, reserved_objects, state, created_at, updated_at)
                 VALUES(?1, ?2, ?3, 'catalog', ?4, ?5, 1, 'pending',
                        1000002, 1000002)",
                &vals![
                    catalog_reservation_id,
                    registry_id,
                    org_id,
                    catalog_owner_id,
                    byte_size
                ],
            )
            .await
            .unwrap(),
        1,
        "terminal GC must reopen deterministic catalog admission identity"
    );
    assert_eq!(
        database
            .backend
            .execute(
                "DELETE FROM binding_credential_revisions
                 WHERE binding_id = ?1 AND purpose = 'delete' AND generation = ?2",
                &vals![placement.binding_id, delete_credential.generation],
            )
            .await
            .unwrap(),
        1,
        "terminal GC must release its transient frozen-credential hold"
    );
}
