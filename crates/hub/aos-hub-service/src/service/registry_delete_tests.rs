//! Reviewed registry deletion through the RPC surface and its controller.
//!
//! Each case plans and applies through [`RpcService`], then drives the
//! resulting operation with a [`RegistryDeletionController`] over an
//! in-memory provider whose listing is empty unless a case says otherwise.

use std::sync::Arc;

use aos_oci_types::{RepositoryName, Sha256Digest};

use super::super::cache_upload_tests::release_test_service;
use super::*;
use crate::fetch::{SurfaceFetch, SurfaceListPage, SurfaceProvider};
use crate::oci_inventory_controller::NATIVE_OCI_INVENTORY_DISPATCH_BUDGET;
use crate::registry_delete_controller::{RegistryDeletionController, RegistryDeletionPassStats};
use aos_hub_db::backend::Statement;
use aos_hub_db::db::{
    oci_blob_object_key, AppendOciProviderInventoryPage, BeginOciProviderInventory,
    CompleteOciProviderInventory, Database, NewBindingWriteRevision, NewSurfacePlacementSpec,
    OciProviderInventoryEntryInput, RegistryRecord, SurfacePlacementRecord, SurfaceTarget,
};

/// Binds SQL parameters like the database module's private `vals!`.
macro_rules! values {
    ($($value:expr),* $(,)?) => {
        vec![$(aos_hub_db::value::ToValue::to_value(&$value)),*]
    };
}

/// A provider whose placements list no objects.
struct EmptyProvider;

#[async_trait::async_trait]
impl SurfaceFetch for EmptyProvider {
    async fn fetch(&self, _path: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn list_page(
        &self,
        _prefix: &str,
        _cursor: Option<&str>,
        _limit: usize,
    ) -> anyhow::Result<SurfaceListPage> {
        Ok(SurfaceListPage {
            paths: Vec::new(),
            evidence: Default::default(),
            next_cursor: None,
        })
    }

    fn describe(&self) -> String {
        "empty registry deletion provider".into()
    }
}

#[async_trait::async_trait]
impl SurfaceProvider for EmptyProvider {
    async fn placement_fetcher(
        &self,
        _placement: &SurfacePlacementRecord,
    ) -> anyhow::Result<Box<dyn SurfaceFetch>> {
        Ok(Box::new(EmptyProvider))
    }
}

struct Fixture {
    service: RpcService,
    db: Arc<Database>,
    auth: String,
    registry: RegistryRecord,
    placement: SurfacePlacementRecord,
}

impl Fixture {
    /// Creates a registry with one writable placement, observed when `scanned`.
    async fn new(slug: &str, scanned: bool) -> Self {
        let (service, db, auth) = release_test_service().await;
        let org_id = db.create_org(slug, "Deletion").await.unwrap();
        let org = db.org_by_id(org_id).await.unwrap().unwrap();
        let registry_id = db
            .create_managed_registry(org_id, "", "scratch", "public", &[], false)
            .await
            .unwrap();
        let binding_id = db
            .create_topology_binding(
                Some(org_id),
                &format!("{slug}-binding"),
                &org.stable_id,
                "deletion",
                "s3",
                None,
                Some("deletion"),
                Some("registry"),
                Some("https"),
                Some("dns"),
                Some(b"storage.example.invalid"),
                Some(443),
                Some("auto"),
                Some("private"),
            )
            .await
            .unwrap();
        let placement = db
            .create_surface_placement(&NewSurfacePlacementSpec {
                surface: SurfaceTarget::Registry(registry_id),
                name: "primary".into(),
                binding_id,
                prefix: "scratch".into(),
                kind: "complete".into(),
                desired_state: "active".into(),
                hash_range: None,
                desired_read_enabled: true,
                read_order: 0,
                requires_conditional_writes: false,
            })
            .await
            .unwrap();
        if scanned {
            db.observe_surface_placement(placement.id, "ready", "complete", 1)
                .await
                .unwrap();
        }
        bind_write_revision(&db, binding_id, placement.id).await;

        let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
        let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
        Self {
            service,
            db,
            auth,
            registry,
            placement,
        }
    }

    async fn plan(&self) -> pb::RegistryDeletePlanResponse {
        self.service
            .plan_delete_registry(
                Some(&self.auth),
                pb::PlanDeleteTopologyResourceRequest {
                    stable_id: self.registry.stable_id.clone(),
                    expected_resource_version: Some(self.registry.resource_version.to_string()),
                    idempotency_key: format!("plan-{}", self.registry.stable_id),
                },
            )
            .await
            .unwrap()
    }

    async fn apply(
        &self,
        planned: &pb::RegistryDeletePlanResponse,
    ) -> Result<pb::OperationResponse, RpcError> {
        let plan = planned.plan.as_ref().unwrap();
        self.service
            .apply_delete_registry(
                Some(&self.auth),
                pb::ApplyDeleteTopologyResourceRequest {
                    plan_id: plan.plan_id.clone(),
                    idempotency_key: format!("plan-{}", self.registry.stable_id),
                    confirmation_hash: plan.confirmation_hash.clone(),
                },
            )
            .await
    }

    async fn run_controller(&self) -> RegistryDeletionPassStats {
        RegistryDeletionController::new(
            Arc::clone(&self.db),
            Arc::new(EmptyProvider),
            "registry-delete-test",
            NATIVE_OCI_INVENTORY_DISPATCH_BUDGET,
        )
        .run_due(5)
        .await
        .unwrap()
    }

    async fn operation(
        &self,
        response: &pb::OperationResponse,
    ) -> aos_hub_db::db::TopologyOperationRecord {
        let operation_id = &response.operation.as_ref().unwrap().operation_id;
        self.db
            .topology_operation(operation_id)
            .await
            .unwrap()
            .unwrap()
    }

    async fn registry_exists(&self) -> bool {
        self.db
            .registry_by_id(self.registry.id)
            .await
            .unwrap()
            .is_some()
    }

    /// Inserts one OCI GC run row in `state` for this registry.
    async fn insert_gc_run(&self, run_id: &str, state: &str, expires_at: i64) {
        let now = aos_hub_model::clock::now_unix_secs();
        self.db
            .fixture_backend()
            .checked_batch(&[Statement::new(
                "INSERT INTO oci_gc_runs
                   (id, registry_id, actor_id, plan_idempotency_key, state,
                    captured_mutation_epoch, policy_resource_version, policy_digest,
                    root_set_digest, placement_inventory_digest, topology_digest,
                    plan_digest, confirmation_hash, inventory_object_count,
                    inventory_byte_size, reachable_object_count, planned_bytes,
                    planned_objects, placement_action_count, expires_at, created_at,
                    applied_at, applied_mutation_epoch)
                 VALUES (?1, ?2, 'gc-operator', ?1, ?3, 0, 0, ?4, ?4, ?4, ?4, ?4, ?4,
                   0, 0, 0, 0, 0, 0, ?5, ?6,
                   CASE WHEN ?3 = 'applying' THEN ?6 END,
                   CASE WHEN ?3 = 'applying' THEN 0 END)",
                values![
                    run_id,
                    self.registry.id,
                    state,
                    "0".repeat(64),
                    expires_at,
                    now - 7200
                ],
            )
            .expecting(1)])
            .await
            .unwrap();
    }
}

/// Gives the binding a current, validated write revision bound to the placement.
async fn bind_write_revision(db: &Database, binding_id: i64, placement_id: i64) {
    let credential = db
        .set_binding_credential_revision(
            binding_id,
            "write",
            "secret://test/registry-delete-write/v1",
            0,
            &"0".repeat(64),
            "test",
        )
        .await
        .unwrap();
    db.validate_binding_credential_revision(
        binding_id,
        "write",
        credential.generation,
        "valid",
        None,
        credential.head_resource_version,
    )
    .await
    .unwrap();
    let revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id,
            write_credential_generation: credential.generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "registry-delete-revision".into(),
            capability_fingerprint: "registry-delete-capability".into(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding_id, revision.revision, "valid", None, None)
        .await
        .unwrap();
    let state = db.binding_write_state(binding_id).await.unwrap().unwrap();
    db.set_current_binding_write_revision(binding_id, revision.revision, state.resource_version)
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(placement_id, revision.revision)
        .await
        .unwrap();
}

fn blockers(readiness: Option<&pb::RegistryDeletionReadiness>) -> pb::RegistryDeletionBlockers {
    readiness.unwrap().blockers.unwrap()
}

fn detail(operation: &aos_hub_db::db::TopologyOperationRecord) -> serde_json::Value {
    serde_json::from_str(&operation.detail_json).unwrap()
}

#[tokio::test]
async fn empty_registry_without_inventory_deletes_with_one_apply() {
    let fixture = Fixture::new("delete-empty", true).await;

    let planned = fixture.plan().await;
    let readiness = planned.readiness.as_ref().unwrap();
    assert_eq!(readiness.verdict, "automatic");
    assert!(readiness.blocking_reasons.is_empty());
    assert_eq!(blockers(Some(readiness)).placements_needing_inventory, 1);
    assert_eq!(readiness.placements[0].inventory_state, "needs_inventory");
    assert!(readiness
        .automatic_steps
        .iter()
        .any(|step| step.contains("collect a fresh provider inventory")));
    assert!(planned
        .plan
        .as_ref()
        .unwrap()
        .effects
        .iter()
        .any(|effect| effect.contains("acquire the registry purge fence")));

    let started = fixture.apply(&planned).await.unwrap();
    assert_eq!(started.operation.as_ref().unwrap().kind, "delete_registry");
    let stats = fixture.run_controller().await;

    assert_eq!(stats.deleted, 1, "{stats:?}");
    assert!(!fixture.registry_exists().await);
    let operation = fixture.operation(&started).await;
    assert_eq!(operation.state, "succeeded");
    assert_eq!(operation.progress_current, 4);
    let detail = detail(&operation);
    assert_eq!(detail["phase"], "deleted");
    assert_eq!(detail["fenceAcquired"], true);
    assert_eq!(detail["inventories"][0]["state"], "complete");

    // Replaying the apply returns the same operation instead of a new one.
    let replayed = fixture.apply(&planned).await.unwrap();
    assert_eq!(replayed.operation, started.operation);
}

#[tokio::test]
async fn stale_inventory_listing_objects_is_recollected_before_deletion() {
    let fixture = Fixture::new("delete-stale", true).await;
    let stale_at = aos_hub_model::clock::now_unix_secs() - 7200;
    let untracked = Sha256Digest::digest(b"removed-out-of-band");
    let inventory = fixture
        .db
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id: fixture.registry.id,
            placement_id: fixture.placement.id,
            expected_placement_resource_version: fixture.placement.resource_version,
            expected_placement_observation_version: fixture.placement.observation_version.unwrap(),
            collector_id: "stale-collector".into(),
            collector_claim_token: "stale-claim".into(),
            collector_lease_seconds: 100,
            idempotency_key: "stale-inventory".into(),
            now: stale_at,
        })
        .await
        .unwrap();
    fixture
        .db
        .append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
            generation_id: inventory.id.clone(),
            collector_id: "stale-collector".into(),
            collector_claim_token: "stale-claim".into(),
            expected_checkpoint_ordinal: 0,
            expected_provider_cursor: None,
            next_provider_cursor: None,
            last_listed_key: Some(oci_blob_object_key(untracked)),
            entries: vec![OciProviderInventoryEntryInput {
                object_key: oci_blob_object_key(untracked),
                object_digest: untracked,
                observed_hash: untracked,
                byte_size: 19,
                strong_etag: "\"stale\"".into(),
            }],
            now: stale_at + 1,
            lease_seconds: 100,
        })
        .await
        .unwrap();
    fixture
        .db
        .complete_oci_provider_inventory(&CompleteOciProviderInventory {
            generation_id: inventory.id,
            collector_id: "stale-collector".into(),
            collector_claim_token: "stale-claim".into(),
            expected_checkpoint_ordinal: 1,
            observed_at: stale_at + 1,
            now: stale_at + 2,
        })
        .await
        .unwrap();

    let planned = fixture.plan().await;
    let readiness = planned.readiness.as_ref().unwrap();
    assert_eq!(readiness.verdict, "automatic");
    assert_eq!(blockers(Some(readiness)).untracked_provider_objects, 1);
    assert!(readiness.placements[0].detail.contains("stale"));

    let started = fixture.apply(&planned).await.unwrap();
    assert_eq!(fixture.run_controller().await.deleted, 1);
    assert!(!fixture.registry_exists().await);
    assert_eq!(fixture.operation(&started).await.state, "succeeded");
}

#[tokio::test]
async fn repositories_fail_closed_with_the_blocker_breakdown() {
    let fixture = Fixture::new("delete-repositories", true).await;
    for name in ["app", "tools"] {
        fixture
            .db
            .ensure_oci_repository(
                fixture.registry.id,
                &RepositoryName::parse(name).unwrap(),
                aos_hub_model::clock::now_unix_secs(),
            )
            .await
            .unwrap();
    }

    let planned = fixture.plan().await;
    let readiness = planned.readiness.as_ref().unwrap();
    assert_eq!(readiness.verdict, "blocked");
    assert_eq!(blockers(Some(readiness)).repositories, 2);
    assert!(readiness.automatic_steps.is_empty());
    assert!(readiness.blocking_reasons[0].contains("OCI repositories"));
    assert!(planned
        .plan
        .as_ref()
        .unwrap()
        .warnings
        .iter()
        .any(|warning| warning.starts_with("blocked: ")));

    let refused = fixture.apply(&planned).await.unwrap_err();
    assert!(
        matches!(&refused, RpcError::FailedPrecondition(message)
            if message.contains("registry deletion is blocked")
                && message.contains("OCI repositories")),
        "{refused:?}"
    );
    assert!(fixture.registry_exists().await);
    assert_eq!(fixture.run_controller().await.claimed, 0);
}

#[tokio::test]
async fn enabled_oci_namespace_blocks_deletion_until_disabled() {
    let fixture = Fixture::new("delete-namespace", true).await;
    let now = aos_hub_model::clock::now_unix_secs();
    fixture
        .db
        .fixture_backend()
        .checked_batch(&[Statement::new(
            "INSERT INTO registry_oci_namespaces
               (registry_id, enabled, resource_version, created_at, updated_at)
             VALUES (?1, 1, 1, ?2, ?2)",
            values![fixture.registry.id, now],
        )
        .expecting(1)])
        .await
        .unwrap();

    let planned = fixture.plan().await;
    let readiness = planned.readiness.as_ref().unwrap();
    assert_eq!(readiness.verdict, "blocked");
    assert_eq!(blockers(Some(readiness)).enabled_oci_namespaces, 1);
    assert!(readiness.blocking_reasons[0].contains("OCI namespace is still enabled"));
    let refused = fixture.apply(&planned).await.unwrap_err();
    assert!(
        matches!(&refused, RpcError::FailedPrecondition(message)
            if message.contains("OCI namespace is still enabled")),
        "{refused:?}"
    );
    assert!(fixture.registry_exists().await);

    // Disabling the namespace leaves only automatic steps, and the deletion
    // retires the disabled namespace row with the registry.
    fixture
        .db
        .fixture_backend()
        .execute(
            "UPDATE registry_oci_namespaces SET enabled = 0 WHERE registry_id = ?1",
            &values![fixture.registry.id],
        )
        .await
        .unwrap();
    let started = fixture.apply(&planned).await.unwrap();
    let stats = fixture.run_controller().await;

    assert_eq!(stats.deleted, 1, "{stats:?}");
    assert!(!fixture.registry_exists().await);
    assert_eq!(fixture.operation(&started).await.state, "succeeded");
    let namespace_rows = fixture
        .db
        .fixture_backend()
        .query_opt(
            "SELECT COUNT(*) FROM registry_oci_namespaces WHERE registry_id = ?1",
            &values![fixture.registry.id],
        )
        .await
        .unwrap()
        .unwrap()
        .get::<i64>(0)
        .unwrap();
    assert_eq!(namespace_rows, 0);
}

#[tokio::test]
async fn planned_gc_runs_are_abandoned_and_applying_runs_block() {
    let fixture = Fixture::new("delete-gc-runs", true).await;
    let now = aos_hub_model::clock::now_unix_secs();
    fixture
        .insert_gc_run(&"a".repeat(64), "planned", now - 60)
        .await;

    let planned = fixture.plan().await;
    let readiness = planned.readiness.as_ref().unwrap();
    assert_eq!(readiness.verdict, "automatic");
    assert_eq!(blockers(Some(readiness)).abandonable_gc_runs, 1);
    assert!(readiness.automatic_steps[0].contains("abandon 1 planned OCI GC run"));

    fixture
        .insert_gc_run(&"b".repeat(64), "applying", now + 600)
        .await;
    let blocked = fixture.plan().await;
    let readiness = blocked.readiness.as_ref().unwrap();
    assert_eq!(readiness.verdict, "blocked");
    assert_eq!(blockers(Some(readiness)).applying_gc_runs, 1);
    assert!(matches!(
        fixture.apply(&blocked).await,
        Err(RpcError::FailedPrecondition(_))
    ));

    fixture
        .db
        .fixture_backend()
        .checked_batch(&[Statement::new(
            "UPDATE oci_gc_runs SET state = 'complete', finished_at = ?2 WHERE id = ?1",
            values!["b".repeat(64), now],
        )
        .expecting(1)])
        .await
        .unwrap();
    let started = fixture.apply(&fixture.plan().await).await.unwrap();
    assert_eq!(fixture.run_controller().await.deleted, 1);
    let detail = detail(&fixture.operation(&started).await);
    assert_eq!(detail["abandonedGcRuns"][0], "a".repeat(64));
}

#[tokio::test]
async fn unscanned_placement_is_scanned_before_its_inventory() {
    let fixture = Fixture::new("delete-unscanned", false).await;

    let planned = fixture.plan().await;
    let readiness = planned.readiness.as_ref().unwrap();
    assert_eq!(readiness.verdict, "automatic");
    assert_eq!(readiness.placements[0].inventory_state, "needs_scan");

    let started = fixture.apply(&planned).await.unwrap();
    let stats = fixture.run_controller().await;
    assert_eq!((stats.deleted, stats.failed), (0, 0));
    assert!(stats.follow_up_due);
    let operation = fixture.operation(&started).await;
    assert_eq!(operation.state, "running");
    let detail = detail(&operation);
    assert_eq!(detail["phase"], "scanning");
    let scan_id = detail["placementScans"][0]["operationId"].as_str().unwrap();
    let scan = fixture
        .db
        .topology_operation(scan_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(scan.operation_kind, "scan_placement");

    // The placement scan controller observes the placement; the deletion
    // then inventories it and completes on its next pass.
    fixture
        .db
        .observe_surface_placement(fixture.placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    assert_eq!(fixture.run_controller().await.deleted, 1);
    assert!(!fixture.registry_exists().await);
}

#[tokio::test]
async fn precondition_changed_after_review_fails_as_a_precondition() {
    let fixture = Fixture::new("delete-race", true).await;
    let planned = fixture.plan().await;
    assert_eq!(planned.readiness.as_ref().unwrap().verdict, "automatic");

    // A repository created between review and apply refuses the apply with
    // the breakdown instead of an opaque internal error.
    fixture
        .db
        .ensure_oci_repository(
            fixture.registry.id,
            &RepositoryName::parse("late").unwrap(),
            aos_hub_model::clock::now_unix_secs(),
        )
        .await
        .unwrap();
    let refused = fixture.apply(&planned).await.unwrap_err();
    assert!(
        matches!(&refused, RpcError::FailedPrecondition(message)
            if message.contains("OCI repositories")),
        "{refused:?}"
    );
}

#[tokio::test]
async fn precondition_changed_while_running_fails_the_operation_with_the_breakdown() {
    let fixture = Fixture::new("delete-running-race", true).await;
    let planned = fixture.plan().await;
    let started = fixture.apply(&planned).await.unwrap();

    fixture
        .db
        .create_registry_publication(&aos_hub_db::db::NewRegistryPublication {
            publication_id: "late-publication".into(),
            registry_id: fixture.registry.id,
            generation: "late-generation".into(),
            manifest_digest: "c".repeat(64),
            refs_digest: "d".repeat(64),
            default_commit: None,
            parent_publication_id: None,
        })
        .await
        .unwrap();
    let stats = fixture.run_controller().await;

    assert_eq!(stats.failed, 1, "{stats:?}");
    assert!(fixture.registry_exists().await);
    let operation = fixture.operation(&started).await;
    assert_eq!(operation.state, "failed");
    assert!(operation
        .error
        .as_deref()
        .unwrap()
        .starts_with("failed_precondition: registry deletion is blocked"));
    let detail = detail(&operation);
    assert_eq!(detail["phase"], "blocked");
    assert_eq!(detail["readiness"]["blockers"]["activePublications"], "1");
}

#[tokio::test]
async fn cancelled_deletion_releases_its_fence_and_a_retry_completes() {
    let fixture = Fixture::new("delete-cancel", false).await;
    let started = fixture.apply(&fixture.plan().await).await.unwrap();
    fixture.run_controller().await;
    let fence_state = || async {
        fixture
            .db
            .fixture_backend()
            .query_opt(
                "SELECT state FROM oci_registry_purge_fences WHERE registry_id = ?1",
                &values![fixture.registry.id],
            )
            .await
            .unwrap()
            .map(|row| row.get::<String>(0).unwrap())
    };
    assert_eq!(fence_state().await.as_deref(), Some("collecting"));

    // Cancelling between passes leaves the fence to the next pass, which
    // releases it because its owning operation can no longer delete.
    let operation = fixture.operation(&started).await;
    fixture
        .db
        .mutate_topology_operation(
            &operation.operation_id,
            operation.resource_version,
            "cancel",
            "cancel-deletion",
        )
        .await
        .unwrap();
    assert_eq!(fixture.run_controller().await.released_fences, 1);
    assert_eq!(fence_state().await.as_deref(), Some("aborted"));

    let operation = fixture.operation(&started).await;
    fixture
        .db
        .mutate_topology_operation(
            &operation.operation_id,
            operation.resource_version,
            "retry",
            "retry-deletion",
        )
        .await
        .unwrap();
    fixture
        .db
        .observe_surface_placement(fixture.placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    assert_eq!(fixture.run_controller().await.deleted, 1);
    assert!(!fixture.registry_exists().await);
}
