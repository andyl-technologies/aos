//! Reviewed public replication and repair scheduling in the controlled pair.
//!
//! These helpers call the existing APIs and retain their actual SQL targets.
//! They do not seed a successful operation, presence or provider receipt.

use super::*;
use aos_hub_core::service::RpcService;
use aos_proto_types::hub_v1 as pb;

async fn surface(db: &Database, source: &SurfacePlacementRecord) -> pb::SurfaceRef {
    let registry = db
        .registry_by_id(source.registry_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    pb::SurfaceRef {
        target: Some(pb::surface_ref::Target::RegistrySlug(registry.slug)),
    }
}

pub(super) async fn replicate_claim(
    db: &Database,
    rpc: &RpcService,
    auth: &str,
    source: &SurfacePlacementRecord,
    destination: &SurfacePlacementRecord,
) -> (TopologyOperationRecord, String, SurfacePlacementRecord) {
    let plan = rpc
        .plan_replicate_placement(
            Some(auth),
            pb::PlanReplicatePlacementRequest {
                surface: Some(surface(db, source).await),
                source_placement_name: source.name.clone(),
                destination_placement_name: destination.name.clone(),
                idempotency_key: "paired-replicate-plan".into(),
                expected_resource_version: destination.resource_version.to_string(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let reply = rpc
        .replicate_placement(
            Some(auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: plan.plan_id,
                confirmation_hash: plan.confirmation_hash,
                idempotency_key: "paired-replicate-apply".into(),
            },
        )
        .await
        .unwrap()
        .operation
        .unwrap();
    let pending = db
        .topology_operation(&reply.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.operation_kind, "replicate_placement");
    let token = uuid::Uuid::new_v4().simple().to_string();
    let running = db
        .claim_surface_placement_scan_operation(
            &pending.operation_id,
            pending.resource_version,
            &token,
            600,
        )
        .await
        .unwrap()
        .unwrap();
    let destination = db.surface_placement(destination.id).await.unwrap().unwrap();
    (running, token, destination)
}

pub(super) async fn repair_incomplete_target(
    db: &Database,
    rpc: &RpcService,
    auth: &str,
    source: &SurfacePlacementRecord,
    destination: &SurfacePlacementRecord,
    controller: &PlacementScanController,
) -> String {
    let target = db
        .create_surface_placement(&aos_hub_core::db::NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(source.registry_id.unwrap()),
            name: "independent-repair-target".into(),
            binding_id: destination.binding_id,
            prefix: "objects/repair-target".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 1,
            requires_conditional_writes: true,
        })
        .await
        .unwrap();
    assert_ne!(target.prefix, destination.prefix);
    assert_ne!(target.state, "ready");
    let plan = rpc
        .plan_repair_placement(
            Some(auth),
            pb::PlanRepairPlacementRequest {
                surface: Some(surface(db, source).await),
                placement_name: target.name.clone(),
                source_placement_name: source.name.clone(),
                idempotency_key: "paired-repair-plan".into(),
                expected_resource_version: target.resource_version.to_string(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let reply = rpc
        .repair_placement(
            Some(auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: plan.plan_id,
                confirmation_hash: plan.confirmation_hash,
                idempotency_key: "paired-repair-apply".into(),
            },
        )
        .await
        .unwrap()
        .operation
        .unwrap();
    assert_eq!(controller.run_due(1).await.unwrap(), 1);
    let settled = db
        .topology_operation(&reply.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        settled.state,
        "succeeded",
        "{}",
        settled.error.unwrap_or_default()
    );
    let presence = db
        .list_object_presence(
            SurfaceTarget::Registry(source.registry_id.unwrap()),
            "nar/source.nar",
        )
        .await
        .unwrap();
    assert!(presence
        .iter()
        .any(|row| row.placement_name == target.name && row.state == "present"));
    settled.operation_id
}
