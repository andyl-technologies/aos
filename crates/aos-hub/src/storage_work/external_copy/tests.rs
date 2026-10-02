//! Actual SQL target/claim checks before any provider copy control.

use aos_hub_core::{
    db::{
        Database, NewBindingWriteRevision, NewSurfacePlacementSpec, NewTopologyOperation,
        NewTopologyOperationTarget, NewTopologyOperationTargetRef, SurfaceTarget,
    },
    domain::Permission,
};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

use super::*;

#[path = "tests/connected.rs"]
mod connected;

#[path = "tests/telemetry.rs"]
mod telemetry;

const MATERIAL: &[u8] = b"fixture-access:fixture-secret:fixture-region";

#[tokio::test]
async fn protected_retained_copy_refuses_lost_current_sql_size() {
    use aos_hub_core::backend::{Backend as _, SqlxBackend, Statement};
    use aos_hub_core::value::Value;

    let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
    let SqlxBackend::Sqlite(pool) = &backend else {
        panic!("fixture must use SQLite");
    };
    let database = Arc::new(
        Database::with_backend(Box::new(SqlxBackend::Sqlite(pool.clone())))
            .await
            .unwrap(),
    );
    let (writer, _, source, _, _) = fixture_with_database(database).await;
    let surface = SurfaceTarget::Registry(source.registry_id.unwrap());
    let input = aos_hub_core::db::SetSurfaceObject {
        surface,
        object_key: "nar/retained-size.nar".into(),
        content_hash: Some("a".repeat(64)),
        size: Some(11),
        object_kind: "immutable".into(),
        mutable_publication_id: None,
    };
    writer.db.create_surface_object(&input).await.unwrap();
    let original = writer
        .copy_catalogue(&source, &input.object_key)
        .await
        .unwrap()
        .unwrap();
    require_retained_catalogue_size(2, 11, Some(&original)).unwrap();

    // Deliberately lose only the trusted size on the exact current SQL row.
    // This mutation supplies no physical observation or provider authority.
    backend
        .checked_batch(&[Statement::new(
            "UPDATE surface_objects SET size = NULL, resource_version = resource_version + 1
         WHERE id = ?1 AND resource_version = ?2 AND object_key = ?3",
            vec![
                Value::Int(original.id),
                Value::Int(original.resource_version),
                Value::Text(original.object_key.clone()),
            ],
        )
        .expecting(1)])
        .await
        .unwrap();
    let changed = writer
        .copy_catalogue(&source, &input.object_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed.id, original.id);
    assert_eq!(changed.content_hash, original.content_hash);
    assert_eq!(changed.size, None);
    assert!(require_retained_catalogue_size(2, 11, Some(&changed)).is_err());
    assert!(require_retained_catalogue_size(2, 11, None).is_err());
    assert!(require_retained_catalogue_size(2, 12, Some(&original)).is_err());
    require_retained_catalogue_size(1, 11, Some(&changed)).unwrap();
}

async fn fixture() -> (
    HybridSurfaceWrites,
    TopologyOperationRecord,
    SurfacePlacementRecord,
    SurfacePlacementRecord,
    String,
) {
    fixture_with_database(Arc::new(Database::open_in_memory().await.unwrap())).await
}

async fn fixture_with_database(
    db: Arc<Database>,
) -> (
    HybridSurfaceWrites,
    TopologyOperationRecord,
    SurfacePlacementRecord,
    SurfacePlacementRecord,
    String,
) {
    let org = db
        .create_org("connected-copy", "Connected copy")
        .await
        .unwrap();
    let owner = db.org_by_id(org).await.unwrap().unwrap();
    let registry = db
        .create_managed_registry(org, "", "system", "public", &[], false)
        .await
        .unwrap();
    let binding = db
        .create_topology_binding(
            Some(org),
            "connected-copy-binding",
            &owner.stable_id,
            "Copy fixture",
            "s3",
            None,
            Some("fixture-bucket"),
            Some("managed/binding"),
            Some("https"),
            Some("dns"),
            Some(b"s3.fleet.test"),
            Some(443),
            Some("fixture-region"),
            Some("private"),
        )
        .await
        .unwrap();
    for purpose in ["read", "write", "list"] {
        let revision = db
            .set_binding_credential_revision(
                binding,
                purpose,
                &format!("secret://connected-copy/{purpose}/v1"),
                0,
                &hex::encode(Sha256::digest(MATERIAL)),
                "fixture",
            )
            .await
            .unwrap();
        db.validate_binding_credential_revision(
            binding,
            purpose,
            revision.generation,
            "valid",
            None,
            revision.head_resource_version,
        )
        .await
        .unwrap();
    }
    let revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id: binding,
            write_credential_generation: 1,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "fixture-writer".into(),
            capability_fingerprint: "fixture-copy".into(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding, revision.revision, "valid", None, None)
        .await
        .unwrap();
    let placement = |name: &str| NewSurfacePlacementSpec {
        surface: SurfaceTarget::Registry(registry),
        name: name.into(),
        binding_id: binding,
        prefix: format!("objects/{name}"),
        kind: "complete".into(),
        desired_state: "active".into(),
        hash_range: None,
        desired_read_enabled: true,
        read_order: 0,
        requires_conditional_writes: true,
    };
    let source = db
        .create_surface_placement(&placement("source"))
        .await
        .unwrap();
    let source = db
        .observe_surface_placement(
            source.id,
            "ready",
            "complete",
            source.observation_version.unwrap(),
        )
        .await
        .unwrap();
    let destination = db
        .create_surface_placement(&placement("destination"))
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(destination.id, revision.revision)
        .await
        .unwrap();
    let target = |role: &str, row: &SurfacePlacementRecord| NewTopologyOperationTarget {
        role: role.into(),
        target: NewTopologyOperationTargetRef::Placement(row.id),
        generation_key: row.resource_version,
        configuration_digest: String::new(),
    };
    let pending = db
        .create_topology_operation(&NewTopologyOperation {
            operation_id: "connected-scheduled-copy".into(),
            operation_kind: "replicate_placement".into(),
            control_permission: Permission::StorageManage,
            targets: vec![target("source", &source), target("primary", &destination)],
            detail_json: "{\"phase\":\"pending\"}".into(),
            progress_total: None,
        })
        .await
        .unwrap();
    let token = "a".repeat(32);
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
    let work = Arc::new(
        RemoteStorageWorkClient::new(
            "https://worker.example",
            "fixture-deployment".into(),
            b"connected-copy-application-key-independent",
        )
        .unwrap(),
    );
    (
        HybridSurfaceWrites::new(db, work),
        running,
        source,
        destination,
        token,
    )
}

#[tokio::test]
async fn actual_resolved_rows_and_live_claim_precede_all_remote_copy_controls() {
    let (writer, operation, source, destination, token) = fixture().await;
    let current = writer
        .current_copy(&operation, &source, &destination, true)
        .await
        .unwrap();
    assert_eq!(current.source.placement_id.get(), source.id);
    assert_eq!(current.destination.placement_id.get(), destination.id);
    assert_eq!(
        current.topology.control_permission,
        Permission::StorageManage.as_str()
    );
    assert_eq!(
        current.topology.source.control_permission,
        Permission::PlacementManage.as_str()
    );
    assert_eq!(
        writer
            .recheck_copy(&current, &operation, &token, &source, &destination)
            .await
            .unwrap()
            .claim_token,
        token
    );
    assert!(writer
        .recheck_copy(&current, &operation, &"b".repeat(32), &source, &destination)
        .await
        .is_err());

    // These rows can have the same generation. Their independently resolved
    // stable targets still forbid exchanging source and destination identities.
    assert_eq!(source.resource_version, destination.resource_version);
    assert!(writer
        .current_copy(&operation, &destination, &source, true)
        .await
        .is_err());
    let mut stale = source.clone();
    stale.prefix = "objects/replacement".into();
    assert!(writer
        .current_copy(&operation, &stale, &destination, true)
        .await
        .is_err());
    let mut forged = operation.clone();
    forged.control_permission = Permission::BindingManage.as_str().into();
    assert!(writer
        .current_copy(&forged, &source, &destination, true)
        .await
        .is_err());

    // A current validated read generation is compared to the acknowledged
    // snapshot before signing. SQL does not supply material to this adapter.
    let changed = writer
        .db
        .set_binding_credential_revision(
            current.binding.id,
            "read",
            "secret://connected-copy/read/v2",
            1,
            &"b".repeat(64),
            "fixture",
        )
        .await
        .unwrap();
    assert_eq!(changed.validation_state, "unknown");
    assert!(writer
        .check_snapshot(&current, &"c".repeat(64))
        .await
        .is_err());
}
