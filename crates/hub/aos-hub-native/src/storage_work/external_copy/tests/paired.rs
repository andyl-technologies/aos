//! Independent current source Read and destination Write SQL authority tests.
//!
//! These tests select real database bindings, placements and sealed claims.
//! They make no provider call or installed-domain qualification claim.

use super::*;

pub(super) async fn fixture() -> (
    HybridSurfaceWrites,
    TopologyOperationRecord,
    SurfacePlacementRecord,
    SurfacePlacementRecord,
    String,
) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    fixture_with_database(db).await
}

pub(super) async fn fixture_with_database(
    db: Arc<Database>,
) -> (
    HybridSurfaceWrites,
    TopologyOperationRecord,
    SurfacePlacementRecord,
    SurfacePlacementRecord,
    String,
) {
    let (writer, _, old_source, destination, _) = super::fixture_with_database(db.clone()).await;
    let old_binding = db.binding(old_source.binding_id).await.unwrap().unwrap();
    let binding = db
        .create_topology_binding(
            old_binding.org_id,
            "independent-copy-source",
            &old_binding.owner_scope_key,
            "Independent Read source",
            "s3",
            None,
            Some("fixture-bucket"),
            Some("managed/source-binding"),
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
            revision_fingerprint: "independent-source-writer".into(),
            capability_fingerprint: "controlled-source-copy".into(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding, revision.revision, "valid", None, None)
        .await
        .unwrap();
    let source = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(old_source.registry_id.unwrap()),
            name: "independent-source".into(),
            binding_id: binding,
            prefix: "objects/source".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
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
    let target = |role: &str, row: &SurfacePlacementRecord| NewTopologyOperationTarget {
        role: role.into(),
        target: NewTopologyOperationTargetRef::Placement(row.id),
        generation_key: row.resource_version,
        configuration_digest: String::new(),
    };
    let operation = db
        .create_topology_operation(&NewTopologyOperation {
            operation_id: "independent-scheduled-copy".into(),
            operation_kind: "replicate_placement".into(),
            control_permission: Permission::StorageManage,
            targets: vec![target("source", &source), target("primary", &destination)],
            detail_json: "{\"phase\":\"pending\"}".into(),
            progress_total: None,
        })
        .await
        .unwrap();
    let token = "b".repeat(32);
    let operation = db
        .claim_surface_placement_scan_operation(
            &operation.operation_id,
            operation.resource_version,
            &token,
            600,
        )
        .await
        .unwrap()
        .unwrap();
    (writer, operation, source, destination, token)
}

#[tokio::test]
async fn current_copy_resolves_independent_read_binding_and_grant() {
    let (writer, operation, source, destination, token) = fixture().await;
    let current = writer
        .current_copy(&operation, &source, &destination, true)
        .await
        .unwrap();
    assert_ne!(current.source_binding.id, current.binding.id);
    assert_ne!(current.source_binding.stable_id, current.binding.stable_id);
    assert_ne!(
        current.source_grant.resource_stable_id,
        current.grant.resource_stable_id
    );
    assert_eq!(current.source_binding.id, source.binding_id);
    assert_eq!(current.binding.id, destination.binding_id);
    assert_eq!(
        writer
            .recheck_copy(&current, &operation, &token, &source, &destination)
            .await
            .unwrap()
            .claim_token,
        token
    );

    let mut substituted = source.clone();
    substituted.binding_id = destination.binding_id;
    assert!(writer
        .current_copy(&operation, &substituted, &destination, true)
        .await
        .is_err());
}

#[tokio::test]
async fn independent_source_state_and_grant_cannot_borrow_destination_pins() {
    let (writer, operation, source, destination, _) = fixture().await;
    let current = writer
        .current_copy(&operation, &source, &destination, true)
        .await
        .unwrap();
    let mut substituted = writer
        .current_copy(&operation, &source, &destination, true)
        .await
        .unwrap();
    substituted.source_binding = substituted.binding.clone();
    assert!(compare_current(&current, &substituted).is_err());
    let mut substituted = writer
        .current_copy(&operation, &source, &destination, true)
        .await
        .unwrap();
    substituted.source_grant = substituted.grant.clone();
    assert!(compare_current(&current, &substituted).is_err());
    let mut substituted = writer
        .current_copy(&operation, &source, &destination, true)
        .await
        .unwrap();
    substituted.source_grant.resource_version += 1;
    assert!(compare_current(&current, &substituted).is_err());
}
