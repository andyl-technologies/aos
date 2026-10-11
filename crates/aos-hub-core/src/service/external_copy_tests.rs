//! Actual service scheduling and SQL controller-claim projections for copy controls.

use crate::db::{GrantResource, NewSurfacePlacementSpec, SurfaceTarget};
use crate::domain::Permission;
use crate::storage_authority::external_object::copy::{CopyPlacementPin, CopyTopologyOriginal};

#[tokio::test]
async fn scheduled_copy_preserves_actual_permission_and_live_sql_claim() {
    let (service, db) = super::cache_upload_tests::delivery_test_service().await;
    let org_id = db.create_org("copy-claim", "Copy claim").await.unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "system", "public", &[], false)
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
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    db.grant_consumer_scope(
        GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        &org.stable_id,
        "explicit",
        "fixture",
        "request:copy-claim-binding-grant",
    )
    .await
    .unwrap();
    let spec = |name: &str| NewSurfacePlacementSpec {
        surface: SurfaceTarget::Registry(registry_id),
        name: name.into(),
        binding_id: binding.id,
        prefix: format!("copy-claim/{name}"),
        kind: "complete".into(),
        desired_state: "active".into(),
        hash_range: None,
        desired_read_enabled: true,
        read_order: 0,
        requires_conditional_writes: false,
    };
    let source = db.create_surface_placement(&spec("source")).await.unwrap();
    let destination = db
        .create_surface_placement(&spec("destination"))
        .await
        .unwrap();

    // Exercise the real service scheduler rather than supplying permission or
    // operation fields to the copy projection. Public authorization is tested
    // by the existing reviewed-operation gates, separately from this fixture.
    let scheduled = service
        .schedule_placement_operation(
            "replicate_placement",
            "copy-claim-original",
            vec![
                ("source".into(), source.clone()),
                ("primary".into(), destination.clone()),
            ],
        )
        .await
        .unwrap()
        .operation
        .unwrap();
    let pending = db
        .topology_operation(&scheduled.operation_id)
        .await
        .unwrap()
        .unwrap();
    let token = "a".repeat(32);
    let claimed = db
        .claim_surface_placement_scan_operation(
            &pending.operation_id,
            pending.resource_version,
            &token,
            60,
        )
        .await
        .unwrap()
        .unwrap();
    let targets = db
        .topology_operation_targets(&claimed.operation_id)
        .await
        .unwrap();
    let source_target = targets
        .iter()
        .find(|target| target.role == "source")
        .unwrap();
    let destination_target = targets
        .iter()
        .find(|target| target.role == "primary")
        .unwrap();
    let original =
        CopyTopologyOriginal::from_records(&claimed, source_target, destination_target).unwrap();
    assert_eq!(
        original.control_permission,
        Permission::StorageManage.as_str()
    );
    assert_eq!(
        original.source.control_permission,
        Permission::PlacementManage.as_str()
    );
    assert_eq!(
        original.destination.control_permission,
        original.control_permission
    );

    // Resolve each stable target independently before projecting either SQL row.
    let resolved_source = db
        .surface_placement_by_operation_target(&source_target.stable_id)
        .await
        .unwrap()
        .unwrap();
    let resolved_destination = db
        .surface_placement_by_operation_target(&destination_target.stable_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resolved_source.id, source.id);
    assert_eq!(resolved_destination.id, destination.id);
    assert_eq!(
        CopyPlacementPin::from_record(&resolved_source, &original.source)
            .unwrap()
            .placement_id
            .get(),
        source.id
    );
    assert_eq!(
        CopyPlacementPin::from_record(&resolved_destination, &original.destination)
            .unwrap()
            .placement_id
            .get(),
        destination.id
    );

    let now = crate::clock::now_unix_secs();
    let actual = db
        .placement_copy_claim(&claimed, &token, now)
        .await
        .unwrap();
    assert_eq!(
        actual.operation_resource_version.get(),
        claimed.resource_version
    );
    assert_eq!(actual.claim_token, token);
    assert!(actual.expires_at.get() > now);
    assert!(db
        .placement_copy_claim(&claimed, &"b".repeat(32), now)
        .await
        .is_err());
    assert!(db
        .placement_copy_claim(&claimed, &token, actual.expires_at.get())
        .await
        .is_err());
    let mut stale = claimed.clone();
    stale.resource_version += 1;
    assert!(db.placement_copy_claim(&stale, &token, now).await.is_err());
    assert!(db
        .placement_copy_claim(&pending, &token, now)
        .await
        .is_err());
}
