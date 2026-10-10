//! Topology regression cases and contract checks.

use super::*;

#[tokio::test]
async fn topology_v34_opens_and_rejects_xor_and_location_collisions() {
    let db = Database::open_in_memory().await.unwrap();
    let version: i64 = db
        .backend
        .query_opt("SELECT version FROM schema_version", &[])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(version, MIGRATIONS.len() as i64);

    let org = db.create_org("topology", "Topology").await.unwrap();
    let binding = create_test_binding(&db, org, "placement", "/tmp/topology").await;
    let registry = db
        .create_managed_registry(org, "", "registry", "public", &[], false)
        .await
        .unwrap();
    let cache = db
        .create_binary_cache(
            Some(org),
            "topology-cache",
            "Topology cache",
            "public",
            10,
            "zstd",
            true,
        )
        .await
        .unwrap();

    let raw_xor = db
        .backend
        .execute(
            "INSERT INTO surface_placements (registry_id, cache_id, name,
                binding_id, prefix, kind, desired_state,
                desired_read_enabled, read_order, created_at, updated_at)
             VALUES (?1, ?2, 'invalid-xor', ?3, 'invalid-xor', 'complete',
                'active', 1, 0, ?4, ?4)",
            &vals![registry, cache, binding, unix_now()],
        )
        .await;
    assert!(
        raw_xor.is_err(),
        "database CHECK must reject a dual-surface row"
    );

    let mut first = topology_placement(SurfaceTarget::Registry(registry), "one", "same", 0);
    first.binding_id = binding;
    let first = db.create_surface_placement(&first).await.unwrap();
    let first = db
        .observe_surface_placement(first.id, "ready", "complete", 1)
        .await
        .unwrap();
    let mut duplicate_name =
        topology_placement(SurfaceTarget::Registry(registry), "one", "different", 1);
    duplicate_name.binding_id = binding;
    let error = db
        .create_surface_placement(&duplicate_name)
        .await
        .unwrap_err();
    assert_eq!(
        surface_placement_create_failure(&error).map(SurfacePlacementCreateFailure::kind),
        Some(SurfacePlacementCreateFailureKind::AlreadyExists)
    );
    let mut collision = topology_placement(SurfaceTarget::BinaryCache(cache), "two", "same", 1);
    collision.binding_id = binding;
    let error = db.create_surface_placement(&collision).await.unwrap_err();
    assert_eq!(
        surface_placement_create_failure(&error).map(SurfacePlacementCreateFailure::kind),
        Some(SurfacePlacementCreateFailureKind::Conflict),
        "physical-location aliases require a future reviewed equivalence workflow"
    );

    let mut second = topology_placement(
        SurfaceTarget::Registry(registry),
        "second-complete",
        "second-complete",
        3,
    );
    second.binding_id = binding;
    db.create_surface_placement(&second).await.unwrap();

    let write_generation =
        create_valid_write_credential(&db, binding, "secret://binding/write/v1").await;
    let revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id: binding,
            write_credential_generation: write_generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "binding-write-v1".to_string(),
            capability_fingerprint: "writes-and-conditional-writes".to_string(),
        })
        .await
        .unwrap();
    let revision_retry = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id: binding,
            write_credential_generation: write_generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "binding-write-v1".to_string(),
            capability_fingerprint: "writes-and-conditional-writes".to_string(),
        })
        .await
        .unwrap();
    assert_eq!(revision_retry, revision);
    db.observe_binding_write_revision(binding, revision.revision, "valid", None, None)
        .await
        .unwrap();
    let binding_write_state = db.binding_write_state(binding).await.unwrap().unwrap();
    let binding_write_state = db
        .set_current_binding_write_revision(
            binding,
            revision.revision,
            binding_write_state.resource_version,
        )
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(first.id, revision.revision)
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(first.id, revision.revision)
        .await
        .unwrap();
    let authority = db
        .create_surface_write_authority(
            SurfaceTarget::Registry(registry),
            "authority-registry-v1",
            first.id,
            first.resource_version,
            first.write_spec_version,
            revision.revision,
        )
        .await
        .unwrap();
    let authority_retry = db
        .create_surface_write_authority(
            SurfaceTarget::Registry(registry),
            "authority-registry-v1",
            first.id,
            first.resource_version,
            first.write_spec_version,
            revision.revision,
        )
        .await
        .unwrap();
    assert_eq!(authority_retry, authority);
    assert_eq!(authority.observed_placement_id, Some(first.id));
    assert!(
        db.surface_placement(first.id)
            .await
            .unwrap()
            .unwrap()
            .effective_write_enabled
    );

    let rotated_generation =
        create_valid_write_credential(&db, binding, "secret://binding/write/v2").await;
    let rotated_revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id: binding,
            write_credential_generation: rotated_generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "binding-write-v2".to_string(),
            capability_fingerprint: "writes-and-conditional-writes".to_string(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding, rotated_revision.revision, "valid", None, None)
        .await
        .unwrap();
    let binding_write_state = db
        .set_current_binding_write_revision(
            binding,
            rotated_revision.revision,
            binding_write_state.resource_version,
        )
        .await
        .unwrap();
    assert_eq!(
        binding_write_state.current_write_revision,
        Some(rotated_revision.revision)
    );
    db.bind_surface_placement_write_capability(first.id, rotated_revision.revision)
        .await
        .unwrap();
    let pending = db
        .request_surface_write_promotion(
            authority.id,
            &authority.incarnation_id,
            authority.resource_version,
            first.id,
            first.id,
            first.write_spec_version,
            rotated_revision.revision,
        )
        .await
        .unwrap();
    assert_eq!(pending.reconciliation_state, "pending");
    assert_eq!(
        db.pending_surface_write_authorities(1).await.unwrap(),
        vec![pending.clone()]
    );
    assert!(
        !db.surface_placement(first.id)
            .await
            .unwrap()
            .unwrap()
            .effective_write_enabled
    );
    let cancelled = db
        .cancel_surface_write_promotion(pending.id, pending.resource_version)
        .await
        .unwrap();
    assert_eq!(cancelled.desired_binding_write_revision, revision.revision);
    let restored = db
        .confirm_surface_write_authority(
            cancelled.id,
            cancelled.resource_version,
            cancelled.desired_generation,
        )
        .await
        .unwrap();
    assert!(db
        .pending_surface_write_authorities(1)
        .await
        .unwrap()
        .is_empty());
    let _pending = db
        .request_surface_write_promotion(
            restored.id,
            &restored.incarnation_id,
            restored.resource_version,
            first.id,
            first.id,
            first.write_spec_version,
            rotated_revision.revision,
        )
        .await
        .unwrap();
    assert!(db
        .retire_binding_write_revision(binding, revision.revision)
        .await
        .is_err());
    let pending = db.pending_surface_write_authorities(1).await.unwrap();
    assert_eq!(pending.len(), 1);
    for authority in pending {
        db.confirm_surface_write_authority(
            authority.id,
            authority.resource_version,
            authority.desired_generation,
        )
        .await
        .unwrap();
    }
    let rotated = db
        .surface_write_authority_by_id(authority.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rotated.observed_binding_write_revision,
        Some(rotated_revision.revision)
    );
    assert!(db
        .retire_binding_write_revision(binding, revision.revision)
        .await
        .unwrap());
    assert!(!db
        .remove_surface_write_authority(
            rotated.id,
            &rotated.incarnation_id,
            rotated.resource_version,
            rotated.observed_generation.unwrap() + 1,
        )
        .await
        .unwrap());
    assert!(db
        .remove_surface_write_authority(
            rotated.id,
            &rotated.incarnation_id,
            rotated.resource_version,
            rotated.observed_generation.unwrap(),
        )
        .await
        .unwrap());
    let replacement = db
        .create_surface_write_authority(
            SurfaceTarget::Registry(registry),
            "authority-registry-replacement",
            first.id,
            first.resource_version,
            first.write_spec_version,
            rotated_revision.revision,
        )
        .await
        .unwrap();
    assert!(!db
        .remove_surface_write_authority(
            rotated.id,
            &rotated.incarnation_id,
            rotated.resource_version,
            rotated.observed_generation.unwrap(),
        )
        .await
        .unwrap());
    assert_eq!(
        db.surface_write_authority(SurfaceTarget::Registry(registry))
            .await
            .unwrap()
            .unwrap()
            .incarnation_id,
        replacement.incarnation_id
    );
    assert!(db
        .remove_surface_write_authority(
            replacement.id,
            &replacement.incarnation_id,
            replacement.resource_version,
            replacement.observed_generation.unwrap(),
        )
        .await
        .unwrap());
    assert!(
        !db.surface_placement(first.id)
            .await
            .unwrap()
            .unwrap()
            .effective_write_enabled
    );
    let drained = db
        .update_surface_placement(
            first.id,
            &UpdateSurfacePlacementSpec {
                expected_version: first.resource_version,
                desired_state: "draining".to_string(),
                desired_read_enabled: false,
                read_order: first.read_order,
            },
        )
        .await
        .unwrap();
    assert_eq!(drained.desired_state, "draining");
    assert_eq!(drained.write_spec_version, first.write_spec_version + 1);
    assert!(db
        .create_surface_write_authority(
            SurfaceTarget::Registry(registry),
            "authority-registry-v2",
            first.id,
            first.resource_version,
            first.write_spec_version,
            rotated_revision.revision,
        )
        .await
        .is_err());

    let mut conditional = topology_placement(
        SurfaceTarget::BinaryCache(cache),
        "conditional-writer",
        "conditional-writer",
        4,
    );
    conditional.binding_id = binding;
    conditional.requires_conditional_writes = true;
    let conditional = db.create_surface_placement(&conditional).await.unwrap();
    let conditional = db
        .observe_surface_placement(conditional.id, "ready", "complete", 1)
        .await
        .unwrap();
    let ordinary_generation =
        create_valid_write_credential(&db, binding, "secret://binding/write/v3").await;
    let ordinary_only = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id: binding,
            write_credential_generation: ordinary_generation,
            writes_supported: true,
            conditional_writes_supported: false,
            revision_fingerprint: "binding-write-ordinary".to_string(),
            capability_fingerprint: "ordinary-writes".to_string(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding, ordinary_only.revision, "valid", None, None)
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(conditional.id, ordinary_only.revision)
        .await
        .unwrap();
    assert!(db
        .create_surface_write_authority(
            SurfaceTarget::BinaryCache(cache),
            "authority-cache-v1",
            conditional.id,
            conditional.resource_version,
            conditional.write_spec_version,
            ordinary_only.revision,
        )
        .await
        .is_err());

    let mut invalid_shard = topology_placement(
        SurfaceTarget::BinaryCache(cache),
        "invalid-shard",
        "invalid-shard",
        5,
    );
    invalid_shard.binding_id = binding;
    invalid_shard.kind = "shard".to_string();
    for range in [
        None,
        Some(SurfacePlacementHashRange { start: -1, end: 1 }),
        Some(SurfacePlacementHashRange { start: 1, end: 1 }),
        Some(SurfacePlacementHashRange {
            start: 0,
            end: 65_537,
        }),
    ] {
        invalid_shard.hash_range = range;
        let error = db
            .create_surface_placement(&invalid_shard)
            .await
            .unwrap_err();
        assert_eq!(
            surface_placement_create_failure(&error).map(SurfacePlacementCreateFailure::kind),
            Some(SurfacePlacementCreateFailureKind::InvalidArgument)
        );
    }
    invalid_shard.kind = "complete".to_string();
    invalid_shard.hash_range = Some(SurfacePlacementHashRange { start: 0, end: 1 });
    let error = db
        .create_surface_placement(&invalid_shard)
        .await
        .unwrap_err();
    assert_eq!(
        surface_placement_create_failure(&error).map(SurfacePlacementCreateFailure::kind),
        Some(SurfacePlacementCreateFailureKind::InvalidArgument)
    );

    let mut invalid = second.clone();
    invalid.name = "invalid-kind".to_string();
    invalid.prefix = "invalid-kind".to_string();
    invalid.kind = "writer".to_string();
    let error = db.create_surface_placement(&invalid).await.unwrap_err();
    assert_eq!(
        surface_placement_create_failure(&error).map(SurfacePlacementCreateFailure::kind),
        Some(SurfacePlacementCreateFailureKind::InvalidArgument)
    );

    db.backend
        .execute(
            "CREATE TRIGGER reject_placement_infrastructure
                 BEFORE INSERT ON surface_placements
                 BEGIN SELECT RAISE(ABORT, 'injected infrastructure failure'); END",
            &[],
        )
        .await
        .unwrap();
    let mut infrastructure = second;
    infrastructure.name = "infrastructure-error".to_string();
    infrastructure.prefix = "infrastructure-error".to_string();
    let error = db
        .create_surface_placement(&infrastructure)
        .await
        .unwrap_err();
    assert!(
        surface_placement_create_failure(&error).is_none(),
        "infrastructure failures must remain unclassified and internal"
    );
}

#[tokio::test]
async fn topology_orders_named_placements_and_rejects_stale_versions() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("ordered", "Ordered").await.unwrap();
    let binding = create_test_binding(&db, org, "ordered", "/tmp/ordered").await;
    let registry = db
        .create_managed_registry(org, "", "registry", "public", &[], false)
        .await
        .unwrap();
    for (name, prefix, order) in [
        ("zeta", "zeta", 0),
        ("alpha", "alpha", 0),
        ("middle", "middle", 1),
    ] {
        let mut input = topology_placement(SurfaceTarget::Registry(registry), name, prefix, order);
        input.binding_id = binding;
        db.create_surface_placement(&input).await.unwrap();
    }
    for (name, prefix) in [("binding-root", ""), ("alpha-child", "alpha/child")] {
        let mut conflicting =
            topology_placement(SurfaceTarget::Registry(registry), name, prefix, 2);
        conflicting.binding_id = binding;
        assert!(db.create_surface_placement(&conflicting).await.is_err());
    }
    let placements = db
        .list_surface_placements(SurfaceTarget::Registry(registry))
        .await
        .unwrap();
    assert_eq!(
        placements
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "zeta", "middle"]
    );
    assert!(
        db.assert_registry_index_mutation_source(registry, Some(placements[1].id))
            .await
            .is_err(),
        "a replica without reconciled authority cannot replace retention roots"
    );
    let selected = &placements[0];
    let update = UpdateSurfacePlacementSpec {
        expected_version: selected.resource_version,
        desired_state: selected.desired_state.clone(),
        desired_read_enabled: selected.desired_read_enabled,
        read_order: selected.read_order,
    };
    let updated = db
        .update_surface_placement(selected.id, &update)
        .await
        .unwrap();
    assert_eq!(updated.resource_version, selected.resource_version + 1);
    assert!(db
        .update_surface_placement(selected.id, &update)
        .await
        .is_err());

    let owner = db.org_by_id(org).await.unwrap().unwrap();
    let binding = db.binding(binding).await.unwrap().unwrap();
    let defaults = db
        .set_stable_topology_defaults(
            "organization",
            Some(org),
            &owner.stable_id,
            Some(&binding.stable_id),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(db
        .set_stable_topology_defaults(
            "organization",
            Some(org),
            &owner.stable_id,
            Some(&binding.stable_id),
            None,
            None,
            None,
            None,
            None,
            Some(defaults.resource_version + 1),
        )
        .await
        .is_err());
}
