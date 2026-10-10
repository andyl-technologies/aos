//! Topology regression cases and contract checks.

use super::*;

#[test]
fn binding_read_sql_projects_only_non_sensitive_columns() {
    fn projected_columns(sql: &str) -> Vec<&str> {
        sql.split_once("FROM")
            .unwrap()
            .0
            .strip_prefix("SELECT")
            .unwrap()
            .split(',')
            .map(str::trim)
            .collect::<Vec<_>>()
    }
    assert_eq!(
        projected_columns(BINDING_READ_DETAIL_SQL),
        [
            "id",
            "org_id",
            "name",
            "kind",
            "is_instance_default",
            "stable_id",
            "owner_scope_key",
            "resource_version",
            "created_at",
            "updated_at",
        ],
    );
    assert_eq!(
        projected_columns(BINDING_READ_SUMMARY_SQL),
        [
            "id",
            "org_id",
            "name",
            "kind",
            "is_instance_default",
            "stable_id",
        ],
    );
    for sql in [BINDING_READ_DETAIL_SQL, BINDING_READ_SUMMARY_SQL] {
        for forbidden in [
            "local_root_path",
            "object_bucket",
            "object_prefix",
            "endpoint_scheme",
            "endpoint_host_kind",
            "endpoint_host_bytes",
            "endpoint_port",
            "signing_region",
            "access_mode",
            "secret_version_ref",
            "credential_fingerprint",
        ] {
            assert!(
                !sql.contains(forbidden),
                "read projection selected {forbidden}"
            );
        }
    }
}

#[tokio::test]
async fn instance_resources_require_explicit_organization_grants() {
    let db = Database::open_in_memory().await.unwrap();
    let binding = db
        .ensure_instance_default_binding(
            "deployment_r2",
            None,
            Some(aos_hub_model::binding::DEPLOYMENT_R2_ATTACHMENT),
        )
        .await
        .unwrap();
    let org_id = db
        .create_org("explicit-grants", "Explicit grants")
        .await
        .unwrap();
    let scope = db.org_by_id(org_id).await.unwrap().unwrap().stable_id;

    assert!(db
        .load_consumer_scope_grant(
            crate::db::GrantResource::NetworkPolicy {
                id: "instance:public"
            },
            &scope,
        )
        .await
        .unwrap()
        .is_none());
    assert!(db
        .list_bindings_available_to_scope(&scope)
        .await
        .unwrap()
        .is_empty());
    let registry_id = db
        .create_managed_registry(org_id, "", "main", "public", &[], false)
        .await
        .unwrap();
    let placement = NewSurfacePlacementSpec {
        surface: SurfaceTarget::Registry(registry_id),
        name: "primary".to_owned(),
        binding_id: binding.id,
        prefix: "explicit-grants/main".to_owned(),
        kind: "complete".to_owned(),
        desired_state: "active".to_owned(),
        hash_range: None,
        desired_read_enabled: true,
        read_order: 0,
        requires_conditional_writes: false,
    };
    assert!(db.create_surface_placement(&placement).await.is_err());

    db.grant_consumer_scope(
        crate::db::GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        &scope,
        "instance_default",
        "legacy-test",
        "request:legacy-binding-grant",
    )
    .await
    .unwrap();
    assert!(db.create_surface_placement(&placement).await.is_ok());

    let adopted = db
        .grant_consumer_scope(
            crate::db::GrantResource::Binding {
                id: binding.id,
                stable_id: &binding.stable_id,
            },
            &scope,
            "explicit",
            "test",
            "request:adopt-binding-grant",
        )
        .await
        .unwrap();
    assert_eq!(adopted.grant_generation, 1);
    assert_eq!(adopted.grant_kind, "explicit");

    let available = db.list_bindings_available_to_scope(&scope).await.unwrap();
    assert_eq!(available.len(), 1);
    assert_eq!(available[0].stable_id, binding.stable_id);
    assert_eq!(
        db.list_surface_placements(SurfaceTarget::Registry(registry_id))
            .await
            .unwrap()
            .len(),
        1
    );

    db.grant_consumer_scope(
        crate::db::GrantResource::NetworkPolicy {
            id: "instance:public",
        },
        &scope,
        "instance_default",
        "legacy-test",
        "request:legacy-network-grant",
    )
    .await
    .unwrap();
    let adopted = db
        .grant_consumer_scope(
            crate::db::GrantResource::NetworkPolicy {
                id: "instance:public",
            },
            &scope,
            "explicit",
            "test",
            "request:adopt-network-grant",
        )
        .await
        .unwrap();
    assert_eq!(adopted.grant_generation, 1);
    assert_eq!(adopted.grant_kind, "explicit");
}

#[tokio::test]
async fn unused_topology_binding_can_be_checked_and_deleted() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db
        .create_org("binding-owner", "Binding Owner")
        .await
        .unwrap();
    let binding_id = create_test_binding(&db, org, "archive", "objects").await;
    create_valid_write_credential(&db, binding_id, "native://archive/write/v1").await;

    assert!(db
        .binding_delete_blockers(binding_id)
        .await
        .unwrap()
        .is_empty());
    assert!(db.delete_topology_binding(binding_id, 1).await.unwrap());
    assert!(!db.delete_topology_binding(binding_id, 1).await.unwrap());
}

#[tokio::test]
async fn signed_images_require_complete_exact_placement_presence_and_remain_gc_roots() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("image-roots", "Image roots").await.unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "system", "public", &[], false)
        .await
        .unwrap();
    let binding_id = create_test_binding(&db, org_id, "images", "/tmp/image-roots").await;
    let mut placement =
        topology_placement(SurfaceTarget::Registry(registry_id), "primary", "system", 0);
    placement.binding_id = binding_id;
    let placement = db.create_surface_placement(&placement).await.unwrap();
    let placement = db
        .observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();

    let package = signed_image_package();
    let mut snapshot = IndexSnapshot {
        commit: "c".repeat(64),
        public_catalog_commit: Some("c".repeat(64)),
        public_catalog_release: Some("2026.8.0".into()),
        name: "AOS system".into(),
        packages: vec![package.clone()],
        releases: vec![ReleaseRow {
            semver: "2026.8.0".into(),
            tag_oid: "a".repeat(64),
            commit_oid: "c".repeat(64),
            signer: Some("release-signer".into()),
            tagged_at: Some(1),
            pack_present: true,
        }],
        release_images: vec![signed_image_release_snapshot(
            &package,
            "2026.8.0",
            &"c".repeat(64),
            &"a".repeat(64),
        )],
        channels: vec![ChannelSummary {
            name: "stable".into(),
            frontier: Some("2026.8.0".into()),
            partitions: vec![Some("2026.8.0".into()); 256],
        }],
        ..Default::default()
    };
    let identities = snapshot
        .release_images
        .iter()
        .flat_map(|release| &release.images)
        .flat_map(|image| {
            let disk = &image.delivery;
            [
                VerifiedRegistryImageObject {
                    object_key: disk.object_key.clone(),
                    sha256: disk.sha256.clone(),
                    byte_size: i64::try_from(disk.byte_size).unwrap(),
                    strong_etag: format!("\"snapshot-sha256-{}\"", disk.sha256),
                },
                VerifiedRegistryImageObject {
                    object_key: disk.artifact_contract.document.object_key.clone(),
                    sha256: disk.artifact_contract.document.sha256.clone(),
                    byte_size: i64::try_from(disk.artifact_contract.document.byte_size).unwrap(),
                    strong_etag: format!(
                        "\"snapshot-sha256-{}\"",
                        disk.artifact_contract.document.sha256
                    ),
                },
            ]
        })
        .collect::<Vec<_>>();
    db.lease_image_snapshot(
        "in-flight-index",
        &identities[0].sha256,
        identities[0].byte_size,
        unix_now() + 60,
    )
    .await
    .unwrap();
    db.lease_image_snapshot(
        "peer-index",
        &identities[0].sha256,
        identities[0].byte_size,
        unix_now() + 60,
    )
    .await
    .unwrap();
    assert!(
        db.lease_image_snapshot(
            "conflicting-size",
            &identities[0].sha256,
            identities[0].byte_size + 1,
            unix_now() + 60,
        )
        .await
        .is_err(),
        "one digest must never acquire two byte-size identities"
    );
    assert!(
        db.collectible_image_snapshots(100)
            .await
            .unwrap()
            .is_empty(),
        "an in-flight verified response must be protected before roots commit"
    );
    assert!(
        db.apply_snapshot_with_image_presence(
            registry_id,
            &snapshot,
            placement.id,
            &identities[..1],
            unix_now(),
        )
        .await
        .is_err(),
        "incomplete presence must not commit the release or channel"
    );
    assert!(db.list_releases(registry_id).await.unwrap().is_empty());
    assert!(
        db.list_system_images(registry_id).await.unwrap().is_empty(),
        "partial disk/metadata publication must not become discoverable"
    );

    db.apply_snapshot_with_image_presence(
        registry_id,
        &snapshot,
        placement.id,
        &identities,
        unix_now(),
    )
    .await
    .unwrap();

    let publication_id = "image-evidence-publication";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.into(),
        registry_id,
        generation: "image-evidence-generation".into(),
        manifest_digest: "e".repeat(64),
        refs_digest: "f".repeat(64),
        default_commit: Some(snapshot.commit.clone()),
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
        publication_id: publication_id.into(),
        placement_id: placement.id,
        required: true,
        state: "preparing".into(),
        observed_at: unix_now(),
    })
    .await
    .unwrap();
    for identity in &identities {
        let object = db
            .surface_object_named(SurfaceTarget::Registry(registry_id), &identity.object_key)
            .await
            .unwrap()
            .unwrap();
        db.set_registry_publication_object(&SetRegistryPublicationObject {
            publication_id: publication_id.into(),
            surface_object_id: object.id,
            object_kind: "immutable".into(),
            expected_hash: identity.sha256.clone(),
            expected_size: identity.byte_size,
        })
        .await
        .unwrap();
        db.record_registry_publication_object_presence(
            publication_id,
            object.id,
            placement.id,
            &identity.sha256,
            identity.byte_size,
            Some(&identity.strong_etag),
            unix_now(),
        )
        .await
        .unwrap();
    }
    db.backend
        .checked_batch(&[
            Statement::new(
                "UPDATE registry_publications
                     SET state = 'ready', completed_at = ?2
                     WHERE publication_id = ?1",
                vals![publication_id, unix_now()],
            )
            .expecting(1),
            Statement::new(
                "UPDATE registry_publication_placements
                     SET state = 'ready', observed_at = ?3
                     WHERE publication_id = ?1 AND placement_id = ?2",
                vals![publication_id, placement.id, unix_now()],
            )
            .expecting(1),
        ])
        .await
        .unwrap();
    let verified_before = db
        .registry_publication_verified_object_at_placement(
            publication_id,
            placement.id,
            &identities[0].object_key,
        )
        .await
        .unwrap();
    assert!(verified_before.is_some());

    db.apply_snapshot_with_image_presence(
        registry_id,
        &snapshot,
        placement.id,
        &identities,
        unix_now(),
    )
    .await
    .unwrap();
    let verified_after = db
        .registry_publication_verified_object_at_placement(
            publication_id,
            placement.id,
            &identities[0].object_key,
        )
        .await
        .unwrap();
    assert!(
        verified_after.is_some(),
        "derived image-presence replacement must preserve publication evidence"
    );

    assert_eq!(
        db.channel_floor(registry_id, "stable")
            .await
            .unwrap()
            .as_deref(),
        Some("2026.8.0"),
        "channel visibility and its anti-rollback floor commit together"
    );
    let events_before_rollback: i64 = db
        .backend
        .query_opt("SELECT COUNT(*) FROM topology_event_outbox", &[])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    let mut rollback = snapshot.clone();
    rollback.channels[0].frontier = Some("2026.7.0".into());
    rollback.channels[0].partitions = vec![Some("2026.7.0".into()); 256];
    assert!(
        db.apply_snapshot_with_image_presence(
            registry_id,
            &rollback,
            placement.id,
            &identities,
            unix_now(),
        )
        .await
        .is_err(),
        "a channel rollback must abort the complete snapshot transaction"
    );
    assert_eq!(
        db.list_channels(registry_id).await.unwrap()[0]
            .frontier
            .as_deref(),
        Some("2026.8.0"),
        "failed floor validation must not publish channel rows"
    );
    let events_after_rollback: i64 = db
        .backend
        .query_opt("SELECT COUNT(*) FROM topology_event_outbox", &[])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(
        events_after_rollback, events_before_rollback,
        "failed floor validation must not publish index or release events"
    );
    assert!(
        db.release_image_snapshot_lease("in-flight-index")
            .await
            .unwrap(),
        "presence completion releases only its own lease"
    );
    assert!(
        db.release_image_snapshot_lease("peer-index").await.unwrap(),
        "committing one index must not delete a concurrent index lease"
    );
    let root_keys = db.list_system_image_root_keys(registry_id).await.unwrap();
    assert_eq!(
        root_keys.len(),
        4,
        "two encodings root disk and metadata bytes"
    );
    let mut replica_spec = topology_placement(
        SurfaceTarget::Registry(registry_id),
        "replica",
        "replica",
        10,
    );
    replica_spec.binding_id = binding_id;
    let replica = db.create_surface_placement(&replica_spec).await.unwrap();
    let replica = db
        .observe_surface_placement(replica.id, "ready", "complete", 1)
        .await
        .unwrap();
    assert!(db
        .mark_index_empty_from_placement(registry_id, replica.id)
        .await
        .is_err());
    assert_eq!(
        db.index_status(registry_id).await.unwrap().unwrap().state,
        "fresh",
        "an empty replica must not clear authoritative discovery state"
    );
    db.record_registry_image_presence(registry_id, replica.id, &identities, unix_now())
        .await
        .unwrap();
    assert!(db
        .collectible_image_snapshots(100)
        .await
        .unwrap()
        .is_empty());
    let visible = db.list_system_images(registry_id).await.unwrap();
    assert_eq!(visible.len(), 2);
    let mut formats = visible
        .iter()
        .map(|image| image.format.as_str())
        .collect::<Vec<_>>();
    formats.sort_unstable();
    assert_eq!(formats, ["qcow2", "raw"]);

    let degraded = db
        .observe_surface_placement(placement.id, "degraded", "complete", 2)
        .await
        .unwrap();
    assert_eq!(
        db.list_system_images(registry_id).await.unwrap().len(),
        2,
        "canonical degraded complete placements remain readable"
    );
    let offline = db
        .update_surface_placement(
            degraded.id,
            &UpdateSurfacePlacementSpec {
                expected_version: degraded.resource_version,
                desired_state: "offline".into(),
                desired_read_enabled: true,
                read_order: degraded.read_order,
            },
        )
        .await
        .unwrap();
    assert!(
        db.list_system_images(registry_id).await.unwrap().len() == 2,
        "taking one placement offline must preserve a healthy verified replica"
    );
    db.update_surface_placement(
        offline.id,
        &UpdateSurfacePlacementSpec {
            expected_version: offline.resource_version,
            desired_state: "active".into(),
            desired_read_enabled: true,
            read_order: offline.read_order,
        },
    )
    .await
    .unwrap();
    assert_eq!(db.list_system_images(registry_id).await.unwrap().len(), 2);

    for key in root_keys {
        let object = db
            .surface_object_named(SurfaceTarget::Registry(registry_id), &key)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !db.tombstone_surface_object(object.id, object.resource_version, unix_now())
                .await
                .unwrap(),
            "signed release root {key} must be protected from GC"
        );
    }
    snapshot.release_images.clear();
    db.apply_snapshot_with_image_presence(registry_id, &snapshot, placement.id, &[], unix_now())
        .await
        .unwrap();
    assert_eq!(
        db.collectible_image_snapshots(100).await.unwrap().len(),
        4,
        "removing signed roots reconciles stale references on every placement"
    );
    db.mark_index_empty_from_placement(registry_id, placement.id)
        .await
        .unwrap();
    let empty = db.index_status(registry_id).await.unwrap().unwrap();
    assert_eq!(empty.state, "empty");
    assert!(empty.error.is_none());
    assert!(empty.last_indexed_commit.is_none());
    assert!(empty.name.is_none());
    assert!(empty.description.is_none());
    assert!(empty.readme.is_none());
    assert!(db.refs_digest(registry_id).await.unwrap().is_none());
    assert!(db
        .registry_cache_stack(registry_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(db.collectible_image_snapshots(100).await.unwrap().len(), 4);
    assert!(db.list_packages(registry_id).await.unwrap().is_empty());
    assert!(db.list_releases(registry_id).await.unwrap().is_empty());
    assert!(db.list_channels(registry_id).await.unwrap().is_empty());
    assert!(db.list_roster(registry_id).await.unwrap().is_empty());
    assert!(db
        .registry_cache_stack_entries(registry_id)
        .await
        .unwrap()
        .is_empty());
    assert!(db
        .list_system_image_root_keys(registry_id)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        db.channel_floor(registry_id, "stable")
            .await
            .unwrap()
            .as_deref(),
        Some("2026.8.0"),
        "emptying derived discovery must preserve system-of-record floors"
    );
}

#[tokio::test]
async fn topology_operation_retry_is_persistently_idempotent() {
    let db = Database::open_in_memory().await.unwrap();
    let now = unix_now();
    db.backend
        .checked_batch(&[Statement::new(
            "INSERT INTO topology_operations
                     (operation_id, operation_kind, authorization_scope_key,
                      control_permission, primary_target_kind, primary_target_stable_id,
                      primary_target_generation_key, state,
                      detail_json, error, created_at, started_at, finished_at,
                      resource_version)
                     VALUES ('retry-op', 'domain_probe', 'instance', 'domain.manage',
                       'domain', 'domain-1', 1, 'failed', '{}', 'transient',
                       ?1, ?1, ?1, 3)",
            vals![now],
        )
        .expecting(1)])
        .await
        .unwrap();

    let first = db
        .mutate_topology_operation("retry-op", 3, "retry", "retry-key")
        .await
        .unwrap();
    let replay = db
        .mutate_topology_operation("retry-op", 3, "retry", "retry-key")
        .await
        .unwrap();
    assert_eq!(first.state, "pending");
    assert_eq!(first.resource_version, 4);
    assert_eq!(replay.resource_version, first.resource_version);
    assert!(db
        .mutate_topology_operation("retry-op", 3, "cancel", "retry-key")
        .await
        .is_err());
}

#[tokio::test]
async fn bindings_use_only_the_typed_topology_shape() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let id = create_test_binding(&db, org, "primary", "/srv/aos-hub").await;
    let binding = db.binding(id).await.unwrap().unwrap();
    assert_eq!(binding.name, "primary");
    assert_eq!(binding.kind, "r2");
    assert_eq!(binding.local_root_path, None);
    assert_eq!(binding.object_bucket.as_deref(), Some("test-bucket"));
    assert_eq!(binding.object_prefix.as_deref(), Some("srv/aos-hub"));
    assert_eq!(binding.access_mode.as_deref(), Some("private"));
    assert_eq!(
        db.binding_by_name(org, "primary")
            .await
            .unwrap()
            .unwrap()
            .id,
        id
    );
    assert!(db.binding_by_name(org, "nope").await.unwrap().is_none());

    create_test_binding(&db, org, "secondary", "/srv/other").await;
    let all = db.list_bindings(org).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].name, "primary");
    assert_eq!(all[1].name, "secondary");
}

#[tokio::test]
async fn topology_regrant_cannot_race_a_soft_deleted_scope() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("race", "Race").await.unwrap();
    let scope = db.org_by_id(org_id).await.unwrap().unwrap().stable_id;
    db.grant_consumer_scope(
        crate::db::GrantResource::NetworkPolicy {
            id: "instance:public",
        },
        &scope,
        "explicit",
        "test",
        "request:grant-before-revoke",
    )
    .await
    .unwrap();
    db.revoke_consumer_scope(
        crate::db::GrantResource::NetworkPolicy {
            id: "instance:public",
        },
        &scope,
        1,
        "test",
        "request:revoke-before-delete",
    )
    .await
    .unwrap();
    db.soft_delete_org(org_id, 100).await.unwrap();
    assert!(db
        .grant_consumer_scope(
            crate::db::GrantResource::NetworkPolicy {
                id: "instance:public",
            },
            &scope,
            "explicit",
            "test",
            "request:forbidden-regrant",
        )
        .await
        .is_err());
    let events: i64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM consumer_scope_grant_events
                 WHERE request_id = 'request:forbidden-regrant'",
            &[],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(events, 0);
}

#[tokio::test]
async fn degraded_registry_placement_remains_eligible_for_publication_repair() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db
        .create_org("publication-repair", "Publication repair")
        .await
        .unwrap();
    let binding_id =
        create_test_binding(&db, org_id, "publication-repair", "/tmp/publication-repair").await;
    let registry_id = db
        .create_managed_registry(org_id, "", "registry", "public", &[], false)
        .await
        .unwrap();
    let mut placement = topology_placement(
        SurfaceTarget::Registry(registry_id),
        "canonical",
        "registry",
        0,
    );
    placement.binding_id = binding_id;
    let placement = db.create_surface_placement(&placement).await.unwrap();
    let write_generation =
        create_valid_write_credential(&db, binding_id, "secret://binding/publication-repair/v1")
            .await;
    let write_revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id,
            write_credential_generation: write_generation,
            writes_supported: true,
            conditional_writes_supported: false,
            revision_fingerprint: "publication-repair-write-v1".into(),
            capability_fingerprint: "publication-repair-writes".into(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding_id, write_revision.revision, "valid", None, None)
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(placement.id, write_revision.revision)
        .await
        .unwrap();

    let ready = db
        .observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    assert_eq!(
        db.registry_publication_write_placements(registry_id)
            .await
            .unwrap()
            .iter()
            .map(|placement| placement.id)
            .collect::<Vec<_>>(),
        vec![placement.id]
    );

    let degraded = db
        .observe_surface_placement(
            placement.id,
            "degraded",
            "partial",
            ready.observation_version.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        db.registry_publication_write_placements(registry_id)
            .await
            .unwrap()
            .iter()
            .map(|placement| placement.id)
            .collect::<Vec<_>>(),
        vec![placement.id]
    );

    db.observe_surface_placement(
        placement.id,
        "syncing",
        "unknown",
        degraded.observation_version.unwrap(),
    )
    .await
    .unwrap();
    assert!(db
        .registry_publication_write_placements(registry_id)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn registry_placement_delete_detaches_only_terminal_placement_history() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db
        .create_org("placement-delete", "Placement delete")
        .await
        .unwrap();
    let binding_id =
        create_test_binding(&db, org_id, "placement-delete", "/tmp/placement-delete").await;
    let registry_id = db
        .create_managed_registry(org_id, "", "registry", "public", &[], false)
        .await
        .unwrap();
    let mut placement = topology_placement(
        SurfaceTarget::Registry(registry_id),
        "retiring",
        "retiring",
        0,
    );
    placement.binding_id = binding_id;
    let placement = db.create_surface_placement(&placement).await.unwrap();
    let publication_id = "placementdeletepublication000000000001";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.into(),
        registry_id,
        generation: "placement-delete-generation".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: Some("c".repeat(64)),
        parent_publication_id: None,
    })
    .await
    .unwrap();
    let object = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: "objects/terminal".into(),
            content_hash: Some("d".repeat(64)),
            size: Some(9),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    db.set_registry_publication_object(&SetRegistryPublicationObject {
        publication_id: publication_id.into(),
        surface_object_id: object.id,
        object_kind: "immutable".into(),
        expected_hash: "d".repeat(64),
        expected_size: 9,
    })
    .await
    .unwrap();
    db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
        publication_id: publication_id.into(),
        placement_id: placement.id,
        required: true,
        state: "preparing".into(),
        observed_at: 1,
    })
    .await
    .unwrap();
    db.record_registry_publication_object_presence(
        publication_id,
        object.id,
        placement.id,
        &"d".repeat(64),
        9,
        Some("terminal-etag"),
        2,
    )
    .await
    .unwrap();

    assert!(!db
        .delete_registry_surface_placement(placement.id, placement.resource_version)
        .await
        .unwrap());
    assert!(db.surface_placement(placement.id).await.unwrap().is_some());
    assert_eq!(
        db.registry_publication_placement_records(publication_id)
            .await
            .unwrap()
            .len(),
        1
    );

    db.fail_registry_publication(publication_id, 3)
        .await
        .unwrap();
    db.backend
        .batch(&[
            Statement::new(
                "INSERT INTO placement_delivery_manifests
                     (manifest_id, placement_id, registry_id, kind,
                      registry_publication_id, content_digest, published_at)
                     VALUES ('terminal-manifest', ?1, ?2,
                       'registry_publication', ?3, ?4, 4)",
                vals![placement.id, registry_id, publication_id, "e".repeat(64)].to_vec(),
            ),
            Statement::new(
                "INSERT INTO placement_delivery_manifest_heads
                     (placement_id, registry_id, manifest_id, updated_at)
                     VALUES (?1, ?2, 'terminal-manifest', 4)",
                vals![placement.id, registry_id].to_vec(),
            ),
        ])
        .await
        .unwrap();

    let blockers = db.surface_placement_blockers(placement.id).await.unwrap();
    assert!(blockers.object_presence);
    assert!(blockers.publication);
    assert!(!blockers.active_publication);
    assert!(db
        .delete_registry_surface_placement(placement.id, placement.resource_version)
        .await
        .unwrap());
    assert!(db.surface_placement(placement.id).await.unwrap().is_none());
    assert!(db
        .registry_publication(publication_id)
        .await
        .unwrap()
        .is_some());
    assert!(db.surface_object(object.id).await.unwrap().is_some());
    assert!(db
        .registry_publication_placement_records(publication_id)
        .await
        .unwrap()
        .is_empty());
}
