//! Releases regression cases and contract checks.

use super::*;

#[tokio::test]
async fn channel_floors_persist_and_overwrite() {
    let db = Database::open_in_memory().await.unwrap();
    let id = db.register_registry("demo", &[], false).await.unwrap();
    assert!(db.channel_floor(id, "stable").await.unwrap().is_none());
    db.set_channel_floor(id, "stable", "1.0.0").await.unwrap();
    db.set_channel_floor(id, "stable", "1.2.0").await.unwrap();
    assert_eq!(
        db.channel_floor(id, "stable").await.unwrap().as_deref(),
        Some("1.2.0")
    );
}

#[tokio::test]
async fn update_channels_replaces_only_channels() {
    let db = Database::open_in_memory().await.unwrap();
    let id = db.register_registry("demo", &[], false).await.unwrap();
    let snapshot = IndexSnapshot {
        commit: "c".repeat(64),
        name: "demo".into(),
        releases: vec![ReleaseRow {
            semver: "1.0.0".into(),
            tag_oid: "t".repeat(64),
            commit_oid: "c".repeat(64),
            signer: None,
            tagged_at: Some(1),
            pack_present: false,
        }],
        channels: vec![ChannelSummary {
            name: "stable".into(),
            frontier: Some("1.0.0".into()),
            partitions: vec![Some("1.0.0".into()); 256],
        }],
        ..Default::default()
    };
    db.apply_snapshot(id, &snapshot).await.unwrap();

    let mut partitions = vec![Some("1.0.0".to_string()); 256];
    partitions[0] = None;
    db.update_channels(
        id,
        &[ChannelSummary {
            name: "stable".into(),
            frontier: Some("1.0.0".into()),
            partitions,
        }],
    )
    .await
    .unwrap();

    let channels = db.list_channels(id).await.unwrap();
    assert_eq!(channels[0].partitions.iter().flatten().count(), 255);
    // Releases (and the rest of the index) are untouched.
    assert_eq!(db.list_releases(id).await.unwrap().len(), 1);
    assert_eq!(db.index_status(id).await.unwrap().unwrap().state, "fresh");
}

#[tokio::test]
async fn registry_delete_rejects_active_publication_without_partial_history() {
    let db = Database::open_in_memory().await.unwrap();
    let id = db
        .register_registry("publishing", &[], false)
        .await
        .unwrap();
    let registry = db.registry_by_id(id).await.unwrap().unwrap();
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: "active-publication".into(),
        registry_id: id,
        generation: "active-generation".into(),
        manifest_digest: "c".repeat(64),
        refs_digest: "d".repeat(64),
        default_commit: None,
        parent_publication_id: None,
    })
    .await
    .unwrap();

    let change_id = uuid::Uuid::new_v4().to_string();
    let error = db
        .delete_registry_at_version(
            id,
            registry.resource_version,
            &change_id,
            "user",
            Some(7),
            "operator@example.test",
        )
        .await
        .unwrap_err();

    assert!(format!("{error:#}").contains("active publication or upload"));
    assert!(db.registry_by_id(id).await.unwrap().is_some());
    assert!(db.changeset(&change_id).await.unwrap().is_none());
}

#[tokio::test]
async fn pointer_advance_accepts_a_raced_retry_for_the_same_publication() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("pointer-race", "Pointer Race").await.unwrap();
    let binding_id = create_test_binding(&db, org_id, "primary", "/tmp/pointer-race").await;
    let registry_id = db
        .create_managed_registry(org_id, "", "registry", "public", &[], false)
        .await
        .unwrap();
    let mut placement = topology_placement(
        SurfaceTarget::Registry(registry_id),
        "primary",
        "registry",
        0,
    );
    placement.binding_id = binding_id;
    let placement = db.create_surface_placement(&placement).await.unwrap();

    let publication_id = "pointerracepublication00000000000001";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.into(),
        registry_id,
        generation: "generation-1".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: Some("c".repeat(64)),
        parent_publication_id: None,
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
    assert!(db
        .advance_registry_publication(publication_id, "preparing", "writing_pointers", 2)
        .await
        .unwrap());

    let watermark_version = placement.watermark_resource_version.unwrap();
    let advanced = db
        .begin_registry_pointer_advance(
            publication_id,
            placement.id,
            placement.resource_version,
            watermark_version,
            3,
        )
        .await
        .unwrap();
    let raced_retry = db
        .begin_registry_pointer_advance(
            publication_id,
            placement.id,
            placement.resource_version,
            watermark_version,
            4,
        )
        .await
        .unwrap();
    let current_retry = db
        .begin_registry_pointer_advance(
            publication_id,
            placement.id,
            placement.resource_version,
            advanced.watermark_resource_version.unwrap(),
            5,
        )
        .await
        .unwrap();

    assert_eq!(
        advanced.watermark_pending_publication_id.as_deref(),
        Some(publication_id)
    );
    assert_eq!(
        raced_retry.watermark_resource_version,
        advanced.watermark_resource_version
    );
    assert_eq!(
        raced_retry.watermark_pending_publication_id,
        advanced.watermark_pending_publication_id
    );
    assert_eq!(
        current_retry.watermark_resource_version,
        advanced.watermark_resource_version
    );
    assert_eq!(
        current_retry.watermark_pending_publication_id,
        advanced.watermark_pending_publication_id
    );
}

#[tokio::test]
async fn registry_index_mutation_waits_for_an_active_publication() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db
        .register_registry("publication-index-fence", &[], false)
        .await
        .unwrap();
    db.mark_index_failed(registry_id, "prior failure")
        .await
        .unwrap();
    let prior = db.index_status(registry_id).await.unwrap().unwrap();

    let publication_id = "publication-index-fence-1";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.into(),
        registry_id,
        generation: "generation-1".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: None,
        parent_publication_id: None,
    })
    .await
    .unwrap();

    assert!(db
        .registry_has_active_publication(registry_id)
        .await
        .unwrap());
    assert!(db.mark_index_pending(registry_id).await.is_err());
    assert!(db.mark_index_stale(registry_id, "transient").await.is_err());
    assert!(db
        .mark_index_failed(registry_id, "replacement")
        .await
        .is_err());
    let retained = db.index_status(registry_id).await.unwrap().unwrap();
    assert_eq!(retained.state, prior.state);
    assert_eq!(retained.error, prior.error);
    assert_eq!(retained.generation, prior.generation);

    db.fail_registry_publication(publication_id, unix_now())
        .await
        .unwrap();
    assert!(!db
        .registry_has_active_publication(registry_id)
        .await
        .unwrap());
    db.mark_index_pending(registry_id).await.unwrap();
    assert_eq!(
        db.index_status(registry_id).await.unwrap().unwrap().state,
        "pending"
    );
}

#[tokio::test]
async fn registry_publication_manifest_is_invisible_and_exact() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db
        .register_registry("publication", &[], false)
        .await
        .unwrap();
    let publication_id = "publication000000000000000000000001";
    let publication = db
        .create_registry_publication(&NewRegistryPublication {
            publication_id: publication_id.into(),
            registry_id,
            generation: "generation-1".into(),
            manifest_digest: "a".repeat(64),
            refs_digest: "b".repeat(64),
            default_commit: Some("c".repeat(40)),
            parent_publication_id: None,
        })
        .await
        .unwrap();
    assert_eq!(publication.ordinal, 1);
    assert_eq!(publication.state, "preparing");

    let immutable = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: "objects/immutable".into(),
            content_hash: Some("d".repeat(64)),
            size: Some(7),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    let pointer = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: "info/refs".into(),
            content_hash: Some("e".repeat(64)),
            size: Some(9),
            object_kind: "mutable_pointer".into(),
            mutable_publication_id: Some(publication_id.into()),
        })
        .await
        .unwrap();
    let pointer_id = pointer.id;
    for (object, kind, hash, size) in [
        (immutable, "immutable", "d".repeat(64), 7),
        (pointer, "mutable_pointer", "e".repeat(64), 9),
    ] {
        db.set_registry_publication_object(&SetRegistryPublicationObject {
            publication_id: publication_id.into(),
            surface_object_id: object.id,
            object_kind: kind.into(),
            expected_hash: hash,
            expected_size: size,
        })
        .await
        .unwrap();
    }
    let objects = db
        .registry_publication_upload_objects(publication_id)
        .await
        .unwrap();
    assert_eq!(objects.len(), 2);
    assert_eq!(objects[0].object_kind, "immutable");
    assert_eq!(objects[1].object_kind, "mutable_pointer");
    assert!(objects.iter().all(|object| !object.verified));
    let selected = db
        .registry_publication_upload_object(publication_id, pointer_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected.surface_object_id, pointer_id);
    assert_eq!(selected.object_kind, "mutable_pointer");
    assert!(!selected.verified);
    assert!(db
        .registry_publication_upload_object(publication_id, i64::MAX)
        .await
        .unwrap()
        .is_none());
    assert!(!db
        .registry_publication_class_is_complete(publication_id, "immutable")
        .await
        .unwrap());
}

#[tokio::test]
async fn empty_registry_publication_object_class_is_complete() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db
        .create_org("minimal-publish", "Minimal publish")
        .await
        .unwrap();
    let binding_id =
        create_test_binding(&db, org_id, "minimal-publish", "/tmp/minimal-publish").await;
    let registry_id = db
        .create_managed_registry(org_id, "", "registry", "private", &[], false)
        .await
        .unwrap();
    let mut placement = topology_placement(
        SurfaceTarget::Registry(registry_id),
        "primary",
        "minimal-publish",
        0,
    );
    placement.binding_id = binding_id;
    let placement = db.create_surface_placement(&placement).await.unwrap();
    let publication_id = "minimalpublication00000000000000001";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.into(),
        registry_id,
        generation: "minimal-generation".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: Some("c".repeat(64)),
        parent_publication_id: None,
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

    assert!(db
        .registry_publication_class_is_complete(publication_id, "immutable")
        .await
        .unwrap());
    assert!(db
        .registry_publication_class_is_complete(publication_id, "mutable_pointer")
        .await
        .unwrap());
}

#[tokio::test]
async fn registry_publication_inherits_exact_reusable_evidence() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("reuse", "Reuse").await.unwrap();
    let binding_id = create_test_binding(&db, org_id, "reuse", "/tmp/reuse").await;
    let registry_id = db
        .create_managed_registry(org_id, "", "registry", "public", &[], false)
        .await
        .unwrap();
    let mut placement =
        topology_placement(SurfaceTarget::Registry(registry_id), "primary", "reuse", 0);
    placement.binding_id = binding_id;
    let placement = db.create_surface_placement(&placement).await.unwrap();

    let first_publication = "reusepublication000000000000000001";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: first_publication.into(),
        registry_id,
        generation: "generation-1".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: Some("c".repeat(40)),
        parent_publication_id: None,
    })
    .await
    .unwrap();
    let object = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: "images/sha256/aa/system.qcow2".into(),
            content_hash: Some("d".repeat(64)),
            size: Some(91),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    db.set_registry_publication_object(&SetRegistryPublicationObject {
        publication_id: first_publication.into(),
        surface_object_id: object.id,
        object_kind: "immutable".into(),
        expected_hash: "d".repeat(64),
        expected_size: 91,
    })
    .await
    .unwrap();
    db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
        publication_id: first_publication.into(),
        placement_id: placement.id,
        required: true,
        state: "preparing".into(),
        observed_at: 1,
    })
    .await
    .unwrap();
    db.record_registry_publication_object_presence(
        first_publication,
        object.id,
        placement.id,
        &"d".repeat(64),
        91,
        Some("\"r2-version-1\""),
        2,
    )
    .await
    .unwrap();
    db.fail_registry_publication(first_publication, 3)
        .await
        .unwrap();

    let second_publication = "reusepublication000000000000000002";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: second_publication.into(),
        registry_id,
        generation: "generation-2".into(),
        manifest_digest: "e".repeat(64),
        refs_digest: "f".repeat(64),
        default_commit: Some("0".repeat(40)),
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.set_registry_publication_object(&SetRegistryPublicationObject {
        publication_id: second_publication.into(),
        surface_object_id: object.id,
        object_kind: "immutable".into(),
        expected_hash: "d".repeat(64),
        expected_size: 91,
    })
    .await
    .unwrap();
    db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
        publication_id: second_publication.into(),
        placement_id: placement.id,
        required: true,
        state: "preparing".into(),
        observed_at: 4,
    })
    .await
    .unwrap();

    db.inherit_registry_publication_object_evidence(second_publication, 5)
        .await
        .unwrap();

    let evidence = db
        .backend
        .query_opt(
            "SELECT observed_hash, observed_size, strong_etag, observed_at
                 FROM registry_publication_object_evidence
                 WHERE publication_id = ?1 AND surface_object_id = ?2
                   AND placement_id = ?3",
            &vals![second_publication, object.id, placement.id],
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(evidence.get::<String>(0).unwrap(), "d".repeat(64));
    assert_eq!(evidence.get::<i64>(1).unwrap(), 91);
    assert_eq!(evidence.get::<String>(2).unwrap(), "\"r2-version-1\"");
    assert_eq!(evidence.get::<i64>(3).unwrap(), 5);
}
