//! Registries regression cases and contract checks.

use super::*;

#[test]
fn snapshot_rows_are_bounded_into_multirow_statements() {
    let rows = (0..121)
        .map(|index| vals![index, format!("row-{index}")])
        .collect::<Vec<_>>();
    let mut statements = Vec::new();

    extend_multirow_insert(
        &mut statements,
        "INSERT INTO example (id, name)",
        &rows,
        " ON CONFLICT(id) DO NOTHING",
    )
    .unwrap();

    assert_eq!(statements.len(), 3);
    assert_eq!(statements[0].params.len(), 100);
    assert_eq!(statements[1].params.len(), 100);
    assert_eq!(statements[2].params.len(), 42);
    assert!(statements[0].sql.contains("(?1, ?2), (?3, ?4)"));
    assert!(statements[0].sql.ends_with("ON CONFLICT(id) DO NOTHING"));
}

#[tokio::test]
async fn instance_registry_slugs_cannot_collide_with_stable_ids() {
    let db = Database::open_in_memory().await.unwrap();
    let error = db
        .register_registry("registry:0123456789abcdef0123456789abcdef", &[], false)
        .await
        .unwrap_err();

    assert!(format!("{error:#}").contains("invalid instance registry slug"));
}

#[tokio::test]
async fn snapshot_replace_is_idempotent() {
    let db = Database::open_in_memory().await.unwrap();
    let id = db.register_registry("demo", &[], false).await.unwrap();
    let package: aos_registry_format::manifest::PackageToml = toml::from_str(
        r#"
            [package]
            name = "curl"
            description = "URL transfers"
            license = "MIT"
            maintainer = "aos"
            [[versions]]
            version = "8.5.0"
            [versions.platforms.x86_64-linux]
            store_path = "/var/lib/store/abc-curl-8.5.0"
            nar_hash = "sha256:aa"
            nar_size = 10
            closure_size = 20
            source_drv = "/var/lib/store/abc.drv"
            source_nar_hash = "sha256:bb"

            [versions.platforms.x86_64-linux.named_outputs]
            dev = { store_path = "/nix/store/dddddddddddddddddddddddddddddddd-curl-dev" }

            "#,
    )
    .unwrap();
    let artifacts = vec![ReleaseSnapshotArtifact {
        package_name: "curl".into(),
        package_version: "8.5.0".into(),
        platform: "x86_64-linux".into(),
        artifact_kind: "output".into(),
        store_path: "/var/lib/store/abc-curl-8.5.0".into(),
        store_hash: "abc".into(),
    }];
    let manifest_digest = hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&artifacts).unwrap(),
    ));
    let mut snapshot = IndexSnapshot {
        commit: "c".repeat(64),
        public_catalog_commit: Some("c".repeat(64)),
        public_catalog_release: Some("1.0.0".into()),
        name: "demo".into(),
        description: None,
        readme: None,
        support: None,
        caches: vec![
            ("https://cache.example".into(), 40),
            ("https://primary-cache.example".into(), 100),
        ],
        roster: vec![("alice".into(), "demo:Ed25519:AA".into(), "active".into())],
        packages: vec![package],
        releases: vec![ReleaseRow {
            semver: "1.0.0".into(),
            tag_oid: "a".repeat(64),
            commit_oid: "c".repeat(64),
            signer: None,
            tagged_at: Some(1),
            pack_present: true,
        }],
        release_artifact_snapshots: vec![ReleaseArtifactSnapshot {
            release_tag: "1.0.0".into(),
            source_commit: "c".repeat(64),
            verified_tag_oid: "a".repeat(64),
            manifest_digest,
            artifacts,
            container_release: None,
        }],
        channels: vec![ChannelSummary {
            name: "stable".into(),
            frontier: Some("1.0.0".into()),
            partitions: vec![Some("1.0.0".into()); 256],
        }],
        ..IndexSnapshot::default()
    };
    db.apply_snapshot(id, &snapshot).await.unwrap();
    let before = db.list_retention_release_snapshots(id).await.unwrap();

    let mut conflicting_snapshot = snapshot.clone();
    conflicting_snapshot.release_artifact_snapshots[0].manifest_digest = "f".repeat(64);
    assert!(db.apply_snapshot(id, &conflicting_snapshot).await.is_err());
    db.backend
        .execute(
            "INSERT INTO registry_catalog_artifacts
                     (registry_id, source_revision, package_name, package_version,
                      platform, artifact_kind, store_path, store_hash, metadata_digest)
                     VALUES (?1, ?2, 'stale', '1.0', 'x86_64-linux', 'output',
                             '/nix/store/stale-output', 'stale', 'stale')",
            &vals![id, "0".repeat(64)],
        )
        .await
        .unwrap();
    let current_artifacts = db
        .list_current_catalog_retention_artifacts(id)
        .await
        .unwrap();
    assert_eq!(current_artifacts.len(), 3);
    assert!(current_artifacts
        .iter()
        .all(|artifact| artifact.package_name == "curl"));
    assert!(current_artifacts.iter().any(|artifact| {
        artifact.artifact_kind == "output"
            && artifact.store_path == "/nix/store/dddddddddddddddddddddddddddddddd-curl-dev"
    }));
    assert_eq!(
        db.list_complete_package_snapshots(id).await.unwrap(),
        [("1.0.0".to_string(), "c".repeat(64))]
    );
    assert!(db
        .list_complete_package_snapshots(id + 1000)
        .await
        .unwrap()
        .is_empty());
    // A moved tag cannot select a complete snapshot of its predecessor.
    db.backend
        .execute(
            "UPDATE releases SET commit_oid = ?1 WHERE registry_id = ?2",
            &vals!["d".repeat(64), id],
        )
        .await
        .unwrap();
    assert!(db
        .list_complete_package_snapshots(id)
        .await
        .unwrap()
        .is_empty());
    db.backend
        .execute(
            "UPDATE releases SET commit_oid = ?1 WHERE registry_id = ?2",
            &vals!["c".repeat(64), id],
        )
        .await
        .unwrap();
    let release_packages = db.list_packages_at_release(id, "1.0.0").await.unwrap();
    assert_eq!(release_packages.len(), 1);
    assert_eq!(release_packages[0].name, "curl");
    assert_eq!(release_packages[0].latest_version.as_deref(), Some("8.5.0"));
    assert_eq!(release_packages[0].platforms, ["x86_64-linux"]);
    assert_eq!(
        db.list_release_package_counts(id).await.unwrap(),
        [("1.0.0".to_string(), 1)]
    );
    assert_eq!(
        db.list_packages_at_release(id, &"c".repeat(64))
            .await
            .unwrap()
            .len(),
        1
    );

    db.apply_snapshot(id, &snapshot).await.unwrap();
    let after = db.list_retention_release_snapshots(id).await.unwrap();
    assert_eq!(before[0].snapshot_id, after[0].snapshot_id);
    assert_eq!(db.list_packages(id).await.unwrap().len(), 1);
    assert_eq!(db.list_channels(id).await.unwrap().len(), 1);

    snapshot.channels.clear();
    db.apply_snapshot(id, &snapshot).await.unwrap();
    assert!(db.list_channels(id).await.unwrap().is_empty());
    assert_eq!(
        db.list_retention_release_snapshots(id).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn snapshot_materializes_only_the_exact_signed_container_root() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db
        .create_org("container-release-root", "Container Release Root")
        .await
        .unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "containers", "public", &[], false)
        .await
        .unwrap();
    let binding_id = create_test_binding(&db, org_id, "container-root", "containers").await;
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".to_string(),
            binding_id,
            prefix: "containers".to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let placement = db
        .observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    let digest = format!("sha256:{}", "a".repeat(64));
    let object = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: format!("oci/blobs/sha256/{}", "a".repeat(64)),
            content_hash: Some("a".repeat(64)),
            size: Some(512),
            object_kind: "immutable".to_string(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    db.backend
        .batch(&[
            Statement::new(
                "INSERT INTO oci_repositories
                       (id, registry_id, name, visibility, lifecycle_state,
                        resource_version, created_at, updated_at)
                     VALUES (42001, ?1, 'aos', 'inherit', 'active', 1, 1, 1)",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "INSERT INTO oci_blobs
                       (registry_id, digest, byte_size, media_type,
                        surface_object_id, quota_bytes, lifecycle_state,
                        created_at, updated_at)
                     VALUES (?1, ?2, 512,
                       'application/vnd.oci.image.index.v1+json', ?3, 512,
                       'active', 1, 1)",
                vals![registry_id, digest, object.id].to_vec(),
            ),
            Statement::new(
                "INSERT INTO oci_repository_objects
                       (repository_id, registry_id, digest, object_kind,
                        media_type, linked_at)
                     VALUES (42001, ?1, ?2, 'manifest',
                       'application/vnd.oci.image.index.v1+json', 1)",
                vals![registry_id, digest].to_vec(),
            ),
            Statement::new(
                "INSERT INTO oci_manifests
                       (registry_id, digest, media_type, byte_size,
                        schema_version, artifact_type, subject_digest,
                        config_digest, annotations_json, descriptor_count,
                        created_at)
                     VALUES (?1, ?2,
                       'application/vnd.oci.image.index.v1+json', 512, 2,
                       NULL, NULL, NULL, '{}', 0, 1)",
                vals![registry_id, digest].to_vec(),
            ),
            Statement::new(
                "INSERT INTO object_placements
                       (surface_object_id, cache_id, registry_id, placement_id,
                        state, observed_hash, observed_size, etag,
                        observed_inventory_generation, observed_at,
                        catalog_object_resource_version)
                     VALUES (?1, NULL, ?2, ?3, 'present', ?4, 512,
                             'fixture-etag', 1, 1, ?5)",
                vals![
                    object.id,
                    registry_id,
                    placement.id,
                    "a".repeat(64),
                    object.resource_version
                ]
                .to_vec(),
            ),
        ])
        .await
        .unwrap();

    let placement_observation_version = placement.observation_version.unwrap();
    let mut required_descriptors = vec![VerifiedContainerReleaseDescriptor {
        role: ContainerReleaseDescriptorRole::Index,
        digest: digest.clone(),
        media_type: "application/vnd.oci.image.index.v1+json".to_string(),
        byte_size: 512,
        surface_object_id: object.id,
        object_resource_version: object.resource_version,
        placement_id: placement.id,
        placement_resource_version: placement.resource_version,
        placement_observation_version,
        observed_inventory_generation: 1,
        observed_at: 1,
        strong_etag: "fixture-etag".to_string(),
    }];
    let required_roles = [
        ContainerReleaseDescriptorRole::PlatformManifest,
        ContainerReleaseDescriptorRole::NixClosure,
        ContainerReleaseDescriptorRole::Abilities,
        ContainerReleaseDescriptorRole::Sbom,
        ContainerReleaseDescriptorRole::Source,
        ContainerReleaseDescriptorRole::License,
        ContainerReleaseDescriptorRole::Provenance,
        ContainerReleaseDescriptorRole::Signature,
    ];
    for (ordinal, role) in required_roles.into_iter().enumerate() {
        let encoded = format!("{:064x}", ordinal + 11);
        let descriptor_digest = format!("sha256:{encoded}");
        let byte_size = 513 + i64::try_from(ordinal).unwrap();
        let descriptor_object = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(registry_id),
                object_key: format!("oci/blobs/sha256/{encoded}"),
                content_hash: Some(encoded.clone()),
                size: Some(byte_size),
                object_kind: "immutable".to_string(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();
        db.backend
            .batch(&[
                Statement::new(
                    "INSERT INTO oci_blobs
                           (registry_id, digest, byte_size, media_type,
                            surface_object_id, quota_bytes, lifecycle_state,
                            created_at, updated_at)
                         VALUES (?1, ?2, ?3,
                           'application/vnd.oci.image.manifest.v1+json', ?4, ?3,
                           'active', 1, 1)",
                    vals![
                        registry_id,
                        descriptor_digest,
                        byte_size,
                        descriptor_object.id
                    ]
                    .to_vec(),
                ),
                Statement::new(
                    "INSERT INTO oci_repository_objects
                           (repository_id, registry_id, digest, object_kind,
                            media_type, linked_at)
                         VALUES (42001, ?1, ?2, 'manifest',
                           'application/vnd.oci.image.manifest.v1+json', 1)",
                    vals![registry_id, descriptor_digest].to_vec(),
                ),
                Statement::new(
                    "INSERT INTO oci_manifests
                           (registry_id, digest, media_type, byte_size,
                            schema_version, artifact_type, subject_digest,
                            config_digest, annotations_json, descriptor_count,
                            created_at)
                         VALUES (?1, ?2,
                           'application/vnd.oci.image.manifest.v1+json', ?3, 2,
                           NULL, NULL, NULL, '{}', 0, 1)",
                    vals![registry_id, descriptor_digest, byte_size].to_vec(),
                ),
                Statement::new(
                    "INSERT INTO object_placements
                           (surface_object_id, cache_id, registry_id, placement_id,
                            state, observed_hash, observed_size, etag,
                            observed_inventory_generation, observed_at,
                            catalog_object_resource_version)
                         VALUES (?1, NULL, ?2, ?3, 'present', ?4, ?5,
                                 ?6, 1, 1, ?7)",
                    vals![
                        descriptor_object.id,
                        registry_id,
                        placement.id,
                        encoded,
                        byte_size,
                        format!("fixture-etag-{ordinal}"),
                        descriptor_object.resource_version
                    ]
                    .to_vec(),
                ),
            ])
            .await
            .unwrap();
        required_descriptors.push(VerifiedContainerReleaseDescriptor {
            role,
            digest: descriptor_digest,
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            byte_size: u64::try_from(byte_size).unwrap(),
            surface_object_id: descriptor_object.id,
            object_resource_version: descriptor_object.resource_version,
            placement_id: placement.id,
            placement_resource_version: placement.resource_version,
            placement_observation_version,
            observed_inventory_generation: 1,
            observed_at: 1,
            strong_etag: format!("fixture-etag-{ordinal}"),
        });
    }

    let closure_layer_digest = required_descriptors[1].digest.clone();
    let evidence_kinds = [
        "closure",
        "sbom",
        "source",
        "license",
        "provenance",
        "signature",
    ];
    let evidence = evidence_kinds
        .iter()
        .zip(&required_descriptors[2..])
        .map(|(kind, descriptor)| ContainerReleaseEvidenceSnapshot {
            kind: (*kind).to_string(),
            digest: descriptor.digest.clone(),
            media_type: "application/vnd.aos.nix-closure.v1+json".to_string(),
            referrer_digest: descriptor.digest.clone(),
        })
        .collect::<Vec<_>>();
    let artifacts = Vec::<ReleaseSnapshotArtifact>::new();
    let snapshot = IndexSnapshot {
        commit: "c".repeat(64),
        name: "container-release-root".to_string(),
        releases: vec![ReleaseRow {
            semver: "1.0.0".to_string(),
            tag_oid: "b".repeat(64),
            commit_oid: "c".repeat(64),
            signer: Some("fixture-key".to_string()),
            tagged_at: Some(1),
            pack_present: true,
        }],
        release_artifact_snapshots: vec![ReleaseArtifactSnapshot {
            release_tag: "1.0.0".to_string(),
            source_commit: "c".repeat(64),
            verified_tag_oid: "b".repeat(64),
            manifest_digest: hex::encode(sha2::Sha256::digest(
                serde_json::to_vec(&artifacts).unwrap(),
            )),
            artifacts,
            container_release: Some(ContainerReleaseRootSnapshot {
                repository: "aos".to_string(),
                container_name: "aos".to_string(),
                index_digest: digest.clone(),
                index_media_type: "application/vnd.oci.image.index.v1+json".to_string(),
                index_size: 512,
                catalog_digest: "d".repeat(64),
                package_name: "aos".to_string(),
                closure_members: vec![ContainerReleaseClosureMemberSnapshot {
                    store_path: "/nix/store/fixture-aos".to_string(),
                    nar_hash: "sha256:fixture".to_string(),
                    nar_size: 123,
                    layer_digest: closure_layer_digest,
                    direct: true,
                }],
                layers: Vec::new(),
                evidence,
                required_descriptors,
            }),
        }],
        ..IndexSnapshot::default()
    };
    let mut changed_observation = snapshot.clone();
    changed_observation.release_artifact_snapshots[0]
        .container_release
        .as_mut()
        .unwrap()
        .required_descriptors[0]
        .observed_inventory_generation += 1;
    assert_ne!(
        index_snapshot_digest(&snapshot).unwrap(),
        index_snapshot_digest(&changed_observation).unwrap(),
        "the index digest must bind exact signed-root placement evidence"
    );
    db.apply_snapshot_from_placement(registry_id, &snapshot, Some(placement.id))
        .await
        .unwrap();
    assert!(db.has_container_release_catalog(registry_id).await.unwrap());

    let root = db
        .backend
        .query_opt(
            "SELECT release_id, release_tag, repository_id, container_name,
                        index_digest, source_commit, verified_tag_oid,
                        catalog_digest
                 FROM oci_release_roots WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap()
        .unwrap();
    let release_id: i64 = db
        .backend
        .query_opt(
            "SELECT id FROM releases WHERE registry_id = ?1 AND semver = '1.0.0'",
            &vals![registry_id],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(root.get::<i64>(0).unwrap(), release_id);
    assert_eq!(root.get::<String>(1).unwrap(), "1.0.0");
    assert_eq!(root.get::<i64>(2).unwrap(), 42001);
    assert_eq!(root.get::<String>(3).unwrap(), "aos");
    assert_eq!(root.get::<String>(4).unwrap(), digest);
    assert_eq!(root.get::<String>(5).unwrap(), "c".repeat(64));
    assert_eq!(root.get::<String>(6).unwrap(), "b".repeat(64));
    assert_eq!(root.get::<String>(7).unwrap(), "d".repeat(64));
    let provenance = db
        .oci_admin_release_provenance(
            registry_id,
            &aos_oci_types::RepositoryName::parse("aos").unwrap(),
            aos_oci_types::Sha256Digest::parse(&digest).unwrap(),
            "1.0.0",
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(provenance.package, "aos");
    assert_eq!(provenance.closure_members.len(), 1);
    assert_eq!(provenance.evidence.len(), 6);
    assert!(provenance
        .evidence
        .iter()
        .all(|evidence| evidence.verification == "verified"));

    let epoch_before_shared_root: i64 = db
        .backend
        .query_opt(
            "SELECT mutation_epoch FROM oci_registry_state WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    let mut shared_root = snapshot.clone();
    shared_root.releases.push(ReleaseRow {
        semver: "2.0.0".to_string(),
        tag_oid: "f".repeat(64),
        commit_oid: "c".repeat(64),
        signer: Some("fixture-key".to_string()),
        tagged_at: Some(2),
        pack_present: true,
    });
    let mut second_release = shared_root.release_artifact_snapshots[0].clone();
    second_release.release_tag = "2.0.0".to_string();
    second_release.verified_tag_oid = "f".repeat(64);
    shared_root.release_artifact_snapshots.push(second_release);
    db.apply_snapshot_from_placement(registry_id, &shared_root, Some(placement.id))
        .await
        .unwrap();
    let all_provenance = db
        .list_oci_admin_release_provenance(
            registry_id,
            &aos_oci_types::RepositoryName::parse("aos").unwrap(),
            aos_oci_types::Sha256Digest::parse(&digest).unwrap(),
            10,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        all_provenance
            .items
            .iter()
            .map(|record| record.release.as_str())
            .collect::<Vec<_>>(),
        vec!["1.0.0", "2.0.0"]
    );
    assert_eq!(all_provenance.items[1].closure_members.len(), 1);
    assert_eq!(all_provenance.items[1].evidence.len(), 6);
    let epoch_after_shared_root: i64 = db
        .backend
        .query_opt(
            "SELECT mutation_epoch FROM oci_registry_state WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(epoch_after_shared_root, epoch_before_shared_root + 1);

    async fn mutation_epoch(db: &Database, registry_id: i64) -> i64 {
        db.backend
            .query_opt(
                "SELECT mutation_epoch FROM oci_registry_state WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap()
    }

    // Dropping the second release changes the projection again.
    db.apply_snapshot_from_placement(registry_id, &snapshot, Some(placement.id))
        .await
        .unwrap();
    let epoch_after_revert = mutation_epoch(&db, registry_id).await;
    assert_eq!(epoch_after_revert, epoch_after_shared_root + 1);

    // The periodic re-index rewrites an unchanged projection. Keeping the
    // epoch keeps provider inventories and GC plans of the registry current.
    db.apply_snapshot_from_placement(registry_id, &snapshot, Some(placement.id))
        .await
        .unwrap();
    assert_eq!(mutation_epoch(&db, registry_id).await, epoch_after_revert);
    assert!(db.has_container_release_catalog(registry_id).await.unwrap());

    db.backend
        .execute(
            "UPDATE object_placements SET state = 'missing'
                 WHERE surface_object_id = ?1 AND placement_id = ?2",
            &vals![object.id, placement.id],
        )
        .await
        .unwrap();
    assert!(db
        .apply_snapshot_from_placement(registry_id, &snapshot, Some(placement.id))
        .await
        .is_err());
    db.backend
        .execute(
            "UPDATE object_placements SET state = 'present'
                 WHERE surface_object_id = ?1 AND placement_id = ?2",
            &vals![object.id, placement.id],
        )
        .await
        .unwrap();

    let platform_object_id = snapshot.release_artifact_snapshots[0]
        .container_release
        .as_ref()
        .unwrap()
        .required_descriptors[1]
        .surface_object_id;
    db.backend
        .execute(
            "UPDATE object_placements
                 SET observed_inventory_generation = 2
                 WHERE surface_object_id = ?1 AND placement_id = ?2",
            &vals![platform_object_id, placement.id],
        )
        .await
        .unwrap();
    assert!(db
        .apply_snapshot_from_placement(registry_id, &snapshot, Some(placement.id))
        .await
        .is_err());
    let retained_after_object_interleaving: i64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM oci_release_roots
                 WHERE registry_id = ?1 AND index_digest = ?2",
            &vals![registry_id, digest],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(retained_after_object_interleaving, 1);
    db.backend
        .execute(
            "UPDATE object_placements
                 SET observed_inventory_generation = 1
                 WHERE surface_object_id = ?1 AND placement_id = ?2",
            &vals![platform_object_id, placement.id],
        )
        .await
        .unwrap();

    let mut mismatched = snapshot.clone();
    mismatched.release_artifact_snapshots[0]
        .container_release
        .as_mut()
        .unwrap()
        .index_size += 1;
    assert!(db
        .apply_snapshot_from_placement(registry_id, &mismatched, Some(placement.id))
        .await
        .is_err());
    let retained: i64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM oci_release_roots
                 WHERE registry_id = ?1 AND index_digest = ?2",
            &vals![registry_id, digest],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(retained, 1);

    db.observe_surface_placement(placement.id, "ready", "complete", 2)
        .await
        .unwrap();
    assert!(db
        .apply_snapshot_from_placement(registry_id, &snapshot, Some(placement.id))
        .await
        .is_err());
    let retained_after_placement_interleaving: i64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM oci_release_roots
                 WHERE registry_id = ?1 AND index_digest = ?2",
            &vals![registry_id, digest],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(retained_after_placement_interleaving, 1);
}

#[tokio::test]
async fn git_changeset_records_ref_and_commit() {
    let db = Database::open_in_memory().await.unwrap();
    db.create_git_changeset(
        "ch-1",
        "user",
        Some(7),
        "alice@acme.com",
        "instance",
        Some("edit registry.toml"),
        "refs/hub/changes/ch-1",
        "abc123",
        None,
        None,
    )
    .await
    .unwrap();
    let cs = db.changeset("ch-1").await.unwrap().unwrap();
    assert_eq!(cs.status, "draft");
    assert_eq!(cs.git_ref.as_deref(), Some("refs/hub/changes/ch-1"));
    assert_eq!(cs.git_commit.as_deref(), Some("abc123"));
    // A plain change-set leaves both columns NULL.
    db.create_changeset("ch-2", "user", Some(7), "alice@acme.com", "instance", None)
        .await
        .unwrap();
    let plain = db.changeset("ch-2").await.unwrap().unwrap();
    assert!(plain.git_ref.is_none());
    assert!(plain.git_commit.is_none());
}

#[tokio::test]
async fn managed_registry_canonical_slug_and_scope_lookup() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_project(org, "infra", "Infrastructure")
        .await
        .unwrap();
    db.create_project(org, "infra/prod", "Production")
        .await
        .unwrap();

    // With a project path.
    let cdn = db
        .create_managed_registry(org, "infra/prod", "cdn", "public", &[], true)
        .await
        .unwrap();
    let record = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.id, cdn);
    assert_eq!(record.org_id, Some(org));
    assert_eq!(record.project_path, "infra/prod");
    assert_eq!(record.visibility, "public");
    // registry_by_scope builds the same canonical slug.
    assert_eq!(
        db.registry_by_scope("acme", "infra/prod", "cdn")
            .await
            .unwrap()
            .unwrap()
            .id,
        cdn
    );
    // project_path normalization: leading/trailing slashes collapse.
    assert_eq!(
        db.registry_by_scope("acme", "/infra/prod/", "cdn")
            .await
            .unwrap()
            .unwrap()
            .id,
        cdn
    );

    // Org-root registry (empty project path) -> "acme/web".
    let web = db
        .create_managed_registry(org, "", "web", "internal", &[], true)
        .await
        .unwrap();
    assert_eq!(
        db.registry_by_slug("acme/web").await.unwrap().unwrap().id,
        web
    );
    assert_eq!(
        db.registry_by_scope("acme", "", "web")
            .await
            .unwrap()
            .unwrap()
            .id,
        web
    );

    // Duplicate canonical path is rejected.
    assert!(db
        .create_managed_registry(org, "infra/prod", "cdn", "public", &[], true)
        .await
        .is_err());

    // A flat phase-1 slug coexists and resolves by its bare slug.
    db.register_registry("legacy", &[], false).await.unwrap();
    assert!(db.registry_by_slug("legacy").await.unwrap().is_some());
    assert!(db
        .registry_by_scope("acme", "", "legacy")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn registry_crawl_policy_and_llms_defaults_and_round_trip() {
    use aos_hub_model::crawl::CrawlPolicy;
    let db = Database::open_in_memory().await.unwrap();
    db.register_registry("demo", &[], false).await.unwrap();

    // The new columns default permissively / null on an existing registry.
    let reg = db.registry_by_slug("demo").await.unwrap().unwrap();
    assert_eq!(reg.crawl_policy, "allow_all");
    assert_eq!(reg.llms_txt_body, None);

    // Registry configuration round-trips through the exact-version atomic path.
    let change_id = uuid::Uuid::new_v4().to_string();
    assert!(db
        .apply_registry_configuration_change(
            reg.id,
            reg.resource_version,
            &reg.visibility,
            CrawlPolicy::DenyAll.as_str(),
            Some("# custom\n"),
            &reg.trust_keys,
            &change_id,
            "system",
            None,
            "test",
        )
        .await
        .unwrap());
    let reg = db.registry_by_slug("demo").await.unwrap().unwrap();
    assert_eq!(reg.crawl_policy, "deny_all");
    assert_eq!(reg.llms_txt_body, Some("# custom\n".to_string()));
    let clear_id = uuid::Uuid::new_v4().to_string();
    assert!(db
        .apply_registry_configuration_change(
            reg.id,
            reg.resource_version,
            &reg.visibility,
            &reg.crawl_policy,
            None,
            &reg.trust_keys,
            &clear_id,
            "system",
            None,
            "test",
        )
        .await
        .unwrap());
    assert_eq!(
        db.registry_by_slug("demo")
            .await
            .unwrap()
            .unwrap()
            .llms_txt_body,
        None
    );
}

#[tokio::test]
async fn stale_index_failure_cannot_replace_a_newer_success() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db
        .register_registry("index-failure-generation", &[], false)
        .await
        .unwrap();
    let snapshot = IndexSnapshot {
        commit: "c".repeat(64),
        public_catalog_commit: None,
        public_catalog_release: None,
        name: "generation guard".into(),
        description: None,
        readme: None,
        support: None,
        caches: Vec::new(),
        cache_stack: None,
        roster: Vec::new(),
        packages: Vec::new(),
        releases: Vec::new(),
        release_artifact_snapshots: Vec::new(),
        release_images: Vec::new(),
        channels: Vec::new(),
        refs_digest: Some("d".repeat(64)),
    };

    db.apply_snapshot(registry_id, &snapshot).await.unwrap();
    let fresh = db.index_status(registry_id).await.unwrap().unwrap();
    assert_eq!(fresh.state, "fresh");
    assert_eq!(fresh.generation, 1);

    db.mark_index_failed_if_generation(registry_id, 0, "late failure")
        .await
        .unwrap();
    let retained = db.index_status(registry_id).await.unwrap().unwrap();
    assert_eq!(retained.state, "fresh");
    assert_eq!(retained.generation, 1);
    assert!(retained.error.is_none());

    db.mark_index_failed_if_generation(registry_id, 1, "current failure")
        .await
        .unwrap();
    let failed = db.index_status(registry_id).await.unwrap().unwrap();
    assert_eq!(failed.state, "failed");
    assert_eq!(failed.error.as_deref(), Some("current failure"));
    assert_eq!(failed.generation, 1);
}
