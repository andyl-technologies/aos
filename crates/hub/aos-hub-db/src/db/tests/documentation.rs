//! Documentation regression cases and contract checks.

use super::*;

#[tokio::test]
async fn legacy_registry_object_conversion_follows_shared_mutability_policy() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db
        .register_registry("loose-migration", &[], false)
        .await
        .unwrap();
    let current_publication_id = "loosemigrationpublication000000000000";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: current_publication_id.into(),
        registry_id,
        generation: "generation-0".into(),
        manifest_digest: "0".repeat(64),
        refs_digest: "1".repeat(64),
        default_commit: Some("2".repeat(64)),
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.backend
        .execute(
            "UPDATE registry_publications SET state = 'ready', completed_at = ?2
                 WHERE publication_id = ?1",
            &vals![current_publication_id, unix_now()],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "UPDATE registry_publication_state SET current_publication_id = ?1
                 WHERE registry_id = ?2",
            &vals![current_publication_id, registry_id],
        )
        .await
        .unwrap();
    let object_key = "objects/ab/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let object = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: object_key.into(),
            content_hash: Some("d".repeat(64)),
            size: Some(91),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    let publication_id = "loosemigrationpublication000000000001";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.into(),
        registry_id,
        generation: "generation-1".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: Some("c".repeat(64)),
        parent_publication_id: Some(current_publication_id.into()),
    })
    .await
    .unwrap();

    for _ in 0..2 {
        let converted = db
            .convert_registry_object_to_mutable(registry_id, object.id, object_key, publication_id)
            .await
            .unwrap();
        assert_eq!(converted.object_kind, "mutable_pointer");
        assert_eq!(converted.content_hash, Some("d".repeat(64)));
        assert_eq!(converted.size, Some(91));
        assert_eq!(
            converted.mutable_publication_id.as_deref(),
            Some(current_publication_id)
        );
    }

    let release_info_key = "releases/1/0/0/objects/info/packs";
    let release_info = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: release_info_key.into(),
            content_hash: Some("e".repeat(64)),
            size: Some(12),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    let converted = db
        .convert_registry_object_to_mutable(
            registry_id,
            release_info.id,
            release_info_key,
            publication_id,
        )
        .await
        .unwrap();
    assert_eq!(converted.object_kind, "mutable_pointer");
    assert_eq!(converted.content_hash, Some("e".repeat(64)));
    assert_eq!(
        converted.mutable_publication_id.as_deref(),
        Some(current_publication_id)
    );

    for pack_index_key in [
            "objects/pack/pack-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.idx",
            "releases/1/0/0/objects/pack/pack-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.idx",
        ] {
            let pack_index = db
                .create_surface_object(&SetSurfaceObject {
                    surface: SurfaceTarget::Registry(registry_id),
                    object_key: pack_index_key.into(),
                    content_hash: Some("f".repeat(64)),
                    size: Some(2048),
                    object_kind: "immutable".into(),
                    mutable_publication_id: None,
                })
                .await
                .unwrap();
            let converted = db
                .convert_registry_object_to_mutable(
                    registry_id,
                    pack_index.id,
                    pack_index_key,
                    publication_id,
                )
                .await
                .unwrap();
            assert_eq!(converted.object_kind, "mutable_pointer");
            assert_eq!(converted.content_hash, Some("f".repeat(64)));
            assert_eq!(
                converted.mutable_publication_id.as_deref(),
                Some(current_publication_id)
            );
        }

    let narinfo_key = "00wvyrrlz4wggxnpkhl91im5ibh493m5.narinfo";
    let narinfo = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: narinfo_key.into(),
            content_hash: Some("1".repeat(64)),
            size: Some(512),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    let converted = db
        .convert_registry_object_to_mutable(registry_id, narinfo.id, narinfo_key, publication_id)
        .await
        .unwrap();
    assert_eq!(converted.object_kind, "mutable_pointer");
    assert_eq!(
        converted.mutable_publication_id.as_deref(),
        Some(current_publication_id)
    );

    let nar_key = format!("nar/store-sha256-{}.nar.zst", "2".repeat(64));
    let nar = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: nar_key.clone(),
            content_hash: Some("2".repeat(64)),
            size: Some(4096),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    let error = db
        .convert_registry_object_to_mutable(registry_id, nar.id, &nar_key, publication_id)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("not replaceable metadata"));
}
