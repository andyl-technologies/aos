//! Integration checks for shared stage inventories and immutable-object retention.

use aos_registry_format::staging::{inventory_digest, StageObject, StageRevision, STAGE_SCHEMA};

use super::{unix_now, Database, SetSurfaceObject, SurfaceTarget, STAGED_RELEASE_GRACE_SECONDS};

#[tokio::test]
async fn staged_git_and_image_objects_survive_shared_stages_and_discard_grace() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db
        .register_registry("staged-retention", &[], false)
        .await
        .unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let image_hash = "a".repeat(64);
    let git_key = format!("objects/{}/{}", "b".repeat(2), "b".repeat(62));
    let image_key = format!("images/sha256/{image_hash}/fixture.qcow2");
    let mut inventory = Vec::new();
    let mut objects = Vec::new();
    for (key, hash) in [(git_key, "b".repeat(64)), (image_key, image_hash.clone())] {
        objects.push(
            db.create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(registry_id),
                object_key: key.clone(),
                content_hash: Some(hash.clone()),
                size: Some(1),
                object_kind: "immutable".into(),
                mutable_publication_id: None,
            })
            .await
            .unwrap(),
        );
        inventory.push(StageObject {
            path: key,
            sha256: format!("sha256:{hash}"),
            byte_size: 1,
            kind: "artifact".into(),
            media_type: "application/octet-stream".into(),
        });
    }
    inventory.sort_by(|left, right| left.path.cmp(&right.path));
    let started = unix_now() - 3 * STAGED_RELEASE_GRACE_SECONDS;
    let revision = StageRevision {
        schema: STAGE_SCHEMA.into(),
        id: "first".into(),
        registry: registry.slug,
        revision: 1,
        release_id: "1.0.0".into(),
        source_branch: "maintainer/candidate".into(),
        commit: "c".repeat(64),
        container: None,
        inventory_digest: inventory_digest(&inventory).unwrap(),
        inventory,
        publication: vec![],
        store_roots: vec![],
    };
    db.upsert_staged_release(registry_id, &revision, 0, None, started)
        .await
        .unwrap();
    let second = StageRevision {
        id: "second".into(),
        ..revision
    };
    db.upsert_staged_release(registry_id, &second, 0, None, started)
        .await
        .unwrap();
    for object in &mut objects {
        *object = db.surface_object(object.id).await.unwrap().unwrap();
    }
    db.backend.execute(
        "INSERT INTO image_snapshots(digest, byte_size, state, created_at) VALUES (?1, 1, 'collectible', ?2)",
        &vals![image_hash, started],
    ).await.unwrap();

    for object in &objects {
        assert!(!db
            .tombstone_surface_object(object.id, object.resource_version, started + 1)
            .await
            .unwrap());
    }
    assert!(db
        .collectible_image_snapshots(100)
        .await
        .unwrap()
        .is_empty());
    assert!(!db
        .forget_collectible_image_snapshot(&image_hash)
        .await
        .unwrap());

    // One expired draft cannot relinquish another draft's shared identity.
    let discarded = started + 100;
    db.discard_staged_release(registry_id, "first", 1, discarded)
        .await
        .unwrap();
    for object in &objects {
        assert!(!db
            .tombstone_surface_object(
                object.id,
                object.resource_version,
                discarded + STAGED_RELEASE_GRACE_SECONDS
            )
            .await
            .unwrap());
    }
    assert!(db
        .collectible_image_snapshots(100)
        .await
        .unwrap()
        .is_empty());

    db.discard_staged_release(registry_id, "second", 1, discarded)
        .await
        .unwrap();
    for object in &objects {
        assert!(!db
            .tombstone_surface_object(
                object.id,
                object.resource_version,
                discarded + STAGED_RELEASE_GRACE_SECONDS - 1
            )
            .await
            .unwrap());
        assert!(db
            .tombstone_surface_object(
                object.id,
                object.resource_version,
                discarded + STAGED_RELEASE_GRACE_SECONDS
            )
            .await
            .unwrap());
    }
    assert_eq!(
        db.collectible_image_snapshots(100).await.unwrap(),
        [(image_hash.clone(), 1)]
    );
    assert!(db
        .forget_collectible_image_snapshot(&image_hash)
        .await
        .unwrap());
}

#[tokio::test]
async fn expired_stage_publication_relinquishes_objects_after_multipart_settlement() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db
        .register_registry("multipart-staged-retention", &[], false)
        .await
        .unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let hash = "a".repeat(64);
    let key = format!("objects/{}/{}", "a".repeat(2), "a".repeat(62));
    let object = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: key.clone(),
            content_hash: Some(hash.clone()),
            size: Some(1),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO registry_publications
         (publication_id, registry_id, ordinal, generation, manifest_digest, refs_digest,
          state, created_at, completed_at)
         VALUES ('stage-publication', ?1, 1, 'generation', 'manifest', 'refs', 'preparing', 1, NULL)",
            &vals![registry_id],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO registry_publication_objects
         (publication_id, registry_id, surface_object_id, object_kind, expected_hash, expected_size)
         VALUES ('stage-publication', ?1, ?2, 'immutable', ?3, 1)",
            &vals![registry_id, object.id, hash],
        )
        .await
        .unwrap();
    let inventory = vec![StageObject {
        path: key,
        sha256: format!("sha256:{hash}"),
        byte_size: 1,
        kind: "git-object".into(),
        media_type: "application/octet-stream".into(),
    }];
    let revision = StageRevision {
        schema: STAGE_SCHEMA.into(),
        id: "candidate".into(),
        registry: registry.slug,
        revision: 1,
        release_id: "1.0.0".into(),
        source_branch: "maintainer/candidate".into(),
        commit: "c".repeat(64),
        container: None,
        inventory_digest: inventory_digest(&inventory).unwrap(),
        inventory,
        publication: vec![],
        store_roots: vec![],
    };
    db.upsert_staged_release(registry_id, &revision, 0, Some("stage-publication"), 10)
        .await
        .unwrap();
    let object = db.surface_object(object.id).await.unwrap().unwrap();
    db.discard_staged_release(registry_id, "candidate", 1, 20)
        .await
        .unwrap();
    db.backend
        .execute(
            "UPDATE registry_publications SET state = 'failed', completed_at = 20
         WHERE publication_id = 'stage-publication'",
            &[],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO registry_publication_multipart_uploads
         (upload_id, publication_id, registry_id, surface_object_id, state,
          active_object_slot, expires_at, created_at)
         VALUES ('active-part', 'stage-publication', ?1, ?2, 'active', 1, ?3, 10)",
            &vals![registry_id, object.id, 30 + STAGED_RELEASE_GRACE_SECONDS],
        )
        .await
        .unwrap();

    let after_grace = 20 + STAGED_RELEASE_GRACE_SECONDS;
    assert!(!db
        .tombstone_surface_object(object.id, object.resource_version, after_grace)
        .await
        .unwrap());

    db.backend.execute(
        "UPDATE registry_publication_multipart_uploads
         SET state = 'aborted', active_object_slot = NULL, finished_at = ?1 WHERE upload_id = 'active-part'",
        &vals![after_grace],
    ).await.unwrap();
    assert!(db
        .tombstone_surface_object(object.id, object.resource_version, after_grace)
        .await
        .unwrap());
}

#[tokio::test]
async fn superseded_inventory_releases_only_its_unshared_objects_after_grace() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db
        .register_registry("superseded-staged-retention", &[], false)
        .await
        .unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let mut inventory = Vec::new();
    let mut objects = Vec::new();
    for digit in ['a', 'b'] {
        let hash = digit.to_string().repeat(64);
        let path = format!("objects/{}/{}", &hash[..2], &hash[2..]);
        objects.push(
            db.create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(registry_id),
                object_key: path.clone(),
                content_hash: Some(hash.clone()),
                size: Some(1),
                object_kind: "immutable".into(),
                mutable_publication_id: None,
            })
            .await
            .unwrap(),
        );
        inventory.push(StageObject {
            path,
            sha256: format!("sha256:{hash}"),
            byte_size: 1,
            kind: "git-object".into(),
            media_type: "application/octet-stream".into(),
        });
    }
    let initial = vec![inventory[0].clone()];
    let first = StageRevision {
        schema: STAGE_SCHEMA.into(),
        id: "candidate".into(),
        registry: registry.slug,
        revision: 1,
        release_id: "1.0.0".into(),
        source_branch: "maintainer/candidate".into(),
        commit: "c".repeat(64),
        container: None,
        inventory_digest: inventory_digest(&initial).unwrap(),
        inventory: initial,
        publication: vec![],
        store_roots: vec![],
    };
    db.upsert_staged_release(registry_id, &first, 0, None, 100)
        .await
        .unwrap();
    let replacement = vec![inventory[1].clone()];
    let second = StageRevision {
        revision: 2,
        commit: "d".repeat(64),
        inventory_digest: inventory_digest(&replacement).unwrap(),
        inventory: replacement,
        ..first
    };
    db.upsert_staged_release(registry_id, &second, 1, None, 200)
        .await
        .unwrap();
    let prior_version = objects[0].resource_version;
    for object in &mut objects {
        *object = db.surface_object(object.id).await.unwrap().unwrap();
    }
    assert!(objects[0].resource_version > prior_version);

    let deadline = 200 + STAGED_RELEASE_GRACE_SECONDS;
    // A collector that captured the object before stage admission loses its
    // version CAS even after that superseded revision's roots expire.
    assert!(!db
        .tombstone_surface_object(objects[0].id, prior_version, deadline)
        .await
        .unwrap());
    assert!(!db
        .tombstone_surface_object(objects[0].id, objects[0].resource_version, deadline - 1)
        .await
        .unwrap());
    assert!(db
        .tombstone_surface_object(objects[0].id, objects[0].resource_version, deadline)
        .await
        .unwrap());
    assert!(!db
        .tombstone_surface_object(objects[1].id, objects[1].resource_version, deadline)
        .await
        .unwrap());
}
