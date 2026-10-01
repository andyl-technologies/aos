//! Isolated seed admission remains invisible and uncharged without verification.

use super::*;
use std::sync::Arc;

#[tokio::test]
async fn preparing_seed_requires_complete_verified_index_before_presence_or_charge() {
    let root = tempfile::tempdir().unwrap();
    let db = Database::open(&root.path().join("hub.db")).await.unwrap();
    let storage_root = root.path().join("storage");
    std::fs::create_dir_all(&storage_root).unwrap();
    db.ensure_instance_default_binding("local_fs", Some(storage_root.to_str().unwrap()), None)
        .await
        .unwrap();
    let binding = db.instance_default_binding().await.unwrap().unwrap();
    let surface_root = Path::new(binding.local_root_path.as_deref().unwrap()).join("seed");
    let snapshots = crate::image_snapshot::ImageSnapshotStore::open(root.path()).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let trust = aos_registry_surface::sshsig::trusted_key_line("maintainer", &key.verifying_key());
    super::super::write_signed_surface(&surface_root, &key, &trust).unwrap();
    let org = db.create_org("seed-failure", "Seed failure").await.unwrap();
    let registry_id = db
        .create_managed_registry(org, "", "seed", "private", &[trust], true)
        .await
        .unwrap();
    let (registry, placement) = super::super::seed_placement(&db, binding.id, registry_id, "seed")
        .await
        .unwrap();
    let prepared = prepare(&db, registry_id, &surface_root, &snapshots)
        .await
        .unwrap();
    let fetch = LocalFsFetch::new(&surface_root).with_image_snapshots(Arc::clone(&snapshots));

    // Public/background indexing preserves its active-publication deferral.
    let deferred =
        crate::indexer::index_and_record_from_placement(&db, &fetch, &registry, Some(placement))
            .await
            .unwrap();
    assert!(deferred.pending);
    assert!(record(&db, placement, &surface_root, &snapshots, &prepared)
        .await
        .is_err());

    // Even the isolated bootstrap's normal verifier rejects malformed refs. No
    // failed verification can turn the prepared origin into positive presence.
    std::fs::write(surface_root.join("info/refs"), b"invalid refs\n").unwrap();
    assert!(
        verify_index(&db, placement, &surface_root, &snapshots, &prepared)
            .await
            .is_err()
    );
    assert!(record(&db, placement, &surface_root, &snapshots, &prepared)
        .await
        .is_err());
    let publication = db
        .registry_publication(&prepared.input.publication_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(publication.state, "failed");
    assert!(db
        .registry_publication_state(registry_id)
        .await
        .unwrap()
        .unwrap()
        .current_publication_id
        .is_none());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 0);
    assert_eq!(db.org_usage(org).await.unwrap().object_count, 0);
    for object in db
        .list_active_surface_objects(SurfaceTarget::Registry(registry_id))
        .await
        .unwrap()
    {
        assert!(db.surface_object_usage(object.id).await.unwrap().is_none());
    }
}
