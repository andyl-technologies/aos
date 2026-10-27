//! Preserves both genuine catalog preimages when concurrent misses race publication.

use super::*;
use std::os::unix::fs::MetadataExt;
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};

#[tokio::test]
async fn gc_catalog_sharing_retains_concurrent_miss_preimages() {
    let fixture = Fixture::new().await;
    let session = metadata_session(&fixture).await;
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let before_state = observed.state().clone();
    let before_logical = observed.logical().clone();
    let capabilities =
        BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let generation = capabilities.generation.unwrap();
    let manifest = GenerationManifest::decode(
        observed.logical()[&format!("objects/index/{generation}/MANIFEST")]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.generation, generation);
    let shard = manifest.shards.first().unwrap();
    let path = fixture
        .config
        .root
        .join(format!("objects/index/{generation}/{}.idx", shard.shard));
    let original = tokio::fs::read(&path).await.unwrap();
    let old_metadata = tokio::fs::symlink_metadata(&path).await.unwrap();
    let store = MetadataStore::new(&held, &observed, &session);
    let (arrived, release) = fixture.fs.pause_next_catalog_read(path.clone());
    let mut first = Box::pin(store.collection_catalog());
    tokio::select! {
        result = &mut first => panic!("first catalog miss did not pause: {}", result.is_ok()),
        result = tokio::time::timeout(Duration::from_secs(10), arrived) => result.unwrap().unwrap(),
    }

    // Arrival follows the actual native leaf read. Only its delivery is paused,
    // so the second miss sees equal canonical bytes under a distinct live inode.
    let replacement = path.with_extension("concurrent-replacement");
    tokio::fs::write(&replacement, &original).await.unwrap();
    tokio::fs::set_permissions(&replacement, old_metadata.permissions())
        .await
        .unwrap();
    tokio::fs::rename(&replacement, &path).await.unwrap();
    let new_metadata = tokio::fs::symlink_metadata(&path).await.unwrap();
    assert_eq!(old_metadata.dev(), new_metadata.dev());
    assert_ne!(old_metadata.ino(), new_metadata.ino());
    let second = tokio::time::timeout(Duration::from_secs(10), store.collection_catalog())
        .await
        .unwrap()
        .unwrap();
    release.send(()).unwrap();
    let first = tokio::time::timeout(Duration::from_secs(10), first)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.capability_bytes(), second.capability_bytes());
    assert_eq!(first.inventory().unwrap(), second.inventory().unwrap());

    let reads = store.reads().unwrap();
    let preimages = reads
        .iter()
        .filter(|read| read.path() == path)
        .collect::<Vec<_>>();
    assert_eq!(preimages.len(), 2);
    for (metadata, read) in [
        (
            &old_metadata,
            preimages
                .iter()
                .find(|read| read.metadata().unwrap().ino() == old_metadata.ino())
                .unwrap(),
        ),
        (
            &new_metadata,
            preimages
                .iter()
                .find(|read| read.metadata().unwrap().ino() == new_metadata.ino())
                .unwrap(),
        ),
    ] {
        assert_eq!(read.bytes(), Some(original.as_slice()));
        let actual = read.metadata().unwrap();
        assert_eq!(actual.dev(), metadata.dev());
        assert_eq!(actual.ino(), metadata.ino());
        assert_eq!(actual.len(), metadata.len());
        assert_eq!(actual.mode(), metadata.mode());
        assert_eq!(actual.uid(), metadata.uid());
        assert_eq!(actual.gid(), metadata.gid());
        assert_eq!(actual.mtime(), metadata.mtime());
        assert_eq!(actual.mtime_nsec(), metadata.mtime_nsec());
    }
    assert!(store.identities().unwrap().is_empty());
    let reused = store.collection_catalog().await.unwrap();
    assert_eq!(reused.capability_bytes(), second.capability_bytes());
    assert_eq!(store.reads().unwrap().len(), reads.len());

    // A fresh operation must observe the replacement itself. The raced ledger
    // above remains intact; it grants no checkpoint or publication authority.
    let fresh = MetadataStore::new(&held, &observed, &session);
    fresh.collection_catalog().await.unwrap();
    let fresh_reads = fresh.reads().unwrap();
    let current = fresh_reads
        .iter()
        .filter(|read| read.path() == path)
        .collect::<Vec<_>>();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].metadata().unwrap().ino(), new_metadata.ino());
    assert_eq!(current[0].bytes(), Some(original.as_slice()));
    assert_eq!(store.reads().unwrap().len(), reads.len());
    session.recheck().unwrap();
    observed.revalidate().await.unwrap();
    let after = held.observe_publication_unrepaired().await.unwrap();
    assert_eq!(after.state(), &before_state);
    assert_eq!(after.logical(), &before_logical);
    drop(after);
    drop(fresh);
    drop(store);
    drop(observed);
    drop(held);
    drop(holder);
    assert_eq!(
        fixture
            .guard()
            .store()
            .ref_get("refs/heads/_/main")
            .await
            .unwrap(),
        Some(fixture.head.clone())
    );
    drop(session);
    fixture.cleanup();
}
