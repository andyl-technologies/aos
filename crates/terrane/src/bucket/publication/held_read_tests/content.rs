//! Verifies fresh held content reads and every direct artifact boundary.

use super::*;
use crate::bucket::content_tests::{chunk_identity, raw, upload};
use crate::store::{ChunkPosition, ContentStore};
use terrane_core::identity::Identity;

struct ContentFixture {
    parent: PathBuf,
    bucket: FileBucket<ReadFs, TokioClock, Validator>,
    identity: Identity,
    encoded: Vec<u8>,
    pack: PathBuf,
}

async fn admitted() -> ContentFixture {
    let (parent, bucket) = fixture().await;
    let encoded = raw(b"held content disclosure");
    let identity = chunk_identity(b"held content disclosure");
    let profile = terrane_core::chunking::ChunkProfile::cdc_1m([0; 32]);
    bucket
        .put(upload(
            &encoded,
            &identity,
            b"held content disclosure".len(),
            &profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    let catalog = bucket.catalog().await.unwrap();
    let id = catalog
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == identity.digest())
        .unwrap()
        .pack();
    let pack = bucket.root().join(id.pack_key());
    ContentFixture {
        parent,
        bucket,
        identity,
        encoded,
        pack,
    }
}

#[tokio::test]
async fn held_content_get_preserves_all_exact_reads_and_reduces_metadata_dispatch() {
    let ContentFixture {
        parent,
        bucket,
        identity,
        encoded,
        ..
    } = admitted().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let adapter = holder.source();
    bucket.inner.fs.reset_read_counters();
    let started = TokioClock.monotonic();
    let ordinary = bucket.get_locked(&identity, None).await.unwrap();
    let ordinary_elapsed = TokioClock.monotonic().saturating_sub(started);
    let ordinary_counts = bucket.inner.fs.read_counters();
    let mut ordinary_paths = bucket.inner.fs.read_paths.lock().unwrap().clone();

    bucket.inner.fs.reset_read_counters();
    let started = TokioClock.monotonic();
    let held = adapter.get(&identity, None).await.unwrap();
    let held_elapsed = TokioClock.monotonic().saturating_sub(started);
    let held_counts = bucket.inner.fs.read_counters();
    let mut held_paths = bucket.inner.fs.read_paths.lock().unwrap().clone();
    ordinary_paths.sort();
    held_paths.sort();
    assert_eq!(ordinary, encoded);
    assert_eq!(held, ordinary);
    assert_eq!(held_paths, ordinary_paths);
    assert_eq!(held_counts.2, ordinary_counts.2);
    assert!(held_counts.1 < ordinary_counts.1);
    assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);
    assert_eq!(bucket.inner.fs.retained_effects.load(Ordering::SeqCst), 0);
    eprintln!(
        "held content entries/dispatches/GETs {ordinary_counts:?}->{held_counts:?}; actual elapsed {ordinary_elapsed:?}->{held_elapsed:?}"
    );

    let range = ByteRange {
        start: 1,
        length: 4,
    };
    assert_eq!(
        adapter.get(&identity, Some(range)).await.unwrap(),
        bucket.get_locked(&identity, Some(range)).await.unwrap()
    );
    let invalid = ByteRange {
        start: 0,
        length: encoded.len() as u64 + 1,
    };
    assert_eq!(
        adapter
            .get(&identity, Some(invalid))
            .await
            .unwrap_err()
            .kind(),
        bucket
            .get_locked(&identity, Some(invalid))
            .await
            .unwrap_err()
            .kind()
    );
    drop(adapter);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn held_content_get_refuses_actual_ancestry_change_after_body_read() {
    let ContentFixture {
        parent,
        bucket,
        identity,
        encoded,
        pack,
    } = admitted().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let adapter = holder.source();
    let original = TokioLocalFs.read_nofollow(&pack).await.unwrap();
    *bucket.inner.fs.permission_change.lock().unwrap() = Some((pack.clone(), parent.clone()));

    assert!(adapter.get(&identity, None).await.is_err());
    assert!(bucket.inner.fs.permission_change.lock().unwrap().is_none());
    assert_eq!(TokioLocalFs.read_nofollow(&pack).await.unwrap(), original);
    TokioLocalFs
        .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    assert_eq!(adapter.get(&identity, None).await.unwrap(), encoded);
    drop(adapter);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn held_content_get_refuses_replaced_leaf_even_when_body_bytes_match() {
    let ContentFixture {
        parent,
        bucket,
        identity,
        encoded,
        pack,
    } = admitted().await;
    let original = TokioLocalFs.read_nofollow(&pack).await.unwrap();
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let adapter = holder.source();
    *bucket.inner.fs.leaf_replacement.lock().unwrap() = Some(pack.clone());

    assert!(adapter.get(&identity, None).await.is_err());
    assert!(bucket.inner.fs.leaf_replacement.lock().unwrap().is_none());
    assert_eq!(TokioLocalFs.read_nofollow(&pack).await.unwrap(), original);
    assert_eq!(adapter.get(&identity, None).await.unwrap(), encoded);
    drop(adapter);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn held_content_get_preserves_unavailable_read_and_complete_body_verification() {
    let ContentFixture {
        parent,
        bucket,
        identity,
        pack,
        ..
    } = admitted().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let adapter = holder.source();
    *bucket.inner.fs.read_failure.lock().unwrap() = Some(pack.clone());
    assert!(matches!(
        adapter.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Unavailable { .. }
    ));
    assert!(matches!(
        bucket.get_locked(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Unavailable { .. }
    ));
    bucket.inner.fs.read_failure.lock().unwrap().take();

    let mut damaged = TokioLocalFs.read_nofollow(&pack).await.unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    tokio::fs::write(&pack, &damaged).await.unwrap();
    let range = ByteRange {
        start: 0,
        length: 1,
    };
    assert!(matches!(
        adapter
            .get(&identity, Some(range))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    assert!(matches!(
        bucket
            .get_locked(&identity, Some(range))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Corrupt(_)
    ));
    drop(adapter);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn held_content_get_rechecks_intervening_real_publication_before_return() {
    let ContentFixture {
        parent,
        bucket,
        identity,
        encoded,
        pack,
    } = admitted().await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let source = holder.source();
    let destination = holder.destination();
    let before = destination.observe_publication().await.unwrap();
    let (entered, arrived) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    *bucket.inner.fs.read_gate.lock().unwrap() = Some(ReadGate {
        target: pack,
        entered,
        release: released,
    });

    let (read, written) = tokio::join!(source.get(&identity, None), async {
        arrived.await.unwrap();
        let written = destination.publish_raw(&before, Vec::new()).await.unwrap();
        release.send(()).unwrap();
        written
    });
    assert!(matches!(
        read.unwrap_err().kind(),
        StoreErrorKind::Unavailable { .. }
    ));
    assert_eq!(written.stamp.0, before.stamp().0 + 1);
    assert_eq!(source.get(&identity, None).await.unwrap(), encoded);
    drop(before);
    drop(source);
    drop(destination);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn held_content_catalog_rejects_symlinked_cache_nodes_without_reads_or_repair() {
    let ContentFixture {
        parent,
        bucket,
        identity,
        ..
    } = admitted().await;
    let holder = SingleHeld::acquire_read_only(&bucket).await.unwrap();
    let adapter = holder.source();
    let selected = adapter.observe_publication().await.unwrap();
    let generation = super::super::projection::capabilities(selected.logical())
        .unwrap()
        .generation
        .unwrap();
    let capabilities = bucket.root().join("CAPABILITIES");
    let manifest_parent = bucket.root().join(format!("objects/index/{generation}"));

    for unsafe_node in [capabilities.clone(), manifest_parent.clone()] {
        let backup = unsafe_node.with_extension("held-read-backup");
        tokio::fs::rename(&unsafe_node, &backup).await.unwrap();
        std::os::unix::fs::symlink(&backup, &unsafe_node).unwrap();
        bucket.inner.fs.reset_read_counters();

        let baseline = bucket.get_locked(&identity, None).await.unwrap_err();
        let held = adapter.get(&identity, None).await.unwrap_err();
        assert_eq!(held.kind(), baseline.kind());
        assert!(matches!(held.kind(), StoreErrorKind::Corrupt(_)));
        let paths = bucket.inner.fs.read_paths.lock().unwrap().clone();
        assert!(
            !paths
                .iter()
                .any(|path| path == &capabilities || path.starts_with(&manifest_parent))
        );
        assert_eq!(bucket.inner.fs.writes.load(Ordering::SeqCst), 0);
        assert_eq!(bucket.inner.fs.retained_effects.load(Ordering::SeqCst), 0);

        tokio::fs::remove_file(&unsafe_node).await.unwrap();
        tokio::fs::rename(&backup, &unsafe_node).await.unwrap();
        selected.revalidate().await.unwrap();
    }
    drop(selected);
    drop(adapter);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}
