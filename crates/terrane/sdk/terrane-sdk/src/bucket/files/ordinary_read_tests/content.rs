//! Exercises ordinary optimization beneath complete content and final fences.

#![allow(clippy::unwrap_used, reason = "fixture failures are test assertions")]

use super::fixture::{Fault, Mode, bucket};
use crate::bucket::content_tests::{chunk_identity, fixture, raw, upload};
use crate::store::{ByteRange, ChunkPosition, ContentStore, InvalidReason, StoreErrorKind};

async fn populated() -> (
    crate::bucket::tests::Bucket,
    terrane_format::identity::Identity,
    Vec<u8>,
) {
    let source = fixture().await;
    let plaintext = b"verified ordinary optimization complete body";
    let identity = chunk_identity(plaintext);
    let encoded = raw(plaintext);
    source
        .put(upload(
            &encoded,
            &identity,
            plaintext.len(),
            &source.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    (source, identity, encoded)
}

/// Requires complete reads before rejecting an actual changed final parent.
///
/// # Panics
/// Panics if fixture construction, reads, or the required refusal fail.
pub(super) async fn parent_recheck_and_whole_body() {
    let (source, identity, encoded) = populated().await;
    let catalog = source.catalog().await.unwrap();
    let location = catalog
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == identity.digest())
        .unwrap();
    let path = source.root().join(location.pack().pack_key());

    for mode in [Mode::Native, Mode::Scalar] {
        let probe = bucket(&source, mode, Fault::None);
        assert_eq!(probe.get(&identity, None).await.unwrap(), encoded);
        assert!(probe.inner.fs.counts().1 > 0);
        if matches!(mode, Mode::Native) {
            assert_eq!(probe.inner.fs.counts().3, 0);
        }
    }
    let moved = source.root().with_extension("ordinary-recheck-moved");
    let probe = bucket(&source, Mode::Native, Fault::None);
    *probe.inner.fs.change_parent.lock().unwrap() =
        Some((path, source.root().to_owned(), moved.clone()));

    let result = probe.get(&identity, None).await;

    super::assert_layout(&result.unwrap_err());
    assert!(
        probe.inner.fs.change_parent.lock().unwrap().is_none(),
        "actual complete pack read must have preceded parent replacement"
    );
    assert!(
        std::fs::symlink_metadata(source.root())
            .unwrap()
            .file_type()
            .is_symlink()
    );
    std::fs::remove_file(source.root()).unwrap();
    std::fs::rename(moved, source.root()).unwrap();
    std::fs::remove_dir_all(source.root()).unwrap();
}

/// Requires equal native/scalar ranges and corruption outside a requested range.
///
/// # Panics
/// Panics if fixture construction or a complete-body verification assertion fails.
pub(super) async fn range_and_hash_rejections() {
    let (source, identity, encoded) = populated().await;
    for mode in [Mode::Native, Mode::Scalar] {
        let probe = bucket(&source, mode, Fault::None);
        assert_eq!(
            probe
                .get(
                    &identity,
                    Some(ByteRange {
                        start: 1,
                        length: 8
                    })
                )
                .await
                .unwrap(),
            b"verified"
        );
        for range in [
            ByteRange {
                start: 0,
                length: encoded.len() as u64 + 1,
            },
            ByteRange {
                start: u64::MAX,
                length: 1,
            },
        ] {
            assert_eq!(
                probe.get(&identity, Some(range)).await.unwrap_err().kind(),
                &StoreErrorKind::Invalid(InvalidReason::Range(range))
            );
        }
    }
    let catalog = source.catalog().await.unwrap();
    let location = catalog
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|entry| entry.entry().hash() == identity.digest())
        .unwrap();
    let path = source.root().join(location.pack().pack_key());
    let mut complete = std::fs::read(&path).unwrap();
    let offset = usize::try_from(location.entry().offset()).unwrap();
    complete[offset + encoded.len() - 1] ^= 1;
    std::fs::write(&path, complete).unwrap();

    for mode in [Mode::Native, Mode::Scalar] {
        let probe = bucket(&source, mode, Fault::None);
        for range in [
            None,
            Some(ByteRange {
                start: 0,
                length: 1,
            }),
        ] {
            assert!(matches!(
                probe.get(&identity, range).await.unwrap_err().kind(),
                StoreErrorKind::Corrupt(_)
            ));
        }
        assert!(probe.has(std::slice::from_ref(&identity)).await.is_err());
    }
    std::fs::remove_dir_all(source.root()).unwrap();
}
