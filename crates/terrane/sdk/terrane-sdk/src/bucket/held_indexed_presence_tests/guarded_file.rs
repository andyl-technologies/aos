//! Checks file-scoped membership against genuine signed native publications.

use terrane_format::{
    identity::{Digest, IdentityKind, TERRANE_V1},
    surface::View,
    tree_format::{ContentRef, Property},
};

use crate::{
    ref_advance::tests::{fixture, request_file, token},
    store::{ContentStore, IndexedContent, MAX_INDEXED_HASHES, StoreErrorKind, TokioLocalFs},
};

const REFERENCE: &str = "refs/heads/_/main";

fn chunk(bytes: &[u8]) -> Digest {
    TERRANE_V1
        .calculate(IdentityKind::Chunk, bytes)
        .unwrap()
        .terrane_v1_digest()
        .unwrap()
}

#[tokio::test]
async fn guarded_file_presence_uses_index_with_chunk_body_withheld() {
    let native = fixture().await;
    let bytes = b"independently withheld file body";
    let digest = chunk(bytes);
    let mut writer = native.begin(REFERENCE, &token(), "sdk").await.unwrap();
    native
        .advance(&mut writer, request_file(Vec::new(), bytes))
        .await
        .unwrap();
    let bucket = native.store();
    let catalog = bucket.catalog().await.unwrap();
    let pack = catalog
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|row| row.entry().hash() == &digest)
        .unwrap()
        .pack();
    let body = bucket.root().join(format!(
        "objects/pack/{}/{pack}.pack",
        &pack.to_string()[..2]
    ));
    let detached = body.with_extension("withheld-file-body");
    let view = View::parse(REFERENCE).unwrap();
    let prepared = native
        .repository()
        .prepare_file_read(&view, b"file", &token(), "sdk")
        .await
        .unwrap();
    assert_eq!(prepared.content(), ContentRef::Inline(digest));

    tokio::fs::rename(&body, &detached).await.unwrap();
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Chunk, &digest)
        .unwrap();
    assert!(bucket.get(&identity, None).await.is_err());
    let presence = prepared
        .indexed_presence(&[chunk(b"unknown"), digest, chunk(b""), digest])
        .await;
    tokio::fs::rename(&detached, &body).await.unwrap();

    assert_eq!(presence.unwrap(), [false, true, false, true]);
    assert_eq!(bucket.get(&identity, None).await.unwrap()[1..], *bytes);
}

#[tokio::test]
async fn guarded_file_presence_filters_stored_siblings_and_bounds_duplicates() {
    let native = fixture().await;
    let first = b"previously reachable content";
    let second = b"the selected current file";
    let mut writer = native.begin(REFERENCE, &token(), "sdk").await.unwrap();
    let old = native
        .advance(&mut writer, request_file(Vec::new(), first))
        .await
        .unwrap();
    native
        .advance(&mut writer, request_file(vec![old.commit], second))
        .await
        .unwrap();
    assert_eq!(
        native
            .store()
            .indexed_presence(&[chunk(first)])
            .await
            .unwrap(),
        [true]
    );
    let view = View::parse(REFERENCE).unwrap();

    for (hashes, expected) in [
        (Vec::new(), Vec::new()),
        (vec![chunk(first)], vec![false]),
        (
            vec![chunk(second); MAX_INDEXED_HASHES],
            vec![true; MAX_INDEXED_HASHES],
        ),
    ] {
        let prepared = native
            .repository()
            .prepare_file_read(&view, b"file", &token(), "sdk")
            .await
            .unwrap();
        assert_eq!(prepared.indexed_presence(&hashes).await.unwrap(), expected);
    }
    let prepared = native
        .repository()
        .prepare_file_read(&view, b"file", &token(), "sdk")
        .await
        .unwrap();
    assert!(matches!(
        prepared.indexed_presence(&vec![chunk(second); MAX_INDEXED_HASHES + 1]).await,
        Err(crate::repository::Error::Store(error))
            if matches!(error.kind(), StoreErrorKind::Invalid(_))
    ));
}

#[tokio::test]
async fn guarded_file_presence_refuses_changed_whole_policy_reference() {
    let native = fixture().await;
    let bytes = b"unchanged file bytes across publication";
    let mut writer = native.begin(REFERENCE, &token(), "sdk").await.unwrap();
    let old = native
        .advance(&mut writer, request_file(Vec::new(), bytes))
        .await
        .unwrap();
    let view = View::parse(REFERENCE).unwrap();
    let prepared = native
        .repository()
        .prepare_file_read(&view, b"file", &token(), "sdk")
        .await
        .unwrap();

    native
        .advance(&mut writer, request_file(vec![old.commit], bytes))
        .await
        .unwrap();
    assert!(prepared.indexed_presence(&[chunk(bytes)]).await.is_err());
}

#[tokio::test]
async fn guarded_manifest_presence_verifies_metadata_without_chunk_reads() {
    let native = fixture().await;
    let source = native.store().root().with_extension("manifest-source");
    tokio::fs::create_dir(&source).await.unwrap();
    let bytes = vec![7; native.guard().config().chunk_profile.maximum() * 2];
    tokio::fs::write(source.join("file"), &bytes).await.unwrap();
    let prepared_tree = crate::repository::import_directory(
        &TokioLocalFs,
        &source,
        &native.guard().config().chunk_profile,
        &[
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ],
    )
    .await
    .unwrap();
    tokio::fs::remove_dir_all(&source).await.unwrap();
    let mut request = request_file(Vec::new(), b"unused");
    request.commit.tree = prepared_tree.root;
    request.uploads = prepared_tree.uploads;
    let mut writer = native.begin(REFERENCE, &token(), "sdk").await.unwrap();
    native.advance(&mut writer, request).await.unwrap();
    let view = View::parse(REFERENCE).unwrap();
    let prepared = native
        .repository()
        .prepare_file_read(&view, b"file", &token(), "sdk")
        .await
        .unwrap();
    let ContentRef::Manifest(digest) = prepared.content() else {
        panic!("expected CDC manifest")
    };
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Manifest, &digest)
        .unwrap();
    let encoded = native.store().get(&identity, None).await.unwrap();
    let manifest = terrane_format::manifest::Manifest::decode_verified(
        &encoded,
        &native.guard().config().chunk_profile,
        &identity,
    )
    .unwrap();
    assert!(manifest.chunks.len() > 1);
    let mut hashes = vec![digest, chunk(b"outside selected file")];
    hashes.extend(manifest.chunks.iter().map(|reference| reference.digest));
    let expected: Vec<_> = hashes.iter().map(|hash| *hash != hashes[1]).collect();
    let mut detached = Vec::new();
    let catalog = native.store().catalog().await.unwrap();
    let packs: std::collections::BTreeSet<_> = catalog
        .shards
        .iter()
        .flat_map(|shard| shard.entries())
        .filter(|row| {
            manifest
                .chunks
                .iter()
                .any(|reference| reference.digest == *row.entry().hash())
        })
        .map(|row| row.pack().to_string())
        .collect();
    for pack in packs {
        let body = native
            .store()
            .root()
            .join(format!("objects/pack/{}/{pack}.pack", &pack[..2]));
        let withheld = body.with_extension("withheld-manifest-chunk");
        tokio::fs::rename(&body, &withheld).await.unwrap();
        detached.push((body, withheld));
    }
    let presence = prepared.indexed_presence(&hashes).await;
    for (body, withheld) in detached {
        tokio::fs::rename(withheld, body).await.unwrap();
    }
    assert_eq!(presence.unwrap(), expected);
}
