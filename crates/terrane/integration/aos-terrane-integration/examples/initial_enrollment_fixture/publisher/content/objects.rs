//! Exercises real chunked object opening after reopening native recovery custody.

use std::{
    collections::BTreeMap,
    io::{self, Read},
};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
};
use terrane_linux::host_cache::{NativeContentStore, NativePreparedObject};
use terrane_sdk::host::cache::ReassemblyMode;
use terrane_sdk::store::{
    ByteRange, ChunkPosition, ChunkUpload, Clock, ContentStore, ContentUpload, MetaUpload,
    StoreErrorKind, TokioClock,
};

pub(super) async fn exercise(store: &NativeContentStore, profile: &ChunkProfile) -> io::Result<()> {
    let state = terrane_sdk::host::cache::CacheState::load(
        &terrane_sdk::store::TokioLocalFs,
        &store.ready().layout().layout().root().join("state/cache"),
        terrane_sdk::host::cache::StateLimits {
            bytes: 65536,
            records: 64,
        },
    )
    .await
    .map_err(io::Error::other)?
    .ok_or_else(|| io::Error::other("reopened cache state absent"))?;
    println!(
        "OBJECT_OPEN_REOPENED_STATE pins={} leases={} reservations={} residences={}",
        state.pins.len(),
        state.leases.len(),
        state.reservations.len(),
        state.residences.len()
    );
    let plaintext = super::repeated::natural_chunk(profile)?;
    let final_bytes = vec![41; 33];
    let mut references = Vec::new();
    let mut expected = Vec::new();
    for (bytes, position) in [
        (plaintext.as_slice(), ChunkPosition::NonFinal),
        (final_bytes.as_slice(), ChunkPosition::Final),
    ] {
        println!(
            "OBJECT_OPEN_STAGE admit-chunk position={position:?} bytes={}",
            bytes.len()
        );
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, bytes)
            .map_err(io::Error::other)?;
        let mut encoded = vec![0];
        encoded.extend_from_slice(bytes);
        store
            .put(ContentUpload::Chunk(ChunkUpload {
                encoded: &encoded,
                identity: &identity,
                declared_plaintext_len: bytes.len(),
                position,
                profile,
            }))
            .await
            .map_err(io::Error::other)?;
        references.push(ChunkRef {
            digest: identity.terrane_v1_digest().map_err(io::Error::other)?,
            length: bytes.len() as u64,
        });
        expected.extend_from_slice(bytes);
    }
    let mut manifest = Manifest {
        size: expected.len() as u64,
        chunks: references,
        hashes: BTreeMap::from([(
            "blake3".to_owned(),
            blake3::hash(&expected).as_bytes().to_vec(),
        )]),
        media_type: None,
    };
    let canonical = manifest.encode(profile).map_err(io::Error::other)?;
    println!("OBJECT_OPEN_STAGE admit-manifest");
    let identity = store
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Manifest, &canonical).map_err(io::Error::other)?,
        ))
        .await
        .map_err(io::Error::other)?;

    println!("OBJECT_OPEN_STAGE open-manifest");
    let NativePreparedObject::Chunked(object) = store
        .prepare_object(&identity, ReassemblyMode::Never)
        .await
        .map_err(io::Error::other)?
    else {
        return Err(io::Error::other("never mode sealed a multi-chunk object"));
    };
    let object = *object;
    assert_eq!(object.identity(), &identity);
    assert_eq!(object.plaintext_size(), expected.len() as u64);

    let boundary = plaintext.len() - 13;
    let range = ByteRange {
        start: boundary as u64,
        length: 29,
    };
    assert_eq!(
        object.read_range(range).map_err(io::Error::other)?,
        expected[boundary..boundary + 29]
    );
    assert_eq!(
        terrane_sdk::derived::PlaintextObject::read_range(&object, boundary as u64, 29)
            .await
            .map_err(io::Error::other)?,
        expected[boundary..boundary + 29]
    );
    assert_eq!(
        terrane_sdk::derived::PlaintextObject::digest(&object),
        identity.terrane_v1_digest().map_err(io::Error::other)?
    );
    assert_eq!(
        terrane_sdk::derived::PlaintextObject::size(&object),
        expected.len() as u64
    );
    assert!(
        object
            .read_range(ByteRange {
                start: expected.len() as u64,
                length: 0
            })
            .map_err(io::Error::other)?
            .is_empty()
    );
    assert!(matches!(
        object.read_range(ByteRange { start: u64::MAX, length: 1 }),
        Err(error) if matches!(error.kind(), StoreErrorKind::Invalid(_))
    ));
    assert!(matches!(
        terrane_sdk::derived::PlaintextObject::read_range(
            &object,
            0,
            terrane_format::derived::MAGIC_PREFIX_LIMIT + 1
        )
        .await,
        Err(terrane_sdk::derived::Error::Derived(
            terrane_format::derived::Error::Limit
        ))
    ));
    println!(
        "PASS actual native SDK plaintext object ranges cross chunk boundaries and preserve read limits"
    );

    let mut actual = Vec::new();
    object.reader().read_to_end(&mut actual)?;
    assert_eq!(actual, expected);
    let expires = object.expires_at().map_err(io::Error::other)?;
    TokioClock
        .sleep(std::time::Duration::from_secs(1))
        .await
        .map_err(io::Error::other)?;
    object.renew().await.map_err(io::Error::other)?;
    assert!(object.expires_at().map_err(io::Error::other)? > expires);
    let mut prefix = [0; 17];
    object.reader().read_exact(&mut prefix)?;
    assert_eq!(prefix, expected[..17]);
    object.close().await.map_err(io::Error::other)?;

    // Individually valid chunks cannot excuse a false whole-file declaration.
    manifest
        .hashes
        .get_mut("blake3")
        .ok_or_else(|| io::Error::other("fixture hash absent"))?[0] ^= 1;
    let invalid = manifest.encode(profile).map_err(io::Error::other)?;
    let invalid_identity = store
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Manifest, &invalid).map_err(io::Error::other)?,
        ))
        .await
        .map_err(io::Error::other)?;
    assert!(
        matches!(store.open_manifest_chunks(&invalid_identity).await,
        Err(error) if matches!(error.kind(), StoreErrorKind::Corrupt(_)))
    );
    println!(
        "PASS actual chunked object opening verifies ordered plaintext and whole-file hashes, restarts readers and creates no sealed output"
    );
    Ok(())
}
