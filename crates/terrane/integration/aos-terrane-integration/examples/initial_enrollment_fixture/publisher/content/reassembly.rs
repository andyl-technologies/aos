//! Verifies genuine Always and single-chunk Never publication and physical handoff.

use std::{collections::BTreeMap, io, os::unix::fs::FileExt};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{Identity, IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
};
use terrane_linux::host_cache::{NativeContentStore, NativePreparedObject};
use terrane_sdk::{
    host::cache::ReassemblyMode,
    store::{ChunkPosition, ChunkUpload, ContentStore, ContentUpload, MetaUpload},
};

pub(super) async fn exercise(store: &NativeContentStore, profile: &ChunkProfile) -> io::Result<()> {
    let first = super::repeated::natural_chunk(profile)?;
    let last = vec![71; 33];
    let mut chunks = Vec::new();
    let mut expected = Vec::new();
    for (bytes, position) in [
        (first.as_slice(), ChunkPosition::NonFinal),
        (last.as_slice(), ChunkPosition::Final),
    ] {
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
        chunks.push(ChunkRef {
            digest: identity.terrane_v1_digest().map_err(io::Error::other)?,
            length: bytes.len() as u64,
        });
        expected.extend_from_slice(bytes);
    }
    let multiple = admit_manifest(store, profile, chunks.clone(), &expected).await?;
    let single = admit_manifest(store, profile, vec![chunks[1].clone()], &last).await?;

    // Both canonical declarations exist before source retirement. The later
    // single-chunk publication must retain or reconstruct genuine source backing
    // after the first publication completes its actual cache handoff.
    for (identity, mode, plaintext) in [
        (&multiple, ReassemblyMode::Always, expected.as_slice()),
        (&single, ReassemblyMode::Never, last.as_slice()),
    ] {
        let NativePreparedObject::Sealed(object) = store
            .prepare_object(identity, mode)
            .await
            .map_err(io::Error::other)?
        else {
            return Err(io::Error::other("required whole object was not sealed"));
        };
        assert_eq!(object.identity(), identity);
        assert_eq!(object.claim().plaintext_size(), plaintext.len() as u64);
        assert_eq!(object.handle().metadata()?.len(), plaintext.len() as u64);
        terrane_linux::verity::measure(object.handle())?;

        let mut actual = vec![0; plaintext.len()];
        let mut offset = 0;
        while offset < actual.len() {
            let count = object
                .handle()
                .read_at(&mut actual[offset..], offset as u64)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sealed plaintext truncated",
                ));
            }
            offset += count;
        }
        assert_eq!(actual, plaintext);
        assert_eq!(object.handle().read_at(&mut [0], actual.len() as u64)?, 0);
        assert!(object.handle().write_at(b"forbidden", 0).is_err());

        let report = object.into_cache().await.map_err(io::Error::other)?;
        super::assert_cache_grace(store, identity, report.release_grace_ends_at).await?;
        store.ready().validate_portable().await?;
        println!(
            "PASS actual native {mode:?} manifest reassembly verified read-only fs-verity plaintext and completed source cleanup and cache handoff; chunks={} bytes={} released_admissions={}",
            if mode == ReassemblyMode::Always { 2 } else { 1 },
            plaintext.len(),
            report.released_source_admissions,
        );
    }
    Ok(())
}

async fn admit_manifest(
    store: &NativeContentStore,
    profile: &ChunkProfile,
    chunks: Vec<ChunkRef>,
    plaintext: &[u8],
) -> io::Result<Identity> {
    let canonical = Manifest {
        size: plaintext.len() as u64,
        chunks,
        hashes: BTreeMap::from([(
            "blake3".to_owned(),
            blake3::hash(plaintext).as_bytes().to_vec(),
        )]),
        media_type: None,
    }
    .encode(profile)
    .map_err(io::Error::other)?;
    store
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Manifest, &canonical).map_err(io::Error::other)?,
        ))
        .await
        .map_err(io::Error::other)
}
