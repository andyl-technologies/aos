//! Verifies immediate nonempty inline sealing without a synthetic consumer grant.

use std::{collections::BTreeSet, io, os::unix::fs::FileExt};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
};
use terrane_linux::host_cache::{NativeContentStore, NativePreparedObject};
use terrane_sdk::{
    host::cache::ReassemblyMode,
    store::{ChunkPosition, ChunkUpload, ContentStore, ContentUpload},
};

pub(super) async fn exercise(store: &NativeContentStore, profile: &ChunkProfile) -> io::Result<()> {
    let plaintext = vec![47; 1337];
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &plaintext)
        .map_err(io::Error::other)?;
    let mut encoded = vec![0];
    encoded.extend_from_slice(&plaintext);
    store
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &encoded,
            identity: &identity,
            declared_plaintext_len: plaintext.len(),
            position: ChunkPosition::Final,
            profile,
        }))
        .await
        .map_err(io::Error::other)?;

    let before = consumer_owners(store).await?;
    // There is deliberately no consumer-grace delay between admission and seal.
    let NativePreparedObject::Sealed(object) = store
        .prepare_object(&identity, ReassemblyMode::Never)
        .await
        .map_err(io::Error::other)?
    else {
        return Err(io::Error::other(
            "nonempty inline object escaped mandatory sealing",
        ));
    };
    assert_eq!(object.identity(), &identity);
    assert_eq!(object.claim().plaintext_size(), plaintext.len() as u64);
    assert_eq!(object.handle().metadata()?.len(), plaintext.len() as u64);
    terrane_linux::verity::measure(object.handle())?;
    let mut actual = vec![0; plaintext.len()];
    object.handle().read_exact_at(&mut actual, 0)?;
    assert_eq!(actual, plaintext);
    assert!(object.handle().write_at(b"forbidden", 0).is_err());
    assert!(consumer_owners(store).await?.is_subset(&before));

    let report = object.into_cache().await.map_err(io::Error::other)?;
    assert_eq!(report.released_source_admissions, 1);
    assert!(consumer_owners(store).await?.is_subset(&before));
    super::super::assert_cache_grace(store, &identity, report.release_grace_ends_at).await?;
    store.ready().validate_portable().await?;
    println!(
        "PASS actual native nonempty inline sealing without a new consumer grant; bytes=1337 released_admissions=1"
    );
    Ok(())
}

async fn consumer_owners(store: &NativeContentStore) -> io::Result<BTreeSet<String>> {
    Ok(super::load_policy(store)
        .await?
        .leases
        .into_iter()
        .filter_map(|lease| lease.owner.starts_with("consumer").then_some(lease.owner))
        .collect())
}
