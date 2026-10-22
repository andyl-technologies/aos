//! Exercises original recovered manifest backing and final metadata-custody release.

use super::*;
use std::collections::BTreeMap;
use terrane_format::manifest::{ChunkRef, Manifest};
use terrane_sdk::store::MetaUpload;

/// Builds the same genuine canonical single-chunk manifest in independent actors.
fn material(profile: &ChunkProfile) -> io::Result<(Identity, Identity, Vec<u8>, Vec<u8>)> {
    let natural = super::super::repeated::natural_chunk(profile)?;
    let plaintext = natural[..profile.minimum() + 1].to_vec();
    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, &plaintext)
        .map_err(io::Error::other)?;
    let canonical = Manifest {
        size: plaintext.len() as u64,
        chunks: vec![ChunkRef {
            digest: chunk.terrane_v1_digest().map_err(io::Error::other)?,
            length: plaintext.len() as u64,
        }],
        hashes: BTreeMap::from([(
            "blake3".to_owned(),
            blake3::hash(&plaintext).as_bytes().to_vec(),
        )]),
        media_type: None,
    }
    .encode(profile)
    .map_err(io::Error::other)?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Manifest, &canonical)
        .map_err(io::Error::other)?;
    Ok((identity, chunk, plaintext, canonical))
}

pub(super) async fn seed(
    store: &NativeContentStore,
    profile: &ChunkProfile,
    domain: &str,
) -> io::Result<()> {
    let (identity, chunk, plaintext, canonical) = material(profile)?;
    let mut encoded = vec![0];
    encoded.extend_from_slice(&plaintext);
    store
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &encoded,
            identity: &chunk,
            declared_plaintext_len: plaintext.len(),
            position: ChunkPosition::Final,
            profile,
        }))
        .await
        .map_err(io::Error::other)?;
    let actual = store
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Manifest, &canonical).map_err(io::Error::other)?,
        ))
        .await
        .map_err(io::Error::other)?;
    assert_eq!(actual, identity);
    // Manifest validation holds genuine source consumers through release grace.
    // Observe their durable deadlines before moving those original sources.
    super::super::reassembly::wait_consumer_grace(store).await?;
    let NativePreparedObject::Sealed(object) = store
        .prepare_object(&identity, terrane_sdk::host::cache::ReassemblyMode::Never)
        .await
        .map_err(io::Error::other)?
    else {
        return Err(io::Error::other(
            "cold manifest release seed escaped mandatory sealing",
        ));
    };
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(15)
        .ok_or_else(|| io::Error::other("cold manifest seed expiry overflows"))?;
    let lease = object
        .pin_consumer(expires)
        .await
        .map_err(io::Error::other)?;
    object.into_cache().await.map_err(io::Error::other)?;
    store.ready().validate_portable().await?;
    drop(lease);
    println!(
        "PASS actual cold {domain} manifest seed retains original sealed inode and acknowledged finite consumer expiry {expires}"
    );
    Ok(())
}

pub(super) async fn recovered(
    store: &NativeContentStore,
    profile: &ChunkProfile,
    domain: &str,
) -> io::Result<()> {
    let (identity, _, plaintext, _) = material(profile)?;
    let before = super::super::metadata_policy(store).await?;
    let object_hash = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let purposes = before
        .pins
        .iter()
        .filter(|pin| pin.hash == object_hash && pin.owner.starts_with("metadata:"))
        .map(|pin| pin.owner.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(purposes.len() >= 2);
    super::recover_material(store, domain, identity, plaintext).await?;
    let after = super::super::metadata_policy(store).await?;
    for purpose in purposes {
        let token = purpose
            .strip_prefix("metadata:")
            .ok_or_else(|| io::Error::other("manifest metadata purpose changed"))?;
        if domain.starts_with("private:") {
            assert!(!after.pins.iter().any(|row| row.owner == purpose));
            assert!(!after.leases.iter().any(|row| row.owner == purpose));
            assert!(!after.reservations.iter().any(|row| row.id == token));
        } else {
            assert!(after.pins.iter().any(|row| row.owner == purpose));
            assert!(after.reservations.iter().any(|row| row.id == token));
        }
    }
    println!(
        "PASS actual cold {domain} recovered manifest release preserves public or removes exact old and current metadata custody after original backing closure"
    );
    Ok(())
}
