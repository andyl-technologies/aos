//! Observes private erasure and public retention through actual independent grants.
//!
//! This explicit guest fixture uses original sealed backing and authenticated
//! whole-project quota queries. It neither asks for pressure eviction nor opens
//! the publisher's private namespace as the content identity.

use super::super::super::config::{Case, DOMAINS, OWNERS};
use std::{
    fs::File,
    io,
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt},
    },
    time::{Duration, UNIX_EPOCH},
};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
};
use terrane_linux::{
    host_cache::{NativeContentStore, NativePreparedObject},
    host_quota::HostQuotaClient,
};
use terrane_sdk::store::{
    ChunkPosition, ChunkUpload, Clock, ContentStore, ContentUpload, TokioClock,
};

pub(super) async fn exercise(
    store: &NativeContentStore,
    profile: &ChunkProfile,
    domain: &str,
) -> io::Result<()> {
    let index = DOMAINS
        .iter()
        .position(|candidate| *candidate == domain)
        .ok_or_else(|| io::Error::other("unknown actual release domain"))?;
    let case = Case::existing("positive")?;
    let mut quota = HostQuotaClient::connect(&case.socket(), 0, 1u128.to_be_bytes())?;
    let plaintext = vec![61; 1337];
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
    let NativePreparedObject::Sealed(object) = store
        .prepare_object(&identity, terrane_sdk::host::cache::ReassemblyMode::Never)
        .await
        .map_err(io::Error::other)?
    else {
        return Err(io::Error::other(
            "private release escaped mandatory sealing",
        ));
    };
    let original = object.handle().metadata()?;
    let inode = (original.dev(), original.ino());
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(25)
        .ok_or_else(|| io::Error::other("release expiry overflows"))?;
    let first = object
        .pin_consumer(expires)
        .await
        .map_err(io::Error::other)?;
    let second = object
        .pin_consumer(expires)
        .await
        .map_err(io::Error::other)?;
    assert_ne!(first.owner(), second.owner());
    let allocated = first.initial_accounting().synchronized_sealed_inode_bytes;
    assert!(allocated > 0);
    let backing = first.backing()?;
    let descriptor = File::from(backing.as_fd().try_clone_to_owned()?);
    check_original(&descriptor, inode, &plaintext)?;
    terrane_linux::verity::measure(&descriptor)?;
    object.into_cache().await.map_err(io::Error::other)?;

    let owner = store.ready().owner();
    owner.release_sealed_object_lease(&first).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    owner.sweep_consumer_leases().await?;
    let protected = super::metadata_policy(store).await?;
    assert!(protected.pins.iter().any(|pin| pin.owner == second.owner()));
    assert!(first.backing().is_err());
    assert_eq!(descriptor.metadata()?.nlink(), 1);
    check_original(&descriptor, inode, &plaintext)?;
    println!(
        "PASS actual {domain} independent second consumer prevents early sealed retirement after first release"
    );

    owner.release_sealed_object_lease(&second).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    owner.sweep_consumer_leases().await?;
    let released = super::metadata_policy(store).await?;
    assert!(
        !released
            .pins
            .iter()
            .any(|pin| pin.owner == first.owner() || pin.owner == second.owner())
    );
    assert!(second.backing().is_err());
    if domain.starts_with("private:") {
        let deadline = TokioClock.monotonic() + Duration::from_secs(8);
        while descriptor.metadata()?.nlink() != 0 {
            if TokioClock.monotonic() >= deadline {
                return Err(io::Error::other(
                    "private sealed inode survived final release without quota pressure",
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    } else {
        assert_eq!(descriptor.metadata()?.nlink(), 1);
    }
    check_original(&descriptor, inode, &plaintext)?;
    let retained = quota
        .query(OWNERS[index], domain)?
        .observation()
        .charged_reserved_bytes;
    assert!(retained >= allocated);
    // A delegated fd closes before its tracked owner. Neither revoked lease nor
    // namespace removal proves that the original kernel allocation has closed.
    drop(descriptor);
    drop(backing);
    drop(first);
    drop(second);

    if domain.starts_with("private:") {
        let deadline = TokioClock.monotonic() + Duration::from_secs(8);
        loop {
            let actual = quota
                .query(OWNERS[index], domain)?
                .observation()
                .charged_reserved_bytes;
            if actual
                .checked_add(allocated)
                .is_some_and(|total| total <= retained)
            {
                break;
            }
            if TokioClock.monotonic() >= deadline {
                return Err(io::Error::other(
                    "private sealed allocation remained charged after actual backing closure",
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!(
            "PASS actual private sealed inode retires without pressure and original project charge falls only after retained backing closes"
        );
    } else {
        let actual = quota
            .query(OWNERS[index], domain)?
            .observation()
            .charged_reserved_bytes;
        assert!(actual >= retained);
        println!(
            "PASS actual public sealed cache retains original allocation after final consumer and backing release without pressure"
        );
    }
    store.ready().validate_portable().await?;
    Ok(())
}

fn check_original(file: &File, inode: (u64, u64), plaintext: &[u8]) -> io::Result<()> {
    let metadata = file.metadata()?;
    assert_eq!((metadata.dev(), metadata.ino()), inode);
    let mut bytes = vec![0; plaintext.len()];
    file.read_exact_at(&mut bytes, 0)?;
    assert_eq!(bytes, plaintext);
    assert_eq!(file.read_at(&mut [0], plaintext.len() as u64)?, 0);
    assert!(file.write_at(b"forbidden", 0).is_err());
    Ok(())
}
