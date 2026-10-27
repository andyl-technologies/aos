//! Exercises real content operations after the physical owner's acknowledged Resume.

#[path = "content/objects.rs"]
mod objects;
#[path = "content/reassembly.rs"]
mod reassembly;
#[path = "content/release.rs"]
mod release;
#[path = "content/repeated.rs"]
mod repeated;

use std::{collections::BTreeMap, io};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
};
use terrane_linux::host_cache::NativeContentStore;
use terrane_sdk::store::{
    ByteRange, ChunkPosition, ChunkUpload, ContentStore, ContentUpload, IdentityPrefix,
    InvalidReason, MetaUpload, StoreErrorKind,
};

pub(super) async fn seed_manifest_release(
    store: &NativeContentStore,
    profile: &ChunkProfile,
    domain: &str,
) -> io::Result<()> {
    release::seed_manifest(store, profile, domain).await
}

pub(super) async fn recovered_manifest_release(
    store: &NativeContentStore,
    profile: &ChunkProfile,
    domain: &str,
) -> io::Result<()> {
    release::recovered_manifest(store, profile, domain).await
}

pub(super) async fn exercise(store: &NativeContentStore, profile: &ChunkProfile) -> io::Result<()> {
    let plaintext = vec![23; 32769];
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &plaintext)
        .map_err(io::Error::other)?;
    let mut encoded = vec![0];
    encoded.extend_from_slice(&plaintext);
    let upload = ChunkUpload {
        encoded: &encoded,
        identity: &identity,
        declared_plaintext_len: plaintext.len(),
        position: ChunkPosition::Final,
        profile,
    };

    assert_eq!(
        store
            .put(ContentUpload::Chunk(upload))
            .await
            .map_err(io::Error::other)?,
        identity
    );
    assert_eq!(
        store.get(&identity, None).await.map_err(io::Error::other)?,
        encoded
    );
    assert_eq!(
        store
            .get(
                &identity,
                Some(ByteRange {
                    start: 0,
                    length: 2
                })
            )
            .await
            .map_err(io::Error::other)?,
        [0, 23]
    );
    assert!(
        matches!(store.get(&identity, Some(ByteRange { start: u64::MAX, length: 2 })).await,
        Err(error) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::Range(_))))
    );

    // An existing plaintext identity cannot excuse a newly invalid declaration
    // or nonfinal CDC position. Both refusals must preserve its original bytes.
    for (offered, expected_rule) in [
        (
            ChunkUpload {
                declared_plaintext_len: plaintext.len() + 1,
                ..upload
            },
            "CDC-12",
        ),
        (
            ChunkUpload {
                position: ChunkPosition::NonFinal,
                ..upload
            },
            "CDC-15",
        ),
    ] {
        assert!(matches!(store.put(ContentUpload::Chunk(offered)).await,
            Err(error) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::Upload { rule_id }) if *rule_id == expected_rule)));
    }
    assert_eq!(
        store.get(&identity, None).await.map_err(io::Error::other)?,
        encoded
    );

    let absent = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"never admitted here")
        .map_err(io::Error::other)?;
    let empty = TERRANE_V1
        .calculate(IdentityKind::Chunk, &[])
        .map_err(io::Error::other)?;
    assert_eq!(
        store
            .has(&[identity.clone(), absent, empty.clone()])
            .await
            .map_err(io::Error::other)?,
        [true, false, true]
    );
    assert_eq!(
        store.get(&empty, None).await.map_err(io::Error::other)?,
        [0]
    );

    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks: vec![ChunkRef {
            digest: identity.terrane_v1_digest().map_err(io::Error::other)?,
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
    let upload = MetaUpload::new(IdentityKind::Manifest, &manifest).map_err(io::Error::other)?;
    let metadata = store
        .put(ContentUpload::Meta(upload))
        .await
        .map_err(io::Error::other)?;
    assert_eq!(
        store.get(&metadata, None).await.map_err(io::Error::other)?,
        manifest
    );
    let before = metadata_policy(store).await?;
    assert_eq!(
        store
            .put(ContentUpload::Meta(upload))
            .await
            .map_err(io::Error::other)?,
        metadata
    );
    let after = metadata_policy(store).await?;
    let added = after
        .leases
        .iter()
        .filter(|lease| !before.leases.iter().any(|old| old.owner == lease.owner))
        .collect::<Vec<_>>();
    // A duplicate manifest still verifies its chunk dependency and acquires an
    // independent original pack/index grant before reporting an existing copy.
    assert_eq!(added.len(), 2);
    let metadata_hash: String = metadata
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        added
            .iter()
            .filter(|lease| {
                let pins = after
                    .pins
                    .iter()
                    .filter(|pin| pin.owner == lease.owner)
                    .collect::<Vec<_>>();
                pins.len() == 2 && pins.iter().any(|pin| pin.hash == metadata_hash)
            })
            .count(),
        1
    );
    assert_eq!(after.pins.len(), before.pins.len() + 3);
    assert_eq!(after.reservations.len(), before.reservations.len() + 2);
    assert_eq!(after.residences.len(), before.residences.len());
    for old in &before.pins {
        assert!(after.pins.iter().any(|pin| pin.owner == old.owner
            && pin.hash == old.hash
            && pin.expires == old.expires));
    }
    println!(
        "PASS actual duplicate metadata upload retains independent original pair consumer grace and verifies dependency before deduplication"
    );
    assert_eq!(
        store
            .has(std::slice::from_ref(&metadata))
            .await
            .map_err(io::Error::other)?,
        [true]
    );
    for candidate in [&identity, &metadata] {
        assert_eq!(
            store
                .list(&IdentityPrefix {
                    kind: candidate.kind(),
                    digest_prefix: candidate.digest().to_vec(),
                })
                .await
                .map_err(io::Error::other)?,
            std::slice::from_ref(candidate)
        );
    }
    assert!(matches!(store.list(&IdentityPrefix {
        kind: IdentityKind::Chunk,
        digest_prefix: vec![0; 33],
    }).await, Err(error) if matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::MalformedRequest))));
    println!(
        "PASS actual native advisory listing finds ordinary chunk and metadata candidates and rejects malformed prefixes"
    );
    repeated::exercise(store, profile).await?;
    Ok(())
}

/// Exercises chunked objects separately from the finite 65-reference admission case.
pub(super) async fn exercise_objects(
    store: &NativeContentStore,
    profile: &ChunkProfile,
) -> io::Result<()> {
    objects::exercise(store, profile).await
}

/// Seals the canonical empty inline object without a fabricated source admission.
pub(super) async fn exercise_sealed(
    cache: &terrane_linux::configured::NativeConfiguredCache,
) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    use terrane_linux::host_cache::NativePreparedObject;

    let store = cache.content();
    assert_eq!(
        cache.reassembly(),
        terrane_sdk::host::cache::ReassemblyMode::Never
    );
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &[])
        .map_err(io::Error::other)?;
    let NativePreparedObject::Sealed(object) = cache
        .prepare_object(&identity)
        .await
        .map_err(io::Error::other)?
    else {
        return Err(io::Error::other("inline object escaped mandatory sealing"));
    };
    assert_eq!(object.identity(), &identity);
    assert_eq!(object.claim().plaintext_size(), 0);
    assert_eq!(object.handle().metadata()?.len(), 0);
    terrane_linux::verity::measure(object.handle())?;
    assert!(object.handle().write_at(b"forbidden", 0).is_err());
    assert_eq!(object.handle().metadata()?.len(), 0);

    println!(
        "INLINE_SEAL_STAGE actual empty sealed publication verified; completing cache handoff"
    );
    let report = object.into_cache().await.map_err(io::Error::other)?;
    assert_eq!(report.released_source_admissions, 0);
    assert_cache_grace(store, &identity, report.release_grace_ends_at).await?;
    println!(
        "PASS actual never-mode inline object is a read-only fs-verity inode with genuine completed cache handoff"
    );
    Ok(())
}

/// Exercises actual direct and whole-object sealing on a fresh Running owner.
pub(super) async fn exercise_reassembly(
    cache: &terrane_linux::configured::NativeConfiguredCache,
    profile: &ChunkProfile,
) -> io::Result<()> {
    reassembly::exercise(cache, profile).await
}

/// Observes the actual durable protection after a completed physical handoff.
async fn assert_cache_grace(
    store: &NativeContentStore,
    identity: &terrane_format::identity::Identity,
    deadline: u64,
) -> io::Result<()> {
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
    .ok_or_else(|| io::Error::other("publication handoff lost its durable snapshot"))?;
    let hash: String = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(state.leases.iter().any(|lease| {
        lease.owner.starts_with("publication-grace:")
            && lease.expires == deadline
            && state.pins.iter().any(|pin| {
                pin.owner == lease.owner && pin.hash == hash && pin.expires == lease.expires
            })
    }));
    Ok(())
}

/// Reads the actual synchronized policy without constructing consumer authority.
async fn metadata_policy(
    store: &NativeContentStore,
) -> io::Result<terrane_sdk::host::cache::CacheState> {
    terrane_sdk::host::cache::CacheState::load(
        &terrane_sdk::store::TokioLocalFs,
        &store.ready().layout().layout().root().join("state/cache"),
        terrane_sdk::host::cache::StateLimits {
            bytes: 65536,
            records: 64,
        },
    )
    .await
    .map_err(io::Error::other)?
    .ok_or_else(|| io::Error::other("metadata deduplication lost original durable policy"))
}

/// Checks real status against the synchronized ledger without inventing counters.
pub(super) async fn exercise_status(
    store: &NativeContentStore,
    domain: &str,
    populated: bool,
) -> io::Result<()> {
    let owner = store.ready().owner();
    let first = owner.status().await?;
    let records = store
        .ready()
        .layout()
        .layout()
        .root()
        .join("state/cache/records.toml");
    let before = std::fs::read(&records)?;
    let second = owner.status().await?;
    let after = metadata_policy(store).await?;

    // This fixture observes newly established promises well before their grace
    // deadlines. Neither status request may write the synchronized policy.
    assert_eq!(before, std::fs::read(&records)?);
    assert_eq!(first.generation, second.generation);
    assert!(second.quota_request_id > first.quota_request_id);
    assert_eq!(second.domain, domain);
    assert_eq!(second.hard_limit_bytes, super::super::config::LIMIT);
    assert_eq!(second.capacity_bytes, 24 * 1024 * 1024);
    assert!(second.charged_reserved_bytes > 0);
    assert!(second.charged_inodes > 0);
    assert_eq!(second.pins, after.pins.len());
    assert_eq!(second.leases, after.leases.len());
    assert_eq!(second.residences, after.residences.len());
    assert_eq!(second.reservations, after.reservations.len());
    assert_eq!(second.active_exposures, 0);
    assert_eq!(second.draining_exposures, 0);
    let reserved = after.reservations.iter().try_fold(0_u64, |sum, row| {
        sum.checked_add(row.bytes)
            .ok_or_else(|| io::Error::other("fixture reservation sum overflow"))
    })?;
    assert_eq!(second.reservation_bytes, reserved);
    if populated {
        assert!(second.pins > 0);
        assert!(second.leases > 0);
        assert!(second.reservations > 1);
    }

    println!(
        "PASS actual native status fresh quota query and unchanged synchronized policy, populated={populated} for {domain}"
    );
    Ok(())
}

/// Exercises independent grants and retained descriptors through final release.
pub(super) async fn exercise_release(
    store: &NativeContentStore,
    profile: &ChunkProfile,
    domain: &str,
) -> io::Result<()> {
    release::exercise(store, profile, domain).await
}

/// Seeds actual durable private/public grants for an independent cold actor.
pub(super) async fn seed_release(
    store: &NativeContentStore,
    profile: &ChunkProfile,
    domain: &str,
) -> io::Result<()> {
    release::seed(store, profile, domain).await
}

/// Releases independently recovered native backing without publishing a replacement.
pub(super) async fn recovered_release(store: &NativeContentStore, domain: &str) -> io::Result<()> {
    release::recovered(store, domain).await
}

/// Exercises pressure-driven public retirement alongside private lifetime release.
pub(super) async fn recovered_pressure(
    store: &NativeContentStore,
    profile: &ChunkProfile,
    domain: &str,
    manifest: bool,
) -> io::Result<()> {
    release::recovered_pressure(store, profile, domain, manifest).await
}
