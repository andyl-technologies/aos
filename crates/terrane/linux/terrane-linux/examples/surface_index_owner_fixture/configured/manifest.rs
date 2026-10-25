//! Resolves a signed manifest only during an actual native exposure file open.
//!
//! The original configured owner compiles metadata without reading content,
//! retains the cold preparation while its first chunk is withheld, and closes
//! the same scoped Read before returning the original sealed whole-file inode.

use super::{NativeCachePlan, Result, paused_lower::PausedLower};
use crate::{
    exposure::{limits, now},
    repository_fixture::RepositoryFixture,
};
use std::{
    fs,
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use terrane_format::{
    identity::{IdentityKind, TERRANE_V1},
    surface::{View, ViewTarget},
    tree_format::ContentRef,
};
use terrane_linux::{
    host_cache::NativeReadPolicy, quota_confinement::Installed, structural_index::Kind, verity,
};
use terrane_sdk::{
    config::host::HostTier,
    host::cache::{CacheState, ExposureBackingKind, ExposurePhase, ReassemblyMode, StateLimits},
    store::TokioLocalFs,
};
use tokio::{sync::Notify, time::timeout};

/// Checks deferred manifest resolution, real sealed handoff and warm inode reuse.
///
/// # Errors
/// Refuses failed native recovery, insufficient CDC input, metadata-time content
/// reads, changed signed selection, failed cold or closing Read, incorrect
/// original inode custody and repeated lower reads on a warm open.
pub(super) async fn verify(
    plan: NativeCachePlan,
    host: &HostTier,
    confinement: Arc<Installed>,
    source_parent: &Path,
) -> Result<()> {
    let mut caches = plan.open(confinement).await?;
    let cache = caches.remove("public").ok_or("missing manifest cache")?;
    if cache.reassembly() != ReassemblyMode::Always {
        return Err("manifest open requires explicit always policy".into());
    }
    let native = cache.into_content();
    let profile = native.ready().layout().layout().chunk_profile();
    let body = body();
    let boundaries = profile.boundaries(&body);
    if boundaries.len() < 2 {
        return Err("manifest open requires several actual CDC chunks".into());
    }
    let chunks = boundaries
        .iter()
        .map(|range| {
            TERRANE_V1
                .calculate(IdentityKind::Chunk, &body[range.clone()])
                .map(|identity| hexadecimal(identity.digest()))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut policy = Vec::new();
    terrane_format::cbor::write_text(&mut policy, "always");
    let fixture = Box::pin(RepositoryFixture::new_with_properties(
        "public",
        source_parent,
        vec![("reassembly".into(), policy)],
        profile.seed(),
    ))
    .await?;
    let commit = Box::pin(fixture.commit(&body)).await?;

    let reads = Arc::new(AtomicUsize::new(0));
    let manifests = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let mut driver = None;
    let read_policy = NativeReadPolicy::new(Duration::from_secs(10), 3, Duration::from_secs(5))?;
    let repository = fixture.repository.with_read_driver(|original| {
        let actual = native.with_lower(
            PausedLower {
                original: original.clone(),
                reads: Arc::clone(&reads),
                manifests: Arc::clone(&manifests),
                started: Arc::clone(&started),
                resume: Arc::clone(&resume),
            },
            read_policy,
        );
        driver = Some(actual.clone());
        actual
    });
    let driver = driver.ok_or("missing original manifest driver")?;
    let owner = driver.native().ready().owner();
    let target = ViewTarget::Commit(commit);
    let selection = repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    let served = owner.prepare_surface_mapping(selection).await?;
    let content = match served.index().lookup(b"file").map(|entry| entry.kind()) {
        Some(Kind::File {
            content: ContentRef::Manifest(hash),
            size,
        }) if size == body.len() as u64 => ContentRef::Manifest(hash),
        _ => return Err("index lost actual signed manifest identity or size".into()),
    };
    if reads.load(Ordering::Relaxed) != 0 || manifests.load(Ordering::Relaxed) != 0 {
        return Err("index compilation fetched manifest or chunk content".into());
    }
    println!("PASS signed manifest index compiles and maps with zero manifest or chunk reads");

    let expires = now()?
        .checked_add(90)
        .ok_or("manifest exposure deadline overflow")?;
    let lease = owner.retain_surface_exposure(&served, expires).await?;
    let view = View {
        target,
        subtree: Vec::new(),
        policy: None,
    };
    let selection = repository
        .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
        .await?;
    if reads.load(Ordering::Relaxed) != 0 || manifests.load(Ordering::Relaxed) != 0 {
        return Err("selecting the file fetched its manifest before native open".into());
    }

    let preparation = driver.prepare_exposure_file_backing(
        &lease,
        &served,
        selection,
        ReassemblyMode::Always,
        Duration::from_secs(10),
        expires,
    );
    tokio::pin!(preparation);
    timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut preparation => Err(format!("manifest open finished before withheld chunk: {}", result.is_ok())),
            () = started.notified() => Ok(()),
        }
    }).await??;
    if manifests.load(Ordering::Relaxed) != 1 || reads.load(Ordering::Relaxed) == 0 {
        return Err("actual open did not resolve exactly one signed manifest before chunks".into());
    }
    resume.notify_one();
    let backing = timeout(Duration::from_secs(10), &mut preparation).await??;
    let file = fs::File::from(backing.as_fd().try_clone_to_owned()?);
    let metadata = file.metadata()?;
    let seal = verity::measure(&file)?;
    let mut received = vec![0; body.len()];
    file.read_exact_at(&mut received, 0)?;
    let ContentRef::Manifest(hash) = content else {
        return Err("manifest selection changed kind".into());
    };
    let identity = TERRANE_V1.from_digest(IdentityKind::Manifest, &hash)?;
    if received != body
        || backing.size() != body.len() as u64
        || backing.commit() != commit
        || backing.root() != served.key().root()
        || backing.lease().identity() != &identity
        || backing
            .exposure()
            .map(|value| (value.id(), value.generation()))
            != Some((lease.id(), lease.generation()))
        || manifests.load(Ordering::Relaxed) != 1
        || reads.load(Ordering::Relaxed) != boundaries.len()
    {
        return Err("manifest open lost verified bytes, original Read or cache handoff".into());
    }

    let root = &host.domains["public"];
    let resources = root.cache.as_ref().ok_or("missing manifest cache bounds")?;
    let state = CacheState::load(
        &TokioLocalFs,
        &Path::new(&root.path).join("state/cache"),
        StateLimits {
            bytes: resources.state_bytes,
            records: resources.state_records,
        },
    )
    .await?
    .ok_or("missing original manifest cache snapshot")?;
    let original = state
        .exposures
        .iter()
        .find(|row| row.id == lease.id())
        .ok_or("manifest open lost original exposure")?;
    let whole = original
        .backings
        .iter()
        .find(|row| row.kind == ExposureBackingKind::Manifest)
        .ok_or("manifest open omitted durable whole-file binding")?;
    if original.phase != ExposurePhase::Active
        || original.backings.len() != 2
        || whole.hash != hexadecimal(&hash)
        || whole.device != metadata.dev()
        || whole.inode != metadata.ino()
        || whole.size != metadata.len()
        || whole.verity_algorithm != seal.algorithm
        || whole.verity_digest != hexadecimal(&seal.digest)
        || chunks
            .iter()
            .any(|hash| !state.residences.iter().any(|row| &row.chunk == hash))
        || state.pins.iter().any(|row| {
            (chunks.contains(&row.hash) || row.hash == whole.hash)
                && row.owner.starts_with("publication:")
        })
    {
        return Err(
            "manifest handoff differs from original native inode or durable obligations".into(),
        );
    }
    println!(
        "PASS authenticated manifest open resolves original CDC ranges and closes Read around the measured sealed inode and durable exposure binding"
    );

    let selection = repository
        .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
        .await?;
    let warm = driver
        .prepare_exposure_file_backing(
            &lease,
            &served,
            selection,
            ReassemblyMode::Always,
            Duration::from_secs(10),
            expires,
        )
        .await?;
    let warm_file = fs::File::from(warm.as_fd().try_clone_to_owned()?);
    let warm_metadata = warm_file.metadata()?;
    if (warm_metadata.dev(), warm_metadata.ino()) != (metadata.dev(), metadata.ino())
        || verity::measure(&warm_file)? != seal
        || manifests.load(Ordering::Relaxed) != 1
        || reads.load(Ordering::Relaxed) != boundaries.len()
    {
        return Err("warm manifest open replaced original inode or repeated lower reads".into());
    }
    owner.release_sealed_object_lease(warm.lease()).await?;
    owner.release_sealed_object_lease(backing.lease()).await?;
    file.read_exact_at(&mut received, 0)?;
    if received != body {
        return Err("original manifest descriptor changed after consumer release".into());
    }
    println!(
        "PASS warm manifest open reuses the original measured inode without another manifest or chunk read; retained descriptor survives consumer release"
    );
    Ok(())
}

fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn body() -> Vec<u8> {
    let mut state = 7_u32;
    (0..2_097_153)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}
