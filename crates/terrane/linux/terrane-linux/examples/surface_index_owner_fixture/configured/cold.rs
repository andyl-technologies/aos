//! Checks bounded cold preparation against actual signed inline and manifest files.

use super::super::Result;
use crate::{exposure::now, repository_fixture::RepositoryFixture};
use std::{
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use terrane_format::{
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
    surface::{View, ViewTarget},
    tree_format::ContentRef,
};
use terrane_linux::{configured::NativeConfiguredCache, host_cache::NativeReadPolicy};
use terrane_sdk::{
    host::cache::ReassemblyMode,
    store::{
        ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix,
        StoreErrorKind, StoreFailure,
    },
};

struct CountedLower<S> {
    original: S,
    chunks: Arc<AtomicUsize>,
    manifests: Arc<AtomicUsize>,
    oversized_chunk: AtomicBool,
}

impl<S: CapabilityReport> CapabilityReport for CountedLower<S> {
    fn capabilities(&self) -> &Capabilities {
        self.original.capabilities()
    }
}

#[async_trait::async_trait]
impl<S: ContentStore + Send + Sync> ContentStore for CountedLower<S> {
    async fn put(&self, _: ContentUpload<'_>) -> std::result::Result<Identity, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> std::result::Result<Vec<u8>, StoreFailure> {
        match identity.kind() {
            IdentityKind::Chunk => {
                self.chunks.fetch_add(1, Ordering::Relaxed);
                if self.oversized_chunk.swap(false, Ordering::Relaxed) {
                    // One byte above the supervisor's explicit 2 MiB native
                    // read bound. Capacity must win before decoding this
                    // deliberately malformed body or attempting admission.
                    return Ok(vec![0; 2_097_153]);
                }
            }
            IdentityKind::Manifest => {
                self.manifests.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        self.original.get(identity, range).await
    }

    async fn has(&self, identities: &[Identity]) -> std::result::Result<Vec<bool>, StoreFailure> {
        self.original.has(identities).await
    }

    async fn list(
        &self,
        prefix: &IdentityPrefix,
    ) -> std::result::Result<Vec<Identity>, StoreFailure> {
        self.original.list(prefix).await
    }
}

/// Checks genuine cold publication and ordinary scoped backing on one configured owner.
///
/// # Errors
/// Refuses mismatched policy or profiles, content I/O during metadata preparation,
/// ineffective input bounds, failed publication or closing Read, changed sealed
/// inode identity, unexpected lower reads and native custody failures.
pub(super) async fn verify(cache: NativeConfiguredCache, source_parent: &Path) -> Result<()> {
    let mode = cache.reassembly();
    if mode != ReassemblyMode::Always {
        return Err("cold whole-file fixture requires explicit configured always policy".into());
    }
    let native = cache.into_content();
    let profile = native.ready().layout().layout().chunk_profile();
    let mut encoded_mode = Vec::new();
    terrane_format::cbor::write_text(&mut encoded_mode, "always");
    let fixture = Box::pin(RepositoryFixture::new_with_properties(
        "public",
        source_parent,
        vec![("reassembly".into(), encoded_mode)],
        profile.seed(),
    ))
    .await?;
    if fixture.repository.chunk_profile() != profile {
        return Err("cold source and native CDC profiles differ".into());
    }
    let inline = b"original signed inline cold-open preparation";
    let first = Box::pin(fixture.commit(inline)).await?;
    let mut state = 7_u32;
    let manifest: Vec<u8> = (0..2_097_153)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let chunk_count = profile.boundaries(&manifest).len();
    if chunk_count < 2 {
        return Err("cold fixture lacks actual multi-chunk input".into());
    }
    let second = Box::pin(fixture.commit(&manifest)).await?;
    let chunks = Arc::new(AtomicUsize::new(0));
    let manifests = Arc::new(AtomicUsize::new(0));
    let mut driver = None;
    let policy = NativeReadPolicy::new(Duration::from_secs(10), 3, Duration::from_secs(5))?;
    let repository = fixture.repository.with_read_driver(|original| {
        let actual = native.with_lower(
            CountedLower {
                original: original.clone(),
                chunks: Arc::clone(&chunks),
                manifests: Arc::clone(&manifests),
                oversized_chunk: AtomicBool::new(true),
            },
            policy,
        );
        driver = Some(actual.clone());
        actual
    });
    let driver = driver.ok_or("missing original cold driver")?;
    let owner = driver.native().ready().owner();
    let records = driver
        .native()
        .ready()
        .layout()
        .layout()
        .root()
        .join("state/cache/records.toml");
    let before = std::fs::read(&records)?;
    let oversized = TERRANE_V1.calculate(IdentityKind::Chunk, b"bounded lower refusal")?;
    if !matches!(driver.get(&oversized, None).await, Err(ref error) if matches!(error.kind(), StoreErrorKind::Capacity))
        || std::fs::read(&records)? != before
        || chunks.load(Ordering::Relaxed) != 1
        || manifests.load(Ordering::Relaxed) != 0
    {
        return Err("oversized lower body reached decoding or changed native policy".into());
    }

    for (commit, expected, is_manifest) in [
        (first, inline.as_slice(), false),
        (second, manifest.as_slice(), true),
    ] {
        let view = pinned(commit);
        let counts = (
            chunks.load(Ordering::Relaxed),
            manifests.load(Ordering::Relaxed),
        );
        let selection = repository
            .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
            .await?;
        if matches!(selection.content(), ContentRef::Manifest(_)) != is_manifest
            || (
                chunks.load(Ordering::Relaxed),
                manifests.load(Ordering::Relaxed),
            ) != counts
        {
            return Err(
                "cold file selection fetched a content body or changed its signed kind".into(),
            );
        }
        let before = std::fs::read(&records)?;
        let refusal = driver
            .prepare_cold_file(&selection, ReassemblyMode::Never, Duration::from_secs(10))
            .await;
        if !matches!(refusal, Err(terrane_sdk::repository::Error::Store(ref error)) if matches!(error.kind(), StoreErrorKind::Unsupported))
            || std::fs::read(&records)? != before
            || (
                chunks.load(Ordering::Relaxed),
                manifests.load(Ordering::Relaxed),
            ) != counts
        {
            return Err(
                "cold preparation overrode signed mode or changed physical policy before refusal"
                    .into(),
            );
        }

        let (grant, metadata) = if is_manifest {
            // Exercise the complete miss-to-cache bridge with the very same
            // opaque SDK selection retained across publication and closing Read.
            let grant = driver
                .prepare_file_backing(selection, mode, Duration::from_secs(10), now()? + 30)
                .await?;
            let file = std::fs::File::from(grant.as_fd().try_clone_to_owned()?);
            terrane_linux::verity::measure(&file)?;
            verify_bytes(&file, expected)?;
            let metadata = file.metadata()?;
            (grant, metadata)
        } else {
            let object = driver
                .prepare_cold_file(&selection, mode, Duration::from_secs(10))
                .await?;
            let metadata = object.handle().metadata()?;
            terrane_linux::verity::measure(object.handle())?;
            verify_bytes(object.handle(), expected)?;
            let grant = owner.prepare_file_backing(selection, now()? + 30).await;
            // Failed authorization must still attempt genuine completed cache
            // handoff; it never turns valid cached data into a disclosed result.
            let handoff = object.into_cache().await;
            let grant = grant?;
            handoff?;
            (grant, metadata)
        };
        let actual = std::fs::File::from(grant.as_fd().try_clone_to_owned()?).metadata()?;
        if (actual.dev(), actual.ino()) != (metadata.dev(), metadata.ino()) {
            return Err("cold grant substituted the original sealed publication inode".into());
        }
        owner.release_sealed_object_lease(grant.lease()).await?;
        drop(grant);

        let counts = (
            chunks.load(Ordering::Relaxed),
            manifests.load(Ordering::Relaxed),
        );
        let selection = repository
            .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
            .await?;
        let warm = driver
            .prepare_file_backing(selection, mode, Duration::from_secs(10), now()? + 30)
            .await?;
        let actual = std::fs::File::from(warm.as_fd().try_clone_to_owned()?).metadata()?;
        if (actual.dev(), actual.ino()) != (metadata.dev(), metadata.ino())
            || (
                chunks.load(Ordering::Relaxed),
                manifests.load(Ordering::Relaxed),
            ) != counts
        {
            return Err("warm backing fetched lower content or replaced its sealed inode".into());
        }
        owner.release_sealed_object_lease(warm.lease()).await?;
    }
    if chunks.load(Ordering::Relaxed) != 2 + chunk_count || manifests.load(Ordering::Relaxed) != 1 {
        return Err("cold preparation did not fetch the exact original content inputs".into());
    }
    println!(
        "PASS signed cold inline and multi-chunk preparations seal original native backing before closing Read; warm grants preserve inode without lower content traffic"
    );
    println!(
        "PASS oversized lower body refuses before decoding and native policy mutation; incompatible signed reassembly refuses before content traffic"
    );
    Ok(())
}

fn pinned(commit: Digest) -> View {
    View {
        target: ViewTarget::Commit(commit),
        subtree: Vec::new(),
        policy: None,
    }
}

fn verify_bytes(file: &std::fs::File, expected: &[u8]) -> Result<()> {
    if file.metadata()?.len() != expected.len() as u64 {
        return Err("cold sealed file size differs".into());
    }
    let mut scratch = [0; 65536];
    for (index, bytes) in expected.chunks(scratch.len()).enumerate() {
        let offset = (index * scratch.len()) as u64;
        file.read_exact_at(&mut scratch[..bytes.len()], offset)?;
        if scratch[..bytes.len()] != *bytes {
            return Err("cold sealed file changed independently expected plaintext".into());
        }
    }
    Ok(())
}
