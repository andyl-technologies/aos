//! Exercises genuine scoped SDK selection around actual native sealed backing.

use super::config::Inputs;
#[path = "repository_fixture.rs"]
mod repository_fixture;

use repository_fixture::{MAIN, RepositoryFixture};
use std::{
    fs,
    io::{self, Write},
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt},
    },
    time::UNIX_EPOCH,
};
use terrane_format::{
    identity::{Descriptor, IdentityKind, TERRANE_V1},
    surface::View,
    tree_format::ContentRef,
};
use terrane_linux::host_cache::{NativeFileBacking, NativeMetadataOwner};
use terrane_sdk::{
    repository::Error,
    store::{Clock, StoreErrorKind, TokioClock},
};

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;
const BYTES: &[u8] = b"scoped native whole-file backing";

/// Runs scoped admission and disclosure with genuine independent authority.
///
/// # Errors
/// Refuses changed native custody, incorrect selection, premature disclosure,
/// missing real authorization refusal or failed fixture cleanup.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    runtime
        .block_on(run_async(owner, inputs, original))
        .map_err(|error| io::Error::other(error.to_string()))
}

fn progress(stage: &str) -> io::Result<()> {
    println!("SCOPED_STAGE {stage}");
    io::stdout().flush()
}

async fn recover(
    owner: &NativeMetadataOwner,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> FixtureResult<()> {
    if inputs.domain != "tenant:sealed-consumer-cold" || original.is_none() {
        return Err("scoped file requires the completed cold whole-file consumer domain".into());
    }
    progress("recover")?;
    let completed = owner.recover().await?;
    owner.resume_recovered(completed).await?;
    progress("resumed")?;
    Ok(())
}

fn deadline() -> FixtureResult<u64> {
    TokioClock
        .now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| "fixture deadline overflow".into())
}

async fn run_async(
    owner: &NativeMetadataOwner,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> FixtureResult<()> {
    recover(owner, inputs, original).await?;
    run_inline_async(owner, inputs).await?;
    run_manifest_async(owner, inputs).await
}

async fn run_inline_async(owner: &NativeMetadataOwner, inputs: &Inputs) -> FixtureResult<()> {
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, BYTES)?;
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, BYTES)?;
    let published = owner
        .publish_inline(descriptor, [vec![0], BYTES.to_vec()].concat())
        .await?;
    let inode = published.handle().metadata()?.ino();
    let expires = deadline()?;
    progress("inline-repository")?;
    let fixture = RepositoryFixture::new(&inputs.domain).await?;
    let commit = fixture.commit(BYTES).await?;
    let view = View::parse(MAIN)?;
    let selection = fixture
        .repository
        .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
        .await?;
    let root = selection.root();
    progress("inline-backing")?;
    let backing = owner.prepare_file_backing(selection, expires).await?;
    if backing.commit() != commit
        || backing.root() != root
        || backing.size() != BYTES.len() as u64
        || backing.lease().identity() != &identity
    {
        return Err("scoped backing lost signed file selection".into());
    }
    check_backing(&backing, inode, BYTES)?;

    progress("changed-policy")?;
    let selection = fixture
        .repository
        .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
        .await?;
    fixture.commit(b"genuine policy advance").await?;
    if !matches!(owner.prepare_file_backing(selection, expires).await,
        Err(Error::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    {
        return Err("native backing escaped a changed actual policy head".into());
    }
    // A previously disclosed descriptor stays held by its actual owner. A
    // later authorization refusal cannot pretend that the kernel closed it.
    check_backing(&backing, inode, BYTES)?;
    owner.release_sealed_object_lease(backing.lease()).await?;
    check_backing(&backing, inode, BYTES)?;
    drop(backing);

    progress("foreign-domain")?;
    let foreign = RepositoryFixture::new("tenant:another-scoped-file").await?;
    foreign.commit(BYTES).await?;
    let selection = foreign
        .repository
        .prepare_file_read(&view, b"file", foreign.authority.token(), "sdk")
        .await?;
    let policy = inputs.root.join("state/cache/records.toml");
    let before = fs::read(&policy)?;
    if owner.prepare_file_backing(selection, expires).await.is_ok() || fs::read(policy)? != before {
        return Err("foreign-domain selection disclosed backing or mutated pin policy".into());
    }

    drop(published);
    println!("SCOPED_FILE_INODE inode={inode} size={}", BYTES.len());
    println!(
        "PASS actual signed scoped file returns original sealed inode; changed policy denies disclosure, foreign domain leaves physical policy unchanged, retained descriptor survives release"
    );
    io::stdout().flush()?;
    Ok(())
}

async fn run_manifest_async(owner: &NativeMetadataOwner, inputs: &Inputs) -> FixtureResult<()> {
    let expires = deadline()?;
    progress("manifest-repository")?;
    // Keep one actual native owner and its retained bootstrap funding. A fresh
    // signed SDK repository isolates this case from the inline policy advances.
    let fixture = RepositoryFixture::new(&inputs.domain).await?;
    let view = View::parse(MAIN)?;

    // The earlier cold control independently recovered this complete file.
    // Commit its bytes through the real SDK, then select its signed manifest;
    // neither a caller-written content reference nor a chunk range is accepted.
    let plaintext = vec![0x5a; terrane_format::chunking::CDC_1M_MIN + 1];
    progress("manifest-commit")?;
    let manifest_commit = fixture.commit(&plaintext).await?;
    progress("manifest-selection")?;
    let selection = fixture
        .repository
        .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
        .await?;
    let ContentRef::Manifest(digest) = selection.content() else {
        return Err("scoped manifest fixture unexpectedly selected an inline chunk".into());
    };
    let manifest_identity = TERRANE_V1.from_digest(IdentityKind::Manifest, &digest)?;
    let manifest_root = selection.root();
    progress("manifest-backing")?;
    let manifest = owner.prepare_file_backing(selection, expires).await?;
    let manifest_stat = rustix::fs::fstat(&manifest)?;
    if manifest.commit() != manifest_commit
        || manifest.root() != manifest_root
        || manifest.size() != plaintext.len() as u64
        || manifest.lease().identity() != &manifest_identity
    {
        return Err("scoped manifest lost its signed whole-file selection".into());
    }
    check_backing(&manifest, manifest_stat.st_ino, &plaintext)?;
    progress("manifest-release")?;
    owner.release_sealed_object_lease(manifest.lease()).await?;
    check_backing(&manifest, manifest_stat.st_ino, &plaintext)?;
    let hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    println!(
        "SCOPED_MANIFEST_INODE hash={hash} inode={} size={}",
        manifest_stat.st_ino,
        plaintext.len(),
    );
    drop(manifest);
    println!(
        "PASS actual signed scoped manifest returns recovered whole-file backing without substituting metadata or chunk ranges; retained descriptor survives release"
    );
    io::stdout().flush()?;
    Ok(())
}

fn check_backing(backing: &NativeFileBacking, inode: u64, expected: &[u8]) -> FixtureResult<()> {
    let file = fs::File::from(backing.as_fd().try_clone_to_owned()?);
    let metadata = file.metadata()?;
    let flags = rustix::fs::fcntl_getfl(&file)?;
    if metadata.ino() != inode
        || metadata.len() != expected.len() as u64
        || flags.intersects(
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::PATH,
        )
        || !rustix::io::fcntl_getfd(backing)?.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err("scoped descriptor differs from the original immutable whole file".into());
    }
    terrane_linux::verity::measure(&file)?;
    let mut actual = vec![0; expected.len()];
    file.read_exact_at(&mut actual, 0)?;
    if actual != expected {
        return Err("scoped descriptor returned different plaintext".into());
    }
    Ok(())
}
