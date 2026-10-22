//! Exercises genuine scoped SDK selection around actual native sealed backing.

use super::config::Inputs;
use std::{
    fs,
    io::{self, Write},
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt, PermissionsExt},
    },
    path::PathBuf,
    time::{Duration, UNIX_EPOCH},
};
use terrane_format::{
    auth::{Authority, Grant, Verbs},
    identity::{Descriptor, IdentityKind, TERRANE_V1},
    refs::{CommitSource, Locality, PrincipalKind},
    surface::View,
    tree_format::ContentRef,
};
use terrane_linux::host_cache::{NativeFileBacking, NativeMetadataOwner};
use terrane_sdk::{
    bucket::FileBucket,
    ref_advance::CommitTiming,
    repository::{
        CommitMetadata, Error, LocalAuthority, LocalAuthorityParameters, LocalRepositoryLocation,
        LocalRepositoryPolicy, MetadataValidator, Repository,
    },
    store::{Clock, LocalFs, StoreErrorKind, TokioClock, TokioLocalFs},
};

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;
type LocalRepository =
    Repository<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;
const MAIN: &str = "refs/heads/_/main";
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

/// Runs an independent scoped manifest actor within the same bounded lifecycle.
///
/// # Errors
/// Refuses absent original custody, invalid SDK selection, changed backing or
/// failed durable pin release.
pub(super) fn run_manifest(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    runtime
        .block_on(run_manifest_async(owner, inputs, original))
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

async fn run_manifest_async(
    owner: &NativeMetadataOwner,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> FixtureResult<()> {
    recover(owner, inputs, original).await?;
    let expires = deadline()?;
    progress("manifest-repository")?;
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

struct RepositoryFixture {
    repository: LocalRepository,
    authority: LocalAuthority,
    directory: FixtureDirectory,
}

impl RepositoryFixture {
    async fn new(domain: &str) -> FixtureResult<Self> {
        let entropy = TokioLocalFs.random_bytes(16).await?;
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        // Source and protected signing authority are separate from the quota
        // project under test; no fixture metadata enters the physical cache.
        let path = std::env::temp_dir().join(format!("terrane-scoped-file-{suffix}"));
        fs::create_dir(&path)?;
        let directory = FixtureDirectory(path);
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700))?;
        let owner_uid = fs::metadata(&directory.0)?.uid();
        let location = LocalRepositoryLocation {
            bucket: directory.0.join("bucket"),
            authority: directory.0.join("authority"),
        };
        // Register the same immutable CDC profile as the native cache. Signing
        // keys and token identities still come from actual local entropy.
        let (repository, authority) = Repository::initialize_local_with_seed(
            &location,
            LocalAuthorityParameters {
                owner_uid,
                authority: Authority {
                    issuer: "scoped-fixture".into(),
                    key_id: "initial".into(),
                    subject: "owner".into(),
                    kind: PrincipalKind::Human,
                    groups: Vec::new(),
                    not_after: u64::MAX,
                    not_before: None,
                    token_id: entropy.try_into().map_err(|_| "invalid fixture entropy")?,
                    grants: vec![Grant::new("refs/**".into(), Verbs::new(31)?)?],
                    workload: None,
                },
            },
            LocalRepositoryPolicy {
                store_name: "scoped-fixture".into(),
                domain: domain.into(),
                default_private_domain: "private:scoped-fixture".into(),
                acl: vec![("owner".into(), 31)],
                locality: Locality::default(),
                timing: CommitTiming::new(
                    Duration::from_secs(30),
                    Duration::from_secs(60),
                    Duration::from_secs(10),
                )?,
                policy_authority: Some(MAIN.into()),
                bootstrap_properties: Vec::new(),
            },
            MAIN,
            [0; 32],
            TokioLocalFs,
            TokioClock,
        )
        .await?;
        fs::create_dir(directory.0.join("source"))?;
        Ok(Self {
            repository,
            authority,
            directory,
        })
    }

    async fn commit(&self, bytes: &[u8]) -> FixtureResult<[u8; 32]> {
        let source = self.directory.0.join("source");
        fs::write(source.join("file"), bytes)?;
        let mut session = self
            .repository
            .begin(MAIN, self.authority.token(), "sdk")
            .await?;
        let receipt = self
            .repository
            .commit_directory(
                &mut session,
                &source,
                &self.authority,
                CommitMetadata {
                    message: "Publish scoped native fixture".into(),
                    process: "native-fixture".into(),
                    source: CommitSource::Built,
                },
            )
            .await?;
        Ok(receipt.commit)
    }
}

struct FixtureDirectory(PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove scoped-file fixture: {error}");
        }
    }
}
