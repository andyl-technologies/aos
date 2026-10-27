//! Owns isolated genuine local repositories and independent filesystem oracles.

use std::{
    collections::BTreeMap,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use terrane_format::{
    auth::{Authority, Grant, Verbs},
    refs::{CommitSource, Locality, PrincipalKind},
};
use terrane_sdk::{
    bucket::FileBucket,
    ref_advance::CommitTiming,
    repository::{
        CommitMetadata, LocalAuthority, LocalAuthorityIdentity, LocalAuthorityParameters,
        LocalRepositoryLocation, LocalRepositoryPolicy, MetadataValidator, Repository,
    },
    store::{LocalFs, TokioClock, TokioLocalFs},
    surface::{Endpoint, EndpointKind, ReaderMode, RealizationHints, View},
};

/// Propagates fixture construction and filesystem oracle failures.
pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;
/// Names the actual source-built native repository bindings.
pub(super) type LocalRepository =
    Repository<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;
/// Selects the signed main branch and independent current-policy authority.
pub(super) const MAIN: &str = "refs/heads/_/main";
/// Supplies independent expected bytes for historical presentations.
pub(super) const OLD: &[u8] = b"historical SDK bytes\n";
/// Supplies independent expected bytes after the main branch advances.
pub(super) const NEW: &[u8] = b"current SDK bytes\n";

/// Holds one isolated genuine repository and its sibling signing authority.
pub(super) struct Fixture {
    /// Contains only this fixture's persistent source and output namespaces.
    pub parent: PathBuf,
    /// Locates the actual bucket and its protected sibling authority.
    pub location: LocalRepositoryLocation,
    /// Records the validated fixture directory's Unix owner.
    pub owner: u32,
    /// Provides canonical publication, reads and registered realization.
    pub repository: LocalRepository,
    /// Supplies genuine locally issued capability and commit signing input.
    pub authority: LocalAuthority,
    cleanup: FixtureDirectory,
}

impl Fixture {
    /// Initializes a fresh signed repository in an exclusively created directory.
    ///
    /// # Errors
    /// Propagates entropy, filesystem, policy and authorized initialization failures.
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let entropy = TokioLocalFs.random_bytes(16).await?;
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let parent = std::env::temp_dir().join(format!("terrane-local-sdk-{suffix}"));
        std::fs::create_dir(&parent)?;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))?;
        let owner = std::fs::metadata(&parent)?.uid();
        let location = LocalRepositoryLocation {
            bucket: parent.join("bucket"),
            authority: parent.join("authority"),
        };
        let (repository, authority) = Repository::initialize_local(
            &location,
            LocalAuthorityParameters {
                owner_uid: owner,
                authority: Authority {
                    issuer: "local".into(),
                    key_id: "initial".into(),
                    subject: "owner".into(),
                    kind: PrincipalKind::Human,
                    groups: Vec::new(),
                    not_after: u64::MAX,
                    not_before: None,
                    token_id: entropy.try_into().map_err(|_| "invalid entropy")?,
                    grants: vec![Grant::new("refs/**".into(), Verbs::new(31)?)?],
                    workload: None,
                },
            },
            policy()?,
            MAIN,
            TokioLocalFs,
            TokioClock,
        )
        .await?;
        Ok(Self {
            cleanup: FixtureDirectory(parent.clone()),
            parent,
            location,
            owner,
            repository,
            authority,
        })
    }

    /// Drops original handles and reopens only durable destination state.
    ///
    /// # Errors
    /// Propagates protected authority, backend and signed-head verification failures.
    pub async fn reopen(self) -> Result<Self, Box<dyn std::error::Error>> {
        let Self {
            parent,
            location,
            owner,
            repository,
            authority,
            cleanup,
        } = self;
        drop(repository);
        drop(authority);
        let (repository, authority) = Repository::open_local(
            &location,
            &LocalAuthorityIdentity {
                issuer: "local".into(),
                key_id: "initial".into(),
                owner_uid: owner,
            },
            policy()?,
            MAIN,
            TokioLocalFs,
            TokioClock,
        )
        .await?;
        Ok(Self {
            parent,
            location,
            owner,
            repository,
            authority,
            cleanup,
        })
    }

    /// Imports exact independent bytes and publishes a genuine signed commit.
    ///
    /// # Errors
    /// Propagates source writes, session authorization and directory commit failures.
    pub async fn commit_bytes(&self, bytes: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let source = self.parent.join("source");
        if !source.exists() {
            std::fs::create_dir(&source)?;
        }
        std::fs::write(source.join("file"), bytes)?;
        self.commit_directory(&source).await
    }

    /// Publishes source entries through canonical authorized directory import.
    ///
    /// # Errors
    /// Propagates session, import, current policy and durable publication failures.
    pub async fn commit_directory(
        &self,
        source: &Path,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let mut session = self
            .repository
            .begin(MAIN, self.authority.token(), "sdk")
            .await?;
        Ok(self
            .repository
            .commit_directory(
                &mut session,
                source,
                &self.authority,
                metadata("Import SDK fixture"),
            )
            .await?
            .commit)
    }

    /// Selects registered pinned SDK presentation with the exposure capability.
    pub fn hints(&self, output: &str) -> RealizationHints {
        RealizationHints {
            surface: "sdk".into(),
            endpoint: Endpoint {
                kind: EndpointKind::Directory,
                address: self.parent.join(output).to_string_lossy().into_owned(),
            },
            token: self.authority.token().to_vec(),
            reader: ReaderMode::Pinned,
        }
    }
}

struct FixtureDirectory(PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("Failed to remove private SDK fixture: {error}");
        }
    }
}

/// Supplies public commit metadata without constructing signing authority.
pub(super) fn metadata(message: &str) -> CommitMetadata {
    CommitMetadata {
        message: message.into(),
        process: "sdk-test".into(),
        source: CommitSource::Built,
    }
}

/// Configures local private ownership and a separate current policy reference.
///
/// # Errors
/// Propagates invalid publication timing relative to collection grace.
pub(super) fn policy() -> Result<LocalRepositoryPolicy, Box<dyn std::error::Error>> {
    Ok(LocalRepositoryPolicy {
        store_name: "local".into(),
        domain: "private:owner".into(),
        default_private_domain: "private:owner".into(),
        acl: vec![("owner".into(), 31)],
        locality: Locality::default(),
        timing: CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )?,
        policy_authority: Some(MAIN.into()),
        bootstrap_properties: Vec::new(),
    })
}

/// Selects an immutable target independently of current policy resolution.
pub(super) fn fixed(commit: [u8; 32]) -> View {
    View {
        target: terrane_sdk::surface::ViewTarget::Commit(commit),
        subtree: Vec::new(),
        policy: None,
    }
}

/// Records independent persistent entry identity, mode and payload observations.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct EntryState {
    mode: u32,
    inode: u64,
    bytes: Vec<u8>,
}

/// Inventories persistent names, inode identity, modes, bytes and symlink targets.
///
/// # Errors
/// Propagates metadata, directory traversal, file reads and symlink reads.
/// Concurrent fixture mutation can make a previously observed path unavailable.
pub(super) fn inventory(root: &Path) -> Result<BTreeMap<PathBuf, EntryState>, std::io::Error> {
    fn visit(
        root: &Path,
        path: &Path,
        result: &mut BTreeMap<PathBuf, EntryState>,
    ) -> Result<(), std::io::Error> {
        let stat = std::fs::symlink_metadata(path)?;
        let bytes = if stat.file_type().is_symlink() {
            use std::os::unix::ffi::OsStrExt;
            std::fs::read_link(path)?.as_os_str().as_bytes().to_vec()
        } else if stat.is_file() {
            std::fs::read(path)?
        } else {
            Vec::new()
        };
        result.insert(
            path.strip_prefix(root)
                .map_err(std::io::Error::other)?
                .to_path_buf(),
            EntryState {
                mode: stat.mode(),
                inode: stat.ino(),
                bytes,
            },
        );
        if stat.is_dir() {
            for child in std::fs::read_dir(path)? {
                visit(root, &child?.path(), result)?;
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result)?;
    Ok(result)
}
