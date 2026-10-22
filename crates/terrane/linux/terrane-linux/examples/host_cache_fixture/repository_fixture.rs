//! Builds genuine signed fixture repositories outside the cache project.

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
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
        CommitMetadata, LocalAuthority, LocalAuthorityParameters, LocalRepositoryLocation,
        LocalRepositoryPolicy, MetadataValidator, Repository,
    },
    store::{LocalFs, TokioClock, TokioLocalFs},
};

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;
type LocalRepository =
    Repository<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;
/// Selects the genuinely signed fixture branch.
pub(super) const MAIN: &str = "refs/heads/_/main";

/// Owns a signed repository and its protected authority outside the quota project.
pub(super) struct RepositoryFixture {
    /// Supplies ordinary guarded repository operations.
    pub(super) repository: LocalRepository,
    /// Supplies actual locally issued credentials and signing custody.
    pub(super) authority: LocalAuthority,
    directory: FixtureDirectory,
}

impl RepositoryFixture {
    /// Initializes the selected domain with real local entropy and CDC geometry.
    ///
    /// # Errors
    /// Preserves filesystem, signing, domain and repository initialization failures.
    pub(super) async fn new(domain: &str) -> FixtureResult<Self> {
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

    /// Publishes one ordinary file through actual guarded commit admission.
    ///
    /// # Errors
    /// Preserves source writes, authorization and durable publication failures.
    pub(super) async fn commit(&self, bytes: &[u8]) -> FixtureResult<[u8; 32]> {
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
