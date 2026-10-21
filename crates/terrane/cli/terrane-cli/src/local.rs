//! Parses local porcelain and calls repository and registered surface APIs.
//!
//! The library owns initialization, credential persistence, admission, merging,
//! and checkout. These arguments provide explicit trusted local setup without
//! extending the store/exposure configuration vocabulary (CRATE-16, CRATE-17).

use std::{path::PathBuf, time::Duration};

use clap::{Args, Subcommand};
use terrane_sdk::{
    bucket::FileBucket,
    model::{Authority, CommitSource, Grant, Locality, PrincipalKind, Verbs},
    ref_advance::CommitTiming,
    repository::{
        CommitMetadata, LocalAuthority, LocalAuthorityIdentity, LocalAuthorityParameters,
        LocalRepositoryLocation, LocalRepositoryPolicy, MetadataValidator, Repository,
    },
    store::{LocalFs, TokioClock, TokioLocalFs},
    surface::{Endpoint, EndpointKind, ReaderMode, RealizationHints, View},
};

mod history;

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Show committed reflog entries under current read authorization.
    Log {
        #[command(flatten)]
        repository: LocalArguments,
        /// Start at this sequence, with zero selecting the beginning.
        #[arg(long, default_value_t = 0)]
        from_sequence: u64,
    },
    /// Initialize a file bucket and its private sibling authority.
    Init {
        #[command(flatten)]
        repository: LocalArguments,
        /// Set the capability expiration as Unix seconds.
        #[arg(long)]
        not_after: u64,
    },
    /// Commit a directory to an existing branch.
    Commit {
        #[command(flatten)]
        repository: LocalArguments,
        /// Import this directory through the repository SDK.
        directory: PathBuf,
        /// Record this commit message.
        #[arg(short, long)]
        message: String,
    },
    /// Fork the selected branch without copying its content.
    Fork {
        #[command(flatten)]
        repository: LocalArguments,
        /// Create this full refs/heads/ name.
        destination: String,
        /// Record this fork message.
        #[arg(short, long)]
        message: String,
    },
    /// Merge a source branch into the selected branch.
    Merge {
        #[command(flatten)]
        repository: LocalArguments,
        /// Merge this full refs/heads/ name.
        source: String,
        /// Record this merge message.
        #[arg(short, long)]
        message: String,
    },
    /// Check out a view through the registered sdk surface.
    Checkout {
        #[command(flatten)]
        repository: LocalArguments,
        /// Select a ref or commit:DIGEST, optionally with :/subtree.
        view: String,
        /// Create this new directory for the pinned checkout.
        destination: PathBuf,
    },
}

#[derive(Args)]
pub(crate) struct LocalArguments {
    /// Open this absolute file:// bucket URL.
    #[arg(long)]
    bucket: String,
    /// Use this absolute private sibling authority directory.
    #[arg(long)]
    authority: PathBuf,
    /// Require this Unix owner for bucket and authority state.
    #[arg(long)]
    owner_uid: u32,
    /// Trust this local issuer name.
    #[arg(long, default_value = "local")]
    issuer: String,
    /// Trust this issuer rotation key identifier.
    #[arg(long, default_value = "initial")]
    key_id: String,
    /// Authorize this local principal in the bootstrap ACL.
    #[arg(long, default_value = "owner")]
    subject: String,
    /// Bind this bucket to its registered disclosure domain.
    #[arg(long, default_value = "private:owner")]
    domain: String,
    /// Name the local authority store in root policy.
    #[arg(long, default_value = "local")]
    store_name: String,
    /// Select an existing branch, or the initial branch for init.
    #[arg(long, default_value = "refs/heads/_/main")]
    reference: String,
    /// Keep this registered policy authority unchanged for every command.
    #[arg(long, default_value = "refs/heads/_/main")]
    policy_authority: String,
}

type Error = Box<dyn std::error::Error>;
type LocalRepository =
    Repository<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;

impl LocalArguments {
    fn location(&self) -> Result<LocalRepositoryLocation, Error> {
        Ok(LocalRepositoryLocation::from_file_url(
            &self.bucket,
            self.authority.clone(),
        )?)
    }

    fn identity(&self) -> LocalAuthorityIdentity {
        LocalAuthorityIdentity {
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            owner_uid: self.owner_uid,
        }
    }

    fn policy(&self) -> Result<LocalRepositoryPolicy, Error> {
        Ok(LocalRepositoryPolicy {
            store_name: self.store_name.clone(),
            domain: self.domain.clone(),
            default_private_domain: self.domain.clone(),
            acl: vec![(self.subject.clone(), Verbs::new(31)?.bits())],
            locality: Locality::default(),
            timing: CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            // Selecting a writer branch must not change registered guard setup.
            policy_authority: Some(self.policy_authority.clone()),
            bootstrap_properties: Vec::new(),
        })
    }

    async fn initialize(&self, not_after: u64) -> Result<(), Error> {
        let token_id = TokioLocalFs
            .random_bytes(16)
            .await?
            .try_into()
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid entropy length")
            })?;
        Repository::initialize_local(
            &self.location()?,
            LocalAuthorityParameters {
                owner_uid: self.owner_uid,
                authority: Authority {
                    issuer: self.issuer.clone(),
                    key_id: self.key_id.clone(),
                    subject: self.subject.clone(),
                    kind: PrincipalKind::Human,
                    groups: Vec::new(),
                    not_after,
                    not_before: None,
                    token_id,
                    grants: vec![Grant::new("refs/**".to_owned(), Verbs::new(31)?)?],
                    workload: None,
                },
            },
            self.policy()?,
            &self.reference,
            TokioLocalFs,
            TokioClock,
        )
        .await?;
        println!("initialized {}", self.reference);
        Ok(())
    }

    async fn open(&self) -> Result<(LocalRepository, LocalAuthority), Error> {
        Ok(Repository::open_local(
            &self.location()?,
            &self.identity(),
            self.policy()?,
            &self.reference,
            TokioLocalFs,
            TokioClock,
        )
        .await?)
    }
}

impl Command {
    /// Runs one porcelain operation through the public local SDK (CRATE-23).
    ///
    /// # Errors
    /// Propagates invalid setup, authentication, repository publication,
    /// registered realization, and local filesystem errors.
    pub(crate) async fn run(self) -> Result<(), Error> {
        let commit = match self {
            Self::Log {
                repository: arguments,
                from_sequence,
            } => {
                let (repository, authority) = arguments.open().await?;
                let history = repository
                    .ref_history(
                        &arguments.reference,
                        from_sequence,
                        authority.token(),
                        "sdk",
                    )
                    .await?;
                history::write(&history, &mut std::io::stdout().lock())?;
                return Ok(());
            }
            Self::Init {
                repository,
                not_after,
            } => return repository.initialize(not_after).await,
            Self::Commit {
                repository: arguments,
                directory,
                message,
            } => {
                let (repository, authority) = arguments.open().await?;
                let mut session = repository
                    .begin(&arguments.reference, authority.token(), "sdk")
                    .await?;
                repository
                    .commit_directory(
                        &mut session,
                        &directory,
                        &authority,
                        metadata(message, CommitSource::Uploaded),
                    )
                    .await?
                    .commit
            }
            Self::Fork {
                repository: arguments,
                destination,
                message,
            } => {
                let (repository, authority) = arguments.open().await?;
                let request =
                    repository.source_request(&authority, metadata(message, CommitSource::Built));
                repository
                    .fork(&arguments.reference, &destination, request)
                    .await?
                    .commit
            }
            Self::Merge {
                repository: arguments,
                source,
                message,
            } => {
                let (repository, authority) = arguments.open().await?;
                let mut session = repository
                    .begin(&arguments.reference, authority.token(), "sdk")
                    .await?;
                let request =
                    repository.source_request(&authority, metadata(message, CommitSource::Merged));
                repository
                    .merge(&mut session, &source, request, &[])
                    .await?
                    .commit
            }
            Self::Checkout {
                repository: arguments,
                view,
                destination,
            } => {
                let (repository, authority) = arguments.open().await?;
                let address = destination.to_str().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "checkout endpoint must be UTF-8",
                    )
                })?;
                let serving = repository
                    .realize(
                        View::parse(&view)?,
                        RealizationHints {
                            surface: "sdk".to_owned(),
                            endpoint: Endpoint {
                                kind: EndpointKind::Directory,
                                address: address.to_owned(),
                            },
                            token: authority.token().to_vec(),
                            reader: ReaderMode::Pinned,
                        },
                    )
                    .await?;
                serving.status().commit
            }
        };

        print_commit(&commit);
        Ok(())
    }
}

fn metadata(message: String, source: CommitSource) -> CommitMetadata {
    CommitMetadata {
        message,
        process: "terrane-cli".to_owned(),
        source,
    }
}

fn print_commit(commit: &[u8; 32]) {
    for byte in commit {
        print!("{byte:02x}");
    }
    println!();
}
