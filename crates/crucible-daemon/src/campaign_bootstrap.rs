//! Durable single-host bootstrap for the local campaign service.
//!
//! This module composes the managed Unix endpoint, strict peer policy, fixed
//! listener, and directory-backed campaign repository behind one lifecycle.
//! The state root is an operator-owned namespace with a lifetime exclusive
//! lock, preventing two cooperating daemon incarnations from claiming the sole
//! writer repository through different socket paths.

use std::fs::{self, File, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crucible_campaign::{
    CampaignAuthorizationError, CampaignHash, CampaignName, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignRepository, CampaignServiceOperation,
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use rustix::fs::{FlockOperation, Mode, OFlags, flock};

use crate::{
    CampaignLoopbackEndpointConfig, CampaignLoopbackEndpointError, CampaignLoopbackListenerError,
    CampaignLoopbackServer, CampaignLoopbackServerConfig, CampaignLoopbackServerReport,
    CampaignLoopbackServerShutdown, MAX_CAMPAIGN_POLICY_BYTES, UnixPeerCampaignPolicy,
    UnixPeerCampaignPolicyLoadError,
};

const STATE_LOCK_FILE: &str = ".crucible-campaign-repository.lock";
const OBJECT_DIRECTORY: &str = "objects";
const REF_DIRECTORY: &str = "refs";
const MAX_DEPLOYMENT_PATH_BYTES: usize = 4_095;

/// Complete deployment contract for one durable local campaign service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignLocalServiceConfig {
    endpoint: CampaignLoopbackEndpointConfig,
    state_directory: PathBuf,
    policy_path: PathBuf,
    mode: CampaignLocalServiceMode,
    server: CampaignLoopbackServerConfig,
}

/// Mutation policy applied by one local campaign service incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignLocalServiceMode {
    /// Permits every operation granted by the strict deployment policy.
    ReadWrite,
    /// Denies every mutation even when the deployment policy grants it.
    ReadOnly,
}

impl CampaignLocalServiceMode {
    const fn permits(self, operation: CampaignServiceOperation) -> bool {
        match self {
            Self::ReadWrite => true,
            Self::ReadOnly => match operation {
                CampaignServiceOperation::CreateCampaign
                | CampaignServiceOperation::DeriveCampaign
                | CampaignServiceOperation::ApplyCampaignCommand
                | CampaignServiceOperation::PinCampaign
                | CampaignServiceOperation::SubmitBranchRequest => false,
                CampaignServiceOperation::GetCampaign
                | CampaignServiceOperation::GetCampaignSnapshot
                | CampaignServiceOperation::WatchCampaign
                | CampaignServiceOperation::QueryCampaignGraph
                | CampaignServiceOperation::QueryCampaignFindings
                | CampaignServiceOperation::GetCampaignFindingObject
                | CampaignServiceOperation::ExplainCampaignAttempt
                | CampaignServiceOperation::GetCampaignGraphObject
                | CampaignServiceOperation::QueryCampaignChoices
                | CampaignServiceOperation::QueryCampaignFrontier
                | CampaignServiceOperation::GetCampaignFrontierObject
                | CampaignServiceOperation::GetCampaignChoiceObject => true,
            },
        }
    }
}

impl CampaignLocalServiceConfig {
    /// Builds one exact local service deployment contract.
    ///
    /// The state directory and policy file must already exist. Their exact
    /// owner is inherited from `endpoint`; both paths must be absolute, free of
    /// dot components and NUL, and bounded to 4,095 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::InvalidStatePath`] or
    /// [`CampaignLocalServiceError::InvalidPolicyPath`] when a deployment path
    /// is not structurally admissible.
    pub fn new(
        endpoint: CampaignLoopbackEndpointConfig,
        state_directory: impl Into<PathBuf>,
        policy_path: impl Into<PathBuf>,
        mode: CampaignLocalServiceMode,
        server: CampaignLoopbackServerConfig,
    ) -> Result<Self, CampaignLocalServiceError> {
        let state_directory = state_directory.into();
        if !valid_deployment_path(&state_directory) {
            return Err(CampaignLocalServiceError::InvalidStatePath);
        }
        let policy_path = policy_path.into();
        if !valid_deployment_path(&policy_path) {
            return Err(CampaignLocalServiceError::InvalidPolicyPath);
        }
        Ok(Self {
            endpoint,
            state_directory,
            policy_path,
            mode,
            server,
        })
    }

    /// Returns the managed Unix endpoint contract.
    #[must_use]
    pub const fn endpoint(&self) -> &CampaignLoopbackEndpointConfig {
        &self.endpoint
    }

    /// Returns the exact durable repository root.
    #[must_use]
    pub fn state_directory(&self) -> &Path {
        &self.state_directory
    }

    /// Returns the exact strict deployment-policy path.
    #[must_use]
    pub fn policy_path(&self) -> &Path {
        &self.policy_path
    }

    /// Returns the exact read-only or read-write service mode.
    #[must_use]
    pub const fn mode(&self) -> CampaignLocalServiceMode {
        self.mode
    }

    /// Returns the bounded listener configuration.
    #[must_use]
    pub const fn server(&self) -> CampaignLoopbackServerConfig {
        self.server
    }

    /// Authenticates deployment input and opens one exclusive local service.
    ///
    /// Policy authentication is read-only and precedes any state-directory or
    /// socket mutation. The returned owner retains both the repository and
    /// endpoint locks until serving has stopped and every worker has joined.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError`] when the policy, state namespace,
    /// durable subdirectories, endpoint, or listener cannot be authenticated
    /// and acquired exactly.
    pub fn open(&self) -> Result<CampaignLocalService, CampaignLocalServiceError> {
        let policy = Arc::new(load_policy(
            &self.policy_path,
            self.endpoint.owner_user_id(),
            self.endpoint.owner_group_id(),
        )?);
        let state = CampaignStateOwner::open(
            &self.state_directory,
            self.endpoint.owner_user_id(),
            self.endpoint.owner_group_id(),
        )?;

        let blobs = Arc::new(DirectoryBlobBackend::new(
            "campaign-primary",
            state.object_directory.clone(),
        ));
        let refs = Arc::new(DirectoryRefBackend::new(state.ref_directory.clone()));
        let repository = Arc::new(CampaignRepository::new(blobs, refs));
        let listener = self.endpoint.bind()?;
        let server = CampaignLoopbackServer::from_managed_listener(
            listener,
            repository,
            Arc::clone(&policy),
            Arc::new(CampaignLocalAuthorizer {
                policy,
                mode: self.mode,
            }),
            self.server,
        )?;
        Ok(CampaignLocalService {
            server,
            _state: state,
        })
    }
}

/// Exclusive owner of one durable local CampaignService incarnation.
pub struct CampaignLocalService {
    server: CampaignLoopbackServer<UnixPeerCampaignPolicy, CampaignLocalAuthorizer>,
    _state: CampaignStateOwner,
}

struct CampaignLocalAuthorizer {
    policy: Arc<UnixPeerCampaignPolicy>,
    mode: CampaignLocalServiceMode,
}

impl CampaignPrincipalAuthorizer for CampaignLocalAuthorizer {
    fn authorize(
        &self,
        principal: &CampaignPrincipal,
        operation: CampaignServiceOperation,
        campaign: &CampaignName,
        request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        if !self.mode.permits(operation) {
            return Err(CampaignAuthorizationError::Unauthorized);
        }
        self.policy
            .authorize(principal, operation, campaign, request_digest)
    }
}

impl CampaignLocalService {
    /// Returns a cloneable sticky shutdown authority.
    #[must_use]
    pub fn shutdown_handle(&self) -> CampaignLoopbackServerShutdown {
        self.server.shutdown_handle()
    }

    /// Serves authenticated campaign requests until sticky shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::Listener`] when listener acceptance
    /// or a worker invariant fails. Repository and endpoint ownership remain
    /// held until all workers have stopped.
    pub fn serve(self) -> Result<CampaignLoopbackServerReport, CampaignLocalServiceError> {
        let Self {
            server,
            _state: state,
        } = self;
        let result = server.serve().map_err(CampaignLocalServiceError::Listener);
        drop(state);
        result
    }
}

/// Failure to authenticate, acquire, or serve one local campaign deployment.
#[derive(Debug, thiserror::Error)]
pub enum CampaignLocalServiceError {
    /// The durable state path was relative, noncanonical, unbounded, or empty.
    #[error("campaign service state path is invalid")]
    InvalidStatePath,
    /// The deployment-policy path was relative, noncanonical, unbounded, or empty.
    #[error("campaign service policy path is invalid")]
    InvalidPolicyPath,
    /// The state root was not a secure exact-owner directory.
    #[error("campaign service state directory is invalid")]
    InvalidStateDirectory,
    /// Another cooperating daemon owns the durable repository lock.
    #[error("campaign service repository is already in use")]
    StateInUse,
    /// The durable repository lock was not an owner-only regular file.
    #[error("campaign service repository lock is invalid")]
    InvalidStateLock,
    /// A required object/ref subdirectory was not a secure exact-owner directory.
    #[error("campaign service repository subdirectory is invalid")]
    InvalidStateSubdirectory,
    /// The policy was not a secure exact-owner regular file.
    #[error("campaign service policy file is invalid")]
    InvalidPolicyFile,
    /// The strict policy body was malformed or violated a policy invariant.
    #[error(transparent)]
    Policy(#[from] UnixPeerCampaignPolicyLoadError),
    /// The managed Unix endpoint could not be acquired.
    #[error(transparent)]
    Endpoint(#[from] CampaignLoopbackEndpointError),
    /// The fixed listener could not be configured or failed while serving.
    #[error(transparent)]
    Listener(#[from] CampaignLoopbackListenerError),
    /// A deployment filesystem operation failed.
    #[error("campaign service {operation} failed for {}: {source}", path.display())]
    Io {
        /// Stable operation category.
        operation: &'static str,
        /// Exact affected deployment path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },
}

struct CampaignStateOwner {
    object_directory: PathBuf,
    ref_directory: PathBuf,
    _root: File,
    _lock: File,
}

impl CampaignStateOwner {
    fn open(path: &Path, user_id: u32, group_id: u32) -> Result<Self, CampaignLocalServiceError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|source| io_error("stat-state-directory", path, source))?;
        validate_secure_directory(&metadata, user_id, group_id)
            .map_err(|()| CampaignLocalServiceError::InvalidStateDirectory)?;
        let root =
            File::open(path).map_err(|source| io_error("open-state-directory", path, source))?;
        require_same_file(&root, &metadata, path, "state-directory")?;

        let lock_path = path.join(STATE_LOCK_FILE);
        let lock: File = rustix::fs::open(
            &lock_path,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|source| {
            io_error(
                "open-state-lock",
                &lock_path,
                io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?
        .into();
        let lock_metadata = lock
            .metadata()
            .map_err(|source| io_error("stat-state-lock", &lock_path, source))?;
        if !lock_metadata.is_file()
            || lock_metadata.uid() != user_id
            || lock_metadata.gid() != group_id
        {
            return Err(CampaignLocalServiceError::InvalidStateLock);
        }
        rustix::fs::fchmod(&lock, Mode::RUSR | Mode::WUSR).map_err(|source| {
            io_error(
                "set-state-lock-mode",
                &lock_path,
                io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?;
        if lock
            .metadata()
            .map_err(|source| io_error("restat-state-lock", &lock_path, source))?
            .mode()
            & 0o777
            != 0o600
        {
            return Err(CampaignLocalServiceError::InvalidStateLock);
        }
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
            if source == rustix::io::Errno::WOULDBLOCK {
                CampaignLocalServiceError::StateInUse
            } else {
                io_error(
                    "lock-state-directory",
                    &lock_path,
                    io::Error::from_raw_os_error(source.raw_os_error()),
                )
            }
        })?;
        revalidate_state_path(&root, &metadata, path, user_id, group_id)?;

        let object_directory = prepare_subdirectory(path, OBJECT_DIRECTORY, user_id, group_id)?;
        let ref_directory = prepare_subdirectory(path, REF_DIRECTORY, user_id, group_id)?;
        revalidate_state_path(&root, &metadata, path, user_id, group_id)?;
        root.sync_all()
            .map_err(|source| io_error("sync-state-directory", path, source))?;
        Ok(Self {
            object_directory,
            ref_directory,
            _root: root,
            _lock: lock,
        })
    }
}

fn load_policy(
    path: &Path,
    user_id: u32,
    group_id: u32,
) -> Result<UnixPeerCampaignPolicy, CampaignLocalServiceError> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("stat-policy-file", path, source))?;
    if !path_metadata.is_file()
        || path_metadata.uid() != user_id
        || path_metadata.gid() != group_id
        || path_metadata.mode() & 0o022 != 0
    {
        return Err(CampaignLocalServiceError::InvalidPolicyFile);
    }
    let mut file: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        io_error(
            "open-policy-file",
            path,
            io::Error::from_raw_os_error(source.raw_os_error()),
        )
    })?
    .into();
    let file_metadata = file
        .metadata()
        .map_err(|source| io_error("stat-open-policy-file", path, source))?;
    if file_metadata.dev() != path_metadata.dev()
        || file_metadata.ino() != path_metadata.ino()
        || !file_metadata.is_file()
        || file_metadata.uid() != user_id
        || file_metadata.gid() != group_id
        || file_metadata.mode() & 0o022 != 0
    {
        return Err(CampaignLocalServiceError::InvalidPolicyFile);
    }
    if file_metadata.len() > MAX_CAMPAIGN_POLICY_BYTES as u64 {
        return Err(UnixPeerCampaignPolicyLoadError::TooLarge.into());
    }

    let mut bytes = Vec::with_capacity(file_metadata.len() as usize);
    file.by_ref()
        .take((MAX_CAMPAIGN_POLICY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read-policy-file", path, source))?;
    if bytes.len() > MAX_CAMPAIGN_POLICY_BYTES {
        return Err(UnixPeerCampaignPolicyLoadError::TooLarge.into());
    }
    UnixPeerCampaignPolicy::from_toml_bytes(&bytes).map_err(Into::into)
}

fn prepare_subdirectory(
    root: &Path,
    name: &'static str,
    user_id: u32,
    group_id: u32,
) -> Result<PathBuf, CampaignLocalServiceError> {
    let path = root.join(name);
    match fs::create_dir(&path) {
        Ok(()) => fs::set_permissions(&path, Permissions::from_mode(0o700))
            .map_err(|source| io_error("set-state-subdirectory-mode", &path, source))?,
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(io_error("create-state-subdirectory", &path, source)),
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|source| io_error("stat-state-subdirectory", &path, source))?;
    if validate_secure_directory(&metadata, user_id, group_id).is_err()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(CampaignLocalServiceError::InvalidStateSubdirectory);
    }
    Ok(path)
}

fn validate_secure_directory(
    metadata: &fs::Metadata,
    user_id: u32,
    group_id: u32,
) -> Result<(), ()> {
    if metadata.is_dir()
        && metadata.uid() == user_id
        && metadata.gid() == group_id
        && metadata.mode() & 0o022 == 0
    {
        Ok(())
    } else {
        Err(())
    }
}

fn require_same_file(
    file: &File,
    path_metadata: &fs::Metadata,
    path: &Path,
    operation: &'static str,
) -> Result<(), CampaignLocalServiceError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error(operation, path, source))?;
    if metadata.dev() != path_metadata.dev() || metadata.ino() != path_metadata.ino() {
        return Err(match operation {
            "policy-file" => CampaignLocalServiceError::InvalidPolicyFile,
            _ => CampaignLocalServiceError::InvalidStateDirectory,
        });
    }
    Ok(())
}

fn revalidate_state_path(
    root: &File,
    original: &fs::Metadata,
    path: &Path,
    user_id: u32,
    group_id: u32,
) -> Result<(), CampaignLocalServiceError> {
    require_same_file(root, original, path, "state-directory")?;
    let current = fs::symlink_metadata(path)
        .map_err(|source| io_error("restat-state-directory", path, source))?;
    if current.dev() != original.dev()
        || current.ino() != original.ino()
        || validate_secure_directory(&current, user_id, group_id).is_err()
    {
        return Err(CampaignLocalServiceError::InvalidStateDirectory);
    }
    Ok(())
}

fn valid_deployment_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    path.is_absolute()
        && path.file_name().is_some()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && !bytes.contains(&0)
        && bytes.len() <= MAX_DEPLOYMENT_PATH_BYTES
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> CampaignLocalServiceError {
    CampaignLocalServiceError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests;
