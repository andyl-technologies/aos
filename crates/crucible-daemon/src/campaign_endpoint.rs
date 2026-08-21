//! Managed Unix-socket namespace for the local campaign service.
//!
//! Production listener bootstrap uses one operator-owned directory whose owner
//! is exact and whose group/other write bits are clear. A lifetime `flock` on a
//! stable lock file proves that no cooperating prior listener remains before a
//! stale socket is removed. The bound socket's device/inode identity is retained
//! so teardown never removes a replacement path.

use std::fs::{self, File, Permissions};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{FlockOperation, Mode, OFlags, flock};

const ENDPOINT_LOCK_FILE: &str = ".crucible-campaign-listener.lock";
// Linux `sockaddr_un.sun_path` has 108 bytes including the terminating NUL.
const MAX_ENDPOINT_PATH_BYTES: usize = 107;

/// Exact deployment contract for one managed campaign-service socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignLoopbackEndpointConfig {
    path: PathBuf,
    owner_user_id: u32,
    owner_group_id: u32,
    socket_mode: u32,
}

impl CampaignLoopbackEndpointConfig {
    /// Builds one absolute bounded endpoint contract.
    ///
    /// `owner_user_id` and `owner_group_id` must own both the endpoint
    /// directory and the resulting socket. `socket_mode` contains only Unix
    /// permission bits; the parent directory separately controls traversal.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLoopbackEndpointError::InvalidPath`] when `path` is
    /// relative, noncanonical, contains NUL, has no ordinary filename, or
    /// exceeds the 107-byte Linux pathname-socket ceiling. Returns
    /// [`CampaignLoopbackEndpointError::InvalidSocketMode`] when `socket_mode`
    /// contains bits outside `0o777` or grants no write permission to any
    /// principal.
    pub fn new(
        path: impl Into<PathBuf>,
        owner_user_id: u32,
        owner_group_id: u32,
        socket_mode: u32,
    ) -> Result<Self, CampaignLoopbackEndpointError> {
        let path = path.into();
        let encoded_path = path.as_os_str().as_encoded_bytes();
        let ordinary_name = path.file_name().is_some();
        let canonical_components = path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
        if !path.is_absolute()
            || !ordinary_name
            || !canonical_components
            || encoded_path.contains(&0)
            || encoded_path.len() > MAX_ENDPOINT_PATH_BYTES
        {
            return Err(CampaignLoopbackEndpointError::InvalidPath);
        }
        if socket_mode == 0 || socket_mode & !0o777 != 0 || socket_mode & 0o222 == 0 {
            return Err(CampaignLoopbackEndpointError::InvalidSocketMode);
        }
        Ok(Self {
            path,
            owner_user_id,
            owner_group_id,
            socket_mode,
        })
    }

    /// Returns the exact stable socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the required socket and directory owner user ID.
    #[must_use]
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }

    /// Returns the required socket and directory owner group ID.
    #[must_use]
    pub const fn owner_group_id(&self) -> u32 {
        self.owner_group_id
    }

    /// Returns the exact socket permission bits installed after bind.
    #[must_use]
    pub const fn socket_mode(&self) -> u32 {
        self.socket_mode
    }

    /// Acquires the endpoint namespace, removes an authenticated stale socket,
    /// and binds one managed listener.
    ///
    /// The endpoint directory must already exist. It must be a real directory
    /// owned by the configured user/group, and group/other write bits must be
    /// clear. A persistent regular lock file in that directory excludes another
    /// cooperating listener incarnation. Only a socket owned by the same exact
    /// user/group is eligible for stale recovery.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLoopbackEndpointError`] when the namespace contract,
    /// stale entry, lifetime lock, bind result, ownership, permissions, or
    /// directory synchronization cannot be validated exactly.
    pub fn bind(&self) -> Result<ManagedCampaignLoopbackListener, CampaignLoopbackEndpointError> {
        let parent = self
            .path
            .parent()
            .ok_or(CampaignLoopbackEndpointError::InvalidPath)?;
        let parent_path_metadata = fs::symlink_metadata(parent)
            .map_err(|source| io_error("stat-endpoint-directory", parent, source))?;
        validate_parent_metadata(self, &parent_path_metadata)?;
        let parent_directory = File::open(parent)
            .map_err(|source| io_error("open-endpoint-directory", parent, source))?;
        let parent_identity = FileIdentity::from_metadata(&parent_path_metadata);
        require_file_identity(&parent_directory, parent_identity, parent)?;

        let lock_path = parent.join(ENDPOINT_LOCK_FILE);
        let endpoint_lock: File = rustix::fs::open(
            &lock_path,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|source| {
            io_error(
                "open-endpoint-lock",
                &lock_path,
                io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?
        .into();
        validate_lock(self, &lock_path, &endpoint_lock)?;
        flock(&endpoint_lock, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
            if source == rustix::io::Errno::WOULDBLOCK {
                CampaignLoopbackEndpointError::EndpointInUse
            } else {
                io_error(
                    "lock-endpoint-namespace",
                    &lock_path,
                    io::Error::from_raw_os_error(source.raw_os_error()),
                )
            }
        })?;
        revalidate_parent(self, parent, &parent_directory, parent_identity)?;

        remove_stale_socket(self)?;
        parent_directory
            .sync_all()
            .map_err(|source| io_error("sync-endpoint-directory-before-bind", parent, source))?;

        let listener = UnixListener::bind(&self.path)
            .map_err(|source| io_error("bind-campaign-endpoint", &self.path, source))?;
        let socket_identity =
            match finish_bound_socket(self, parent, &parent_directory, parent_identity) {
                Ok(identity) => identity,
                Err(source) => {
                    let _ = fs::remove_file(&self.path);
                    let _ = parent_directory.sync_all();
                    return Err(source);
                }
            };
        Ok(ManagedCampaignLoopbackListener {
            listener,
            guard: CampaignEndpointGuard {
                path: self.path.clone(),
                socket_identity,
                parent_identity,
                parent_directory,
                _endpoint_lock: endpoint_lock,
            },
        })
    }
}

/// Bound listener retaining exact endpoint namespace ownership for its lifetime.
pub struct ManagedCampaignLoopbackListener {
    listener: UnixListener,
    guard: CampaignEndpointGuard,
}

impl ManagedCampaignLoopbackListener {
    /// Returns the exact managed socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.guard.path
    }

    pub(crate) fn into_parts(self) -> (UnixListener, CampaignEndpointGuard) {
        (self.listener, self.guard)
    }
}

pub(crate) struct CampaignEndpointGuard {
    path: PathBuf,
    socket_identity: FileIdentity,
    parent_identity: FileIdentity,
    parent_directory: File,
    _endpoint_lock: File,
}

impl Drop for CampaignEndpointGuard {
    fn drop(&mut self) {
        let Some(parent) = self.path.parent() else {
            return;
        };
        let Ok(parent_metadata) = fs::symlink_metadata(parent) else {
            return;
        };
        if FileIdentity::from_metadata(&parent_metadata) != self.parent_identity
            || !parent_metadata.file_type().is_dir()
        {
            return;
        }
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && FileIdentity::from_metadata(&metadata) == self.socket_identity
        {
            let _ = fs::remove_file(&self.path);
            let _ = self.parent_directory.sync_all();
        }
    }
}

/// Failure to establish or retain one managed campaign endpoint.
#[derive(Debug, thiserror::Error)]
pub enum CampaignLoopbackEndpointError {
    /// The endpoint path was not absolute, bounded, or ordinarily named.
    #[error("campaign endpoint path is invalid")]
    InvalidPath,
    /// Socket permission bits were invalid or granted no write access.
    #[error("campaign endpoint socket mode is invalid")]
    InvalidSocketMode,
    /// The endpoint parent was not a real directory.
    #[error("campaign endpoint parent is not a directory")]
    ParentNotDirectory,
    /// The endpoint parent owner did not match deployment configuration.
    #[error("campaign endpoint parent ownership does not match configuration")]
    ParentOwnershipMismatch,
    /// The endpoint parent granted namespace mutation to group or other users.
    #[error("campaign endpoint parent must not be group/other writable")]
    ParentNamespaceWritable,
    /// Another cooperating listener owns the endpoint namespace lock.
    #[error("campaign endpoint is already in use")]
    EndpointInUse,
    /// The persistent endpoint lock was not an owner-only regular file.
    #[error("campaign endpoint lock file is invalid")]
    InvalidLockFile,
    /// A preexisting endpoint path was not an eligible same-owner Unix socket.
    #[error("campaign endpoint stale path is invalid")]
    InvalidStalePath,
    /// The bound socket did not match its exact ownership/type/mode contract.
    #[error("campaign endpoint bound socket is invalid")]
    InvalidBoundSocket,
    /// The pinned endpoint directory changed across namespace operations.
    #[error("campaign endpoint directory identity changed")]
    DirectoryIdentityChanged,
    /// A filesystem or socket operation failed.
    #[error("campaign endpoint {operation} failed for {}: {source}", path.display())]
    Io {
        /// Stable operation category.
        operation: &'static str,
        /// Exact affected path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

fn validate_parent_metadata(
    config: &CampaignLoopbackEndpointConfig,
    metadata: &fs::Metadata,
) -> Result<(), CampaignLoopbackEndpointError> {
    if !metadata.file_type().is_dir() {
        return Err(CampaignLoopbackEndpointError::ParentNotDirectory);
    }
    if metadata.uid() != config.owner_user_id || metadata.gid() != config.owner_group_id {
        return Err(CampaignLoopbackEndpointError::ParentOwnershipMismatch);
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(CampaignLoopbackEndpointError::ParentNamespaceWritable);
    }
    Ok(())
}

fn validate_lock(
    config: &CampaignLoopbackEndpointConfig,
    path: &Path,
    lock: &File,
) -> Result<(), CampaignLoopbackEndpointError> {
    rustix::fs::fchmod(lock, Mode::RUSR | Mode::WUSR).map_err(|source| {
        io_error(
            "set-endpoint-lock-mode",
            path,
            io::Error::from_raw_os_error(source.raw_os_error()),
        )
    })?;
    let metadata = lock
        .metadata()
        .map_err(|source| io_error("stat-endpoint-lock", path, source))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != config.owner_user_id
        || metadata.gid() != config.owner_group_id
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(CampaignLoopbackEndpointError::InvalidLockFile);
    }
    Ok(())
}

fn remove_stale_socket(
    config: &CampaignLoopbackEndpointConfig,
) -> Result<(), CampaignLoopbackEndpointError> {
    let metadata = match fs::symlink_metadata(&config.path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(io_error("stat-stale-endpoint", &config.path, source)),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != config.owner_user_id
        || metadata.gid() != config.owner_group_id
    {
        return Err(CampaignLoopbackEndpointError::InvalidStalePath);
    }
    fs::remove_file(&config.path)
        .map_err(|source| io_error("remove-stale-endpoint", &config.path, source))
}

fn finish_bound_socket(
    config: &CampaignLoopbackEndpointConfig,
    parent: &Path,
    parent_directory: &File,
    parent_identity: FileIdentity,
) -> Result<FileIdentity, CampaignLoopbackEndpointError> {
    fs::set_permissions(&config.path, Permissions::from_mode(config.socket_mode))
        .map_err(|source| io_error("set-campaign-endpoint-mode", &config.path, source))?;
    let metadata = fs::symlink_metadata(&config.path)
        .map_err(|source| io_error("stat-bound-endpoint", &config.path, source))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != config.owner_user_id
        || metadata.gid() != config.owner_group_id
        || metadata.mode() & 0o777 != config.socket_mode
    {
        return Err(CampaignLoopbackEndpointError::InvalidBoundSocket);
    }
    revalidate_parent(config, parent, parent_directory, parent_identity)?;
    parent_directory
        .sync_all()
        .map_err(|source| io_error("sync-bound-endpoint-directory", parent, source))?;
    Ok(FileIdentity::from_metadata(&metadata))
}

fn revalidate_parent(
    config: &CampaignLoopbackEndpointConfig,
    path: &Path,
    directory: &File,
    identity: FileIdentity,
) -> Result<(), CampaignLoopbackEndpointError> {
    require_file_identity(directory, identity, path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("restat-endpoint-directory", path, source))?;
    validate_parent_metadata(config, &metadata)?;
    if FileIdentity::from_metadata(&metadata) != identity {
        return Err(CampaignLoopbackEndpointError::DirectoryIdentityChanged);
    }
    Ok(())
}

fn require_file_identity(
    file: &File,
    expected: FileIdentity,
    path: &Path,
) -> Result<(), CampaignLoopbackEndpointError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("stat-pinned-endpoint-directory", path, source))?;
    if FileIdentity::from_metadata(&metadata) != expected || !metadata.file_type().is_dir() {
        return Err(CampaignLoopbackEndpointError::DirectoryIdentityChanged);
    }
    Ok(())
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> CampaignLoopbackEndpointError {
    CampaignLoopbackEndpointError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests;
