//! Managed Unix-socket namespaces for local campaign components.
//!
//! Production listener bootstrap uses one operator-owned directory whose owner
//! is exact and whose group/other write bits are clear. A lifetime `flock` on a
//! stable lock file proves that no cooperating prior listener remains before a
//! stale socket is removed. The bound socket's device/inode identity is retained
//! so teardown never removes a replacement path. The executor endpoint also
//! owns the matching outbound connector: it brackets connect with exact
//! namespace/socket identity checks and authenticates peer credentials.

use std::fs::{self, File, Permissions};
use std::io;
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{FlockOperation, Mode, OFlags, flock};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use rustix::time::Timespec;

const CAMPAIGN_ENDPOINT_LOCK_FILE: &str = ".crucible-campaign-listener.lock";
const EXECUTOR_ENDPOINT_LOCK_FILE: &str = ".crucible-executor-listener.lock";
// Linux `sockaddr_un.sun_path` has 108 bytes including the terminating NUL.
const MAX_ENDPOINT_PATH_BYTES: usize = 107;
const DEFAULT_EXECUTOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_EXECUTOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(60 * 60);

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
        let (listener, guard) = self.bind_parts(
            CAMPAIGN_ENDPOINT_LOCK_FILE,
            "bind-campaign-endpoint",
            "set-campaign-endpoint-mode",
        )?;
        Ok(ManagedCampaignLoopbackListener { listener, guard })
    }

    fn bind_parts(
        &self,
        lock_file: &'static str,
        bind_operation: &'static str,
        mode_operation: &'static str,
    ) -> Result<(UnixListener, LocalEndpointGuard), CampaignLoopbackEndpointError> {
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

        let lock_path = parent.join(lock_file);
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
            .map_err(|source| io_error(bind_operation, &self.path, source))?;
        let socket_identity = match finish_bound_socket(
            self,
            parent,
            &parent_directory,
            parent_identity,
            mode_operation,
        ) {
            Ok(identity) => identity,
            Err(source) => {
                let _ = fs::remove_file(&self.path);
                let _ = parent_directory.sync_all();
                return Err(source);
            }
        };
        Ok((
            listener,
            LocalEndpointGuard {
                path: self.path.clone(),
                socket_identity,
                parent_identity,
                parent_directory,
                _endpoint_lock: endpoint_lock,
            },
        ))
    }
}

/// Exact deployment contract for one managed executor-component socket.
///
/// The executor endpoint uses the same pathname, ownership, stale-recovery,
/// and exact-inode teardown rules as [`CampaignLoopbackEndpointConfig`], but a
/// distinct lifetime lock lets both endpoints coexist in one secure directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorLoopbackEndpointConfig {
    inner: CampaignLoopbackEndpointConfig,
}

impl ExecutorLoopbackEndpointConfig {
    /// Builds one absolute bounded executor endpoint contract.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorLoopbackEndpointError`] for the same invalid path,
    /// ownership profile, or socket mode as
    /// [`CampaignLoopbackEndpointConfig::new`].
    pub fn new(
        path: impl Into<PathBuf>,
        owner_user_id: u32,
        owner_group_id: u32,
        socket_mode: u32,
    ) -> Result<Self, ExecutorLoopbackEndpointError> {
        CampaignLoopbackEndpointConfig::new(path, owner_user_id, owner_group_id, socket_mode)
            .map(|inner| Self { inner })
    }

    /// Returns the exact stable socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    /// Returns the required socket and directory owner user ID.
    #[must_use]
    pub const fn owner_user_id(&self) -> u32 {
        self.inner.owner_user_id()
    }

    /// Returns the required socket and directory owner group ID.
    #[must_use]
    pub const fn owner_group_id(&self) -> u32 {
        self.inner.owner_group_id()
    }

    /// Returns the exact socket permission bits installed after bind.
    #[must_use]
    pub const fn socket_mode(&self) -> u32 {
        self.inner.socket_mode()
    }

    /// Acquires the executor namespace and binds one managed listener.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorLoopbackEndpointError`] when the namespace contract,
    /// stale entry, lifetime lock, bind result, ownership, permissions, or
    /// directory synchronization cannot be validated exactly.
    pub fn bind(&self) -> Result<ManagedExecutorLoopbackListener, ExecutorLoopbackEndpointError> {
        let (listener, guard) = self.inner.bind_parts(
            EXECUTOR_ENDPOINT_LOCK_FILE,
            "bind-executor-endpoint",
            "set-executor-endpoint-mode",
        )?;
        Ok(ManagedExecutorLoopbackListener { listener, guard })
    }

    /// Connects to one exact authenticated executor-component endpoint.
    ///
    /// The endpoint parent must satisfy the same exact-owner, non-writable
    /// namespace profile required for binding. The named socket must have the
    /// configured exact owner and mode before and after connection, retain the
    /// same device/inode identity, and report the configured effective peer
    /// credentials through `SO_PEERCRED`.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorLoopbackEndpointError`] when the parent, named socket,
    /// connection, peer credentials, or before/after identity cannot be
    /// authenticated exactly. A connected stream is shut down before any
    /// post-connect authentication error is returned.
    pub fn connect(&self) -> Result<UnixStream, ExecutorLoopbackEndpointError> {
        self.connect_with_timeout(DEFAULT_EXECUTOR_CONNECT_TIMEOUT)
    }

    /// Connects with one finite absolute deadline and authenticates the peer.
    ///
    /// Unlike socket read/write timeouts, this deadline bounds the complete
    /// nonblocking connect even if the executor's listen backlog remains full.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorLoopbackEndpointError::InvalidConnectTimeout`] when
    /// `timeout` is zero or exceeds one hour. Other failures match
    /// [`Self::connect`].
    pub fn connect_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<UnixStream, ExecutorLoopbackEndpointError> {
        if timeout.is_zero() || timeout > MAX_EXECUTOR_CONNECT_TIMEOUT {
            return Err(CampaignLoopbackEndpointError::InvalidConnectTimeout);
        }
        let config = &self.inner;
        let parent = config
            .path
            .parent()
            .ok_or(CampaignLoopbackEndpointError::InvalidPath)?;
        let parent_metadata = fs::symlink_metadata(parent)
            .map_err(|source| io_error("stat-executor-endpoint-directory", parent, source))?;
        validate_parent_metadata(config, &parent_metadata)?;
        let parent_directory = File::open(parent)
            .map_err(|source| io_error("open-executor-endpoint-directory", parent, source))?;
        let parent_identity = FileIdentity::from_metadata(&parent_metadata);
        revalidate_parent(config, parent, &parent_directory, parent_identity)?;

        let before = fs::symlink_metadata(&config.path).map_err(|source| {
            io_error(
                "stat-executor-endpoint-before-connect",
                &config.path,
                source,
            )
        })?;
        validate_connected_executor_socket(config, &before)?;
        let socket_identity = FileIdentity::from_metadata(&before);

        let stream = connect_executor_stream(&config.path, timeout)?;
        let authentication = (|| {
            let after = fs::symlink_metadata(&config.path).map_err(|source| {
                io_error("stat-executor-endpoint-after-connect", &config.path, source)
            })?;
            validate_connected_executor_socket(config, &after)?;
            if FileIdentity::from_metadata(&after) != socket_identity {
                return Err(CampaignLoopbackEndpointError::InvalidConnectedSocket);
            }
            revalidate_parent(config, parent, &parent_directory, parent_identity)?;
            let peer = rustix::net::sockopt::socket_peercred(&stream).map_err(|source| {
                io_error(
                    "authenticate-executor-endpoint-peer",
                    &config.path,
                    io::Error::from_raw_os_error(source.raw_os_error()),
                )
            })?;
            if peer.uid.as_raw() != config.owner_user_id
                || peer.gid.as_raw() != config.owner_group_id
            {
                return Err(CampaignLoopbackEndpointError::InvalidConnectedSocket);
            }
            Ok(())
        })();
        if let Err(source) = authentication {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(source);
        }
        Ok(stream)
    }
}

/// Bound listener retaining exact endpoint namespace ownership for its lifetime.
pub struct ManagedCampaignLoopbackListener {
    listener: UnixListener,
    guard: LocalEndpointGuard,
}

impl ManagedCampaignLoopbackListener {
    /// Returns the exact managed socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.guard.path
    }

    pub(crate) fn into_parts(self) -> (UnixListener, LocalEndpointGuard) {
        (self.listener, self.guard)
    }
}

/// Bound executor listener retaining exact endpoint namespace ownership.
pub struct ManagedExecutorLoopbackListener {
    listener: UnixListener,
    guard: LocalEndpointGuard,
}

impl ManagedExecutorLoopbackListener {
    /// Returns the exact managed socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.guard.path
    }

    pub(crate) fn into_parts(self) -> (UnixListener, LocalEndpointGuard) {
        (self.listener, self.guard)
    }
}

pub(crate) struct LocalEndpointGuard {
    path: PathBuf,
    socket_identity: FileIdentity,
    parent_identity: FileIdentity,
    parent_directory: File,
    _endpoint_lock: File,
}

impl Drop for LocalEndpointGuard {
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

/// Failure to establish or retain one managed local component endpoint.
#[derive(Debug, thiserror::Error)]
pub enum CampaignLoopbackEndpointError {
    /// The endpoint path was not absolute, bounded, or ordinarily named.
    #[error("local component endpoint path is invalid")]
    InvalidPath,
    /// Socket permission bits were invalid or granted no write access.
    #[error("local component endpoint socket mode is invalid")]
    InvalidSocketMode,
    /// The endpoint parent was not a real directory.
    #[error("local component endpoint parent is not a directory")]
    ParentNotDirectory,
    /// The endpoint parent owner did not match deployment configuration.
    #[error("local component endpoint parent ownership does not match configuration")]
    ParentOwnershipMismatch,
    /// The endpoint parent granted namespace mutation to group or other users.
    #[error("local component endpoint parent must not be group/other writable")]
    ParentNamespaceWritable,
    /// Another cooperating listener owns the endpoint namespace lock.
    #[error("local component endpoint is already in use")]
    EndpointInUse,
    /// The persistent endpoint lock was not an owner-only regular file.
    #[error("local component endpoint lock file is invalid")]
    InvalidLockFile,
    /// A preexisting endpoint path was not an eligible same-owner Unix socket.
    #[error("local component endpoint stale path is invalid")]
    InvalidStalePath,
    /// The bound socket did not match its exact ownership/type/mode contract.
    #[error("local component endpoint bound socket is invalid")]
    InvalidBoundSocket,
    /// A connected executor socket or peer did not match its exact contract.
    #[error("local executor endpoint or authenticated peer is invalid")]
    InvalidConnectedSocket,
    /// The executor connect deadline was zero or exceeded one hour.
    #[error("local executor endpoint connect timeout is invalid")]
    InvalidConnectTimeout,
    /// The pinned endpoint directory changed across namespace operations.
    #[error("local component endpoint directory identity changed")]
    DirectoryIdentityChanged,
    /// A filesystem or socket operation failed.
    #[error("local component endpoint {operation} failed for {}: {source}", path.display())]
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

/// Failure to establish or retain one managed executor endpoint.
pub type ExecutorLoopbackEndpointError = CampaignLoopbackEndpointError;

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

fn validate_connected_executor_socket(
    config: &CampaignLoopbackEndpointConfig,
    metadata: &fs::Metadata,
) -> Result<(), CampaignLoopbackEndpointError> {
    if !metadata.file_type().is_socket()
        || metadata.uid() != config.owner_user_id
        || metadata.gid() != config.owner_group_id
        || metadata.mode() & 0o7777 != config.socket_mode
    {
        return Err(CampaignLoopbackEndpointError::InvalidConnectedSocket);
    }
    Ok(())
}

fn connect_executor_stream(
    path: &Path,
    timeout: Duration,
) -> Result<UnixStream, CampaignLoopbackEndpointError> {
    let socket = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|source| rustix_io_error("create-executor-endpoint-socket", path, source))?;
    let address = SocketAddrUnix::new(path)
        .map_err(|source| rustix_io_error("encode-executor-endpoint-address", path, source))?;
    match rustix::net::connect(&socket, &address) {
        Ok(()) => {}
        Err(source)
            if source == rustix::io::Errno::INPROGRESS
                || source == rustix::io::Errno::AGAIN
                || source == rustix::io::Errno::INTR =>
        {
            wait_for_executor_connect(&socket, path, timeout)?;
        }
        Err(source) => {
            return Err(rustix_io_error("connect-executor-endpoint", path, source));
        }
    }

    let stream = UnixStream::from(socket);
    stream
        .set_nonblocking(false)
        .map_err(|source| io_error("configure-executor-endpoint-stream", path, source))?;
    Ok(stream)
}

fn wait_for_executor_connect(
    socket: &std::os::fd::OwnedFd,
    path: &Path,
    timeout: Duration,
) -> Result<(), CampaignLoopbackEndpointError> {
    let deadline = endpoint_now()
        .checked_add(timeout)
        .ok_or(CampaignLoopbackEndpointError::InvalidConnectTimeout)?;
    loop {
        let remaining = deadline
            .checked_duration_since(endpoint_now())
            .ok_or_else(|| {
                io_error(
                    "connect-executor-endpoint-timeout",
                    path,
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "executor endpoint connect timed out",
                    ),
                )
            })?;
        let timeout = Timespec::try_from(remaining).map_err(|source| {
            io_error(
                "convert-executor-endpoint-timeout",
                path,
                io::Error::new(io::ErrorKind::InvalidInput, source),
            )
        })?;
        let mut descriptors = [PollFd::new(socket, PollFlags::OUT)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => {
                return Err(io_error(
                    "connect-executor-endpoint-timeout",
                    path,
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "executor endpoint connect timed out",
                    ),
                ));
            }
            Ok(_) => match rustix::net::sockopt::socket_error(socket)
                .map_err(|source| rustix_io_error("read-executor-endpoint-error", path, source))?
            {
                Ok(()) => return Ok(()),
                Err(source) => {
                    return Err(rustix_io_error("connect-executor-endpoint", path, source));
                }
            },
            Err(source) if source == rustix::io::Errno::INTR => {}
            Err(source) => {
                return Err(rustix_io_error("poll-executor-endpoint", path, source));
            }
        }
    }
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
    mode_operation: &'static str,
) -> Result<FileIdentity, CampaignLoopbackEndpointError> {
    fs::set_permissions(&config.path, Permissions::from_mode(config.socket_mode))
        .map_err(|source| io_error(mode_operation, &config.path, source))?;
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

fn rustix_io_error(
    operation: &'static str,
    path: &Path,
    source: rustix::io::Errno,
) -> CampaignLoopbackEndpointError {
    io_error(
        operation,
        path,
        io::Error::from_raw_os_error(source.raw_os_error()),
    )
}

// Monotonic endpoint time bounds only operational socket blocking and never
// enters campaign semantic state or content identity.
// crucible-lint: allow clippy-disallowed-method -- the bounded host operation is operational only and cannot enter modeled state.
#[allow(clippy::disallowed_methods)]
fn endpoint_now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests;
