//! Length-bounded access to Unix sockets owned by a QEMU run directory.
//!
//! QEMU creates its sockets from stable relative names after changing into the
//! run directory. On Linux, joining the same name to a long Nix build directory
//! can exceed `sockaddr_un.sun_path` even though QEMU bound the socket. These
//! helpers resolve the parent through an open directory descriptor, keeping the
//! pathname supplied to the socket syscall short without changing the socket's
//! filesystem identity.

#[cfg(target_os = "linux")]
use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, RenameFlags, chmodat, chownat, fstat, mkdirat, openat,
    renameat_with, statat, unlinkat,
};
#[cfg(target_os = "linux")]
use rustix::process::{Gid, Uid, getegid, geteuid};

#[cfg(target_os = "linux")]
const SOCKET_STAGING_DIRECTORY_NAME: &str = ".crucible-socket-staging";

/// Nonblocking listener that authenticates the one expected QEMU process.
#[cfg(target_os = "linux")]
pub(crate) struct ExpectedPeerUnixListener {
    listener: UnixListener,
    expected_credentials: Option<(u32, u32)>,
}

#[cfg(target_os = "linux")]
impl ExpectedPeerUnixListener {
    /// Wraps a listener for an uncontained QEMU process.
    pub(crate) fn for_process(listener: UnixListener) -> io::Result<Self> {
        Self::new(listener, None)
    }

    /// Wraps a listener for QEMU running as one admitted child identity.
    pub(crate) fn for_child(
        listener: UnixListener,
        user_id: u32,
        group_id: u32,
    ) -> io::Result<Self> {
        Self::new(listener, Some((user_id, group_id)))
    }

    fn new(listener: UnixListener, expected_credentials: Option<(u32, u32)>) -> io::Result<Self> {
        // The caller accepts only after QEMU's plugin setup ACK, which is
        // emitted after chardev realization. Nonblocking mode converts any
        // violated ordering invariant into a launch failure instead of a hang.
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            expected_credentials,
        })
    }

    /// Accepts and authenticates the connection from the exact spawned QEMU.
    pub(crate) fn accept_from(&self, process_id: u32) -> io::Result<UnixStream> {
        let (stream, _address) = self.listener.accept()?;
        let peer = rustix::net::sockopt::socket_peercred(&stream)?;
        let process_matches = u32::try_from(peer.pid.as_raw_pid()).ok() == Some(process_id);
        let credentials_match = self.expected_credentials.is_none_or(|(user_id, group_id)| {
            peer.uid.as_raw() == user_id && peer.gid.as_raw() == group_id
        });
        if !process_matches || !credentials_match {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Unix socket peer does not match the spawned QEMU identity",
            ));
        }
        Ok(stream)
    }
}

/// Connects to a filesystem Unix socket without embedding a long parent path.
pub(crate) fn connect(path: &Path) -> io::Result<UnixStream> {
    let resolved = ResolvedSocketPath::new(path)?;
    UnixStream::connect(&resolved.path)
}

/// Binds a filesystem Unix socket without embedding a long parent path.
#[cfg(target_os = "linux")]
pub(crate) fn bind(path: &Path) -> io::Result<UnixListener> {
    let resolved = ResolvedSocketPath::new(path)?;
    UnixListener::bind(&resolved.path)
}

/// Binds a socket privately for a child identity and installs it by descriptor.
///
/// The prepared run directory is child-owned. Binding at the final name and
/// then changing that pathname's owner would therefore authorize a concurrent
/// namespace substitution. A supervisor-owned staging directory keeps the
/// socket entry inaccessible while its policy is installed; `renameat2` then
/// publishes the already-configured socket without replacing an existing name.
#[cfg(target_os = "linux")]
pub(crate) fn bind_child_owned_at(
    directory: BorrowedFd<'_>,
    file_name: &str,
    user_id: u32,
    group_id: u32,
) -> io::Result<UnixListener> {
    validate_file_name(file_name)?;

    mkdirat(
        directory,
        SOCKET_STAGING_DIRECTORY_NAME,
        Mode::from_bits_truncate(0o700),
    )?;
    // The child-owned parent may have been mutated after `mkdirat`. An
    // unverified name is retained for attempt cleanup rather than removed.
    let staging = open_staging_directory(directory)?;
    let staging_identity = directory_identity(&staging)?;

    let staged = bind_staged_socket(&staging, file_name);
    let result = staged.and_then(|staged| {
        let result = install_child_owned_socket(
            directory,
            &staging,
            file_name,
            user_id,
            group_id,
            staged.identity,
        );
        if result.is_err() {
            let _ = unlink_socket_if_same(&staging, file_name, staged.identity);
        }
        result.map(|()| staged.listener)
    });
    let cleanup = remove_pinned_staging_directory(directory, &staging, staging_identity);

    match (result, cleanup) {
        (Ok(listener), Ok(())) => Ok(listener),
        (Err(primary), _) => Err(primary),
        (Ok(_listener), Err(cleanup)) => Err(cleanup),
    }
}

#[cfg(target_os = "linux")]
struct StagedSocket {
    listener: UnixListener,
    identity: (u128, u128),
}

#[cfg(target_os = "linux")]
fn bind_staged_socket(staging: &OwnedFd, file_name: &str) -> io::Result<StagedSocket> {
    let resolved = descriptor_relative_path(staging.as_fd(), file_name);
    let listener = UnixListener::bind(resolved)?;
    let metadata = statat(staging, file_name, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Socket {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "new Unix socket pathname is not a socket",
        ));
    }

    Ok(StagedSocket {
        listener,
        identity: directory_identity_from_stat(&metadata),
    })
}

#[cfg(target_os = "linux")]
fn install_child_owned_socket(
    directory: BorrowedFd<'_>,
    staging: &OwnedFd,
    file_name: &str,
    user_id: u32,
    group_id: u32,
    expected_identity: (u128, u128),
) -> io::Result<()> {
    chmodat(
        staging,
        file_name,
        Mode::from_bits_truncate(0o600),
        AtFlags::empty(),
    )?;
    chownat(
        staging,
        file_name,
        Some(Uid::from_raw(user_id)),
        Some(Gid::from_raw(group_id)),
        AtFlags::SYMLINK_NOFOLLOW,
    )?;

    let staged = statat(staging, file_name, AtFlags::SYMLINK_NOFOLLOW)?;
    if directory_identity_from_stat(&staged) != expected_identity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged Unix socket identity changed",
        ));
    }
    validate_socket_policy(&staged, user_id, group_id)?;
    renameat_with(
        staging,
        file_name,
        directory,
        file_name,
        RenameFlags::NOREPLACE,
    )?;

    let installed = statat(directory, file_name, AtFlags::SYMLINK_NOFOLLOW)?;
    if !same_identity(&staged, &installed) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed Unix socket identity changed",
        ));
    }
    validate_socket_policy(&installed, user_id, group_id)?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn unlink_socket_if_same(
    staging: &OwnedFd,
    file_name: &str,
    expected_identity: (u128, u128),
) -> io::Result<()> {
    let named = match statat(staging, file_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(named) => named,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(source) => return Err(source.into()),
    };
    if directory_identity_from_stat(&named) != expected_identity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged Unix socket identity changed before cleanup",
        ));
    }
    unlinkat(staging, file_name, AtFlags::empty())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_staging_directory(directory: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    let staging = openat(
        directory,
        SOCKET_STAGING_DIRECTORY_NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let metadata = fstat(&staging)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != geteuid().as_raw()
        || metadata.st_gid != getegid().as_raw()
        || metadata.st_mode & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix socket staging directory is not supervisor-private",
        ));
    }
    Ok(staging)
}

#[cfg(target_os = "linux")]
fn remove_pinned_staging_directory(
    directory: BorrowedFd<'_>,
    staging: &OwnedFd,
    expected: (u128, u128),
) -> io::Result<()> {
    let retained = directory_identity(staging)?;
    let named = statat(
        directory,
        SOCKET_STAGING_DIRECTORY_NAME,
        AtFlags::SYMLINK_NOFOLLOW,
    )?;
    if retained != expected || directory_identity_from_stat(&named) != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unix socket staging directory identity changed before cleanup",
        ));
    }

    unlinkat(directory, SOCKET_STAGING_DIRECTORY_NAME, AtFlags::REMOVEDIR)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_file_name(file_name: &str) -> io::Result<()> {
    let path = Path::new(file_name);
    if file_name.is_empty()
        || file_name.as_bytes().contains(&0)
        || path.file_name() != Some(path.as_os_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix socket name must be one non-empty path component",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_socket_policy(
    metadata: &rustix::fs::Stat,
    user_id: u32,
    group_id: u32,
) -> io::Result<()> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Socket
        || metadata.st_uid != user_id
        || metadata.st_gid != group_id
        || metadata.st_mode & 0o777 != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix socket does not have the admitted child owner and owner-only mode",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn directory_identity(directory: &OwnedFd) -> io::Result<(u128, u128)> {
    let metadata = fstat(directory)?;
    Ok(directory_identity_from_stat(&metadata))
}

#[cfg(target_os = "linux")]
fn directory_identity_from_stat(metadata: &rustix::fs::Stat) -> (u128, u128) {
    (u128::from(metadata.st_dev), u128::from(metadata.st_ino))
}

#[cfg(target_os = "linux")]
fn same_identity(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    directory_identity_from_stat(left) == directory_identity_from_stat(right)
}

#[cfg(target_os = "linux")]
fn descriptor_relative_path(directory: BorrowedFd<'_>, file_name: &str) -> PathBuf {
    PathBuf::from("/proc/self/fd")
        .join(directory.as_raw_fd().to_string())
        .join(file_name)
}

struct ResolvedSocketPath {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    _directory: Option<File>,
}

impl ResolvedSocketPath {
    fn new(path: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        if let (Some(parent), Some(file_name)) = (path.parent(), path.file_name())
            && !parent.as_os_str().is_empty()
        {
            let directory = File::open(parent)?;
            let resolved = PathBuf::from("/proc/self/fd")
                .join(directory.as_raw_fd().to_string())
                .join(file_name);
            return Ok(Self {
                path: resolved,
                _directory: Some(directory),
            });
        }

        Ok(Self {
            path: path.to_path_buf(),
            #[cfg(target_os = "linux")]
            _directory: None,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, ExitStatus};
    use std::thread;
    use std::time::Duration;

    const CHILD_CONNECT_PATH_ENV: &str = "CRUCIBLE_SOCKET_OWNER_TEST_PATH";

    struct TestChildGuard {
        child: Child,
        reaped: bool,
    }

    impl TestChildGuard {
        fn spawn(command: &mut Command) -> io::Result<Self> {
            Ok(Self {
                child: command.spawn()?,
                reaped: false,
            })
        }

        fn process_id(&self) -> u32 {
            self.child.id()
        }

        fn wait_bounded(&mut self) -> io::Result<ExitStatus> {
            for _attempt in 0..5_000 {
                if let Some(status) = self.child.try_wait()? {
                    self.reaped = true;
                    return Ok(status);
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "admitted child connector did not exit",
            ))
        }
    }

    impl Drop for TestChildGuard {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            let _ = self.child.kill();
            for _attempt in 0..1_000 {
                match self.child.try_wait() {
                    Ok(Some(_status)) => {
                        self.reaped = true;
                        return;
                    }
                    Ok(None) => thread::sleep(Duration::from_millis(1)),
                    Err(_source) => return,
                }
            }
        }
    }

    #[test]
    fn descriptor_relative_path_reaches_socket_beyond_sun_path_limit() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("a".repeat(64)).join("b".repeat(64));
        std::fs::create_dir_all(&directory)?;
        let socket = directory.join("console.sock");
        assert!(socket.as_os_str().as_bytes().len() > 108);

        let listener = bind(&socket)?;
        let client = connect(&socket)?;
        let (_server, _address) = listener.accept()?;
        drop(client);
        Ok(())
    }

    #[test]
    fn child_owned_bind_installs_exact_private_policy() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let directory = File::open(root.path())?;
        let listener = bind_child_owned_at(
            directory.as_fd(),
            "activation.sock",
            geteuid().as_raw(),
            getegid().as_raw(),
        )?;

        let socket = root.path().join("activation.sock");
        let metadata = std::fs::symlink_metadata(&socket)?;
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), geteuid().as_raw());
        assert_eq!(metadata.gid(), getegid().as_raw());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(!root.path().join(SOCKET_STAGING_DIRECTORY_NAME).exists());

        let client = connect(&socket)?;
        let (_server, _address) = listener.accept()?;
        drop(client);
        Ok(())
    }

    #[test]
    fn child_owned_bind_preserves_occupied_destination() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let socket = root.path().join("activation.sock");
        let original = UnixListener::bind(&socket)?;
        let directory = File::open(root.path())?;

        let error = match bind_child_owned_at(
            directory.as_fd(),
            "activation.sock",
            geteuid().as_raw(),
            getegid().as_raw(),
        ) {
            Ok(_listener) => panic!("occupied destination must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(!root.path().join(SOCKET_STAGING_DIRECTORY_NAME).exists());

        let client = connect(&socket)?;
        let (_server, _address) = original.accept()?;
        drop(client);
        Ok(())
    }

    #[test]
    fn expected_peer_listener_rejects_absence_and_wrong_process() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let socket = root.path().join("activation.sock");
        let listener = UnixListener::bind(&socket)?;
        let listener = ExpectedPeerUnixListener::for_process(listener)?;

        let absent = match listener.accept_from(std::process::id()) {
            Ok(_stream) => panic!("absent QEMU connection must not succeed"),
            Err(error) => error,
        };
        assert_eq!(absent.kind(), io::ErrorKind::WouldBlock);

        let _client = connect(&socket)?;
        let wrong_process_id = std::process::id().wrapping_add(1).max(1);
        let wrong = match listener.accept_from(wrong_process_id) {
            Ok(_stream) => panic!("unexpected process must fail authentication"),
            Err(error) => error,
        };
        assert_eq!(wrong.kind(), io::ErrorKind::PermissionDenied);
        Ok(())
    }

    #[test]
    fn child_owned_bind_reaches_directory_beyond_sun_path_limit() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("a".repeat(64)).join("b".repeat(64));
        std::fs::create_dir_all(&path)?;
        let socket = path.join("activation.sock");
        assert!(socket.as_os_str().as_bytes().len() > 108);
        let directory = File::open(&path)?;

        let listener = bind_child_owned_at(
            directory.as_fd(),
            "activation.sock",
            geteuid().as_raw(),
            getegid().as_raw(),
        )?;
        let client = connect(&socket)?;
        let (_server, _address) = listener.accept()?;
        drop(client);
        Ok(())
    }

    #[test]
    fn child_owned_socket_accepts_the_distinct_admitted_identity() -> io::Result<()> {
        if geteuid().as_raw() != 0 {
            return Ok(());
        }

        let child_user_id = 65_534;
        let child_group_id = 65_534;
        let root = tempfile::tempdir()?;
        let directory = File::open(root.path())?;
        rustix::fs::fchown(
            &directory,
            Some(Uid::from_raw(child_user_id)),
            Some(Gid::from_raw(child_group_id)),
        )?;
        let socket = root.path().join("activation.sock");
        let listener = bind_child_owned_at(
            directory.as_fd(),
            "activation.sock",
            child_user_id,
            child_group_id,
        )?;
        let listener =
            ExpectedPeerUnixListener::for_child(listener, child_user_id, child_group_id)?;

        let test_executable = std::env::current_exe()?;
        let mut command = Command::new(test_executable);
        command
            .arg("--exact")
            .arg("unix_socket_path::tests::connect_as_admitted_identity_child")
            .env(CHILD_CONNECT_PATH_ENV, &socket);
        // `uid` drops supplementary groups when changing away from root; `gid`
        // installs the exact admitted primary group before `exec`.
        command.uid(child_user_id).gid(child_group_id);
        let mut child = TestChildGuard::spawn(&mut command)?;
        let mut accepted = None;
        for _attempt in 0..5_000 {
            match listener.accept_from(child.process_id()) {
                Ok(stream) => {
                    accepted = Some(stream);
                    break;
                }
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(source) => return Err(source),
            }
        }
        let accepted = accepted.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "admitted child did not connect to owner-only socket",
            )
        })?;
        drop(accepted);
        let status = child.wait_bounded()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "admitted child connector failed with {status}"
            )));
        }
        Ok(())
    }

    #[test]
    fn connect_as_admitted_identity_child() -> io::Result<()> {
        let Some(path) = std::env::var_os(CHILD_CONNECT_PATH_ENV) else {
            return Ok(());
        };
        let _stream = UnixStream::connect(path)?;
        Ok(())
    }
}
