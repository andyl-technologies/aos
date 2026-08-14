//! Linux QEMU process spawning with fixed inherited descriptors.
//!
//! This module owns the Linux-only process boundary required by RFC-0010
//! T-QEMU-7. It creates the per-node control socket pair, shared-memory memfd,
//! and wake eventfd before `exec`, maps the child descriptors to the fixed
//! plugin fd numbers, clears the inherited host environment, and sets
//! `PR_SET_PDEATHSIG=SIGKILL` in the child.

use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use thiserror::Error;

use crate::{
    QEMU_PLUGIN_CONTROL_FD, QEMU_PLUGIN_SHMEM_FD, QEMU_PLUGIN_WAKE_FD, QemuLaunchCommand,
    QemuNodeChild,
};

const CHILD_SOURCE_FD_MIN: RawFd = QEMU_PLUGIN_WAKE_FD + 1;

/// Host-side descriptors retained after spawning a QEMU child.
#[derive(Debug)]
pub struct QemuSpawnHostResources {
    control_socket: OwnedFd,
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
    region_len: u64,
    fault_node_hash: [u8; 32],
}

impl QemuSpawnHostResources {
    /// Returns the host end of the plugin IPC control socket.
    #[must_use]
    pub fn control_socket_fd(&self) -> RawFd {
        self.control_socket.as_raw_fd()
    }

    /// Returns the host shared-memory descriptor.
    #[must_use]
    pub fn shmem_fd(&self) -> RawFd {
        self.shmem_fd.as_raw_fd()
    }

    /// Returns the host wake event descriptor.
    #[must_use]
    pub fn wake_fd(&self) -> RawFd {
        self.wake_fd.as_raw_fd()
    }

    /// Returns the shared-memory region length used to size the memfd.
    #[must_use]
    pub const fn region_len(&self) -> u64 {
        self.region_len
    }

    /// Consumes retained host descriptors into setup-driver resources.
    #[must_use]
    pub fn into_setup_resources(self) -> QemuSpawnSetupResources {
        QemuSpawnSetupResources {
            control_socket: UnixStream::from(self.control_socket),
            shmem_fd: self.shmem_fd,
            wake_fd: self.wake_fd,
            region_len: self.region_len,
            fault_node_hash: self.fault_node_hash,
        }
    }
}

/// Host-side descriptors in the shape required by the setup protocol driver.
#[derive(Debug)]
pub struct QemuSpawnSetupResources {
    control_socket: UnixStream,
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
    region_len: u64,
    fault_node_hash: [u8; 32],
}

impl QemuSpawnSetupResources {
    /// Returns the host end of the plugin IPC control socket.
    #[must_use]
    pub fn control_socket_fd(&self) -> RawFd {
        self.control_socket.as_raw_fd()
    }

    /// Returns the host shared-memory descriptor.
    #[must_use]
    pub fn shmem_fd(&self) -> RawFd {
        self.shmem_fd.as_raw_fd()
    }

    /// Returns the host wake event descriptor.
    #[must_use]
    pub fn wake_fd(&self) -> RawFd {
        self.wake_fd.as_raw_fd()
    }

    /// Returns the shared-memory region length used to size the memfd.
    #[must_use]
    pub const fn region_len(&self) -> u64 {
        self.region_len
    }

    /// Returns the node identity hash encoded in the spawned plugin argument.
    #[must_use]
    pub const fn fault_node_hash(&self) -> [u8; 32] {
        self.fault_node_hash
    }

    /// Consumes the setup resources into their owned parts.
    #[must_use]
    pub fn into_parts(self) -> (UnixStream, OwnedFd, OwnedFd, u64, [u8; 32]) {
        (
            self.control_socket,
            self.shmem_fd,
            self.wake_fd,
            self.region_len,
            self.fault_node_hash,
        )
    }
}

/// A spawned QEMU child plus the host descriptors retained for its node.
#[derive(Debug)]
pub struct QemuSpawnedChild {
    child: QemuNodeChild,
    resources: QemuSpawnHostResources,
}

impl QemuSpawnedChild {
    /// Consumes the spawn result into its node child and retained host resources.
    #[must_use]
    pub fn into_parts(self) -> (QemuNodeChild, QemuSpawnHostResources) {
        (self.child, self.resources)
    }
}

/// Errors returned while preparing or spawning a QEMU child.
#[derive(Debug, Error)]
pub enum QemuSpawnError {
    /// The shared-memory region length was zero.
    #[error("shared-memory region length must be non-zero")]
    RegionLengthZero,
    /// The shared-memory region length cannot be represented by `ftruncate`.
    #[error("shared-memory region length {region_len} is too large for ftruncate")]
    RegionLengthTooLarge {
        /// Requested shared-memory region length.
        region_len: u64,
    },
    /// A Linux descriptor or process operation failed.
    #[error("{operation} failed: {source}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Underlying OS error.
        source: io::Error,
    },
    /// The exact-VMState qcow2 container could not be created.
    #[error("qemu-img could not create exact-VMState container {path}: {status}: {stderr}")]
    VmStateImageTool {
        /// Intended qcow2 container path.
        path: PathBuf,
        /// Process exit status rendered without host-specific structure.
        status: String,
        /// Trimmed qemu-img diagnostic output.
        stderr: String,
    },
}

/// Spawns a validated QEMU launch command in `run_directory`.
///
/// The spawn path first creates the exact-VMState qcow2 container with the
/// `qemu-img` adjacent to the selected QEMU executable. Relative launch
/// artifacts, including that container, the QMP socket filename, and root
/// overlay image, are then resolved by QEMU under this working directory
/// without embedding volatile host paths in the launch hash material.
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when run-directory or VMState-container
/// preparation, descriptor creation, descriptor duplication, parent-death
/// signal setup, changing the child working directory, or process spawning
/// fails.
pub fn spawn_qemu_child_with_fds_in_directory(
    command: &QemuLaunchCommand,
    run_directory: impl AsRef<Path>,
    region_len: u64,
) -> Result<QemuSpawnedChild, QemuSpawnError> {
    let run_directory = run_directory.as_ref();
    prepare_vmstate_container(command, run_directory)?;
    let (mut resources, child_resources) = create_spawn_resources(region_len)?;
    resources.fault_node_hash = command.plugin_fault_node_hash();
    let child = spawn_process_with_resources(
        command.executable(),
        command.args(),
        Some(run_directory),
        child_resources,
        &[],
        "spawn QEMU child",
    )?;
    Ok(QemuSpawnedChild {
        child: QemuNodeChild::new(child),
        resources,
    })
}

fn prepare_vmstate_container(
    command: &QemuLaunchCommand,
    run_directory: &Path,
) -> Result<(), QemuSpawnError> {
    fs::create_dir_all(run_directory).map_err(|source| QemuSpawnError::Io {
        operation: "create QEMU run directory",
        source,
    })?;
    let path = run_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME);
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => return Ok(()),
        Ok(_) => {
            return Err(QemuSpawnError::Io {
                operation: "validate exact-VMState container path",
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "exact-VMState container path is not a regular file",
                ),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(QemuSpawnError::Io {
                operation: "inspect exact-VMState container",
                source,
            });
        }
    }

    let staging = tempfile::Builder::new()
        .prefix(".crucible-vmstate-")
        .suffix(".qcow2")
        .tempfile_in(run_directory)
        .map_err(|source| QemuSpawnError::Io {
            operation: "stage exact-VMState container",
            source,
        })?;
    let image_tool = Path::new(command.executable()).with_file_name("qemu-img");
    let output = Command::new(&image_tool)
        .arg("create")
        .arg("-q")
        .arg("-f")
        .arg("qcow2")
        .arg(staging.path())
        .arg(format!("{}M", command.vmstate_size_mib()))
        .output()
        .map_err(|source| QemuSpawnError::Io {
            operation: "execute qemu-img for exact-VMState container",
            source,
        })?;
    if !output.status.success() {
        return Err(QemuSpawnError::VmStateImageTool {
            path,
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    staging
        .as_file()
        .sync_all()
        .map_err(|source| QemuSpawnError::Io {
            operation: "flush exact-VMState container",
            source,
        })?;
    match staging.persist_noclobber(&path) {
        Ok(_) => {}
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::metadata(&path).map_err(|source| QemuSpawnError::Io {
                operation: "inspect concurrently created exact-VMState container",
                source,
            })?;
            if !metadata.is_file() {
                return Err(QemuSpawnError::Io {
                    operation: "validate concurrently created exact-VMState container",
                    source: io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "exact-VMState container path is not a regular file",
                    ),
                });
            }
        }
        Err(error) => {
            return Err(QemuSpawnError::Io {
                operation: "publish exact-VMState container",
                source: error.error,
            });
        }
    }
    File::open(run_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| QemuSpawnError::Io {
            operation: "flush QEMU run directory",
            source,
        })
}

#[derive(Debug)]
struct QemuSpawnChildResources {
    control_socket: OwnedFd,
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
}

fn create_spawn_resources(
    region_len: u64,
) -> Result<(QemuSpawnHostResources, QemuSpawnChildResources), QemuSpawnError> {
    if region_len == 0 {
        return Err(QemuSpawnError::RegionLengthZero);
    }

    let (host_control, child_control) = socket_pair()?;
    let child_control =
        duplicate_cloexec_fd(child_control.as_raw_fd(), "duplicate plugin control fd")?;
    let host_shmem = memfd_region(region_len)?;
    let child_shmem = duplicate_cloexec_fd(host_shmem.as_raw_fd(), "duplicate shmem fd")?;
    let host_wake = event_fd()?;
    let child_wake = duplicate_cloexec_fd(host_wake.as_raw_fd(), "duplicate wake fd")?;

    Ok((
        QemuSpawnHostResources {
            control_socket: host_control,
            shmem_fd: host_shmem,
            wake_fd: host_wake,
            region_len,
            fault_node_hash: [0; 32],
        },
        QemuSpawnChildResources {
            control_socket: child_control,
            shmem_fd: child_shmem,
            wake_fd: child_wake,
        },
    ))
}

#[cfg(test)]
/// Creates host setup resources and the child-side control socket for tests.
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when descriptor setup fails or `region_len` is
/// zero.
pub(crate) fn create_test_spawn_resource_pair(
    region_len: u64,
) -> Result<(QemuSpawnHostResources, UnixStream), QemuSpawnError> {
    let (mut host_resources, child_resources) = create_spawn_resources(region_len)?;
    host_resources.fault_node_hash = crate::qemu_fault_target_hash("standalone-vm-slot-0");
    Ok((
        host_resources,
        UnixStream::from(child_resources.control_socket),
    ))
}

fn spawn_process_with_resources(
    executable: &str,
    args: &[String],
    run_directory: Option<&Path>,
    child_resources: QemuSpawnChildResources,
    envs: &[(&str, &str)],
    operation: &'static str,
) -> Result<Child, QemuSpawnError> {
    let control_fd = child_resources.control_socket.as_raw_fd();
    let shmem_fd = child_resources.shmem_fd.as_raw_fd();
    let wake_fd = child_resources.wake_fd.as_raw_fd();
    let expected_parent_pid = unsafe {
        // SAFETY: `getpid` has no preconditions.
        libc::getpid()
    };

    let mut command = Command::new(executable);
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Some(run_directory) = run_directory {
        command.current_dir(run_directory);
    }
    for (key, value) in envs {
        command.env(key, value);
    }

    // SAFETY: the closure only calls async-signal-safe syscalls between fork
    // and exec: `prctl`, `getppid`, `dup2`, and `close`. It captures only raw
    // descriptor numbers, not heap-owning Rust values.
    unsafe {
        command.pre_exec(move || {
            install_child_process_contract(control_fd, shmem_fd, wake_fd, expected_parent_pid)
        });
    }

    command
        .spawn()
        .map_err(|source| QemuSpawnError::Io { operation, source })
}

fn socket_pair() -> Result<(OwnedFd, OwnedFd), QemuSpawnError> {
    let mut fds = [-1; 2];
    let result = unsafe {
        // SAFETY: `fds` points to two writable RawFd slots for `socketpair`.
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(last_io_error("create plugin control socketpair"));
    }
    let host = owned_fd_from_raw(fds[0]);
    let child = owned_fd_from_raw(fds[1]);
    Ok((host, child))
}

fn memfd_region(region_len: u64) -> Result<OwnedFd, QemuSpawnError> {
    let region_len = libc::off_t::try_from(region_len)
        .map_err(|_| QemuSpawnError::RegionLengthTooLarge { region_len })?;
    let name = CString::new("crucible-qemu-shmem").map_err(|source| QemuSpawnError::Io {
        operation: "build memfd name",
        source: io::Error::new(io::ErrorKind::InvalidInput, source),
    })?;
    let fd = unsafe {
        // SAFETY: `name` is a valid NUL-terminated C string.
        libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
    };
    if fd < 0 {
        return Err(last_io_error("create shmem memfd"));
    }
    let fd = owned_fd_from_raw(fd);
    let truncate = unsafe {
        // SAFETY: `fd` is a live memfd, and `region_len` was range-checked.
        libc::ftruncate(fd.as_raw_fd(), region_len)
    };
    if truncate != 0 {
        return Err(last_io_error("size shmem memfd"));
    }
    let seal = unsafe {
        // SAFETY: `fd` is a live sealable memfd. The shrink seal preserves the
        // mapping length while still permitting shared-memory writes.
        libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, libc::F_SEAL_SHRINK)
    };
    if seal != 0 {
        return Err(last_io_error("seal shmem memfd against shrink"));
    }
    Ok(fd)
}

fn event_fd() -> Result<OwnedFd, QemuSpawnError> {
    let fd = unsafe {
        // SAFETY: `eventfd` has no pointer arguments; flags request close-on-exec.
        libc::eventfd(0, libc::EFD_CLOEXEC)
    };
    if fd < 0 {
        return Err(last_io_error("create wake eventfd"));
    }
    Ok(owned_fd_from_raw(fd))
}

fn duplicate_cloexec_fd(fd: RawFd, operation: &'static str) -> Result<OwnedFd, QemuSpawnError> {
    let duplicated = unsafe {
        // SAFETY: `fcntl` reads a live fd and returns a new fd on success.
        libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, CHILD_SOURCE_FD_MIN)
    };
    if duplicated < 0 {
        return Err(last_io_error(operation));
    }
    Ok(owned_fd_from_raw(duplicated))
}

fn install_child_process_contract(
    control_fd: RawFd,
    shmem_fd: RawFd,
    wake_fd: RawFd,
    expected_parent_pid: libc::pid_t,
) -> io::Result<()> {
    set_parent_death_signal(expected_parent_pid)?;
    dup_to_fixed_child_fd(control_fd, QEMU_PLUGIN_CONTROL_FD)?;
    dup_to_fixed_child_fd(shmem_fd, QEMU_PLUGIN_SHMEM_FD)?;
    dup_to_fixed_child_fd(wake_fd, QEMU_PLUGIN_WAKE_FD)?;
    close_child_source_fd(control_fd)?;
    close_child_source_fd(shmem_fd)?;
    close_child_source_fd(wake_fd)
}

fn set_parent_death_signal(expected_parent_pid: libc::pid_t) -> io::Result<()> {
    let result = unsafe {
        // SAFETY: `prctl` is called with integer arguments only.
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0)
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    let current_parent = unsafe {
        // SAFETY: `getppid` has no preconditions.
        libc::getppid()
    };
    if current_parent == expected_parent_pid {
        Ok(())
    } else {
        // Abort when the "parent changed before child exec" race is observed.
        Err(io::Error::from_raw_os_error(libc::ECHILD))
    }
}

fn dup_to_fixed_child_fd(source_fd: RawFd, target_fd: RawFd) -> io::Result<()> {
    let result = unsafe {
        // SAFETY: both arguments are descriptor numbers; `dup2` validates them.
        libc::dup2(source_fd, target_fd)
    };
    if result == target_fd {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn close_child_source_fd(fd: RawFd) -> io::Result<()> {
    let result = unsafe {
        // SAFETY: `fd` is a descriptor number owned by the post-fork child.
        libc::close(fd)
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn owned_fd_from_raw(fd: RawFd) -> OwnedFd {
    unsafe {
        // SAFETY: callers pass a newly returned descriptor that is uniquely owned.
        OwnedFd::from_raw_fd(fd)
    }
}

fn last_io_error(operation: &'static str) -> QemuSpawnError {
    QemuSpawnError::Io {
        operation,
        source: io::Error::last_os_error(),
    }
}

#[cfg(test)]
#[path = "spawn_test.rs"]
mod tests;
