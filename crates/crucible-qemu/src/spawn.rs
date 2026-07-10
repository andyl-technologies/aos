//! Linux QEMU process spawning with fixed inherited descriptors.
//!
//! This module owns the Linux-only process boundary required by RFC-0010
//! T-QEMU-7. It creates the per-node control socket pair, shared-memory memfd,
//! and wake eventfd before `exec`, maps the child descriptors to the fixed
//! plugin fd numbers, clears the inherited host environment, and sets
//! `PR_SET_PDEATHSIG=SIGKILL` in the child.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
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

    /// Consumes the setup resources into their owned parts.
    #[must_use]
    pub fn into_parts(self) -> (UnixStream, OwnedFd, OwnedFd, u64) {
        (
            self.control_socket,
            self.shmem_fd,
            self.wake_fd,
            self.region_len,
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
}

/// Spawns a validated QEMU launch command with fixed child descriptors.
///
/// The child receives the plugin control socket at fd 3, the shared-memory memfd
/// at fd 4, and the wake eventfd at fd 5. The host retains its own descriptor
/// copies in the returned [`QemuSpawnHostResources`].
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when descriptor creation, descriptor duplication,
/// parent-death signal setup, or process spawning fails.
pub fn spawn_qemu_child_with_fds(
    command: &QemuLaunchCommand,
    region_len: u64,
) -> Result<QemuSpawnedChild, QemuSpawnError> {
    spawn_qemu_child_with_fds_in_optional_directory(command, None, region_len)
}

/// Spawns a validated QEMU launch command in `run_directory`.
///
/// Relative launch artifacts, including the QMP socket filename and root overlay
/// image, are resolved by QEMU under this working directory without embedding
/// volatile host paths in the launch hash material.
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when descriptor creation, descriptor duplication,
/// parent-death signal setup, changing the child working directory, or process
/// spawning fails.
pub fn spawn_qemu_child_with_fds_in_directory(
    command: &QemuLaunchCommand,
    run_directory: impl AsRef<Path>,
    region_len: u64,
) -> Result<QemuSpawnedChild, QemuSpawnError> {
    spawn_qemu_child_with_fds_in_optional_directory(
        command,
        Some(run_directory.as_ref()),
        region_len,
    )
}

fn spawn_qemu_child_with_fds_in_optional_directory(
    command: &QemuLaunchCommand,
    run_directory: Option<&Path>,
    region_len: u64,
) -> Result<QemuSpawnedChild, QemuSpawnError> {
    let (resources, child_resources) = create_spawn_resources(region_len)?;
    let child = spawn_process_with_resources(
        command.executable(),
        command.args(),
        run_directory,
        child_resources,
        &[],
        "spawn QEMU child",
    )?;
    Ok(QemuSpawnedChild {
        child: QemuNodeChild::new(child),
        resources,
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
    let (host_resources, child_resources) = create_spawn_resources(region_len)?;
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
        .stderr(Stdio::null());
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
mod tests {
    use std::env;
    use std::error::Error;
    use std::io::Write;
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    const PROBE_ENV: &str = "CRUCIBLE_QEMU_SPAWN_CHILD_PROBE";
    const SOURCE_FDS_ENV: &str = "CRUCIBLE_QEMU_SPAWN_SOURCE_FDS";
    const CWD_PROBE_ENV: &str = "CRUCIBLE_QEMU_SPAWN_CWD_PROBE";
    const PDEATH_PARENT_ENV: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_PARENT_PROBE";
    const PDEATH_CHILD_ENV: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_CHILD_PROBE";
    const PDEATH_CHILD_PID_PREFIX: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_CHILD_PID=";
    const ENV_CLEAR_PARENT_PROBE: &str = "CRUCIBLE_QEMU_SPAWN_ENV_CLEAR_PARENT_PROBE";
    const ENV_CLEAR_CHILD_PROBE: &str = "CRUCIBLE_QEMU_SPAWN_ENV_CLEAR_CHILD_PROBE";
    const INHERITED_ENV_SENTINEL: &str = "CRUCIBLE_QEMU_SPAWN_INHERITED_SENTINEL";
    const EXPLICIT_ENV_SENTINEL: &str = "CRUCIBLE_QEMU_SPAWN_EXPLICIT_SENTINEL";
    static TEMP_DIR_SUFFIX: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn qemu_spawn_resources_create_socket_memfd_eventfd_and_host_copies()
    -> Result<(), Box<dyn Error>> {
        let (resources, child_resources) = create_spawn_resources(4096)?;

        assert_eq!(resources.region_len(), 4096);
        assert_fd_open(resources.control_socket_fd())?;
        assert_fd_open(resources.shmem_fd())?;
        assert_fd_open(resources.wake_fd())?;
        assert_fd_open(child_resources.control_socket.as_raw_fd())?;
        assert_fd_open(child_resources.shmem_fd.as_raw_fd())?;
        assert_fd_open(child_resources.wake_fd.as_raw_fd())?;
        assert_eq!(fd_size(resources.shmem_fd())?, 4096);
        assert_ne!(
            fd_seals(resources.shmem_fd())? & libc::F_SEAL_SHRINK,
            0,
            "spawned shared-memory memfd must be sealed against shrink"
        );
        assert_ne!(
            resources.control_socket_fd(),
            child_resources.control_socket.as_raw_fd()
        );
        assert_ne!(resources.shmem_fd(), child_resources.shmem_fd.as_raw_fd());
        assert_ne!(resources.wake_fd(), child_resources.wake_fd.as_raw_fd());

        Ok(())
    }

    #[test]
    fn qemu_spawn_rejects_empty_region() {
        assert!(matches!(
            create_spawn_resources(0),
            Err(QemuSpawnError::RegionLengthZero)
        ));
    }

    #[test]
    fn qemu_spawn_maps_fixed_child_fds_after_pre_exec() -> Result<(), Box<dyn Error>> {
        if env::var_os(PROBE_ENV).is_some() {
            child_probe_fixed_fds()?;
            return Ok(());
        }

        let (_host, child_resources) = create_spawn_resources(4096)?;
        let source_fds = format!(
            "{},{},{}",
            child_resources.control_socket.as_raw_fd(),
            child_resources.shmem_fd.as_raw_fd(),
            child_resources.wake_fd.as_raw_fd()
        );
        let current_exe = env::current_exe()?;
        let current_exe = current_exe.to_string_lossy().into_owned();
        let args = vec![
            String::from("--exact"),
            String::from("spawn::tests::qemu_spawn_maps_fixed_child_fds_after_pre_exec"),
        ];
        let mut child = spawn_process_with_resources(
            &current_exe,
            &args,
            None,
            child_resources,
            &[(PROBE_ENV, "1"), (SOURCE_FDS_ENV, &source_fds)],
            "spawn child fd probe",
        )?;

        let status = child.wait()?;

        assert!(status.success());
        Ok(())
    }

    #[test]
    fn qemu_spawn_run_directory_sets_child_cwd() -> Result<(), Box<dyn Error>> {
        if let Some(expected) = env::var_os(CWD_PROBE_ENV) {
            child_probe_cwd(Path::new(&expected))?;
            return Ok(());
        }

        let (_host, child_resources) = create_spawn_resources(4096)?;
        let source_fds = format!(
            "{},{},{}",
            child_resources.control_socket.as_raw_fd(),
            child_resources.shmem_fd.as_raw_fd(),
            child_resources.wake_fd.as_raw_fd()
        );
        let run_directory = unique_temp_run_directory("qemu-spawn-cwd")?;
        let expected_directory = run_directory.canonicalize()?;
        let current_exe = env::current_exe()?;
        let current_exe = current_exe.to_string_lossy().into_owned();
        let args = vec![
            String::from("--exact"),
            String::from("spawn::tests::qemu_spawn_run_directory_sets_child_cwd"),
        ];
        let mut child = spawn_process_with_resources(
            &current_exe,
            &args,
            Some(&run_directory),
            child_resources,
            &[
                (
                    CWD_PROBE_ENV,
                    expected_directory.as_os_str().to_string_lossy().as_ref(),
                ),
                (SOURCE_FDS_ENV, &source_fds),
            ],
            "spawn child cwd probe",
        )?;

        let status = child.wait()?;

        assert!(status.success());
        std::fs::remove_dir_all(run_directory)?;
        Ok(())
    }

    #[test]
    fn qemu_spawn_clears_inherited_environment_and_preserves_explicit_values()
    -> Result<(), Box<dyn Error>> {
        if env::var_os(ENV_CLEAR_CHILD_PROBE).is_some() {
            assert!(env::var_os(INHERITED_ENV_SENTINEL).is_none());
            assert!(env::var_os(ENV_CLEAR_PARENT_PROBE).is_none());
            assert_eq!(env::var(EXPLICIT_ENV_SENTINEL)?, "explicit-child-value");
            child_probe_fixed_fds()?;
            return Ok(());
        }
        if env::var_os(ENV_CLEAR_PARENT_PROBE).is_some() {
            assert_eq!(env::var(INHERITED_ENV_SENTINEL)?, "parent-only-value");
            let (_host, child_resources) = create_spawn_resources(4096)?;
            let source_fds = format!(
                "{},{},{}",
                child_resources.control_socket.as_raw_fd(),
                child_resources.shmem_fd.as_raw_fd(),
                child_resources.wake_fd.as_raw_fd()
            );
            let current_exe = env::current_exe()?;
            let current_exe = current_exe.to_string_lossy().into_owned();
            let args = vec![
                String::from("--exact"),
                String::from(
                    "spawn::tests::qemu_spawn_clears_inherited_environment_and_preserves_explicit_values",
                ),
            ];
            let mut child = spawn_process_with_resources(
                &current_exe,
                &args,
                None,
                child_resources,
                &[
                    (ENV_CLEAR_CHILD_PROBE, "1"),
                    (EXPLICIT_ENV_SENTINEL, "explicit-child-value"),
                    (SOURCE_FDS_ENV, &source_fds),
                ],
                "spawn child clean-environment probe",
            )?;

            assert!(child.wait()?.success());
            return Ok(());
        }

        let current_exe = env::current_exe()?;
        let mut parent = Command::new(current_exe)
            .args([
                "--exact",
                "spawn::tests::qemu_spawn_clears_inherited_environment_and_preserves_explicit_values",
            ])
            .env(ENV_CLEAR_PARENT_PROBE, "1")
            .env(INHERITED_ENV_SENTINEL, "parent-only-value")
            .spawn()?;

        assert!(parent.wait()?.success());
        Ok(())
    }

    #[test]
    fn qemu_spawn_kills_child_when_parent_exits() -> Result<(), Box<dyn Error>> {
        if env::var_os(PDEATH_CHILD_ENV).is_some() {
            std::thread::sleep(Duration::from_secs(60));
            return Ok(());
        }
        if env::var_os(PDEATH_PARENT_ENV).is_some() {
            parent_probe_spawn_pdeath_child()?;
            return Ok(());
        }

        let current_exe = env::current_exe()?;
        let output = Command::new(current_exe)
            .args([
                "--exact",
                "spawn::tests::qemu_spawn_kills_child_when_parent_exits",
                "--nocapture",
            ])
            .env(PDEATH_PARENT_ENV, "1")
            .stdout(Stdio::piped())
            .spawn()?
            .wait_with_output()?;

        assert!(output.status.success());
        let pid = parse_pdeath_child_pid(&output.stdout)?;
        assert_process_eventually_gone(pid, Duration::from_secs(2))?;
        Ok(())
    }

    #[test]
    fn qemu_node_child_drop_kills_and_reaps_unreaped_child() -> Result<(), Box<dyn Error>> {
        if env::var_os("CRUCIBLE_QEMU_SPAWN_SLEEP_PROBE").is_some() {
            std::thread::sleep(std::time::Duration::from_secs(60));
            return Ok(());
        }

        let current_exe = env::current_exe()?;
        let child = Command::new(current_exe)
            .args([
                "--exact",
                "spawn::tests::qemu_node_child_drop_kills_and_reaps_unreaped_child",
            ])
            .env("CRUCIBLE_QEMU_SPAWN_SLEEP_PROBE", "1")
            .spawn()?;
        let pid = child.id();
        drop(QemuNodeChild::new(child));

        assert_process_is_gone(pid)?;
        Ok(())
    }

    fn parent_probe_spawn_pdeath_child() -> Result<(), Box<dyn Error>> {
        let (_host, child_resources) = create_spawn_resources(4096)?;
        let current_exe = env::current_exe()?;
        let current_exe = current_exe.to_string_lossy().into_owned();
        let args = vec![
            String::from("--exact"),
            String::from("spawn::tests::qemu_spawn_kills_child_when_parent_exits"),
        ];
        let child = spawn_process_with_resources(
            &current_exe,
            &args,
            None,
            child_resources,
            &[(PDEATH_CHILD_ENV, "1")],
            "spawn parent-death probe child",
        )?;

        println!("{PDEATH_CHILD_PID_PREFIX}{}", child.id());
        let mut stdout = std::io::stdout();
        stdout.flush()?;
        Ok(())
    }

    fn child_probe_fixed_fds() -> Result<(), Box<dyn Error>> {
        assert_fd_open(QEMU_PLUGIN_CONTROL_FD)?;
        assert_fd_open(QEMU_PLUGIN_SHMEM_FD)?;
        assert_fd_open(QEMU_PLUGIN_WAKE_FD)?;
        assert_eq!(fd_size(QEMU_PLUGIN_SHMEM_FD)?, 4096);
        for fd in source_fds_from_env()? {
            assert_fd_closed(fd)?;
        }
        Ok(())
    }

    fn child_probe_cwd(expected: &Path) -> Result<(), Box<dyn Error>> {
        let actual = std::env::current_dir()?.canonicalize()?;
        assert_eq!(actual, expected);
        child_probe_fixed_fds()
    }

    fn unique_temp_run_directory(prefix: &str) -> Result<PathBuf, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            unique_temp_suffix()
        ));
        std::fs::create_dir(&path)?;
        Ok(path)
    }

    fn unique_temp_suffix() -> u64 {
        TEMP_DIR_SUFFIX.fetch_add(1, Ordering::Relaxed)
    }

    fn assert_fd_open(fd: RawFd) -> Result<(), Box<dyn Error>> {
        let result = unsafe {
            // SAFETY: `fcntl` validates the descriptor number.
            libc::fcntl(fd, libc::F_GETFD)
        };
        if result < 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn assert_fd_closed(fd: RawFd) -> Result<(), Box<dyn Error>> {
        let result = unsafe {
            // SAFETY: `fcntl` validates the descriptor number.
            libc::fcntl(fd, libc::F_GETFD)
        };
        if result >= 0 {
            return Err(format!("source fd {fd} survived exec").into());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBADF) {
            Ok(())
        } else {
            Err(Box::new(error))
        }
    }

    fn parse_pdeath_child_pid(stdout: &[u8]) -> Result<u32, Box<dyn Error>> {
        let text = String::from_utf8(stdout.to_vec())?;
        for line in text.lines() {
            if let Some(pid) = line.strip_prefix(PDEATH_CHILD_PID_PREFIX) {
                return Ok(pid.parse()?);
            }
        }
        Err(format!("parent-death child pid marker missing in output: {text}").into())
    }

    // crucible-lint: allow clippy-disallowed-method -- test polling observes OS process cleanup only.
    #[allow(clippy::disallowed_methods)]
    fn assert_process_eventually_gone(pid: u32, timeout: Duration) -> Result<(), Box<dyn Error>> {
        // Test-only host wait: this polls for OS process cleanup and never
        // feeds Crucible scenario state, scheduling, or fingerprint material.
        let deadline = Instant::now() + timeout;
        loop {
            match assert_process_is_gone(pid) {
                Ok(()) => return Ok(()),
                Err(error) if Instant::now() < deadline => {
                    drop(error);
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn fd_size(fd: RawFd) -> Result<i64, Box<dyn Error>> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            // SAFETY: `stat` points to writable storage for `fstat`.
            libc::fstat(fd, stat.as_mut_ptr())
        };
        if result != 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }
        let stat = unsafe {
            // SAFETY: successful `fstat` initialized `stat`.
            stat.assume_init()
        };
        Ok(stat.st_size)
    }

    fn fd_seals(fd: RawFd) -> Result<i32, Box<dyn Error>> {
        let seals = unsafe {
            // SAFETY: `fcntl(F_GET_SEALS)` reads metadata from the live test fd.
            libc::fcntl(fd, libc::F_GET_SEALS)
        };
        if seals < 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }
        Ok(seals)
    }

    fn assert_process_is_gone(pid: u32) -> Result<(), Box<dyn Error>> {
        let pid = libc::pid_t::try_from(pid)?;
        let result = unsafe {
            // SAFETY: `kill(pid, 0)` only probes process existence.
            libc::kill(pid, 0)
        };
        if result == 0 {
            return Err("child process still exists after QemuNodeChild drop".into());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(Box::new(error))
        }
    }

    fn source_fds_from_env() -> Result<Vec<RawFd>, Box<dyn Error>> {
        let raw = env::var(SOURCE_FDS_ENV)?;
        raw.split(',')
            .map(|part| part.parse::<RawFd>().map_err(Into::into))
            .collect()
    }
}
