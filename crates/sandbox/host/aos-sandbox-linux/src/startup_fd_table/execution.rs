//! Pidfd, cgroup, executable, and launcher capture for startup authority.

use std::ffi::CString;
use std::fs::File;
use std::io::Read as _;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use crate::boot::KernelBootId;
use crate::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use crate::immutable_file::is_kernel_verity_filesystem;
use crate::pidfd::PidFd;
use crate::uapi::{self, OpenHow, RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS};
use crate::{Error, Result};

use super::model::{
    PendingProcessObservationV2, PendingStartupProcessV2, RetainedStartupProcessV1,
    StartupExecutableObservationV1, StartupKernelProcessObservationV2, StartupProcessObservationV1,
    build_identity,
};

const MAXIMUM_CGROUP_RECORD_BYTES: usize = 4_096;
const ELF_HEADER_BYTES: usize = 64;
const ELF_PROGRAM_HEADER_BYTES: usize = 56;
const MAXIMUM_PROGRAM_HEADERS: usize = 128;
const MAXIMUM_NOTE_BYTES: usize = 64 * 1_024;
const PT_NOTE: u32 = 4;
const NT_GNU_BUILD_ID: u32 = 3;
const MAXIMUM_EXECUTABLE_PATH_BYTES: usize = 4096;
const SELINUX_CONTEXT_BYTES: usize = 256;

/// Observes one operator-provisioned startup executable without authorizing its later execution.
///
/// The absolute path is walked beneath `/` without symlinks. Every ancestor
/// must be root-owned and not group- or world-writable. The exact file must be
/// root-owned, single-linked, executable, non-writable, and carry the supplied
/// SELinux context on an admitted kernel fs-verity filesystem mounted read-only
/// and executable. The observation includes the kernel SHA-256 fs-verity
/// measurement and GNU build ID, and the name is reopened before return.
///
/// A later launcher must independently pin and execute this same inode. This
/// preflight observation does not grant a pathname-based handoff capability.
///
/// # Errors
///
/// Returns an error for unsafe path ancestry, inode ownership or mode, an
/// unsuitable mount, missing SELinux enforcement or label, absent fs-verity or
/// build ID, or a changed name or inode during observation.
pub fn observe_provisioned_startup_executable(
    path: &Path,
    expected_context: &str,
) -> Result<StartupExecutableObservationV1> {
    require_selinux_enforcing()?;

    let first = open_provisioned_executable(path)?;
    let observation = inspect_provisioned_executable(&first, expected_context)?;
    let reopened = open_provisioned_executable(path)?;
    if inspect_provisioned_executable(&reopened, expected_context)? != observation {
        return Err(Error::invalid(
            "startup executable carrier",
            "path changed during executable observation",
        ));
    }
    Ok(observation)
}

fn require_selinux_enforcing() -> Result<()> {
    let status_file = File::open("/sys/fs/selinux/enforce").map_err(|source| Error::Syscall {
        operation: "open SELinux enforcing status",
        source,
    })?;
    let mut status = Vec::new();
    status_file
        .take(3)
        .read_to_end(&mut status)
        .map_err(|source| Error::Syscall {
            operation: "read SELinux enforcing status",
            source,
        })?;
    if !selinux_is_enforcing(&status) {
        return Err(Error::invalid(
            "startup executable carrier",
            "SELinux is not enforcing",
        ));
    }
    Ok(())
}

fn selinux_is_enforcing(status: &[u8]) -> bool {
    status == b"1" || status == b"1\n"
}

fn open_provisioned_executable(path: &Path) -> Result<OwnedFd> {
    let components = canonical_executable_path_components(path)?;

    let mut directory: OwnedFd = File::open("/")
        .map_err(|source| Error::Syscall {
            operation: "open startup carrier path root",
            source,
        })?
        .into();
    inspect_protected_ancestor(&directory)?;
    for component in &components[..components.len() - 1] {
        let component = CString::new(*component)
            .map_err(|_| Error::invalid("startup executable carrier", "path contains NUL"))?;
        directory = uapi::openat2(
            directory.as_fd(),
            &component,
            &OpenHow {
                flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                    as u64,
                mode: 0,
                resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
            },
        )?;
        inspect_protected_ancestor(&directory)?;
    }

    let name = CString::new(components[components.len() - 1])
        .map_err(|_| Error::invalid("startup executable carrier", "path contains NUL"))?;
    uapi::openat2(
        directory.as_fd(),
        &name,
        &OpenHow {
            flags: (libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_NOCTTY) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        },
    )
}

fn canonical_executable_path_components(path: &Path) -> Result<Vec<&[u8]>> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() < 2 || bytes.len() >= MAXIMUM_EXECUTABLE_PATH_BYTES || bytes[0] != b'/' {
        return Err(Error::invalid(
            "startup executable carrier",
            "path is not a bounded absolute path",
        ));
    }
    let components = bytes[1..].split(|byte| *byte == b'/').collect::<Vec<_>>();
    if components.iter().any(|component| {
        component.is_empty() || *component == b"." || *component == b".." || component.contains(&0)
    }) {
        return Err(Error::invalid(
            "startup executable carrier",
            "path has a noncanonical component",
        ));
    }

    Ok(components)
}

fn inspect_protected_ancestor(directory: &OwnedFd) -> Result<()> {
    let stat = rustix::fs::fstat(directory).map_err(|source| Error::Syscall {
        operation: "fstat startup carrier ancestor",
        source: source.into(),
    })?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(Error::invalid(
            "startup executable carrier",
            "path ancestry is not root-owned and protected",
        ));
    }
    Ok(())
}

fn inspect_provisioned_executable(
    executable: &OwnedFd,
    expected_context: &str,
) -> Result<StartupExecutableObservationV1> {
    let before = rustix::fs::fstat(executable).map_err(|source| Error::Syscall {
        operation: "fstat startup carrier executable",
        source: source.into(),
    })?;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o7000 != 0
        || before.st_mode & 0o100 == 0
        || before.st_mode & 0o222 != 0
    {
        return Err(Error::invalid(
            "startup executable carrier",
            "inode is not a protected root-owned executable",
        ));
    }
    if !is_kernel_verity_filesystem(uapi::filesystem_type(executable.as_fd())?) {
        return Err(Error::invalid(
            "startup executable carrier",
            "filesystem does not implement admitted fs-verity",
        ));
    }
    let mount = rustix::fs::fstatvfs(executable).map_err(|source| Error::Syscall {
        operation: "fstatvfs startup carrier executable",
        source: source.into(),
    })?;
    if !mount.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY)
        || mount.f_flag.contains(rustix::fs::StatVfsMountFlags::NOEXEC)
    {
        return Err(Error::invalid(
            "startup executable carrier",
            "carrier mount is writable or noexec",
        ));
    }

    let mut context = [0_u8; SELINUX_CONTEXT_BYTES];
    let length = rustix::fs::fgetxattr(executable, "security.selinux", &mut context[..]).map_err(
        |source| Error::Syscall {
            operation: "read startup carrier SELinux context",
            source: source.into(),
        },
    )?;
    let expected = expected_context.as_bytes();
    if !selinux_context_matches(&context[..length], expected) {
        return Err(Error::invalid(
            "startup executable carrier",
            "inode has the wrong SELinux context",
        ));
    }

    let observed = observe_executable(executable)?;
    let after = rustix::fs::fstat(executable).map_err(|source| Error::Syscall {
        operation: "recheck startup carrier executable",
        source: source.into(),
    })?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid
        || before.st_gid != after.st_gid
        || before.st_nlink != after.st_nlink
        || before.st_size != after.st_size
    {
        return Err(Error::invalid(
            "startup executable carrier",
            "inode changed during observation",
        ));
    }
    Ok(observed)
}

fn selinux_context_matches(observed: &[u8], expected: &[u8]) -> bool {
    !expected.is_empty()
        && expected.len() < SELINUX_CONTEXT_BYTES
        && (observed == expected
            || (observed.len() == expected.len() + 1
                && observed.starts_with(expected)
                && observed.last() == Some(&0)))
}

pub(super) fn capture_current_and_launcher(
    boot_id: [u8; 16],
) -> Result<(RetainedStartupProcessV1, RetainedStartupProcessV1)> {
    let current_pid = NonZeroU32::new(std::process::id())
        .ok_or_else(|| Error::invalid("startup execution", "current PID is zero"))?;
    let execution = capture_process(current_pid, boot_id)?;
    let launcher_pid =
        NonZeroU32::new(execution.observation.process.parent_pid()).ok_or_else(|| {
            Error::invalid("startup launcher", "current process has no direct parent")
        })?;
    let launcher = capture_process(launcher_pid, boot_id)?;
    require_process_relationship(execution.observation.process, launcher.observation.process)?;
    Ok((execution, launcher))
}

pub(super) fn capture_selected_current_and_launcher(
    execution: &mut PendingStartupProcessV2,
    launcher: &mut PendingStartupProcessV2,
    boot_id: [u8; 16],
) -> Result<()> {
    let current_pid = NonZeroU32::new(std::process::id())
        .ok_or_else(|| Error::invalid("startup execution", "current PID is zero"))?;
    capture_selected_process(execution, current_pid, boot_id, SelectedProcessImageV2::CurrentExecution)?;
    let execution_observation = execution.execution().ok_or_else(|| {
        Error::invalid("startup execution", "selected self capture is absent")
    })?;
    let launcher_pid = NonZeroU32::new(execution_observation.process.parent_pid()).ok_or_else(|| {
        Error::invalid("startup launcher", "current process has no direct parent")
    })?;
    capture_selected_process(launcher, launcher_pid, boot_id, SelectedProcessImageV2::DirectParentKernelOnly)?;
    let launcher_observation = launcher.kernel().ok_or_else(|| {
        Error::invalid("startup launcher", "selected parent capture is absent")
    })?;
    require_process_relationship(execution_observation.process, launcher_observation.process)
}

fn require_process_relationship(
    execution: crate::pidfd::PidFdProcessIdentity,
    launcher: crate::pidfd::PidFdProcessIdentity,
) -> Result<()> {
    if execution.parent_pid() != launcher.pid()
        || execution.pid() != execution.thread_group_id()
        || launcher.pid() != launcher.thread_group_id()
    {
        return Err(Error::invalid(
            "startup launcher",
            "process/launcher relationship is not exact",
        ));
    }
    Ok(())
}

pub(super) fn revalidate_process(process: &RetainedStartupProcessV1) -> Result<()> {
    revalidate_process_recipe(
        &process.pidfd,
        &process.cgroup,
        Some(&process.executable),
        process.observation.kernel_boot_id,
        process.observation.process,
        process.observation.credentials,
        process.observation.cgroup_id,
        Some(process.observation.executable),
        ProcessImageChecks::Legacy,
    )
}

pub(super) fn revalidate_selected_process(process: &mut PendingStartupProcessV2) -> Result<()> {
    let (boot, identity, credentials, cgroup_id, executable_observation) =
        match process.observation.as_ref() {
            Some(PendingProcessObservationV2::Execution(observation)) => (
                observation.kernel_boot_id, observation.process, observation.credentials,
                observation.cgroup_id, Some(observation.executable),
            ),
            Some(PendingProcessObservationV2::Kernel(observation)) => (
                observation.kernel_boot_id, observation.process, observation.credentials,
                observation.cgroup_id, None,
            ),
            None => return Err(Error::invalid("startup execution", "selected capture is incomplete")),
        };
    let pidfd = process.pidfd.as_ref().ok_or_else(|| {
        Error::invalid("startup execution", "selected pidfd is absent")
    })?;
    let cgroup = process.cgroup.as_ref().ok_or_else(|| {
        Error::invalid("startup execution", "selected cgroup is absent")
    })?;
    if process.executable.is_some() != executable_observation.is_some() {
        return Err(Error::invalid("startup execution", "selected image disposition changed"));
    }

    // These are scratch/current-path owners from the previous successful
    // observation. The admitted original executable, pidfd and cgroup stay
    // resident. This bounded positive cleanup is not a drain assertion.
    process.executable_scratch = None;
    process.current_executable_scratch = None;
    process.current_executable = None;
    revalidate_process_recipe(
        pidfd, cgroup, process.executable.as_ref(), boot, identity, credentials,
        cgroup_id, executable_observation,
        ProcessImageChecks::Selected {
            executable_scratch: &mut process.executable_scratch,
            current_executable: &mut process.current_executable,
            current_scratch: &mut process.current_executable_scratch,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn revalidate_process_recipe(
    pidfd: &PidFd,
    cgroup: &RetainedCgroupAnchor,
    executable: Option<&OwnedFd>,
    expected_boot: [u8; 16],
    expected_identity: crate::pidfd::PidFdProcessIdentity,
    expected_credentials: crate::pidfd::PidFdCredentials,
    expected_cgroup: u64,
    expected_executable: Option<StartupExecutableObservationV1>,
    mut image_checks: ProcessImageChecks<'_>,
) -> Result<()> {
    let before_boot = KernelBootId::current()?.into_bytes();
    let identity = pidfd.process_identity()?;
    let info = cgroup.verify_exact_membership(pidfd)?;
    let retained_executable = executable.map(|image| image_checks.retained(image)).transpose()?;
    let current_executable = if executable.is_some() {
        Some(image_checks.current(identity.pid())?)
    } else {
        None
    };
    let after_boot = KernelBootId::current()?.into_bytes();
    if before_boot != expected_boot
        || after_boot != expected_boot
        || identity != expected_identity
        || info.credentials() != Some(expected_credentials)
        || info.cgroup_id() != Some(expected_cgroup)
        || cgroup.kernel_id() != expected_cgroup
        || retained_executable != expected_executable
        || current_executable != expected_executable
        || !pidfd.is_alive()?
    {
        return Err(Error::invalid(
            "startup execution",
            "retained process identity changed",
        ));
    }
    cgroup.validate_current()
}

fn capture_process(pid: NonZeroU32, boot_id: [u8; 16]) -> Result<RetainedStartupProcessV1> {
    capture_process_recipe(pid, boot_id, ProcessCaptureDestination::Legacy)?
        .ok_or_else(|| Error::invalid("startup execution", "legacy capture omitted its owner"))
}

pub(super) fn capture_selected_process(
    process: &mut PendingStartupProcessV2,
    pid: NonZeroU32,
    boot_id: [u8; 16],
    image: SelectedProcessImageV2,
) -> Result<()> {
    capture_process_recipe(pid, boot_id, ProcessCaptureDestination::Selected(process, image))?;
    Ok(())
}

pub(super) enum SelectedProcessImageV2 {
    CurrentExecution,
    DirectParentKernelOnly,
}

enum ProcessCaptureDestination<'owner> {
    Legacy,
    Selected(&'owner mut PendingStartupProcessV2, SelectedProcessImageV2),
}

enum ProcessImageChecks<'owner> {
    Legacy,
    Selected {
        executable_scratch: &'owner mut Option<File>,
        current_executable: &'owner mut Option<OwnedFd>,
        current_scratch: &'owner mut Option<File>,
    },
}

impl ProcessImageChecks<'_> {
    fn retained(&mut self, image: &OwnedFd) -> Result<StartupExecutableObservationV1> {
        match self {
            Self::Legacy => observe_executable(image),
            Self::Selected { executable_scratch, .. } => {
                measure_retained_image(image.as_fd(), executable_scratch)
            }
        }
    }

    fn current(&mut self, pid: u32) -> Result<StartupExecutableObservationV1> {
        match self {
            Self::Legacy => observe_current_executable(pid),
            Self::Selected { current_executable, current_scratch, .. } => {
                **current_executable = Some(open_process_executable(pid)?);
                let image = current_executable.as_ref().ok_or_else(|| {
                    Error::invalid("startup execution", "current executable is absent")
                })?;
                measure_retained_image(image.as_fd(), current_scratch)
            }
        }
    }
}

// Each local occupies its old lexical interval in Legacy. Selected instead
// parks the same returned original in its outer owner before the next check.
// This private adapter neither validates a process nor constructs authority.
pub(super) struct ReturnedProcessSlot<'owner, T> {
    local: Option<T>,
    resident: Option<&'owner mut Option<T>>,
}

impl<'owner, T> ReturnedProcessSlot<'owner, T> {
    pub(super) fn park(original: T, resident: Option<&'owner mut Option<T>>) -> Self {
        match resident {
            Some(destination) => {
                // The closed recipe checked every destination before its first
                // syscall, and the exclusive borrow prevents slot mutation.
                *destination = Some(original);
                Self { local: None, resident: Some(destination) }
            }
            None => Self { local: Some(original), resident: None },
        }
    }

    pub(super) fn original(&self) -> Result<&T> {
        self.resident.as_ref().and_then(|slot| slot.as_ref())
            .or(self.local.as_ref())
            .ok_or_else(|| Error::invalid("startup execution", "original process slot is absent"))
    }

    pub(super) fn original_mut(&mut self) -> Result<&mut T> {
        match self.resident.as_mut() {
            Some(slot) => slot.as_mut(),
            None => self.local.as_mut(),
        }.ok_or_else(|| Error::invalid("startup capture", "returned original slot is absent"))
    }

    pub(super) fn into_local(mut self) -> Result<T> {
        self.local.take().ok_or_else(|| {
            Error::invalid("startup execution", "legacy process slot is absent")
        })
    }

    pub(super) fn take_after_checks(mut self) -> Option<T> {
        match self.resident.as_mut() {
            Some(slot) => slot.take(),
            None => self.local.take(),
        }
    }
}

fn capture_process_recipe(
    pid: NonZeroU32,
    boot_id: [u8; 16],
    destination: ProcessCaptureDestination<'_>,
) -> Result<Option<RetainedStartupProcessV1>> {
    let (pidfd_destination, cgroup_destination, executable_destination, observation_destination,
        capture_image, mut image_checks) = match destination {
        ProcessCaptureDestination::Legacy => (None, None, None, None, true, ProcessImageChecks::Legacy),
        ProcessCaptureDestination::Selected(process, image) => {
            if process.pidfd.is_some() || process.cgroup.is_some()
                || process.executable.is_some() || process.observation.is_some()
                || process.executable_scratch.is_some() || process.current_executable.is_some()
                || process.current_executable_scratch.is_some()
            {
                return Err(Error::invalid("startup execution", "selected process already attempted"));
            }
            (Some(&mut process.pidfd), Some(&mut process.cgroup), Some(&mut process.executable),
                Some(&mut process.observation), matches!(image, SelectedProcessImageV2::CurrentExecution),
                ProcessImageChecks::Selected {
                    executable_scratch: &mut process.executable_scratch,
                    current_executable: &mut process.current_executable,
                    current_scratch: &mut process.current_executable_scratch,
                })
        }
    };

    let pidfd_owner = ReturnedProcessSlot::park(PidFd::open(pid)?, pidfd_destination);
    let pidfd = pidfd_owner.original()?;
    let before_identity = pidfd.process_identity()?;
    let before_info = pidfd.info()?;
    let credentials = before_info
        .credentials()
        .ok_or_else(|| Error::invalid("startup execution", "pidfd omitted credentials"))?;
    let cgroup_id = before_info
        .cgroup_id()
        .ok_or_else(|| Error::invalid("startup execution", "pidfd omitted cgroup ID"))?;
    let cgroup_path = read_cgroup_path(pid.get())?;
    let unit = cgroup_unit(&cgroup_path)?;
    let cgroup_owner = ReturnedProcessSlot::park(open_exact_cgroup(&cgroup_path)?, cgroup_destination);
    let cgroup = cgroup_owner.original()?;
    cgroup.verify_exact_membership(&pidfd)?;
    if cgroup.kernel_id() != cgroup_id {
        return Err(Error::invalid(
            "startup execution",
            "procfs cgroup path differs from pidfd cgroup ID",
        ));
    }

    let executable_owner = if capture_image {
        Some(ReturnedProcessSlot::park(open_process_executable(pid.get())?, executable_destination))
    } else {
        None
    };
    let executable_observation = executable_owner.as_ref()
        .map(|owner| image_checks.retained(owner.original()?)).transpose()?;
    cgroup.verify_exact_membership(&pidfd)?;
    let after_identity = pidfd.process_identity()?;
    let after_info = pidfd.info()?;
    let current_executable = if capture_image {
        Some(image_checks.current(pid.get())?)
    } else {
        None
    };
    let final_boot = KernelBootId::current()?.into_bytes();
    if before_identity != after_identity
        || before_info != after_info
        || before_identity.pid() != pid.get()
        || before_identity.thread_group_id() != pid.get()
        || current_executable != executable_observation
        || final_boot != boot_id
        || !pidfd.is_alive()?
    {
        return Err(Error::invalid(
            "startup execution",
            "process changed during identity capture",
        ));
    }

    let observation = match executable_observation {
        Some(executable) => PendingProcessObservationV2::Execution(StartupProcessObservationV1 {
            kernel_boot_id: boot_id,
            process: after_identity,
            credentials,
            cgroup_id,
            cgroup_path,
            unit,
            executable,
        }),
        None => PendingProcessObservationV2::Kernel(StartupKernelProcessObservationV2 {
            kernel_boot_id: boot_id,
            process: after_identity,
            credentials,
            cgroup_id,
            cgroup_path,
            unit,
        }),
    };
    if let Some(destination) = observation_destination {
        *destination = Some(observation);
        return Ok(None);
    }

    let PendingProcessObservationV2::Execution(observation) = observation else {
        return Err(Error::invalid("startup execution", "legacy execution image is absent"));
    };
    let executable_owner = executable_owner.ok_or_else(|| {
        Error::invalid("startup execution", "legacy executable owner is absent")
    })?;
    Ok(Some(RetainedStartupProcessV1 {
        pidfd: pidfd_owner.into_local()?,
        cgroup: cgroup_owner.into_local()?,
        executable: executable_owner.into_local()?,
        observation,
    }))
}

fn read_cgroup_path(pid: u32) -> Result<String> {
    let path = format!("/proc/{pid}/cgroup");
    let file = File::open(path).map_err(|source| Error::Syscall {
        operation: "open /proc/PID/cgroup",
        source,
    })?;
    let mut bytes = Vec::new();
    file.take((MAXIMUM_CGROUP_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| Error::Syscall {
            operation: "read /proc/PID/cgroup",
            source,
        })?;
    if bytes.len() > MAXIMUM_CGROUP_RECORD_BYTES {
        return Err(Error::invalid(
            "startup cgroup",
            "procfs cgroup record exceeds its fixed bound",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::invalid("startup cgroup", "record is not UTF-8"))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.contains('\n') || !text.starts_with("0::/") {
        return Err(Error::invalid(
            "startup cgroup",
            "record is not one canonical cgroup-v2 membership",
        ));
    }
    let cgroup_path = text
        .strip_prefix("0::")
        .ok_or_else(|| Error::invalid("startup cgroup", "record prefix changed"))?;
    if cgroup_path.len() <= 1
        || cgroup_path.len() > 1_024
        || cgroup_path.split('/').any(|part| part == "..")
    {
        return Err(Error::invalid(
            "startup cgroup",
            "cgroup path is outside the closed profile",
        ));
    }
    Ok(cgroup_path.to_owned())
}

fn cgroup_unit(path: &str) -> Result<String> {
    let unit = path
        .rsplit('/')
        .next()
        .filter(|unit| !unit.is_empty() && unit.len() <= 255)
        .ok_or_else(|| Error::invalid("startup cgroup", "unit component is absent"))?;
    if unit
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
    {
        return Err(Error::invalid(
            "startup cgroup",
            "unit component is noncanonical",
        ));
    }
    Ok(unit.to_owned())
}

fn open_exact_cgroup(path: &str) -> Result<RetainedCgroupAnchor> {
    let root: OwnedFd = File::open("/sys/fs/cgroup")
        .map_err(|source| Error::Syscall {
            operation: "open cgroup-v2 root",
            source,
        })?
        .into();
    let root = CgroupV2Root::from_owned(root)?;
    let relative = path
        .strip_prefix('/')
        .ok_or_else(|| Error::invalid("startup cgroup", "path is not absolute"))?;
    root.resolve(Path::new(relative))
}

fn open_process_executable(pid: u32) -> Result<OwnedFd> {
    rustix::fs::open(
        format!("/proc/{pid}/exe"),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| Error::Syscall {
        operation: "open /proc/PID/exe",
        source: source.into(),
    })
}

fn observe_current_executable(pid: u32) -> Result<StartupExecutableObservationV1> {
    let executable = open_process_executable(pid)?;
    observe_executable(&executable)
}

fn observe_executable(executable: &OwnedFd) -> Result<StartupExecutableObservationV1> {
    observe_image(executable.as_fd(), ImageBuildSource::Legacy(executable))
}

pub(super) fn measure_retained_image(
    image: BorrowedFd<'_>,
    scratch: &mut Option<File>,
) -> Result<StartupExecutableObservationV1> {
    observe_image(image, ImageBuildSource::Retained(scratch))
}

enum ImageBuildSource<'owner> {
    Legacy(&'owner OwnedFd),
    Retained(&'owner mut Option<File>),
}

fn observe_image(
    executable: BorrowedFd<'_>,
    build_source: ImageBuildSource<'_>,
) -> Result<StartupExecutableObservationV1> {
    let before = rustix::fs::fstat(executable).map_err(|source| Error::Syscall {
        operation: "fstat startup executable",
        source: source.into(),
    })?;
    let measurement = uapi::measure_verity(executable)?;
    if measurement.algorithm != 1 || measurement.length != 32 {
        return Err(Error::invalid(
            "startup executable",
            "executable lacks the required SHA-256 fs-verity profile",
        ));
    }
    let build_identity = match build_source {
        ImageBuildSource::Legacy(original) => read_gnu_build_id(original)?,
        ImageBuildSource::Retained(scratch) => {
            if scratch.is_some() {
                return Err(Error::invalid(
                    "startup image measurement",
                    "scratch descriptor is already occupied",
                ));
            }
            let duplicate = executable.try_clone_to_owned().map_err(|source| Error::Syscall {
                operation: "duplicate startup executable",
                source,
            })?;
            *scratch = Some(File::from(duplicate));
            let file = scratch.as_ref().ok_or_else(|| {
                Error::invalid("startup image measurement", "scratch descriptor is absent")
            })?;
            read_gnu_build_id_file(file)?
        }
    };
    let after = rustix::fs::fstat(executable).map_err(|source| Error::Syscall {
        operation: "fstat startup executable",
        source: source.into(),
    })?;
    if before.st_dev == 0
        || before.st_ino == 0
        || before.st_size <= 0
        || before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mode != after.st_mode
    {
        return Err(Error::invalid(
            "startup executable",
            "executable identity changed or is not one regular file",
        ));
    }
    let mut fs_verity_sha256 = [0; 32];
    fs_verity_sha256.copy_from_slice(&measurement.digest[..32]);
    Ok(StartupExecutableObservationV1 {
        device: before.st_dev,
        inode: before.st_ino,
        size: u64::try_from(before.st_size)
            .map_err(|_| Error::invalid("startup executable", "size is negative"))?,
        mode: before.st_mode,
        fs_verity_sha256,
        build_identity,
    })
}

fn read_gnu_build_id(executable: &OwnedFd) -> Result<super::ExecutableBuildIdentityV1> {
    let file = File::from(executable.try_clone().map_err(|source| Error::Syscall {
        operation: "duplicate startup executable",
        source,
    })?);
    read_gnu_build_id_file(&file)
}

fn read_gnu_build_id_file(file: &File) -> Result<super::ExecutableBuildIdentityV1> {
    let mut header = [0; ELF_HEADER_BYTES];
    read_exact_at(file, &mut header, 0)?;
    if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 {
        return Err(Error::invalid(
            "startup executable",
            "executable is not canonical ELF64 little-endian",
        ));
    }
    let program_offset = u64::from_le_bytes(
        header[32..40]
            .try_into()
            .map_err(|_| Error::invalid("startup executable", "ELF header is truncated"))?,
    );
    let entry_size =
        usize::from(u16::from_le_bytes(header[54..56].try_into().map_err(
            |_| Error::invalid("startup executable", "ELF header is truncated"),
        )?));
    let entry_count =
        usize::from(u16::from_le_bytes(header[56..58].try_into().map_err(
            |_| Error::invalid("startup executable", "ELF header is truncated"),
        )?));
    if entry_size != ELF_PROGRAM_HEADER_BYTES
        || entry_count == 0
        || entry_count > MAXIMUM_PROGRAM_HEADERS
    {
        return Err(Error::invalid(
            "startup executable",
            "ELF program-header table is outside the closed profile",
        ));
    }

    let mut found = None;
    for index in 0..entry_count {
        let offset = program_offset
            .checked_add((index * entry_size) as u64)
            .ok_or_else(|| Error::invalid("startup executable", "program header overflows"))?;
        let mut program = [0; ELF_PROGRAM_HEADER_BYTES];
        read_exact_at(file, &mut program, offset)?;
        let kind = u32::from_le_bytes(
            program[..4]
                .try_into()
                .map_err(|_| Error::invalid("startup executable", "program header is invalid"))?,
        );
        if kind != PT_NOTE {
            continue;
        }
        let note_offset = u64::from_le_bytes(
            program[8..16]
                .try_into()
                .map_err(|_| Error::invalid("startup executable", "program header is invalid"))?,
        );
        let note_size =
            usize::try_from(u64::from_le_bytes(program[32..40].try_into().map_err(
                |_| Error::invalid("startup executable", "program header is invalid"),
            )?))
            .map_err(|_| Error::invalid("startup executable", "note size overflows"))?;
        if note_size == 0 || note_size > MAXIMUM_NOTE_BYTES {
            return Err(Error::invalid(
                "startup executable",
                "ELF note segment exceeds its fixed bound",
            ));
        }
        let mut notes = vec![0; note_size];
        read_exact_at(file, &mut notes, note_offset)?;
        for build_id in gnu_build_ids(&notes)? {
            if found.replace(build_id).is_some() {
                return Err(Error::invalid(
                    "startup executable",
                    "executable contains multiple GNU build IDs",
                ));
            }
        }
    }
    found.ok_or_else(|| Error::invalid("startup executable", "executable omits a GNU build ID"))
}

fn gnu_build_ids(notes: &[u8]) -> Result<Vec<super::ExecutableBuildIdentityV1>> {
    let mut found = Vec::new();
    let mut offset = 0usize;
    while offset < notes.len() {
        if notes[offset..].iter().all(|byte| *byte == 0) {
            break;
        }
        let header_end = offset
            .checked_add(12)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note overflows"))?;
        let header = notes
            .get(offset..header_end)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note is truncated"))?;
        let name_size =
            usize::try_from(u32::from_le_bytes(header[..4].try_into().map_err(
                |_| Error::invalid("startup executable", "ELF note is invalid"),
            )?))
            .map_err(|_| Error::invalid("startup executable", "note name length overflows"))?;
        let value_size =
            usize::try_from(u32::from_le_bytes(header[4..8].try_into().map_err(
                |_| Error::invalid("startup executable", "ELF note is invalid"),
            )?))
            .map_err(|_| Error::invalid("startup executable", "note value length overflows"))?;
        let note_type = u32::from_le_bytes(
            header[8..12]
                .try_into()
                .map_err(|_| Error::invalid("startup executable", "ELF note is invalid"))?,
        );
        let name_end = header_end
            .checked_add(name_size)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note overflows"))?;
        let value_start = align4(name_end)?;
        let value_end = value_start
            .checked_add(value_size)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note overflows"))?;
        let next = align4(value_end)?;
        let name = notes
            .get(header_end..name_end)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note name is truncated"))?;
        let value = notes
            .get(value_start..value_end)
            .ok_or_else(|| Error::invalid("startup executable", "ELF note value is truncated"))?;
        if note_type == NT_GNU_BUILD_ID && name == b"GNU\0" {
            found.push(build_identity(value)?);
        }
        if next <= offset {
            return Err(Error::invalid(
                "startup executable",
                "ELF note does not advance",
            ));
        }
        offset = next;
    }
    Ok(found)
}

fn align4(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .map(|aligned| aligned & !3)
        .ok_or_else(|| Error::invalid("startup executable", "ELF note alignment overflows"))
}

fn read_exact_at(file: &File, mut output: &mut [u8], mut offset: u64) -> Result<()> {
    while !output.is_empty() {
        let read = file
            .read_at(output, offset)
            .map_err(|source| Error::Syscall {
                operation: "pread startup executable",
                source,
            })?;
        if read == 0 {
            return Err(Error::invalid(
                "startup executable",
                "executable is truncated",
            ));
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| Error::invalid("startup executable", "read offset overflows"))?;
        output = &mut output[read..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn carrier_path_requires_canonical_absolute_components() {
        let components =
            canonical_executable_path_components(Path::new("/aos/carrier/mountd")).unwrap();
        assert_eq!(components, [b"aos".as_slice(), b"carrier", b"mountd"]);

        for invalid in [
            "",
            "/",
            "relative/file",
            "/aos//mountd",
            "/aos/./mountd",
            "/aos/../mountd",
            "/aos/mountd/",
        ] {
            assert!(canonical_executable_path_components(Path::new(invalid)).is_err());
        }
        assert!(
            canonical_executable_path_components(Path::new(OsStr::from_bytes(b"/aos/mou\0ntd")))
                .is_err()
        );
        let overlong = format!("/{}", "a".repeat(MAXIMUM_EXECUTABLE_PATH_BYTES - 1));
        assert!(canonical_executable_path_components(Path::new(&overlong)).is_err());
    }

    #[test]
    fn carrier_preflight_accepts_only_enforcing_selinux_status() {
        assert!(selinux_is_enforcing(b"1"));
        assert!(selinux_is_enforcing(b"1\n"));
        for invalid in [b"0".as_slice(), b"0\n", b"1\n0", b"", b"1 "] {
            assert!(!selinux_is_enforcing(invalid));
        }
    }

    #[test]
    fn carrier_preflight_requires_exact_selinux_context() {
        let expected = b"system_u:object_r:init_exec_t";
        assert!(selinux_context_matches(expected, expected));
        assert!(selinux_context_matches(
            b"system_u:object_r:init_exec_t\0",
            expected
        ));
        for invalid in [
            b"system_u:object_r:bin_t".as_slice(),
            b"system_u:object_r:init_exec_t:s0",
            b"system_u:object_r:init_exec_t\0x",
        ] {
            assert!(!selinux_context_matches(invalid, expected));
        }
        assert!(!selinux_context_matches(b"", b""));
    }

    #[test]
    fn carrier_ancestor_and_inode_reject_mutable_permissions() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let directory: OwnedFd = File::open(temporary.path()).unwrap().into();
        assert!(inspect_protected_ancestor(&directory).is_err());

        let executable = tempfile::tempfile().unwrap();
        executable
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let executable: OwnedFd = executable.into();
        assert!(inspect_provisioned_executable(&executable, "system_u:object_r:bin_t").is_err());
    }
}
