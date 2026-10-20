//! Safe fixed-descriptor `posix_spawn` execution.
//!
//! The wrapper validates one closed child descriptor range, duplicates every
//! caller-borrowed source above that range, configures libc file actions, runs
//! an absolute executable with no arguments and an empty environment, and
//! synchronously reaps the exact child. Raw libc state and wait-status handling
//! remain private to this Linux boundary.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path};

use crate::{Error, Result};

const FIRST_NONSTANDARD_FD: RawFd = 3;
const MAXIMUM_FIXED_ROLE_FD: RawFd = 1_024;
const MAXIMUM_FIXED_ROLES: usize = 64;
const MINIMUM_DUPLICATE_FD: RawFd = 64;
const MAXIMUM_EXECUTABLE_BYTES: usize = 4_096;

/// Borrows one owned source for a fixed child descriptor number.
#[derive(Clone, Copy, Debug)]
pub struct FixedDescriptorMappingV1<'a> {
    target: RawFd,
    source: BorrowedFd<'a>,
}

impl<'a> FixedDescriptorMappingV1<'a> {
    /// Associates `source` with `target` for a validated fixed child table.
    #[must_use]
    pub const fn new(target: RawFd, source: BorrowedFd<'a>) -> Self {
        Self { target, source }
    }
}

/// Describes one exact no-argument fixed-descriptor child invocation.
#[derive(Debug)]
pub struct FixedDescriptorSpawnRequestV1<'a> {
    executable: &'a Path,
    first_role: RawFd,
    last_role: RawFd,
    mappings: &'a [FixedDescriptorMappingV1<'a>],
}

impl<'a> FixedDescriptorSpawnRequestV1<'a> {
    /// Validates a fixed descriptor table and executable path.
    ///
    /// `first_role..=last_role` is the complete permitted child table. Missing
    /// nonmandatory roles are closed explicitly, and all descriptors above the
    /// table are closed in the child before `execve`.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-normalized or overlong absolute path, an
    /// invalid/oversized role range, a duplicate or out-of-range mapping, an
    /// invalid source descriptor, or an absent/duplicate mandatory role.
    pub fn new(
        executable: &'a Path,
        first_role: RawFd,
        last_role: RawFd,
        mandatory_roles: &'a [RawFd],
        mappings: &'a [FixedDescriptorMappingV1<'a>],
    ) -> Result<Self> {
        validate_executable(executable)?;
        validate_role_table(first_role, last_role, mandatory_roles, mappings)?;

        Ok(Self {
            executable,
            first_role,
            last_role,
            mappings,
        })
    }
}

/// Spawns and synchronously reaps one fixed-descriptor child.
///
/// The executable becomes `argv[0]`, no further arguments are supplied, and
/// the child environment is empty. Standard input, output, and error remain
/// inherited. The caller must serialize child reaping for this synchronous
/// operation; the returned status belongs to the exact PID returned by libc.
///
/// # Errors
///
/// Returns an error for descriptor duplication, libc file-action setup,
/// `posix_spawn`, waiting, signal death, or an unexpected wait status.
pub fn spawn_fixed_descriptor_process(request: FixedDescriptorSpawnRequestV1<'_>) -> Result<i32> {
    let executable = CString::new(request.executable.as_os_str().as_bytes())
        .map_err(|_| Error::invalid("fixed executable", "path contains NUL"))?;
    let duplicate_minimum = request
        .last_role
        .checked_add(1)
        .map(|minimum| minimum.max(MINIMUM_DUPLICATE_FD))
        .ok_or_else(|| Error::invalid("fixed descriptor table", "duplicate floor overflows"))?;
    let duplicates = request
        .mappings
        .iter()
        .map(|mapping| {
            rustix::io::fcntl_dupfd_cloexec(mapping.source, duplicate_minimum)
                .map(|descriptor| (mapping.target, descriptor))
                .map_err(|source| kernel_error("duplicate fixed child descriptor", source))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut storage = MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
    // SAFETY: storage is writable and uninitialized. Success initializes it
    // exactly once for the guarded calls below.
    check_libc(
        unsafe { libc::posix_spawn_file_actions_init(storage.as_mut_ptr()) },
        "initialize fixed child file actions",
    )?;
    // SAFETY: successful initialization above produced a live action object.
    let mut actions = unsafe { storage.assume_init() };

    if let Err(error) = configure_actions(
        &mut actions,
        request.first_role,
        request.last_role,
        &duplicates,
    ) {
        destroy_actions(&mut actions);
        return Err(error);
    }

    let arguments = [executable.as_ptr().cast_mut(), std::ptr::null_mut()];
    let environment = [std::ptr::null_mut::<libc::c_char>()];
    let mut pid: libc::pid_t = 0;
    // SAFETY: the C string and NULL-terminated pointer arrays remain live;
    // actions is initialized; and pid points to writable result storage.
    let spawned = unsafe {
        libc::posix_spawn(
            &raw mut pid,
            executable.as_ptr(),
            &raw const actions,
            std::ptr::null(),
            arguments.as_ptr(),
            environment.as_ptr(),
        )
    };
    destroy_actions(&mut actions);
    check_libc(spawned, "spawn fixed descriptor child")?;

    wait_status(pid)
}

fn validate_executable(executable: &Path) -> Result<()> {
    let bytes = executable.as_os_str().as_bytes();
    let normalized = executable
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    if bytes.is_empty()
        || bytes.len() > MAXIMUM_EXECUTABLE_BYTES
        || !executable.is_absolute()
        || !normalized
        || bytes.contains(&0)
    {
        return Err(Error::invalid(
            "fixed executable",
            "must be a normalized absolute path within 4096 bytes",
        ));
    }
    Ok(())
}

fn validate_role_table(
    first_role: RawFd,
    last_role: RawFd,
    mandatory_roles: &[RawFd],
    mappings: &[FixedDescriptorMappingV1<'_>],
) -> Result<()> {
    let role_count = last_role
        .checked_sub(first_role)
        .and_then(|difference| difference.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| Error::invalid("fixed descriptor table", "role range is invalid"))?;
    if first_role < FIRST_NONSTANDARD_FD
        || last_role > MAXIMUM_FIXED_ROLE_FD
        || role_count > MAXIMUM_FIXED_ROLES
    {
        return Err(Error::invalid(
            "fixed descriptor table",
            "role range is outside the bounded nonstandard descriptor table",
        ));
    }

    let mut targets = BTreeSet::new();
    for mapping in mappings {
        if !(first_role..=last_role).contains(&mapping.target) || !targets.insert(mapping.target) {
            return Err(Error::invalid(
                "fixed descriptor mappings",
                "target is outside the role range or duplicated",
            ));
        }
        rustix::io::fcntl_getfd(mapping.source)
            .map_err(|source| kernel_error("inspect fixed child descriptor", source))?;
    }

    let mut mandatory = BTreeSet::new();
    for role in mandatory_roles {
        if !(first_role..=last_role).contains(role)
            || !mandatory.insert(*role)
            || !targets.contains(role)
        {
            return Err(Error::invalid(
                "fixed mandatory descriptors",
                "role is outside the table, duplicated, or absent",
            ));
        }
    }
    Ok(())
}

fn configure_actions(
    actions: &mut libc::posix_spawn_file_actions_t,
    first_role: RawFd,
    last_role: RawFd,
    duplicates: &[(RawFd, OwnedFd)],
) -> Result<()> {
    let present = duplicates
        .iter()
        .map(|(target, _)| *target)
        .collect::<BTreeSet<_>>();
    for target in first_role..=last_role {
        if !present.contains(&target) {
            // SAFETY: actions is initialized and remains exclusively borrowed.
            check_libc(
                unsafe { libc::posix_spawn_file_actions_addclose(actions, target) },
                "close absent fixed descriptor role",
            )?;
        }
    }
    for (target, source) in duplicates {
        // SAFETY: actions is initialized, the validated target is nonnegative,
        // and every source remains owned until posix_spawn returns.
        check_libc(
            unsafe { libc::posix_spawn_file_actions_adddup2(actions, source.as_raw_fd(), *target) },
            "map fixed descriptor role",
        )?;
    }
    // SAFETY: actions is initialized. The GNU action is available in AOS glibc
    // and closes high duplicates plus unrelated inherited descriptors.
    check_libc(
        unsafe { libc::posix_spawn_file_actions_addclosefrom_np(actions, last_role + 1) },
        "close unrelated child descriptors",
    )
}

fn destroy_actions(actions: &mut libc::posix_spawn_file_actions_t) {
    // SAFETY: callers invoke this exactly once after successful initialization.
    let _ = unsafe { libc::posix_spawn_file_actions_destroy(actions) };
}

fn wait_status(pid: libc::pid_t) -> Result<i32> {
    let mut status = 0;
    loop {
        // SAFETY: status is writable and pid is the exact successful spawn
        // result. The synchronous caller retains exclusive reaping authority.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if waited == pid {
            break;
        }
        let source = std::io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::EINTR) {
            return Err(Error::Syscall {
                operation: "wait for fixed descriptor child",
                source,
            });
        }
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Err(Error::invalid(
            "fixed descriptor child",
            format!("terminated by signal {}", libc::WTERMSIG(status)),
        ))
    } else {
        Err(Error::MalformedKernelResponse {
            object: "fixed descriptor child wait status",
            message: "child returned neither an exit nor signal status".to_owned(),
        })
    }
}

fn check_libc(result: libc::c_int, operation: &'static str) -> Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(Error::Syscall {
            operation,
            source: std::io::Error::from_raw_os_error(result),
        })
    }
}

fn kernel_error(operation: &'static str, source: rustix::io::Errno) -> Error {
    Error::Syscall {
        operation,
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    }
}
