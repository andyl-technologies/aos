//! Audited `posix_spawn` boundary for the namespace helper.
//!
//! The broker never runs Rust after `fork` in a copied process. It duplicates
//! every source descriptor above the child role range, asks libc's
//! `posix_spawn` file-action engine to map only exact fixed roles, closes all
//! descriptors above the role table, and supplies an empty environment.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::io::fcntl_dupfd_cloexec;

use crate::{MountError, Result};

/// Fixed child descriptor carrying the sealed helper plan.
pub const PLAN_FD: i32 = 3;
/// Optional fixed child descriptor carrying a detached mount.
pub const DETACHED_MOUNT_FD: i32 = 4;
/// Fixed child descriptor carrying the mount namespace.
pub const MOUNT_NAMESPACE_FD: i32 = 5;
/// Fixed child descriptor carrying the target root.
pub const TARGET_ROOT_FD: i32 = 6;
/// Fixed child descriptor carrying the pre-effect target slot.
pub const TARGET_SLOT_FD: i32 = 7;
/// Fixed child descriptor carrying its bounded kernel observation report.
pub const OBSERVATION_FD: i32 = 8;

const FIRST_ROLE_FD: i32 = PLAN_FD;
const LAST_ROLE_FD: i32 = OBSERVATION_FD;
const DUPLICATE_FD_MINIMUM: i32 = 64;

/// Maps one broker-owned descriptor to a fixed helper role.
#[derive(Clone, Copy, Debug)]
pub struct DescriptorMapping<'a> {
    /// Fixed child descriptor number from the constants in this module.
    pub target: i32,
    /// Typed broker-side descriptor borrowed through `posix_spawn`.
    pub source: BorrowedFd<'a>,
}

/// Spawns and synchronously waits for one fixed helper invocation.
///
/// The executable path must be an absolute Nix-store path selected by the
/// system module. Standard input/output/error are inherited for service-log
/// integration; descriptors 3 through 7 exactly match `mappings`; everything
/// above 7 is closed in the child; and the child environment is empty.
///
/// # Errors
///
/// Returns an error for an unsafe executable path, duplicate/unknown/missing
/// mandatory descriptor roles, descriptor duplication, libc spawn setup,
/// launch, wait failure, signal death, or a nonzero helper exit status.
pub fn run_helper(executable: &Path, mappings: &[DescriptorMapping<'_>]) -> Result<()> {
    let status = run_helper_status(executable, mappings)?;
    if status == 0 {
        Ok(())
    } else {
        Err(MountError::Worker(format!(
            "mount helper exited with status {status}"
        )))
    }
}

/// Spawns one helper and returns its normal exit status.
///
/// This variant lets the observation operation reserve status `3` for an
/// absent exact mount. Signals and all launch/wait failures remain errors.
///
/// # Errors
///
/// Returns the same setup, spawn, wait, and signal errors as [`run_helper`].
pub fn run_helper_status(executable: &Path, mappings: &[DescriptorMapping<'_>]) -> Result<i32> {
    validate(executable, mappings)?;
    let executable = CString::new(executable.as_os_str().as_encoded_bytes())
        .map_err(|_| MountError::Worker("helper executable contains NUL".to_owned()))?;
    let duplicates = mappings
        .iter()
        .map(|mapping| {
            fcntl_dupfd_cloexec(mapping.source, DUPLICATE_FD_MINIMUM)
                .map(|fd| (mapping.target, fd))
                .map_err(|error| MountError::Worker(error.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut storage = MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
    // SAFETY: `storage` points to writable uninitialized action storage. A
    // successful call initializes it exactly once for the guard below.
    let result = unsafe { libc::posix_spawn_file_actions_init(storage.as_mut_ptr()) };
    check_libc(result, "initialize helper file actions")?;
    // SAFETY: initialization above succeeded, so the value is initialized.
    let mut actions = unsafe { storage.assume_init() };

    if let Err(error) = configure_actions(&mut actions, &duplicates) {
        destroy_actions(&mut actions);
        return Err(error);
    }

    let argument_pointers = [executable.as_ptr().cast_mut(), std::ptr::null_mut()];
    let environment = [std::ptr::null_mut::<libc::c_char>()];
    let mut pid: libc::pid_t = 0;
    // SAFETY: all C strings and pointer arrays remain live through the call;
    // actions is initialized; argv/envp are NULL terminated; and `pid` is a
    // writable result. libc performs child-side work without returning into
    // Rust between process creation and exec.
    let spawned = unsafe {
        libc::posix_spawn(
            &raw mut pid,
            executable.as_ptr(),
            &raw const actions,
            std::ptr::null(),
            argument_pointers.as_ptr(),
            environment.as_ptr(),
        )
    };
    destroy_actions(&mut actions);
    check_libc(spawned, "spawn mount namespace helper")?;
    wait_status(pid)
}

fn configure_actions(
    actions: &mut libc::posix_spawn_file_actions_t,
    duplicates: &[(i32, OwnedFd)],
) -> Result<()> {
    let present = duplicates
        .iter()
        .map(|(target, _)| *target)
        .collect::<BTreeSet<_>>();
    for target in FIRST_ROLE_FD..=LAST_ROLE_FD {
        if !present.contains(&target) {
            // SAFETY: actions is initialized and remains exclusively borrowed.
            let result = unsafe { libc::posix_spawn_file_actions_addclose(actions, target) };
            check_libc(result, "close absent helper role")?;
        }
    }
    for (target, source) in duplicates {
        // SAFETY: actions is initialized, both descriptors are nonnegative,
        // and every source duplicate remains owned until posix_spawn returns.
        let result =
            unsafe { libc::posix_spawn_file_actions_adddup2(actions, source.as_raw_fd(), *target) };
        check_libc(result, "map helper descriptor role")?;
    }
    // SAFETY: actions is initialized. The GNU action is available in AOS glibc
    // and closes high duplicate sources plus every unrelated inherited fd.
    let result =
        unsafe { libc::posix_spawn_file_actions_addclosefrom_np(actions, LAST_ROLE_FD + 1) };
    check_libc(result, "close unrelated helper descriptors")
}

fn destroy_actions(actions: &mut libc::posix_spawn_file_actions_t) {
    // SAFETY: callers invoke this exactly once after successful initialization.
    let _ = unsafe { libc::posix_spawn_file_actions_destroy(actions) };
}

fn wait_status(pid: libc::pid_t) -> Result<i32> {
    let mut status = 0;
    loop {
        // SAFETY: `status` is writable and `pid` is the exact successful spawn
        // result. No other thread in this synchronous broker reaps the helper.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if waited == pid {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(MountError::Worker(format!(
                "wait for mount helper failed: {error}"
            )));
        }
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Err(MountError::Worker(format!(
            "mount helper died from signal {}",
            libc::WTERMSIG(status)
        )))
    } else {
        Err(MountError::Worker(
            "mount helper returned an unexpected wait status".to_owned(),
        ))
    }
}

fn validate(executable: &Path, mappings: &[DescriptorMapping<'_>]) -> Result<()> {
    let path = executable.as_os_str().as_encoded_bytes();
    if path.is_empty()
        || path.len() > 4096
        || !executable.is_absolute()
        || path.contains(&0)
        || executable
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(MountError::Worker(
            "mount helper executable path is unsafe".to_owned(),
        ));
    }
    let mut targets = BTreeSet::new();
    for mapping in mappings {
        if !(FIRST_ROLE_FD..=LAST_ROLE_FD).contains(&mapping.target)
            || !targets.insert(mapping.target)
        {
            return Err(MountError::Worker(
                "mount helper descriptor role table is invalid".to_owned(),
            ));
        }
    }
    for mandatory in [
        PLAN_FD,
        MOUNT_NAMESPACE_FD,
        TARGET_ROOT_FD,
        TARGET_SLOT_FD,
        OBSERVATION_FD,
    ] {
        if !targets.contains(&mandatory) {
            return Err(MountError::Worker(
                "mount helper descriptor role table is incomplete".to_owned(),
            ));
        }
    }
    Ok(())
}

fn check_libc(result: libc::c_int, operation: &str) -> Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(MountError::Worker(format!(
            "{operation}: {}",
            std::io::Error::from_raw_os_error(result)
        )))
    }
}
