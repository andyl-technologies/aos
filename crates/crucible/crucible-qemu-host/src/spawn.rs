//! Linux QEMU process spawning with fixed inherited descriptors.
//!
//! This module owns the Linux process boundary for contained guest execution.
//! It creates the per-node control socket pair, shared-memory memfd,
//! and wake eventfd before `exec`, maps the child descriptors to the fixed
//! plugin fd numbers, clears the inherited host environment, and sets
//! `PR_SET_PDEATHSIG=SIGKILL` in the child.

use std::fs;
use std::io::{self, Read, Write as _};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::supervision::HostSupervisionDeadline;

use rustix::fs::{FileType, OFlags, fcntl_getfl, fcntl_setfl, fstat, fstatfs};
use thiserror::Error;

use crate::{
    QEMU_PLUGIN_CONTROL_FD, QEMU_PLUGIN_SHMEM_FD, QEMU_PLUGIN_WAKE_FD, QemuLaunchCommand,
    QemuNodeChild,
};

#[cfg(target_os = "linux")]
mod process_envelope;
#[cfg(target_os = "linux")]
pub(crate) use process_envelope::{ConfiguredProcessEnvelope, ProcessEnvelopeRefinementError};

mod control_delivery_trace;
#[cfg(target_os = "linux")]
mod device_digest_workspace;
mod image_launch;
mod materialization;
mod plugin_startup;
#[cfg(target_os = "linux")]
pub(crate) mod preexec_setup;
#[cfg(target_os = "linux")]
pub(crate) mod ram_endpoint_binding;
mod ram_spill;
mod run_directory;
pub(crate) mod source_supervision;
mod worker_stack_profile;

#[cfg(target_os = "linux")]
pub(crate) use device_digest_workspace::{
    DeviceDigestWorkspaceBody, DeviceDigestWorkspaceIssueError, OriginalDeviceDigestWorkspace,
};

pub(crate) use plugin_startup::OriginalPluginStartup;
pub use plugin_startup::PluginStartupError;
#[cfg(target_os = "linux")]
pub use preexec_setup::PreexecSetupError;
pub(crate) use worker_stack_profile::GuardedWorkerStackProfile;

pub(crate) use control_delivery_trace::valid_control_delivery_row;
pub(crate) use run_directory::valid_rr_control_boundary_row;

use image_launch::{GuardedLaunchImagePins, GuardedSetupProbeCommand, guarded_launch_args};
pub(crate) use materialization::QemuProductionExactRestoreSource;
pub(crate) use materialization::SealedAtomicExactRestoreInputs;
pub(crate) use materialization::{QemuExactDeviceStateBinding, require_exact_restore_not_canceled};
pub use run_directory::QemuPreparedRunDirectory;
use run_directory::{PinnedFileIdentity, open_prepared_root_overlay};

const QEMU_VMSTATE_LAUNCH_FD: RawFd = QEMU_PLUGIN_WAKE_FD + 1;
const QEMU_ROOT_OVERLAY_READ_LAUNCH_FD: RawFd = QEMU_VMSTATE_LAUNCH_FD + 1;
const QEMU_ROOT_OVERLAY_WRITE_LAUNCH_FD: RawFd = QEMU_ROOT_OVERLAY_READ_LAUNCH_FD + 1;
// Every inherited source is relocated above all fixed exec targets before dup2.
pub(crate) const QEMU_RAM_SOURCE_LAUNCH_FD: RawFd = 10;
pub(crate) const QEMU_RAM_SPILL_LAUNCH_FD: RawFd = 11;
pub(crate) const QEMU_STARTUP_CANCELLATION_FD: RawFd = QEMU_RAM_SPILL_LAUNCH_FD + 1;
const CHILD_SOURCE_FD_MIN: RawFd = QEMU_STARTUP_CANCELLATION_FD + 1;
const CGROUP_ATTACH_SELF: &[u8] = b"0\n";
const MAX_SUPERVISOR_GROUPS: usize = 65_536;
const VMSTATE_FILE_NAME_C: &[u8] = b"crucible-vmstate.qcow2\0";
const GUARDED_IMAGE_TOOL_TIMEOUT: Duration = Duration::from_secs(60);
const GUARDED_IMAGE_TOOL_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// Owned pre-exec contract for one attempt-contained child process.
///
/// The cgroup descriptors pin the attempt directory and its `cgroup.procs`
/// file. The cancellation descriptor is a nonblocking eventfd that becomes
/// readable once cancellation wins. All descriptors must be opened by the
/// supervising resource guard and remain owned by that guard independently of
/// this per-spawn duplicate. A production contract also carries validated non-root
/// child credentials; pre-exec clears supplementary groups, sets
/// `no_new_privs`, and switches every user/group identity after attaching the
/// child to the cgroup. The contract seals the exact admitted vCPU,
/// resident-memory, and aggregate writable-byte ceilings so guarded launch can
/// reject an incompatible command before touching the run directory or
/// allocating child descriptors. A private lifecycle token also binds every
/// prepared run-directory authority to this exact contract rather than merely
/// to another attempt with equal numeric limits.
#[derive(Debug)]
pub struct QemuChildProcessContract {
    cgroup_directory: Option<OwnedFd>,
    cgroup_procs: OwnedFd,
    cancellation_event: OwnedFd,
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_tasks: Option<u32>,
    maximum_writable_bytes: u64,
    maximum_file_descriptors: Option<u64>,
    maximum_locked_bytes: u64,
    credentials: Option<QemuChildCredentials>,
    attempt_binding: Arc<AttemptResourceBinding>,
    exact_checkpoint_root: Option<crucible_engine::ContentHash>,
}

/// Independently bounded writable storage and descriptor limits of one child.
pub(crate) struct QemuChildFileLimits {
    pub(crate) writable_bytes: u64,
    pub(crate) descriptors: u64,
    pub(crate) locked_bytes: u64,
}

#[derive(Debug)]
struct AttemptResourceBinding {
    #[cfg(target_os = "linux")]
    helper_receiver: std::sync::OnceLock<crate::linux_attempt_host::SourceCleanupLender>,
    // Refinement closes before the first attempted exec. Genuine duplicates
    // observe the same effective ceiling through this retained binding.
    // The state is shared by the existing allocation, never a new authority.
    launch_state: std::sync::atomic::AtomicU8,
    effective_resident_bytes: std::sync::atomic::AtomicU64,
    main_stack_bytes: std::sync::atomic::AtomicU64,
    effective_file_descriptors: std::sync::atomic::AtomicU64,
}

impl AttemptResourceBinding {
    fn new(resident_bytes: u64, file_descriptors: Option<u64>) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            helper_receiver: std::sync::OnceLock::new(),
            launch_state: std::sync::atomic::AtomicU8::new(0),
            effective_resident_bytes: std::sync::atomic::AtomicU64::new(resident_bytes),
            main_stack_bytes: std::sync::atomic::AtomicU64::new(0),
            effective_file_descriptors: std::sync::atomic::AtomicU64::new(
                file_descriptors.unwrap_or(0),
            ),
        }
    }
}

mod child_privilege;
mod main_stack;
pub(crate) mod helper_first;
pub use helper_first::QemuIssuedHelperFailure;
pub(crate) mod helper_receiver;
pub use helper_receiver::QemuIssuedHelperReceiver;
mod process_stage_binding;
pub(crate) use process_stage_binding::QemuProcessStageRetirement;
pub use process_stage_binding::{QemuProcessStageBinding, QemuProcessStageIdentityError};

fn invalid_input(operation: &'static str, message: &'static str) -> QemuSpawnError {
    QemuSpawnError::Io {
        operation,
        source: io::Error::new(io::ErrorKind::InvalidInput, message),
    }
}

/// Distinct unprivileged credentials installed in a guarded QEMU child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QemuChildCredentials {
    user_id: libc::uid_t,
    group_id: libc::gid_t,
}

struct SupervisorCredentials {
    user_ids: [libc::uid_t; 3],
    group_ids: [libc::gid_t; 3],
    supplementary_group_ids: SupervisorGroups,
}

// The physical group array always drops before its same-budget temporary loan.
struct SupervisorGroups {
    values: Vec<libc::gid_t>,
    _credit: Option<crucible_engine::owned_decode::DecodeScratch>,
}

impl SupervisorGroups {
    fn contains(&self, group: &libc::gid_t) -> bool {
        self.values.contains(group)
    }
}

impl QemuChildCredentials {
    /// Validates credentials that cannot retain the supervisor's identity.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError::InvalidChildCredentials`] when either ID is
    /// root, the user ID equals any real, effective, or saved daemon user, or
    /// the group ID equals any real, effective, saved, or supplementary daemon
    /// group. Returns
    /// [`QemuSpawnError::Io`] when credential inspection fails, or a typed
    /// group-bound, group-change or decode-admission refusal before use.
    pub(crate) fn new(user_id: libc::uid_t, group_id: libc::gid_t) -> Result<Self, QemuSpawnError> {
        let supervisor = current_supervisor_credentials()?;
        if user_id == 0
            || group_id == 0
            || supervisor.user_ids.contains(&user_id)
            || supervisor.group_ids.contains(&group_id)
            || supervisor.supplementary_group_ids.contains(&group_id)
        {
            return Err(QemuSpawnError::InvalidChildCredentials { user_id, group_id });
        }
        Ok(Self { user_id, group_id })
    }
}

fn current_supervisor_credentials() -> Result<SupervisorCredentials, QemuSpawnError> {
    let mut real_user_id = 0;
    let mut effective_user_id = 0;
    let mut saved_user_id = 0;
    let users_read = unsafe {
        // SAFETY: all three pointers name writable uid_t values.
        libc::getresuid(
            &mut real_user_id,
            &mut effective_user_id,
            &mut saved_user_id,
        )
    };
    if users_read != 0 {
        return Err(last_io_error("inspect supervisor user credentials"));
    }
    let mut real_group_id = 0;
    let mut effective_group_id = 0;
    let mut saved_group_id = 0;
    let groups_read = unsafe {
        // SAFETY: all three pointers name writable gid_t values.
        libc::getresgid(
            &mut real_group_id,
            &mut effective_group_id,
            &mut saved_group_id,
        )
    };
    if groups_read != 0 {
        return Err(last_io_error("inspect supervisor group credentials"));
    }
    Ok(SupervisorCredentials {
        user_ids: [real_user_id, effective_user_id, saved_user_id],
        group_ids: [real_group_id, effective_group_id, saved_group_id],
        supplementary_group_ids: current_supplementary_groups()?,
    })
}

fn current_supplementary_groups() -> Result<SupervisorGroups, QemuSpawnError> {
    let count = unsafe {
        // SAFETY: a zero count permits a null list and returns its required size.
        libc::getgroups(0, std::ptr::null_mut())
    };
    if count < 0 {
        return Err(last_io_error("inspect supervisor supplementary groups"));
    }
    let count = count as usize;
    if count > MAX_SUPERVISOR_GROUPS {
        return Err(QemuSpawnError::SupervisorGroupLimit);
    }
    let credit = crucible_engine::owned_decode::current_budget()
        .map(|budget| budget.reserve_scratch_array::<libc::gid_t>(count))
        .transpose()
        .map_err(QemuSpawnError::ConfigurationAdmission)?;
    let mut groups = SupervisorGroups {
        values: vec![0; count],
        _credit: credit,
    };
    if count == 0 {
        return Ok(groups);
    }
    let returned = unsafe {
        // SAFETY: `groups` contains exactly `count` writable gid_t elements.
        libc::getgroups(count as libc::c_int, groups.values.as_mut_ptr())
    };
    if returned < 0 {
        return Err(last_io_error("read supervisor supplementary groups"));
    }
    if returned as usize != count {
        return Err(QemuSpawnError::SupervisorGroupsChanged);
    }
    Ok(groups)
}

impl QemuChildProcessContract {
    /// Returns the validated effective credentials installed by guarded spawn.
    ///
    /// The identifiers come from this retained process contract, rather than
    /// from an operator-supplied capability receipt. `None` identifies a contract
    /// without native child credentials and cannot authenticate a kernel probe.
    pub fn effective_credentials(&self) -> Option<(u32, u32)> {
        self.credentials
            .map(|credentials| (credentials.user_id, credentials.group_id))
    }

    /// Returns the authenticated hard and soft child memory-lock entitlement.
    #[must_use]
    pub const fn maximum_locked_bytes(&self) -> u64 {
        self.maximum_locked_bytes
    }

    /// Duplicates the sticky cancellation event for one bounded QMP operation.
    ///
    /// The returned descriptor observes the same eventfd counter as the child
    /// process contract. An attempt cancellation therefore interrupts both a
    /// process blocked in setup and a descriptor-backed QMP capture or restore.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError::Io`] when the retained eventfd cannot be
    /// duplicated.
    pub fn try_clone_cancellation_event(&self) -> Result<OwnedFd, QemuSpawnError> {
        self.cancellation_event
            .try_clone()
            .map_err(|source| QemuSpawnError::Io {
                operation: "duplicate QMP cancellation eventfd",
                source,
            })
    }

    /// Duplicates this contract for another generation under the same attempt.
    ///
    /// The duplicated descriptors retain the same cgroup, cancellation event,
    /// credentials, resource ceilings, and private attempt binding. This is for
    /// a lifecycle launcher whose aggregate guard is shared through an ownership
    /// registry and therefore cannot lend a reference while that registry is
    /// unlocked.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError::Io`] when a retained descriptor cannot be
    /// duplicated.
    pub fn try_clone_for_attempt_generation(&self) -> Result<Self, QemuSpawnError> {
        self.attempt_binding.check_clone_available()?;

        let cgroup_directory = self
            .cgroup_directory
            .as_ref()
            .map(OwnedFd::try_clone)
            .transpose()
            .map_err(|source| QemuSpawnError::Io {
                operation: "duplicate generation cgroup directory",
                source,
            })?;
        let cgroup_procs = self
            .cgroup_procs
            .try_clone()
            .map_err(|source| QemuSpawnError::Io {
                operation: "duplicate generation cgroup.procs descriptor",
                source,
            })?;
        let cancellation_event =
            self.cancellation_event
                .try_clone()
                .map_err(|source| QemuSpawnError::Io {
                    operation: "duplicate generation cancellation eventfd",
                    source,
                })?;

        Ok(Self {
            cgroup_directory,
            cgroup_procs,
            cancellation_event,
            maximum_vcpus: self.maximum_vcpus,
            maximum_resident_bytes: self.maximum_resident_bytes,
            maximum_tasks: self.maximum_tasks,
            maximum_writable_bytes: self.maximum_writable_bytes,
            maximum_file_descriptors: self.maximum_file_descriptors,
            maximum_locked_bytes: self.maximum_locked_bytes,
            credentials: self.credentials,
            attempt_binding: Arc::clone(&self.attempt_binding),
            exact_checkpoint_root: self.exact_checkpoint_root,
        })
    }

    /// Derives a contract for a newly authenticated repository checkpoint.
    ///
    /// The returned contract retains this attempt's cgroup, cancellation,
    /// resource ceilings, credentials, and private directory binding. Its root
    /// is fixed at construction, so an exact restore request cannot substitute
    /// another repository closure. The caller must first publish and
    /// authenticate `root` in its selected campaign checkpoint store.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when an attempt descriptor cannot be cloned.
    pub fn try_derive_for_exact_checkpoint_root(
        &self,
        root: crucible_engine::ContentHash,
    ) -> Result<Self, QemuSpawnError> {
        let mut contract = self.try_clone_for_attempt_generation()?;
        contract.exact_checkpoint_root = Some(root);
        Ok(contract)
    }

    fn admitted_resource_ceiling(&self) -> (u32, u64, u64) {
        (
            self.maximum_vcpus,
            self.effective_resident_bytes(),
            self.maximum_writable_bytes,
        )
    }

    fn effective_resident_bytes(&self) -> u64 {
        self.attempt_binding
            .effective_resident_bytes
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn effective_file_descriptors(&self) -> Option<u64> {
        self.maximum_file_descriptors.map(|_| {
            self.attempt_binding
                .effective_file_descriptors
                .load(std::sync::atomic::Ordering::Acquire)
        })
    }

    /// Returns the descriptor-index floor of the actual fixed child assignments.
    ///
    /// Stdio and every selected launch target must fit below NOFILE. This is
    /// neither an aggregate family entitlement nor a promise that transient
    /// opens or unrelated inherited descriptors fit inside the chosen limit.
    pub(crate) const fn required_launch_file_descriptors() -> u64 {
        let targets = [
            libc::STDERR_FILENO,
            QEMU_PLUGIN_CONTROL_FD,
            QEMU_PLUGIN_SHMEM_FD,
            QEMU_PLUGIN_WAKE_FD,
            QEMU_VMSTATE_LAUNCH_FD,
            QEMU_ROOT_OVERLAY_READ_LAUNCH_FD,
            QEMU_ROOT_OVERLAY_WRITE_LAUNCH_FD,
            crate::QEMU_PLUGIN_RAM_CONTROL_FD,
            QEMU_RAM_SOURCE_LAUNCH_FD,
            QEMU_RAM_SPILL_LAUNCH_FD,
            QEMU_STARTUP_CANCELLATION_FD,
        ];
        let mut highest = libc::STDERR_FILENO;
        let mut index = 0;
        while index < targets.len() {
            if targets[index] > highest {
                highest = targets[index];
            }
            index += 1;
        }
        highest as u64 + 1
    }

    /// Builds one child-side containment and credential contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when either descriptor is invalid.
    pub(crate) fn new(
        cgroup_directory: OwnedFd,
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        cgroup_limits: crate::linux_cgroup::LinuxQemuCgroupLimits,
        files: QemuChildFileLimits,
        credentials: QemuChildCredentials,
        exact_checkpoint_root: Option<crucible_engine::ContentHash>,
    ) -> Result<Self, QemuSpawnError> {
        if files.locked_bytes == libc::RLIM_INFINITY {
            return Err(invalid_input(
                "seal QEMU memory-lock limit",
                "memory-lock entitlement must be finite",
            ));
        }
        if files.descriptors == libc::RLIM_INFINITY
            || files.descriptors < Self::required_launch_file_descriptors()
        {
            return Err(invalid_input(
                "seal QEMU descriptor limit",
                "descriptor limit must be finite and accommodate fixed launch descriptors",
            ));
        }
        validate_cgroup_directory_fd(&cgroup_directory)?;
        validate_cgroup_procs_fd(&cgroup_procs)?;
        validate_cancellation_eventfd(cancellation_event.as_raw_fd())?;
        Ok(Self {
            cgroup_directory: Some(cgroup_directory),
            cgroup_procs,
            cancellation_event,
            maximum_vcpus: cgroup_limits.maximum_vcpus(),
            maximum_resident_bytes: cgroup_limits.maximum_resident_bytes(),
            maximum_tasks: Some(cgroup_limits.maximum_tasks()),
            maximum_writable_bytes: files.writable_bytes,
            maximum_file_descriptors: Some(files.descriptors),
            maximum_locked_bytes: files.locked_bytes,
            credentials: Some(credentials),
            attempt_binding: Arc::new(AttemptResourceBinding::new(
                cgroup_limits.maximum_resident_bytes(),
                Some(files.descriptors),
            )),
            exact_checkpoint_root,
        })
    }

    pub(crate) fn require_exact_checkpoint_root(
        &self,
        root: crucible_engine::ContentHash,
    ) -> Result<(), QemuSpawnError> {
        if self.exact_checkpoint_root != Some(root) {
            return Err(invalid_input(
                "authenticate exact checkpoint root",
                "attempt process contract is not bound to this exact checkpoint root",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_writable_bytes: u64,
    ) -> Self {
        Self::from_unvalidated_test_descriptors_with_root(
            cgroup_procs,
            cancellation_event,
            u32::MAX,
            u64::MAX,
            maximum_writable_bytes,
            None,
        )
    }

    #[cfg(test)]
    fn for_exact_checkpoint_test(
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_writable_bytes: u64,
        exact_checkpoint_root: crucible_engine::ContentHash,
    ) -> Self {
        Self::from_unvalidated_test_descriptors_with_root(
            cgroup_procs,
            cancellation_event,
            u32::MAX,
            u64::MAX,
            maximum_writable_bytes,
            Some(exact_checkpoint_root),
        )
    }

    /// Builds an unvalidated process contract for cross-crate conformance tests.
    ///
    /// This constructor exists only with the `test-support` feature or while
    /// compiling this crate's unit tests. It must never be used as a production
    /// containment boundary.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn from_unvalidated_test_descriptors(
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
    ) -> Self {
        Self::from_unvalidated_test_descriptors_with_root(
            cgroup_procs,
            cancellation_event,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            None,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    fn from_unvalidated_test_descriptors_with_root(
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
        exact_checkpoint_root: Option<crucible_engine::ContentHash>,
    ) -> Self {
        Self {
            cgroup_directory: None,
            cgroup_procs,
            cancellation_event,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_tasks: None,
            maximum_writable_bytes,
            maximum_file_descriptors: None,
            maximum_locked_bytes: 0,
            credentials: None,
            attempt_binding: Arc::new(AttemptResourceBinding::new(maximum_resident_bytes, None)),
            exact_checkpoint_root,
        }
    }

    /// Builds an unvalidated hot-fork process contract for cross-crate tests.
    ///
    /// Unlike [`Self::from_unvalidated_test_descriptors`], this value carries a
    /// directory descriptor so tests can exercise retained-template descriptor
    /// transfer. No descriptor provenance or credential policy is validated.
    /// It must never be used as a production containment boundary.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn from_unvalidated_hot_fork_test_descriptors(
        cgroup_directory: OwnedFd,
        cgroup_procs: OwnedFd,
        cancellation_event: OwnedFd,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
    ) -> Self {
        Self {
            cgroup_directory: Some(cgroup_directory),
            cgroup_procs,
            cancellation_event,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_tasks: None,
            maximum_writable_bytes,
            maximum_file_descriptors: None,
            maximum_locked_bytes: 0,
            credentials: None,
            attempt_binding: Arc::new(AttemptResourceBinding::new(maximum_resident_bytes, None)),
            exact_checkpoint_root: None,
        }
    }

    /// Duplicates the cgroup directory, its `cgroup.procs`, and the
    /// cancellation eventfd for one hot-fork contract stage, in that order.
    pub(crate) fn duplicate_hot_fork_descriptors(
        &self,
    ) -> Result<(OwnedFd, OwnedFd, OwnedFd), QemuSpawnError> {
        let cgroup_directory = self
            .cgroup_directory
            .as_ref()
            .ok_or_else(|| QemuSpawnError::Io {
                operation: "duplicate hot-fork cgroup directory",
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "test-only process contract has no cgroup directory",
                ),
            })?
            .try_clone()
            .map_err(|source| QemuSpawnError::Io {
                operation: "duplicate hot-fork cgroup directory",
                source,
            })?;
        let cgroup_procs = self
            .cgroup_procs
            .try_clone()
            .map_err(|source| QemuSpawnError::Io {
                operation: "duplicate hot-fork cgroup.procs descriptor",
                source,
            })?;
        let cancellation_event =
            self.cancellation_event
                .try_clone()
                .map_err(|source| QemuSpawnError::Io {
                    operation: "duplicate hot-fork cancellation eventfd",
                    source,
                })?;
        Ok((cgroup_directory, cgroup_procs, cancellation_event))
    }

    pub(crate) const fn maximum_writable_bytes(&self) -> u64 {
        self.maximum_writable_bytes
    }
}

/// Host-side descriptors retained after spawning a QEMU child.
#[derive(Debug)]
pub struct QemuSpawnHostResources {
    control_socket: OwnedFd,
    ram_control_socket: Option<OwnedFd>,
    ram_source_socket: Option<OwnedFd>,
    ram_control: Option<crate::QemuRamControlLaunch>,
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
    region_len: u64,
    fault_node_hash: [u8; 32],
    process_generation: u64,
    #[cfg(target_os = "linux")]
    preexec_receipt: Option<crucible_qemu_protocol::PreexecSetupHandover>,
    #[cfg(target_os = "linux")]
    device_digest_workspace: Option<Arc<DeviceDigestWorkspaceBody>>,
    service_lease: Option<crucible_host_resources::host_services::HostServiceLease>,
    launch_cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
}

impl QemuSpawnHostResources {
    #[cfg(target_os = "linux")]
    pub(crate) fn retain_device_digest_workspace(&mut self, body: Arc<DeviceDigestWorkspaceBody>) {
        self.device_digest_workspace = Some(body);
    }

    // Copy the same identity that was validated and emitted before child birth.
    fn bind_plugin_launch(&mut self, command: &QemuLaunchCommand) {
        self.fault_node_hash = command.plugin_fault_node_hash();
        self.process_generation = command.plugin_process_generation();
        self.ram_control = command.ram_control();
    }

    pub(crate) fn retain_launch_cleanup(&mut self, cleanup: crate::launch_cleanup::LaunchCleanup) {
        self.launch_cleanup = Some(cleanup);
    }
    /// Returns shared retained authority for this launch's descriptor peak.
    #[must_use]
    pub fn host_service_lease(
        &self,
    ) -> Option<&crucible_host_resources::host_services::HostServiceLease> {
        self.service_lease.as_ref()
    }

    /// Takes the independent pager-control endpoint and its authenticated setup.
    ///
    /// Callers retain this separately from QMP and the execution control stream.
    pub fn take_ram_control_socket(&mut self) -> Option<(UnixStream, crate::QemuRamControlLaunch)> {
        let setup = self.ram_control?;
        self.ram_control_socket
            .take()
            .map(|fd| (UnixStream::from(fd), setup))
    }

    /// Takes the independent lazy authenticated RAM-source endpoint.
    ///
    /// The source owner supplies its fresh binding before restore or fork readiness.
    pub fn take_ram_source_socket(&mut self) -> Option<UnixStream> {
        self.ram_source_socket.take().map(UnixStream::from)
    }

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
            ram_control_socket: self.ram_control_socket,
            ram_source_socket: self.ram_source_socket,
            ram_control: self.ram_control,
            service_lease: self.service_lease,
            shmem_fd: self.shmem_fd,
            wake_fd: self.wake_fd,
            region_len: self.region_len,
            fault_node_hash: self.fault_node_hash,
            process_generation: self.process_generation,
            #[cfg(target_os = "linux")]
            preexec_receipt: self.preexec_receipt,
            #[cfg(target_os = "linux")]
            device_digest_workspace: self.device_digest_workspace,
            launch_cleanup: self.launch_cleanup,
        }
    }
}

/// Host-side descriptors in the shape required by the setup protocol driver.
#[derive(Debug)]
pub struct QemuSpawnSetupResources {
    control_socket: UnixStream,
    ram_control_socket: Option<OwnedFd>,
    ram_source_socket: Option<OwnedFd>,
    ram_control: Option<crate::QemuRamControlLaunch>,
    shmem_fd: OwnedFd,
    wake_fd: OwnedFd,
    region_len: u64,
    fault_node_hash: [u8; 32],
    process_generation: u64,
    #[cfg(target_os = "linux")]
    preexec_receipt: Option<crucible_qemu_protocol::PreexecSetupHandover>,
    #[cfg(target_os = "linux")]
    device_digest_workspace: Option<Arc<DeviceDigestWorkspaceBody>>,
    service_lease: Option<crucible_host_resources::host_services::HostServiceLease>,
    launch_cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
}

impl QemuSpawnSetupResources {
    #[cfg(target_os = "linux")]
    pub(crate) fn take_preexec_receipt(
        &mut self,
    ) -> Option<crucible_qemu_protocol::PreexecSetupHandover> {
        self.preexec_receipt.take()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn take_device_digest_workspace(
        &mut self,
    ) -> Option<Arc<DeviceDigestWorkspaceBody>> {
        self.device_digest_workspace.take()
    }

    /// Returns the same generation retained from the validated launch command.
    pub(crate) const fn process_generation(&self) -> u64 {
        self.process_generation
    }

    pub(crate) fn launch_cleanup(&self) -> Option<crate::launch_cleanup::LaunchCleanup> {
        self.launch_cleanup.clone()
    }
    /// Returns shared retained authority for this launch's descriptor peak.
    #[must_use]
    pub fn host_service_lease(
        &self,
    ) -> Option<&crucible_host_resources::host_services::HostServiceLease> {
        self.service_lease.as_ref()
    }

    /// Takes the independent pager-control endpoint and its authenticated setup.
    ///
    /// Callers retain this separately from QMP and the execution control stream.
    pub fn take_ram_control_socket(&mut self) -> Option<(UnixStream, crate::QemuRamControlLaunch)> {
        let setup = self.ram_control?;
        self.ram_control_socket
            .take()
            .map(|fd| (UnixStream::from(fd), setup))
    }

    /// Takes the independent lazy authenticated RAM-source endpoint.
    ///
    /// The source owner supplies its fresh binding before restore or fork readiness.
    pub fn take_ram_source_socket(&mut self) -> Option<UnixStream> {
        self.ram_source_socket.take().map(UnixStream::from)
    }

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
    pub(crate) fn into_parts(
        self,
    ) -> (
        UnixStream,
        OwnedFd,
        OwnedFd,
        u64,
        [u8; 32],
        Option<crate::launch_cleanup::LaunchCleanup>,
    ) {
        (
            self.control_socket,
            self.shmem_fd,
            self.wake_fd,
            self.region_len,
            self.fault_node_hash,
            self.launch_cleanup,
        )
    }
}

/// A spawned QEMU child plus the host descriptors retained for its node.
#[derive(Debug)]
pub struct QemuSpawnedChild {
    child: QemuNodeChild,
    resources: QemuSpawnHostResources,
}

/// Reports guarded preparation while its issued recipient retains every child.
///
/// The error never owns a process. The constructor-bound Source keeps any
/// unsettled helper in its original preborn slot through later cleanup.
#[derive(Debug, Error)]
#[error("{source}")]
pub struct QemuGuardedImagePreparationError {
    pub(super) source: QemuSpawnError,
    #[cfg(target_os = "linux")]
    receiver: Option<QemuIssuedHelperReceiver>,
}

impl QemuGuardedImagePreparationError {
    pub(super) fn local(source: QemuSpawnError) -> Self {
        Self {
            source,
            #[cfg(target_os = "linux")]
            receiver: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn issued(
        source: QemuSpawnError,
        receiver: &crate::linux_attempt_host::SourceCleanupLender,
    ) -> Self {
        Self {
            source,
            receiver: Some(QemuIssuedHelperReceiver::from_lender(receiver.clone())),
        }
    }

    /// Borrows the actual first helper failure without replacing its type.
    #[must_use]
    pub fn first_cause(&self) -> &QemuSpawnError {
        match &self.source {
            QemuSpawnError::HelperFailure { first } => first.source_ref(),
            source => source,
        }
    }

    /// Clones the saved nominal recipient without inferring current custody.
    ///
    /// An unavailable Source remains a retained cleanup obligation. Callers
    /// must resolve this identity before attempting any recipient operation.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn retained_receiver_identity(&self) -> Option<QemuIssuedHelperReceiver> {
        self.receiver.clone()
    }

    /// Returns the existing issued recipient that retains helper disposition.
    ///
    /// This observer creates neither a process nor an operation or return loan.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn retained_receiver(
        &self,
    ) -> Option<crate::linux_attempt_host::RetainedNativeFreshLaunchError> {
        self.receiver
            .as_ref()
            .and_then(QemuIssuedHelperReceiver::upgrade)
    }

    /// Projects the original helper's independent first, post and cleanup causes.
    ///
    /// # Errors
    /// Refuses absent, expired, contended or poisoned issued helper custody.
    ///
    /// # Panics
    /// Propagates a projection panic while retaining the original journal;
    /// subsequent access refuses its poisoned mutex.
    #[cfg(target_os = "linux")]
    pub fn with_retained_history<T>(
        &self,
        apply: impl for<'a> FnOnce(crate::linux_attempt_host::QemuIssuedHelperHistory<'a>) -> T,
    ) -> Result<T, crate::linux_attempt_host::OriginalActorAccountError> {
        let receiver = self
            .retained_receiver()
            .ok_or(crate::linux_attempt_host::OriginalActorAccountError::Unavailable)?;
        receiver.with_helper_history(apply)
    }

    /// Observes known helper return without inferring absence from contention.
    ///
    /// # Errors
    /// Refuses unavailable access to the original issued recipient.
    #[cfg(target_os = "linux")]
    pub fn retained_helper_process(
        &self,
    ) -> Result<Option<u32>, crate::linux_attempt_host::OriginalActorAccountError> {
        match self.receiver.as_ref() {
            Some(receiver) => receiver
                .upgrade()
                .ok_or(crate::linux_attempt_host::OriginalActorAccountError::Unavailable)?
                .retained_helper_process(),
            None => Ok(None),
        }
    }
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
    /// The containing launch's physical child-return slot was already consumed.
    #[error("the original child-return recipient is unavailable")]
    ChildReturnUnavailable,
    /// The constructor-bound helper recipient is unavailable or occupied.
    ///
    /// This custody refusal retains no boxed I/O error or diagnostic allocation.
    #[error("retain guarded helper failed: issued helper custody is unavailable or still occupied")]
    HelperCustodyUnavailable,
    /// Shares the actual first helper error with its issued physical recipient.
    #[error("issued helper failed: {first:?}")]
    HelperFailure {
        /// Same concrete first error; its separately owned payload stays live.
        #[source]
        first: QemuIssuedHelperFailure,
    },
    /// The real Source host owner refused custody before or after process birth.
    #[error("authenticated Source custody refused: {source}")]
    SourceHost {
        /// Actual Main resource or kernel-custody cause.
        #[source]
        source: crucible_host_resources::host_services::process_birth::ServiceBirthError,
    },
    /// The actual Source spawn control reservation refused before any socket birth.
    #[error("Source spawn admission refused: {source}")]
    SourceAdmission {
        /// The actual initiating nominal account refusal.
        #[source]
        source: crate::linux_attempt_host::OriginalActorAccountError,
    },
    /// The active original configuration account refused before allocation.
    #[error("QEMU configuration admission refused: {0}")]
    ConfigurationAdmission(#[source] crucible_engine::owned_decode::DecodeAdmissionError),
    /// The actual supervisor group inventory exceeded its source bound.
    #[error("supervisor supplementary groups exceed the supported bound")]
    SupervisorGroupLimit,
    /// The actual supervisor group inventory changed during inspection.
    #[error("supervisor supplementary groups changed while inspected")]
    SupervisorGroupsChanged,
    /// The guarded environment does not preserve the matched worker request.
    #[error("guarded QEMU worker stack profile is unsupported")]
    UnsupportedWorkerStackProfile,
    /// Explicit per-node host service descriptor admission failed before allocation.
    #[error(transparent)]
    HostServices {
        /// Original independently configured service capacity refusal.
        #[from]
        source: crucible_host_resources::host_services::HostServiceError,
    },
    /// The actual registered startup refused before selected native birth.
    #[error("registered startup refused: {source}")]
    PluginStartup {
        /// The original typed startup cause and retained control loan.
        #[source]
        source: PluginStartupError,
    },
    /// The actual original Setup refused an independent boundary check.
    #[error("original Setup refused: {source}")]
    OriginalStartup {
        /// The unchanged original cancellation or deadline cause.
        #[source]
        source: crucible_host_resources::host_supervision::HostSupervisionError,
    },
    /// The sole selected plan or descriptor handover refused with its owner.
    #[error("pre-exec handover refused: {source}")]
    Preexec {
        /// The first cause, independent postcut and actual retained aliases.
        #[source]
        source: PreexecSetupError,
    },
    /// The selected region exceeds the prepaid encoder overlap or fixed topology.
    #[error("selected pre-exec region {region_len} does not fit its funded single-node encoder")]
    PreexecRegionUnsupported {
        /// Actual requested region size, which grants no additional credit.
        region_len: u64,
    },
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
    /// A guarded image-tool helper exited unsuccessfully.
    #[error("guarded qemu-img operation `{operation}` failed with {status}")]
    GuardedImageTool {
        /// Stable preparation operation.
        operation: &'static str,
        /// Actual process exit status, retained without formatting allocation.
        status: std::process::ExitStatus,
    },
    /// The owned helper had already been reaped before a natural-wait poll.
    #[error("{operation} failed: helper child was already reaped")]
    HelperAlreadyReaped {
        /// Operation being attempted.
        operation: &'static str,
    },
    /// A guarded image-tool helper exceeded its absolute execution deadline.
    #[error("guarded qemu-img operation `{operation}` exceeded its execution deadline")]
    GuardedImageToolTimeout {
        /// Stable preparation operation.
        operation: &'static str,
    },
    /// A guarded QEMU setup probe exceeded its absolute execution deadline.
    #[error("guarded QEMU setup probe exceeded its execution deadline")]
    GuardedQemuProbeTimeout,
    /// A guarded QEMU setup probe exceeded its bounded diagnostic output.
    #[error("guarded QEMU setup probe exceeded its {maximum_bytes}-byte output limit")]
    GuardedQemuProbeOutputLimit {
        /// Maximum bytes retained independently for stdout and stderr.
        maximum_bytes: usize,
    },
    /// A fixed diagnostic trace had the wrong filesystem identity.
    #[error(
        "diagnostic trace `{file}` metadata is invalid: type={file_type_mode:o} links={links} owner={user_id}:{group_id} mode={mode:o}"
    )]
    DiagnosticTraceMetadata {
        /// Fixed trace file name.
        file: &'static str,
        /// Observed file-type mode bits.
        file_type_mode: u32,
        /// Observed hard-link count.
        links: u64,
        /// Observed owning user.
        user_id: libc::uid_t,
        /// Observed owning group.
        group_id: libc::gid_t,
        /// Observed permission and special-mode bits.
        mode: u32,
    },
    /// A fixed diagnostic trace was empty or exceeded its byte limit.
    #[error("diagnostic trace `{file}` length {actual} is outside maximum {maximum}")]
    DiagnosticTraceLength {
        /// Fixed trace file name.
        file: &'static str,
        /// Observed byte length.
        actual: u64,
        /// Fixed maximum byte length.
        maximum: u64,
    },
    /// A fixed diagnostic trace exceeded its line limit.
    #[error("diagnostic trace `{file}` line count {actual} is outside maximum {maximum}")]
    DiagnosticTraceLines {
        /// Fixed trace file name.
        file: &'static str,
        /// Observed newline count.
        actual: usize,
        /// Fixed maximum newline count.
        maximum: usize,
    },
    /// A streamed diagnostic trace contained an invalid complete row.
    #[error("diagnostic trace `{file}` row {line} is malformed: {reason}")]
    DiagnosticTraceMalformed {
        /// Fixed trace file name.
        file: &'static str,
        /// One-based row number.
        line: usize,
        /// Failed row invariant.
        reason: &'static str,
    },
    /// The fixed trace and launch artifacts exceeded aggregate storage admission.
    #[error(
        "diagnostic trace `{file}` uses {trace_bytes} bytes outside aggregate writable maximum {maximum}"
    )]
    DiagnosticTraceExceedsAdmission {
        /// Fixed trace file name.
        file: &'static str,
        /// Trace bytes counted with the other launch artifacts.
        trace_bytes: u64,
        /// Aggregate attempt ceiling.
        maximum: u64,
    },
    /// The fixed trace name or inode changed while being retained.
    #[error("diagnostic trace `{file}` changed during retention")]
    DiagnosticTraceChanged {
        /// Fixed trace file name.
        file: &'static str,
    },
    /// The fixed trace was not valid UTF-8 text.
    #[error("diagnostic trace `{file}` is not UTF-8: {source}")]
    DiagnosticTraceUtf8 {
        /// Fixed trace file name.
        file: &'static str,
        /// UTF-8 decoding failure.
        #[source]
        source: std::string::FromUtf8Error,
    },
    /// A disk-backed fresh launch omitted its immutable root image.
    #[error("fresh disk-backed QEMU preparation requires one root image")]
    FreshRootImageMissing,
    /// A diskless fresh launch was paired with an unexpected root image.
    #[error("diskless fresh QEMU preparation received an unexpected root image")]
    FreshRootImageUnexpected,
    /// Guarded fresh preparation requires a path immune to cwd changes.
    #[error("guarded qemu-img path must be absolute: {path}")]
    FreshImageToolPath {
        /// Rejected adjacent image-tool path.
        path: PathBuf,
    },
    /// The immutable root image has no bytes.
    #[error("fresh QEMU root image is empty: {path}")]
    FreshRootImageEmpty {
        /// Root-image path used only for diagnostics.
        path: PathBuf,
    },
    /// Fresh image-tool output has not been completely sealed.
    #[error("fresh QEMU generation artifacts are not ready: {path}")]
    FreshArtifactsNotReady {
        /// Descriptor-pinned generation path used only for diagnostics.
        path: PathBuf,
    },
    /// The guarded run directory lacks its pre-provisioned device-state container.
    #[error("guarded QEMU launch requires pre-provisioned device-state container {path}")]
    MissingPreparedDeviceState {
        /// Required device-state container path.
        path: PathBuf,
    },
    /// The retained run-directory descriptor no longer names its opened inode.
    #[error("prepared QEMU run-directory identity changed: {path}")]
    PreparedRunDirectoryChanged {
        /// Original diagnostic path of the pinned directory.
        path: PathBuf,
    },
    /// The device-state name no longer resolves to the retained regular file.
    #[error("prepared device-state identity changed: {path}")]
    PreparedDeviceStateChanged {
        /// Original diagnostic path of the device-state container.
        path: PathBuf,
    },
    /// The command, admitted ceiling, or attempt lifecycle differs from preparation.
    #[error("prepared QEMU run directory is bound to a different launch admission")]
    PreparedLaunchAdmissionChanged,
    /// A prepared writable artifact has an invalid length.
    #[error("prepared QEMU artifact is not ready: {path}")]
    PreparedArtifactNotReady {
        /// Descriptor-pinned artifact path used only for diagnostics.
        path: PathBuf,
    },
    /// The complete prepared artifact pair exceeds the aggregate quota.
    #[error(
        "prepared artifacts use {device_state_bytes} device-state bytes and {root_overlay_bytes} root-overlay bytes, above maximum {maximum}"
    )]
    PreparedArtifactsTooLarge {
        /// Logical device-state bytes.
        device_state_bytes: u64,
        /// Logical root-overlay bytes.
        root_overlay_bytes: u64,
        /// Admitted aggregate writable-byte ceiling.
        maximum: u64,
    },
    /// A declared exact restore exceeds the aggregate writable-byte admission.
    #[error(
        "exact checkpoint artifacts use {device_state_bytes} device-state bytes, {root_overlay_bytes} root-overlay bytes, and {ram_bytes} RAM bytes, above maximum {maximum}"
    )]
    PreparedExactCheckpointArtifactsTooLarge {
        /// Declared device-state bytes.
        device_state_bytes: u64,
        /// Declared root-overlay bytes.
        root_overlay_bytes: u64,
        /// Sum of every declared RAM layer.
        ram_bytes: u64,
        /// Admitted aggregate writable-byte ceiling.
        maximum: u64,
    },
    /// Exact-checkpoint admission metadata could not be allocated.
    #[error("exact checkpoint artifact-set admission allocation failed")]
    PreparedExactCheckpointAdmissionAllocation,
    /// An exact-checkpoint materialization set is incomplete.
    #[error("prepared exact-checkpoint materialization is not ready: {path}")]
    PreparedExactCheckpointNotReady {
        /// Pinned generation path used only for diagnostics.
        path: PathBuf,
    },
    /// The exact device-state input has an invalid declared byte length.
    #[error(
        "prepared exact device-state length {length} is outside the admitted maximum {maximum}"
    )]
    PreparedDeviceStateLength {
        /// Declared exact checkpoint bytes.
        length: u64,
        /// Admitted aggregate writable-byte ceiling.
        maximum: u64,
    },
    /// The exact device-state input is absent or incomplete.
    #[error("prepared sealed device-state input is absent or incomplete")]
    PreparedDeviceStateNotReady,
    /// A materialized exact descriptor input is shorter or longer than declared.
    #[error("prepared exact input is incomplete: expected {expected} bytes, found {actual}")]
    PreparedExactInputIncomplete {
        /// Declared complete checkpoint length.
        expected: u64,
        /// Bytes written or found in the pinned file.
        actual: u64,
    },
    /// The root-overlay name no longer resolves to the retained regular file.
    #[error("prepared root-overlay identity changed: {path}")]
    PreparedRootOverlayChanged {
        /// Original diagnostic path of the root overlay.
        path: PathBuf,
    },
    /// The exact root overlay has an invalid declared byte length.
    #[error(
        "prepared exact root-overlay length {length} is outside the admitted maximum {maximum}"
    )]
    PreparedRootOverlayLength {
        /// Declared exact checkpoint bytes.
        length: u64,
        /// Conservative aggregate writable-byte share.
        maximum: u64,
    },
    /// The exact root-overlay destination already exists.
    #[error("prepared exact root-overlay destination already exists: {path}")]
    PreparedRootOverlayAlreadyExists {
        /// Pinned root-overlay path used only for diagnostics.
        path: PathBuf,
    },
    /// The exact root overlay is absent or remains incomplete.
    #[error("prepared exact root-overlay materialization is not ready: {path}")]
    PreparedRootOverlayNotReady {
        /// Pinned root-overlay path used only for diagnostics.
        path: PathBuf,
    },
    /// The materialized root overlay is shorter or longer than declared.
    #[error("prepared exact root overlay is incomplete: expected {expected} bytes, found {actual}")]
    PreparedRootOverlayIncomplete {
        /// Declared complete checkpoint length.
        expected: u64,
        /// Bytes written or found in the pinned file.
        actual: u64,
    },
    /// The guarded child would retain root or a supervisor credential.
    #[error(
        "QEMU child credentials must be non-root and distinct from the supervisor: {user_id}:{group_id}"
    )]
    InvalidChildCredentials {
        /// Requested child user ID.
        user_id: libc::uid_t,
        /// Requested child group ID.
        group_id: libc::gid_t,
    },
    /// The validated launch command exceeds the attempt's admitted ceiling.
    #[error("QEMU launch exceeds admitted attempt resources: {source}")]
    LaunchResources {
        /// Exact launch-resource mismatch.
        source: crate::QemuLaunchResourceError,
    },
    /// The spill filesystem would retain externalized RAM in host memory.
    #[error("RAM spill storage uses an unsupported memory filesystem: {filesystem_type:#x}")]
    RamSpillMemoryFilesystem {
        /// Linux filesystem type reported by the pinned descriptor.
        filesystem_type: i64,
    },
    /// The private spill file lacks a valid admitted backing quota.
    #[error("RAM spill backing quota is invalid: {bytes}")]
    InvalidRamSpillQuota {
        /// Requested private backing bytes.
        bytes: u64,
    },
}

impl QemuSpawnError {
    /// Moves the actual helper wait cause without formatting or rebuilding I/O.
    pub(crate) fn from_helper_wait(
        operation: &'static str,
        failure: crate::node::ChildNaturalWaitFailure,
    ) -> Self {
        match failure {
            crate::node::ChildNaturalWaitFailure::AlreadyReaped => {
                Self::HelperAlreadyReaped { operation }
            }
            crate::node::ChildNaturalWaitFailure::Io(source) => Self::Io { operation, source },
        }
    }
}

/// Spawns QEMU from an already-provisioned run directory under `contract`.
///
/// This fixed-FD operation never invokes `qemu-img` or creates the exact-VMState
/// container. The supervisor must provision and validate that container under
/// its own bounded service policy before admitting the attempt. Before
/// revalidating that authority, this path validates the command's fixed
/// resource baseline against the ceilings sealed into `contract`. The child
/// writes itself into the attempt cgroup and checks cancellation in `pre_exec`,
/// before QEMU executes.
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when the launch exceeds its admitted resources,
/// the prepared container is absent or not a regular file, descriptor
/// preparation fails, the pre-exec containment contract rejects the child, or
/// QEMU cannot be spawned.
pub(crate) fn spawn_prepared_qemu_child_with_fds_in_directory_guarded(
    command: &QemuLaunchCommand,
    run_directory: &QemuPreparedRunDirectory,
    region_len: u64,
    contract: &QemuChildProcessContract,
    host_services: Option<&crucible_host_resources::host_services::HostServiceAllocator>,
    launch_cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
) -> Result<QemuSpawnedChild, QemuSpawnError> {
    spawn_prepared_qemu_child_with_preexec(PreparedQemuChildLaunch {
        command,
        run_directory,
        region_len,
        contract,
        host_services,
        launch_cleanup,
        preexec: None,
        child_return: None,
    })
}

/// Retains the inputs to one guarded child birth and its existing return slot.
///
/// Constructing this record borrows the already-admitted launch basis and
/// transfers the same cleanup alias; it does not reserve or issue resources.
pub(crate) struct PreparedQemuChildLaunch<'a> {
    /// Command whose fixed resource baseline must match the process contract.
    pub(crate) command: &'a QemuLaunchCommand,
    /// Existing pinned run directory revalidated before descriptor creation.
    pub(crate) run_directory: &'a QemuPreparedRunDirectory,
    /// Admitted shared-region extent checked against pre-exec requirements.
    pub(crate) region_len: u64,
    /// Sealed process resource and containment contract.
    pub(crate) contract: &'a QemuChildProcessContract,
    /// Existing service allocator used for the fixed launch descriptor lease.
    pub(crate) host_services:
        Option<&'a crucible_host_resources::host_services::HostServiceAllocator>,
    /// Same-original cleanup control retained across birth and failure.
    pub(crate) launch_cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
    /// Borrowed native startup and descriptor handover inputs, when selected.
    pub(crate) preexec: Option<preexec_setup::BorrowedPreexecSetup<'a>>,
    /// Existing reservation that receives the child immediately after birth.
    pub(crate) child_return: Option<&'a mut crate::node::SourceLaunchReservation>,
}

/// Spawns one prepared child through its retained pre-exec and return inputs.
///
/// # Errors
///
/// Returns the original launch, resource, descriptor or containment refusal.
/// Missing child-return custody is rejected before resource construction.
pub(crate) fn spawn_prepared_qemu_child_with_preexec(
    launch: PreparedQemuChildLaunch<'_>,
) -> Result<QemuSpawnedChild, QemuSpawnError> {
    let PreparedQemuChildLaunch {
        command,
        run_directory,
        region_len,
        contract,
        host_services,
        launch_cleanup,
        preexec,
        child_return,
    } = launch;

    GuardedWorkerStackProfile::for_environment(command.diagnostic_envs())
        .ok_or(QemuSpawnError::UnsupportedWorkerStackProfile)?;

    run_directory.validate_launch_basis(command, contract)?;
    let child_return = child_return.ok_or_else(helper_receiver::helper_custody_refusal)?;
    run_directory.revalidate()?;
    if let Some(selected) = preexec.as_ref() {
        selected
            .startup
            .require_preexec_receiver()
            .map_err(|source| QemuSpawnError::PluginStartup { source })?;
        if region_len == 0
            || region_len
                > crucible_qemu_protocol::plugin_setup_plan::PLUGIN_SETUP_PLAN_MAX_BYTES as u64
            || selected.region_config.vm_node_count != 1
        {
            return Err(QemuSpawnError::PreexecRegionUnsupported { region_len });
        }
    }
    let spill_quota = if command.ram_control().is_some() {
        let bytes = command.ram_backing_quota_bytes().unwrap_or(0);
        if bytes < 4096 || bytes > contract.maximum_writable_bytes {
            return Err(QemuSpawnError::InvalidRamSpillQuota { bytes });
        }
        Some(bytes)
    } else {
        None
    };
    // Reserve the same selected owner before endpoint birth and binder landing.
    // Declaring it first keeps its final control after the physical pair locals.
    let mut prepared_preexec = preexec
        .as_ref()
        .map(|selected| {
            let cleanup = launch_cleanup
                .as_ref()
                .ok_or(QemuSpawnError::RegionLengthZero)?
                .clone();
            preexec_setup::PreparedPreexecSetup::reserve(selected.startup, cleanup)
                .map_err(|source| QemuSpawnError::Preexec { source })
        })
        .transpose()?;
    let mut child_return_recipient = if let Some(cleanup) = launch_cleanup.as_ref() {
        Some(
            cleanup
                .claim_child_return()
                .ok_or(QemuSpawnError::ChildReturnUnavailable)?,
        )
    } else {
        None
    };

    // Three socket pairs, three temporary duplicated child endpoints, two
    // shared-memory descriptors, two wake descriptors, and three image pins.
    let service_lease = host_services
        .map(|services| services.reserve_resources(0, 16, 0))
        .transpose()
        .map_err(|source| QemuSpawnError::HostServices { source })?;
    if let Some(selected) = preexec.as_ref() {
        launch_cleanup
            .as_ref()
            .ok_or(QemuSpawnError::RegionLengthZero)?
            .reserve_source_spawn_controls(
                selected
                    .startup
                    .admission()
                    .map_err(OriginalPluginStartup::state_refusal)
                    .map_err(|source| QemuSpawnError::PluginStartup { source })?,
            )
            .map_err(|source| QemuSpawnError::SourceAdmission { source })?;
    }
    let source_purpose = preexec
        .as_ref()
        .map(|selected| {
            selected
                .startup
                .admission()
                .map(|admission| admission.host_purpose().clone())
        })
        .transpose()
        .map_err(OriginalPluginStartup::state_refusal)
        .map_err(|source| QemuSpawnError::PluginStartup { source })?;
    let image_pins = GuardedLaunchImagePins::new(run_directory)?;
    let launch_args = guarded_launch_args(
        command.args(),
        image_pins.overlay.is_some(),
        run_directory.path(),
    )?;
    let (mut resources, mut child_resources) = create_spawn_resources(region_len)?;
    resources.service_lease = service_lease;
    resources.bind_plugin_launch(command);
    if let Some(cleanup) = &launch_cleanup {
        resources.retain_launch_cleanup(cleanup.clone());
    }
    if let Some(bytes) = spill_quota {
        child_resources.ram_spill = Some(ram_spill::create_private_spill(
            &run_directory.directory,
            bytes,
        )?);
    }
    if let Some(preexec) = preexec {
        let ram_endpoint =
            child_resources.issue_ram_control_endpoint(&resources, command, contract, &preexec)?;
        let owner = prepared_preexec.take().ok_or_else(|| QemuSpawnError::Io {
            operation: "retain prepaid selected pre-exec owner",
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "selected pre-exec owner was consumed before endpoint sealing",
            ),
        })?;
        let owner = owner
            .prepare(
                &preexec,
                preexec_setup::PreexecSetupMaterial {
                    contract,
                    ram_endpoint: ram_endpoint.as_ref(),
                    plan: command.plugin_setup_plan(),
                    region_len,
                    shmem: &resources.shmem_fd,
                    wake: &resources.wake_fd,
                },
            )
            .map_err(|source| QemuSpawnError::Preexec { source })?;
        let mut owner = owner
            .queue(&resources.control_socket, preexec.startup)
            .map_err(|source| QemuSpawnError::Preexec { source })?;
        resources.preexec_receipt = owner.take_receipt();
        prepared_preexec = Some(owner);
    }
    let selected_preexec = prepared_preexec.is_some();
    if selected_preexec {
        // A failed spawn can follow a successful fork or partial pre-exec.
        // Until actual reap is known, queued aliases and their original owner
        // must not retire as a never-started launch.
        if let Some(cleanup) = launch_cleanup.as_ref() {
            cleanup.child_started();
        }
    }
    if let Some(purpose) = source_purpose.as_ref() {
        purpose
            .begin_birth()
            .map_err(|source| QemuSpawnError::SourceHost { source })?;
    }
    let child = spawn_process_with_resources(
        command.executable(),
        &launch_args,
        run_directory,
        child_resources,
        &image_pins,
        command.diagnostic_envs(),
        Some(BorrowedSpawnProcessContract {
            process: contract,
            startup: command.plugin_setup_plan().startup_operation(),
            selected_preexec,
        }),
    )?;
    let mut child = match source_purpose.as_ref() {
        Some(purpose) => match purpose.retain_child(child) {
            Ok(child) => QemuNodeChild::from_authenticated_source(child),
            Err((child, source)) => {
                let mut child = QemuNodeChild::new(child);
                if let Some(recipient) = child_return_recipient.take() {
                    child.retain_child_return(recipient);
                }
                if let Some(cleanup) = launch_cleanup {
                    child.retain_launch_cleanup(cleanup);
                }
                if let Some(owner) = prepared_preexec.take() {
                    child.retain_preexec_setup(owner);
                }
                child_return.retain_failed_child(child);
                return Err(QemuSpawnError::SourceHost { source });
            }
        },
        None => QemuNodeChild::new(child),
    };
    if let Some(recipient) = child_return_recipient.take() {
        child.retain_child_return(recipient);
    }
    if let Some(owner) = prepared_preexec.take() {
        child.retain_preexec_setup(owner);
    }
    if let Some(cleanup) = launch_cleanup {
        child.retain_launch_cleanup(cleanup);
    }
    Ok(QemuSpawnedChild { child, resources })
}

pub(crate) fn validate_guarded_launch_resources(
    command: &QemuLaunchCommand,
    contract: &QemuChildProcessContract,
) -> Result<(), QemuSpawnError> {
    validate_guarded_launch_requirements(command.resource_requirements(), contract)
}

pub(crate) fn validate_guarded_launch_requirements(
    requirements: crate::QemuLaunchResourceRequirements,
    contract: &QemuChildProcessContract,
) -> Result<(), QemuSpawnError> {
    requirements
        .validate_ceiling(
            contract.maximum_vcpus,
            contract.effective_resident_bytes(),
            contract.maximum_writable_bytes,
        )
        .map_err(|source| QemuSpawnError::LaunchResources { source })
}
#[derive(Debug)]
struct QemuSpawnChildResources {
    control_socket: OwnedFd,
    ram_control_socket: OwnedFd,
    ram_source_socket: OwnedFd,
    ram_spill: Option<OwnedFd>,
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
    let (host_ram_control, child_ram_control) = socket_pair()?;
    let (host_ram_source, child_ram_source) = socket_pair()?;
    let child_ram_control =
        duplicate_cloexec_fd(child_ram_control.as_raw_fd(), "duplicate pager control fd")?;
    let child_ram_source =
        duplicate_cloexec_fd(child_ram_source.as_raw_fd(), "duplicate RAM source fd")?;
    let child_control =
        duplicate_cloexec_fd(child_control.as_raw_fd(), "duplicate plugin control fd")?;
    let host_shmem = memfd_region(region_len)?;
    let child_shmem = duplicate_cloexec_fd(host_shmem.as_raw_fd(), "duplicate shmem fd")?;
    let host_wake = event_fd()?;
    let child_wake = duplicate_cloexec_fd(host_wake.as_raw_fd(), "duplicate wake fd")?;

    Ok((
        QemuSpawnHostResources {
            control_socket: host_control,
            ram_control_socket: Some(host_ram_control),
            ram_source_socket: Some(host_ram_source),
            ram_control: None,
            launch_cleanup: None,
            service_lease: None,
            shmem_fd: host_shmem,
            wake_fd: host_wake,
            region_len,
            fault_node_hash: [0; 32],
            process_generation: 0,
            #[cfg(target_os = "linux")]
            preexec_receipt: None,
            #[cfg(target_os = "linux")]
            device_digest_workspace: None,
        },
        QemuSpawnChildResources {
            control_socket: child_control,
            ram_control_socket: child_ram_control,
            ram_source_socket: child_ram_source,
            ram_spill: None,
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
    // This explicit standalone fixture models its existing first generation.
    host_resources.process_generation = 1;
    Ok((
        host_resources,
        UnixStream::from(child_resources.control_socket),
    ))
}

/// Initializes and prequeues real transport fixtures without issuing native authority.
///
/// # Errors
/// Returns actual layout, descriptor, serialization, sealing or one-shot send errors.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn prepare_test_preexec_setup(
    resources: &mut QemuSpawnHostResources,
    config: crucible_qemu_shmem::RegionConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use crucible_qemu_protocol::plugin_setup_plan::{
        PluginSetupPlan, StartupOperation, StartupOperationFields,
    };
    use std::os::unix::fs::FileExt as _;

    if resources.preexec_receipt.is_some() {
        return Err("fixture setup was already queued".into());
    }
    let region = crucible_qemu_shmem::RegionAllocation::new(config)?;
    let bytes = region.setup_region_bytes()?;
    if bytes.len() as u64 > resources.region_len {
        return Err("fixture region does not fit its actual backing".into());
    }
    let shmem = fs::File::from(resources.shmem_fd.try_clone()?);
    shmem.write_all_at(&bytes, 0)?;
    drop(shmem);

    // These syntax-only fields deliberately do not name an issued native account
    // or usable original. The fixture qualifies transport, never native startup.
    let startup = StartupOperation::new(StartupOperationFields {
        cap_id: [0xa1; 32],
        operation_id: 1,
        original_start_ns: 1,
        absolute_end_ns: 2,
        poll_ns: 1,
        process_generation: resources.process_generation,
        cancellation_device: 0,
        cancellation_inode: 1,
        cancellation_event_id: 1,
        cancellation_descriptor: resources.wake_fd.as_raw_fd(),
        original_total_metadata_bytes: 4096,
    })?;
    let mut purpose = [0_u8; crucible_qemu_protocol::plugin_setup_plan::PROCESS_PURPOSE_BYTES];
    purpose[..8].copy_from_slice(b"CRUCPUR8");
    purpose[8..12].copy_from_slice(&8_u32.to_be_bytes());
    purpose[12..16].copy_from_slice(
        &(crucible_qemu_protocol::plugin_setup_plan::PROCESS_PURPOSE_BYTES as u32).to_be_bytes(),
    );
    for (offset, value) in [
        (16, 4096_u64),
        (96, resources.process_generation),
        (520, 1),
        (528, 1),
        (536, 100_000),
        (544, 1),
        (552, 1),
        (560, 1),
    ] {
        purpose[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    purpose[184..216].copy_from_slice(&startup.fields().cap_id);
    // Syntax-only reservations exercise the codec; they issue no native owner.
    for (offset, value) in [
        (24, 2048_u64),
        (72, 512),
        (80, 1),
        (88, 9),
        (104, 1024),
        (112, 256),
        (120, 1),
        (128, 32),
        (136, 1),
        (472, 1024),
        (480, 2),
        (528, 100_000),
    ] {
        purpose[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    let mut family = [0; 256];
    family[..8].copy_from_slice(b"CRUCFAM1");
    family[8..12].copy_from_slice(&1_u32.to_be_bytes());
    family[12..16].copy_from_slice(&256_u32.to_be_bytes());
    family[16..48].copy_from_slice(&purpose[184..216]);
    family[48..56].copy_from_slice(&9_u64.to_be_bytes());
    family[56..64].copy_from_slice(&9_u64.to_be_bytes());
    for (index, identity) in [(0, 11), (1, 13)] {
        let offset = 64 + index * 96;
        family[offset..offset + 4].copy_from_slice(&(index as u32).to_be_bytes());
        family[offset + 8..offset + 40].fill(identity);
        for (relative, value) in [
            (40, 1024_u64),
            (56, 1024),
            (64, 256),
            (72, 1),
            (80, 32),
            (88, 1),
        ] {
            family[offset + relative..offset + relative + 8].copy_from_slice(&value.to_be_bytes());
        }
    }
    purpose[744..1000].copy_from_slice(&family);
    // Fixed syntax-only standing observation; no kernel owner is issued.
    for (offset, value) in [(1000, 1_u64), (1008, 29), (1016, 1504)] {
        purpose[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    let mut standing = [0_u8; 1496];
    standing[..8].copy_from_slice(b"CRUCSRV4");
    standing[8..12].copy_from_slice(&4_u32.to_be_bytes());
    standing[12..16].copy_from_slice(&1496_u32.to_be_bytes());
    standing[16..48].copy_from_slice(&purpose[184..216]);
    standing[88..120].copy_from_slice(&purpose[184..216]);
    standing[120..152].copy_from_slice(&purpose[816..848]);
    standing[200..232].copy_from_slice(&purpose[144..176]);
    standing[72..80].copy_from_slice(&purpose[88..96]);
    standing[80..88].copy_from_slice(&purpose[96..104]);
    for (offset, value) in [(48, 1_u64), (160, 1), (168, 2), (176, 1)] {
        standing[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    // Independently authored schema11 literal roster: fourteen 1ns polls,
    // absent progress and 500us total bounds, with canonical zero padding.
    standing[192..196].copy_from_slice(&256_u32.to_be_bytes());
    standing[196..200].copy_from_slice(&1_u32.to_be_bytes());
    standing[232..236].copy_from_slice(&11_u32.to_be_bytes());
    for index in 0..14 {
        let offset = 236 + index * 18;
        standing[offset..offset + 8].copy_from_slice(&1_u64.to_be_bytes());
        standing[offset + 9] = 1;
        standing[offset + 10..offset + 18].copy_from_slice(&500_000_u64.to_be_bytes());
    }
    purpose[1024..2520].copy_from_slice(&standing);

    let selectable = crucible_qemu_protocol::selectable_catalog_plan::SelectableCatalogPlan::new(
        crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanLimits::new(1, 1, 1)?,
        Vec::new(),
        crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanContinuation::cold(),
    )?;
    let bytes = PluginSetupPlan::new(
        crucible_qemu_protocol::app_random_branch_plan::AppRandomBranchPlan::default(),
        selectable,
    )
    .with_startup_operation(startup)
    .encode_preexec(&purpose, None)?;
    let plan = fs::File::from(memfd_region(u64::try_from(bytes.len())?)?);
    plan.write_all_at(&bytes, 0)?;
    rustix::fs::fcntl_add_seals(
        &plan,
        rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::SEAL,
    )?;

    let frame: [u8; 61] =
        crucible_qemu_protocol::control_encode_host_msg(&crucible_qemu_protocol::HostMsg::Setup {
            region_len: resources.region_len,
            process_generation: resources.process_generation,
            device_digest_workspace: None,
        })
        .try_into()
        .map_err(|_| "fixture current setup frame size differs")?;
    // Physical transport fixtures provide each mandatory owned role. They
    // establish no standing Source, Main payer or native constructor authority.
    let source_publication = fs::File::open("/dev/null")?;
    let source_cancellation = rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )?;
    resources.preexec_receipt = Some(
        crucible_qemu_protocol::send_preexec_setup_frame_with_descriptors(
            resources.control_socket.as_raw_fd(),
            &frame,
            &[
                resources.shmem_fd.as_raw_fd(),
                resources.wake_fd.as_raw_fd(),
                plan.as_raw_fd(),
                source_publication.as_raw_fd(),
                source_cancellation.as_raw_fd(),
            ],
        )?,
    );
    Ok(())
}

// The startup borrow belongs to the same already-authenticated launch plan.
// Grouping it with the actual process contract keeps retention at this private
// spawn boundary; neither a bool nor a numeric descriptor issues authority.
struct BorrowedSpawnProcessContract<'contract> {
    process: &'contract QemuChildProcessContract,
    startup: Option<&'contract crucible_qemu_protocol::plugin_setup_plan::StartupOperation>,
    selected_preexec: bool,
}

fn spawn_process_with_resources(
    executable: &str,
    args: &[String],
    run_directory: &QemuPreparedRunDirectory,
    child_resources: QemuSpawnChildResources,
    image_pins: &GuardedLaunchImagePins,
    envs: &[(&str, &str)],
    process_contract: Option<BorrowedSpawnProcessContract<'_>>,
) -> Result<Child, QemuSpawnError> {
    if let Some(contract) = &process_contract {
        // A failed or ambiguous spawn still closes pre-exec refinement. Later
        // generations may use this same frozen contract, never reopen it.
        contract.process.attempt_binding.freeze_for_launch()?;
    }

    let selected_preexec = process_contract
        .as_ref()
        .is_some_and(|contract| contract.selected_preexec);
    let retain_startup_cancellation = process_contract
        .as_ref()
        .is_some_and(|contract| contract.startup.is_some());
    let control_fd = child_resources.control_socket.as_raw_fd();
    let ram_control_fd = child_resources.ram_control_socket.as_raw_fd();
    let ram_source_fd = child_resources.ram_source_socket.as_raw_fd();
    let ram_spill_fd = child_resources.ram_spill.as_ref().map(AsRawFd::as_raw_fd);
    let shmem_fd = child_resources.shmem_fd.as_raw_fd();
    let wake_fd = child_resources.wake_fd.as_raw_fd();
    let expected_parent_pid = unsafe {
        // SAFETY: `getpid` has no preconditions.
        libc::getpid()
    };
    let process_contract = process_contract.map(|contract| ChildProcessContractRaw {
        cgroup_procs: contract.process.cgroup_procs.as_raw_fd(),
        cancellation_event: contract.process.cancellation_event.as_raw_fd(),
        maximum_file_bytes: contract.process.maximum_writable_bytes,
        maximum_file_descriptors: contract.process.effective_file_descriptors(),
        maximum_locked_bytes: contract.process.maximum_locked_bytes,
        main_stack_bytes: contract.process.main_stack_limit(),
        credentials: contract.process.credentials,
    });
    let pinned_run_directory = PreparedRunDirectoryRaw {
        directory: run_directory.directory.as_raw_fd(),
        vmstate_device: run_directory.vmstate_identity.device,
        vmstate_inode: run_directory.vmstate_identity.inode,
    };
    let vmstate_fd = image_pins.vmstate.as_raw_fd();
    let overlay_fds = image_pins
        .overlay
        .as_ref()
        .map(|overlay| (overlay.read.as_raw_fd(), overlay.write.as_raw_fd()));

    let mut command = guarded_qemu_process_command(executable, args, envs);
    if selected_preexec {
        command.env("QEMU_CRUCIBLE_PREEXEC_SETUP", "6");
    }

    // SAFETY: the closure only calls async-signal-safe syscalls between fork
    // and exec: `write`, `poll`, `setrlimit`, `openat`, `fstat`, `fchdir`, raw
    // credential syscalls, `prctl`, `getppid`, `dup2`, and `close`. It captures
    // only integers and raw descriptor numbers, not heap-owning Rust values.
    unsafe {
        command.pre_exec(move || {
            if let Some(contract) = process_contract {
                install_attempt_process_contract(contract)?;
            }
            install_prepared_run_directory(pinned_run_directory)?;
            if let Some(credentials) = process_contract.and_then(|contract| contract.credentials) {
                install_child_credentials(credentials)?;
            }
            // Contract and directory sources may occupy descriptor 12. Consume
            // them first, then preserve cancellation before fixed exec targets.
            if retain_startup_cancellation {
                let contract =
                    process_contract.ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
                dup_to_fixed_child_fd(contract.cancellation_event, QEMU_STARTUP_CANCELLATION_FD)?;
            }
            install_child_process_contract(control_fd, shmem_fd, wake_fd, expected_parent_pid)?;
            dup_to_fixed_child_fd(ram_control_fd, crate::QEMU_PLUGIN_RAM_CONTROL_FD)?;
            dup_to_fixed_child_fd(ram_source_fd, QEMU_RAM_SOURCE_LAUNCH_FD)?;
            if let Some(spill) = ram_spill_fd {
                dup_to_fixed_child_fd(spill, QEMU_RAM_SPILL_LAUNCH_FD)?;
                close_child_source_fd(spill)?;
            }
            close_child_source_fd(ram_control_fd)?;
            close_child_source_fd(ram_source_fd)?;
            install_guarded_launch_image_pins(vmstate_fd, overlay_fds)?;
            Ok(())
        });
    }

    command.spawn().map_err(|source| QemuSpawnError::Io {
        operation: "spawn guarded QEMU child",
        source,
    })
}

/// Constructs the actual child command with an empty inherited environment.
pub(crate) fn guarded_qemu_process_command(
    executable: &str,
    args: &[String],
    envs: &[(&str, &str)],
) -> Command {
    let mut command = Command::new(executable);
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for (key, value) in envs {
        command.env(key, value);
    }
    // The stage minimum is diagnostic-only and cannot escape the existing
    // witness opt-in. Invalid or noncanonical values leave stage notices off.
    if envs.contains(&("CRUCIBLE_CONTROL_CALLBACK_WITNESS", "1")) {
        const STAGE_MINIMUM: &str = "CRUCIBLE_CONTROL_CALLBACK_STAGE_MIN_TOKEN";
        if let Ok(minimum) = std::env::var(STAGE_MINIMUM)
            && minimum
                .parse::<u32>()
                .is_ok_and(|parsed| parsed.to_string() == minimum)
        {
            command.env(STAGE_MINIMUM, minimum);
        }
    }
    command
}

/// Runs the stopped QEMU setup probe through an admitted attempt contract.
///
/// The probe uses the exact descriptor-pinned launch directory and child
/// credentials of the eventual VM. Its input, lifetime, and two diagnostic
/// streams are bounded. The issued Source recipient owns the helper before
/// pipe validation and retains it when synchronous cleanup refuses.
pub(crate) fn run_guarded_qemu_setup_probe(
    launch: &QemuLaunchCommand,
    args: &[String],
    input: &[u8],
    maximum_output_bytes: usize,
    timeout: Duration,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
) -> Result<helper_receiver::GuardedProbeOutput, QemuGuardedImagePreparationError> {
    let fail = |source| QemuGuardedImagePreparationError::local(source);
    run_directory
        .validate_launch_basis(launch, process_contract)
        .and_then(|()| run_directory.revalidate())
        .map_err(fail)?;
    let overlay = run_directory
        .open_direct_root_overlay_for_probe()
        .and_then(|overlay| {
            overlay
                .map(|file| {
                    duplicate_cloexec_fd(file.as_raw_fd(), "pin read-only QEMU setup overlay")
                })
                .transpose()
        })
        .map_err(fail)?;
    let probe_args =
        image_launch::guarded_probe_args(args, overlay.is_some(), run_directory.path())
            .map_err(fail)?;
    let setup = GuardedSetupProbeCommand {
        args: &probe_args,
        root_overlay: overlay.as_ref(),
    };
    run_guarded_qemu_setup_probe_inner(
        launch,
        setup,
        input,
        maximum_output_bytes,
        timeout,
        run_directory,
        process_contract,
    )
}

fn run_guarded_qemu_setup_probe_inner(
    launch: &QemuLaunchCommand,
    setup: GuardedSetupProbeCommand<'_>,
    input: &[u8],
    maximum_output_bytes: usize,
    timeout: Duration,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
) -> Result<helper_receiver::GuardedProbeOutput, QemuGuardedImagePreparationError> {
    if let Err(source) = run_directory
        .validate_launch_basis(launch, process_contract)
        .and_then(|()| run_directory.revalidate())
    {
        return Err(QemuGuardedImagePreparationError::local(source));
    }

    if maximum_output_bytes > helper_receiver::MAXIMUM_PROBE_OUTPUT_BYTES {
        return Err(QemuGuardedImagePreparationError::local(invalid_input(
            "prepare guarded QEMU setup probe",
            "probe output exceeds the issued Source capture capacity",
        )));
    }

    let deadline = HostSupervisionDeadline::start(timeout);
    let mut command = Command::new(launch.executable());
    command
        .env_clear()
        .args(setup.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    install_guarded_helper_authority_with_probe_pin(
        &mut command,
        run_directory,
        process_contract,
        setup.root_overlay.map(AsRawFd::as_raw_fd),
    );

    process_contract
        .attempt_binding
        .freeze_for_launch()
        .map_err(QemuGuardedImagePreparationError::local)?;

    process_contract.with_spawned_helper(
        command,
        "spawn guarded QEMU setup probe",
        |child, original, output| {
            helper_receiver::wait_probe(
                child,
                original,
                input,
                maximum_output_bytes,
                &deadline,
                output,
            )
        },
    )
}

fn install_guarded_helper_authority(
    command: &mut Command,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
) {
    install_guarded_helper_authority_with_probe_pin(command, run_directory, process_contract, None);
}

fn install_guarded_helper_authority_with_probe_pin(
    command: &mut Command,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
    probe_overlay: Option<RawFd>,
) {
    let expected_parent_pid = unsafe {
        // SAFETY: `getpid` has no preconditions.
        libc::getpid()
    };
    let contract = ChildProcessContractRaw {
        cgroup_procs: process_contract.cgroup_procs.as_raw_fd(),
        cancellation_event: process_contract.cancellation_event.as_raw_fd(),
        maximum_file_bytes: process_contract.maximum_writable_bytes,
        maximum_file_descriptors: process_contract.effective_file_descriptors(),
        maximum_locked_bytes: process_contract.maximum_locked_bytes,
        main_stack_bytes: process_contract.main_stack_limit(),
        credentials: process_contract.credentials,
    };
    let directory = PreparedRunDirectoryRaw {
        directory: run_directory.directory.as_raw_fd(),
        vmstate_device: run_directory.vmstate_identity.device,
        vmstate_inode: run_directory.vmstate_identity.inode,
    };
    unsafe {
        // SAFETY: the closure uses only async-signal-safe scalar syscalls and
        // captures raw descriptor numbers plus copyable credentials.
        command.pre_exec(move || {
            install_attempt_process_contract(contract)?;
            install_prepared_run_directory(directory)?;
            if let Some(credentials) = contract.credentials {
                install_child_credentials(credentials)?;
            }
            if let Some(overlay) = probe_overlay {
                dup_to_fixed_child_fd(overlay, QEMU_ROOT_OVERLAY_READ_LAUNCH_FD)?;
                close_child_source_fd(overlay)?;
            }
            set_parent_death_signal(expected_parent_pid)
        });
    }
}

struct ProbeCapture {
    bytes: Vec<u8>,
    maximum_bytes: usize,
    exceeded: bool,
    eof: bool,
}

impl ProbeCapture {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum_bytes),
            maximum_bytes,
            exceeded: false,
            eof: false,
        }
    }

    // One read per iteration prevents a flooding stream from starving the
    // deadline, the monitor request, or the other diagnostic stream.
    fn read_once(&mut self, reader: &mut impl Read) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        let mut buffer = [0_u8; 16 * 1024];
        match reader.read(&mut buffer) {
            Ok(0) => {
                self.eof = true;
                Ok(true)
            }
            Ok(count) => {
                let retained = count.min(self.maximum_bytes.saturating_sub(self.bytes.len()));
                self.bytes.extend_from_slice(&buffer[..retained]);
                self.exceeded |= retained != count;
                Ok(true)
            }
            Err(error) if retryable_probe_io(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

fn nonblocking_probe_pipe(pipe: &impl AsFd) -> Result<(), QemuSpawnError> {
    fcntl_getfl(pipe)
        .and_then(|flags| fcntl_setfl(pipe, flags | OFlags::NONBLOCK))
        .map_err(|source| QemuSpawnError::Io {
            operation: "configure guarded QEMU probe pipe",
            source: source.into(),
        })
}

fn retryable_probe_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// Distinguishes original image provisioning from a retained source helper.
#[derive(Clone, Copy)]
enum GuardedImageToolPurpose {
    FreshLaunch,
    RetainedHotForkSource,
}

fn run_guarded_image_tool(
    executable: &Path,
    args: &[std::ffi::OsString],
    operation: &'static str,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
) -> Result<(), QemuGuardedImagePreparationError> {
    run_guarded_image_tool_for_purpose(
        executable,
        args,
        operation,
        run_directory,
        process_contract,
        GuardedImageToolPurpose::FreshLaunch,
    )
}

fn run_guarded_image_tool_for_purpose(
    executable: &Path,
    args: &[std::ffi::OsString],
    operation: &'static str,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
    purpose: GuardedImageToolPurpose,
) -> Result<(), QemuGuardedImagePreparationError> {
    run_guarded_image_tool_with_original(
        executable,
        args,
        operation,
        run_directory,
        process_contract,
        purpose,
        None,
    )
}

fn run_guarded_image_tool_with_original(
    executable: &Path,
    args: &[std::ffi::OsString],
    operation: &'static str,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
    purpose: GuardedImageToolPurpose,
    effect_original: Option<&crate::QemuHotForkSourceOriginal>,
) -> Result<(), QemuGuardedImagePreparationError> {
    let admission = match purpose {
        GuardedImageToolPurpose::FreshLaunch => {
            run_directory.validate_helper_basis(process_contract)
        }
        GuardedImageToolPurpose::RetainedHotForkSource => run_directory
            .validate_retained_source_helper_basis(process_contract)
            .and_then(|()| {
                let receiver = process_contract.retained_source_helper_lender()?;
                effect_original
                    .ok_or_else(helper_receiver::helper_custody_refusal)?
                    .checked_original(&receiver)
                    .map(|_| ())
            }),
    };
    if let Err(source) = admission {
        return Err(QemuGuardedImagePreparationError::local(source));
    }
    let mut command = Command::new(executable);
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    install_guarded_helper_authority(&mut command, run_directory, process_contract);
    process_contract
        .attempt_binding
        .freeze_for_launch()
        .map_err(QemuGuardedImagePreparationError::local)?;

    match purpose {
        GuardedImageToolPurpose::FreshLaunch => {
            process_contract.with_spawned_helper(command, operation, |child, original, _output| {
                helper_receiver::wait_image_tool(child, original, operation)
            })
        }
        GuardedImageToolPurpose::RetainedHotForkSource => {
            let effect_original = effect_original.ok_or_else(|| {
                QemuGuardedImagePreparationError::local(helper_receiver::helper_custody_refusal())
            })?;
            let receiver = process_contract
                .retained_source_helper_lender()
                .map_err(QemuGuardedImagePreparationError::local)?;
            process_contract.with_spawned_retained_source_helper(
                effect_original,
                command,
                operation,
                |child, _original, _output| {
                    helper_receiver::wait_image_tool_checked(child, operation, || {
                        let original = effect_original.checked_original(&receiver)?;
                        helper_receiver::wait_slice(original)
                    })
                },
            )
        }
    }
}

#[derive(Clone, Copy)]
struct ChildProcessContractRaw {
    cgroup_procs: RawFd,
    cancellation_event: RawFd,
    maximum_file_bytes: u64,
    maximum_file_descriptors: Option<u64>,
    maximum_locked_bytes: u64,
    credentials: Option<QemuChildCredentials>,
    main_stack_bytes: Option<u64>,
}

#[derive(Clone, Copy)]
struct PreparedRunDirectoryRaw {
    directory: RawFd,
    vmstate_device: u128,
    vmstate_inode: u128,
}

fn install_prepared_run_directory(directory: PreparedRunDirectoryRaw) -> io::Result<()> {
    let changed = || io::Error::from_raw_os_error(libc::ESTALE);
    let changed_directory = unsafe {
        // SAFETY: `directory` is the live retained directory descriptor
        // captured by the parent. `fchdir` copies no Rust-owned memory.
        libc::fchdir(directory.directory)
    };
    if changed_directory != 0 {
        return Err(io::Error::last_os_error());
    }
    let vmstate = unsafe {
        // SAFETY: the static filename is NUL-terminated and `directory` names
        // the retained run directory. `openat` returns a new child-owned fd.
        libc::openat(
            directory.directory,
            VMSTATE_FILE_NAME_C.as_ptr().cast(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if vmstate < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let inspected = unsafe {
        // SAFETY: `metadata` points to writable storage for one stat and
        // `vmstate` is the live descriptor returned above.
        libc::fstat(vmstate, metadata.as_mut_ptr())
    };
    let inspect_error = (inspected != 0).then(io::Error::last_os_error);
    let close_result = unsafe {
        // SAFETY: `vmstate` is owned by this child-side function.
        libc::close(vmstate)
    };
    if let Some(error) = inspect_error {
        return Err(error);
    }
    if close_result != 0 {
        return Err(io::Error::last_os_error());
    }
    let metadata = unsafe {
        // SAFETY: successful fstat initialized the complete structure.
        metadata.assume_init()
    };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || u128::from(metadata.st_dev) != directory.vmstate_device
        || u128::from(metadata.st_ino) != directory.vmstate_inode
    {
        return Err(changed());
    }
    Ok(())
}

fn install_guarded_launch_image_pins(
    vmstate: RawFd,
    overlay: Option<(RawFd, RawFd)>,
) -> io::Result<()> {
    dup_to_fixed_child_fd(vmstate, QEMU_VMSTATE_LAUNCH_FD)?;
    if let Some((read, write)) = overlay {
        dup_to_fixed_child_fd(read, QEMU_ROOT_OVERLAY_READ_LAUNCH_FD)?;
        dup_to_fixed_child_fd(write, QEMU_ROOT_OVERLAY_WRITE_LAUNCH_FD)?;
    }
    close_child_source_fd(vmstate)?;
    if let Some((read, write)) = overlay {
        close_child_source_fd(read)?;
        close_child_source_fd(write)?;
    }
    Ok(())
}

fn install_attempt_process_contract(contract: ChildProcessContractRaw) -> io::Result<()> {
    let attached = unsafe {
        // SAFETY: `cgroup_procs` is a live descriptor supplied by the parent,
        // and the static two-byte buffer remains valid for the syscall.
        libc::write(
            contract.cgroup_procs,
            CGROUP_ATTACH_SELF.as_ptr().cast(),
            CGROUP_ATTACH_SELF.len(),
        )
    };
    if attached < 0 {
        return Err(io::Error::last_os_error());
    }
    if attached != 2 {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }

    let mut cancellation = libc::pollfd {
        fd: contract.cancellation_event,
        events: libc::POLLIN,
        revents: 0,
    };
    let canceled = unsafe {
        // SAFETY: `cancellation` points to one initialized pollfd. A zero
        // timeout performs a non-consuming readiness query.
        libc::poll(&mut cancellation, 1, 0)
    };
    if canceled > 0 && cancellation.revents & libc::POLLIN != 0 {
        return Err(io::Error::from_raw_os_error(libc::ECANCELED));
    }
    if canceled < 0 {
        return Err(io::Error::last_os_error());
    }
    if cancellation.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }

    let file_limit = libc::rlimit {
        rlim_cur: contract.maximum_file_bytes,
        rlim_max: contract.maximum_file_bytes,
    };
    let limited = unsafe {
        // SAFETY: `file_limit` is initialized and `setrlimit` copies it during
        // this async-signal-safe syscall.
        libc::setrlimit(libc::RLIMIT_FSIZE, &file_limit)
    };
    if limited != 0 {
        return Err(io::Error::last_os_error());
    }
    if let Some(maximum) = contract.maximum_file_descriptors {
        let descriptor_limit = libc::rlimit {
            rlim_cur: maximum,
            rlim_max: maximum,
        };
        let result = unsafe {
            // SAFETY: The initialized limit is copied by this async-signal-safe syscall.
            libc::setrlimit(libc::RLIMIT_NOFILE, &descriptor_limit)
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    if let Some(bytes) = contract.main_stack_bytes {
        main_stack::install_and_verify(bytes)?;
    }

    // Install the exact authored limit before credentials are dropped. Kernel
    // refusal to raise an inherited hard limit aborts launch before placement.
    let locked_limit = libc::rlimit {
        rlim_cur: contract.maximum_locked_bytes,
        rlim_max: contract.maximum_locked_bytes,
    };
    let result = unsafe {
        // SAFETY: The initialized limit is copied by this async-signal-safe syscall.
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &locked_limit)
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    let no_new_privileges = unsafe {
        // SAFETY: PR_SET_NO_NEW_PRIVS takes scalar arguments and permanently
        // prevents this child from regaining privilege across exec.
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    };
    if no_new_privileges != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Installs the existing sealed birth contract for the private outer VM.
///
/// The operator retains the original account and process owner before calling
/// this helper. The child joins that already limited domain before exec; the
/// helper exports neither a raw cgroup descriptor nor new launch authority.
#[cfg(feature = "private-measurement-domain")]
pub(super) fn install_original_parent_birth(
    command: &mut Command,
    run_directory: &QemuPreparedRunDirectory,
    process_contract: &QemuChildProcessContract,
) {
    install_guarded_helper_authority(command, run_directory, process_contract);
}

fn install_child_credentials(credentials: QemuChildCredentials) -> io::Result<()> {
    let groups_cleared = unsafe {
        // SAFETY: the raw Linux syscall receives a zero count and null array,
        // so it removes every supplementary group without dereferencing data.
        libc::syscall(
            libc::SYS_setgroups,
            0_usize,
            std::ptr::null::<libc::gid_t>(),
        )
    };
    if groups_cleared != 0 {
        return Err(io::Error::last_os_error());
    }
    let group_changed = unsafe {
        // SAFETY: the raw Linux syscall takes three scalar group IDs.
        libc::syscall(
            libc::SYS_setresgid,
            credentials.group_id,
            credentials.group_id,
            credentials.group_id,
        )
    };
    if group_changed != 0 {
        return Err(io::Error::last_os_error());
    }
    let user_changed = unsafe {
        // SAFETY: the raw Linux syscall takes three scalar user IDs.
        libc::syscall(
            libc::SYS_setresuid,
            credentials.user_id,
            credentials.user_id,
            credentials.user_id,
        )
    };
    if user_changed != 0 {
        return Err(io::Error::last_os_error());
    }
    child_privilege::clear_and_verify(credentials)
}

fn validate_cgroup_procs_fd(fd: &OwnedFd) -> Result<(), QemuSpawnError> {
    validate_live_fd(fd.as_raw_fd(), "validate child cgroup descriptor")?;
    let filesystem = fstatfs(fd).map_err(|source| QemuSpawnError::Io {
        operation: "inspect child cgroup filesystem",
        source: source.into(),
    })?;
    if filesystem.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(QemuSpawnError::Io {
            operation: "validate child cgroup filesystem",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "cgroup.procs descriptor is not on cgroup v2",
            ),
        });
    }
    let target = fs::read_link(PathBuf::from("/proc/self/fd").join(fd.as_raw_fd().to_string()))
        .map_err(|source| QemuSpawnError::Io {
            operation: "resolve child cgroup descriptor",
            source,
        })?;
    if target.file_name().and_then(|name| name.to_str()) != Some("cgroup.procs") {
        return Err(QemuSpawnError::Io {
            operation: "validate child cgroup descriptor target",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "child cgroup descriptor does not name cgroup.procs",
            ),
        });
    }
    Ok(())
}

fn validate_cgroup_directory_fd(fd: &OwnedFd) -> Result<(), QemuSpawnError> {
    validate_live_fd(fd.as_raw_fd(), "validate child cgroup directory")?;
    let filesystem = fstatfs(fd).map_err(|source| QemuSpawnError::Io {
        operation: "inspect child cgroup directory filesystem",
        source: source.into(),
    })?;
    let metadata = fstat(fd).map_err(|source| QemuSpawnError::Io {
        operation: "inspect child cgroup directory",
        source: source.into(),
    })?;
    if filesystem.f_type != libc::CGROUP2_SUPER_MAGIC
        || FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_dev == 0
        || metadata.st_ino == 0
    {
        return Err(QemuSpawnError::Io {
            operation: "validate child cgroup directory",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "child cgroup directory is not a cgroup-v2 directory",
            ),
        });
    }
    Ok(())
}

fn validate_cancellation_eventfd(fd: RawFd) -> Result<(), QemuSpawnError> {
    let flags = validate_live_fd(fd, "validate child cancellation descriptor")?;
    if flags & libc::O_NONBLOCK == 0 {
        return Err(QemuSpawnError::Io {
            operation: "validate child cancellation descriptor flags",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "child cancellation eventfd is blocking",
            ),
        });
    }
    let target =
        fs::read_link(PathBuf::from("/proc/self/fd").join(fd.to_string())).map_err(|source| {
            QemuSpawnError::Io {
                operation: "resolve child cancellation descriptor",
                source,
            }
        })?;
    if target.to_string_lossy() != "anon_inode:[eventfd]" {
        return Err(QemuSpawnError::Io {
            operation: "validate child cancellation descriptor target",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "child cancellation descriptor is not an eventfd",
            ),
        });
    }
    Ok(())
}

fn validate_live_fd(fd: RawFd, operation: &'static str) -> Result<i32, QemuSpawnError> {
    let flags = unsafe {
        // SAFETY: `fcntl(F_GETFL)` reads descriptor metadata without pointers.
        libc::fcntl(fd, libc::F_GETFL)
    };
    if flags < 0 {
        return Err(last_io_error(operation));
    }
    Ok(flags)
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

/// Creates one writable, shrink-sealed setup-region memfd.
///
/// # Errors
///
/// Returns [`QemuSpawnError`] when the length is not representable or the
/// memfd cannot be created, sized, or sealed.
pub(crate) fn memfd_region(region_len: u64) -> Result<OwnedFd, QemuSpawnError> {
    libc::off_t::try_from(region_len)
        .map_err(|_| QemuSpawnError::RegionLengthTooLarge { region_len })?;

    let fd = rustix::fs::memfd_create(
        c"crucible-qemu-shmem",
        rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
    )
    .map_err(|source| QemuSpawnError::Io {
        operation: "create shmem memfd",
        source: source.into(),
    })?;
    rustix::fs::ftruncate(&fd, region_len).map_err(|source| QemuSpawnError::Io {
        operation: "size shmem memfd",
        source: source.into(),
    })?;

    // The shrink seal preserves mapping length while allowing shared writes.
    rustix::fs::fcntl_add_seals(&fd, rustix::fs::SealFlags::SHRINK).map_err(|source| {
        QemuSpawnError::Io {
            operation: "seal shmem memfd against shrink",
            source: source.into(),
        }
    })?;
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
#[path = "spawn/memfd_tests.rs"]
mod memfd_tests;

#[cfg(test)]
#[path = "spawn_test.rs"]
mod tests;
