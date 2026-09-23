//! Pinned authority over one prepared QEMU run directory and its launch artifacts.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use rustix::fs::{FileType, Mode, OFlags, fchmod, fchown, fstat, open, openat};

use super::materialization::{
    PreparedDeviceStateMaterialization, PreparedExactCheckpointMaterialization,
    PreparedRootOverlayMaterialization,
};
use super::{
    AttemptResourceBinding, QemuChildCredentials, QemuChildProcessContract,
    QemuGuardedExactRamInput, QemuSpawnError, invalid_input, validate_guarded_launch_requirements,
    validate_guarded_launch_resources,
};
use crate::QemuLaunchCommand;
use crate::launch::{
    MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_BYTES, MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_LINES,
    MAXIMUM_RUNTIME_DETERMINISM_TRACE_BYTES, MAXIMUM_RUNTIME_DETERMINISM_TRACE_LINES,
};

const MAXIMUM_RUNTIME_LIVENESS_TRACE_TAIL_BYTES: u64 = 60 * 1024;
const MAXIMUM_RUNTIME_LIVENESS_TRACE_TAIL_LINES: usize = 512;

/// Pinned authority over one pre-provisioned QEMU run directory.
///
/// The authority opens the directory without following a final symlink and
/// retains the exact regular VMState file and optional writable root overlay
/// named inside it. Guarded spawn uses the directory descriptor for `fchdir`
/// and reauthenticates every required named artifact immediately before
/// `exec`. It also retains the exact admitted command resource profile and
/// contract ceiling. Replacement of the diagnostic path, replacement of a
/// retained artifact before that boundary, or reuse under a different resource
/// admission or attempt lifecycle therefore fails closed.
/// This authority does not make the directory namespace immutable: the
/// production supervisor must exclude concurrent mutators until QEMU has
/// opened every relative launch artifact and must enforce the separate
/// aggregate quota.
#[derive(Debug)]
#[must_use = "guarded QEMU launch requires the pinned run-directory authority"]
pub struct QemuPreparedRunDirectory {
    pub(super) path: PathBuf,
    pub(super) directory: OwnedFd,
    directory_identity: PinnedFileIdentity,
    pub(super) vmstate: OwnedFd,
    pub(super) vmstate_identity: PinnedFileIdentity,
    pub(super) exact_device_state: Option<File>,
    pub(super) root_overlay: Option<OwnedFd>,
    pub(super) root_overlay_identity: Option<PinnedFileIdentity>,
    rr_control_boundary_trace_identity: OnceLock<PinnedFileIdentity>,
    runtime_determinism_trace_identity: OnceLock<PinnedFileIdentity>,
    pub(super) launch_resources: crate::QemuLaunchResourceRequirements,
    pub(super) admitted_ceiling: (u32, u64, u64),
    pub(super) child_credentials: Option<QemuChildCredentials>,
    pub(super) attempt_binding: Arc<AttemptResourceBinding>,
    pub(super) exact_device_state_materialization: PreparedDeviceStateMaterialization,
    pub(super) root_overlay_materialization: PreparedRootOverlayMaterialization,
    pub(super) exact_checkpoint_materialization: PreparedExactCheckpointMaterialization,
    pub(super) exact_checkpoint_target:
        Option<crucible::exact_checkpoint::ExactCheckpointVerifiedNode>,
    pub(super) exact_ram_inputs: Vec<QemuGuardedExactRamInput>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PinnedFileIdentity {
    pub(super) device: u128,
    pub(super) inode: u128,
}

struct AuthenticatedDiagnosticTrace {
    descriptor: OwnedFd,
    metadata: rustix::fs::Stat,
    identity: PinnedFileIdentity,
    credentials: QemuChildCredentials,
    bytes: u64,
}

impl PinnedFileIdentity {
    pub(super) fn from_stat(metadata: &rustix::fs::Stat) -> Self {
        Self {
            device: u128::from(metadata.st_dev),
            inode: u128::from(metadata.st_ino),
        }
    }

    fn matches(self, metadata: &rustix::fs::Stat) -> bool {
        self == Self::from_stat(metadata)
    }
}

impl QemuPreparedRunDirectory {
    /// Opens a prepared directory from an explicit resource profile for tests.
    ///
    /// This constructor exercises the same descriptor pinning and resource
    /// admission as production attempt storage without requiring a launch fixture.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the profile exceeds the process contract
    /// or the directory does not contain the required pinned regular files.
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_for_test_requirements(
        requirements: crate::QemuLaunchResourceRequirements,
        path: impl AsRef<Path>,
        contract: &QemuChildProcessContract,
    ) -> Result<Self, QemuSpawnError> {
        Self::open_for_requirements(requirements, path.as_ref(), contract)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn open_for_requirements(
        requirements: crate::QemuLaunchResourceRequirements,
        path: &Path,
        contract: &QemuChildProcessContract,
    ) -> Result<Self, QemuSpawnError> {
        validate_guarded_launch_requirements(requirements, contract)?;
        let path = path.to_owned();
        let directory = open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "pin prepared QEMU run directory",
            source: source.into(),
        })?;
        let vmstate = open_prepared_vmstate(&directory, &path)?;
        Self::from_admitted_descriptors(requirements, &path, directory, vmstate, contract)
    }

    /// Constructs one prepared authority from already-pinned storage descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the launch profile exceeds the process
    /// contract or either descriptor has the wrong file type.
    pub(crate) fn from_admitted_descriptors(
        requirements: crate::QemuLaunchResourceRequirements,
        path: &Path,
        directory: OwnedFd,
        vmstate: OwnedFd,
        contract: &QemuChildProcessContract,
    ) -> Result<Self, QemuSpawnError> {
        validate_guarded_launch_requirements(requirements, contract)?;

        let directory_metadata = fstat(&directory).map_err(|source| QemuSpawnError::Io {
            operation: "inspect prepared QEMU run directory",
            source: source.into(),
        })?;
        if FileType::from_raw_mode(directory_metadata.st_mode) != FileType::Directory {
            return Err(invalid_input(
                "validate prepared QEMU run directory",
                "prepared QEMU run path is not a directory",
            ));
        }
        let vmstate_metadata = fstat(&vmstate).map_err(|source| QemuSpawnError::Io {
            operation: "inspect prepared exact-VMState container",
            source: source.into(),
        })?;
        if FileType::from_raw_mode(vmstate_metadata.st_mode) != FileType::RegularFile {
            return Err(invalid_input(
                "validate prepared exact-VMState container",
                "exact-VMState container path is not a regular file",
            ));
        }
        let root_overlay = open_optional_root_overlay(&directory)?;
        let root_overlay_metadata =
            root_overlay
                .as_ref()
                .map(fstat)
                .transpose()
                .map_err(|source| QemuSpawnError::Io {
                    operation: "inspect prepared root overlay",
                    source: source.into(),
                })?;
        if root_overlay_metadata.as_ref().is_some_and(|metadata| {
            FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        }) {
            return Err(invalid_input(
                "validate prepared root overlay",
                "prepared root overlay path is not a regular file",
            ));
        }
        let root_overlay_identity = root_overlay_metadata
            .as_ref()
            .map(PinnedFileIdentity::from_stat);

        Ok(Self {
            path: path.to_owned(),
            directory_identity: PinnedFileIdentity::from_stat(&directory_metadata),
            directory,
            vmstate_identity: PinnedFileIdentity::from_stat(&vmstate_metadata),
            vmstate,
            exact_device_state: None,
            root_overlay_materialization: if root_overlay.is_some() {
                PreparedRootOverlayMaterialization::Provisioned
            } else {
                PreparedRootOverlayMaterialization::Absent
            },
            root_overlay,
            root_overlay_identity,
            rr_control_boundary_trace_identity: OnceLock::new(),
            runtime_determinism_trace_identity: OnceLock::new(),
            launch_resources: requirements,
            admitted_ceiling: contract.admitted_resource_ceiling(),
            child_credentials: contract.credentials,
            attempt_binding: Arc::clone(&contract.attempt_binding),
            exact_device_state_materialization: PreparedDeviceStateMaterialization::Provisioned,
            exact_checkpoint_materialization: PreparedExactCheckpointMaterialization::Absent,
            exact_checkpoint_target: None,
            exact_ram_inputs: Vec::new(),
        })
    }

    /// Binds one owner-only listener for this directory's admitted child.
    pub(crate) fn bind_child_owned_socket(
        &self,
        file_name: &str,
    ) -> Result<crate::unix_socket_path::ExpectedPeerUnixListener, QemuSpawnError> {
        let directory_metadata = fstat(&self.directory).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect prepared QEMU run directory for socket binding",
            source: source.into(),
        })?;
        if !self.directory_identity.matches(&directory_metadata) {
            return Err(QemuSpawnError::PreparedRunDirectoryChanged {
                path: self.path.clone(),
            });
        }
        let credentials = self.child_credentials.ok_or_else(|| {
            invalid_input(
                "bind child-owned QEMU socket",
                "prepared run directory has no admitted child credentials",
            )
        })?;
        let listener = crate::unix_socket_path::bind_child_owned_at(
            self.directory.as_fd(),
            file_name,
            credentials.user_id,
            credentials.group_id,
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "bind child-owned QEMU socket",
            source,
        })?;
        crate::unix_socket_path::ExpectedPeerUnixListener::for_child(
            listener,
            credentials.user_id,
            credentials.group_id,
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "configure child-owned QEMU socket listener",
            source,
        })
    }

    /// Returns the original run-directory path for diagnostics only.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Prepares the fixed child-owned RR control-boundary trace destination.
    ///
    /// The file is created through the retained directory descriptor before
    /// spawn. QEMU may truncate and write the inode, but cannot choose its name,
    /// ownership, or permissions.
    pub(crate) fn prepare_rr_control_boundary_trace(&self) -> Result<(), QemuSpawnError> {
        self.prepare_diagnostic_trace(
            crate::QEMU_RR_CONTROL_BOUNDARY_TRACE_FILE_NAME,
            &self.rr_control_boundary_trace_identity,
        )
    }

    /// Prepares the fixed child-owned runtime-determinism trace destination.
    pub(crate) fn prepare_runtime_determinism_trace(&self) -> Result<(), QemuSpawnError> {
        self.prepare_diagnostic_trace(
            crate::QEMU_RUNTIME_DETERMINISM_TRACE_FILE_NAME,
            &self.runtime_determinism_trace_identity,
        )
    }

    fn prepare_diagnostic_trace(
        &self,
        file_name: &'static str,
        identity: &OnceLock<PinnedFileIdentity>,
    ) -> Result<(), QemuSpawnError> {
        self.revalidate_identity()?;
        let credentials = self.child_credentials.ok_or_else(|| {
            invalid_input(
                "prepare fixed diagnostic trace",
                "prepared run directory has no admitted child credentials",
            )
        })?;
        let trace = openat(
            &self.directory,
            file_name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "create fixed diagnostic trace",
            source: source.into(),
        })?;
        fchmod(&trace, Mode::from_bits_truncate(0o600)).map_err(|source| QemuSpawnError::Io {
            operation: "set fixed diagnostic trace permissions",
            source: source.into(),
        })?;
        fchown(
            &trace,
            Some(rustix::process::Uid::from_raw(credentials.user_id)),
            Some(rustix::process::Gid::from_raw(credentials.group_id)),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "assign fixed diagnostic trace ownership",
            source: source.into(),
        })?;
        let pinned_identity =
            PinnedFileIdentity::from_stat(&fstat(&trace).map_err(|source| QemuSpawnError::Io {
                operation: "pin fixed diagnostic trace identity",
                source: source.into(),
            })?);
        identity
            .set(pinned_identity)
            .map_err(|_identity| QemuSpawnError::DiagnosticTraceChanged { file: file_name })?;
        Ok(())
    }

    /// Retains the bounded RR control-boundary trace after QEMU has been reaped.
    ///
    /// The read is descriptor-relative and refuses symlinks, non-regular files,
    /// extra links, substituted inodes, unexpected ownership or permissions,
    /// and files outside the fixed byte and line ceilings. Its bytes also count
    /// toward the attempt's aggregate writable-file admission.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the trace is absent, malformed, changed
    /// during retention, or exceeds its fixed or aggregate storage ceiling.
    pub fn retain_rr_control_boundary_trace_after_reap(&self) -> Result<String, QemuSpawnError> {
        self.retain_diagnostic_trace_after_reap(
            crate::QEMU_RR_CONTROL_BOUNDARY_TRACE_FILE_NAME,
            &self.rr_control_boundary_trace_identity,
            MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_BYTES,
            MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_LINES,
        )
    }

    /// Retains the bounded runtime-determinism trace after QEMU has been reaped.
    ///
    /// This applies the same descriptor-relative identity, metadata, bounded
    /// read, and aggregate-admission checks as the RR trace reader, with the
    /// larger fixed byte and line ceilings needed by the two-row runtime schema.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the fixed trace cannot be authenticated.
    pub fn retain_runtime_determinism_trace_after_reap(&self) -> Result<String, QemuSpawnError> {
        self.retain_diagnostic_trace_after_reap(
            crate::QEMU_RUNTIME_DETERMINISM_TRACE_FILE_NAME,
            &self.runtime_determinism_trace_identity,
            MAXIMUM_RUNTIME_DETERMINISM_TRACE_BYTES,
            MAXIMUM_RUNTIME_DETERMINISM_TRACE_LINES,
        )
    }

    /// Retains the authenticated tail of an oversized scheduler-liveness trace.
    ///
    /// Unlike [`Self::retain_runtime_determinism_trace_after_reap`], this
    /// diagnostic reads only the final fixed byte window and then retains at
    /// most the final 512 rows. The returned text begins with the
    /// original file size and whether earlier bytes were omitted. The complete
    /// trace still counts against the attempt's aggregate writable admission.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the trace is absent, empty, not the
    /// prepared inode, outside aggregate admission, changed during retention,
    /// or its retained row suffix is not UTF-8.
    pub fn retain_runtime_liveness_trace_tail_after_reap(&self) -> Result<String, QemuSpawnError> {
        let file_name = crate::QEMU_RUNTIME_DETERMINISM_TRACE_FILE_NAME;
        let authenticated = self.open_authenticated_diagnostic_trace_after_reap(
            file_name,
            &self.runtime_determinism_trace_identity,
            None,
        )?;
        let trace_bytes = authenticated.bytes;

        let start = trace_bytes.saturating_sub(MAXIMUM_RUNTIME_LIVENESS_TRACE_TAIL_BYTES);
        let mut trace = File::from(authenticated.descriptor);
        trace
            .seek(SeekFrom::Start(start))
            .map_err(|source| QemuSpawnError::Io {
                operation: "seek scheduler-liveness trace tail",
                source,
            })?;
        let mut bytes = Vec::new();
        trace
            .take(MAXIMUM_RUNTIME_LIVENESS_TRACE_TAIL_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|source| QemuSpawnError::Io {
                operation: "read scheduler-liveness trace tail",
                source,
            })?;
        if u64::try_from(bytes.len()) != Ok(trace_bytes - start) {
            return Err(QemuSpawnError::DiagnosticTraceChanged { file: file_name });
        }
        if start != 0 {
            let first_complete_row = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |index| index + 1);
            bytes.drain(..first_complete_row);
        }
        let retained =
            String::from_utf8(bytes).map_err(|source| QemuSpawnError::DiagnosticTraceUtf8 {
                file: file_name,
                source,
            })?;
        let mut rows = retained
            .lines()
            .rev()
            .take(MAXIMUM_RUNTIME_LIVENESS_TRACE_TAIL_LINES)
            .collect::<Vec<_>>();
        if rows.is_empty() {
            return Err(QemuSpawnError::DiagnosticTraceLines {
                file: file_name,
                actual: 0,
                maximum: MAXIMUM_RUNTIME_LIVENESS_TRACE_TAIL_LINES,
            });
        }
        rows.reverse();

        self.revalidate_authenticated_diagnostic_trace_after_read(
            file_name,
            authenticated.identity,
            authenticated.metadata.st_size,
            authenticated.credentials,
        )?;

        Ok(format!(
            "trace_original_bytes={trace_bytes} trace_tail_truncated={}\n{}",
            start != 0 || retained.lines().count() > rows.len(),
            rows.join("\n")
        ))
    }

    fn retain_diagnostic_trace_after_reap(
        &self,
        file_name: &'static str,
        trace_identity: &OnceLock<PinnedFileIdentity>,
        maximum_bytes: u64,
        maximum_lines: usize,
    ) -> Result<String, QemuSpawnError> {
        let authenticated = self.open_authenticated_diagnostic_trace_after_reap(
            file_name,
            trace_identity,
            Some(maximum_bytes),
        )?;

        let mut bytes = Vec::new();
        File::from(authenticated.descriptor)
            .take(maximum_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| QemuSpawnError::Io {
                operation: "read retained diagnostic trace",
                source,
            })?;
        if u64::try_from(bytes.len()) != Ok(authenticated.bytes) {
            return Err(QemuSpawnError::DiagnosticTraceChanged { file: file_name });
        }
        let lines = bytes.iter().filter(|byte| **byte == b'\n').count();
        if lines == 0 || lines > maximum_lines {
            return Err(QemuSpawnError::DiagnosticTraceLines {
                file: file_name,
                actual: lines,
                maximum: maximum_lines,
            });
        }

        self.revalidate_authenticated_diagnostic_trace_after_read(
            file_name,
            authenticated.identity,
            authenticated.metadata.st_size,
            authenticated.credentials,
        )?;

        String::from_utf8(bytes).map_err(|source| QemuSpawnError::DiagnosticTraceUtf8 {
            file: file_name,
            source,
        })
    }

    fn open_authenticated_diagnostic_trace_after_reap(
        &self,
        file_name: &'static str,
        trace_identity: &OnceLock<PinnedFileIdentity>,
        maximum_bytes: Option<u64>,
    ) -> Result<AuthenticatedDiagnosticTrace, QemuSpawnError> {
        self.revalidate_identity()?;
        let credentials = self.child_credentials.ok_or_else(|| {
            invalid_input(
                "retain fixed diagnostic trace",
                "prepared run directory has no admitted child credentials",
            )
        })?;
        let trace = openat(
            &self.directory,
            file_name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "open retained diagnostic trace",
            source: source.into(),
        })?;
        let metadata = fstat(&trace).map_err(|source| QemuSpawnError::Io {
            operation: "inspect retained diagnostic trace",
            source: source.into(),
        })?;
        validate_diagnostic_trace_metadata(file_name, &metadata, credentials)?;
        let expected_identity = trace_identity.get().copied().ok_or_else(|| {
            invalid_input(
                "retain fixed diagnostic trace",
                "trace destination was not prepared before launch",
            )
        })?;
        if !expected_identity.matches(&metadata) {
            return Err(QemuSpawnError::DiagnosticTraceChanged { file: file_name });
        }
        let trace_bytes = u64::try_from(metadata.st_size).map_err(|_source| {
            invalid_input(
                "retain fixed diagnostic trace",
                "trace length cannot be represented",
            )
        })?;
        let fixed_maximum = maximum_bytes.unwrap_or(self.admitted_ceiling.2);
        if trace_bytes == 0 || maximum_bytes.is_some_and(|maximum| trace_bytes > maximum) {
            return Err(QemuSpawnError::DiagnosticTraceLength {
                file: file_name,
                actual: trace_bytes,
                maximum: fixed_maximum,
            });
        }

        let vmstate_bytes =
            u64::try_from(self.revalidate_identity()?.st_size).map_err(|_source| {
                invalid_input(
                    "account retained diagnostic trace",
                    "VMState length cannot be represented",
                )
            })?;
        let root_overlay_bytes = if self.root_overlay.is_some() {
            u64::try_from(self.revalidate_root_overlay_identity()?.st_size).map_err(|_source| {
                invalid_input(
                    "account retained diagnostic trace",
                    "root-overlay length cannot be represented",
                )
            })?
        } else {
            0
        };
        if vmstate_bytes
            .checked_add(root_overlay_bytes)
            .and_then(|bytes| bytes.checked_add(trace_bytes))
            .is_none_or(|bytes| bytes > self.admitted_ceiling.2)
        {
            return Err(QemuSpawnError::DiagnosticTraceExceedsAdmission {
                file: file_name,
                trace_bytes,
                maximum: self.admitted_ceiling.2,
            });
        }

        Ok(AuthenticatedDiagnosticTrace {
            descriptor: trace,
            metadata,
            identity: expected_identity,
            credentials,
            bytes: trace_bytes,
        })
    }

    fn revalidate_authenticated_diagnostic_trace_after_read(
        &self,
        file_name: &'static str,
        expected_identity: PinnedFileIdentity,
        expected_size: i64,
        credentials: QemuChildCredentials,
    ) -> Result<(), QemuSpawnError> {
        let named = openat(
            &self.directory,
            file_name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "reopen retained diagnostic trace",
            source: source.into(),
        })?;
        let retained = fstat(&named).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect retained diagnostic trace",
            source: source.into(),
        })?;
        validate_diagnostic_trace_metadata(file_name, &retained, credentials)?;
        if !expected_identity.matches(&retained) || retained.st_size != expected_size {
            return Err(QemuSpawnError::DiagnosticTraceChanged { file: file_name });
        }
        Ok(())
    }

    /// Lends the provisioned empty VMState container as a hot-fork destination.
    ///
    /// The retained source copies its frozen VMState bytes into this file
    /// during the fork and the child adopts it as its private container. The
    /// container must still be the empty file this authority pinned at
    /// provisioning; a materialized or replaced container is not a valid
    /// destination.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the container was materialized for a
    /// fresh launch, its pinned identity changed, or it is no longer empty.
    pub fn hot_fork_child_file_destination(
        &self,
    ) -> Result<std::os::fd::BorrowedFd<'_>, QemuSpawnError> {
        if self.exact_device_state_materialization
            != PreparedDeviceStateMaterialization::Provisioned
        {
            return Err(QemuSpawnError::PreparedDeviceStateNotReady);
        }
        let retained = self.revalidate_identity()?;
        if retained.st_size != 0 {
            return Err(invalid_input(
                "lend prepared exact-VMState container",
                "prepared exact-VMState container is not empty",
            ));
        }
        Ok(std::os::fd::AsFd::as_fd(&self.vmstate))
    }

    /// Lends the provisioned empty root overlay as a hot-fork destination.
    ///
    /// Disk-backed hot-fork children must receive a branch-private copy of the
    /// source generation's writable overlay. The destination must remain the
    /// empty regular file pinned when this run directory was provisioned.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when this launch has no root overlay, the
    /// overlay is being materialized, its pinned identity changed, or it is no
    /// longer empty.
    pub fn hot_fork_root_overlay_destination(
        &self,
    ) -> Result<std::os::fd::BorrowedFd<'_>, QemuSpawnError> {
        if !self.launch_resources.has_root_overlay()
            || self.root_overlay_materialization != PreparedRootOverlayMaterialization::Provisioned
        {
            return Err(QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        let retained = self.revalidate_root_overlay_identity()?;
        if retained.st_size != 0 {
            return Err(invalid_input(
                "lend prepared root-overlay container",
                "prepared root-overlay container is not empty",
            ));
        }
        let overlay = self.root_overlay.as_ref().ok_or_else(|| {
            QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            }
        })?;
        Ok(std::os::fd::AsFd::as_fd(overlay))
    }

    /// Seals the destination pair against one successful QEMU fork result.
    ///
    /// The launch token is the unforgeable proof that QEMU consumed the exact
    /// staged child-file generation. Sealing reauthenticates both named pinned
    /// artifacts after QEMU wrote them, verifies that the pair remains distinct
    /// and within the admitted aggregate storage ceiling, then prevents either
    /// file from being lent to another fork or mistaken for fresh artifacts.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] and leaves the pair fail-closed when the run
    /// directory was not in its provisioned state, a named inode changed, the
    /// pair aliases one backing file, or its combined size exceeds admission.
    pub fn seal_hot_fork_child_file_transfer<A>(
        &mut self,
        launch: &crate::QemuHotForkChildLaunch<A>,
    ) -> Result<(), QemuSpawnError> {
        if self.exact_device_state_materialization
            != PreparedDeviceStateMaterialization::Provisioned
            || (self.launch_resources.has_root_overlay()
                && self.root_overlay_materialization
                    != PreparedRootOverlayMaterialization::Provisioned)
            || launch.parent_state().request().child_files_generation() == 0
        {
            self.invalidate_hot_fork_child_file_transfer();
            return Err(invalid_input(
                "seal hot-fork child files",
                "successful fork does not match a provisioned child-file destination pair",
            ));
        }
        let vmstate = self.revalidate_identity();
        let overlay = self
            .launch_resources
            .has_root_overlay()
            .then(|| self.revalidate_root_overlay_identity())
            .transpose();
        let validation = vmstate.and_then(|vmstate| {
            overlay.map(|overlay| {
                let overlay_bytes = overlay
                    .as_ref()
                    .and_then(|metadata| u64::try_from(metadata.st_size).ok())
                    .unwrap_or(0);
                let device_state_bytes = u64::try_from(vmstate.st_size).unwrap_or(u64::MAX);
                (device_state_bytes, overlay_bytes)
            })
        });
        let (device_state_bytes, overlay_bytes) = match validation {
            Ok(bytes) => bytes,
            Err(source) => {
                self.invalidate_hot_fork_child_file_transfer();
                return Err(source);
            }
        };
        let expected_file_count = 1 + usize::from(self.launch_resources.has_root_overlay());
        let vmstate_root = crate::QmpHotForkChildFileRoot::node_name(
            crate::DEFAULT_VMSTATE_NODE_NAME,
        )
        .map_err(|_source| {
            invalid_input(
                "seal hot-fork child files",
                "the built-in VMState root selector is invalid",
            )
        })?;
        let overlay_root = self
            .launch_resources
            .has_root_overlay()
            .then(|| crate::QmpHotForkChildFileRoot::device(crate::ROOT_DRIVE_ID))
            .transpose()
            .map_err(|_source| {
                invalid_input(
                    "seal hot-fork child files",
                    "the built-in root-overlay selector is invalid",
                )
            })?;
        let matches_vmstate = launch.child_files().iter().any(|file| {
            file.root() == &vmstate_root
                && u64::try_from(self.vmstate_identity.device) == Ok(file.device())
                && u64::try_from(self.vmstate_identity.inode) == Ok(file.inode())
        });
        let matches_overlay = match (overlay_root.as_ref(), self.root_overlay_identity) {
            (None, None) => true,
            (Some(root), Some(identity)) => launch.child_files().iter().any(|file| {
                file.root() == root
                    && u64::try_from(identity.device) == Ok(file.device())
                    && u64::try_from(identity.inode) == Ok(file.inode())
            }),
            _ => false,
        };
        if launch.child_files().len() != expected_file_count
            || !matches_vmstate
            || !matches_overlay
            || device_state_bytes == 0
            || (self.launch_resources.has_root_overlay() && overlay_bytes == 0)
            || self.root_overlay_identity == Some(self.vmstate_identity)
            || device_state_bytes
                .checked_add(overlay_bytes)
                .is_none_or(|bytes| bytes > self.admitted_ceiling.2)
        {
            self.invalidate_hot_fork_child_file_transfer();
            return Err(invalid_input(
                "seal hot-fork child files",
                "transferred child files alias or exceed their admitted storage ceiling",
            ));
        }
        self.exact_device_state_materialization = PreparedDeviceStateMaterialization::HotForkChild;
        if self.launch_resources.has_root_overlay() {
            self.root_overlay_materialization = PreparedRootOverlayMaterialization::HotForkChild;
        }
        Ok(())
    }

    /// Authenticates the sealed child files and named directory before adoption.
    ///
    /// The lifecycle receives the directory path while its lease retains this
    /// pinned authority. The path must still resolve to the same directory so
    /// later generation operations cannot use a substituted namespace. The
    /// production attempt root is supervisor-owned mode `0700`; the QEMU user
    /// cannot replace this directory's parent entry after adoption.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the child files were not sealed, a
    /// pinned file changed, or the named directory no longer matches its pin.
    pub fn validate_hot_fork_adoption(&self) -> Result<(), QemuSpawnError> {
        if self.exact_device_state_materialization
            != PreparedDeviceStateMaterialization::HotForkChild
            || (self.launch_resources.has_root_overlay()
                && self.root_overlay_materialization
                    != PreparedRootOverlayMaterialization::HotForkChild)
        {
            return Err(invalid_input(
                "adopt hot-fork child files",
                "child files have not been sealed for this run directory",
            ));
        }

        self.revalidate()?;
        let named_directory = open(
            &self.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_source| QemuSpawnError::PreparedRunDirectoryChanged {
            path: self.path.clone(),
        })?;
        let named_metadata = fstat(&named_directory).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect named hot-fork run directory",
            source: source.into(),
        })?;
        if !self.directory_identity.matches(&named_metadata) {
            return Err(QemuSpawnError::PreparedRunDirectoryChanged {
                path: self.path.clone(),
            });
        }
        Ok(())
    }

    /// Opens the current root overlay through this pinned generation directory.
    ///
    /// The returned file has its own open-file description for sparse extent
    /// scanning. The named entry must still match the originally pinned inode;
    /// a replacement or symlink fails before checkpoint bytes are read.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the overlay is absent, unready, or its
    /// named entry differs from the pinned regular file.
    pub fn open_root_overlay_for_checkpoint(&self) -> Result<File, QemuSpawnError> {
        if !self.launch_resources.has_root_overlay()
            || matches!(
                self.root_overlay_materialization,
                PreparedRootOverlayMaterialization::Absent
                    | PreparedRootOverlayMaterialization::Updating
            )
        {
            return Err(QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        let identity = self.root_overlay_identity.ok_or_else(|| {
            QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            }
        })?;
        let overlay = openat(
            &self.directory,
            crate::DEFAULT_ROOT_OVERLAY_FILE_NAME,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "open pinned checkpoint root overlay",
            source: source.into(),
        })?;
        let metadata = fstat(&overlay).map_err(|source| QemuSpawnError::Io {
            operation: "inspect pinned checkpoint root overlay",
            source: source.into(),
        })?;
        if !identity.matches(&metadata)
            || FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        {
            return Err(QemuSpawnError::PreparedRootOverlayChanged {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        Ok(File::from(overlay))
    }

    /// Invalidates destinations after any fork exchange without a success token.
    ///
    /// This operation can only remove launch authority. It is safe after an
    /// explicit rejection and required after an ambiguous or post-fork error.
    pub fn invalidate_hot_fork_child_file_transfer(&mut self) {
        self.exact_device_state_materialization = PreparedDeviceStateMaterialization::Updating;
        if self.launch_resources.has_root_overlay() {
            self.root_overlay_materialization = PreparedRootOverlayMaterialization::Updating;
        }
    }

    pub(super) fn revalidate(&self) -> Result<(), QemuSpawnError> {
        if matches!(
            &self.exact_checkpoint_materialization,
            PreparedExactCheckpointMaterialization::Updating { .. }
        ) {
            return Err(QemuSpawnError::PreparedExactCheckpointNotReady {
                path: self.path.clone(),
            });
        }
        if self.exact_device_state_materialization == PreparedDeviceStateMaterialization::Updating {
            return Err(QemuSpawnError::PreparedDeviceStateNotReady);
        }
        let retained_vmstate = self.revalidate_identity()?;
        if self.root_overlay_materialization == PreparedRootOverlayMaterialization::Updating {
            return Err(QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        if self.launch_resources.has_root_overlay()
            && self.root_overlay_materialization == PreparedRootOverlayMaterialization::Absent
        {
            return Err(QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        if let PreparedDeviceStateMaterialization::Exact { bytes, .. } =
            self.exact_device_state_materialization
        {
            let actual = if let Some(exact_device_state) = &self.exact_device_state {
                let exact_device_metadata =
                    fstat(exact_device_state).map_err(|source| QemuSpawnError::Io {
                        operation: "inspect sealed exact device-state input",
                        source: source.into(),
                    })?;
                u64::try_from(exact_device_metadata.st_size).unwrap_or(u64::MAX)
            } else {
                u64::try_from(retained_vmstate.st_size).unwrap_or(u64::MAX)
            };
            if actual != bytes {
                return Err(QemuSpawnError::PreparedExactInputIncomplete {
                    expected: bytes,
                    actual,
                });
            }
        }
        if let PreparedRootOverlayMaterialization::Exact { bytes, .. } =
            self.root_overlay_materialization
        {
            let retained = self.revalidate_root_overlay_identity()?;
            let actual = u64::try_from(retained.st_size).unwrap_or(u64::MAX);
            if actual != bytes {
                return Err(QemuSpawnError::PreparedRootOverlayIncomplete {
                    expected: bytes,
                    actual,
                });
            }
        }
        Ok(())
    }

    pub(super) fn revalidate_identity(&self) -> Result<rustix::fs::Stat, QemuSpawnError> {
        let directory_metadata = fstat(&self.directory).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect prepared QEMU run directory",
            source: source.into(),
        })?;
        if !self.directory_identity.matches(&directory_metadata) {
            return Err(QemuSpawnError::PreparedRunDirectoryChanged {
                path: self.path.clone(),
            });
        }
        let retained_vmstate = fstat(&self.vmstate).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect retained exact-VMState container",
            source: source.into(),
        })?;
        if !self.vmstate_identity.matches(&retained_vmstate) {
            return Err(QemuSpawnError::PreparedDeviceStateChanged {
                path: self.path.join(crate::DEFAULT_VMSTATE_FILE_NAME),
            });
        }
        let named_vmstate = open_prepared_vmstate(&self.directory, &self.path)?;
        let named_metadata = fstat(&named_vmstate).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect named exact-VMState container",
            source: source.into(),
        })?;
        if !self.vmstate_identity.matches(&named_metadata) {
            return Err(QemuSpawnError::PreparedDeviceStateChanged {
                path: self.path.join(crate::DEFAULT_VMSTATE_FILE_NAME),
            });
        }
        Ok(retained_vmstate)
    }

    pub(super) fn revalidate_root_overlay_identity(
        &self,
    ) -> Result<rustix::fs::Stat, QemuSpawnError> {
        let retained = self.root_overlay.as_ref().ok_or_else(|| {
            QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            }
        })?;
        let identity = self.root_overlay_identity.ok_or_else(|| {
            QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            }
        })?;
        let retained_metadata = fstat(retained).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect retained root overlay",
            source: source.into(),
        })?;
        if !identity.matches(&retained_metadata) {
            return Err(QemuSpawnError::PreparedRootOverlayChanged {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        let named = open_prepared_root_overlay(&self.directory, &self.path)?;
        let named_metadata = fstat(&named).map_err(|source| QemuSpawnError::Io {
            operation: "reinspect named root overlay",
            source: source.into(),
        })?;
        if !identity.matches(&named_metadata) {
            return Err(QemuSpawnError::PreparedRootOverlayChanged {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        Ok(retained_metadata)
    }

    pub(super) fn validate_launch_basis(
        &self,
        command: &QemuLaunchCommand,
        contract: &QemuChildProcessContract,
    ) -> Result<(), QemuSpawnError> {
        if self.launch_resources != command.resource_requirements()
            || self.admitted_ceiling != contract.admitted_resource_ceiling()
            || !Arc::ptr_eq(&self.attempt_binding, &contract.attempt_binding)
        {
            return Err(QemuSpawnError::PreparedLaunchAdmissionChanged);
        }
        validate_guarded_launch_resources(command, contract)
    }

    pub(super) fn validate_helper_basis(
        &self,
        contract: &QemuChildProcessContract,
    ) -> Result<(), QemuSpawnError> {
        if self.admitted_ceiling != contract.admitted_resource_ceiling()
            || !Arc::ptr_eq(&self.attempt_binding, &contract.attempt_binding)
            || self.exact_device_state_materialization
                != PreparedDeviceStateMaterialization::Provisioned
            || self.root_overlay_materialization != PreparedRootOverlayMaterialization::Absent
        {
            return Err(QemuSpawnError::PreparedLaunchAdmissionChanged);
        }
        validate_guarded_launch_requirements(self.launch_resources, contract)?;
        self.revalidate_identity().map(|_| ())
    }
}

fn open_prepared_vmstate(directory: &OwnedFd, path: &Path) -> Result<OwnedFd, QemuSpawnError> {
    openat(
        directory,
        crate::DEFAULT_VMSTATE_FILE_NAME,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        let source: io::Error = source.into();
        if source.kind() == io::ErrorKind::NotFound {
            QemuSpawnError::MissingPreparedDeviceState {
                path: path.join(crate::DEFAULT_VMSTATE_FILE_NAME),
            }
        } else {
            QemuSpawnError::Io {
                operation: "open prepared exact-VMState container",
                source,
            }
        }
    })
}

fn validate_diagnostic_trace_metadata(
    file_name: &'static str,
    metadata: &rustix::fs::Stat,
    credentials: QemuChildCredentials,
) -> Result<(), QemuSpawnError> {
    let mode = metadata.st_mode & 0o7777;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1
        || metadata.st_uid != credentials.user_id
        || metadata.st_gid != credentials.group_id
        || mode != 0o600
    {
        return Err(QemuSpawnError::DiagnosticTraceMetadata {
            file: file_name,
            file_type_mode: metadata.st_mode & libc::S_IFMT,
            links: metadata.st_nlink,
            user_id: metadata.st_uid,
            group_id: metadata.st_gid,
            mode,
        });
    }
    Ok(())
}

fn open_optional_root_overlay(directory: &OwnedFd) -> Result<Option<OwnedFd>, QemuSpawnError> {
    match openat(
        directory,
        crate::DEFAULT_ROOT_OVERLAY_FILE_NAME,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => Ok(Some(file)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(source) => Err(QemuSpawnError::Io {
            operation: "open optional prepared root overlay",
            source: source.into(),
        }),
    }
}

pub(super) fn open_prepared_root_overlay(
    directory: &OwnedFd,
    path: &Path,
) -> Result<OwnedFd, QemuSpawnError> {
    open_optional_root_overlay(directory)?.ok_or_else(|| {
        QemuSpawnError::PreparedRootOverlayNotReady {
            path: path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
        }
    })
}
