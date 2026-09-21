//! Linear exact device-state and root-overlay materialization for guarded QEMU.

mod exact_restore;
mod exact_writers;

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use crucible::ContentHash;
use rustix::fs::{Mode, OFlags, fchown, fstat, fsync, openat};
use rustix::process::{Gid, Uid};
use sha2::{Digest as _, Sha256};

use super::{
    AttemptResourceBinding, QemuChildProcessContract, QemuPreparedRunDirectory, QemuSpawnError,
};
use crate::QemuExactCheckpointInputMaterialization;

const EXACT_DEVICE_STATE_BINDING_DOMAIN: &str =
    "crucible.executor.exact-device-state-restore-binding.v1";

/// Operational binding from one exact-checkpoint root to sealed device state.
///
/// The constructor accepts only the digest of the complete typed checkpoint
/// root. It deliberately does not accept a [`crate::QemuVmSnapshot`] metadata
/// identity, because metadata alone does not authenticate the device-state
/// child selected for restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QemuExactDeviceStateBinding {
    identity: ContentHash,
    snapshot: Option<ContentHash>,
}

impl QemuExactDeviceStateBinding {
    /// Derives the binding from one authenticated exact-checkpoint root digest.
    #[must_use]
    pub(crate) fn from_exact_checkpoint_root(
        root: ContentHash,
        target_manifest: ContentHash,
        snapshot: ContentHash,
    ) -> Self {
        let identity = ContentHash::from_canonical_material(
            EXACT_DEVICE_STATE_BINDING_DOMAIN,
            &format!(
                "root={}\ntarget_manifest={}\nsnapshot={}",
                root.to_hex(),
                target_manifest.to_hex(),
                snapshot.to_hex()
            ),
        );
        Self {
            identity,
            snapshot: Some(snapshot),
        }
    }

    pub(crate) const fn snapshot(self) -> Option<ContentHash> {
        self.snapshot
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PreparedDeviceStateMaterialization {
    Provisioned,
    Updating,
    HotForkChild,
    Exact {
        binding: QemuExactDeviceStateBinding,
        bytes: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PreparedRootOverlayMaterialization {
    Absent,
    Provisioned,
    Updating,
    HotForkChild,
    Exact {
        binding: QemuExactDeviceStateBinding,
        bytes: u64,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum PreparedExactCheckpointMaterialization {
    Absent,
    Updating {
        binding: QemuExactDeviceStateBinding,
        device_state_bytes: u64,
        root_overlay_bytes: u64,
        ram_layer_bytes: Vec<u64>,
        next_ram_layer: usize,
    },
    Complete {
        binding: QemuExactDeviceStateBinding,
    },
    Claimed {
        binding: QemuExactDeviceStateBinding,
    },
}

/// Linear writer for one authenticated exact device-state materialization.
///
/// The writer borrows its pinned run-directory authority for the complete
/// transaction. Dropping it before [`Self::finish`] leaves the destination in
/// a fail-closed updating state, so a partially copied checkpoint cannot be
/// launched using this device-state input.
#[derive(Debug)]
#[must_use = "exact device-state materialization must be finished before guarded launch"]
struct AtomicExactDeviceStateWriter<'a> {
    prepared: &'a mut QemuPreparedRunDirectory,
    destination: QemuExactCheckpointInputMaterialization,
    verifier: StreamSha256Verifier,
    binding: QemuExactDeviceStateBinding,
    expected_bytes: u64,
    written_bytes: u64,
}

/// Linear writer for one authenticated exact root-overlay materialization.
///
/// The destination is created relative to the retained directory descriptor
/// and remains pinned for guarded spawn. Dropping before [`Self::finish`]
/// leaves the directory unlaunchable.
#[derive(Debug)]
#[must_use = "exact root-overlay materialization must be finished before guarded launch"]
struct AtomicExactRootOverlayWriter<'a> {
    prepared: &'a mut QemuPreparedRunDirectory,
    destination: File,
    verifier: crucible::exact_checkpoint::ExactCheckpointRootOverlayVerifier,
    binding: QemuExactDeviceStateBinding,
    expected_bytes: u64,
    written_bytes: u64,
}

/// Opaque sealed RAM input admitted by one guarded exact-checkpoint transaction.
#[derive(Debug)]
pub(crate) struct QemuGuardedExactRamInput {
    file: File,
    binding: QemuExactDeviceStateBinding,
    attempt_binding: Arc<AttemptResourceBinding>,
    layer_index: usize,
    expected_bytes: u64,
}

#[derive(Debug)]
struct QemuGuardedRamInputs {
    inputs: Vec<QemuGuardedExactRamInput>,
    binding: QemuExactDeviceStateBinding,
    attempt_binding: Arc<AttemptResourceBinding>,
    request: crate::QmpCheckpointRestoreRequest,
    topology: ContentHash,
}

/// Linear ordered RAM authority for one rooted production checkpoint.
#[derive(Debug)]
pub(crate) struct SealedAtomicExactRestoreInputs {
    inner: QemuGuardedRamInputs,
    target: crucible::exact_checkpoint::ExactCheckpointVerifiedNode,
}

/// Owned byte streams for one repository-rooted exact restore.
///
/// The streams carry no launch authority. QEMU consumes them only together
/// with an authenticated execution binding and verifies every byte before it
/// can spawn or issue a restore command.
pub(crate) struct QemuProductionExactRestoreSource {
    root_overlay: Box<dyn Read + Send>,
    device_state: Box<dyn Read + Send>,
    ram_layers: Vec<Box<dyn Read + Send>>,
}

impl std::fmt::Debug for QemuProductionExactRestoreSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuProductionExactRestoreSource")
            .field("ram_layers", &self.ram_layers.len())
            .finish_non_exhaustive()
    }
}

impl QemuProductionExactRestoreSource {
    pub(crate) fn new(
        root_overlay: Box<dyn Read + Send>,
        device_state: Box<dyn Read + Send>,
        ram_layers: Vec<Box<dyn Read + Send>>,
    ) -> Self {
        Self {
            root_overlay,
            device_state,
            ram_layers,
        }
    }
}

impl QemuGuardedRamInputs {
    pub(crate) fn descriptors(&self) -> impl Iterator<Item = std::os::fd::BorrowedFd<'_>> {
        self.inputs.iter().map(QemuGuardedExactRamInput::as_fd)
    }

    pub(crate) fn binding(&self) -> QemuExactDeviceStateBinding {
        self.binding
    }

    pub(crate) const fn request(&self) -> &crate::QmpCheckpointRestoreRequest {
        &self.request
    }

    pub(crate) const fn topology(&self) -> ContentHash {
        self.topology
    }
}

macro_rules! guarded_ram_input_accessors {
    ($type:ty) => {
        impl $type {
            pub(crate) fn descriptors(&self) -> impl Iterator<Item = std::os::fd::BorrowedFd<'_>> {
                self.inner.descriptors()
            }

            pub(crate) fn binding(&self) -> QemuExactDeviceStateBinding {
                self.inner.binding()
            }

            pub(crate) const fn request(&self) -> &crate::QmpCheckpointRestoreRequest {
                self.inner.request()
            }

            pub(crate) const fn topology(&self) -> ContentHash {
                self.inner.topology()
            }
        }
    };
}

guarded_ram_input_accessors!(SealedAtomicExactRestoreInputs);

impl SealedAtomicExactRestoreInputs {
    pub(crate) const fn target(&self) -> &crucible::exact_checkpoint::ExactCheckpointVerifiedNode {
        &self.target
    }

    pub(crate) fn into_target(self) -> crucible::exact_checkpoint::ExactCheckpointVerifiedNode {
        self.target
    }
}

impl QemuGuardedExactRamInput {
    pub(crate) fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.file.as_fd()
    }

    fn matches(
        &self,
        attempt_binding: &Arc<AttemptResourceBinding>,
        binding: QemuExactDeviceStateBinding,
        layer_index: usize,
        expected_bytes: u64,
    ) -> bool {
        Arc::ptr_eq(&self.attempt_binding, attempt_binding)
            && self.binding == binding
            && self.layer_index == layer_index
            && self.expected_bytes == expected_bytes
    }
}

/// Linear writer for one descriptor-backed exact RAM restore input.
///
/// The input is created as an anonymous sealable memfd and never reopened by
/// path. Successful completion returns the same sealed file at offset zero so
/// QMP can import it directly.
#[derive(Debug)]
#[must_use = "exact RAM input materialization must be finished before restore"]
struct AtomicExactRamLayerWriter<'a> {
    prepared: &'a mut QemuPreparedRunDirectory,
    destination: QemuExactCheckpointInputMaterialization,
    verifier: StreamSha256Verifier,
    layer_index: usize,
    expected_bytes: u64,
    written_bytes: u64,
}

#[derive(Debug)]
struct StreamSha256Verifier {
    expected: ContentHash,
    observed: Sha256,
}

impl StreamSha256Verifier {
    fn update(&mut self, bytes: &[u8]) {
        self.observed.update(bytes);
    }

    fn finish(self) -> Result<(), QemuSpawnError> {
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&self.observed.finalize());
        if (ContentHash { bytes }) != self.expected {
            return Err(super::invalid_input(
                "authenticate exact checkpoint input",
                "materialized bytes differ from the repository-bound content digest",
            ));
        }
        Ok(())
    }
}

impl QemuPreparedRunDirectory {
    /// Duplicates the bound sealed device-state input at offset zero for QMP restore.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the complete artifact set or device-state
    /// materialization is incomplete, belongs to another closure root, or the
    /// sealed input cannot be duplicated and positioned.
    pub(crate) fn exact_device_state_input(
        &self,
        expected: QemuExactDeviceStateBinding,
    ) -> Result<File, QemuSpawnError> {
        self.require_exact_device_state(expected)?;
        self.revalidate_identity()?;
        let sealed = self.exact_device_state.as_ref().ok_or_else(|| {
            QemuSpawnError::PreparedExactCheckpointNotReady {
                path: self.path.clone(),
            }
        })?;
        let mut input = sealed.try_clone().map_err(|source| QemuSpawnError::Io {
            operation: "duplicate sealed exact device-state input",
            source,
        })?;
        input
            .seek(SeekFrom::Start(0))
            .map_err(|source| QemuSpawnError::Io {
                operation: "position exact device-state input",
                source,
            })?;
        Ok(input)
    }

    /// Creates fresh QCOW2 VMState and root-overlay artifacts under containment.
    ///
    /// The image tool adjacent to `qemu_executable` runs under the same cgroup,
    /// cancellation event, file ceiling, pinned directory, and unprivileged
    /// credentials as the eventual QEMU process. Both invocations have a fixed
    /// absolute deadline. Success reauthenticates and synchronizes the exact
    /// named inodes before fresh launch becomes possible.
    ///
    /// # Errors
    ///
    /// Returns `QemuGuardedImagePreparationError` when admission or
    /// pinned-directory authentication fails, the root image has an invalid
    /// size, either helper cannot be spawned, contained, completed, or reaped,
    /// or the resulting artifacts violate the aggregate writable ceiling.
    pub fn prepare_fresh_artifacts_guarded(
        &mut self,
        qemu_executable: &Path,
        root_image: Option<&Path>,
        contract: &super::QemuChildProcessContract,
    ) -> Result<(), super::QemuGuardedImagePreparationError> {
        let root_bytes = match (self.launch_resources.has_root_overlay(), root_image) {
            (true, Some(root_image)) => {
                let bytes = std::fs::metadata(root_image)
                    .map_err(|source| super::QemuGuardedImagePreparationError {
                        source: QemuSpawnError::Io {
                            operation: "inspect fresh root image",
                            source,
                        },
                        child: None,
                    })?
                    .len();
                if bytes == 0 {
                    return Err(super::QemuGuardedImagePreparationError {
                        source: QemuSpawnError::FreshRootImageEmpty {
                            path: root_image.to_owned(),
                        },
                        child: None,
                    });
                }
                Some(bytes)
            }
            (true, None) => {
                return Err(super::QemuGuardedImagePreparationError {
                    source: QemuSpawnError::FreshRootImageMissing,
                    child: None,
                });
            }
            (false, Some(_)) => {
                return Err(super::QemuGuardedImagePreparationError {
                    source: QemuSpawnError::FreshRootImageUnexpected,
                    child: None,
                });
            }
            (false, None) => None,
        };
        let image_tool = qemu_executable.with_file_name("qemu-img");
        if !image_tool.is_absolute() {
            return Err(super::QemuGuardedImagePreparationError {
                source: QemuSpawnError::FreshImageToolPath { path: image_tool },
                child: None,
            });
        }
        let device_state_bytes = self.launch_resources.minimum_writable_bytes();
        let device_state_args = [
            OsString::from("create"),
            OsString::from("-q"),
            OsString::from("-f"),
            OsString::from("qcow2"),
            OsString::from(crate::DEFAULT_VMSTATE_FILE_NAME),
            OsString::from(format!("{device_state_bytes}B")),
        ];
        super::run_guarded_image_tool(
            &image_tool,
            &device_state_args,
            "create fresh VMState container",
            self,
            contract,
        )?;

        if let Some(root_bytes) = root_bytes {
            let root_args = [
                OsString::from("create"),
                OsString::from("-q"),
                OsString::from("-f"),
                OsString::from("qcow2"),
                OsString::from(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
                OsString::from(format!("{root_bytes}B")),
            ];
            super::run_guarded_image_tool(
                &image_tool,
                &root_args,
                "create fresh root overlay",
                self,
                contract,
            )?;
        }

        self.seal_fresh_artifacts()
            .map_err(|source| super::QemuGuardedImagePreparationError {
                source,
                child: None,
            })
    }

    /// Begins one sealed exact device-state input for descriptor restore.
    ///
    /// The authority becomes unlaunchable before any write. The returned writer
    /// accepts at most `expected_bytes`; successful completion seals the bytes
    /// and binds them to `binding`. The owner must derive that binding
    /// from the complete exact-checkpoint root, not metadata alone.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] if the declared length is zero, exceeds the
    /// admitted aggregate writable-byte ceiling, or the sealed memfd cannot be
    /// created. Once a valid
    /// transaction begins, every error leaves the authority unready. The
    /// run-directory VMState file remains the writable container for future
    /// native captures and is never used as this restore input.
    fn begin_atomic_exact_device_state(
        &mut self,
        expected_bytes: u64,
    ) -> Result<AtomicExactDeviceStateWriter<'_>, QemuSpawnError> {
        let (_, expected_sha256, target_bytes) = self
            .exact_checkpoint_target
            .as_ref()
            .ok_or_else(|| {
                super::invalid_input(
                    "begin exact device-state materialization",
                    "production device-state materialization has no authenticated target",
                )
            })?
            .device_state();
        if target_bytes != expected_bytes {
            return Err(super::invalid_input(
                "begin exact device-state materialization",
                "device-state length differs from the repository target",
            ));
        }
        self.begin_device_state_materialization(
            expected_bytes,
            StreamSha256Verifier {
                expected: expected_sha256,
                observed: Sha256::new(),
            },
        )
    }

    fn begin_device_state_materialization(
        &mut self,
        expected_bytes: u64,
        verifier: StreamSha256Verifier,
    ) -> Result<AtomicExactDeviceStateWriter<'_>, QemuSpawnError> {
        if expected_bytes == 0 || expected_bytes > self.admitted_ceiling.2 {
            return Err(QemuSpawnError::PreparedDeviceStateLength {
                length: expected_bytes,
                maximum: self.admitted_ceiling.2,
            });
        }
        let binding = match &self.exact_checkpoint_materialization {
            PreparedExactCheckpointMaterialization::Updating {
                binding: admitted_binding,
                device_state_bytes,
                root_overlay_bytes,
                ..
            } if *device_state_bytes == expected_bytes
                && self.root_overlay_materialization
                    == (PreparedRootOverlayMaterialization::Exact {
                        binding: *admitted_binding,
                        bytes: *root_overlay_bytes,
                    }) =>
            {
                *admitted_binding
            }
            PreparedExactCheckpointMaterialization::Updating { .. }
            | PreparedExactCheckpointMaterialization::Complete { .. }
            | PreparedExactCheckpointMaterialization::Claimed { .. }
            | PreparedExactCheckpointMaterialization::Absent => {
                return Err(super::invalid_input(
                    "begin exact device-state materialization",
                    "device state differs from the admitted exact checkpoint or is out of order",
                ));
            }
        };

        self.exact_device_state_materialization = PreparedDeviceStateMaterialization::Updating;
        self.exact_device_state = None;
        let destination =
            QemuExactCheckpointInputMaterialization::new(expected_bytes).map_err(|source| {
                QemuSpawnError::Io {
                    operation: "create sealed exact device-state input",
                    source,
                }
            })?;

        Ok(AtomicExactDeviceStateWriter {
            prepared: self,
            destination,
            verifier,
            binding,
            expected_bytes,
            written_bytes: 0,
        })
    }

    /// Begins materializing one exact root overlay into the pinned directory.
    ///
    /// The maximum overlay length is the admitted aggregate writable ceiling
    /// after reserving the command's complete VMState baseline. The destination
    /// is created without following or replacing a named inode and is retained
    /// by descriptor through guarded spawn.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the launch has no root overlay, the
    /// declared length is zero or exceeds its conservative aggregate share, a
    /// destination already exists, or descriptor-relative creation fails.
    fn begin_atomic_exact_root_overlay(
        &mut self,
        expected_bytes: u64,
    ) -> Result<AtomicExactRootOverlayWriter<'_>, QemuSpawnError> {
        let verifier = self
            .exact_checkpoint_target
            .as_ref()
            .ok_or_else(|| {
                super::invalid_input(
                    "begin exact root-overlay materialization",
                    "production root-overlay materialization has no authenticated target",
                )
            })?
            .root_overlay_verifier()
            .map_err(|_| {
                super::invalid_input(
                    "allocate exact root-overlay verifier",
                    "exact root-overlay verifier allocation failed",
                )
            })?;
        self.begin_root_overlay_materialization(expected_bytes, verifier)
    }

    fn begin_root_overlay_materialization(
        &mut self,
        expected_bytes: u64,
        verifier: crucible::exact_checkpoint::ExactCheckpointRootOverlayVerifier,
    ) -> Result<AtomicExactRootOverlayWriter<'_>, QemuSpawnError> {
        let maximum = self
            .admitted_ceiling
            .2
            .saturating_sub(self.launch_resources.minimum_writable_bytes());
        if !self.launch_resources.has_root_overlay()
            || expected_bytes == 0
            || expected_bytes > maximum
        {
            return Err(QemuSpawnError::PreparedRootOverlayLength {
                length: expected_bytes,
                maximum,
            });
        }
        if self.root_overlay_materialization != PreparedRootOverlayMaterialization::Absent {
            return Err(QemuSpawnError::PreparedRootOverlayAlreadyExists {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            });
        }
        let binding = match &self.exact_checkpoint_materialization {
            PreparedExactCheckpointMaterialization::Updating {
                binding: admitted_binding,
                root_overlay_bytes,
                ..
            } if *root_overlay_bytes == expected_bytes => *admitted_binding,
            PreparedExactCheckpointMaterialization::Updating { .. }
            | PreparedExactCheckpointMaterialization::Complete { .. }
            | PreparedExactCheckpointMaterialization::Claimed { .. }
            | PreparedExactCheckpointMaterialization::Absent => {
                return Err(super::invalid_input(
                    "begin exact root-overlay materialization",
                    "root overlay differs from the admitted exact checkpoint",
                ));
            }
        };
        self.root_overlay_materialization = PreparedRootOverlayMaterialization::Updating;
        let destination = File::from(self.create_root_overlay_destination()?);

        Ok(AtomicExactRootOverlayWriter {
            prepared: self,
            destination,
            verifier,
            binding,
            expected_bytes,
            written_bytes: 0,
        })
    }

    fn create_root_overlay_destination(&mut self) -> Result<OwnedFd, QemuSpawnError> {
        let destination = openat(
            &self.directory,
            crate::DEFAULT_ROOT_OVERLAY_FILE_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "create prepared root overlay",
            source: source.into(),
        })?;
        let metadata = fstat(&destination).map_err(|source| QemuSpawnError::Io {
            operation: "inspect prepared root overlay",
            source: source.into(),
        })?;
        if let Some(credentials) = self.child_credentials {
            fchown(
                &destination,
                Some(Uid::from_raw(credentials.user_id)),
                Some(Gid::from_raw(credentials.group_id)),
            )
            .map_err(|source| QemuSpawnError::Io {
                operation: "assign prepared root-overlay ownership",
                source: source.into(),
            })?;
        }
        self.root_overlay_identity = Some(super::PinnedFileIdentity::from_stat(&metadata));
        self.root_overlay = Some(
            destination
                .try_clone()
                .map_err(|source| QemuSpawnError::Io {
                    operation: "retain prepared root overlay",
                    source,
                })?,
        );
        Ok(destination)
    }

    /// Requires the prepared files to be the provisioned fresh-generation pair.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when preparation was incomplete, exact bytes
    /// were substituted, or either retained inode changed.
    pub fn require_fresh_artifacts(&self) -> Result<(), QemuSpawnError> {
        if self.exact_device_state_materialization
            != PreparedDeviceStateMaterialization::Provisioned
            || (self.launch_resources.has_root_overlay()
                && self.root_overlay_materialization
                    != PreparedRootOverlayMaterialization::Provisioned)
        {
            return Err(QemuSpawnError::FreshArtifactsNotReady {
                path: self.path.clone(),
            });
        }
        self.revalidate().map(|_| ())
    }

    fn seal_fresh_artifacts(&mut self) -> Result<(), QemuSpawnError> {
        let vmstate = self.revalidate_identity()?;
        let device_state_bytes =
            checked_artifact_length(vmstate.st_size, self.admitted_ceiling.2, &self.path)?;
        let root_bytes = if self.launch_resources.has_root_overlay() {
            let root = super::open_prepared_root_overlay(&self.directory, &self.path)?;
            let metadata = fstat(&root).map_err(|source| QemuSpawnError::Io {
                operation: "inspect fresh root overlay",
                source: source.into(),
            })?;
            let bytes =
                checked_artifact_length(metadata.st_size, self.admitted_ceiling.2, &self.path)?;
            self.root_overlay_identity = Some(super::PinnedFileIdentity::from_stat(&metadata));
            self.root_overlay = Some(root);
            bytes
        } else {
            0
        };
        if device_state_bytes
            .checked_add(root_bytes)
            .is_none_or(|bytes| bytes > self.admitted_ceiling.2)
        {
            return Err(QemuSpawnError::PreparedArtifactsTooLarge {
                device_state_bytes,
                root_overlay_bytes: root_bytes,
                maximum: self.admitted_ceiling.2,
            });
        }
        fsync(&self.vmstate).map_err(|source| QemuSpawnError::Io {
            operation: "synchronize fresh VMState container",
            source: source.into(),
        })?;
        if let Some(root) = &self.root_overlay {
            fsync(root).map_err(|source| QemuSpawnError::Io {
                operation: "synchronize fresh root overlay",
                source: source.into(),
            })?;
        }
        fsync(&self.directory).map_err(|source| QemuSpawnError::Io {
            operation: "synchronize fresh generation directory",
            source: source.into(),
        })?;
        self.root_overlay_materialization = if self.launch_resources.has_root_overlay() {
            PreparedRootOverlayMaterialization::Provisioned
        } else {
            PreparedRootOverlayMaterialization::Absent
        };
        Ok(())
    }

    /// Requires the sealed device-state memfd to contain one exact root binding.
    ///
    /// Exact-restore launchers call this after materialization and immediately
    /// before guarded spawn. A merely provisioned image is deliberately not an
    /// exact-checkpoint authority.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] if materialization is incomplete or the
    /// sealed input is bound to another exact-checkpoint root.
    pub(crate) fn require_exact_device_state(
        &self,
        expected: QemuExactDeviceStateBinding,
    ) -> Result<(), QemuSpawnError> {
        match (
            &self.exact_checkpoint_materialization,
            self.exact_device_state_materialization,
        ) {
            (
                PreparedExactCheckpointMaterialization::Complete { binding }
                | PreparedExactCheckpointMaterialization::Claimed { binding },
                PreparedDeviceStateMaterialization::Exact {
                    binding: device_binding,
                    ..
                },
            ) if *binding == expected && device_binding == expected => Ok(()),
            (PreparedExactCheckpointMaterialization::Absent, _)
            | (PreparedExactCheckpointMaterialization::Updating { .. }, _)
            | (PreparedExactCheckpointMaterialization::Complete { .. }, _)
            | (PreparedExactCheckpointMaterialization::Claimed { .. }, _) => {
                Err(QemuSpawnError::PreparedDeviceStateNotReady)
            }
        }
    }

    /// Requires the pinned root overlay to carry one exact checkpoint binding.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the launch has no completed exact root
    /// overlay or its bytes were materialized for another checkpoint root.
    pub(crate) fn require_exact_root_overlay(
        &self,
        expected: QemuExactDeviceStateBinding,
    ) -> Result<(), QemuSpawnError> {
        match (
            &self.exact_checkpoint_materialization,
            self.root_overlay_materialization,
        ) {
            (
                PreparedExactCheckpointMaterialization::Complete { binding }
                | PreparedExactCheckpointMaterialization::Claimed { binding },
                PreparedRootOverlayMaterialization::Exact {
                    binding: overlay_binding,
                    ..
                },
            ) if *binding == expected && overlay_binding == expected => Ok(()),
            _ => Err(QemuSpawnError::PreparedRootOverlayNotReady {
                path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            }),
        }
    }

    pub(crate) fn claim_exact_checkpoint_materialization(
        &mut self,
        process_contract: &QemuChildProcessContract,
        expected: QemuExactDeviceStateBinding,
    ) -> Result<(), QemuSpawnError> {
        self.require_same_attempt(process_contract)?;
        match self.exact_checkpoint_materialization {
            PreparedExactCheckpointMaterialization::Complete { binding } if binding == expected => {
                self.exact_checkpoint_materialization =
                    PreparedExactCheckpointMaterialization::Claimed { binding };
                Ok(())
            }
            _ => Err(super::invalid_input(
                "claim exact checkpoint materialization",
                "the exact checkpoint set is incomplete, belongs to another root, or was already claimed",
            )),
        }
    }

    pub(crate) fn validate_exact_ram_inputs(
        &self,
        expected: QemuExactDeviceStateBinding,
        inputs: &SealedAtomicExactRestoreInputs,
        expected_bytes: impl IntoIterator<Item = u64>,
    ) -> Result<(), QemuSpawnError> {
        self.validate_guarded_ram_inputs(expected, &inputs.inner, expected_bytes)
    }

    fn validate_guarded_ram_inputs(
        &self,
        expected: QemuExactDeviceStateBinding,
        inputs: &QemuGuardedRamInputs,
        expected_bytes: impl IntoIterator<Item = u64>,
    ) -> Result<(), QemuSpawnError> {
        let expected_bytes = expected_bytes.into_iter().collect::<Vec<_>>();
        if inputs.binding != expected
            || !Arc::ptr_eq(&inputs.attempt_binding, &self.attempt_binding)
            || inputs.inputs.len() != expected_bytes.len()
            || inputs.inputs.iter().enumerate().any(|(index, input)| {
                !input.matches(
                    &self.attempt_binding,
                    expected,
                    index,
                    expected_bytes[index],
                )
            })
        {
            return Err(super::invalid_input(
                "validate exact RAM materialization",
                "RAM inputs do not belong to this exact root, attempt, order, or geometry",
            ));
        }
        Ok(())
    }

    fn require_same_attempt(
        &self,
        process_contract: &QemuChildProcessContract,
    ) -> Result<(), QemuSpawnError> {
        if self.admitted_ceiling != process_contract.admitted_resource_ceiling()
            || !std::sync::Arc::ptr_eq(&self.attempt_binding, &process_contract.attempt_binding)
        {
            return Err(QemuSpawnError::PreparedLaunchAdmissionChanged);
        }
        Ok(())
    }
}

fn copy_exact_checkpoint_stream(
    source: &mut dyn Read,
    destination: &mut dyn Write,
    cancellation: BorrowedFd<'_>,
    operation: &'static str,
) -> Result<(), QemuSpawnError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(1024 * 1024).map_err(|_| {
        super::invalid_input(
            "allocate exact restore copy buffer",
            "exact restore copy buffer allocation failed",
        )
    })?;
    buffer.resize(1024 * 1024, 0);
    loop {
        require_exact_restore_not_canceled(cancellation)?;
        let count = source
            .read(&mut buffer)
            .map_err(|source| QemuSpawnError::Io { operation, source })?;
        if count == 0 {
            break;
        }
        destination
            .write_all(&buffer[..count])
            .map_err(|source| QemuSpawnError::Io { operation, source })?;
    }
    require_exact_restore_not_canceled(cancellation)
}

pub(crate) fn require_exact_restore_not_canceled(
    cancellation: BorrowedFd<'_>,
) -> Result<(), QemuSpawnError> {
    let mut descriptor = libc::pollfd {
        fd: cancellation.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let observed = unsafe {
        // SAFETY: `descriptor` points to one initialized pollfd. The zero
        // timeout observes readiness without consuming the sticky eventfd.
        libc::poll(&mut descriptor, 1, 0)
    };
    if observed < 0 {
        return Err(QemuSpawnError::Io {
            operation: "poll exact restore cancellation",
            source: io::Error::last_os_error(),
        });
    }
    if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(QemuSpawnError::Io {
            operation: "poll exact restore cancellation",
            source: io::Error::from_raw_os_error(libc::EBADF),
        });
    }
    if observed > 0 && descriptor.revents & libc::POLLIN != 0 {
        return Err(QemuSpawnError::Io {
            operation: "authenticate exact restore cancellation",
            source: io::Error::from_raw_os_error(libc::ECANCELED),
        });
    }
    Ok(())
}

fn checked_artifact_length(raw: i64, maximum: u64, path: &Path) -> Result<u64, QemuSpawnError> {
    let bytes = u64::try_from(raw).map_err(|_| QemuSpawnError::PreparedArtifactNotReady {
        path: path.to_owned(),
    })?;
    if bytes == 0 || bytes > maximum {
        return Err(QemuSpawnError::PreparedArtifactNotReady {
            path: path.to_owned(),
        });
    }
    Ok(bytes)
}
