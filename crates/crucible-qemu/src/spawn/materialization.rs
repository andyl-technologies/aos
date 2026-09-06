//! Linear exact-VMState materialization for pinned QEMU run directories.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use crucible::ContentHash;
use rustix::fs::{Mode, OFlags, fchown, fstat, fsync, openat};
use rustix::ioctl::{IntegerSetter, ioctl, opcode};
use rustix::process::{Gid, Uid};

use super::{QemuPreparedRunDirectory, QemuSpawnError};
use crate::QemuLaunchCommand;

const EXACT_VMSTATE_BINDING_DOMAIN: &str = "crucible.executor.exact-vmstate-restore-binding.v1";
const REPLACEMENT_VMSTATE_BINDING_DOMAIN: &str =
    "crucible.executor.replacement-vmstate-restore-binding.v1";
const THIN_VMSTATE_BINDING_DOMAIN: &str = "crucible.executor.thin-vmstate-restore-binding.v1";
const FICLONE: rustix::ioctl::Opcode = opcode::write::<libc::c_int>(0x94, 9);

/// Operational binding from one exact-checkpoint root to materialized VMState.
///
/// The constructor accepts only the digest of the complete typed checkpoint
/// root. It deliberately does not accept a [`crate::QemuVmSnapshot`] metadata
/// identity, because metadata alone does not authenticate the opaque VMState
/// child selected for restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuVmStateBinding(ContentHash);

impl QemuVmStateBinding {
    /// Derives the binding from one authenticated exact-checkpoint root digest.
    #[must_use]
    pub fn from_exact_checkpoint_root_digest(digest: [u8; 32]) -> Self {
        Self(ContentHash::from_canonical_hex_bytes(
            EXACT_VMSTATE_BINDING_DOMAIN,
            &digest,
        ))
    }

    /// Derives a binding for one locally captured replacement snapshot.
    ///
    /// Unlike an externally retained exact checkpoint, replacement artifacts
    /// are cloned from descriptor-pinned files in the same attempt while the
    /// lifecycle holds the source node at its authenticated capture boundary.
    /// The snapshot digest therefore binds the two reflinked destination
    /// inodes to that local capture transaction without pretending that it is
    /// a complete repository checkpoint root.
    #[must_use]
    pub fn from_replacement_snapshot_digest(digest: [u8; 32]) -> Self {
        Self(ContentHash::from_canonical_hex_bytes(
            REPLACEMENT_VMSTATE_BINDING_DOMAIN,
            &digest,
        ))
    }

    /// Derives the binding for one authenticated thin-path artifact pair.
    ///
    /// The digest identifies a catalog entry that binds the prepared VMState,
    /// root overlay when present, and checkpoint metadata. Domain separation
    /// prevents a thin artifact from being mistaken for an exact campaign root
    /// or an in-attempt replacement.
    #[must_use]
    pub fn from_thin_checkpoint_artifact_digest(digest: [u8; 32]) -> Self {
        Self(ContentHash::from_canonical_hex_bytes(
            THIN_VMSTATE_BINDING_DOMAIN,
            &digest,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PreparedVmStateMaterialization {
    Provisioned,
    Updating,
    HotForkChild,
    Exact {
        binding: QemuVmStateBinding,
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
        binding: QemuVmStateBinding,
        bytes: u64,
    },
}

/// Linear writer for one authenticated exact-VMState materialization.
///
/// The writer borrows its pinned run-directory authority for the complete
/// transaction. Dropping it before [`Self::finish`] leaves the destination in
/// a fail-closed updating state, so a partially copied checkpoint cannot be
/// launched as either a provisioned or exact VMState image.
#[derive(Debug)]
#[must_use = "exact VMState materialization must be finished before guarded launch"]
pub struct QemuVmStateMaterialization<'a> {
    prepared: &'a mut QemuPreparedRunDirectory,
    destination: File,
    binding: QemuVmStateBinding,
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
pub struct QemuRootOverlayMaterialization<'a> {
    prepared: &'a mut QemuPreparedRunDirectory,
    destination: File,
    binding: QemuVmStateBinding,
    expected_bytes: u64,
    written_bytes: u64,
}

impl QemuPreparedRunDirectory {
    /// Admits a run directory for exact-checkpoint materialization only.
    ///
    /// This operation does not grant process-launch authority. It accepts the
    /// execution ceiling already reserved by the daemon, validates the command
    /// baseline before path access, and pins the destination to the exact
    /// attempt lifecycle carried by `contract`. A retained checkpoint can then
    /// be streamed before the same contract is lent to spawn. Guarded spawn
    /// rejects a contract from another attempt even when every numeric ceiling
    /// is identical.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] before path access when the command exceeds
    /// the supplied contract. Otherwise returns an error when the path or
    /// required VMState file cannot be pinned without following symlinks.
    pub fn open_for_materialization(
        command: &QemuLaunchCommand,
        path: impl AsRef<Path>,
        contract: &super::QemuChildProcessContract,
    ) -> Result<Self, QemuSpawnError> {
        super::validate_guarded_launch_resources(command, contract)?;
        Self::open_for_requirements(command.resource_requirements(), path.as_ref(), contract)
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
        let vmstate_bytes = self.launch_resources.minimum_writable_bytes();
        let vmstate_args = [
            OsString::from("create"),
            OsString::from("-q"),
            OsString::from("-f"),
            OsString::from("qcow2"),
            OsString::from(crate::DEFAULT_VMSTATE_FILE_NAME),
            OsString::from(format!("{vmstate_bytes}B")),
        ];
        super::run_guarded_image_tool(
            &image_tool,
            &vmstate_args,
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

    /// Begins replacing the pinned VMState file with one exact snapshot image.
    ///
    /// The authority becomes unlaunchable before any truncate or write. The
    /// returned writer accepts at most `expected_bytes`; successful completion
    /// durably binds the file to `binding`. The owner must derive that binding
    /// from the complete exact-checkpoint root, not metadata alone.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] if the declared length is zero, exceeds the
    /// admitted aggregate writable-byte ceiling, or the pinned file cannot be
    /// duplicated, truncated, or positioned for replacement. Once a valid
    /// transaction begins, every error leaves the authority unready.
    pub fn begin_exact_vmstate_materialization(
        &mut self,
        binding: QemuVmStateBinding,
        expected_bytes: u64,
    ) -> Result<QemuVmStateMaterialization<'_>, QemuSpawnError> {
        if expected_bytes == 0 || expected_bytes > self.admitted_ceiling.2 {
            return Err(QemuSpawnError::PreparedVmStateLength {
                length: expected_bytes,
                maximum: self.admitted_ceiling.2,
            });
        }

        self.vmstate_materialization = PreparedVmStateMaterialization::Updating;
        let mut destination =
            File::from(
                self.vmstate
                    .try_clone()
                    .map_err(|source| QemuSpawnError::Io {
                        operation: "duplicate prepared exact-VMState container",
                        source,
                    })?,
            );
        destination
            .set_len(0)
            .map_err(|source| QemuSpawnError::Io {
                operation: "truncate prepared exact-VMState container",
                source,
            })?;
        destination
            .seek(SeekFrom::Start(0))
            .map_err(|source| QemuSpawnError::Io {
                operation: "position prepared exact-VMState container",
                source,
            })?;

        Ok(QemuVmStateMaterialization {
            prepared: self,
            destination,
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
    pub fn begin_exact_root_overlay_materialization(
        &mut self,
        binding: QemuVmStateBinding,
        expected_bytes: u64,
    ) -> Result<QemuRootOverlayMaterialization<'_>, QemuSpawnError> {
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

        self.root_overlay_materialization = PreparedRootOverlayMaterialization::Updating;
        let destination = File::from(self.create_root_overlay_destination()?);

        Ok(QemuRootOverlayMaterialization {
            prepared: self,
            destination,
            binding,
            expected_bytes,
            written_bytes: 0,
        })
    }

    /// Reflinks one paused generation's writable artifacts into this generation.
    ///
    /// Both authorities must belong to the same attempt and exact launch
    /// admission. The source and destination are addressed only through their
    /// retained descriptors, and the kernel clone is followed by identity,
    /// length, and durability checks before either destination is marked exact.
    /// The caller supplies a binding derived from the authenticated local
    /// replacement snapshot captured while the source node is paused.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when either authority changed, belongs to a
    /// different attempt or launch profile, lacks a complete artifact, exceeds
    /// the aggregate writable ceiling, the filesystem cannot reflink within the
    /// attempt quota, or synchronization and post-clone authentication fail.
    pub fn clone_replacement_artifacts_from(
        &mut self,
        source: &Self,
        binding: QemuVmStateBinding,
    ) -> Result<(), QemuSpawnError> {
        if !std::sync::Arc::ptr_eq(&self.attempt_binding, &source.attempt_binding)
            || self.launch_resources != source.launch_resources
            || self.admitted_ceiling != source.admitted_ceiling
        {
            return Err(QemuSpawnError::PreparedLaunchAdmissionChanged);
        }
        if self.vmstate_materialization != PreparedVmStateMaterialization::Provisioned
            || self.root_overlay_materialization != PreparedRootOverlayMaterialization::Absent
        {
            return Err(QemuSpawnError::ReplacementDestinationNotEmpty {
                path: self.path.clone(),
            });
        }
        if source.vmstate_materialization == PreparedVmStateMaterialization::Updating
            || source.root_overlay_materialization == PreparedRootOverlayMaterialization::Updating
        {
            return Err(QemuSpawnError::ReplacementSourceNotReady {
                path: source.path.clone(),
            });
        }

        let source_vmstate = source.revalidate_identity()?;
        let vmstate_bytes = checked_artifact_length(
            source_vmstate.st_size,
            source.admitted_ceiling.2,
            &source.path,
        )?;
        let (source_root, root_bytes) = if source.launch_resources.has_root_overlay() {
            let metadata = source.revalidate_root_overlay_identity()?;
            let bytes =
                checked_artifact_length(metadata.st_size, source.admitted_ceiling.2, &source.path)?;
            (source.root_overlay.as_ref(), bytes)
        } else {
            (None, 0)
        };
        if vmstate_bytes
            .checked_add(root_bytes)
            .is_none_or(|bytes| bytes > self.admitted_ceiling.2)
        {
            return Err(QemuSpawnError::ReplacementArtifactsTooLarge {
                vmstate_bytes,
                root_overlay_bytes: root_bytes,
                maximum: self.admitted_ceiling.2,
            });
        }

        self.vmstate_materialization = PreparedVmStateMaterialization::Updating;
        clone_file(
            &source.vmstate,
            &self.vmstate,
            "reflink replacement VMState",
        )?;
        let destination_root = if let Some(source_root) = source_root {
            self.root_overlay_materialization = PreparedRootOverlayMaterialization::Updating;
            let destination = self.create_root_overlay_destination()?;
            clone_file(
                source_root,
                &destination,
                "reflink replacement root overlay",
            )?;
            Some(destination)
        } else {
            None
        };

        fsync(&self.vmstate).map_err(|source| QemuSpawnError::Io {
            operation: "synchronize replacement VMState",
            source: source.into(),
        })?;
        if let Some(destination) = &destination_root {
            fsync(destination).map_err(|source| QemuSpawnError::Io {
                operation: "synchronize replacement root overlay",
                source: source.into(),
            })?;
        }
        fsync(&self.directory).map_err(|source| QemuSpawnError::Io {
            operation: "synchronize replacement generation directory",
            source: source.into(),
        })?;

        require_length(
            self.revalidate_identity()?.st_size,
            vmstate_bytes,
            &self.path,
        )?;
        require_length(
            source.revalidate_identity()?.st_size,
            vmstate_bytes,
            &source.path,
        )?;
        if root_bytes != 0 {
            require_length(
                self.revalidate_root_overlay_identity()?.st_size,
                root_bytes,
                &self.path,
            )?;
            require_length(
                source.revalidate_root_overlay_identity()?.st_size,
                root_bytes,
                &source.path,
            )?;
        }

        self.vmstate_materialization = PreparedVmStateMaterialization::Exact {
            binding,
            bytes: vmstate_bytes,
        };
        if root_bytes != 0 {
            self.root_overlay_materialization = PreparedRootOverlayMaterialization::Exact {
                binding,
                bytes: root_bytes,
            };
        }
        Ok(())
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
        if self.vmstate_materialization != PreparedVmStateMaterialization::Provisioned
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
        let vmstate_bytes =
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
        if vmstate_bytes
            .checked_add(root_bytes)
            .is_none_or(|bytes| bytes > self.admitted_ceiling.2)
        {
            return Err(QemuSpawnError::ReplacementArtifactsTooLarge {
                vmstate_bytes,
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

    /// Requires the pinned VMState file to contain one exact root binding.
    ///
    /// Exact-restore launchers call this after materialization and immediately
    /// before guarded spawn. A merely provisioned image is deliberately not an
    /// exact-checkpoint authority.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] if materialization is incomplete or the
    /// committed file is bound to another exact-checkpoint root.
    pub fn require_exact_vmstate(&self, binding: QemuVmStateBinding) -> Result<(), QemuSpawnError> {
        match self.vmstate_materialization {
            PreparedVmStateMaterialization::Exact {
                binding: actual, ..
            } if actual == binding => Ok(()),
            PreparedVmStateMaterialization::Exact {
                binding: actual, ..
            } => Err(QemuSpawnError::PreparedVmStateBindingMismatch {
                expected: binding,
                actual,
            }),
            PreparedVmStateMaterialization::Provisioned
            | PreparedVmStateMaterialization::Updating
            | PreparedVmStateMaterialization::HotForkChild => {
                Err(QemuSpawnError::PreparedVmStateNotReady {
                    path: self.path.join(crate::DEFAULT_VMSTATE_FILE_NAME),
                })
            }
        }
    }

    /// Requires the pinned root overlay to carry one exact checkpoint binding.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] when the launch has no completed exact root
    /// overlay or its bytes were materialized for another checkpoint root.
    pub fn require_exact_root_overlay(
        &self,
        binding: QemuVmStateBinding,
    ) -> Result<(), QemuSpawnError> {
        match self.root_overlay_materialization {
            PreparedRootOverlayMaterialization::Exact {
                binding: actual, ..
            } if actual == binding => Ok(()),
            PreparedRootOverlayMaterialization::Exact {
                binding: actual, ..
            } => Err(QemuSpawnError::PreparedRootOverlayBindingMismatch {
                expected: binding,
                actual,
            }),
            PreparedRootOverlayMaterialization::Absent
            | PreparedRootOverlayMaterialization::Provisioned
            | PreparedRootOverlayMaterialization::Updating
            | PreparedRootOverlayMaterialization::HotForkChild => {
                Err(QemuSpawnError::PreparedRootOverlayNotReady {
                    path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
                })
            }
        }
    }

    /// Requires every checkpoint artifact named by one launch command.
    ///
    /// VMState is always required. The root overlay is required only when the
    /// validated command names one, but it must then carry the same binding.
    pub(crate) fn require_exact_launch_artifacts(
        &self,
        command: &QemuLaunchCommand,
        binding: QemuVmStateBinding,
    ) -> Result<(), QemuSpawnError> {
        self.require_exact_vmstate(binding)?;
        if command.resource_requirements().has_root_overlay() {
            self.require_exact_root_overlay(binding)?;
        }
        Ok(())
    }
}

fn clone_file(
    source: &OwnedFd,
    destination: &OwnedFd,
    operation: &'static str,
) -> Result<(), QemuSpawnError> {
    let source_fd = usize::try_from(source.as_raw_fd()).map_err(|error| QemuSpawnError::Io {
        operation,
        source: io::Error::new(io::ErrorKind::InvalidInput, error),
    })?;
    let request = unsafe {
        // SAFETY: Linux FICLONE takes the source descriptor as an integer and
        // clones its data into the ioctl destination. Both descriptors remain
        // pinned and owned for the complete call.
        IntegerSetter::<FICLONE>::new_usize(source_fd)
    };
    unsafe {
        // SAFETY: `destination` is a live writable regular-file descriptor and
        // `request` contains the live source regular-file descriptor.
        ioctl(destination, request)
    }
    .map_err(|source| QemuSpawnError::Io {
        operation,
        source: source.into(),
    })
}

fn checked_artifact_length(raw: i64, maximum: u64, path: &Path) -> Result<u64, QemuSpawnError> {
    let bytes = u64::try_from(raw).map_err(|_| QemuSpawnError::ReplacementSourceNotReady {
        path: path.to_owned(),
    })?;
    if bytes == 0 || bytes > maximum {
        return Err(QemuSpawnError::ReplacementSourceNotReady {
            path: path.to_owned(),
        });
    }
    Ok(bytes)
}

fn require_length(raw: i64, expected: u64, path: &Path) -> Result<(), QemuSpawnError> {
    if u64::try_from(raw).ok() == Some(expected) {
        Ok(())
    } else {
        Err(QemuSpawnError::ReplacementArtifactChanged {
            path: path.to_owned(),
        })
    }
}

impl Write for QemuVmStateMaterialization<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.expected_bytes.saturating_sub(self.written_bytes);
        let requested = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "exact VMState write length cannot be represented",
            )
        })?;
        if requested > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exact VMState write exceeds the declared checkpoint length",
            ));
        }
        let written = self.destination.write(bytes)?;
        self.written_bytes = self
            .written_bytes
            .checked_add(u64::try_from(written).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "exact VMState write count cannot be represented",
                )
            })?)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "exact VMState write overflow")
            })?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.destination.flush()
    }
}

impl Write for QemuRootOverlayMaterialization<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.expected_bytes.saturating_sub(self.written_bytes);
        let requested = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "exact root-overlay write length cannot be represented",
            )
        })?;
        if requested > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exact root-overlay write exceeds the declared checkpoint length",
            ));
        }
        let written = self.destination.write(bytes)?;
        self.written_bytes = self
            .written_bytes
            .checked_add(u64::try_from(written).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "exact root-overlay write count cannot be represented",
                )
            })?)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "exact root-overlay write overflow",
                )
            })?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.destination.flush()
    }
}

impl QemuVmStateMaterialization<'_> {
    /// Authenticates and durably commits the complete materialized VMState.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] if the caller wrote fewer than the declared
    /// bytes, file flush or synchronization fails, or the pinned inode or final
    /// file length changed. Failure leaves the run-directory authority
    /// unlaunchable until a new materialization succeeds.
    pub fn finish(mut self) -> Result<(), QemuSpawnError> {
        if self.written_bytes != self.expected_bytes {
            return Err(QemuSpawnError::PreparedVmStateIncomplete {
                expected: self.expected_bytes,
                actual: self.written_bytes,
            });
        }
        self.destination
            .flush()
            .map_err(|source| QemuSpawnError::Io {
                operation: "flush materialized exact-VMState container",
                source,
            })?;
        self.destination
            .sync_all()
            .map_err(|source| QemuSpawnError::Io {
                operation: "synchronize materialized exact-VMState container",
                source,
            })?;
        fsync(&self.prepared.directory).map_err(|source| QemuSpawnError::Io {
            operation: "synchronize materialized exact-VMState directory",
            source: source.into(),
        })?;
        let metadata = fstat(&self.prepared.vmstate).map_err(|source| QemuSpawnError::Io {
            operation: "inspect materialized exact-VMState container",
            source: source.into(),
        })?;
        if !self.prepared.vmstate_identity.matches(&metadata) {
            return Err(QemuSpawnError::PreparedVmStateChanged {
                path: self.prepared.path.join(crate::DEFAULT_VMSTATE_FILE_NAME),
            });
        }
        let actual = u64::try_from(metadata.st_size).map_err(|_| {
            QemuSpawnError::PreparedVmStateIncomplete {
                expected: self.expected_bytes,
                actual: u64::MAX,
            }
        })?;
        if actual != self.expected_bytes {
            return Err(QemuSpawnError::PreparedVmStateIncomplete {
                expected: self.expected_bytes,
                actual,
            });
        }
        self.prepared.vmstate_materialization = PreparedVmStateMaterialization::Exact {
            binding: self.binding,
            bytes: self.expected_bytes,
        };
        Ok(())
    }
}

impl QemuRootOverlayMaterialization<'_> {
    /// Authenticates and durably commits the complete root overlay.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] if the caller wrote a different length,
    /// synchronization fails, or the retained inode changes. Failure leaves the
    /// prepared directory unlaunchable.
    pub fn finish(mut self) -> Result<(), QemuSpawnError> {
        if self.written_bytes != self.expected_bytes {
            return Err(QemuSpawnError::PreparedRootOverlayIncomplete {
                expected: self.expected_bytes,
                actual: self.written_bytes,
            });
        }
        self.destination
            .flush()
            .map_err(|source| QemuSpawnError::Io {
                operation: "flush materialized exact root overlay",
                source,
            })?;
        self.destination
            .sync_all()
            .map_err(|source| QemuSpawnError::Io {
                operation: "synchronize materialized exact root overlay",
                source,
            })?;
        fsync(&self.prepared.directory).map_err(|source| QemuSpawnError::Io {
            operation: "synchronize materialized exact root-overlay directory",
            source: source.into(),
        })?;
        let metadata = self.prepared.revalidate_root_overlay_identity()?;
        let actual = u64::try_from(metadata.st_size).map_err(|_| {
            QemuSpawnError::PreparedRootOverlayIncomplete {
                expected: self.expected_bytes,
                actual: u64::MAX,
            }
        })?;
        if actual != self.expected_bytes {
            return Err(QemuSpawnError::PreparedRootOverlayIncomplete {
                expected: self.expected_bytes,
                actual,
            });
        }
        self.prepared.root_overlay_materialization = PreparedRootOverlayMaterialization::Exact {
            binding: self.binding,
            bytes: self.expected_bytes,
        };
        Ok(())
    }
}
