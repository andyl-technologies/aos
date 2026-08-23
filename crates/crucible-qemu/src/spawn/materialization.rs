//! Linear exact-VMState materialization for pinned QEMU run directories.

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

use crucible::ContentHash;
use rustix::fs::{Mode, OFlags, fchown, fstat, fsync, openat};
use rustix::process::{Gid, Uid};

use super::{QemuPreparedRunDirectory, QemuSpawnError};
use crate::QemuLaunchCommand;

const EXACT_VMSTATE_BINDING_DOMAIN: &str = "crucible.executor.exact-vmstate-restore-binding.v1";

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PreparedVmStateMaterialization {
    Provisioned,
    Updating,
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
        let destination = openat(
            &self.directory,
            crate::DEFAULT_ROOT_OVERLAY_FILE_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "create prepared exact root overlay",
            source: source.into(),
        })?;
        let metadata = fstat(&destination).map_err(|source| QemuSpawnError::Io {
            operation: "inspect prepared exact root overlay",
            source: source.into(),
        })?;
        if let Some(credentials) = self.child_credentials {
            fchown(
                &destination,
                Some(Uid::from_raw(credentials.user_id)),
                Some(Gid::from_raw(credentials.group_id)),
            )
            .map_err(|source| QemuSpawnError::Io {
                operation: "assign prepared exact root-overlay ownership",
                source: source.into(),
            })?;
        }
        self.root_overlay_identity = Some(super::PinnedFileIdentity::from_stat(&metadata));
        let destination =
            File::from(
                destination
                    .try_clone()
                    .map_err(|source| QemuSpawnError::Io {
                        operation: "duplicate prepared exact root overlay",
                        source,
                    })?,
            );
        self.root_overlay = Some(
            destination
                .try_clone()
                .map_err(|source| QemuSpawnError::Io {
                    operation: "retain prepared exact root overlay",
                    source,
                })?
                .into(),
        );

        Ok(QemuRootOverlayMaterialization {
            prepared: self,
            destination,
            binding,
            expected_bytes,
            written_bytes: 0,
        })
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
            | PreparedVmStateMaterialization::Updating => {
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
            | PreparedRootOverlayMaterialization::Updating => {
                Err(QemuSpawnError::PreparedRootOverlayNotReady {
                    path: self.path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
                })
            }
        }
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
