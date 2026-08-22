//! Linear exact-VMState materialization for pinned QEMU run directories.

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

use crucible::ContentHash;
use rustix::fs::fstat;

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

impl QemuPreparedRunDirectory {
    /// Admits a run directory for exact-checkpoint materialization only.
    ///
    /// This operation does not grant process-launch authority. It accepts the
    /// execution ceiling already reserved by the daemon, validates the command
    /// baseline before path access, and pins the destination so a retained
    /// checkpoint can be streamed before the child contract is lent to spawn.
    /// Guarded spawn later requires an unforgeable process contract carrying
    /// the exact same ceiling and revalidates the command independently.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSpawnError`] before path access when the command exceeds
    /// the supplied reservation. Otherwise returns an error when the path or
    /// required VMState file cannot be pinned without following symlinks.
    pub fn open_for_materialization(
        command: &QemuLaunchCommand,
        path: impl AsRef<Path>,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
    ) -> Result<Self, QemuSpawnError> {
        let admitted_ceiling = (
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
        );
        command
            .resource_requirements()
            .validate_ceiling(admitted_ceiling.0, admitted_ceiling.1, admitted_ceiling.2)
            .map_err(|source| QemuSpawnError::LaunchResources { source })?;
        Self::open_admitted(command, path.as_ref(), admitted_ceiling)
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
