//! Pinned child-owned output for the untimed UART RAM observation.

use std::fs::File;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::FileExt;
use std::sync::OnceLock;

use rustix::fs::{Mode, OFlags, fstat, openat};

use super::{PinnedFileIdentity, QemuPreparedRunDirectory, validate_diagnostic_trace_metadata};
use crate::spawn::{QemuChildCredentials, QemuSpawnError, invalid_input};

const FILE_NAME: &str = "console-sentinel.bin";

/// Retains the diagnostic inode independently of its directory entry.
pub(crate) struct ConsoleSentinelOutput {
    directory: OwnedFd,
    file: File,
    identity: PinnedFileIdentity,
    credentials: QemuChildCredentials,
}

impl QemuPreparedRunDirectory {
    /// Allocates only the fixed probe file under the admitted child credentials.
    ///
    /// # Errors
    ///
    /// Returns an error when allocation collides, the run-directory authority
    /// or child credentials are unavailable, or the new inode is substituted.
    pub(crate) fn prepare_console_sentinel_for_test(
        &self,
    ) -> Result<ConsoleSentinelOutput, QemuSpawnError> {
        let identity = OnceLock::new();
        self.prepare_diagnostic_trace(FILE_NAME, &identity)?;
        let descriptor = openat(
            &self.directory,
            FILE_NAME,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "retain console sample inode",
            source: source.into(),
        })?;
        let metadata = fstat(&descriptor).map_err(|source| QemuSpawnError::Io {
            operation: "inspect empty console sample",
            source: source.into(),
        })?;
        let credentials = self.child_credentials.ok_or_else(|| {
            invalid_input(
                "retain console sample inode",
                "admitted child credentials disappeared",
            )
        })?;
        validate_diagnostic_trace_metadata(FILE_NAME, &metadata, credentials)?;
        let identity = identity.get().copied().ok_or_else(|| {
            invalid_input(
                "retain console sample inode",
                "diagnostic inode was not prepared",
            )
        })?;
        if !identity.matches(&metadata) || metadata.st_size != 0 {
            return Err(QemuSpawnError::DiagnosticTraceChanged { file: FILE_NAME });
        }

        Ok(ConsoleSentinelOutput {
            directory: self
                .directory
                .try_clone()
                .map_err(|source| QemuSpawnError::Io {
                    operation: "retain console sample directory",
                    source,
                })?,
            file: File::from(descriptor),
            identity,
            credentials,
        })
    }
}

impl ConsoleSentinelOutput {
    /// Names the output relative to the guarded child's already-pinned cwd.
    pub(crate) fn filename(&self) -> &'static str {
        FILE_NAME
    }

    /// Reads exactly one byte from the retained inode, refusing substitution.
    ///
    /// # Errors
    ///
    /// Returns an error for changed ownership, mode, link count, inode identity,
    /// missing or extra bytes, or a failed descriptor read.
    pub(crate) fn read_byte(&self) -> Result<u8, QemuSpawnError> {
        self.validate_sample()?;
        let mut byte = [0];
        self.file
            .read_exact_at(&mut byte, 0)
            .map_err(|source| QemuSpawnError::Io {
                operation: "read retained console sample",
                source,
            })?;
        let mut tail = [0];
        if self
            .file
            .read_at(&mut tail, 1)
            .map_err(|source| QemuSpawnError::Io {
                operation: "check retained console sample length",
                source,
            })?
            != 0
        {
            return Err(QemuSpawnError::DiagnosticTraceChanged { file: FILE_NAME });
        }
        self.validate_sample()?;
        Ok(byte[0])
    }

    fn validate_sample(&self) -> Result<(), QemuSpawnError> {
        let named = openat(
            &self.directory,
            FILE_NAME,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| QemuSpawnError::Io {
            operation: "authenticate named console sample",
            source: source.into(),
        })?;
        for descriptor in [named.as_fd(), self.file.as_fd()] {
            let metadata = fstat(descriptor).map_err(|source| QemuSpawnError::Io {
                operation: "inspect retained console sample",
                source: source.into(),
            })?;
            validate_diagnostic_trace_metadata(FILE_NAME, &metadata, self.credentials)?;
            if !self.identity.matches(&metadata) || metadata.st_size != 1 {
                return Err(QemuSpawnError::DiagnosticTraceChanged { file: FILE_NAME });
            }
        }
        Ok(())
    }
}
