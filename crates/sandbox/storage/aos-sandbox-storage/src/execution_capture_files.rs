//! Closed file-namespace custody for a future dedicated capture worker.
//!
//! This module cannot acquire a mount or construct its pinned-directory token
//! in production. A future Storage worker must first authenticate the
//! Controller/Host grants, cold-replay AOSEOR03, prove the exclusive ZFS mount,
//! and mint that token. Claiming names here does not authorize execution or
//! produce a physical capture receipt.
//!
//! The durable exclusive marker has this fixed layout:
//!
//! ```text
//! domain || attempt[16] || Controller grant digest[32] || Host receipt digest[32]
//!        || AOSEOR03 record digest[32] || dataset binding[32]
//! ```

use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::mount::DetachedMount;
use rustix::fs::{FileType, Mode, OFlags, fstat, fsync, openat};

use crate::execution_capture_writer::{
    CaptureWriteErrorV1, CaptureWriterConstructionFailureV2, DetachedCaptureWriterV1,
};
use crate::execution_capture_zfs_worker::AuthorizedCaptureWriterAttemptV1;
use crate::execution_output::ProtectedRetainedCaptureV1;

use crate::execution_capture_writer::{CaptureFileIoOriginalV3, CaptureFileIoV3};

const CLAIM_NAME: &str = "capture-writer.claim";
const STDOUT_NAME: &str = "stdout";
const STDERR_NAME: &str = "stderr";
const CLAIM_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-file-claim.v1\0";

// Covers the exact exclusive marker payload and both retained stream ceilings.
// The enclosing dataset reservation, including its trusted metadata headroom,
// must contain this payload before any create/write is entered.
pub(crate) fn capture_retained_payload_bytes_v3(stdout_maximum: u64, stderr_maximum: u64) -> Option<u64> {
    let marker = u64::try_from(CLAIM_DOMAIN.len()).ok()?.checked_add(16 + 4 * 32)?;
    stdout_maximum.checked_add(stderr_maximum)?.checked_add(marker)
}


/// Bounds native file-custody carriers without granting a mount or writer.
pub(crate) fn capture_file_receiving_bytes_v2() -> Option<usize> {
    let carriers = std::mem::size_of::<PinnedCaptureDirectoryV1>()
        .checked_add(std::mem::size_of::<ClaimedCaptureFilesV1>())?
        .checked_add(std::mem::size_of::<CaptureWriterDirectoryGuardV1>())?
        .checked_add(std::mem::size_of::<CaptureDirectoryPinFailureV2>())?
        .checked_add(std::mem::size_of::<CaptureFileClaimFailureV2>())?
        .checked_add(std::mem::size_of::<CaptureFilesWriterFailureV2>())?;
    carriers.checked_mul(3)?.checked_add(
        crate::execution_capture_writer::capture_writer_receiving_bytes_v2()?,
    )
}

/// Reports an invalid pin, occupied name, or incomplete namespace sync.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureFileCustodyErrorV1 {
    #[error("capture directory no longer matches its pinned mount")]
    StaleMount,
    #[error("capture writer was already claimed")]
    AlreadyClaimed,
    #[error("capture stream name is already occupied")]
    OccupiedStream,
    #[error("capture files do not match their pinned directory")]
    InvalidFile,
    #[error("capture namespace operation failed: {0}")]
    Io(#[from] rustix::io::Errno),
    #[error("capture file operation failed: {0}")]
    FileIo(#[from] std::io::Error),
    #[error("capture bounded writer rejected its pinned files: {0}")]
    Writer(#[from] CaptureWriteErrorV1),
}

/// Holds an exact directory fd and mount identity that only a future worker may mint.
///
/// There is deliberately no production constructor. The future issuer must
/// prove that this fd is the exclusive, unmounted-to-Host capture dataset
/// named by current AOSEOR03 and authenticated Controller/Host receipts.
pub(crate) struct PinnedCaptureDirectoryV1 {
    directory: OwnedFd,
    device: u64,
    inode: u64,
    mount_id: MountId,
    owner_uid: u32,
    attempt: [u8; 16],
    controller_grant_digest: ObjectDigest,
    host_receipt_digest: ObjectDigest,
    record_digest: ObjectDigest,
    dataset_binding: ObjectDigest,
}

impl PinnedCaptureDirectoryV1 {
    #[cfg(test)]
    pub(crate) fn for_test(
        path: &std::path::Path,
        retained: &ProtectedRetainedCaptureV1,
    ) -> Result<Self, CaptureFileCustodyErrorV1> {
        let directory = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let identity = fstat(&directory)?;
        let mount_id = MountId::from_fd(directory.as_fd())
            .map_err(|_| CaptureFileCustodyErrorV1::StaleMount)?;
        let pin = Self {
            directory,
            device: identity.st_dev,
            inode: identity.st_ino,
            mount_id,
            owner_uid: identity.st_uid,
            attempt: [6; 16],
            controller_grant_digest: ObjectDigest::from_bytes([7; 32]),
            host_receipt_digest: ObjectDigest::from_bytes([8; 32]),
            record_digest: retained.record_digest(),
            dataset_binding: ObjectDigest::from_bytes([9; 32]),
        };
        pin.check_current()?;
        Ok(pin)
    }

    /// Pins a detached ZFS root only through the opaque verified writer attempt.
    pub(crate) fn from_authorized_detached_root(
        authorized: &AuthorizedCaptureWriterAttemptV1,
        detached: &DetachedMount,
        directory: OwnedFd,
    ) -> Result<Self, CaptureFileCustodyErrorV1> {
        Self::from_authorized_detached_root_retaining_v2(authorized, detached, directory)
            .map_err(CaptureDirectoryPinFailureV2::into_ordinary_error)
    }

    /// Retains the exact directory and native results if authorized pinning refuses.
    pub(crate) fn from_authorized_detached_root_retaining_v2(
        authorized: &AuthorizedCaptureWriterAttemptV1,
        detached: &DetachedMount,
        directory: OwnedFd,
    ) -> Result<Self, CaptureDirectoryPinFailureV2> {
        let mut original = CaptureDirectoryPinFailureV2 {
            directory: Some(directory),
            pinned: None,
            initial: CaptureDirectoryCurrentnessV2::new(),
            current: CaptureDirectoryCurrentnessV2::new(),
            error: None,
        };
        let result = (|| -> Result<(), CaptureFileCustodyErrorV1> {
            let Some(directory) = original.directory.as_ref() else {
                std::process::abort();
            };
            original.initial.identity = Some(fstat(directory));
            let Some(identity) = original.initial.identity.as_ref() else {
                std::process::abort();
            };
            let identity = identity.as_ref().map_err(|error| CaptureFileCustodyErrorV1::Io(*error))?;
            original.initial.mount_id = Some(MountId::from_fd(directory.as_fd()));
            let Some(Ok(mount_id)) = original.initial.mount_id.as_ref() else {
                return Err(CaptureFileCustodyErrorV1::StaleMount);
            };
            if *mount_id != detached.mount_id()
                || FileType::from_raw_mode(identity.st_mode) != FileType::Directory
                || identity.st_dev == 0
                || identity.st_ino == 0
            {
                return Err(CaptureFileCustodyErrorV1::StaleMount);
            }
            let (attempt, controller_grant_digest, host_receipt_digest, record_digest, dataset_binding) =
                authorized.file_custody_binding();
            let Some(directory) = original.directory.take() else {
                std::process::abort();
            };
            original.pinned = Some(Self {
                directory,
                device: identity.st_dev,
                inode: identity.st_ino,
                mount_id: *mount_id,
                owner_uid: 0,
                attempt,
                controller_grant_digest,
                host_receipt_digest,
                record_digest,
                dataset_binding,
            });
            let Some(pinned) = original.pinned.as_ref() else {
                std::process::abort();
            };
            pinned.check_current_retaining_v2(&mut original.current)
        })();
        if let Err(error) = result {
            original.error = Some(error);
            return Err(original);
        }
        match original.pinned.take() {
            Some(pinned) => Ok(pinned),
            None => std::process::abort(),
        }
    }

    fn check_current(&self) -> Result<(), CaptureFileCustodyErrorV1> {
        self.check_current_retaining_v2(&mut CaptureDirectoryCurrentnessV2::new())
    }

    fn check_current_retaining_v2(
        &self,
        original: &mut CaptureDirectoryCurrentnessV2,
    ) -> Result<(), CaptureFileCustodyErrorV1> {
        if original.identity.is_some() {
            return Err(CaptureFileCustodyErrorV1::StaleMount);
        }
        original.identity = Some(fstat(&self.directory));
        let Some(identity) = original.identity.as_ref() else {
            std::process::abort();
        };
        let identity = identity.as_ref().map_err(|error| CaptureFileCustodyErrorV1::Io(*error))?;
        original.mount_id = Some(MountId::from_fd(self.directory.as_fd()));
        let Some(Ok(mount_id)) = original.mount_id.as_ref() else {
            return Err(CaptureFileCustodyErrorV1::StaleMount);
        };
        if FileType::from_raw_mode(identity.st_mode) != FileType::Directory
            || identity.st_dev != self.device
            || identity.st_ino != self.inode
            || *mount_id != self.mount_id
            || identity.st_uid != self.owner_uid
            || identity.st_mode & 0o7777 != 0o700
            || self.attempt == [0; 16]
            || self.controller_grant_digest.as_bytes() == &[0; 32]
            || self.host_receipt_digest.as_bytes() == &[0; 32]
            || self.record_digest.as_bytes() == &[0; 32]
            || self.dataset_binding.as_bytes() == &[0; 32]
        {
            return Err(CaptureFileCustodyErrorV1::StaleMount);
        }
        Ok(())
    }

    /// Claims this execution's only writer and creates two durable private names.
    ///
    /// The marker is synced before either stream file is created. If any step
    /// fails, it remains on disk and replay must observe rather than retry.
    pub(crate) fn claim_files(self) -> Result<ClaimedCaptureFilesV1, CaptureFileCustodyErrorV1> {
        self.claim_files_with_sync(|directory| fsync(directory))
    }

    fn claim_files_with_sync<F>(
        self,
        mut sync_directory: F,
    ) -> Result<ClaimedCaptureFilesV1, CaptureFileCustodyErrorV1>
    where
        F: FnMut(BorrowedFd<'_>) -> Result<(), rustix::io::Errno>,
    {
        self.claim_files_retaining_with_sync_v2(&mut sync_directory, None)
            .map_err(CaptureFileClaimFailureV2::into_ordinary_error)
    }

    /// Runs the same exclusive namespace engine while retaining every failed fd.
    pub(crate) fn claim_files_retaining_v2(
        self,
    ) -> Result<ClaimedCaptureFilesV1, CaptureFileClaimFailureV2> {
        self.claim_files_retaining_with_sync_v2(|directory| fsync(directory), None)
    }

    pub(crate) fn claim_files_retaining_in_scope_v3(
        self, context: &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
        boot: [u8; 16], cutoff: u64,
    ) -> Result<ClaimedCaptureFilesV1, CaptureFileClaimFailureV2> {
        self.claim_files_retaining_with_sync_v2(|directory| fsync(directory),
            Some(CaptureFileIoOriginalV3::from_worker_v3(context, boot, cutoff)))
    }

    fn claim_files_retaining_with_sync_v2<F>(
        self,
        mut sync_directory: F,
        native_io: Option<CaptureFileIoOriginalV3>,
    ) -> Result<ClaimedCaptureFilesV1, CaptureFileClaimFailureV2>
    where
        F: FnMut(BorrowedFd<'_>) -> Result<(), rustix::io::Errno>,
    {
        let mut original = CaptureFileClaimFailureV2 {
            native_io,
            pin: Some(self),
            marker: None,
            stdout: None,
            stderr: None,
            before: CaptureDirectoryCurrentnessV2::new(),
            stdout_identity: None,
            stderr_identity: None,
            after: CaptureDirectoryCurrentnessV2::new(),
            error: None,
        };
        let result = (|| -> Result<(), CaptureFileCustodyErrorV1> {
            let Some(pin) = original.pin.as_ref() else {
                std::process::abort();
            };
            pin.check_current_retaining_v2(&mut original.before)?;

            observe_claim_errno_v3(&mut original.native_io, || {
                // Park the actual new File before its independent after-clock.
                original.marker = Some(File::from(create_exclusive(&pin.directory, CLAIM_NAME)?));
                Ok(())
            }).map_err(|error| occupied(error, CaptureFileCustodyErrorV1::AlreadyClaimed))?;
            let Some(marker) = original.marker.as_mut() else {
                std::process::abort();
            };
            let mut marker = CaptureFileIoV3 { file: marker, original: original.native_io.as_mut() };
            marker.write_all(CLAIM_DOMAIN)?;
            marker.write_all(&pin.attempt)?;
            marker.write_all(pin.controller_grant_digest.as_bytes())?;
            marker.write_all(pin.host_receipt_digest.as_bytes())?;
            marker.write_all(pin.record_digest.as_bytes())?;
            marker.write_all(pin.dataset_binding.as_bytes())?;
            marker.sync_all()?;
            observe_claim_errno_v3(&mut original.native_io, || sync_directory(pin.directory.as_fd()))?;

            observe_claim_errno_v3(&mut original.native_io, || {
                // Park the actual new File before its independent after-clock.
                original.stdout = Some(File::from(create_exclusive(&pin.directory, STDOUT_NAME)?));
                Ok(())
            }).map_err(|error| occupied(error, CaptureFileCustodyErrorV1::OccupiedStream))?;
            observe_claim_errno_v3(&mut original.native_io, || {
                // Park the actual new File before its independent after-clock.
                original.stderr = Some(File::from(create_exclusive(&pin.directory, STDERR_NAME)?));
                Ok(())
            }).map_err(|error| occupied(error, CaptureFileCustodyErrorV1::OccupiedStream))?;
            let Some(stdout) = original.stdout.as_ref() else {
                std::process::abort();
            };
            let Some(stderr) = original.stderr.as_ref() else {
                std::process::abort();
            };
            observe_claim_file_v3(&mut original.native_io, || stdout.sync_all())?;
            observe_claim_file_v3(&mut original.native_io, || stderr.sync_all())?;
            observe_claim_errno_v3(&mut original.native_io, || sync_directory(pin.directory.as_fd()))?;

            observe_claim_errno_v3(&mut original.native_io, || {
                original.stdout_identity = Some(fstat(stdout)?);
                Ok(())
            })?;
            observe_claim_errno_v3(&mut original.native_io, || {
                original.stderr_identity = Some(fstat(stderr)?);
                Ok(())
            })?;
            let (Some(stdout_identity), Some(stderr_identity)) =
                (original.stdout_identity.as_ref(), original.stderr_identity.as_ref())
            else {
                std::process::abort();
            };
            if !private_file_on_device(&stdout_identity, pin.device)
                || !private_file_on_device(&stderr_identity, pin.device)
                || stdout_identity.st_ino == stderr_identity.st_ino
            {
                return Err(CaptureFileCustodyErrorV1::InvalidFile);
            }
            pin.check_current_retaining_v2(&mut original.after)?;

            Ok(())
        })();
        if let Err(error) = result {
            original.error = Some(error);
            return Err(original);
        }
        let Some(pin) = original.pin.take() else {
            std::process::abort();
        };
        let Some(marker) = original.marker.take() else {
            std::process::abort();
        };
        let Some(stdout) = original.stdout.take() else {
            std::process::abort();
        };
        let Some(stderr) = original.stderr.take() else {
            std::process::abort();
        };
        Ok(ClaimedCaptureFilesV1 {
            native_io: original.native_io.take(),
            directory: pin.directory,
            marker,
            stdout,
            stderr,
            attempt: pin.attempt,
            controller_grant_digest: pin.controller_grant_digest,
            host_receipt_digest: pin.host_receipt_digest,
            record_digest: pin.record_digest,
            dataset_binding: pin.dataset_binding,
        })
    }
}

/// Holds every reached native result of an authorized directory pin attempt.
pub(crate) struct CaptureDirectoryPinFailureV2 {
    directory: Option<OwnedFd>,
    pinned: Option<PinnedCaptureDirectoryV1>,
    initial: CaptureDirectoryCurrentnessV2,
    current: CaptureDirectoryCurrentnessV2,
    error: Option<CaptureFileCustodyErrorV1>,
}

impl CaptureDirectoryPinFailureV2 {
    pub(crate) fn into_ordinary_error(mut self) -> CaptureFileCustodyErrorV1 {
        drop(self.pinned.take());
        drop(self.directory.take());
        match self.error.take() {
            Some(error) => error,
            None => std::process::abort(),
        }
    }
}

impl std::fmt::Debug for CaptureDirectoryPinFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureDirectoryPinFailureV2")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for CaptureDirectoryPinFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.error {
            Some(error) => std::fmt::Display::fmt(error, formatter),
            None => formatter.write_str("capture directory pin is incomplete"),
        }
    }
}

impl std::error::Error for CaptureDirectoryPinFailureV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.initial
            .failure()
            .or_else(|| self.current.failure())
            .or_else(|| self.error.as_ref().map(|error| error as _))
    }
}

struct CaptureDirectoryCurrentnessV2 {
    identity: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    mount_id: Option<Result<MountId, aos_linux_descriptors::Error>>,
}

impl CaptureDirectoryCurrentnessV2 {
    const fn new() -> Self {
        Self {
            identity: None,
            mount_id: None,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.identity.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.mount_id.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as _))
    }
}

/// Retains the directory and every reached exclusive file after a refusal.
///
/// This owner reports the actual first namespace error. It provides no retry,
/// mount authority or permission to publish a partially created writer.
pub(crate) struct CaptureFileClaimFailureV2 {
    native_io: Option<CaptureFileIoOriginalV3>,
    pin: Option<PinnedCaptureDirectoryV1>,
    marker: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
    before: CaptureDirectoryCurrentnessV2,
    stdout_identity: Option<rustix::fs::Stat>,
    stderr_identity: Option<rustix::fs::Stat>,
    after: CaptureDirectoryCurrentnessV2,
    error: Option<CaptureFileCustodyErrorV1>,
}

impl CaptureFileClaimFailureV2 {
    pub(crate) fn native_io_failure_v3(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native_io.as_ref()?.failure()
    }

    pub(crate) fn failure(&self) -> Option<&CaptureFileCustodyErrorV1> {
        self.error.as_ref()
    }

    pub(crate) fn into_ordinary_error(mut self) -> CaptureFileCustodyErrorV1 {
        // Preserve the consuming caller's old reverse-local disposal frontier.
        drop(self.stderr.take());
        drop(self.stdout.take());
        drop(self.marker.take());
        drop(self.pin.take());
        match self.error.take() {
            Some(error) => error,
            None => std::process::abort(),
        }
    }
}

impl std::fmt::Debug for CaptureFileClaimFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureFileClaimFailureV2")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for CaptureFileClaimFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.error {
            Some(error) => std::fmt::Display::fmt(error, formatter),
            None => formatter.write_str("capture namespace is incomplete"),
        }
    }
}

impl std::error::Error for CaptureFileClaimFailureV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native_io_failure_v3().or_else(|| self.before
            .failure())
            .or_else(|| self.after.failure())
            .or_else(|| self.error.as_ref().map(|error| error as _))
    }
}

fn create_exclusive(directory: &OwnedFd, name: &str) -> Result<OwnedFd, rustix::io::Errno> {
    openat(
        directory,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
}

fn occupied(
    error: rustix::io::Errno,
    collision: CaptureFileCustodyErrorV1,
) -> CaptureFileCustodyErrorV1 {
    if error == rustix::io::Errno::EXIST {
        collision
    } else {
        CaptureFileCustodyErrorV1::Io(error)
    }
}

fn private_file_on_device(identity: &rustix::fs::Stat, device: u64) -> bool {
    FileType::from_raw_mode(identity.st_mode) == FileType::RegularFile
        && identity.st_dev == device
        && identity.st_nlink == 1
        && identity.st_mode & 0o7777 == 0o600
        && identity.st_size == 0
}

/// Retains the exclusive marker, two private files, and the directory sync fd.
///
/// This is not a Host writer grant. A future worker must keep this custody
/// until both stream EOFs, file sync/readback, post-write ZFS readback, and
/// durable result commitment have completed.
pub(crate) struct ClaimedCaptureFilesV1 {
    native_io: Option<CaptureFileIoOriginalV3>,
    directory: OwnedFd,
    marker: File,
    stdout: File,
    stderr: File,
    attempt: [u8; 16],
    controller_grant_digest: ObjectDigest,
    host_receipt_digest: ObjectDigest,
    record_digest: ObjectDigest,
    dataset_binding: ObjectDigest,
}

impl ClaimedCaptureFilesV1 {
    /// Transfers exactly the pinned files to the AOSEOR03-bound prefix writer.
    pub(crate) fn into_writer(
        self,
        retained: &ProtectedRetainedCaptureV1,
    ) -> Result<(DetachedCaptureWriterV1, CaptureWriterDirectoryGuardV1), CaptureFileCustodyErrorV1>
    {
        self.into_writer_retaining_v2(retained)
            .map_err(CaptureFilesWriterFailureV2::into_ordinary_error)
    }

    /// Transfers the same files and retains the whole native prefix on refusal.
    pub(crate) fn into_writer_retaining_v2(
        self,
        retained: &ProtectedRetainedCaptureV1,
    ) -> Result<(DetachedCaptureWriterV1, CaptureWriterDirectoryGuardV1), CaptureFilesWriterFailureV2> {
        if self.record_digest != retained.record_digest() {
            return Err(CaptureFilesWriterFailureV2 {
                files: Some(self),
                guard: None,
                writer: None,
                error: Some(CaptureFileCustodyErrorV1::InvalidFile),
            });
        }
        let Self {
            native_io,
            directory,
            marker,
            stdout,
            stderr,
            attempt,
            controller_grant_digest,
            host_receipt_digest,
            record_digest,
            dataset_binding,
        } = self;
        let guard = CaptureWriterDirectoryGuardV1 {
            native_io,
            directory,
            _marker: marker,
            attempt,
            controller_grant_digest,
            host_receipt_digest,
            record_digest,
            dataset_binding,
        };
        match DetachedCaptureWriterV1::new_retaining_v2(retained, stdout, stderr) {
            Ok(writer) => Ok((writer, guard)),
            Err(writer) => Err(CaptureFilesWriterFailureV2 {
                files: None,
                guard: Some(guard),
                writer: Some(writer),
                error: None,
            }),
        }
    }

    fn sync_directory(&self) -> Result<(), CaptureFileCustodyErrorV1> {
        fsync(&self.directory)?;
        Ok(())
    }
}

/// Retains the marker, directory and both files after writer adoption refuses.
pub(crate) struct CaptureFilesWriterFailureV2 {
    files: Option<ClaimedCaptureFilesV1>,
    guard: Option<CaptureWriterDirectoryGuardV1>,
    writer: Option<CaptureWriterConstructionFailureV2>,
    error: Option<CaptureFileCustodyErrorV1>,
}

impl CaptureFilesWriterFailureV2 {
    pub(crate) fn into_ordinary_error(mut self) -> CaptureFileCustodyErrorV1 {
        let error = match self.writer.take() {
            Some(writer) => CaptureFileCustodyErrorV1::Writer(writer.into_ordinary_error()),
            None => match self.error.take() {
                Some(error) => error,
                None => std::process::abort(),
            },
        };
        drop(self.guard.take());
        drop(self.files.take());
        error
    }
}

impl std::fmt::Debug for CaptureFilesWriterFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureFilesWriterFailureV2")
            .field("error", &self.error)
            .field("writer", &self.writer)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for CaptureFilesWriterFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.writer, &self.error) {
            (Some(writer), _) => std::fmt::Display::fmt(writer, formatter),
            (_, Some(error)) => std::fmt::Display::fmt(error, formatter),
            _ => formatter.write_str("capture file adoption is incomplete"),
        }
    }
}

impl std::error::Error for CaptureFilesWriterFailureV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.writer.as_ref().map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.error.as_ref().map(|error| error as _))
    }
}

/// Retains the exclusive marker and namespace fsync fd while output is written.
pub(crate) struct CaptureWriterDirectoryGuardV1 {
    native_io: Option<CaptureFileIoOriginalV3>,
    directory: OwnedFd,
    _marker: File,
    pub(crate) attempt: [u8; 16],
    pub(crate) controller_grant_digest: ObjectDigest,
    pub(crate) host_receipt_digest: ObjectDigest,
    pub(crate) record_digest: ObjectDigest,
    pub(crate) dataset_binding: ObjectDigest,
}

impl CaptureWriterDirectoryGuardV1 {
    pub(crate) fn native_io_failure_v3(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native_io.as_ref()?.failure()
    }

    pub(crate) fn sync_after_write_selected_v3(&mut self) -> Result<(), CaptureFileCustodyErrorV1> {
        observe_claim_errno_v3(&mut self.native_io, || sync_capture_directory_v3(&self.directory))?;
        Ok(())
    }

    pub(crate) fn sync_after_write(&self) -> Result<(), CaptureFileCustodyErrorV1> {
        sync_capture_directory_v3(&self.directory)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    fn pinned(directory: &tempfile::TempDir) -> PinnedCaptureDirectoryV1 {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let fd = rustix::fs::open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let identity = fstat(&fd).unwrap();
        let mount_id = MountId::from_fd(fd.as_fd()).unwrap();
        PinnedCaptureDirectoryV1 {
            directory: fd,
            device: identity.st_dev,
            inode: identity.st_ino,
            mount_id,
            owner_uid: identity.st_uid,
            attempt: [1; 16],
            controller_grant_digest: ObjectDigest::from_bytes([4; 32]),
            host_receipt_digest: ObjectDigest::from_bytes([5; 32]),
            record_digest: ObjectDigest::from_bytes([2; 32]),
            dataset_binding: ObjectDigest::from_bytes([3; 32]),
        }
    }

    #[test]
    fn selected_claim_expired_wall_refuses_before_the_first_exclusive_name() {
        use std::os::fd::AsRawFd as _;
        let directory = tempfile::TempDir::new().unwrap();
        let pin = pinned(&directory);
        let original_fd = pin.directory.as_raw_fd();
        let gate = CaptureFileIoOriginalV3::expired_wall_fixture_v3();

        let failure = pin.claim_files_retaining_with_sync_v2(|fd| fsync(fd), Some(gate)).err().unwrap();

        assert_eq!(failure.pin.as_ref().unwrap().directory.as_raw_fd(), original_fd);
        assert!(failure.native_io_failure_v3().is_some());
        assert!(failure.marker.is_none());
        assert!(failure.stdout.is_none());
        assert!(failure.stderr.is_none());
        assert!(!directory.path().join(CLAIM_NAME).exists());
        assert!(!directory.path().join(STDOUT_NAME).exists());
        assert!(!directory.path().join(STDERR_NAME).exists());
    }

    #[test]
    fn selected_claim_keeps_opened_prefix_on_occupied_stderr() {
        use std::os::fd::AsRawFd as _;
        let directory = tempfile::TempDir::new().unwrap();
        let pin = pinned(&directory);
        let expected_directory = pin.directory.as_raw_fd();
        std::fs::write(directory.path().join(STDERR_NAME), b"occupied").unwrap();

        let failed = match pin.claim_files_retaining_v2() {
            Err(failed) => failed,
            Ok(_) => panic!("occupied stderr must retain the failed prefix"),
        };

        assert!(matches!(failed.failure(), Some(CaptureFileCustodyErrorV1::OccupiedStream)));
        assert_eq!(failed.pin.as_ref().unwrap().directory.as_raw_fd(), expected_directory);
        assert!(failed.marker.as_ref().unwrap().metadata().is_ok());
        assert!(failed.stdout.as_ref().unwrap().metadata().is_ok());
        assert!(failed.stderr.is_none());
        assert_eq!(std::fs::read(directory.path().join(STDERR_NAME)).unwrap(), b"occupied");
    }

    #[test]
    fn durable_claim_pins_private_files_and_syncs_both_namespace_phases() {
        let directory = tempfile::TempDir::new().unwrap();
        let mut syncs = 0;

        let claimed = pinned(&directory)
            .claim_files_with_sync(|fd| {
                syncs += 1;
                fsync(fd)
            })
            .unwrap();

        assert_eq!(syncs, 2);
        assert_eq!(claimed.attempt, [1; 16]);
        assert_eq!(claimed.controller_grant_digest.as_bytes(), &[4; 32]);
        assert_eq!(claimed.host_receipt_digest.as_bytes(), &[5; 32]);
        assert_eq!(claimed.record_digest.as_bytes(), &[2; 32]);
        assert_eq!(claimed.dataset_binding.as_bytes(), &[3; 32]);
        assert_eq!(claimed.stdout.metadata().unwrap().len(), 0);
        assert_eq!(claimed.stderr.metadata().unwrap().len(), 0);
        assert_ne!(
            claimed.stdout.metadata().unwrap().ino(),
            claimed.stderr.metadata().unwrap().ino()
        );
        assert_eq!(
            claimed.stdout.metadata().unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(
            claimed.stderr.metadata().unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(
            claimed.marker.metadata().unwrap().len(),
            (CLAIM_DOMAIN.len() + 16 + 32 * 4) as u64
        );
        let mut expected_marker = CLAIM_DOMAIN.to_vec();
        expected_marker.extend_from_slice(&[1; 16]);
        expected_marker.extend_from_slice(&[4; 32]);
        expected_marker.extend_from_slice(&[5; 32]);
        expected_marker.extend_from_slice(&[2; 32]);
        expected_marker.extend_from_slice(&[3; 32]);
        assert_eq!(
            std::fs::read(directory.path().join(CLAIM_NAME)).unwrap(),
            expected_marker
        );
        claimed.sync_directory().unwrap();
        drop(claimed);

        assert!(matches!(
            pinned(&directory).claim_files(),
            Err(CaptureFileCustodyErrorV1::AlreadyClaimed)
        ));
    }

    #[test]
    fn failed_first_directory_sync_leaves_an_unretryable_claim() {
        let directory = tempfile::TempDir::new().unwrap();

        let failure = pinned(&directory).claim_files_with_sync(|_| Err(rustix::io::Errno::IO));

        assert!(matches!(
            failure,
            Err(CaptureFileCustodyErrorV1::Io(rustix::io::Errno::IO))
        ));
        assert!(directory.path().join(CLAIM_NAME).exists());
        assert!(!directory.path().join(STDOUT_NAME).exists());
        assert!(matches!(
            pinned(&directory).claim_files(),
            Err(CaptureFileCustodyErrorV1::AlreadyClaimed)
        ));
    }

    #[test]
    fn failed_second_directory_sync_never_returns_a_file_pair() {
        let directory = tempfile::TempDir::new().unwrap();
        let mut syncs = 0;

        let failure = pinned(&directory).claim_files_with_sync(|fd| {
            syncs += 1;
            if syncs == 2 {
                Err(rustix::io::Errno::IO)
            } else {
                fsync(fd)
            }
        });

        assert_eq!(syncs, 2);
        assert!(matches!(
            failure,
            Err(CaptureFileCustodyErrorV1::Io(rustix::io::Errno::IO))
        ));
        assert!(directory.path().join(STDOUT_NAME).exists());
        assert!(directory.path().join(STDERR_NAME).exists());
        assert!(matches!(
            pinned(&directory).claim_files(),
            Err(CaptureFileCustodyErrorV1::AlreadyClaimed)
        ));
    }

    #[test]
    fn occupied_symlink_does_not_replace_a_stream_target() {
        let directory = tempfile::TempDir::new().unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&target, directory.path().join(STDOUT_NAME)).unwrap();

        let failure = pinned(&directory).claim_files();

        assert!(matches!(
            failure,
            Err(CaptureFileCustodyErrorV1::OccupiedStream)
        ));
        assert!(directory.path().join(CLAIM_NAME).exists());
        let mut bytes = Vec::new();
        File::open(&target)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"unchanged");
    }

    #[test]
    fn changed_mount_identity_is_rejected_before_claim() {
        let directory = tempfile::TempDir::new().unwrap();
        let mut pin = pinned(&directory);
        pin.inode += 1;

        assert!(matches!(
            pin.claim_files(),
            Err(CaptureFileCustodyErrorV1::StaleMount)
        ));
        assert!(!directory.path().join(CLAIM_NAME).exists());
    }
}


#[cfg(test)]
mod capture_payload_geometry_tests {
    use super::*;

    #[test]
    fn retained_payload_includes_the_actual_claim_and_both_stream_ceilings() {
        let claim_bytes = (CLAIM_DOMAIN.len() + 16 + 4 * 32) as u64;
        assert_eq!(capture_retained_payload_bytes_v3(17, 29), Some(claim_bytes + 46));
        assert_eq!(capture_retained_payload_bytes_v3(0, 0), Some(claim_bytes));
        assert_eq!(capture_retained_payload_bytes_v3(u64::MAX, 1), None);
    }
}


fn observe_claim_errno_v3(
    original: &mut Option<CaptureFileIoOriginalV3>,
    action: impl FnOnce() -> Result<(), rustix::io::Errno>,
) -> Result<(), rustix::io::Errno> {
    match original {
        Some(original) => original.observe_errno_v3(action),
        None => action(),
    }
}

fn observe_claim_file_v3(
    original: &mut Option<CaptureFileIoOriginalV3>,
    action: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    match original {
        Some(original) => original.observe_native_v3(action),
        None => action(),
    }
}


fn sync_capture_directory_v3(directory: &OwnedFd) -> Result<(), rustix::io::Errno> {
    fsync(directory)
}
