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

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::mount::DetachedMount;
use rustix::fs::{FileType, Mode, OFlags, fstat, fsync, openat};

use crate::execution_capture_writer::{CaptureWriteErrorV1, DetachedCaptureWriterV1};
use crate::execution_capture_zfs_worker::AuthorizedCaptureWriterAttemptV1;
use crate::execution_output::ProtectedRetainedCaptureV1;

const CLAIM_NAME: &str = "capture-writer.claim";
const STDOUT_NAME: &str = "stdout";
const STDERR_NAME: &str = "stderr";
const CLAIM_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-file-claim.v1\0";

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
        let identity = fstat(&directory)?;
        let mount_id = MountId::from_fd(directory.as_fd())
            .map_err(|_| CaptureFileCustodyErrorV1::StaleMount)?;
        if mount_id != detached.mount_id()
            || FileType::from_raw_mode(identity.st_mode) != FileType::Directory
            || identity.st_dev == 0
            || identity.st_ino == 0
        {
            return Err(CaptureFileCustodyErrorV1::StaleMount);
        }
        let (attempt, controller_grant_digest, host_receipt_digest, record_digest, dataset_binding) =
            authorized.file_custody_binding();
        let pinned = Self {
            directory,
            device: identity.st_dev,
            inode: identity.st_ino,
            mount_id,
            owner_uid: 0,
            attempt,
            controller_grant_digest,
            host_receipt_digest,
            record_digest,
            dataset_binding,
        };
        pinned.check_current()?;
        Ok(pinned)
    }

    fn check_current(&self) -> Result<(), CaptureFileCustodyErrorV1> {
        let identity = fstat(&self.directory)?;
        let mount_id = MountId::from_fd(self.directory.as_fd())
            .map_err(|_| CaptureFileCustodyErrorV1::StaleMount)?;
        if FileType::from_raw_mode(identity.st_mode) != FileType::Directory
            || identity.st_dev != self.device
            || identity.st_ino != self.inode
            || mount_id != self.mount_id
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
        self.check_current()?;

        let mut marker = File::from(
            create_exclusive(&self.directory, CLAIM_NAME)
                .map_err(|error| occupied(error, CaptureFileCustodyErrorV1::AlreadyClaimed))?,
        );
        marker.write_all(CLAIM_DOMAIN)?;
        marker.write_all(&self.attempt)?;
        marker.write_all(self.controller_grant_digest.as_bytes())?;
        marker.write_all(self.host_receipt_digest.as_bytes())?;
        marker.write_all(self.record_digest.as_bytes())?;
        marker.write_all(self.dataset_binding.as_bytes())?;
        marker.sync_all()?;
        sync_directory(self.directory.as_fd())?;

        let stdout = File::from(
            create_exclusive(&self.directory, STDOUT_NAME)
                .map_err(|error| occupied(error, CaptureFileCustodyErrorV1::OccupiedStream))?,
        );
        let stderr = File::from(
            create_exclusive(&self.directory, STDERR_NAME)
                .map_err(|error| occupied(error, CaptureFileCustodyErrorV1::OccupiedStream))?,
        );
        stdout.sync_all()?;
        stderr.sync_all()?;
        sync_directory(self.directory.as_fd())?;

        let stdout_identity = fstat(&stdout)?;
        let stderr_identity = fstat(&stderr)?;
        if !private_file_on_device(&stdout_identity, self.device)
            || !private_file_on_device(&stderr_identity, self.device)
            || stdout_identity.st_ino == stderr_identity.st_ino
        {
            return Err(CaptureFileCustodyErrorV1::InvalidFile);
        }
        self.check_current()?;

        Ok(ClaimedCaptureFilesV1 {
            directory: self.directory,
            marker,
            stdout,
            stderr,
            attempt: self.attempt,
            controller_grant_digest: self.controller_grant_digest,
            host_receipt_digest: self.host_receipt_digest,
            record_digest: self.record_digest,
            dataset_binding: self.dataset_binding,
        })
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
        if self.record_digest != retained.record_digest() {
            return Err(CaptureFileCustodyErrorV1::InvalidFile);
        }
        let writer = DetachedCaptureWriterV1::new(retained, self.stdout, self.stderr)?;
        let guard = CaptureWriterDirectoryGuardV1 {
            directory: self.directory,
            _marker: self.marker,
            attempt: self.attempt,
            controller_grant_digest: self.controller_grant_digest,
            host_receipt_digest: self.host_receipt_digest,
            record_digest: self.record_digest,
            dataset_binding: self.dataset_binding,
        };
        Ok((writer, guard))
    }

    fn sync_directory(&self) -> Result<(), CaptureFileCustodyErrorV1> {
        fsync(&self.directory)?;
        Ok(())
    }
}

/// Retains the exclusive marker and namespace fsync fd while output is written.
pub(crate) struct CaptureWriterDirectoryGuardV1 {
    directory: OwnedFd,
    _marker: File,
    pub(crate) attempt: [u8; 16],
    pub(crate) controller_grant_digest: ObjectDigest,
    pub(crate) host_receipt_digest: ObjectDigest,
    pub(crate) record_digest: ObjectDigest,
    pub(crate) dataset_binding: ObjectDigest,
}

impl CaptureWriterDirectoryGuardV1 {
    pub(crate) fn sync_after_write(&self) -> Result<(), CaptureFileCustodyErrorV1> {
        fsync(&self.directory)?;
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
