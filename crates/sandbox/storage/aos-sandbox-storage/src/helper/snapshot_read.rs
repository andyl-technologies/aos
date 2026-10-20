//! Owns the actual operation-bound Snapshot metadata leaf observation.
//!
//! The ordinary adapter and selected backend share the existing fixed leaf
//! grammar, native order and semantic decoder. Payment is supplied only by the
//! actual State recovery guard before selected open/read/result allocation.

use super::*;

pub(super) struct SnapshotMetadataReadV1 {
    // The ordinary local bytes preceded File destruction, including errors.
    bytes: Vec<u8>,
    decoded: Option<Result<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1,
        crate::snapshot_metadata::SnapshotMetadataError>>,
    identity: Option<Result<(), ZfsHelperError>>,
    after: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    exact_length: Option<Result<(), ZfsHelperError>>,
    read: Option<Result<usize, std::io::Error>>,
    file: Option<File>,
    policy: Option<Result<(), ZfsHelperError>>,
    before: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    opened: Option<Result<OwnedFd, rustix::io::Errno>>,
    name: Option<String>,
    entered: bool,
    armed: bool,
}

impl SnapshotMetadataReadV1 {
    pub(super) fn new() -> Self {
        Self {
            bytes: Vec::new(), decoded: None, identity: None, after: None,
            exact_length: None, read: None, file: None, policy: None,
            before: None, opened: None, name: None, entered: false, armed: false,
        }
    }

    pub(super) fn demand_v1()
        -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>
    {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use crate::receiving_demand::{add, count, multiply};
        let memory = add(count(3 * std::mem::size_of::<Self>())?,
            add(multiply(count(SNAPSHOT_METADATA_RECORD_BYTES + 1)?, 3)?, 41 + 8 * 256)?)?;
        // Three simultaneous thirteen-field read carriers cover local and
        // old/new Vec backing destinations. The five-field batch destination
        // and reached returned checked record add six; the Native payment
        // receipt is separately included by its genuine stage.
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::OpenFiles, 1).with(D::MetadataEntries, 45))
    }

    pub(super) fn capture_once(
        &mut self,
        directory: &OwnedFd,
        operation_id: [u8; 16],
    ) -> Result<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1, ZfsHelperError> {
        if self.entered {
            return Err(ZfsHelperError::ProcessContract);
        }
        self.entered = true;
        self.name = Some(snapshot_metadata_name(operation_id));
        let Some(name) = self.name.as_deref() else {
            return Err(ZfsHelperError::ProcessContract);
        };
        self.opened = Some(openat(directory, name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()));
        let Some(Ok(descriptor)) = self.opened.as_ref() else {
            return Err(ZfsHelperError::ProcessContract);
        };
        self.before = Some(fstat(descriptor));
        let Some(Ok(before)) = self.before.as_ref() else {
            return Err(ZfsHelperError::ProcessContract);
        };
        self.policy = Some(if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != 0 || before.st_nlink != 1
            || before.st_mode & 0o7777 != 0o400
            || before.st_size != SNAPSHOT_METADATA_RECORD_BYTES as i64
        {
            Err(ZfsHelperError::ProcessContract)
        } else { Ok(()) });
        if !matches!(self.policy, Some(Ok(()))) {
            return Err(ZfsHelperError::ProcessContract);
        }
        let Some(Ok(descriptor)) = self.opened.take() else {
            return Err(ZfsHelperError::ProcessContract);
        };
        self.file = Some(File::from(descriptor));
        self.bytes = Vec::with_capacity(SNAPSHOT_METADATA_RECORD_BYTES);
        let Some(file) = self.file.as_mut() else {
            return Err(ZfsHelperError::ProcessContract);
        };
        self.read = Some((&mut *file).take((SNAPSHOT_METADATA_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut self.bytes));
        if !matches!(self.read, Some(Ok(_))) {
            return Err(ZfsHelperError::ProcessContract);
        }
        self.exact_length = Some(if self.bytes.len() == SNAPSHOT_METADATA_RECORD_BYTES {
            Ok(())
        } else { Err(ZfsHelperError::ProcessContract) });
        if !matches!(self.exact_length, Some(Ok(()))) {
            return Err(ZfsHelperError::ProcessContract);
        }
        self.after = Some(fstat(file));
        let Some(Ok(after)) = self.after.as_ref() else {
            return Err(ZfsHelperError::ProcessContract);
        };
        self.identity = Some(if before.st_dev == after.st_dev
            && before.st_ino == after.st_ino && before.st_size == after.st_size
            && before.st_mtime == after.st_mtime && before.st_mtime_nsec == after.st_mtime_nsec
        { Ok(()) } else { Err(ZfsHelperError::ProcessContract) });
        if !matches!(self.identity, Some(Ok(()))) {
            return Err(ZfsHelperError::ProcessContract);
        }
        self.decoded = Some(crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1
            ::from_canonical_bytes(&self.bytes));
        self.decoded.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ZfsHelperError::ProcessContract)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.opened.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.before.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.policy.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.read.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.exact_length.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.identity.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.decoded.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }
}

impl Drop for SnapshotMetadataReadV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

pub(super) fn read_ordinary(
    directory: &OwnedFd,
    operation_id: [u8; 16],
) -> Result<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1, ZfsHelperError> {
    let mut original = SnapshotMetadataReadV1::new();
    let result = original.capture_once(directory, operation_id);
    if result.is_err() {
        // Ordinary map_err discarded the raw leaf error before its local
        // buffers/File. Selected callers keep these exact slots instead.
        if matches!(original.opened, Some(Err(_))) {
            drop(original.opened.take());
        }
        if matches!(original.before, Some(Err(_))) {
            drop(original.before.take());
        }
        if matches!(original.read, Some(Err(_))) {
            drop(original.read.take());
        }
        if matches!(original.after, Some(Err(_))) {
            drop(original.after.take());
        }
        if matches!(original.decoded, Some(Err(_))) {
            drop(original.decoded.take());
        }
    }
    result
}

#[derive(Default)]
pub(super) struct SnapshotMetadataReadsV1 {
    attempts: Vec<SnapshotMetadataReadV1>,
    demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    first: Option<usize>,
}

impl SnapshotMetadataReadsV1 {
    pub(super) fn capture_receiving_v1(
        &mut self,
        directory: &OwnedFd,
        operation_id: [u8; 16],
        journal: &aos_sandbox_controller_domain::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1, ZfsHelperError> {
        if self.failure().is_some() {
            return Err(ZfsHelperError::ProcessContract);
        }
        self.demand = Some(SnapshotMetadataReadV1::demand_v1());
        let Some(demand) = self.demand.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            return Err(StorageStateError::Receiving.into());
        };
        self.payment = Some(receiving.reserve_snapshot_metadata_read_v1(journal, demand));
        if !matches!(self.payment, Some(Ok(()))) {
            return Err(StorageStateError::Receiving.into());
        }
        self.allocation = Some(self.attempts.try_reserve_exact(1));
        if !matches!(self.allocation, Some(Ok(()))) {
            return Err(StorageStateError::Receiving.into());
        }
        let mut attempt = SnapshotMetadataReadV1::new();
        attempt.armed = true;
        let result = attempt.capture_once(directory, operation_id);
        if result.is_err() {
            self.first = Some(self.attempts.len());
        }
        self.attempts.push(attempt);
        result
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.demand.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.payment.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.allocation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.first.and_then(|index| self.attempts.get(index))
                .and_then(SnapshotMetadataReadV1::failure))
    }

    pub(super) fn require_positive_after_posts_v1(&self) -> Result<(), ZfsHelperError> {
        if self.failure().is_some() || self.attempts.iter().any(|attempt| {
            !matches!(attempt.decoded, Some(Ok(_))) || attempt.failure().is_some()
        }) {
            return Err(ZfsHelperError::ProcessContract);
        }
        Ok(())
    }

    pub(super) fn complete_positive_disposal_v1(&mut self) {
        for attempt in &mut self.attempts {
            attempt.armed = false;
        }
        self.attempts = Vec::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn missing_leaf_preserves_the_original_native_error_on_reentry() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ).unwrap();
        let mut original = SnapshotMetadataReadV1::new();

        assert!(original.capture_once(&descriptor, [7; 16]).is_err());
        let Some(Err(cause)) = original.opened.as_ref() else {
            panic!("the actual failed open must remain on its original");
        };
        assert_eq!(*cause, rustix::io::Errno::NOENT);
        let first = cause as *const rustix::io::Errno;

        assert!(original.capture_once(&descriptor, [8; 16]).is_err());
        let retained = original.failure().unwrap()
            .downcast_ref::<rustix::io::Errno>().unwrap();
        assert_eq!(first, retained as *const rustix::io::Errno);
        assert_eq!(original.name.as_deref(), Some(snapshot_metadata_name([7; 16]).as_str()));
    }

    #[test]
    fn rejected_leaf_keeps_the_actual_open_descriptor_and_policy_result() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let name = snapshot_metadata_name([9; 16]);
        let path = directory.path().join(&name);
        std::fs::write(&path, b"short").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ).unwrap();
        let mut original = SnapshotMetadataReadV1::new();

        assert!(original.capture_once(&descriptor, [9; 16]).is_err());
        let Some(Ok(opened)) = original.opened.as_ref() else {
            panic!("the rejected leaf descriptor must stay resident");
        };
        let actual = fstat(opened).unwrap();
        assert_eq!(actual.st_ino, original.before.as_ref().unwrap().as_ref().unwrap().st_ino);
        assert!(matches!(original.policy, Some(Err(ZfsHelperError::ProcessContract))));
        assert!(original.read.is_none());

        let before = opened.as_raw_fd();
        assert!(original.capture_once(&descriptor, [0; 16]).is_err());
        let Some(Ok(opened)) = original.opened.as_ref() else {
            panic!("reentry must preserve the rejected original");
        };
        assert_eq!(opened.as_raw_fd(), before);
        assert!(fstat(opened).is_ok());
    }
}
