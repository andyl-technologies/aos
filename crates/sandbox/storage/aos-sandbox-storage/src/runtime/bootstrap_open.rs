//! Retains the actual bootstrap directory, two file reads, and decode results.
//!
//! The enclosing genuine receiver pays and joins its measured argv7 before
//! entry. This private result owner cannot issue authority or receiving funds.

use super::*;

pub(super) struct ProtectedBootstrapFileReadV1 {
    opened: Option<Result<std::fs::File, rustix::io::Errno>>,
    metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    declared_size: Option<Result<usize, StorageRuntimeError>>,
    read: Option<Result<usize, std::io::Error>>,
    length: Option<Result<(), StorageRuntimeError>>,
    pub(super) bytes: Vec<u8>,
}

impl ProtectedBootstrapFileReadV1 {
    pub(super) const fn new() -> Self {
        Self {
            opened: None,
            metadata: None,
            declared_size: None,
            read: None,
            length: None,
            bytes: Vec::new(),
        }
    }

    pub(super) fn read_once_v1(
        &mut self,
        directory: &OwnedFd,
        name: &'static str,
        maximum_bytes: usize,
        expected_uid: u32,
    ) -> Result<(), StorageRuntimeError> {
        if self.opened.is_some() {
            return Err(StorageRuntimeError::Bootstrap);
        }
        self.opened = Some(openat(
            directory, name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ).map(std::fs::File::from));
        let file = self.opened.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(StorageRuntimeError::Bootstrap)?;
        self.metadata = Some(fstat(file));
        let metadata = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(StorageRuntimeError::Bootstrap)?;
        self.declared_size = Some((|| {
            let size = usize::try_from(metadata.st_size)
                .map_err(|_| StorageRuntimeError::Bootstrap)?;
            if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
                || metadata.st_uid != expected_uid
                || metadata.st_nlink != 1
                || !matches!(metadata.st_mode & 0o7777, 0o400 | 0o600)
                || size == 0 || size > maximum_bytes
            {
                return Err(StorageRuntimeError::Bootstrap);
            }
            Ok(size)
        })());
        let size = self.declared_size.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(StorageRuntimeError::Bootstrap)?;
        self.bytes = Vec::with_capacity(size);
        let file = self.opened.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(StorageRuntimeError::Bootstrap)?;
        self.read = Some(file.take((maximum_bytes + 1) as u64).read_to_end(&mut self.bytes));
        if matches!(self.read, Some(Ok(_))) {
            Ok(())
        } else {
            Err(StorageRuntimeError::Bootstrap)
        }
    }

    pub(super) fn require_length_v1(&mut self, maximum_bytes: usize) -> Result<(), StorageRuntimeError> {
        let size = self.declared_size.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(StorageRuntimeError::Bootstrap)?;
        self.length = Some(if self.bytes.len() == size && self.bytes.len() <= maximum_bytes {
            Ok(())
        } else { Err(StorageRuntimeError::Bootstrap) });
        if matches!(self.length, Some(Ok(()))) {
            Ok(())
        } else {
            Err(StorageRuntimeError::Bootstrap)
        }
    }

    // Only the ordinary adapter calls this, at its original successful read
    // boundary. The selected caller keeps the same File on every result.
    pub(super) fn dispose_positive_file_v1(&mut self) {
        if matches!(self.read, Some(Ok(_))) {
            self.opened.take();
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.opened.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.metadata.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.declared_size.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.read.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.length.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }
}

pub(super) struct ProtectedStorageBootstrapOpenV1 {
    directory: Option<Result<OwnedFd, rustix::io::Errno>>,
    metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    directory_validation: Option<Result<(), StorageRuntimeError>>,
    minimum: ProtectedBootstrapFileReadV1,
    minimum_generation: Option<Result<u64, StorageRuntimeError>>,
    bootstrap: ProtectedBootstrapFileReadV1,
    decoded: Option<Result<(u64, Vec<ResolvedCatalogCommitmentV1>), StorageRuntimeError>>,
    taken: bool,
}

impl ProtectedStorageBootstrapOpenV1 {
    pub(super) const fn new() -> Self {
        Self {
            directory: None,
            metadata: None,
            directory_validation: None,
            minimum: ProtectedBootstrapFileReadV1::new(),
            minimum_generation: None,
            bootstrap: ProtectedBootstrapFileReadV1::new(),
            decoded: None,
            taken: false,
        }
    }

    pub(super) fn capture_once_v1(&mut self, path: &Path, expected_uid: u32)
        -> Result<(), StorageRuntimeError>
    {
        if self.directory.is_some() {
            return Err(StorageRuntimeError::Bootstrap);
        }
        self.directory = Some(open(path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty()));
        let directory = self.directory.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(StorageRuntimeError::Bootstrap)?;
        self.metadata = Some(fstat(directory));
        let metadata = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(StorageRuntimeError::Bootstrap)?;
        self.directory_validation = Some(validate_bootstrap_directory_metadata_v1(metadata, expected_uid));
        if !matches!(self.directory_validation, Some(Ok(()))) {
            return Err(StorageRuntimeError::Bootstrap);
        }
        self.minimum.read_once_v1(directory, MINIMUM_GENERATION_FILE, 8, expected_uid)?;
        self.minimum.require_length_v1(8)?;
        self.minimum_generation = Some(decode_bootstrap_minimum_v1(&self.minimum.bytes));
        if !matches!(self.minimum_generation, Some(Ok(_))) {
            return Err(StorageRuntimeError::Bootstrap);
        }
        self.bootstrap.read_once_v1(directory, BOOTSTRAP_FILE, MAXIMUM_BOOTSTRAP_BYTES, expected_uid)?;
        self.bootstrap.require_length_v1(MAXIMUM_BOOTSTRAP_BYTES)?;
        self.decoded = Some(decode_bootstrap(&self.bootstrap.bytes));
        if matches!(self.decoded, Some(Ok(_))) {
            Ok(())
        } else {
            Err(StorageRuntimeError::Bootstrap)
        }
    }

    pub(super) fn take_success_v1(&mut self) -> Option<ProtectedStorageBootstrap> {
        if self.taken || self.failure().is_some() {
            return None;
        }
        let minimum_generation = match self.minimum_generation.as_ref()? {
            Ok(value) => *value,
            Err(_) => return None,
        };
        if !matches!(self.decoded, Some(Ok(_))) {
            return None;
        }
        let (genesis_generation, catalogs) = self.decoded.take()?.ok()?;
        self.taken = true;
        Some(ProtectedStorageBootstrap { minimum_generation, genesis_generation, catalogs })
    }

    #[cfg(test)]
    pub(super) fn retained_file_count_v1(&self) -> usize {
        usize::from(self.directory.as_ref().is_some_and(Result::is_ok))
            + usize::from(self.minimum.opened.as_ref().is_some_and(Result::is_ok))
            + usize::from(self.bootstrap.opened.as_ref().is_some_and(Result::is_ok))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.directory.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.metadata.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.directory_validation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.minimum.failure())
            .or_else(|| self.minimum_generation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.bootstrap.failure())
            .or_else(|| self.decoded.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }
}
