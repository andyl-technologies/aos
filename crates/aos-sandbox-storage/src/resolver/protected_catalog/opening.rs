//! Shared native policy acquisition with an optional retained caller lifetime.
//!
//! These inert destinations create no payer or policy authority. The ordinary
//! adapters keep them local; the prepaid selected caller parks them before IO.

use std::io::Read as _;
use std::fs::File;
use super::*;

pub(crate) struct ResolverPolicyDirectoryOriginalV1 {
    authority: Option<Result<(), StorageResolverPolicyError>>,
    opened: Option<Result<OwnedFd, rustix::io::Errno>>,
    metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    admission: Option<Result<(), StorageResolverPolicyError>>,
    entered: bool,
}

impl ResolverPolicyDirectoryOriginalV1 {
    pub(crate) const fn new() -> Self {
        Self {
            authority: None,
            opened: None,
            metadata: None,
            admission: None,
            entered: false,
        }
    }

    pub(super) fn open_once(&mut self, path: &Path, binding: ObjectDigest, uid: u32)
        -> Result<(), StorageResolverPolicyError>
    {
        if self.entered {
            return Err(StorageResolverPolicyError::ProtectedPath);
        }
        self.entered = true;
        self.authority = Some(if binding.as_bytes() == &[0; 32] {
            Err(StorageResolverPolicyError::AuthorityMismatch)
        } else { Ok(()) });
        if let Some(Err(cause)) = &self.authority {
            return Err(*cause);
        }
        self.opened = Some(open(path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty()));
        let Some(Ok(directory)) = self.opened.as_ref() else {
            return Err(StorageResolverPolicyError::ProtectedPath);
        };
        self.metadata = Some(fstat(directory));
        let Some(Ok(metadata)) = self.metadata.as_ref() else {
            return Err(StorageResolverPolicyError::ProtectedPath);
        };
        self.admission = Some(if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || metadata.st_uid != uid || !matches!(metadata.st_mode & 0o7777, 0o500 | 0o700)
        { Err(StorageResolverPolicyError::ProtectedPath) } else { Ok(()) });
        match self.admission.as_ref() {
            Some(Ok(())) => Ok(()),
            _ => Err(StorageResolverPolicyError::ProtectedPath),
        }
    }

    pub(super) fn take_directory(&mut self) -> Result<OwnedFd, StorageResolverPolicyError> {
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(StorageResolverPolicyError::ProtectedPath);
        }
        match self.opened.take() {
            Some(Ok(directory)) => Ok(directory),
            other => {
                self.opened = other;
                Err(StorageResolverPolicyError::ProtectedPath)
            }
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.authority.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _)
            .or_else(|| self.opened.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.metadata.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.admission.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
    }
}

pub(crate) struct ResolverPolicyReadOriginalV1 {
    // The ordinary reader declared bytes before File: File closes first.
    file: Option<Result<File, rustix::io::Errno>>,
    bytes: Vec<u8>,
    directory_metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    directory_admission: Option<Result<(), StorageResolverPolicyError>>,
    metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    declared_size: Option<Result<usize, std::num::TryFromIntError>>,
    admission: Option<Result<(), StorageResolverPolicyError>>,
    read: Option<Result<usize, std::io::Error>>,
    current: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    comparison: Option<Result<(), StorageResolverPolicyError>>,
    decoded: Option<Result<LoadedStorageResolverPolicyCatalogV1, StorageResolverPolicyError>>,
    entered: bool,
}

impl ResolverPolicyReadOriginalV1 {
    /// Prices one retained catalog read and its complete bounded decode.
    ///
    /// The directory is already held. Selection moves one entry out of the
    /// decoded vector; it does not clone another catalog or its string backing.
    pub(crate) fn receiving_demand_v3() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let bytes = MAXIMUM_CATALOG_BYTES.checked_add(1)?;
        // read_to_end may grow past the declared size. Old and replacement
        // allocations overlap; three bounds cover that allocation frontier.
        let raw_read = bytes.checked_mul(3)?;
        // Each entry owns its canonical assignment and five names: the policy
        // root's pair and the ancestor's root pair plus ancestor dataset name.
        let entry_backing = ASSIGNMENT_BYTES.checked_add(MAXIMUM_NAME_BYTES.checked_mul(5)?)?;
        let entries = std::mem::size_of::<LoadedStorageResolverPolicyEntryV1>()
            .checked_add(entry_backing)?.checked_mul(MAXIMUM_ENTRIES)?;
        // The ordering check replaces one previous assignment. The selected
        // policy moves its backing, while the typed local constructors and
        // descendant-prefix formatter can coexist with the last decoded row.
        let scratch = ASSIGNMENT_BYTES.checked_mul(2)?
            .checked_add(MAXIMUM_NAME_BYTES.checked_add(1)?)?
            .checked_add(std::mem::size_of::<LoadedStorageResolverPolicyCatalogV1>())?
            .checked_add(std::mem::size_of::<SelectedStorageResolverPolicyV1>())?
            .checked_add(std::mem::size_of::<ProtectedStorageResolverPolicyV1>())?
            .checked_add(std::mem::size_of::<ManagedDatasetRoot>())?
            .checked_add(std::mem::size_of::<ResolvedDataset>())?
            .checked_add(std::mem::size_of::<ProjectAncestorPolicyV1>())?
            .checked_add(std::mem::size_of::<BoundedReader<'_, StorageResolverPolicyError>>())?
            .checked_add(std::mem::size_of::<Sha256>())?;
        let memory = std::mem::size_of::<Self>().checked_add(raw_read)?
            .checked_add(entries)?.checked_add(scratch)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 1).with(D::MetadataEntries, 1))
    }

    pub(crate) const fn new() -> Self {
        Self {
            file: None,
            bytes: Vec::new(),
            directory_metadata: None,
            directory_admission: None,
            metadata: None,
            declared_size: None,
            admission: None,
            read: None,
            current: None,
            comparison: None,
            decoded: None,
            entered: false,
        }
    }

    pub(super) fn read_once(&mut self, policy: &ProtectedStorageResolverPolicyDirectoryV1)
        -> Result<(), StorageResolverPolicyError>
    {
        if self.entered {
            return Err(StorageResolverPolicyError::ProtectedPath);
        }
        self.entered = true;
        self.directory_metadata = Some(fstat(&policy.directory));
        let Some(Ok(directory_metadata)) = self.directory_metadata.as_ref() else {
            return Err(StorageResolverPolicyError::ProtectedPath);
        };
        self.directory_admission = Some(if FileType::from_raw_mode(directory_metadata.st_mode) != FileType::Directory
            || directory_metadata.st_uid != policy.expected_uid
            || !matches!(directory_metadata.st_mode & 0o7777, 0o500 | 0o700)
        { Err(StorageResolverPolicyError::ProtectedPath) } else { Ok(()) });
        if !matches!(self.directory_admission, Some(Ok(()))) {
            return Err(StorageResolverPolicyError::ProtectedPath);
        }
        self.file = Some(openat(&policy.directory, FILE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty()).map(File::from));
        let Some(Ok(file)) = self.file.as_mut() else {
            return Err(StorageResolverPolicyError::ProtectedPath);
        };
        self.metadata = Some(fstat(&*file));
        let Some(Ok(metadata)) = self.metadata.as_ref() else {
            return Err(StorageResolverPolicyError::ProtectedPath);
        };
        self.declared_size = Some(usize::try_from(metadata.st_size));
        let Some(Ok(declared_size)) = self.declared_size.as_ref().copied() else {
            return Err(StorageResolverPolicyError::ProtectedPath);
        };
        self.admission = Some(if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != policy.expected_uid || metadata.st_nlink != 1
            || !matches!(metadata.st_mode & 0o7777, 0o400 | 0o600)
            || !(HEADER_BYTES..=MAXIMUM_CATALOG_BYTES).contains(&declared_size)
        { Err(StorageResolverPolicyError::ProtectedPath) } else { Ok(()) });
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(StorageResolverPolicyError::ProtectedPath);
        }
        self.bytes = Vec::with_capacity(declared_size);
        self.read = Some((&mut *file).take((MAXIMUM_CATALOG_BYTES + 1) as u64).read_to_end(&mut self.bytes));
        if !matches!(self.read, Some(Ok(_))) {
            return Err(StorageResolverPolicyError::ProtectedPath);
        }
        self.current = Some(fstat(&*file));
        let Some(Ok(current)) = self.current.as_ref() else {
            return Err(StorageResolverPolicyError::ProtectedPath);
        };
        self.comparison = Some(if self.bytes.len() != declared_size
            || current.st_dev != metadata.st_dev || current.st_ino != metadata.st_ino
            || current.st_size != metadata.st_size || current.st_mode != metadata.st_mode
            || current.st_uid != metadata.st_uid || current.st_gid != metadata.st_gid
            || current.st_nlink != metadata.st_nlink || current.st_mtime != metadata.st_mtime
            || current.st_mtime_nsec != metadata.st_mtime_nsec || current.st_ctime != metadata.st_ctime
            || current.st_ctime_nsec != metadata.st_ctime_nsec
        { Err(StorageResolverPolicyError::ProtectedPath) } else { Ok(()) });
        if !matches!(self.comparison, Some(Ok(()))) {
            return Err(StorageResolverPolicyError::ProtectedPath);
        }
        self.decoded = Some(LoadedStorageResolverPolicyCatalogV1::decode(&self.bytes, policy.authority_binding));
        match self.decoded.as_ref() {
            Some(Ok(_)) => Ok(()),
            Some(Err(cause)) => Err(*cause),
            None => Err(StorageResolverPolicyError::ProtectedPath),
        }
    }

    pub(super) fn take_catalog(&mut self) -> Result<LoadedStorageResolverPolicyCatalogV1, StorageResolverPolicyError> {
        match self.decoded.take() {
            Some(Ok(catalog)) => Ok(catalog),
            other => {
                self.decoded = other;
                Err(StorageResolverPolicyError::ProtectedPath)
            }
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.directory_metadata.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _)
            .or_else(|| self.directory_admission.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.file.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.metadata.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.declared_size.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.admission.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.read.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.current.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.comparison.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.decoded.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use super::*;

    #[test]
    fn refused_directory_keeps_its_actual_descriptor_and_first_cause() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let uid = std::fs::metadata(directory.path()).unwrap().uid();
        let mut original = ResolverPolicyDirectoryOriginalV1::new();

        assert!(matches!(ProtectedStorageResolverPolicyDirectoryV1::open_with_original_v1(
            directory.path(), ObjectDigest::from_bytes([7; 32]), uid, &mut original,
        ), Err(StorageResolverPolicyError::ProtectedPath)));

        let descriptor = original.opened.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(fstat(descriptor).unwrap().st_uid, uid);
        let actual = original.admission.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(actual, original.failure().unwrap()
            .downcast_ref::<StorageResolverPolicyError>().unwrap()));
    }

    #[test]
    fn refused_file_keeps_same_file_metadata_and_policy_classification() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::fs::metadata(directory.path()).unwrap().uid();
        let binding = ObjectDigest::from_bytes([7; 32]);
        let bytes = encode_catalog_for_test(7, binding, &[]);
        let path = directory.path().join(FILE_NAME);
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let policy = ProtectedStorageResolverPolicyDirectoryV1::open_with_owner(directory.path(), binding, uid).unwrap();
        let mut original = ResolverPolicyReadOriginalV1::new();

        assert!(matches!(policy.load_retaining_v1(&mut original), Err(StorageResolverPolicyError::ProtectedPath)));
        assert!(matches!(policy.load(), Err(StorageResolverPolicyError::ProtectedPath)));

        let file = original.file.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(fstat(file).unwrap().st_ino, original.metadata.as_ref().unwrap().as_ref().unwrap().st_ino);
        assert!(original.read.is_none());
        let actual = original.admission.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(actual, original.failure().unwrap()
            .downcast_ref::<StorageResolverPolicyError>().unwrap()));
    }

    #[test]
    fn selected_and_ordinary_decode_same_atomic_publication() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::fs::metadata(directory.path()).unwrap().uid();
        let binding = ObjectDigest::from_bytes([7; 32]);
        let bytes = encode_catalog_for_test(7, binding, &[]);
        let path = directory.path().join(FILE_NAME);
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let policy = ProtectedStorageResolverPolicyDirectoryV1::open_with_owner(directory.path(), binding, uid).unwrap();
        let ordinary = policy.load().unwrap();
        let mut original = ResolverPolicyReadOriginalV1::new();
        let selected = policy.load_retaining_v1(&mut original).unwrap();

        assert_eq!(selected.binding().unwrap(), ordinary.binding().unwrap());
        assert_eq!(original.bytes, bytes);
        assert!(original.file.as_ref().unwrap().is_ok());
        assert!(original.failure().is_none());
    }
}
