//! Fully sealed read-only memfds for transient credential transfer.
//!
//! A credential is written into a private memfd, sealed against every content
//! and size change, and reopened through the creator's procfs descriptor alias
//! as an `O_RDONLY` file description. The type owns that read-only description
//! and revalidates its inode, size, ownership, and complete seal set when
//! adopting an existing descriptor.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt as _;

use rustix::fs::{
    FileType, MemfdFlags, OFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, fcntl_getfl, fstat,
    memfd_create,
};

use super::ImmutableFileError;
use crate::Error;

const REQUIRED_SEALS: SealFlags = SealFlags::SEAL
    .union(SealFlags::SHRINK)
    .union(SealFlags::GROW)
    .union(SealFlags::WRITE);

/// Owns one creator-owned, fully sealed memfd through an `O_RDONLY` description.
///
/// The current process's effective UID is checked at construction. A root Host
/// therefore creates a root-owned credential, while unprivileged unit tests can
/// exercise the same kernel invariants without weakening the production type.
#[derive(Debug)]
pub struct SealedReadOnlyCredential {
    descriptor: OwnedFd,
    bytes: u64,
}

impl SealedReadOnlyCredential {
    /// Creates, seals, reopens, and reads back one bounded credential.
    ///
    /// # Errors
    ///
    /// Returns [`ImmutableFileError`] when the input is empty or oversized, a
    /// memfd operation fails, the read-only reopen changes the inode, or exact
    /// readback differs from the supplied bytes.
    pub fn create(
        name: &str,
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<Self, ImmutableFileError> {
        if bytes.is_empty() || bytes.len() > maximum_bytes {
            return Err(ImmutableFileError::MappingLimitExceeded);
        }

        let publisher = memfd_create(name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
            .map_err(|error| linux("memfd_create", error))?;
        let mut writer = File::from(publisher);
        writer
            .write_all(bytes)
            .map_err(|error| std_io("write sealed credential", error))?;
        fcntl_add_seals(&writer, REQUIRED_SEALS)
            .map_err(|error| linux("fcntl(F_ADD_SEALS)", error))?;

        let publisher_metadata = fstat(&writer).map_err(|error| linux("fstat", error))?;
        let reader = OpenOptions::new()
            .read(true)
            .open(format!("/proc/self/fd/{}", writer.as_raw_fd()))
            .map_err(|error| std_io("reopen sealed credential read-only", error))?;
        let reader_metadata = fstat(&reader).map_err(|error| linux("fstat", error))?;
        if publisher_metadata.st_dev != reader_metadata.st_dev
            || publisher_metadata.st_ino != reader_metadata.st_ino
        {
            return Err(ImmutableFileError::AdmissionRace);
        }
        drop(writer);

        let expected_bytes =
            u64::try_from(bytes.len()).map_err(|_| ImmutableFileError::MappingLimitExceeded)?;
        let maximum_bytes =
            u64::try_from(maximum_bytes).map_err(|_| ImmutableFileError::MappingLimitExceeded)?;
        let credential = Self::from_owned(reader.into(), expected_bytes, maximum_bytes)?;
        let mut observed = vec![0; bytes.len()];
        read_exact_at(credential.descriptor.as_fd(), &mut observed)?;
        if observed != bytes {
            return Err(ImmutableFileError::AdmissionRace);
        }
        credential.revalidate()?;
        Ok(credential)
    }

    /// Adopts an already opened, fully sealed read-only memfd.
    ///
    /// # Errors
    ///
    /// Returns [`ImmutableFileError`] unless the descriptor is a creator-owned
    /// anonymous regular file of the exact nonzero size, is opened `O_RDONLY`,
    /// and carries `F_SEAL_SEAL`, `F_SEAL_SHRINK`, `F_SEAL_GROW`, and
    /// `F_SEAL_WRITE`. `F_SEAL_FUTURE_WRITE` does not substitute for the last.
    pub fn from_owned(
        descriptor: OwnedFd,
        expected_bytes: u64,
        maximum_bytes: u64,
    ) -> Result<Self, ImmutableFileError> {
        if expected_bytes == 0 || expected_bytes > maximum_bytes {
            return Err(ImmutableFileError::MappingLimitExceeded);
        }
        let credential = Self {
            descriptor,
            bytes: expected_bytes,
        };
        credential.revalidate()?;
        Ok(credential)
    }

    /// Borrows the sealed read-only descriptor for a bounded transfer.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }

    /// Returns the exact admitted byte length.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.bytes
    }

    /// Reports whether this credential has zero bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    fn revalidate(&self) -> Result<(), ImmutableFileError> {
        let metadata = fstat(&self.descriptor).map_err(|error| linux("fstat", error))?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
            return Err(ImmutableFileError::NotRegular);
        }
        if metadata.st_uid != rustix::process::geteuid().as_raw() {
            return Err(ImmutableFileError::UnexpectedOwner);
        }
        if metadata.st_nlink != 0 {
            return Err(ImmutableFileError::NotAnonymous);
        }
        if fcntl_getfl(&self.descriptor).map_err(|error| linux("fcntl(F_GETFL)", error))?
            & OFlags::ACCMODE
            != OFlags::RDONLY
        {
            return Err(ImmutableFileError::DescriptorNotReadOnly);
        }
        let observed_bytes =
            u64::try_from(metadata.st_size).map_err(|_| ImmutableFileError::SizeMismatch)?;
        if observed_bytes != self.bytes {
            return Err(ImmutableFileError::SizeMismatch);
        }
        let seals =
            fcntl_get_seals(&self.descriptor).map_err(|_| ImmutableFileError::MissingSeals)?;
        if !seals.contains(REQUIRED_SEALS) {
            return Err(ImmutableFileError::MissingSeals);
        }
        Ok(())
    }
}

fn read_exact_at(descriptor: BorrowedFd<'_>, output: &mut [u8]) -> Result<(), ImmutableFileError> {
    let file = File::from(
        descriptor
            .try_clone_to_owned()
            .map_err(|error| std_io("duplicate sealed credential", error))?,
    );
    let mut offset = 0;
    while offset < output.len() {
        let read = file
            .read_at(&mut output[offset..], offset as u64)
            .map_err(|error| std_io("read sealed credential", error))?;
        if read == 0 {
            return Err(ImmutableFileError::SizeMismatch);
        }
        offset += read;
    }
    Ok(())
}

fn linux(operation: &'static str, source: rustix::io::Errno) -> ImmutableFileError {
    ImmutableFileError::Linux(Error::Syscall {
        operation,
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    })
}

fn std_io(operation: &'static str, source: std::io::Error) -> ImmutableFileError {
    ImmutableFileError::Linux(Error::Syscall { operation, source })
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;

    use super::*;

    #[test]
    fn creates_an_exact_fully_sealed_read_only_credential() {
        let credential = SealedReadOnlyCredential::create("aos-credential-test", b"authority", 64)
            .unwrap_or_else(|error| panic!("credential creation failed: {error}"));

        assert_eq!(credential.len(), 9);
        assert!(!credential.is_empty());
        assert_eq!(
            fcntl_getfl(credential.as_fd())
                .unwrap_or_else(|error| panic!("status flags failed: {error}"))
                & OFlags::ACCMODE,
            OFlags::RDONLY
        );
        assert!(
            fcntl_get_seals(credential.as_fd())
                .unwrap_or_else(|error| panic!("seal read failed: {error}"))
                .contains(REQUIRED_SEALS)
        );
    }

    #[test]
    fn rejects_writable_and_incompletely_sealed_handoffs() {
        let writable = memfd_create(
            "aos-writable-credential-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .unwrap_or_else(|error| panic!("memfd failed: {error}"));
        let mut writable = File::from(writable);
        writable
            .write_all(b"authority")
            .unwrap_or_else(|error| panic!("write failed: {error}"));
        fcntl_add_seals(&writable, REQUIRED_SEALS)
            .unwrap_or_else(|error| panic!("seal failed: {error}"));
        assert!(matches!(
            SealedReadOnlyCredential::from_owned(writable.into(), 9, 64),
            Err(ImmutableFileError::DescriptorNotReadOnly)
        ));

        let partial = memfd_create(
            "aos-partial-credential-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .unwrap_or_else(|error| panic!("memfd failed: {error}"));
        let mut partial = File::from(partial);
        partial
            .write_all(b"authority")
            .unwrap_or_else(|error| panic!("write failed: {error}"));
        fcntl_add_seals(
            &partial,
            SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW,
        )
        .unwrap_or_else(|error| panic!("partial seal failed: {error}"));
        let reader = OpenOptions::new()
            .read(true)
            .open(format!("/proc/self/fd/{}", partial.as_raw_fd()))
            .unwrap_or_else(|error| panic!("read-only reopen failed: {error}"));
        assert!(matches!(
            SealedReadOnlyCredential::from_owned(reader.into(), 9, 64),
            Err(ImmutableFileError::MissingSeals)
        ));
    }

    #[test]
    fn future_write_does_not_substitute_for_write_seal() {
        let descriptor = memfd_create(
            "aos-future-write-credential-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .unwrap_or_else(|error| panic!("memfd failed: {error}"));
        let mut file = File::from(descriptor);
        file.write_all(b"authority")
            .unwrap_or_else(|error| panic!("write failed: {error}"));
        fcntl_add_seals(
            &file,
            SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::FUTURE_WRITE,
        )
        .unwrap_or_else(|error| panic!("future-write seal failed: {error}"));
        let reader = OpenOptions::new()
            .read(true)
            .open(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .unwrap_or_else(|error| panic!("read-only reopen failed: {error}"));

        assert!(matches!(
            SealedReadOnlyCredential::from_owned(reader.into(), 9, 64),
            Err(ImmutableFileError::MissingSeals)
        ));
    }

    #[test]
    fn ordinary_regular_file_is_not_an_anonymous_memfd() {
        let file = File::open("/proc/self/exe")
            .unwrap_or_else(|error| panic!("test executable failed: {error}"));
        let bytes = fstat(file.as_fd())
            .unwrap_or_else(|error| panic!("fstat failed: {error}"))
            .st_size as u64;
        assert!(matches!(
            SealedReadOnlyCredential::from_owned(file.into(), bytes, bytes),
            Err(ImmutableFileError::NotAnonymous)
        ));
    }
}
