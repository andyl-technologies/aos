//! One-shot custody for the same sealed credential creation engine.
//!
//! Destinations keep reached native descriptions, exact readback and the first
//! error without reopening a role credential or admitting its contents. Ordinary
//! creation selects no destinations and retains its existing disposal schedule.

use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::Path;

use zeroize::Zeroizing;

use super::{ImmutableFileError, SealedReadOnlyCredential};

/// Stops failed or repeated creation while its actual original remains owned.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("sealed credential creation remains retained and closed")]
pub struct SealedReadOnlyCredentialCreateClosedV1;

/// Describes passive byte and descriptor geometry for one creation attempt.
///
/// This is representation DATA, not a reservation or credential/role grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedReadOnlyCredentialCreateFootprintV1 {
    /// Includes memfd content, exact readback and fixed native/path carriers.
    pub memory_bytes: usize,
    /// Preserves the existing four-descriptor creation/transfer peak.
    pub open_files: usize,
    /// Charges no Rust fields or transient parser controls as namespace entries.
    pub metadata_entries: usize,
}

/// Owns one actual creation attempt and every reached native failure prefix.
///
/// Empty construction performs no IO or allocation. A failed candidate cannot
/// be borrowed as a credential; successful access still grants no role or
/// authority over the bytes. The caller retains its input and this original
/// through its independently owed posts and actual authenticated transfer.
#[must_use]
pub struct SealedReadOnlyCredentialCreateOriginalsV1 {
    pub(super) writer: Option<File>,
    pub(super) reader: Option<File>,
    pub(super) credential: Option<SealedReadOnlyCredential>,
    pub(super) duplicate: Option<File>,
    pub(super) observed: Option<Zeroizing<Vec<u8>>>,
    pub(super) proc_alias: Option<String>,
    pub(super) native_validation_error: Option<ImmutableFileError>,
    error: Option<ImmutableFileError>,
    refused: Option<SealedReadOnlyCredentialCreateClosedV1>,
    attempted: bool,
    completed: bool,
    taken: bool,
}

impl SealedReadOnlyCredentialCreateOriginalsV1 {
    /// Creates inert destinations without native work or variable allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            writer: None,
            reader: None,
            credential: None,
            duplicate: None,
            observed: None,
            proc_alias: None,
            native_validation_error: None,
            error: None,
            refused: None,
            attempted: false,
            completed: false,
            taken: false,
        }
    }

    /// Runs the sole ordinary creation engine once with retained destinations.
    ///
    /// The public entry adds no SELinux label selector. The existing fixed FUSE
    /// recipe keeps its private labelled entry and uses the same native engine.
    ///
    /// # Errors
    /// Returns a stopping marker on native/invariant refusal or repeated entry.
    /// The actual first cause remains borrowed from [`Self::failure`].
    pub fn create_once(
        &mut self,
        name: &str,
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<(), SealedReadOnlyCredentialCreateClosedV1> {
        self.create_labelled_once(name, bytes, maximum_bytes, None)
    }

    pub(super) fn create_labelled_once(
        &mut self,
        name: &str,
        bytes: &[u8],
        maximum_bytes: usize,
        context: Option<&str>,
    ) -> Result<(), SealedReadOnlyCredentialCreateClosedV1> {
        if self.attempted {
            self.refused.get_or_insert(SealedReadOnlyCredentialCreateClosedV1);
            return Err(SealedReadOnlyCredentialCreateClosedV1);
        }
        self.attempted = true;
        match SealedReadOnlyCredential::create_labelled_engine(
            name, bytes, maximum_bytes, context, Some(&mut *self),
        ) {
            Ok(credential) => {
                self.credential = Some(credential);
                self.completed = true;
                Ok(())
            }
            Err(cause) => {
                self.error = Some(cause);
                Err(SealedReadOnlyCredentialCreateClosedV1)
            }
        }
    }

    /// Borrows only the actual successfully created credential before transfer.
    #[must_use]
    pub fn completed(&self) -> Option<&SealedReadOnlyCredential> {
        if !self.completed || self.taken || self.failure().is_some() {
            return None;
        }
        self.credential.as_ref()
    }

    /// Moves the same completed credential at most once after caller completion.
    ///
    /// The caller first completes its real upper posts/transfer interval. Other
    /// native descriptions and readback stay in this original until its disposal;
    /// no financial refund, new attempt or role proof is produced.
    pub fn take_completed_once(&mut self) -> Option<SealedReadOnlyCredential> {
        self.completed()?;
        self.taken = true;
        self.credential.take()
    }

    /// Borrows the first actual native or invariant error before a reentry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native_validation_error
            .as_ref()
            .map(|cause| cause as _)
            .or_else(|| self.error.as_ref().map(|cause| cause as _))
            .or_else(|| self.refused.as_ref().map(|cause| cause as _))
    }

    /// Bounds one attempt from the actual admitted input length before allocation.
    ///
    /// Input storage is caller-owned and paid separately. Two length planes cover
    /// the real memfd content and exact Zeroizing readback. Fixed layout includes
    /// resident/return construction and native work carriers; procfs formatting
    /// uses its fixed prefix plus the maximum signed descriptor decimal width;
    /// formatted String and native path conversion have separate byte lanes.
    /// The memfd name has a separate C-string conversion lane, including invalid
    /// long names. Allocator/page bookkeeping remains a charged cgroup backstop.
    /// Returns `None` on checked byte arithmetic overflow.
    #[must_use]
    pub fn receiving_footprint_v1(
        name_bytes: usize,
        actual_bytes: usize,
    ) -> Option<SealedReadOnlyCredentialCreateFootprintV1> {
        let path = "/proc/self/fd/".len().checked_mul(2)?.checked_add(10)?;
        let memory_bytes = std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(std::mem::size_of::<CreationWorkV1>())?
            .checked_add(actual_bytes.checked_mul(2)?)?
            .checked_add(name_bytes.checked_add(1)?)?
            .checked_add(path.checked_mul(2)?)?;
        Some(SealedReadOnlyCredentialCreateFootprintV1 {
            memory_bytes,
            open_files: 4,
            metadata_entries: 0,
        })
    }
}

impl Default for SealedReadOnlyCredentialCreateOriginalsV1 {
    fn default() -> Self {
        Self::new()
    }
}

// Fixed work carriers are layout DATA only, never a native adopter or payer.
#[allow(dead_code)]
struct CreationWorkV1 {
    writer: CreationSlotV1<'static, File>,
    reader: CreationSlotV1<'static, File>,
    credential: CreationSlotV1<'static, SealedReadOnlyCredential>,
    duplicate: CreationSlotV1<'static, File>,
    observed: CreationSlotV1<'static, Zeroizing<Vec<u8>>>,
    proc_alias: CreationSlotV1<'static, String>,
    publisher: Result<std::os::fd::OwnedFd, rustix::io::Errno>,
    publisher_metadata: rustix::fs::Stat,
    reader_metadata: rustix::fs::Stat,
    validation_metadata: rustix::fs::Stat,
    read: std::io::Result<usize>,
    result: Result<SealedReadOnlyCredential, ImmutableFileError>,
    destinations: CreateDestinationsV1<'static>,
}

pub(super) struct CreateDestinationsV1<'a> {
    pub(super) writer: Option<&'a mut Option<File>>,
    pub(super) reader: Option<&'a mut Option<File>>,
    pub(super) credential: Option<&'a mut Option<SealedReadOnlyCredential>>,
    pub(super) duplicate: Option<&'a mut Option<File>>,
    pub(super) observed: Option<&'a mut Option<Zeroizing<Vec<u8>>>>,
    pub(super) proc_alias: Option<&'a mut Option<String>>,
    pub(super) native_validation_error: Option<&'a mut Option<ImmutableFileError>>,
}

impl<'a> CreateDestinationsV1<'a> {
    pub(super) fn new(original: Option<&'a mut SealedReadOnlyCredentialCreateOriginalsV1>) -> Self {
        match original {
            Some(original) => Self {
                writer: Some(&mut original.writer),
                reader: Some(&mut original.reader),
                credential: Some(&mut original.credential),
                duplicate: Some(&mut original.duplicate),
                observed: Some(&mut original.observed),
                proc_alias: Some(&mut original.proc_alias),
                native_validation_error: Some(&mut original.native_validation_error),
            },
            None => Self {
                writer: None,
                reader: None,
                credential: None,
                duplicate: None,
                observed: None,
                proc_alias: None,
                native_validation_error: None,
            },
        }
    }
}

// With None the value drops at the original local/argument boundary. With Some
// it moves, without clone or allocation, to its prepaid destination on unwind.
pub(super) struct CreationSlotV1<'a, T> {
    value: Option<T>,
    destination: Option<&'a mut Option<T>>,
}

impl<'a, T> CreationSlotV1<'a, T> {
    pub(super) fn new(value: T, destination: Option<&'a mut Option<T>>) -> Self {
        Self { value: Some(value), destination }
    }

    pub(super) fn get(&self) -> &T {
        match &self.value {
            Some(value) => value,
            None => std::process::abort(),
        }
    }

    pub(super) fn get_mut(&mut self) -> &mut T {
        match &mut self.value {
            Some(value) => value,
            None => std::process::abort(),
        }
    }

    pub(super) fn take(mut self) -> T {
        match self.value.take() {
            Some(value) => value,
            None => std::process::abort(),
        }
    }
}

impl<T> Drop for CreationSlotV1<'_, T> {
    fn drop(&mut self) {
        if let Some(destination) = self.destination.as_deref_mut() {
            if let Some(value) = self.value.take() {
                if destination.is_some() {
                    std::process::abort();
                }
                *destination = Some(value);
            }
        }
    }
}

impl<T: AsFd> AsFd for CreationSlotV1<'_, T> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.get().as_fd()
    }
}

impl<T: AsFd> AsRawFd for CreationSlotV1<'_, T> {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.as_fd().as_raw_fd()
    }
}

// OpenOptions consumes this argument at the same boundary as the old String.
impl AsRef<Path> for CreationSlotV1<'_, String> {
    fn as_ref(&self) -> &Path {
        Path::new(self.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::FileExt as _;
    use rustix::fs::{MemfdFlags, OFlags, fcntl_getfl, fstat, memfd_create};

    #[test]
    fn real_memfd_refusal_keeps_its_first_error_on_reentry() {
        let mut original = SealedReadOnlyCredentialCreateOriginalsV1::new();
        let name = "x".repeat(300);

        assert!(original.create_once(&name, b"authority", 64).is_err());
        let first = original.error.as_ref().unwrap() as *const ImmutableFileError;
        assert!(matches!(original.error.as_ref(), Some(ImmutableFileError::Linux(
            crate::Error::Syscall { operation: "memfd_create", .. }
        ))));
        assert!(original.writer.is_none());
        assert!(original.completed().is_none());

        assert!(original.create_once("would-have-created", b"other", 64).is_err());
        assert!(std::ptr::eq(first, original.error.as_ref().unwrap()));
        assert!(original.writer.is_none());
        assert!(original.take_completed_once().is_none());
    }

    #[test]
    fn refused_label_keeps_the_actual_written_memfd() {
        let mut original = SealedReadOnlyCredentialCreateOriginalsV1::new();

        // Linux rejects xattr values above its 64-KiB ceiling. Earlier LSM or
        // unsupported-xattr refusal is equally valid; either path occurs after
        // this actual memfd was written, without depending on SELinux enabled.
        let context = "x".repeat(64 * 1024 + 1);
        assert!(original.create_labelled_once(
            "retained-label-test", b"authority", 64, Some(&context),
        ).is_err());
        let writer = original.writer.as_ref().unwrap();
        let first_fd = writer.as_raw_fd();
        let first_error = original.error.as_ref().unwrap() as *const ImmutableFileError;
        let mut bytes = [0; 9];
        writer.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"authority");
        assert!(original.reader.is_none());
        assert!(original.completed().is_none());

        assert!(original.create_once("cannot-heal-label", b"authority", 64).is_err());
        assert_eq!(original.writer.as_ref().unwrap().as_raw_fd(), first_fd);
        assert!(std::ptr::eq(first_error, original.error.as_ref().unwrap()));
    }

    #[test]
    fn exact_read_eof_keeps_real_duplicate_and_partial_bytes() {
        let descriptor = memfd_create("retained-readback-test", MemfdFlags::CLOEXEC).unwrap();
        let mut writer = File::from(descriptor);
        writer.write_all(b"abc").unwrap();
        let mut retained_duplicate = None;
        let mut observed = [0; 4];

        let result = super::super::read_exact_at_engine(
            writer.as_fd(), &mut observed, Some(&mut retained_duplicate),
        );

        assert!(matches!(result, Err(ImmutableFileError::SizeMismatch)));
        assert_eq!(&observed, b"abc\0");
        let duplicate = retained_duplicate.as_ref().unwrap();
        assert_eq!(fstat(duplicate).unwrap().st_ino, fstat(&writer).unwrap().st_ino);
        let mut ordinary = [0; 4];
        assert!(matches!(super::super::read_exact_at(writer.as_fd(), &mut ordinary),
            Err(ImmutableFileError::SizeMismatch)));
        assert_eq!(ordinary, observed);
    }

    #[test]
    fn successful_creation_lends_and_transfers_the_same_credential_once() {
        let mut original = SealedReadOnlyCredentialCreateOriginalsV1::new();

        original.create_once("retained-positive-test", b"authority", 64).unwrap();
        let credential = original.completed().unwrap();
        let fd = credential.as_fd().as_raw_fd();
        assert_eq!(credential.len(), 9);
        assert_eq!(fcntl_getfl(credential.as_fd()).unwrap() & OFlags::ACCMODE, OFlags::RDONLY);
        assert_eq!(original.observed.as_ref().unwrap().as_slice(), b"authority");
        assert!(original.writer.is_some() && original.duplicate.is_some());
        let credential = original.take_completed_once().unwrap();
        assert_eq!(credential.as_fd().as_raw_fd(), fd);
        assert!(original.completed().is_none());
        assert!(original.take_completed_once().is_none());
        drop(original);
        credential.revalidate().unwrap();
    }

    #[test]
    fn positive_reentry_refuses_without_replacing_native_custody() {
        let mut original = SealedReadOnlyCredentialCreateOriginalsV1::new();
        original.create_once("retained-positive-reentry", b"authority", 64).unwrap();
        let fd = original.completed().unwrap().as_fd().as_raw_fd();

        assert!(original.create_once("not-a-new-attempt", b"replacement", 64).is_err());

        assert_eq!(original.credential.as_ref().unwrap().as_fd().as_raw_fd(), fd);
        assert!(original.failure().is_some());
        assert!(original.completed().is_none());
        assert!(original.take_completed_once().is_none());
    }

    #[test]
    fn footprint_preserves_four_fd_peak_and_refuses_overflow() {
        let shape = SealedReadOnlyCredentialCreateOriginalsV1::receiving_footprint_v1(
            "aos-agent-execution-spec-v1".len(), 15 * 1024 * 1024,
        ).unwrap();
        assert_eq!(shape.open_files, 4);
        assert_eq!(shape.metadata_entries, 0);
        assert!(shape.memory_bytes >= 2 * 15 * 1024 * 1024);
        assert!(SealedReadOnlyCredentialCreateOriginalsV1::receiving_footprint_v1(32, usize::MAX).is_none());
    }
}
