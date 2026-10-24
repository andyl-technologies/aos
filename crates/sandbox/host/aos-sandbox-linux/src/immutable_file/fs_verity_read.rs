//! Retains the existing strict fs-verity open and every reached native owner.
//!
//! This generic mechanical reader authenticates no object descriptor or AOS
//! role. Its caller pays the actual one-file peak and retains it through its
//! own semantic/native posts. The ordinary API invokes the same proof body.

use super::*;
use crate::path::BeneathRegularFileOpenOriginalV2;

#[derive(Default)]
pub(super) struct MeasurementFieldsV2 {
    filesystem_type: Option<libc::c_long>,
    measurement: Option<uapi::VerityMeasurement>,
}

#[derive(Default)]
pub(super) struct FsVerityFieldsV2 {
    raw_before: Option<libc::stat>,
    raw_after: Option<libc::stat>,
    before: Option<ObservedFile>,
    after: Option<ObservedFile>,
    measurements: [MeasurementFieldsV2; 2],
}

/// Retains one actual strict fs-verity acquisition and its original failure.
///
/// Construction performs no IO and grants no path or object authority. A
/// failed native/type/proof check keeps any already opened file resident.
/// Reentry remains refused without replacing the original concrete cause.
#[must_use]
pub struct FsVerityReadOriginalV2 {
    path: BeneathRegularFileOpenOriginalV2,
    fields: FsVerityFieldsV2,
    file: Option<std::fs::File>,
    bytes: Vec<u8>,
    read: Option<Result<(), aos_linux_descriptors::Error>>,
    bytes_taken: bool,
    result: Option<Result<(), ImmutableFileError>>,
    reentry: Option<ImmutableFileError>,
}

impl FsVerityReadOriginalV2 {
    /// Constructs an inert native destination without opening anything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            path: BeneathRegularFileOpenOriginalV2::new(),
            fields: FsVerityFieldsV2::default(),
            file: None,
            bytes: Vec::new(),
            read: None,
            bytes_taken: false,
            result: None,
            reentry: None,
        }
    }

    /// Opens and verifies one file through the sole existing fs-verity recipe.
    ///
    /// # Errors
    /// Returns a closed comparison marker after retaining the original strict
    /// path, size, filesystem, metadata or measurement failure. Callers inspect
    /// `failure` while keeping this original and their input owners resident.
    pub fn open_once_v2(
        &mut self,
        root: &BeneathRoot,
        relative: &Path,
        expected_verity: FsVerityDigest,
        expected_bytes: u64,
    ) -> Result<(), FsVerityReadClosedV2> {
        if self.result.is_some() || self.reentry.is_some() {
            self.reentry.get_or_insert(ImmutableFileError::AdmissionRace);
            return Err(FsVerityReadClosedV2);
        }
        self.result = Some((|| {
            self.path.open_regular_once_v1(root, relative)?;
            let file = self.path.regular_v1().ok_or(ImmutableFileError::AdmissionRace)?;
            require_verified_file_v2(file.as_fd(), expected_verity, expected_bytes, Some(&mut self.fields))
        })());
        if matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(FsVerityReadClosedV2)
        }
    }

    /// Borrows the same verified descriptor only after its complete native proof.
    #[must_use]
    pub fn file_v2(&self) -> Option<BorrowedFd<'_>> {
        if !matches!(self.result, Some(Ok(()))) || self.reentry.is_some() {
            return None;
        }
        self.file.as_ref().map(AsFd::as_fd)
            .or_else(|| self.path.regular_v1().map(|file| file.as_fd()))
    }

    /// Reads the same verified file after separate exact byte admission.
    ///
    /// This generic native reader accepts no new file or descriptor. The caller
    /// must establish its format's real ceiling and pay the full `maximum + 1`
    /// frontier before entry. All partial bytes and the same FD remain here.
    ///
    /// # Errors
    /// Retains absent native proof, reentry, extent overflow or actual read
    /// failure. The original fs-verity refusal remains ahead of later errors.
    pub fn read_once_v2(&mut self, maximum: usize) -> Result<(), FsVerityReadClosedV2> {
        if self.read.is_some() || self.file_v2().is_none() {
            self.reentry.get_or_insert(ImmutableFileError::AdmissionRace);
            return Err(FsVerityReadClosedV2);
        }
        let file = match self.path.take_regular_completed() {
            Some(file) => file,
            None => {
                self.reentry.get_or_insert(ImmutableFileError::AdmissionRace);
                return Err(FsVerityReadClosedV2);
            }
        };
        self.file = Some(std::fs::File::from(file.into_owned_fd()));
        self.read = Some(match self.file.as_mut() {
            Some(file) => crate::path::read_admitted_bounded_recipe_v2(file, maximum, &mut self.bytes),
            None => std::process::abort(),
        });
        if matches!(self.read, Some(Ok(()))) { Ok(()) } else { Err(FsVerityReadClosedV2) }
    }

    /// Borrows complete bytes only after the same verified FD's bounded read.
    #[must_use]
    pub fn bytes_v2(&self) -> Option<&[u8]> {
        if self.reentry.is_some() || self.bytes_taken || !matches!(self.read, Some(Ok(()))) { return None; }
        Some(&self.bytes)
    }

    /// Moves only the same complete successful bytes to its enclosing owner.
    ///
    /// The native file and its proof remain here until that owner completes its
    /// independent posts. This one-shot DATA transfer creates no read authority.
    #[must_use]
    pub fn take_completed_bytes_v2(&mut self) -> Option<Vec<u8>> {
        self.bytes_v2()?;
        self.bytes_taken = true;
        Some(std::mem::take(&mut self.bytes))
    }

    /// Borrows the earliest actual native error before a later reentry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.result.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.read.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl Default for FsVerityReadOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Marks a retained fs-verity failure without replacing its actual error owner.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the retained fs-verity file open is closed")]
pub struct FsVerityReadClosedV2;

pub(super) fn require_verified_file_v2(
    file: BorrowedFd<'_>,
    expected_verity: FsVerityDigest,
    expected_bytes: u64,
    mut retained: Option<&mut FsVerityFieldsV2>,
) -> Result<(), ImmutableFileError> {
    let before = inspect_captured(file, retained.as_deref_mut().map(|fields| &mut fields.raw_before))?;
    if let Some(fields) = retained.as_deref_mut() { fields.before = Some(before); }
    if before.file_type != libc::S_IFREG {
        return Err(ImmutableFileError::NotRegular);
    }
    if before.bytes != expected_bytes {
        return Err(ImmutableFileError::SizeMismatch);
    }
    if !measurement_matches_captured_v2(file, expected_verity, retained.as_deref_mut().map(|fields| &mut fields.measurements[0]))? {
        return Err(ImmutableFileError::VerityMeasurementMismatch);
    }
    let after = inspect_captured(file, retained.as_deref_mut().map(|fields| &mut fields.raw_after))?;
    if let Some(fields) = retained.as_deref_mut() { fields.after = Some(after); }
    if before != after || !measurement_matches_captured_v2(file, expected_verity, retained.as_deref_mut().map(|fields| &mut fields.measurements[1]))? {
        return Err(ImmutableFileError::AdmissionRace);
    }
    Ok(())
}

pub(super) fn measurement_matches_captured_v2(
    file: BorrowedFd<'_>,
    expected: FsVerityDigest,
    mut retained: Option<&mut MeasurementFieldsV2>,
) -> Result<bool, ImmutableFileError> {
    let filesystem_type = uapi::filesystem_type(file)?;
    if let Some(fields) = retained.as_deref_mut() {
        fields.filesystem_type = Some(filesystem_type);
    }
    if !is_kernel_verity_filesystem(filesystem_type) {
        return Err(ImmutableFileError::UnsupportedVerityFilesystem);
    }
    let measurement = uapi::measure_verity(file)?;
    let matches = expected.matches(measurement.algorithm, &measurement.digest[..measurement.length]);
    if let Some(fields) = retained {
        fields.measurement = Some(measurement);
    }
    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn size_refusal_retains_the_same_open_file_and_first_error() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("manifest"), b"canonical candidate").unwrap();
        let root = BeneathRoot::from_owned(File::open(directory.path()).unwrap().into()).unwrap();
        let expected = FsVerityDigest::Sha256([7; 32]);

        let ordinary = FsVerityMapping::open_verified_beneath(&root, Path::new("manifest"), expected, 1);
        let mut original = FsVerityReadOriginalV2::new();
        assert!(original.open_once_v2(&root, Path::new("manifest"), expected, 1).is_err());

        assert!(matches!(ordinary, Err(ImmutableFileError::SizeMismatch)));
        assert!(original.failure().is_some_and(|cause| matches!(cause.downcast_ref::<ImmutableFileError>(), Some(ImmutableFileError::SizeMismatch))));
        assert!(original.file_v2().is_none());
        let held = original.path.regular_v1().unwrap();
        let identity = uapi::fstat(held.as_fd()).unwrap();
        assert_eq!(identity.st_size, i64::try_from(b"canonical candidate".len()).unwrap());

        std::fs::remove_file(directory.path().join("manifest")).unwrap();
        assert!(uapi::fstat(held.as_fd()).is_ok());
        assert!(original.open_once_v2(&root, Path::new("manifest"), expected, 1).is_err());
        assert!(original.failure().is_some_and(|cause| matches!(cause.downcast_ref::<ImmutableFileError>(), Some(ImmutableFileError::SizeMismatch))));
        assert!(uapi::fstat(original.path.regular_v1().unwrap().as_fd()).is_ok());
    }
}
