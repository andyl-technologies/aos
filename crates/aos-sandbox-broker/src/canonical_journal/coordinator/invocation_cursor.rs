//! Keeps selected Root reads inside the same invocation's actual native fence.
//!
//! The cursor borrows the existing bounded positional engine. Ordinary/C DATA
//! construction retains its old unguarded mechanical behavior; a genuine Root
//! owner privately binds its permanent invocation. Each actual read or metadata
//! operation holds that same phase lock through IO and closes it on failure.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_journal::storage::{JournalReadIdentityDataV1, ReadOnlyCapturedFileCursorV1};

use crate::receiving::root_invocation::{RootInvocationOriginalV1, RootNativeInvocationGuardV1};

/// Lends the same bounded read engine without escaping a selected lifetime fence.
///
/// This has no public constructor, File/FD/Write projection or authority mint.
/// A retained cursor cannot continue Root native reads after Initial ends.
pub struct CanonicalCoordinatorReadCursorV1<'owner> {
    cursor: ReadEngine<'owner>,
    invocation: Option<&'owner RootInvocationOriginalV1>,
}

enum ReadEngine<'owner> {
    Captured(ReadOnlyCapturedFileCursorV1<'owner>),
    Original(&'owner File),
}

impl<'owner> CanonicalCoordinatorReadCursorV1<'owner> {
    pub(crate) fn from_parts(
        cursor: ReadOnlyCapturedFileCursorV1<'owner>,
        invocation: Option<&'owner RootInvocationOriginalV1>,
    ) -> Self {
        Self { cursor: ReadEngine::Captured(cursor), invocation }
    }

    pub(crate) fn from_original(
        file: &'owner File,
        invocation: Option<&'owner RootInvocationOriginalV1>,
    ) -> Self {
        Self { cursor: ReadEngine::Original(file), invocation }
    }
}

pub(super) fn enter_root_read(
    invocation: Option<&RootInvocationOriginalV1>,
) -> io::Result<Option<RootNativeInvocationGuardV1<'_>>> {
    invocation.map(|original| original.enter_native()
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "Root native invocation is closed")))
        .transpose()
}

impl Read for CanonicalCoordinatorReadCursorV1<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut guard = enter_root_read(self.invocation)?;
        let result = match &mut self.cursor {
            ReadEngine::Captured(cursor) => cursor.read(bytes),
            ReadEngine::Original(file) => file.read(bytes),
        };
        if result.is_err() {
            if let Some(guard) = guard.as_mut() {
                guard.refuse();
            }
        }
        result
    }
}

impl Seek for CanonicalCoordinatorReadCursorV1<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let mut guard = enter_root_read(self.invocation)?;
        let result = match &mut self.cursor {
            ReadEngine::Captured(cursor) => cursor.seek(position),
            ReadEngine::Original(file) => file.seek(position),
        };
        if result.is_err() {
            if let Some(guard) = guard.as_mut() {
                guard.refuse();
            }
        }
        result
    }
}

impl JournalReadIdentityDataV1 for CanonicalCoordinatorReadCursorV1<'_> {
    fn sample_file_identity_v1(&self) -> io::Result<FileIdentity> {
        let mut guard = enter_root_read(self.invocation)?;
        let result = match &self.cursor {
            ReadEngine::Captured(cursor) => cursor.sample_file_identity_v1(),
            ReadEngine::Original(file) => FileIdentity::of(file),
        };
        if result.is_err() {
            if let Some(guard) = guard.as_mut() {
                guard.refuse();
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn ordinary_adapter_preserves_the_same_bounded_cursor_results() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"ordinary").unwrap();
        let mut actual = CanonicalCoordinatorReadCursorV1::from_parts(
            ReadOnlyCapturedFileCursorV1::new(&file, 8), None,
        );
        let mut original = ReadOnlyCapturedFileCursorV1::new(&file, 8);
        let mut actual_bytes = [0; 5];
        let mut original_bytes = [0; 5];

        assert_eq!(actual.seek(SeekFrom::Start(3)).unwrap(),
            original.seek(SeekFrom::Start(3)).unwrap());
        assert_eq!(actual.read(&mut actual_bytes).unwrap(),
            original.read(&mut original_bytes).unwrap());
        assert_eq!(actual_bytes, original_bytes);
        assert_eq!(actual.read(&mut [0; 1]).unwrap(), original.read(&mut [0; 1]).unwrap());
        assert!(actual.sample_file_identity_v1().unwrap()
            == original.sample_file_identity_v1().unwrap());
    }
}
