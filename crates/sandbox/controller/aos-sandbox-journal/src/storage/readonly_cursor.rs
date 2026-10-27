//! Shares captured-cut reads and native identity DATA without exporting a file.
//!
//! The read-only wrapper delegates to the existing positional reader on the same
//! open-file description. A separate passive identity sample preserves the native
//! replay metadata frontier. Neither the cursor nor this DATA interface proves a
//! protected role, held lock, current name, semantic history, or paid original.

use std::borrow::Borrow;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use super::CapturedFileCursor;
use crate::protected_storage::FileIdentity;

/// Samples file identity DATA without lending a file or descriptor capability.
///
/// Implementing this interface proves no physical or semantic admission. Actual
/// selected role owners choose the concrete cursor while retaining their genuine
/// original, payment, protected-name and before/after obligations independently.
/// Existing ordinary File/custom-reader callers use the blanket Borrow adapter.
pub trait JournalReadIdentityDataV1 {
    /// Samples the same seven native identity fields at the caller's frontier.
    ///
    /// # Errors
    /// Returns the original metadata IO error without role classification.
    fn sample_file_identity_v1(&self) -> io::Result<FileIdentity>;
}

impl<T: Borrow<File> + ?Sized> JournalReadIdentityDataV1 for T {
    fn sample_file_identity_v1(&self) -> io::Result<FileIdentity> {
        FileIdentity::of::<io::Error>(self.borrow())
    }
}

/// Reads a supplied captured cut without exposing File, FD, or write access.
///
/// Construction borrows an already held File and caller-supplied length DATA; it
/// opens and duplicates nothing. Reads/seeks use the SAME CapturedFileCursor
/// engine and never advance the original File's shared cursor. Identity sampling
/// observes actual current file metadata, not the supplied logical cut length.
/// No output admits a role or proves currentness, completeness, or authority.
///
/// The wrapper deliberately implements no Borrow<File> escape:
///
/// ```compile_fail
/// use std::borrow::Borrow;
/// use std::fs::File;
/// use aos_sandbox_journal::storage::ReadOnlyCapturedFileCursorV1;
/// fn escape<'a>(cursor: &'a ReadOnlyCapturedFileCursorV1<'_>) -> &'a File {
///     Borrow::<File>::borrow(cursor)
/// }
/// ```
///
/// It exposes no descriptor through AsFd:
///
/// ```compile_fail
/// use std::os::fd::{AsFd, BorrowedFd};
/// use aos_sandbox_journal::storage::ReadOnlyCapturedFileCursorV1;
/// fn escape<'a>(cursor: &'a ReadOnlyCapturedFileCursorV1<'_>) -> BorrowedFd<'a> {
///     cursor.as_fd()
/// }
/// ```
///
/// It offers no Write implementation:
///
/// ```compile_fail
/// use std::io::Write;
/// use aos_sandbox_journal::storage::ReadOnlyCapturedFileCursorV1;
/// fn change(cursor: &mut ReadOnlyCapturedFileCursorV1<'_>) {
///     cursor.write_all(b"replacement").unwrap();
/// }
/// ```
pub struct ReadOnlyCapturedFileCursorV1<'file> {
    cursor: CapturedFileCursor<'file>,
}

impl<'file> ReadOnlyCapturedFileCursorV1<'file> {
    /// Borrows the same File at logical offset zero within the supplied cut.
    #[must_use]
    pub fn new(file: &'file File, length: u64) -> Self {
        Self {
            cursor: CapturedFileCursor::new(file, length),
        }
    }
}

impl Read for ReadOnlyCapturedFileCursorV1<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.cursor.read(bytes)
    }
}

impl Seek for ReadOnlyCapturedFileCursorV1<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.cursor.seek(position)
    }
}

impl JournalReadIdentityDataV1 for ReadOnlyCapturedFileCursorV1<'_> {
    fn sample_file_identity_v1(&self) -> io::Result<FileIdentity> {
        // Only this internal mechanical projection can reach the borrowed File.
        // The wrapper itself deliberately has no Borrow<File>/AsFd/Write impl.
        FileIdentity::of::<io::Error>(self.cursor.borrow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use super::super::tests::TemporaryFile;

    #[test]
    fn readonly_cut_shares_original_file_without_advancing_its_cursor() {
        let mut temporary = TemporaryFile::new(b"abcdef");
        let file = temporary.take_file();
        (&file).seek(SeekFrom::Start(2)).unwrap();
        let original_identity = FileIdentity::of::<io::Error>(&file).unwrap();
        let mut reader = ReadOnlyCapturedFileCursorV1::new(&file, 4);

        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        let sampled = reader.sample_file_identity_v1().unwrap();

        assert_eq!(bytes, b"abcd");
        assert_eq!((&file).stream_position().unwrap(), 2);
        assert!(sampled == original_identity);
        assert_eq!(sampled.byte_len(), 6);
        assert_eq!(reader.seek(SeekFrom::End(-1)).unwrap(), 3);
        let mut tail = [0; 4];
        assert_eq!(reader.read(&mut tail).unwrap(), 1);
        assert_eq!(tail[0], b'd');
        assert!(reader.seek(SeekFrom::Start(5)).is_err());
        assert_eq!((&file).stream_position().unwrap(), 2);
    }

    #[test]
    fn cut_and_legacy_cursor_share_seek_and_read_negative_frontiers() {
        let mut temporary = TemporaryFile::new(b"0123456789");
        let file = temporary.take_file();
        let mut legacy = CapturedFileCursor::new(&file, 5);
        let mut readonly = ReadOnlyCapturedFileCursorV1::new(&file, 5);

        for position in [SeekFrom::Start(2), SeekFrom::Current(-3),
            SeekFrom::End(1), SeekFrom::End(-1)] {
            let a = legacy.seek(position);
            let b = readonly.seek(position);
            match (a, b) {
                (Ok(a), Ok(b)) => assert_eq!(a, b),
                (Err(a), Err(b)) => assert_eq!(a.kind(), b.kind()),
                _ => panic!("shared captured-cut seek frontier changed"),
            }
        }
        let mut a = [0; 8];
        let mut b = [0; 8];
        assert_eq!(legacy.read(&mut a).unwrap(), readonly.read(&mut b).unwrap());
        assert_eq!(a, b);
    }

    #[test]
    fn ordinary_custom_reader_identity_uses_one_original_borrow() {
        struct OrdinaryReader<'file> {
            file: &'file File,
            borrows: Cell<usize>,
        }

        impl Borrow<File> for OrdinaryReader<'_> {
            fn borrow(&self) -> &File {
                self.borrows.set(self.borrows.get() + 1);
                self.file
            }
        }

        let mut temporary = TemporaryFile::new(b"identity");
        let file = temporary.take_file();
        let reader = OrdinaryReader { file: &file, borrows: Cell::new(0) };

        let observed = reader.sample_file_identity_v1().unwrap();

        assert_eq!(reader.borrows.get(), 1);
        assert!(observed == FileIdentity::of::<io::Error>(&file).unwrap());
    }
}
