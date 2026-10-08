//! Resident native file custody, append durability, and uncertainty bookkeeping.
//!
//! The storage owner adopts already-owned files without opening, locking, or
//! admitting them. Domain owners retain protected-name checks, semantic replay,
//! final append crossings, index publication, and commit receipts. Native file
//! borrows remain ordinary capabilities, not evidence of those domain checks.
//! The bounded physical reader uses independent offsets on the same file.

use std::fs::File;
use std::io;

#[cfg(unix)]
use std::borrow::Borrow;
#[cfg(unix)]
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::FileExt as _;

use crate::framing::{FrameError, append_and_sync};

/// Retains supplied native files and permanent append uncertainty.
///
/// This owner does not establish that either file has been locked, protected,
/// replayed, or admitted by a domain. Its native operations publish no semantic
/// state or receipt. The data file is dropped before the retained lock file.
pub struct NativeJournalStorage {
    file: File,
    lock: File,
    poisoned: bool,
}

impl NativeJournalStorage {
    /// Adopts two already-owned files without opening or validating them.
    ///
    /// Neither descriptor is duplicated. A domain wrapper must complete its
    /// own fallible admission and replay before transferring its originals.
    pub fn from_owned_files(file: File, lock: File) -> Self {
        Self {
            file,
            lock,
            poisoned: false,
        }
    }

    /// Borrows the original data file as an ordinary native capability.
    ///
    /// A shared `File` reference is not a read-only capability or a currentness
    /// observation. The domain wrapper controls access to this storage owner.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Mutably borrows the original data file without releasing its lock file.
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Borrows the retained lock file without proving a held lock or admission.
    pub fn lock_file(&self) -> &File {
        &self.lock
    }

    /// Replaces only the data file, dropping its predecessor at assignment.
    ///
    /// The retained lock file and permanent uncertainty remain unchanged.
    /// This operation does not replay or admit the replacement file.
    pub fn replace_file(&mut self, file: File) {
        self.file = file;
    }

    /// Reports whether an ambiguous mutation has permanently poisoned this owner.
    ///
    /// A negative answer establishes neither protected admission nor currentness.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Permanently records an ambiguous mutation without releasing either file.
    ///
    /// Domain wrappers also use this denial state when their existing postchecks
    /// fail after native mutation. There is no operation that clears it.
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Computes the bounded resulting length from actual native file metadata.
    ///
    /// This advisory calculation neither reserves bytes nor validates frames or
    /// domain transitions. It does not mutate the uncertainty state.
    ///
    /// # Errors
    ///
    /// Returns the original metadata error or [`FrameError::JournalTooLarge`]
    /// for overflow or a resulting length above `maximum`. Metadata failure
    /// precedes classification of an overflowing frame-byte sum.
    pub fn expected_append_length(
        &self,
        frames: &[Vec<u8>],
        maximum: u64,
    ) -> Result<u64, FrameError> {
        let additional_bytes = frames
            .iter()
            .try_fold(0_u64, |total, frame| total.checked_add(frame.len() as u64));
        let expected_length = self
            .file
            .metadata()?
            .len()
            .checked_add(additional_bytes.ok_or(FrameError::JournalTooLarge)?)
            .ok_or(FrameError::JournalTooLarge)?;
        if expected_length > maximum {
            return Err(FrameError::JournalTooLarge);
        }
        Ok(expected_length)
    }

    /// Appends, flushes, and syncs frames before comparing the resulting length.
    ///
    /// The caller retains domain admission, health checks, and final crossings;
    /// this method adds no observation before the native append. Supplied bytes
    /// and the expected length are DATA, not semantic permission or a receipt.
    ///
    /// # Errors
    ///
    /// Returns an unchanged native write, flush, sync, or metadata error, or an
    /// I/O error if the final length differs from `expected_length`. Either
    /// failure permanently poisons this owner before returning its cause.
    pub fn append_exact(
        &mut self,
        frames: &[Vec<u8>],
        expected_length: u64,
    ) -> Result<u64, FrameError> {
        let durable_bytes = match append_and_sync(&mut self.file, frames) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if durable_bytes != expected_length {
            self.poisoned = true;
            return Err(FrameError::Io(io::Error::other(
                "journal length changed outside the exclusive writer",
            )));
        }
        Ok(durable_bytes)
    }
}

/// Reads a captured-length cut using independent offsets on the original file.
///
/// The captured length is caller-supplied DATA. This reader establishes neither
/// completeness nor currentness and never advances the file's shared cursor.
#[cfg(unix)]
pub struct CapturedFileCursor<'file> {
    file: &'file File,
    cursor: u64,
    length: u64,
}

#[cfg(unix)]
impl<'file> CapturedFileCursor<'file> {
    /// Borrows the original file with a logical cursor starting at zero.
    pub fn new(file: &'file File, length: u64) -> Self {
        Self {
            file,
            cursor: 0,
            length,
        }
    }
}

#[cfg(unix)]
impl Read for CapturedFileCursor<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let remaining = self.length.saturating_sub(self.cursor);
        let bounded = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let read = self.file.read_at(&mut bytes[..bounded], self.cursor)?;
        let advance = u64::try_from(read).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "audit read length overflow")
        })?;
        self.cursor = self
            .cursor
            .checked_add(advance)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "audit cursor overflow"))?;
        Ok(read)
    }
}

#[cfg(unix)]
impl Borrow<File> for CapturedFileCursor<'_> {
    fn borrow(&self) -> &File {
        self.file
    }
}

#[cfg(unix)]
impl Seek for CapturedFileCursor<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.length) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.cursor) + i128::from(offset),
        };
        if next < 0 || next > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit seek outside captured cut",
            ));
        }
        self.cursor = u64::try_from(next)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "audit cursor overflow"))?;
        Ok(self.cursor)
    }
}

#[cfg(test)]
pub(crate) mod tests;
