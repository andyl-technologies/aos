//! Memory-mapped immutable store primitives.
//!
//! The persistent `values/` and `files/` stores in RFC-0007 are append-only
//! content-addressed packfiles. This module provides the low-level read-only
//! mapping primitive that those packfiles need before higher-level code can
//! expose zero-copy validated payload views.

use std::fs;
use std::io;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::ptr::NonNull;

use thiserror::Error;

/// A read-only memory mapping of an immutable file.
///
/// The mapping exposes borrowed bytes without copying. Constructing it is
/// unsafe because Rust cannot prove that no process or file handle mutates the
/// mapped file while shared references produced by [`Self::as_bytes`] or
/// [`Self::get`] are alive.
#[derive(Debug)]
pub struct ReadOnlyMmap {
    ptr: NonNull<u8>,
    len: usize,
}

impl ReadOnlyMmap {
    /// Maps `file` read-only.
    ///
    /// # Errors
    ///
    /// Returns [`ReadOnlyMmapError`] if file metadata cannot be read, the file
    /// is empty, its length cannot fit in the local address space, or the
    /// platform mapping call fails.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that the mapped file's bytes are not mutated
    /// for the lifetime of the returned mapping. This includes writes through
    /// other file descriptors and other processes. Appending, truncating, or
    /// replacing the underlying file while borrowed slices from this mapping
    /// exist violates the contract.
    pub unsafe fn map_file(file: &fs::File) -> Result<Self, ReadOnlyMmapError> {
        let len = file
            .metadata()
            .map_err(|source| ReadOnlyMmapError::Metadata { source })?
            .len();
        let len = usize::try_from(len)
            .map_err(|_| ReadOnlyMmapError::FileTooLarge { len: len as u128 })?;
        if len == 0 {
            return Err(ReadOnlyMmapError::EmptyFile);
        }
        let raw_ptr = unsafe {
            // SAFETY: `file.as_raw_fd()` is a live file descriptor for the
            // duration of this call, `len` is non-zero and was derived from the
            // file metadata, and the caller upholds the file immutability
            // contract documented on this unsafe function.
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if raw_ptr == libc::MAP_FAILED {
            return Err(ReadOnlyMmapError::Map {
                source: io::Error::last_os_error(),
            });
        }
        let Some(ptr) = NonNull::new(raw_ptr.cast::<u8>()) else {
            let result = unsafe {
                // SAFETY: The platform reported a successful mapping for
                // `raw_ptr`/`len`, so this releases that mapping before
                // returning the conservative null-pointer error.
                libc::munmap(raw_ptr, len)
            };
            debug_assert_eq!(result, 0);
            return Err(ReadOnlyMmapError::NullMap);
        };
        Ok(Self { ptr, len })
    }

    /// Returns the number of mapped bytes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the mapping is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the whole mapped file as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            // SAFETY: `ptr` and `len` come from a successful read-only mmap and
            // remain valid until `Drop` unmaps them. The constructor's safety
            // contract guarantees the mapped file is immutable while these
            // shared bytes are observed.
            std::slice::from_raw_parts(self.ptr.as_ptr(), self.len)
        }
    }

    /// Returns a mapped byte range.
    pub fn get(&self, range: Range<usize>) -> Option<&[u8]> {
        if range.start > range.end || range.end > self.len {
            return None;
        }
        Some(&self.as_bytes()[range])
    }
}

impl Drop for ReadOnlyMmap {
    fn drop(&mut self) {
        let result = unsafe {
            // SAFETY: `ptr` and `len` identify a mapping returned by `mmap`
            // during construction and this is the unique `Drop` for it.
            libc::munmap(self.ptr.as_ptr().cast(), self.len)
        };
        debug_assert_eq!(result, 0);
    }
}

/// Read-only memory mapping failed.
#[derive(Debug, Error)]
pub enum ReadOnlyMmapError {
    /// File metadata could not be read before mapping.
    #[error("failed to inspect file before read-only mmap")]
    Metadata {
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Empty files cannot be memory-mapped.
    #[error("cannot memory-map an empty file")]
    EmptyFile,
    /// The file length cannot fit in the local address space.
    #[error("file length {len} is too large for read-only mmap")]
    FileTooLarge {
        /// The oversized file length.
        len: u128,
    },
    /// The platform returned a null mapping pointer.
    #[error("read-only mmap returned a null pointer")]
    NullMap,
    /// The platform mapping call failed.
    #[error("read-only mmap failed")]
    Map {
        /// The underlying OS error.
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ratchet-cache-{name}-{}-{nonce}.tmp",
            std::process::id()
        ))
    }

    #[test]
    fn read_only_mmap_exposes_file_bytes() {
        let path = temp_path("bytes");
        {
            let mut file = fs::File::create(&path).expect("temp file creates");
            file.write_all(b"pack-headerpayload")
                .expect("temp file writes");
            file.sync_all().expect("temp file syncs");
        }
        let file = fs::File::open(&path).expect("temp file opens read-only");
        let mapping = unsafe {
            // SAFETY: The test writes the file before mapping it and performs
            // no further mutation until after the mapping is dropped.
            ReadOnlyMmap::map_file(&file)
        }
        .expect("file maps");

        assert_eq!(mapping.len(), b"pack-headerpayload".len());
        assert_eq!(mapping.as_bytes(), b"pack-headerpayload");
        assert_eq!(mapping.get(11..18), Some(b"payload".as_slice()));
        assert_eq!(mapping.get(18..19), None);

        drop(mapping);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn read_only_mmap_rejects_empty_files() {
        let path = temp_path("empty");
        fs::File::create(&path).expect("empty temp file creates");
        let file = fs::File::open(&path).expect("empty temp file opens");

        let error = unsafe {
            // SAFETY: The test does not mutate the empty file while attempting
            // to map it; the constructor rejects it before mapping.
            ReadOnlyMmap::map_file(&file)
        }
        .expect_err("empty files cannot be mapped");

        assert!(matches!(error, ReadOnlyMmapError::EmptyFile));
        let _ = fs::remove_file(path);
    }
}
