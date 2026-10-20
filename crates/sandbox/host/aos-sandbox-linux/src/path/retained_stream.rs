//! Retains strict virtual-file reads without trusting a reported file size.
//!
//! Cgroup and procfs files can report zero bytes while returning content. This
//! destination uses the same bounded stream reader as `ResolvedFile`, keeping
//! the actual open descriptor, partial bytes and first error on refusal.

use super::*;

/// Owns one strict regular-file opening and its bounded stream read.
#[derive(Debug, Default)]
pub struct BeneathStreamReadOriginalV2 {
    path: BeneathRegularFileOpenOriginalV2,
    file: Option<std::fs::File>,
    bytes: Vec<u8>,
    returned: Option<Result<()>>,
    entered: bool,
    closed: Option<Error>,
}

impl BeneathStreamReadOriginalV2 {
    /// Creates empty destinations without allocation or native work.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens and reads once through the existing strict bounded stream engine.
    ///
    /// # Errors
    /// Keeps the exact open, type, read or extent error and every reached
    /// descriptor and byte prefix. Reentry cannot replace or repeat a read.
    pub fn capture_once(&mut self, root: &BeneathRoot, path: &Path, maximum: usize) -> Result<()> {
        self.capture_with_disposition(root, path, maximum, StreamDisposition::Retained)
    }

    /// Reads through the same kernel with the ordinary consuming File lifetime.
    ///
    /// The opened reader closes at the read statement, before the extent check,
    /// exactly as `ResolvedFile::read_bounded`. Selected native owners use
    /// `capture_once` to keep that same reader through their independent posts.
    ///
    /// # Errors
    /// Returns the same bounded-read marker and retains the original error.
    pub fn capture_consuming_once_v2(
        &mut self,
        root: &BeneathRoot,
        path: &Path,
        maximum: usize,
    ) -> Result<()> {
        self.capture_with_disposition(root, path, maximum, StreamDisposition::Ordinary)
    }

    fn capture_with_disposition(
        &mut self,
        root: &BeneathRoot,
        path: &Path,
        maximum: usize,
        disposition: StreamDisposition,
    ) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.returned = Some((|| {
            self.path.open_regular_once_v1(root, path)?;
            let regular = self.path.take_regular_completed().ok_or_else(closed)?;
            self.file = Some(std::fs::File::from(regular.into_owned_fd()));
            match disposition {
                StreamDisposition::Retained => read_bounded_recipe(
                    self.file.as_mut().ok_or_else(closed)?, maximum, &mut self.bytes,
                ),
                StreamDisposition::Ordinary => read_bounded_recipe(
                    self.file.take().ok_or_else(closed)?, maximum, &mut self.bytes,
                ),
            }
        })());
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    /// Borrows only the same complete bounded bytes after successful reading.
    #[must_use]
    pub fn completed_bytes(&self) -> Option<&[u8]> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        Some(&self.bytes)
    }

    /// Borrows the earliest original error before any subsequent entry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.returned
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .or(self.closed.as_ref())
    }

    /// Bounds the actual reader storage, two path copies and one opened name.
    #[must_use]
    pub fn receiving_obligations_v2(
        path_bytes: usize,
        maximum: usize,
    ) -> Option<(usize, usize, usize)> {
        if path_bytes > MAX_RELATIVE_PATH_BYTES || maximum > MAXIMUM_BOUNDED_READ_BYTES {
            return None;
        }
        Some((
            std::mem::size_of::<Self>()
                .checked_mul(2)?
                .checked_add(path_bytes.checked_add(1)?.checked_mul(2)?)?
                .checked_add(maximum.checked_add(1)?)?,
            1,
            1,
        ))
    }
}

#[derive(Clone, Copy)]
enum StreamDisposition {
    Ordinary,
    Retained,
}

fn closed() -> Error {
    Error::invalid("retained bounded stream", "original remains closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extent_failure_keeps_actual_reader_partial_bytes_and_first_error() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("value"), b"12345").unwrap();
        let root =
            BeneathRoot::from_owned(std::fs::File::open(directory.path()).unwrap().into()).unwrap();
        let mut original = BeneathStreamReadOriginalV2::new();

        assert!(original.capture_once(&root, Path::new("value"), 3).is_err());
        let first = original.failure().unwrap() as *const Error;
        assert_eq!(&original.bytes, b"1234");
        assert!(rustix::fs::fstat(original.file.as_ref().unwrap()).is_ok());

        assert!(original.capture_once(&root, Path::new("value"), 8).is_err());
        assert_eq!(original.failure().unwrap() as *const Error, first);
        assert_eq!(&original.bytes, b"1234");
        assert!(original.completed_bytes().is_none());
        assert!(rustix::fs::fstat(original.file.as_ref().unwrap()).is_ok());
    }

    #[test]
    fn ordinary_extent_refusal_consumes_reader_while_selected_refusal_keeps_it() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("value"), b"12345").unwrap();
        let root = BeneathRoot::from_owned(std::fs::File::open(directory.path()).unwrap().into()).unwrap();
        let mut ordinary = BeneathStreamReadOriginalV2::new();
        let mut retained = BeneathStreamReadOriginalV2::new();

        assert!(ordinary.capture_consuming_once_v2(&root, Path::new("value"), 3).is_err());
        assert!(retained.capture_once(&root, Path::new("value"), 3).is_err());
        assert!(ordinary.file.is_none());
        assert!(rustix::fs::fstat(retained.file.as_ref().unwrap()).is_ok());
        assert_eq!(ordinary.bytes, retained.bytes);
        assert_eq!(ordinary.failure().unwrap().to_string(), retained.failure().unwrap().to_string());
    }

    #[test]
    fn zero_sized_procfs_stream_is_read_through_same_reader() {
        let root =
            BeneathRoot::from_owned(std::fs::File::open("/proc/self").unwrap().into()).unwrap();
        let mut original = BeneathStreamReadOriginalV2::new();

        original
            .capture_once(&root, Path::new("status"), 256 * 1024)
            .unwrap();

        assert!(original.completed_bytes().unwrap().starts_with(b"Name:"));
        assert_eq!(
            rustix::fs::fstat(original.file.as_ref().unwrap())
                .unwrap()
                .st_size,
            0
        );
    }
}
