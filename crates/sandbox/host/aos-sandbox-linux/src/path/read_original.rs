//! Retains the existing strict regular-file acquisition before inspection.
//!
//! These are native mechanical destinations, not path authority or proof of
//! admission. Every operation uses the original root/openat2/fstat recipe.

use super::*;

/// Owns the raw and validated descriptor of one strict regular-file opening.
///
/// Construction is inert. The caller must pay its compiled storage and native
/// descriptor peak before entry and retain it through all independent posts.
#[derive(Debug, Default)]
pub struct BeneathRegularFileOpenOriginalV2 {
    regular: PendingRegularFileV1,
    entered: bool,
}

impl BeneathRegularFileOpenOriginalV2 {
    /// Constructs an empty native destination without opening anything.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Bounds this exact regular-file owner and strict pathname recipe.
    ///
    /// This passive geometry grants no root, pathname or receiving authority.
    /// Returns `None` for an unsupported path width or arithmetic overflow.
    #[must_use]
    pub fn receiving_obligations_v2(path_bytes: usize) -> Option<(usize, usize, usize)> {
        if path_bytes > MAX_RELATIVE_PATH_BYTES { return None; }
        let paths = path_bytes.checked_add(1)?.checked_mul(2)?;
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(paths)?, 1, 1))
    }

    /// Opens one regular file and retains its raw pre-inspection FD.
    ///
    /// # Errors
    /// Rejects reentry or any original strict regular-file resolution failure.
    pub fn open_regular_once_v1(&mut self, root: &BeneathRoot, relative: &Path) -> Result<()> {
        self.begin()?;
        root.open_regular_retaining(relative, &mut self.regular)
    }

    /// Borrows the actual file only after strict regular-file inspection.
    #[must_use]
    pub fn regular_v1(&self) -> Option<&ResolvedFile> { self.regular.validated.as_ref() }

    pub(crate) fn take_regular_completed(&mut self) -> Option<ResolvedFile> {
        self.regular.validated.take()
    }

    fn begin(&mut self) -> Result<()> {
        if self.entered { return Err(Error::invalid("retained beneath-root read", "already attempted")); }
        self.entered = true;
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn regular_type_refusal_retains_the_original_opened_fifo() {
        let directory = tempfile::tempdir().unwrap();
        rustix::fs::mkfifoat(rustix::fs::CWD, directory.path().join("fifo"), rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).unwrap();
        let root = BeneathRoot::from_owned(File::open(directory.path()).unwrap().into()).unwrap();
        let mut original = BeneathRegularFileOpenOriginalV2::new();

        assert!(matches!(original.open_regular_once_v1(&root, Path::new("fifo")), Err(Error::WrongDescriptorType { .. })));
        assert!(original.regular_v1().is_none());
        let fd = original.regular.raw.as_ref().unwrap();
        assert_eq!(rustix::fs::FileType::from_raw_mode(rustix::fs::fstat(fd).unwrap().st_mode), rustix::fs::FileType::Fifo);
        assert!(rustix::fs::fstat(fd).is_ok());
        assert!(original.open_regular_once_v1(&root, Path::new("fifo")).is_err());
        assert!(rustix::fs::fstat(original.regular.raw.as_ref().unwrap()).is_ok());
    }
}
