//! Retains the existing owned-root and strict resolution native prefixes.
//!
//! These are readonly kernel mechanics. Paths, completed identities and moved
//! descriptors establish no principal, launch, service or financial authority.

use super::*;

/// Owns an original directory candidate through the same validation recipe.
#[derive(Debug, Default)]
pub struct BeneathRootOwnedOriginalV2 {
    pending: PendingBeneathRootV5,
    returned: Option<Result<()>>,
    entered: bool,
    closed: Option<Error>,
}

impl BeneathRootOwnedOriginalV2 {
    /// Creates empty native destinations without adopting a descriptor.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Parks the supplied original before close-on-exec and directory checks.
    ///
    /// # Errors
    /// Retains the original descriptor and exact validation error on refusal.
    /// Reentry performs no observation and cannot replace the first original.
    pub fn from_owned_once(&mut self, descriptor: OwnedFd) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(|| closed("owned root"));
            return Err(closed("owned root"));
        }
        self.entered = true;
        self.returned = Some(self.pending.retain(descriptor));
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(closed("owned root")) }
    }

    /// Moves only the actual successfully validated root once.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<BeneathRoot> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) { return None; }
        self.pending.take_validated()
    }

    /// Borrows the first original validation error before a later reentry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.returned.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Bounds actual carrier bytes and the adopted descriptor; no name is opened.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?, 1, 0))
    }
}

/// Retains a strict descendant open before every fallible identity inspection.
#[derive(Debug, Default)]
pub struct BeneathRootResolveOriginalV2 {
    pending: PendingResolvedPathV5,
    returned: Option<Result<()>>,
    entered: bool,
    closed: Option<Error>,
}

impl BeneathRootResolveOriginalV2 {
    /// Creates empty destinations without resolving any path.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Uses the same root, options and strict `openat2`/inspection engine.
    ///
    /// # Errors
    /// Retains reached descriptors and the actual path, kernel or type refusal.
    /// An entered or failed instance cannot repeat a native operation.
    pub fn resolve_once(&mut self, root: &BeneathRoot, relative: &Path, options: ResolveOptions) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(|| closed("root resolution"));
            return Err(closed("root resolution"));
        }
        self.entered = true;
        let pending = &mut self.pending;
        self.returned = Some((|| {
            resolve_path_recipe!(root, relative, options, Retained, pending)
        })());
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(closed("root resolution")) }
    }

    /// Moves the same actual completed resolved object once.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<ResolvedPath> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) { return None; }
        self.pending.validated.take()
    }

    /// Moves a completed directory into a root without reopening its pathname.
    ///
    /// A non-directory remains owned by this original. The type comparison is
    /// identical to [`BeneathRoot::from_resolved`]; no native check follows the
    /// exclusive move of the already inspected descriptor.
    #[must_use]
    pub fn take_directory_root_once(&mut self) -> Option<BeneathRoot> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        if self.pending.validated.as_ref()?.identity.file_type != FileType::Directory {
            return None;
        }
        self.pending.validated.take().map(|path| BeneathRoot {
            fd: path.fd,
            identity: path.identity,
        })
    }

    /// Borrows the original native/type refusal without another observation.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.returned.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Bounds both native pathname copies, one descriptor and one opened name.
    #[must_use]
    pub fn receiving_obligations_v2(path_bytes: usize) -> Option<(usize, usize, usize)> {
        if path_bytes > MAX_RELATIVE_PATH_BYTES { return None; }
        let paths = path_bytes.checked_add(1)?.checked_mul(2)?;
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(paths)?, 1, 1))
    }
}

fn closed(object: &'static str) -> Error {
    Error::invalid(object, "original operation remains closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_owned_regular_file_keeps_the_native_original_and_first_error() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let mut original = BeneathRootOwnedOriginalV2::new();
        assert!(original.from_owned_once(file.into()).is_err());
        let first = original.failure().unwrap() as *const Error;
        let raw = original.pending.raw.as_ref().unwrap();
        assert!(uapi::fstat(raw.as_fd()).is_ok());

        let other = std::fs::File::open("/dev/null").unwrap();
        assert!(original.from_owned_once(other.into()).is_err());
        assert_eq!(original.failure().unwrap() as *const Error, first);
        assert!(uapi::fstat(original.pending.raw.as_ref().unwrap().as_fd()).is_ok());
        assert!(original.take_completed_once().is_none());
    }

    #[test]
    fn completed_resolution_moves_the_actual_directory_and_never_repeats() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("child")).unwrap();
        let descriptor = rustix::fs::open(directory.path(), rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        let root = BeneathRoot::from_owned(descriptor).unwrap();
        let mut original = BeneathRootResolveOriginalV2::new();
        original.resolve_once(&root, Path::new("child"), ResolveOptions::directory()).unwrap();
        let resolved = original.take_completed_once().unwrap();
        assert_eq!(resolved.identity().file_type, FileType::Directory);
        assert!(original.take_completed_once().is_none());
        assert!(original.resolve_once(&root, Path::new("child"), ResolveOptions::directory()).is_err());
        assert!(uapi::fstat(resolved.as_fd()).is_ok());
    }
}
