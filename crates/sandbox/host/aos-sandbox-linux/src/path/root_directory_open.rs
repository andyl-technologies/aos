//! Retains single-purpose root and directory acquisition through existing recipes.
//!
//! These inert mechanical destinations grant no pathname, role, payment or
//! currentness authority. Their callers retain admission and independent posts.

use super::*;

/// Owns one supplied root duplication through its original strict inspection.
#[derive(Debug, Default)]
pub struct BeneathRootOpenOriginalV2 {
    root: PendingBeneathRootV5,
    entered: bool,
}

impl BeneathRootOpenOriginalV2 {
    /// Creates an empty destination without native work.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Duplicates and validates a supplied root through the original recipe.
    ///
    /// # Errors
    /// Rejects reentry, duplication failure or the original root inspection.
    /// Any descriptor returned before inspection remains owned on refusal.
    pub fn capture_root_once_v1(&mut self, root: BorrowedFd<'_>) -> Result<()> {
        if self.entered {
            return Err(Error::invalid("retained beneath-root read", "already attempted"));
        }
        self.entered = true;

        let descriptor = rustix::io::fcntl_dupfd_cloexec(root, 0).map_err(|source| Error::Syscall {
            operation: "fcntl(F_DUPFD_CLOEXEC)",
            source: std::io::Error::from_raw_os_error(source.raw_os_error()),
        })?;
        self.root.retain(descriptor)
    }

    /// Borrows the same root only after its original validation completed.
    #[must_use]
    pub fn root_v1(&self) -> Option<&BeneathRoot> {
        self.root.validated.as_ref()
    }
}

/// Owns one strict directory resolution through its original inspection.
#[derive(Debug, Default)]
pub struct BeneathDirectoryOpenOriginalV2 {
    directory: PendingResolvedPathV5,
    entered: bool,
}

impl BeneathDirectoryOpenOriginalV2 {
    /// Creates an empty destination without native work.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolves one strict directory and retains its raw pre-inspection FD.
    ///
    /// # Errors
    /// Rejects reentry or any original strict directory resolution failure.
    pub fn resolve_directory_once_v1(&mut self, root: &BeneathRoot, relative: &Path) -> Result<()> {
        if self.entered {
            return Err(Error::invalid("retained beneath-root read", "already attempted"));
        }
        self.entered = true;
        root.resolve_directory_retaining(relative, &mut self.directory)
    }

    /// Borrows the same directory only after strict resolution completed.
    #[must_use]
    pub fn directory_v1(&self) -> Option<&ResolvedPath> {
        self.directory.validated.as_ref()
    }

    /// Resolves a directory through the same recipe with explicit mount policy.
    ///
    /// The role owner supplies its existing resolution policy. This method
    /// retains the actual candidate before inspection and grants no pathname
    /// or mutation authority.
    ///
    /// # Errors
    /// Refuses reentry, a non-directory policy or the actual resolution error.
    pub fn resolve_directory_with_options_once_v2(&mut self, root: &BeneathRoot,
        relative: &Path, options: ResolveOptions) -> Result<()> {
        if self.entered {
            return Err(Error::invalid("retained directory read", "already attempted"));
        }
        self.entered = true;
        root.resolve_directory_options_retaining(relative, options, &mut self.directory)
    }

    /// Transfers the same successfully inspected directory as a root once.
    ///
    /// No descriptor is opened, duplicated or reconstructed by this move.
    #[must_use]
    pub fn take_completed_root_once_v2(&mut self) -> Option<BeneathRoot> {
        self.directory.take_directory_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_root_type_keeps_the_actual_duplicate_across_reentry() {
        let file = tempfile::tempfile().unwrap();
        let mut original = BeneathRootOpenOriginalV2::new();

        assert!(matches!(original.capture_root_once_v1(file.as_fd()),
            Err(Error::WrongDescriptorType { .. })));
        assert!(original.root_v1().is_none());
        let before = rustix::fs::fstat(original.root.raw.as_ref().unwrap()).unwrap();

        assert!(original.capture_root_once_v1(file.as_fd()).is_err());
        let after = rustix::fs::fstat(original.root.raw.as_ref().unwrap()).unwrap();
        assert_eq!((before.st_dev, before.st_ino), (after.st_dev, after.st_ino));
        assert_eq!(rustix::fs::FileType::from_raw_mode(after.st_mode), rustix::fs::FileType::RegularFile);
    }
}
