//! Checks actual opened-directory receipts retained inside submitted commands.
//!
//! Descriptors preserve the observed incarnation through cancellation. Their
//! named paths, complete parent observations and configured policy are checked
//! independently; owning a directory descriptor does not establish exclusion.

use super::{MetadataStamp, NativeOpenedDirectory, NodeKind, check_parents};
use std::io;

impl NativeOpenedDirectory {
    /// Rechecks the actual descriptor, named incarnation and complete ancestry.
    ///
    /// # Errors
    /// Rejects a non-directory, unsafe owner or mode, changed named/descriptor
    /// incarnation, incomplete or replaced ancestry, and unavailable metadata.
    pub(super) fn check(&self) -> io::Result<()> {
        self.check_ancestry()?;
        let opened = MetadataStamp::checked(&self.file.metadata()?)?;
        let named = MetadataStamp::checked(&std::fs::symlink_metadata(&self.path)?)?;

        self.policy.validate(opened)?;
        self.policy.validate(named)?;
        if opened.kind != NodeKind::Directory
            || !opened.same_incarnation(self.stamp)
            || !named.same_incarnation(self.stamp)
        {
            return Err(io::Error::other("retained directory incarnation changed"));
        }

        self.check_ancestry()
    }

    fn check_ancestry(&self) -> io::Result<()> {
        // The actual filesystem root has no parent. Its descriptor, named
        // identity and configured ancestor policy are still checked above.
        if self.path.as_os_str() == "/" {
            if self.parents.is_empty() {
                return Ok(());
            }
            return Err(io::Error::other("unexpected filesystem-root ancestry"));
        }
        check_parents(&self.path, &self.parents, self.policy.configured_owner())
    }
}

#[cfg(all(test, feature = "tokio", unix))]
#[path = "directory_retention/tests.rs"]
mod tests;
