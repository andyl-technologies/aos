//! Checks ordinary bounded reads when retained native descriptors are unavailable.
//!
//! Observations retain actual names, metadata and received ranges. Fresh checks
//! reject changed visible inputs, but cannot establish native Original authority
//! or prevent inode reuse without an opened descriptor. These data checks never
//! become publication receipts or permit a whole-pack fallback.

use crate::bucket::BucketBinding;
use crate::bucket::files::{io_failure, layout_corrupt, malformed};
use crate::store::{ByteRange, InvalidReason, LocalFs, StoreErrorKind, StoreFailure};
use std::fs::Metadata;
use std::path::{Component, Path, PathBuf};

/// Collects ordinary metadata and actual exact-range observations.
pub(super) struct OrdinaryRangeCapture {
    retained: OrdinaryRanges,
}

/// Retains visible ordinary inputs without claiming original descriptors.
pub(super) struct OrdinaryRanges {
    path: PathBuf,
    parents: Vec<(PathBuf, Metadata)>,
    leaf: Metadata,
    ranges: Vec<(ByteRange, Vec<u8>)>,
}

impl OrdinaryRangeCapture {
    /// Checks ancestors in traversal order before observing the ordinary leaf.
    ///
    /// # Errors
    /// Rejects noncanonical paths, symlinks, incompatible types and unavailable
    /// metadata while preserving ordinary public modes and hardlinks.
    pub(super) async fn capture<F: LocalFs + BucketBinding>(
        fs: &F,
        path: &Path,
    ) -> Result<Self, StoreFailure> {
        if !path.is_absolute() {
            return Err(malformed());
        }
        let parent = path.parent().ok_or_else(malformed)?;
        let mut prefix = PathBuf::new();
        let mut parents = Vec::new();
        for component in parent.components() {
            if !matches!(component, Component::RootDir | Component::Normal(_)) {
                return Err(malformed());
            }
            prefix.push(component);
            let metadata = fs.symlink_metadata(&prefix).await.map_err(io_failure)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(layout_corrupt());
            }
            parents.push((prefix.clone(), metadata));
        }
        let leaf = fs.symlink_metadata(path).await.map_err(io_failure)?;
        if !leaf.is_file() || leaf.file_type().is_symlink() {
            return Err(layout_corrupt());
        }
        let retained = OrdinaryRanges {
            path: path.to_owned(),
            parents,
            leaf,
            ranges: Vec::new(),
        };
        retained.check_metadata(fs).await?;
        Ok(Self { retained })
    }

    /// Returns the length actually observed before range consumption.
    pub(super) fn len(&self) -> u64 {
        self.retained.leaf.len()
    }

    /// Matches the actual leaf metadata supplied by an earlier ordinary read.
    ///
    /// # Errors
    /// Propagates unavailable portable timestamps without inventing evidence.
    pub(super) fn matches_metadata(&self, observed: &Metadata) -> Result<bool, StoreFailure> {
        same_metadata(&self.retained.leaf, observed, true)
    }

    /// Reads only the requested range and checks visible inputs around the read.
    ///
    /// # Errors
    /// Rejects overflow, out-of-bounds or short reads, changed visible metadata
    /// and actual I/O failures. An unsupported read is never retried whole.
    pub(super) async fn read_range<F: LocalFs + BucketBinding>(
        &mut self,
        fs: &F,
        range: ByteRange,
    ) -> Result<Vec<u8>, StoreFailure> {
        if range
            .start
            .checked_add(range.length)
            .is_none_or(|end| end > self.len())
        {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::Range(range),
            )));
        }
        self.retained.check_metadata(fs).await?;
        let bytes = fs
            .read_range(&self.retained.path, range)
            .await
            .map_err(io_failure)?;
        self.retained.check_metadata(fs).await?;
        if bytes.len() as u64 != range.length {
            return Err(layout_corrupt());
        }
        self.retained.ranges.push((range, bytes.clone()));
        Ok(bytes)
    }

    /// Transfers actual observations for fresh bounded checking before return.
    pub(super) fn finish(self) -> OrdinaryRanges {
        self.retained
    }
}

impl OrdinaryRanges {
    async fn check_metadata<F: LocalFs + BucketBinding>(&self, fs: &F) -> Result<(), StoreFailure> {
        for (path, expected) in &self.parents {
            let actual = fs.symlink_metadata(path).await.map_err(io_failure)?;
            if !actual.is_dir()
                || actual.file_type().is_symlink()
                || !same_metadata(&actual, expected, false)?
            {
                return Err(layout_corrupt());
            }
        }
        let actual = fs.symlink_metadata(&self.path).await.map_err(io_failure)?;
        if !actual.is_file()
            || actual.file_type().is_symlink()
            || !same_metadata(&actual, &self.leaf, true)?
        {
            return Err(layout_corrupt());
        }
        Ok(())
    }

    /// Freshly checks visible inputs and rereads only the consumed ranges.
    ///
    /// # Errors
    /// Rejects changed ancestry, leaf, exact bytes or short reads and propagates
    /// actual bounded I/O failures without claiming descriptor retention.
    pub(super) async fn revalidate<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
    ) -> Result<(), StoreFailure> {
        self.check_metadata(fs).await?;
        for (range, expected) in &self.ranges {
            self.check_metadata(fs).await?;
            let actual = fs
                .read_range(&self.path, *range)
                .await
                .map_err(io_failure)?;
            self.check_metadata(fs).await?;
            if &actual != expected {
                return Err(layout_corrupt());
            }
        }
        self.check_metadata(fs).await
    }
}

fn same_metadata(actual: &Metadata, expected: &Metadata, leaf: bool) -> Result<bool, StoreFailure> {
    if actual.file_type() != expected.file_type()
        || actual.permissions().readonly() != expected.permissions().readonly()
    {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if (actual.dev(), actual.ino(), actual.uid(), actual.mode())
            != (
                expected.dev(),
                expected.ino(),
                expected.uid(),
                expected.mode(),
            )
            || (leaf && actual.nlink() != expected.nlink())
        {
            return Ok(false);
        }
        if leaf
            && (
                actual.mtime(),
                actual.mtime_nsec(),
                actual.ctime(),
                actual.ctime_nsec(),
            ) != (
                expected.mtime(),
                expected.mtime_nsec(),
                expected.ctime(),
                expected.ctime_nsec(),
            )
        {
            return Ok(false);
        }
    }
    // Portable metadata describes the visible name only. Comparing timestamps
    // never substitutes for retaining an original descriptor on native paths.
    if leaf
        && (actual.len() != expected.len()
            || actual.modified().map_err(io_failure)? != expected.modified().map_err(io_failure)?)
    {
        return Ok(false);
    }
    Ok(true)
}
