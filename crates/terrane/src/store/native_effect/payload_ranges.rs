//! Retains ordinary DATA descriptors and verifies exact bounded reads.
//!
//! These recipes carry physical data alone. They perform no mutation, supply
//! no actor authority, and cannot acknowledge a publication or complete a view.
//! Each read and closing check freshly validates the original ordered ancestors,
//! named leaf and retained descriptor without reading unrelated payload bytes.

#[cfg(all(feature = "tokio", unix))]
use crate::bucket::BucketBinding;
#[cfg(all(feature = "tokio", unix))]
use crate::store::{ByteRange, InvalidReason, LocalFs, StoreErrorKind, StoreFailure};
#[cfg(all(feature = "tokio", unix))]
use std::io;
#[cfg(all(feature = "tokio", unix))]
use std::path::Path;

#[cfg(all(feature = "tokio", unix))]
use super::{MetadataStamp, NodeKind, ParentFence};
#[cfg(all(feature = "tokio", unix))]
use std::{fs::File, path::PathBuf, sync::Arc};

/// Carries a sealed original-descriptor capture, bounded read or physical check.
///
/// Only the actual payload reader constructs these recipes. Native execution
/// retains the descriptor through worker completion, including cancellation of
/// its waiting future. The request grants no namespace or publication authority.
pub struct NativePayloadRangeRead {
    #[cfg(all(feature = "tokio", unix))]
    recipe: Recipe,
    #[cfg(all(test, feature = "tokio", unix))]
    before_read: Option<Box<dyn FnOnce() + Send>>,
}

/// Returns actual original-descriptor data or a completed physical observation.
///
/// Its private outcome cannot be constructed from caller-supplied bytes. A
/// successful check supplies neither an actor decision nor a durability ACK.
pub struct NativePayloadRangeRecord {
    #[cfg(all(feature = "tokio", unix))]
    outcome: Outcome,
}

/// Collects exact ranges consumed through one original retained descriptor.
#[cfg(all(feature = "tokio", unix))]
pub(crate) struct PayloadRangeCapture {
    retained: RetainedPayloadRanges,
}

/// Retains original physical observations and every exact consumed range.
///
/// Cloning preserves the actual descriptor and observations rather than
/// recapturing the current path. Revalidation always performs fresh I/O.
#[cfg(all(feature = "tokio", unix))]
#[derive(Clone)]
pub(crate) struct RetainedPayloadRanges {
    length: u64,
    #[cfg(all(feature = "tokio", unix))]
    original: Arc<OriginalPayload>,
    #[cfg(all(feature = "tokio", unix))]
    ranges: Vec<ExpectedRange>,
}

#[cfg(all(feature = "tokio", unix))]
enum Recipe {
    Probe,
    Capture {
        path: PathBuf,
    },
    Read {
        original: Arc<OriginalPayload>,
        range: ByteRange,
    },
    Check(RetainedPayloadRanges),
}

#[cfg(all(feature = "tokio", unix))]
enum Outcome {
    Supported,
    Captured(Arc<OriginalPayload>),
    Bytes(Vec<u8>),
    Checked,
}

#[cfg(all(feature = "tokio", unix))]
struct OriginalPayload {
    path: PathBuf,
    parents: Vec<ParentFence>,
    stamp: MetadataStamp,
    metadata: std::fs::Metadata,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    file: File,
    directories: Vec<File>,
}

#[cfg(all(feature = "tokio", unix))]
#[derive(Clone)]
struct ExpectedRange {
    range: ByteRange,
    bytes: Vec<u8>,
}

#[cfg(all(feature = "tokio", unix))]
impl PayloadRangeCapture {
    /// Observes whether the binding implements sealed native range execution.
    ///
    /// This probe consumes no filesystem data and supplies no actor authority.
    ///
    /// # Errors
    /// Propagates binding failures and refuses unexpected sealed outcomes.
    pub(crate) async fn supported<F: LocalFs + BucketBinding>(
        fs: &F,
    ) -> Result<bool, StoreFailure> {
        match fs
            .read_payload_ranges(NativePayloadRangeRead::new(Recipe::Probe))
            .await
            .map_err(io_failure)?
        {
            None => Ok(false),
            Some(NativePayloadRangeRecord {
                outcome: Outcome::Supported,
            }) => Ok(true),
            Some(_) => Err(io_failure(unexpected_outcome())),
        }
    }

    /// Borrows actual original leaf metadata matched to the retained descriptor.
    #[cfg(all(feature = "tokio", unix))]
    pub(crate) fn metadata(&self) -> &std::fs::Metadata {
        &self.retained.original.metadata
    }

    /// Captures ordinary byte-read inputs without protected ownership claims.
    ///
    /// Hardlinks and public file modes remain valid ordinary inputs. Actual
    /// original stamps, name, descriptors, size and timestamps still bind every
    /// read. This recipe cannot be imported as a protected Frame input.
    ///
    /// # Errors
    /// Refuses unavailable native capture, nonregular leaves, symlinked or
    /// nondirectory ancestors, changed inputs and actual descriptor failures.
    pub(crate) async fn capture_ordinary<F: LocalFs + BucketBinding>(
        fs: &F,
        path: &Path,
    ) -> Result<Self, StoreFailure> {
        Self::capture_native(fs, path).await
    }

    #[cfg(all(feature = "tokio", unix))]
    async fn capture_native<F: LocalFs + BucketBinding>(
        fs: &F,
        path: &Path,
    ) -> Result<Self, StoreFailure> {
        let request = NativePayloadRangeRead::new(Recipe::Capture {
            path: path.to_owned(),
        });
        let record = fs
            .read_payload_ranges(request)
            .await
            .map_err(io_failure)?
            .ok_or_else(unsupported)?;
        let Outcome::Captured(original) = record.outcome else {
            return Err(io_failure(unexpected_outcome()));
        };
        Ok(Self {
            retained: RetainedPayloadRanges {
                length: original.length,
                original,
                ranges: Vec::new(),
            },
        })
    }

    /// Returns the actual size bound to the retained descriptor.
    pub(crate) fn len(&self) -> u64 {
        self.retained.length
    }

    /// Reads and retains exactly one range through the original descriptor.
    ///
    /// # Errors
    /// Rejects overflow or bounds violations, unavailable native execution,
    /// changed inputs, short reads and actual descriptor I/O failures.
    pub(crate) async fn read_range<F: LocalFs + BucketBinding>(
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
        let request = NativePayloadRangeRead::new(Recipe::Read {
            original: Arc::clone(&self.retained.original),
            range,
        });
        let record = fs
            .read_payload_ranges(request)
            .await
            .map_err(io_failure)?
            .ok_or_else(unsupported)?;
        let Outcome::Bytes(bytes) = record.outcome else {
            return Err(io_failure(unexpected_outcome()));
        };
        if bytes.len() as u64 != range.length {
            return Err(io_failure(io::Error::other(
                "incomplete native payload range",
            )));
        }
        self.retained.ranges.push(ExpectedRange {
            range,
            bytes: bytes.clone(),
        });
        Ok(bytes)
    }

    /// Transfers the actual descriptor and consumed ranges into the closing recipe.
    pub(crate) fn finish(self) -> RetainedPayloadRanges {
        self.retained
    }
}

#[cfg(all(feature = "tokio", unix))]
impl RetainedPayloadRanges {
    /// Freshly rechecks original ancestry, descriptor and every consumed range.
    ///
    /// # Errors
    /// Refuses unavailable native execution, changed physical inputs or bytes,
    /// nonregular inputs, short reads and actual I/O failures.
    pub(crate) async fn revalidate<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
    ) -> Result<(), StoreFailure> {
        let request = NativePayloadRangeRead::new(Recipe::Check(self.clone()));
        let record = fs
            .read_payload_ranges(request)
            .await
            .map_err(io_failure)?
            .ok_or_else(unsupported)?;
        match record.outcome {
            Outcome::Checked => Ok(()),
            _ => Err(io_failure(unexpected_outcome())),
        }
    }

    #[cfg(all(feature = "tokio", unix))]
    fn check_ranges(&self) -> io::Result<()> {
        self.original.check()?;
        for expected in &self.ranges {
            let bytes = self.original.read(expected.range)?;
            if bytes != expected.bytes {
                return Err(io::Error::other("retained payload range bytes changed"));
            }
        }
        self.original.check()
    }
}

#[cfg(all(feature = "tokio", unix))]
impl NativePayloadRangeRead {
    #[cfg(all(feature = "tokio", unix))]
    fn new(recipe: Recipe) -> Self {
        Self {
            recipe,
            #[cfg(test)]
            before_read: None,
        }
    }

    /// Borrows the exact data request for forwarding test bindings.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn read_data_range(&self) -> Option<(&Path, ByteRange)> {
        match &self.recipe {
            Recipe::Read { original, range } => Some((&original.path, *range)),
            _ => None,
        }
    }

    /// Identifies closing requests for forwarding test bindings.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn closing_for_test(&self) -> bool {
        matches!(&self.recipe, Recipe::Check(_))
    }

    /// Executes only privately captured physical recipes on the actual worker.
    ///
    /// # Errors
    /// Preserves ordered ancestor, leaf, descriptor, bounds and read failures.
    ///
    /// # Panics
    /// Test builds can panic when an injected worker observation panics.
    #[cfg(all(feature = "tokio", unix))]
    pub(in crate::store) fn execute(self) -> io::Result<NativePayloadRangeRecord> {
        let outcome = match self.recipe {
            Recipe::Probe => Outcome::Supported,
            Recipe::Capture { path } => {
                Outcome::Captured(Arc::new(OriginalPayload::capture(path)?))
            }
            Recipe::Read { original, range } => {
                #[cfg(test)]
                if let Some(before_read) = self.before_read {
                    before_read();
                }
                Outcome::Bytes(original.read(range)?)
            }
            Recipe::Check(retained) => {
                retained.check_ranges()?;
                Outcome::Checked
            }
        };
        Ok(NativePayloadRangeRecord { outcome })
    }
}

#[cfg(all(feature = "tokio", unix))]
impl OriginalPayload {
    fn capture(path: PathBuf) -> io::Result<Self> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload path is not absolute",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("missing payload parent"))?;
        let mut prefix = PathBuf::new();
        let mut parents = Vec::new();
        let mut directories = Vec::new();
        for part in parent.components() {
            if !matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "noncanonical payload ancestor",
                ));
            }
            prefix.push(part);
            let stamp = MetadataStamp::checked(&std::fs::symlink_metadata(&prefix)?)?;
            validate_parent(stamp)?;
            let directory = open_parent(&prefix)?;
            let opened = MetadataStamp::checked(&directory.metadata()?)?;
            validate_parent(opened)?;
            if !opened.same_incarnation(stamp) {
                return Err(io::Error::other("payload ancestor changed during capture"));
            }
            parents.push(ParentFence {
                path: prefix.clone(),
                stamp,
            });
            directories.push(directory);
        }

        let before = std::fs::symlink_metadata(&path)?;
        let stamp = MetadataStamp::checked(&before)?;
        validate_leaf(stamp)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let original = Self {
            path,
            parents,
            stamp,
            length: before.len(),
            modified: (before.mtime(), before.mtime_nsec()),
            changed: (before.ctime(), before.ctime_nsec()),
            metadata: before,
            file,
            directories,
        };
        original.check()?;
        Ok(original)
    }

    fn check(&self) -> io::Result<()> {
        // Each named ancestor is freshly observed before traversing the
        // next. Original descriptors prevent inode-reuse recapture.
        for parent in &self.parents {
            let actual = MetadataStamp::checked(&std::fs::symlink_metadata(&parent.path)?)?;
            validate_parent(actual)?;
            if !actual.same_incarnation(parent.stamp) {
                return Err(io::Error::other(
                    "original ordinary payload ancestor changed",
                ));
            }
        }
        for (parent, directory) in self.parents.iter().zip(&self.directories) {
            let opened = MetadataStamp::checked(&directory.metadata()?)?;
            validate_parent(opened)?;
            if !opened.same_incarnation(parent.stamp) {
                return Err(io::Error::other(
                    "original payload ancestor descriptor changed",
                ));
            }
        }
        self.check_leaf(&std::fs::symlink_metadata(&self.path)?)?;
        self.check_leaf(&self.file.metadata()?)
    }

    fn check_leaf(&self, metadata: &std::fs::Metadata) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        let stamp = MetadataStamp::checked(metadata)?;
        validate_leaf(stamp)?;
        if !stamp.same_incarnation(self.stamp)
            || metadata.len() != self.length
            || (metadata.mtime(), metadata.mtime_nsec()) != self.modified
            || (metadata.ctime(), metadata.ctime_nsec()) != self.changed
        {
            return Err(io::Error::other("original payload range input changed"));
        }
        Ok(())
    }

    fn read(&self, range: ByteRange) -> io::Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;

        let end = range
            .start
            .checked_add(range.length)
            .filter(|end| *end <= self.length)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "payload range outside original length",
                )
            })?;
        let length = usize::try_from(end - range.start).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload range exceeds address space",
            )
        })?;
        self.check()?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(io::Error::other)?;
        bytes.resize(length, 0);
        self.file.read_exact_at(&mut bytes, range.start)?;
        self.check()?;
        Ok(bytes)
    }
}

#[cfg(all(feature = "tokio", unix))]
fn validate_parent(stamp: MetadataStamp) -> io::Result<()> {
    if stamp.kind == NodeKind::Directory {
        Ok(())
    } else {
        Err(io::Error::other(
            "ordinary payload ancestor is not a directory",
        ))
    }
}

#[cfg(all(feature = "tokio", unix))]
fn validate_leaf(stamp: MetadataStamp) -> io::Result<()> {
    if stamp.kind == NodeKind::Regular {
        Ok(())
    } else {
        Err(io::Error::other("ordinary payload leaf is not regular"))
    }
}

/// Opens an ancestor without requesting directory contents or following a link.
#[cfg(all(feature = "tokio", unix))]
fn open_parent(path: &Path) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;

        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "retained payload ancestors require native path descriptors",
        ))
    }
}

#[cfg(all(feature = "tokio", unix))]
fn unsupported() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unsupported)
}

#[cfg(all(feature = "tokio", unix))]
fn unexpected_outcome() -> io::Error {
    io::Error::other("unexpected native payload range outcome")
}

#[cfg(all(feature = "tokio", unix))]
fn io_failure(error: io::Error) -> StoreFailure {
    let kind = match error.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => {
            StoreErrorKind::ReadOnly
        }
        io::ErrorKind::StorageFull => StoreErrorKind::Capacity,
        io::ErrorKind::Unsupported => StoreErrorKind::Unsupported,
        _ => StoreErrorKind::Unavailable { retry_after: None },
    };
    StoreFailure::with_source(kind, error)
}

#[cfg(all(test, feature = "tokio", unix))]
#[path = "payload_ranges/tests.rs"]
mod tests;
