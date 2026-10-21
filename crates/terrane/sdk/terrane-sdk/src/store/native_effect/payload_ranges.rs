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
use std::{
    collections::BTreeMap,
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, Weak},
};

#[cfg(all(feature = "tokio", unix))]
#[path = "payload_ranges/bodies.rs"]
mod bodies;

#[cfg(all(feature = "tokio", unix))]
pub(crate) use bodies::BodyRead;

/// Carries a sealed original-descriptor capture, bounded read or physical check.
///
/// Only the actual payload reader constructs these recipes. Native execution
/// retains the descriptor through worker completion, including cancellation of
/// its waiting future. The request grants no namespace or publication authority.
pub struct NativePayloadRangeRead {
    #[cfg(not(all(feature = "tokio", unix)))]
    _sealed: (),
    #[cfg(all(feature = "tokio", unix))]
    recipe: Recipe,
    #[cfg(all(test, feature = "tokio", unix))]
    before_read: Option<Box<dyn FnOnce() + Send>>,
    #[cfg(all(test, feature = "tokio", unix))]
    before_leaf_open: Option<Box<dyn FnOnce() + Send>>,
}

/// Returns actual original-descriptor data or a completed physical observation.
///
/// Its private outcome cannot be constructed from caller-supplied bytes. A
/// successful check supplies neither an actor decision nor a durability ACK.
pub struct NativePayloadRangeRecord {
    #[cfg(not(all(feature = "tokio", unix)))]
    _sealed: (),
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
    Bodies {
        root: PathBuf,
        relative: Vec<PathBuf>,
    },
    Capture {
        path: PathBuf,
    },
    Read {
        original: Arc<OriginalPayload>,
        range: ByteRange,
    },
    Check(RetainedPayloadRanges),
    CheckBatch(Vec<Arc<RetainedPayloadRanges>>),
}

#[cfg(all(feature = "tokio", unix))]
enum Outcome {
    Supported,
    Bodies(Vec<io::Result<BodyRead>>),
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
    file: Arc<File>,
    directories: Vec<Arc<File>>,
}

/// Identifies one exact named directory incarnation, with directory kind fixed.
#[cfg(all(feature = "tokio", unix))]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct DirectoryKey {
    path: PathBuf,
    identity: (u64, u64),
    owner: u32,
    mode: u32,
}

/// Keeps weak identity rows with amortized cleanup during unique-key growth.
#[cfg(all(feature = "tokio", unix))]
struct DirectoryIndex {
    entries: BTreeMap<DirectoryKey, Weak<File>>,
    next_prune: usize,
}

#[cfg(all(feature = "tokio", unix))]
impl DirectoryIndex {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_prune: 32,
        }
    }

    fn insert(&mut self, key: DirectoryKey, directory: &Arc<File>) {
        self.entries.insert(key, Arc::downgrade(directory));
        if self.entries.len() < self.next_prune {
            return;
        }

        // Hits never scan the index. Dead rows own no descriptors; geometric
        // growth bounds their memory without rescanning every live ancestor.
        self.entries
            .retain(|_, directory| directory.strong_count() != 0);
        self.next_prune = self.entries.len().saturating_mul(2).max(32);
    }
}

/// Shares only original handles; each capture still opens and validates freshly.
#[cfg(all(feature = "tokio", unix))]
fn intern_directory(path: &Path, stamp: MetadataStamp, opened: File) -> io::Result<Arc<File>> {
    static DIRECTORIES: OnceLock<Mutex<DirectoryIndex>> = OnceLock::new();

    let key = DirectoryKey {
        path: path.to_owned(),
        identity: stamp.identity,
        owner: stamp.owner,
        mode: stamp.mode,
    };
    let opened = Arc::new(opened);
    let original = {
        let mut directories = DIRECTORIES
            .get_or_init(|| Mutex::new(DirectoryIndex::new()))
            .lock()
            .map_err(|_| io::Error::other("original directory handle index poisoned"))?;
        match directories.entries.get(&key).and_then(Weak::upgrade) {
            Some(original) => original,
            None => {
                directories.insert(key, &opened);
                Arc::clone(&opened)
            }
        }
    };

    // The process index owns no descriptor or successful observation. Strong
    // ownership belongs to the original operation and its submitted workers.
    // Sharing cannot bypass a fresh capture's open errors or any later checks.
    let metadata = MetadataStamp::checked(&original.metadata()?)?;
    validate_parent(metadata)?;
    if !metadata.same_incarnation(stamp) {
        return Err(io::Error::other(
            "original directory handle incarnation changed",
        ));
    }

    Ok(original)
}

/// Identifies an exact named regular-file incarnation without caching observations.
#[cfg(all(feature = "tokio", unix))]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct PayloadKey {
    path: PathBuf,
    identity: (u64, u64),
    owner: u32,
    mode: u32,
    links: u64,
}

/// Keeps weak leaf handles with geometric cleanup during unique-key growth.
#[cfg(all(feature = "tokio", unix))]
struct PayloadIndex {
    entries: BTreeMap<PayloadKey, Weak<File>>,
    next_prune: usize,
}

#[cfg(all(feature = "tokio", unix))]
impl PayloadIndex {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_prune: 32,
        }
    }

    fn insert(&mut self, key: PayloadKey, file: &Arc<File>) {
        self.entries.insert(key, Arc::downgrade(file));
        if self.entries.len() < self.next_prune {
            return;
        }

        // Hits perform no scan. Dead rows own no handles; geometric pruning
        // amortizes their cleanup without repeatedly visiting live receipts.
        self.entries.retain(|_, file| file.strong_count() != 0);
        self.next_prune = self.entries.len().saturating_mul(2).max(32);
    }
}

/// Shares only a live file handle after the complete fresh capture has checked it.
#[cfg(all(feature = "tokio", unix))]
fn intern_payload(path: &Path, stamp: MetadataStamp, opened: &Arc<File>) -> io::Result<Arc<File>> {
    static PAYLOADS: OnceLock<Mutex<PayloadIndex>> = OnceLock::new();

    let key = PayloadKey {
        path: path.to_owned(),
        identity: stamp.identity,
        owner: stamp.owner,
        mode: stamp.mode,
        links: stamp.links,
    };
    let mut files = PAYLOADS
        .get_or_init(|| Mutex::new(PayloadIndex::new()))
        .lock()
        .map_err(|_| io::Error::other("original payload handle index poisoned"))?;
    match files.entries.get(&key).and_then(Weak::upgrade) {
        Some(original) => Ok(original),
        None => {
            files.insert(key, opened);
            Ok(Arc::clone(opened))
        }
    }
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

    /// Reads a bounded ordered ordinary batch through independently retained originals.
    ///
    /// Unsupported bindings perform no I/O and retain their scalar path. Each
    /// result belongs to its actual input row; execution stops at the first
    /// absence, layout refusal or I/O error before reading any later payload.
    ///
    /// # Errors
    /// Refuses empty/overlarge batches, unavailable workers and invalid outcomes.
    /// Individual physical failures remain ordered data for caller classification.
    pub(crate) async fn read_ordinary_bodies<F: LocalFs + BucketBinding>(
        fs: &F,
        root: &Path,
        relative: &[PathBuf],
    ) -> Result<Option<Vec<io::Result<BodyRead>>>, StoreFailure> {
        if relative.is_empty() || relative.len() > 32 {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::MalformedRequest,
            )));
        }
        let request = NativePayloadRangeRead::new(Recipe::Bodies {
            root: root.to_owned(),
            relative: relative.to_vec(),
        });
        let Some(record) = fs.read_payload_bodies(request).await.map_err(io_failure)? else {
            return Ok(None);
        };
        match record.outcome {
            Outcome::Bodies(rows) => Ok(Some(rows)),
            _ => Err(io_failure(unexpected_outcome())),
        }
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

        // A fresh read must preserve bytes already consumed by this capture,
        // even when file timestamps do not distinguish two writes. Compare
        // only the overlap actually returned by the native worker; closing
        // still rereads every retained range through the original descriptor.
        if self
            .retained
            .ranges
            .iter()
            .any(|expected| !preserves_overlap(range, &bytes, expected))
        {
            return Err(io_failure(io::Error::other(
                "previously consumed native payload bytes changed",
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
fn preserves_overlap(range: ByteRange, bytes: &[u8], expected: &ExpectedRange) -> bool {
    let (Some(end), Some(expected_end)) = (
        range.start.checked_add(range.length),
        expected.range.start.checked_add(expected.range.length),
    ) else {
        return false;
    };

    let start = range.start.max(expected.range.start);
    let end = end.min(expected_end);
    if start >= end {
        return true;
    }

    let (Ok(offset), Ok(expected_offset), Ok(length)) = (
        usize::try_from(start - range.start),
        usize::try_from(start - expected.range.start),
        usize::try_from(end - start),
    ) else {
        return false;
    };
    let (Some(end), Some(expected_end)) = (
        offset.checked_add(length),
        expected_offset.checked_add(length),
    ) else {
        return false;
    };

    bytes
        .get(offset..end)
        .zip(expected.bytes.get(expected_offset..expected_end))
        .is_some_and(|(current, prior)| current == prior)
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

    /// Rechecks one request's original recipes in a single native worker turn.
    ///
    /// No ancestry, descriptor or consumed-range check is omitted or cached.
    /// The worker retains all original recipes after waiter cancellation.
    ///
    /// # Errors
    /// Refuses unavailable native execution or any failed original recipe.
    pub(crate) async fn revalidate_all<F: LocalFs + BucketBinding>(
        fs: &F,
        originals: Vec<Arc<Self>>,
    ) -> Result<(), StoreFailure> {
        if originals.is_empty() {
            return Ok(());
        }
        let request = NativePayloadRangeRead::new(Recipe::CheckBatch(originals));
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
    /// Checks the same original descriptor and every previously consumed range.
    ///
    /// # Errors
    /// Refuses changed ancestors, leaf incarnations or consumed bytes and I/O failures.
    pub(in crate::store::native_effect) fn check_ranges(&self) -> io::Result<()> {
        // Each read brackets its bytes with fresh original checks. The final
        // check follows comparison and also covers receipts with no ranges.
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
            #[cfg(test)]
            before_leaf_open: None,
        }
    }

    /// Borrows the actual pathname of a native descriptor-capture request.
    ///
    /// Probes, range reads and closing recipes supply no capture pathname.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn capture_path_for_test(&self) -> Option<&Path> {
        match &self.recipe {
            Recipe::Capture { path } => Some(path),
            _ => None,
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

    /// Borrows the exact replay ranges retained by a real closing request.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn closing_data_ranges_for_test(
        &self,
    ) -> Option<Box<dyn Iterator<Item = (&Path, ByteRange)> + '_>> {
        match &self.recipe {
            Recipe::Check(retained) => {
                Some(Box::new(retained.ranges.iter().map(move |expected| {
                    (retained.original.path.as_path(), expected.range)
                })))
            }
            Recipe::CheckBatch(originals) => {
                Some(Box::new(originals.iter().flat_map(|retained| {
                    retained
                        .ranges
                        .iter()
                        .map(move |expected| (retained.original.path.as_path(), expected.range))
                })))
            }
            _ => None,
        }
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
            Recipe::Bodies { root, relative } => Outcome::Bodies(bodies::read(root, relative)),
            Recipe::Capture { path } => Outcome::Captured(Arc::new(OriginalPayload::capture(
                path,
                #[cfg(test)]
                self.before_leaf_open,
            )?)),
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
            Recipe::CheckBatch(originals) => {
                for original in &originals {
                    original.check_ranges()?;
                }
                Outcome::Checked
            }
        };
        Ok(NativePayloadRangeRecord { outcome })
    }
}

#[cfg(all(feature = "tokio", unix))]
impl OriginalPayload {
    fn capture(
        path: PathBuf,
        #[cfg(test)] before_leaf_open: Option<Box<dyn FnOnce() + Send>>,
    ) -> io::Result<Self> {
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
            directories.push(intern_directory(&prefix, stamp, directory)?);
        }

        let before = std::fs::symlink_metadata(&path)?;
        let stamp = MetadataStamp::checked(&before)?;
        validate_leaf(stamp)?;
        #[cfg(test)]
        if let Some(before_leaf_open) = before_leaf_open {
            before_leaf_open();
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let mut original = Self {
            path,
            parents,
            stamp,
            length: before.len(),
            modified: (before.mtime(), before.mtime_nsec()),
            changed: (before.ctime(), before.ctime_nsec()),
            metadata: before,
            file: Arc::new(file),
            directories,
        };
        original.check()?;

        // Every capture opens and checks its own descriptor before considering
        // sharing. Only the handle is interned: ancestry, metadata and consumed
        // ranges remain independent, and the weak index grants no authority.
        original.file = intern_payload(&original.path, original.stamp, &original.file)?;
        original.check_leaf(&original.file.metadata()?)?;
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
