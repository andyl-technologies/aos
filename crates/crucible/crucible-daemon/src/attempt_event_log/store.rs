//! Storage for sealed attempt-log segments.
//!
//! Sealed segments are immutable and addressed by the content identity their
//! bytes derive, so stores never coordinate writers: two logs that seal the
//! same entries at the same points write the same segment under the same name.
//!
//! - [`DirectorySegmentStore`] keeps segments as files in one host-owned
//!   [`AttemptLogDirectory`], so a running attempt holds only segment
//!   references and its open tail in memory.
//! - [`MemorySegmentStore`] keeps segments in memory for bounded in-process
//!   callers, transport bundles, and tests.
//! - [`AttemptLogStore`] is the store an executor attempt writes: a directory
//!   created in the executor's [`AttemptLogNamespace`], or memory without one.
//! - [`BoundedSegmentSink`] admits an attempt's resolved-effect trace segments
//!   into their own attempt directory under a byte budget.
//!
//! The read trait and the source chain are the shared
//! [`crucible_store::segment_store`] contracts, so a directory that holds an
//! attempt's event-log segments also holds its resolved-effect trace segments
//! (RFC-0020 section 15), and one prepared-result journal stages both.
//!
//! A directory holds one file per segment, named by the lowercase hex digest
//! of its identity:
//!
//! ```text
//! <directory>/
//!   <64 hex digits>.segment                 complete, synchronized segment
//!   .<64 hex digits>.<pid>.<n>.partial      in-flight write, never read
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_engine::SchedulerEventLogEntry;
use crucible_store::content_store::{ContentId, ObjectKind};
use crucible_store::segment_store::{SegmentSink, SegmentSources};

use super::{
    ATTEMPT_LOG_SEGMENT_SCHEMA, AttemptEventLog, AttemptEventLogError, AttemptLogManifest,
    AttemptLogSegmentRef, MAX_ATTEMPT_LOG_SEGMENT_BYTES, decode_segment,
};

/// Distinguishes concurrent in-flight writes within one process.
static PARTIAL_WRITE_ORDINAL: AtomicU64 = AtomicU64::new(0);

/// Suffix of one complete segment file.
const SEGMENT_FILE_SUFFIX: &str = ".segment";

/// Read access to sealed segments, addressed by content identity.
///
/// Readers authenticate every segment they receive against its reference, so
/// a source only needs to return the bytes it holds under an identity. This
/// is the segment-store read contract every segmented log shares.
pub use crucible_store::segment_store::SegmentSource as AttemptLogSegmentSource;

/// Shared read handles to every store that may hold a result's segments.
///
/// A prepared result references its log segments by identity and keeps these
/// handles instead of the bytes, so its size does not grow with the attempt
/// log. Lookups try each store in order. Every reader authenticates the bytes
/// it receives against the referencing [`AttemptLogSegmentRef`], so a store
/// that lacks a segment, or holds foreign bytes under its name, can only make
/// a read fail.
pub type AttemptLogSegmentSources = SegmentSources;

/// Writable storage for the segments an attempt seals.
pub(crate) trait AttemptLogSegmentStore: AttemptLogSegmentSource {
    /// Stores one encoded segment under its identity.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the segment cannot be durably written.
    fn put(&mut self, id: ContentId, bytes: &[u8]) -> io::Result<()>;
}

/// Host-owned directory that holds one attempt's sealed segments.
///
/// The directory is created empty and private, and is removed with
/// everything in it when the last handle drops. Handles are shared through
/// [`Arc`], so every log, snapshot, and prepared result that references the
/// segments keeps them readable for exactly as long as it lives.
#[derive(Debug)]
pub(crate) struct AttemptLogDirectory {
    path: PathBuf,
}

impl AttemptLogDirectory {
    /// Creates `path` as a new, empty, owner-only directory.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the parent does not exist, `path` already
    /// exists, or the directory cannot be created.
    pub(crate) fn create(path: impl Into<PathBuf>) -> io::Result<Arc<Self>> {
        let path = path.into();
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Arc::new(Self { path }))
    }

    /// Returns the directory's path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for AttemptLogDirectory {
    fn drop(&mut self) {
        // Removal is best effort: a directory left behind by a failed removal
        // or a crash is reclaimed by the owner's startup sweep.
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Segment store backed by one host-owned [`AttemptLogDirectory`].
///
/// Each segment is written to a uniquely named temporary file, synchronized,
/// and renamed to its identity, so a reader never observes a partial segment
/// and concurrent writers of the same segment never truncate each other.
/// Cloning shares the directory.
#[derive(Clone, Debug)]
pub(crate) struct DirectorySegmentStore {
    directory: Arc<AttemptLogDirectory>,
}

impl DirectorySegmentStore {
    /// Stores segments in `directory`.
    pub(crate) fn new(directory: Arc<AttemptLogDirectory>) -> Self {
        Self { directory }
    }

    /// Returns the shared directory handle.
    pub(crate) fn directory(&self) -> &Arc<AttemptLogDirectory> {
        &self.directory
    }

    /// Reports whether the directory already holds a complete segment for `id`.
    ///
    /// Complete segment files appear only by rename, so a present file holds
    /// exactly the bytes its identity names.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the file's presence cannot be determined.
    pub(crate) fn contains(&self, id: ContentId) -> io::Result<bool> {
        self.directory
            .path()
            .join(format!("{}{SEGMENT_FILE_SUFFIX}", digest_hex(id)))
            .try_exists()
    }
}

/// Two stores are equal when they read and write the same directory.
impl PartialEq for DirectorySegmentStore {
    fn eq(&self, other: &Self) -> bool {
        self.directory.path() == other.directory.path()
    }
}

impl Eq for DirectorySegmentStore {}

impl AttemptLogSegmentStore for DirectorySegmentStore {
    fn put(&mut self, id: ContentId, bytes: &[u8]) -> io::Result<()> {
        write_content_file(self.directory.path(), id, SEGMENT_FILE_SUFFIX, bytes)
    }
}

/// The directory also receives resolved-effect trace segments sealed by the
/// attempt's fault runtime, through the shared sink contract.
impl SegmentSink for DirectorySegmentStore {
    fn put_segment(&self, id: ContentId, bytes: &[u8]) -> io::Result<()> {
        if !id.authenticates(bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "segment bytes do not derive their identity",
            ));
        }
        self.clone().put(id, bytes)
    }
}

impl AttemptLogSegmentSource for DirectorySegmentStore {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        read_content_file(
            self.directory.path(),
            id,
            SEGMENT_FILE_SUFFIX,
            MAX_ATTEMPT_LOG_SEGMENT_BYTES,
        )
    }
}

/// Directory sink that charges each newly stored segment against a byte budget.
///
/// An executor attempt's resolved-effect trace grows with virtual time like
/// its event log, so its segments go to host storage rather than memory and
/// observe the same operational bound, the deployment's
/// `maximum_event_log_bytes`. Each identity is charged once, when it is first
/// written; storing a present identity again is free, because the directory
/// already holds its bytes. A write that would exceed the budget is refused
/// before any byte reaches the directory.
#[derive(Debug)]
pub(crate) struct BoundedSegmentSink {
    store: DirectorySegmentStore,
    maximum_bytes: u64,
    charged_bytes: AtomicU64,
}

impl BoundedSegmentSink {
    /// Admits at most `maximum_bytes` of distinct segments into `store`.
    pub(crate) const fn new(store: DirectorySegmentStore, maximum_bytes: u64) -> Self {
        Self {
            store,
            maximum_bytes,
            charged_bytes: AtomicU64::new(0),
        }
    }

    /// Returns the encoded bytes of every distinct segment stored so far.
    pub(crate) fn charged_bytes(&self) -> u64 {
        self.charged_bytes.load(Ordering::Acquire)
    }

    /// Reserves `length` bytes of the budget, or refuses without charging.
    fn reserve(&self, length: u64) -> io::Result<()> {
        self.charged_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |charged| {
                charged
                    .checked_add(length)
                    .filter(|total| *total <= self.maximum_bytes)
            })
            .map(|_| ())
            .map_err(|charged| {
                io::Error::new(
                    io::ErrorKind::QuotaExceeded,
                    format!(
                        "resolved-effect trace segments would use {} of the attempt's \
                         {}-byte maximum_event_log_bytes",
                        charged.saturating_add(length),
                        self.maximum_bytes
                    ),
                )
            })
    }
}

impl AttemptLogSegmentSource for BoundedSegmentSink {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        self.store.segment(id)
    }
}

impl SegmentSink for BoundedSegmentSink {
    fn put_segment(&self, id: ContentId, bytes: &[u8]) -> io::Result<()> {
        if !id.authenticates(bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "segment bytes do not derive their identity",
            ));
        }
        if self.store.contains(id)? {
            return Ok(());
        }

        // Two writers racing on one new identity may both be charged. The
        // overcount is conservative: it can only refuse earlier.
        let length = bytes.len() as u64;
        self.reserve(length)?;
        self.store.put_segment(id, bytes).inspect_err(|_| {
            self.charged_bytes.fetch_sub(length, Ordering::AcqRel);
        })
    }
}

/// In-memory segment store for bounded in-process callers and tests.
///
/// Segments are keyed by the identity their bytes derive, so a store never
/// holds bytes under a foreign identity. Sealed bytes are immutable and
/// shared, so cloning a store copies only its index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemorySegmentStore {
    segments: BTreeMap<ContentId, Arc<[u8]>>,
}

impl MemorySegmentStore {
    /// Stores encoded segment bytes under the identity they derive.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError::InvalidSegment`] when the bytes exceed
    /// [`MAX_ATTEMPT_LOG_SEGMENT_BYTES`].
    pub fn insert(&mut self, bytes: Vec<u8>) -> Result<ContentId, AttemptEventLogError> {
        let id = ContentId::for_bytes(ObjectKind::Trace, ATTEMPT_LOG_SEGMENT_SCHEMA, &bytes);
        if bytes.len() > MAX_ATTEMPT_LOG_SEGMENT_BYTES {
            return Err(AttemptEventLogError::InvalidSegment {
                segment: id,
                reason: format!("unexpected length {}", bytes.len()),
            });
        }
        self.segments.insert(id, Arc::from(bytes));
        Ok(id)
    }

    /// Copies one referenced segment from `source` into this store.
    ///
    /// The segment is authenticated against its reference before it is kept.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when the segment is absent from
    /// `source` or fails authentication.
    pub fn copy_from(
        &mut self,
        source: &dyn AttemptLogSegmentSource,
        segment: &AttemptLogSegmentRef,
    ) -> Result<(), AttemptEventLogError> {
        if self.segments.contains_key(&segment.id) {
            return Ok(());
        }
        let bytes = source
            .segment(segment.id)
            .map_err(|source| AttemptEventLogError::Store { source })?;
        decode_segment(segment, &bytes)?;
        self.segments.insert(segment.id, Arc::from(bytes));
        Ok(())
    }

    /// Moves every segment of `other` into this store.
    pub fn extend(&mut self, other: Self) {
        self.segments.extend(other.segments);
    }

    /// Keeps only the segments whose identities `keep` accepts.
    pub fn retain(&mut self, mut keep: impl FnMut(ContentId) -> bool) {
        self.segments.retain(|id, _| keep(*id));
    }

    /// Returns whether a segment with `id` is stored.
    #[must_use]
    pub fn contains(&self, id: ContentId) -> bool {
        self.segments.contains_key(&id)
    }

    /// Returns the stored identities in ascending order.
    pub fn ids(&self) -> impl Iterator<Item = ContentId> + '_ {
        self.segments.keys().copied()
    }

    /// Returns the stored segments in identity order.
    pub fn iter(&self) -> impl Iterator<Item = (ContentId, &[u8])> {
        self.segments.iter().map(|(id, bytes)| (*id, &**bytes))
    }

    /// Returns the number of stored segments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Returns whether no segment is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns the total encoded bytes of every stored segment.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.segments
            .values()
            .map(|bytes| bytes.len() as u64)
            .fold(0, u64::saturating_add)
    }

    /// Encodes `entries` as one sealed log and returns its manifest.
    ///
    /// The log is sealed at the ordinary target size, so the manifest matches
    /// what an executor retaining the same entries would publish.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptEventLogError`] when the entries are not dense from
    /// sequence zero or cannot be encoded.
    pub fn sealed_log(
        &mut self,
        entries: impl IntoIterator<Item = SchedulerEventLogEntry>,
    ) -> Result<AttemptLogManifest, AttemptEventLogError> {
        let mut log = AttemptEventLog::new(std::mem::take(self), u64::MAX, 0);
        let manifest = log.append(entries).and_then(|()| log.seal_manifest());
        // Segments sealed before a failure stay stored; they are unreferenced.
        *self = log.into_store();
        manifest
    }
}

impl AttemptLogSegmentStore for MemorySegmentStore {
    fn put(&mut self, id: ContentId, bytes: &[u8]) -> io::Result<()> {
        self.segments.insert(id, Arc::from(bytes));
        Ok(())
    }
}

impl AttemptLogSegmentSource for MemorySegmentStore {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        self.segments
            .get(&id)
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "attempt log segment absent"))
    }
}

impl From<DirectorySegmentStore> for AttemptLogSegmentSources {
    fn from(store: DirectorySegmentStore) -> Self {
        Self::single(Arc::new(store))
    }
}

impl From<MemorySegmentStore> for AttemptLogSegmentSources {
    fn from(store: MemorySegmentStore) -> Self {
        let mut sources = Self::default();
        if !store.is_empty() {
            sources.push(Arc::new(store));
        }
        sources
    }
}

/// The segment store an executor attempt writes: in memory, or one directory.
///
/// Attempts that run under an [`AttemptLogNamespace`] seal into a directory,
/// so their memory holds only segment references and the open tail. Callers
/// without a namespace, such as in-process tools and tests, keep segments in
/// memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AttemptLogStore {
    /// Segments held in memory.
    Memory(MemorySegmentStore),
    /// Segments held as files in one attempt directory.
    Directory(DirectorySegmentStore),
}

impl Default for AttemptLogStore {
    fn default() -> Self {
        Self::Memory(MemorySegmentStore::default())
    }
}

impl AttemptLogSegmentStore for AttemptLogStore {
    fn put(&mut self, id: ContentId, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Memory(store) => store.put(id, bytes),
            Self::Directory(store) => store.put(id, bytes),
        }
    }
}

impl AttemptLogSegmentSource for AttemptLogStore {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        match self {
            Self::Memory(store) => store.segment(id),
            Self::Directory(store) => store.segment(id),
        }
    }
}

impl From<AttemptLogStore> for AttemptLogSegmentSources {
    fn from(store: AttemptLogStore) -> Self {
        match store {
            AttemptLogStore::Memory(store) => store.into(),
            AttemptLogStore::Directory(store) => store.into(),
        }
    }
}

/// Executor-owned root that gives each attempt log its own directory.
///
/// The namespace is ephemeral: its owner retires the whole root at startup,
/// before any attempt runs, so directories a crash left behind never outlive
/// one daemon incarnation. Durable copies of the segments a result references
/// live in its prepared-result journal instead.
///
/// ```text
/// <namespace>/
///   attempt-<16 hex digits>/      one attempt log's AttemptLogDirectory
///   trace-<16 hex digits>/        one attempt's resolved-effect trace segments
///   records-<16 hex digits>/      one finding preparation's replay records
/// ```
#[derive(Debug)]
pub(crate) struct AttemptLogNamespace {
    root: PathBuf,
    next_directory: AtomicU64,
}

impl AttemptLogNamespace {
    /// Creates `root` as a new, empty, owner-only namespace.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the parent does not exist, `root` already
    /// exists, or the directory cannot be created.
    pub(crate) fn create(root: impl Into<PathBuf>) -> io::Result<Arc<Self>> {
        let root = root.into();
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        Ok(Arc::new(Self {
            root,
            next_directory: AtomicU64::new(0),
        }))
    }

    /// Returns the namespace root.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Creates a new, empty directory store for one attempt log.
    ///
    /// The directory is removed when the last handle to it drops.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the directory cannot be created.
    pub(crate) fn create_store(&self) -> io::Result<AttemptLogStore> {
        let directory = self.create_directory("attempt")?;
        Ok(AttemptLogStore::Directory(DirectorySegmentStore::new(
            directory,
        )))
    }

    /// Creates a new, empty trace-segment sink bounded by `maximum_bytes`.
    ///
    /// The directory is removed when the last handle to it drops, so it
    /// lives as long as any trace that reads from it.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the directory cannot be created.
    pub(crate) fn create_trace_sink(&self, maximum_bytes: u64) -> io::Result<BoundedSegmentSink> {
        let directory = self.create_directory("trace")?;
        Ok(BoundedSegmentSink::new(
            DirectorySegmentStore::new(directory),
            maximum_bytes,
        ))
    }

    /// Creates a new, empty directory named `<family>-<ordinal>`.
    ///
    /// Every family shares one ordinal sequence, so names never collide. The
    /// directory is removed when the last handle to it drops.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the directory cannot be created.
    pub(crate) fn create_directory(&self, family: &str) -> io::Result<Arc<AttemptLogDirectory>> {
        let ordinal = self.next_directory.fetch_add(1, Ordering::Relaxed);
        AttemptLogDirectory::create(self.root.join(format!("{family}-{ordinal:016x}")))
    }
}

/// Writes one immutable content-addressed file into `directory`.
///
/// The file is named by the identity's digest and `suffix`. It is written to a
/// uniquely named temporary file, synchronized, and renamed, so a reader never
/// observes a partial file and concurrent writers of the same identity never
/// truncate each other.
///
/// # Errors
///
/// Returns an I/O error when the file cannot be durably written.
pub(crate) fn write_content_file(
    directory: &Path,
    id: ContentId,
    suffix: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let digest = digest_hex(id);
    let path = directory.join(format!("{digest}{suffix}"));
    // Content files only ever appear by rename, so a present file already
    // holds exactly the bytes its identity names.
    if path.try_exists()? {
        return Ok(());
    }

    let ordinal = PARTIAL_WRITE_ORDINAL.fetch_add(1, Ordering::Relaxed);
    let staging = directory.join(format!(
        ".{digest}.{}.{ordinal}.partial",
        std::process::id()
    ));
    let written = fs::File::create_new(&staging).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    match written.and_then(|()| fs::rename(&staging, &path)) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&staging);
            Err(error)
        }
    }
}

/// Reads one content-addressed file written by [`write_content_file`].
///
/// # Errors
///
/// Returns an I/O error when the file is absent, unreadable, or longer than
/// `maximum_bytes`.
pub(crate) fn read_content_file(
    directory: &Path,
    id: ContentId,
    suffix: &str,
    maximum_bytes: usize,
) -> io::Result<Vec<u8>> {
    let path = directory.join(format!("{}{suffix}", digest_hex(id)));
    let length = fs::metadata(&path)?.len();
    if length > maximum_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "content file exceeds its format bound",
        ));
    }
    fs::read(path)
}

/// Formats an identity's digest as lowercase hex.
fn digest_hex(id: ContentId) -> String {
    id.digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
