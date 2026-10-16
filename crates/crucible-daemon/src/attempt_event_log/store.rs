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

use crucible::SchedulerEventLogEntry;
use crucible_cas::content_store::{ContentId, ObjectKind};

use super::{
    ATTEMPT_LOG_SEGMENT_SCHEMA, AttemptEventLog, AttemptEventLogError, AttemptLogManifest,
    AttemptLogSegmentRef, MAX_ATTEMPT_LOG_SEGMENT_BYTES, decode_segment,
};

/// Distinguishes concurrent in-flight writes within one process.
static PARTIAL_WRITE_ORDINAL: AtomicU64 = AtomicU64::new(0);

/// Read access to sealed segments, addressed by content identity.
///
/// Readers authenticate every segment they receive against its reference, so
/// a source only needs to return the bytes it holds under an identity.
pub trait AttemptLogSegmentSource {
    /// Reads one encoded segment.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the segment is absent, unreadable, or larger
    /// than [`MAX_ATTEMPT_LOG_SEGMENT_BYTES`].
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>>;
}

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

    fn path(&self, id: ContentId) -> PathBuf {
        self.directory
            .path()
            .join(format!("{}.segment", digest_hex(id)))
    }

    fn partial_path(&self, id: ContentId) -> PathBuf {
        let ordinal = PARTIAL_WRITE_ORDINAL.fetch_add(1, Ordering::Relaxed);
        self.directory.path().join(format!(
            ".{}.{}.{ordinal}.partial",
            digest_hex(id),
            std::process::id()
        ))
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
        let path = self.path(id);
        // Segments are content-addressed and only ever appear by rename, so a
        // present file already holds exactly these bytes.
        if path.try_exists()? {
            return Ok(());
        }

        let staging = self.partial_path(id);
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
}

impl AttemptLogSegmentSource for DirectorySegmentStore {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        let path = self.path(id);
        let length = fs::metadata(&path)?.len();
        if length > MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "attempt log segment exceeds its format bound",
            ));
        }
        fs::read(path)
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

/// Shared read handles to every store that may hold a result's segments.
///
/// A prepared result references its log segments by identity and keeps these
/// handles instead of the bytes, so its size does not grow with the attempt
/// log. Lookups try each store in order. Every reader authenticates the bytes
/// it receives against the referencing [`AttemptLogSegmentRef`], so a store
/// that lacks a segment, or holds foreign bytes under its name, can only make
/// a read fail.
#[derive(Clone, Default)]
pub struct AttemptLogSegmentSources {
    sources: Vec<Arc<dyn AttemptLogSegmentSource + Send + Sync>>,
}

impl AttemptLogSegmentSources {
    /// Adds `source` after every store already held.
    pub fn push(&mut self, source: Arc<dyn AttemptLogSegmentSource + Send + Sync>) {
        self.sources.push(source);
    }

    /// Adds every store of `other` after the stores already held.
    pub fn extend(&mut self, other: Self) {
        self.sources.extend(other.sources);
    }

    /// Returns whether no store is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Reads through one attempt's segment directory.
    pub(crate) fn from_directory(store: DirectorySegmentStore) -> Self {
        let mut sources = Self::default();
        sources.push(Arc::new(store));
        sources
    }
}

impl std::fmt::Debug for AttemptLogSegmentSources {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttemptLogSegmentSources")
            .field("stores", &self.sources.len())
            .finish()
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

impl AttemptLogSegmentSource for AttemptLogSegmentSources {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        let mut last_error = None;
        for source in &self.sources {
            match source.segment(id) {
                Ok(bytes) => return Ok(bytes),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "attempt log segment absent")
        }))
    }
}

/// Formats a segment identity's digest as lowercase hex.
fn digest_hex(id: ContentId) -> String {
    id.digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
