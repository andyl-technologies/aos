//! Bounded external sorting of fixed-width records on private scratch storage.
//!
//! Closure, inventory, and root sets can each hold tens of millions of
//! identities, so their consumers keep them as sorted runs on disk instead of
//! in memory. A record is a fixed-width byte array whose byte order is the
//! order its owner needs; comparing records with `memcmp` sorts them.
//!
//! [`ExternalSorter`] buffers at most one run in memory, spills each full run
//! sorted, and merges at most [`MAX_MERGE_FAN_IN`] runs at a time, so memory is
//! bounded by the run size and fan-in rather than by the set size. Every file
//! lives in one [`SpillDirectory`], created owner-only beside the caller's
//! durable state and removed with its contents when the last handle drops, on
//! success and on every error path alike.
//!
//! [`SpillStorage::Memory`] keeps the same records in process memory. It
//! exists for callers without a filesystem root, such as in-memory stores and
//! tests; it bounds nothing.
//!
//! [`FrameWriter`] spools variable-size byte strings, such as canonical pages
//! built during a scan, in the same storage so a later pass can replay them
//! in order without keeping them resident:
//!
//! ```text
//! frame: length:u32be || bytes[length]
//! ```
//!
//! [`ordered_id_record`] encodes a [`ContentId`] so that record order equals
//! [`ContentId`]'s own `Ord`:
//!
//! ```text
//! ordered id record (37 bytes):
//!   kind rank:u8              # declaration rank of ObjectKind
//!   schema version:u32be
//!   digest[32]
//! ```
//!
//! Records never leave the process and are not a published format.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_store::content_store::{ContentId, ObjectKind};

/// Width of one spilled content-identity record.
pub const ID_RECORD_BYTES: usize = 37;

/// Records buffered in memory before a sorter spills a run.
pub const RUN_RECORDS: usize = 1 << 18;

/// Maximum number of runs read at once by one merge.
pub const MAX_MERGE_FAN_IN: usize = 128;

const IO_BUFFER_BYTES: usize = 64 * 1024;

/// Distinguishes work directories and files created by one process.
static SPILL_ORDINAL: AtomicU64 = AtomicU64::new(0);

/// One fixed-width spilled content identity.
pub type IdRecord = [u8; ID_RECORD_BYTES];

/// Object kinds in declaration order, which is [`ContentId`]'s `Ord` order.
const KINDS_BY_RANK: [ObjectKind; 14] = [
    ObjectKind::CampaignFact,
    ObjectKind::CampaignSnapshot,
    ObjectKind::MerkleNode,
    ObjectKind::Scenario,
    ObjectKind::Configuration,
    ObjectKind::Policy,
    ObjectKind::ExactManifest,
    ObjectKind::RamExtent,
    ObjectKind::DiskExtent,
    ObjectKind::DeviceState,
    ObjectKind::Observation,
    ObjectKind::Finding,
    ObjectKind::Projection,
    ObjectKind::Trace,
];

const fn kind_rank(kind: ObjectKind) -> u8 {
    // An exhaustive match makes a new kind a compile error here rather than
    // a silent ordering hole; the table above must gain the same entry.
    match kind {
        ObjectKind::CampaignFact => 0,
        ObjectKind::CampaignSnapshot => 1,
        ObjectKind::MerkleNode => 2,
        ObjectKind::Scenario => 3,
        ObjectKind::Configuration => 4,
        ObjectKind::Policy => 5,
        ObjectKind::ExactManifest => 6,
        ObjectKind::RamExtent => 7,
        ObjectKind::DiskExtent => 8,
        ObjectKind::DeviceState => 9,
        ObjectKind::Observation => 10,
        ObjectKind::Finding => 11,
        ObjectKind::Projection => 12,
        ObjectKind::Trace => 13,
    }
}

/// Encodes one identity so record byte order equals [`ContentId`] order.
#[must_use]
pub fn ordered_id_record(id: ContentId) -> IdRecord {
    let mut record = [0_u8; ID_RECORD_BYTES];
    record[0] = kind_rank(id.kind());
    record[1..5].copy_from_slice(&id.schema_version().to_be_bytes());
    record[5..].copy_from_slice(&id.digest());
    record
}

/// Decodes one identity written by [`ordered_id_record`].
///
/// # Errors
///
/// Returns [`io::ErrorKind::InvalidData`] for an unknown kind rank or a
/// truncated record.
pub fn decode_ordered_id_record(record: &[u8]) -> io::Result<ContentId> {
    let kind = record
        .first()
        .and_then(|rank| KINDS_BY_RANK.get(usize::from(*rank)))
        .copied()
        .ok_or_else(|| corrupt("spill record has an unknown object kind"))?;
    let schema = record
        .get(1..5)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .ok_or_else(|| corrupt("spill record is truncated"))?;
    let digest = record
        .get(5..ID_RECORD_BYTES)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| corrupt("spill record is truncated"))?;
    Ok(ContentId::from_parts(
        kind,
        u32::from_be_bytes(schema),
        digest,
    ))
}

fn corrupt(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// Owner-only scratch directory removed with its contents on drop.
#[derive(Debug)]
pub struct SpillDirectory {
    path: PathBuf,
}

impl SpillDirectory {
    /// Creates a new private directory named after `prefix` inside `parent`.
    ///
    /// The parent must be real disk beside the caller's durable state; the
    /// spill never chooses a temporary or memory-backed location itself.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when the directory cannot be created.
    pub fn create(parent: &Path, prefix: &str) -> io::Result<Arc<Self>> {
        let ordinal = SPILL_ORDINAL.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("{prefix}.{}.{ordinal}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Arc::new(Self { path }))
    }

    /// Returns a fresh file path inside this directory.
    #[must_use]
    pub fn file_path(&self, label: &str) -> PathBuf {
        let ordinal = SPILL_ORDINAL.fetch_add(1, Ordering::Relaxed);
        self.path.join(format!("{label}.{ordinal}"))
    }
}

impl Drop for SpillDirectory {
    fn drop(&mut self) {
        // Best effort: a directory left by a failed removal or a crash holds
        // only private scratch and can be removed by the operator.
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Where spilled runs live.
#[derive(Clone, Debug)]
pub enum SpillStorage {
    /// Files in one private scratch directory on real disk.
    Directory(Arc<SpillDirectory>),
    /// Process memory, for callers without a filesystem root.
    Memory,
}

impl SpillStorage {
    /// Creates a private scratch directory inside `parent`.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when the directory cannot be created.
    pub fn directory(parent: &Path, prefix: &str) -> io::Result<Self> {
        SpillDirectory::create(parent, prefix).map(Self::Directory)
    }
}

impl From<&Self> for SpillStorage {
    fn from(storage: &Self) -> Self {
        storage.clone()
    }
}

impl From<&Arc<SpillDirectory>> for SpillStorage {
    fn from(directory: &Arc<SpillDirectory>) -> Self {
        Self::Directory(Arc::clone(directory))
    }
}

/// One finished run of fixed-width records, removed when dropped.
#[derive(Debug)]
pub struct SpillFile {
    contents: SpillContents,
    records: u64,
}

#[derive(Debug)]
enum SpillContents {
    Disk {
        path: PathBuf,
        _directory: Arc<SpillDirectory>,
    },
    Memory(Arc<[u8]>),
}

impl SpillFile {
    /// Returns the number of records in the run.
    #[must_use]
    pub const fn records(&self) -> u64 {
        self.records
    }

    /// Opens a sequential reader over the run's records.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when an on-disk run cannot be opened.
    pub fn reader<const N: usize>(&self) -> io::Result<RecordReader<N>> {
        Ok(RecordReader {
            source: ReaderSource::open(&self.contents)?,
            remaining: self.records,
        })
    }

    /// Opens a sequential reader over a run written by [`FrameWriter`].
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when an on-disk run cannot be opened.
    pub fn frames(&self) -> io::Result<FrameReader> {
        Ok(FrameReader {
            source: ReaderSource::open(&self.contents)?,
            remaining: self.records,
        })
    }
}

impl Drop for SpillFile {
    fn drop(&mut self) {
        if let SpillContents::Disk { path, .. } = &self.contents {
            let _ = fs::remove_file(path);
        }
    }
}

/// Destination of one run while it is being written.
enum WriterSink {
    Disk {
        path: PathBuf,
        directory: Arc<SpillDirectory>,
        writer: BufWriter<File>,
    },
    Memory(Vec<u8>),
}

impl WriterSink {
    fn create(storage: SpillStorage, label: &str) -> io::Result<Self> {
        Ok(match storage {
            SpillStorage::Directory(directory) => {
                let path = directory.file_path(label);
                let handle = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                Self::Disk {
                    path,
                    directory,
                    writer: BufWriter::with_capacity(IO_BUFFER_BYTES, handle),
                }
            }
            SpillStorage::Memory => Self::Memory(Vec::new()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Disk { writer, .. } => writer.write_all(bytes),
            Self::Memory(buffer) => {
                buffer.extend_from_slice(bytes);
                Ok(())
            }
        }
    }

    fn finish(self, records: u64) -> io::Result<SpillFile> {
        let contents = match self {
            Self::Disk {
                path,
                directory,
                mut writer,
            } => {
                writer.flush()?;
                SpillContents::Disk {
                    path,
                    _directory: directory,
                }
            }
            Self::Memory(bytes) => SpillContents::Memory(bytes.into()),
        };
        Ok(SpillFile { contents, records })
    }
}

/// Origin of one run while it is being read.
enum ReaderSource {
    Disk(BufReader<File>),
    Memory { bytes: Arc<[u8]>, offset: usize },
}

impl ReaderSource {
    fn open(contents: &SpillContents) -> io::Result<Self> {
        Ok(match contents {
            SpillContents::Disk { path, .. } => {
                Self::Disk(BufReader::with_capacity(IO_BUFFER_BYTES, File::open(path)?))
            }
            SpillContents::Memory(bytes) => Self::Memory {
                bytes: Arc::clone(bytes),
                offset: 0,
            },
        })
    }

    fn read_exact(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        match self {
            Self::Disk(reader) => reader.read_exact(buffer),
            Self::Memory { bytes, offset } => {
                let end = offset
                    .checked_add(buffer.len())
                    .filter(|end| *end <= bytes.len())
                    .ok_or_else(|| corrupt("in-memory spill run is truncated"))?;
                buffer.copy_from_slice(&bytes[*offset..end]);
                *offset = end;
                Ok(())
            }
        }
    }
}

/// Append-only writer for one run of fixed-width records.
pub struct SpillWriter<const N: usize> {
    sink: WriterSink,
    records: u64,
}

impl<const N: usize> SpillWriter<N> {
    /// Starts a new run in `storage`.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when an on-disk run cannot be created.
    pub fn create(storage: impl Into<SpillStorage>, label: &str) -> io::Result<Self> {
        Ok(Self {
            sink: WriterSink::create(storage.into(), label)?,
            records: 0,
        })
    }

    /// Appends one record.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when an on-disk write fails.
    pub fn push(&mut self, record: &[u8; N]) -> io::Result<()> {
        self.sink.write(record)?;
        self.records += 1;
        Ok(())
    }

    /// Returns the number of records appended so far.
    #[must_use]
    pub const fn records(&self) -> u64 {
        self.records
    }

    /// Flushes and closes the run.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when an on-disk flush fails.
    pub fn finish(self) -> io::Result<SpillFile> {
        self.sink.finish(self.records)
    }
}

/// Sequential reader over one run of fixed-width records.
pub struct RecordReader<const N: usize> {
    source: ReaderSource,
    remaining: u64,
}

impl<const N: usize> RecordReader<N> {
    /// Returns the next record, or `None` after the recorded count.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error for a failed or short read.
    pub fn next_record(&mut self) -> io::Result<Option<[u8; N]>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let mut record = [0_u8; N];
        self.source.read_exact(&mut record)?;
        self.remaining -= 1;
        Ok(Some(record))
    }
}

/// Append-only writer for one run of length-prefixed byte strings.
pub struct FrameWriter {
    sink: WriterSink,
    frames: u64,
}

impl FrameWriter {
    /// Starts a new frame run in `storage`.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when an on-disk run cannot be created.
    pub fn create(storage: impl Into<SpillStorage>, label: &str) -> io::Result<Self> {
        Ok(Self {
            sink: WriterSink::create(storage.into(), label)?,
            frames: 0,
        })
    }

    /// Appends one frame.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for a frame longer than
    /// `u32::MAX` bytes, or the filesystem error when an on-disk write fails.
    pub fn push(&mut self, frame: &[u8]) -> io::Result<()> {
        let length = u32::try_from(frame.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "spill frame is too long"))?;
        self.sink.write(&length.to_be_bytes())?;
        self.sink.write(frame)?;
        self.frames += 1;
        Ok(())
    }

    /// Flushes and closes the run.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when an on-disk flush fails.
    pub fn finish(self) -> io::Result<SpillFile> {
        self.sink.finish(self.frames)
    }
}

/// Sequential reader over one run of length-prefixed byte strings.
pub struct FrameReader {
    source: ReaderSource,
    remaining: u64,
}

impl FrameReader {
    /// Returns the next frame, or `None` after the recorded count.
    ///
    /// A frame longer than `maximum` bytes is rejected before it is read, so
    /// a damaged length prefix cannot force a large allocation.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidData`] for an oversized frame, or the
    /// filesystem error for a failed or short read.
    pub fn next_frame(&mut self, maximum: usize) -> io::Result<Option<Vec<u8>>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let mut length = [0_u8; 4];
        self.source.read_exact(&mut length)?;
        let length = usize::try_from(u32::from_be_bytes(length))
            .ok()
            .filter(|length| *length <= maximum)
            .ok_or_else(|| corrupt("spill frame exceeds its bound"))?;
        let mut frame = vec![0_u8; length];
        self.source.read_exact(&mut frame)?;
        self.remaining -= 1;
        Ok(Some(frame))
    }
}

/// Forward-only membership test over one sorted, deduplicated run.
pub struct SortedRecords<const N: usize> {
    reader: RecordReader<N>,
    head: Option<[u8; N]>,
}

impl<const N: usize> SortedRecords<N> {
    /// Opens a cursor at the first record of `file`.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when the run cannot be read.
    pub fn open(file: &SpillFile) -> io::Result<Self> {
        let mut reader = file.reader::<N>()?;
        let head = reader.next_record()?;
        Ok(Self { reader, head })
    }

    /// Reports membership; keys must be queried in nondecreasing order.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when the run cannot be read.
    pub fn contains(&mut self, key: &[u8; N]) -> io::Result<bool> {
        while self.head.is_some_and(|head| head < *key) {
            self.head = self.reader.next_record()?;
        }
        Ok(self.head.as_ref() == Some(key))
    }
}

/// External sorter that yields its records in byte order.
///
/// A sorter made with [`Self::new`] yields each distinct record once; one made
/// with [`Self::new_retaining_duplicates`] keeps every pushed record so the
/// consumer can detect repeats.
pub struct ExternalSorter<const N: usize> {
    storage: SpillStorage,
    label: &'static str,
    buffer: Vec<[u8; N]>,
    run_records: usize,
    runs: Vec<SpillFile>,
    deduplicate: bool,
}

impl<const N: usize> ExternalSorter<N> {
    /// Creates a deduplicating sorter that spills runs of `run_records`.
    #[must_use]
    pub fn new(storage: impl Into<SpillStorage>, label: &'static str, run_records: usize) -> Self {
        Self::with_policy(storage.into(), label, run_records, true)
    }

    /// Creates a sorter that keeps repeated records adjacent in its output.
    #[must_use]
    pub fn new_retaining_duplicates(
        storage: impl Into<SpillStorage>,
        label: &'static str,
        run_records: usize,
    ) -> Self {
        Self::with_policy(storage.into(), label, run_records, false)
    }

    fn with_policy(
        storage: SpillStorage,
        label: &'static str,
        run_records: usize,
        deduplicate: bool,
    ) -> Self {
        Self {
            storage,
            label,
            buffer: Vec::new(),
            run_records: run_records.max(1),
            runs: Vec::new(),
            deduplicate,
        }
    }

    /// Adds one record, spilling a sorted run once the buffer is full.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when a run cannot be spilled.
    pub fn push(&mut self, record: [u8; N]) -> io::Result<()> {
        if self.buffer.len() >= self.run_records {
            self.spill()?;
        }
        self.buffer.push(record);
        Ok(())
    }

    /// Merges every record into one sorted run.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error when a run cannot be written or merged.
    pub fn finish(mut self) -> io::Result<SpillFile> {
        if !self.buffer.is_empty() || self.runs.is_empty() {
            self.spill()?;
        }
        // Merging in fan-in-sized groups keeps the open readers bounded even
        // when the set produced more runs than one merge may read.
        while self.runs.len() > 1 {
            let mut merged = Vec::with_capacity(self.runs.len().div_ceil(MAX_MERGE_FAN_IN));
            let mut runs = std::mem::take(&mut self.runs).into_iter().peekable();
            while runs.peek().is_some() {
                let group = runs.by_ref().take(MAX_MERGE_FAN_IN).collect::<Vec<_>>();
                merged.push(merge_runs::<N>(
                    &self.storage,
                    self.label,
                    &group,
                    self.deduplicate,
                )?);
            }
            self.runs = merged;
        }
        self.runs
            .pop()
            .ok_or_else(|| io::Error::other("external sorter produced no run"))
    }

    fn spill(&mut self) -> io::Result<()> {
        self.buffer.sort_unstable();
        if self.deduplicate {
            self.buffer.dedup();
        }
        let mut writer = SpillWriter::<N>::create(&self.storage, self.label)?;
        for record in &self.buffer {
            writer.push(record)?;
        }
        self.runs.push(writer.finish()?);
        self.buffer.clear();
        Ok(())
    }
}

fn merge_runs<const N: usize>(
    storage: &SpillStorage,
    label: &str,
    runs: &[SpillFile],
    deduplicate: bool,
) -> io::Result<SpillFile> {
    let mut readers = runs
        .iter()
        .map(SpillFile::reader::<N>)
        .collect::<io::Result<Vec<_>>>()?;
    let mut heap = BinaryHeap::with_capacity(readers.len());
    for (index, reader) in readers.iter_mut().enumerate() {
        if let Some(record) = reader.next_record()? {
            heap.push(Reverse((record, index)));
        }
    }

    let mut writer = SpillWriter::<N>::create(storage, label)?;
    let mut previous = None;
    while let Some(Reverse((record, index))) = heap.pop() {
        if !deduplicate || previous != Some(record) {
            writer.push(&record)?;
            previous = Some(record);
        }
        if let Some(next) = readers[index].next_record()? {
            heap.push(Reverse((next, index)));
        }
    }
    writer.finish()
}

#[cfg(test)]
mod tests;
