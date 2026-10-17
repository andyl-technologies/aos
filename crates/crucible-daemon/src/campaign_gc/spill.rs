//! Private scratch storage and external sorting for GC planning and apply.
//!
//! Closure, root, and inventory sets can each hold up to the manifest entry
//! bound, so GC keeps them as sorted runs on disk instead of in memory. A run
//! holds fixed-width records whose byte order is their canonical order:
//!
//! ```text
//! id record (37 bytes):
//!   kind rank:u8              # rank of the kind's wire tag in byte order
//!   schema version:u32be
//!   digest[32]
//! ```
//!
//! so comparing records with `memcmp` matches the manifests' (kind tag,
//! schema version, digest) order. Larger records append fields after the id.
//! Records never leave the process and are not a published format.
//!
//! ```text
//! placement record (45 bytes): id record || logical_length:u64be
//! ```
//!
//! [`sort_inventory`] spills one fenced physical inventory as sorted
//! placement records. It keeps repeats, so a consumer can reject an
//! inventory that lists one object twice.
//!
//! [`ExternalSorter`] buffers at most one run in memory, spills each full run
//! sorted, and merges at most [`MAX_MERGE_FAN_IN`] runs at a time, so memory
//! is bounded by the run size and fan-in, not by the set size. Every file
//! lives in one [`GcWorkDirectory`], created owner-only beside the caller's
//! durable state and removed with its contents when the last handle drops.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_cas::content_store::{
    BlobInventoryFence, BlobInventorySummary, ContentId, ObjectKind, StoreError,
};

/// Width of one spilled content-identity record.
pub(super) const ID_RECORD_BYTES: usize = 37;

/// Records buffered in memory before a sorter spills a run.
pub(super) const RUN_RECORDS: usize = 1 << 18;

/// Maximum number of runs read at once by one merge.
pub(super) const MAX_MERGE_FAN_IN: usize = 128;

const IO_BUFFER_BYTES: usize = 64 * 1024;

/// Distinguishes work directories and files created by one process.
static SPILL_ORDINAL: AtomicU64 = AtomicU64::new(0);

/// One fixed-width spilled content identity.
pub(super) type IdRecord = [u8; ID_RECORD_BYTES];

/// Width of one spilled physical placement record.
pub(super) const PLACEMENT_RECORD_BYTES: usize = ID_RECORD_BYTES + 8;

/// One spilled physical placement: identity and logical length.
pub(super) type PlacementRecord = [u8; PLACEMENT_RECORD_BYTES];

/// Object kinds ordered by their wire tag, which is the manifest order.
const KINDS_BY_TAG: [ObjectKind; 14] = [
    ObjectKind::CampaignFact,
    ObjectKind::CampaignSnapshot,
    ObjectKind::Configuration,
    ObjectKind::DeviceState,
    ObjectKind::DiskExtent,
    ObjectKind::ExactManifest,
    ObjectKind::Finding,
    ObjectKind::MerkleNode,
    ObjectKind::Observation,
    ObjectKind::Policy,
    ObjectKind::Projection,
    ObjectKind::RamExtent,
    ObjectKind::Scenario,
    ObjectKind::Trace,
];

const fn kind_rank(kind: ObjectKind) -> u8 {
    // An exhaustive match makes a new kind a compile error here rather than
    // a silent ordering hole; the table above must gain the same entry.
    match kind {
        ObjectKind::CampaignFact => 0,
        ObjectKind::CampaignSnapshot => 1,
        ObjectKind::Configuration => 2,
        ObjectKind::DeviceState => 3,
        ObjectKind::DiskExtent => 4,
        ObjectKind::ExactManifest => 5,
        ObjectKind::Finding => 6,
        ObjectKind::MerkleNode => 7,
        ObjectKind::Observation => 8,
        ObjectKind::Policy => 9,
        ObjectKind::Projection => 10,
        ObjectKind::RamExtent => 11,
        ObjectKind::Scenario => 12,
        ObjectKind::Trace => 13,
    }
}

/// Encodes one identity as an order-preserving fixed-width record.
pub(super) fn encode_id(id: ContentId) -> IdRecord {
    let mut record = [0_u8; ID_RECORD_BYTES];
    record[0] = kind_rank(id.kind());
    record[1..5].copy_from_slice(&id.schema_version().to_be_bytes());
    record[5..].copy_from_slice(&id.digest());
    record
}

/// Decodes one identity record written by [`encode_id`].
pub(super) fn decode_id(record: &[u8]) -> io::Result<ContentId> {
    let kind = record
        .first()
        .and_then(|rank| KINDS_BY_TAG.get(usize::from(*rank)))
        .copied()
        .ok_or_else(|| corrupt("GC spill record has an unknown object kind"))?;
    let schema = record
        .get(1..5)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .ok_or_else(|| corrupt("GC spill record is truncated"))?;
    let digest = record
        .get(5..ID_RECORD_BYTES)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| corrupt("GC spill record is truncated"))?;
    Ok(ContentId::from_parts(
        kind,
        u32::from_be_bytes(schema),
        digest,
    ))
}

/// Encodes one physical placement as an order-preserving record.
pub(super) fn placement_record(id: ContentId, logical_length: u64) -> PlacementRecord {
    let mut record = [0_u8; PLACEMENT_RECORD_BYTES];
    record[..ID_RECORD_BYTES].copy_from_slice(&encode_id(id));
    record[ID_RECORD_BYTES..].copy_from_slice(&logical_length.to_be_bytes());
    record
}

/// Returns a placement record's identity prefix.
pub(super) fn placement_id(record: &PlacementRecord) -> IdRecord {
    field(record, 0)
}

/// Returns a placement record's logical length.
pub(super) fn placement_length(record: &PlacementRecord) -> u64 {
    u64::from_be_bytes(field(record, ID_RECORD_BYTES))
}

/// Copies a fixed-width field out of a record whose layout fixes its bounds.
pub(super) fn field<const N: usize>(record: &[u8], offset: usize) -> [u8; N] {
    let mut value = [0_u8; N];
    value.copy_from_slice(&record[offset..offset + N]);
    value
}

/// Failure to spill one fenced physical inventory.
pub(super) enum InventorySortError {
    /// The fenced backend failed or reported an incomplete inventory.
    Store(StoreError),
    /// Scratch storage failed.
    Spill(io::Error),
}

/// Visits one fenced inventory into a sorted placement run.
///
/// Repeated placements stay adjacent in the output. A spill failure aborts
/// the visit and takes precedence over the store error that abort produces.
pub(super) fn sort_inventory(
    fence: &mut dyn BlobInventoryFence,
    directory: &Arc<GcWorkDirectory>,
) -> Result<(BlobInventorySummary, SpillFile), InventorySortError> {
    let mut sorter = ExternalSorter::<PLACEMENT_RECORD_BYTES>::new_retaining_duplicates(
        directory,
        "placements",
        RUN_RECORDS,
    );
    let mut spill_error = None;
    let visited = fence.visit_inventory(&mut |record| {
        sorter
            .push(placement_record(record.id(), record.logical_length()))
            .map_err(|source| {
                spill_error = Some(source);
                StoreError::InvalidComposition {
                    reason: "campaign GC inventory spill failed",
                }
            })
    });
    if let Some(source) = spill_error {
        return Err(InventorySortError::Spill(source));
    }
    let summary = visited.map_err(InventorySortError::Store)?;
    let placements = sorter.finish().map_err(InventorySortError::Spill)?;
    Ok((summary, placements))
}

fn corrupt(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// Owner-only scratch directory removed with its contents on drop.
#[derive(Debug)]
pub(super) struct GcWorkDirectory {
    path: PathBuf,
}

impl GcWorkDirectory {
    /// Creates a new private directory inside the existing `parent`.
    pub(super) fn create(parent: &Path) -> io::Result<Arc<Self>> {
        let ordinal = SPILL_ORDINAL.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".crucible-gc-spill.{}.{ordinal}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Arc::new(Self { path }))
    }

    /// Returns a fresh file path inside this directory.
    pub(super) fn file_path(&self, label: &str) -> PathBuf {
        let ordinal = SPILL_ORDINAL.fetch_add(1, Ordering::Relaxed);
        self.path.join(format!("{label}.{ordinal}"))
    }
}

impl Drop for GcWorkDirectory {
    fn drop(&mut self) {
        // Best effort: a directory left by a failed removal or a crash holds
        // only private scratch and can be removed by the operator.
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// One scratch file, removed when dropped.
#[derive(Debug)]
pub(super) struct SpillFile {
    path: PathBuf,
    records: u64,
    _directory: Arc<GcWorkDirectory>,
}

impl SpillFile {
    /// Returns the number of records in the file.
    pub(super) const fn records(&self) -> u64 {
        self.records
    }

    /// Opens a sequential reader over the file's records.
    pub(super) fn reader<const N: usize>(&self) -> io::Result<RecordReader<N>> {
        RecordReader::open(&self.path, self.records)
    }
}

impl Drop for SpillFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Append-only writer for one scratch file of fixed-width records.
pub(super) struct SpillWriter<const N: usize> {
    file: Option<SpillFile>,
    writer: BufWriter<File>,
}

impl<const N: usize> SpillWriter<N> {
    pub(super) fn create(directory: &Arc<GcWorkDirectory>, label: &str) -> io::Result<Self> {
        let path = directory.file_path(label);
        let handle = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        Ok(Self {
            file: Some(SpillFile {
                path,
                records: 0,
                _directory: Arc::clone(directory),
            }),
            writer: BufWriter::with_capacity(IO_BUFFER_BYTES, handle),
        })
    }

    pub(super) fn push(&mut self, record: &[u8; N]) -> io::Result<()> {
        self.writer.write_all(record)?;
        if let Some(file) = self.file.as_mut() {
            file.records += 1;
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> io::Result<SpillFile> {
        self.writer.flush()?;
        self.file
            .take()
            .ok_or_else(|| io::Error::other("GC spill writer finished twice"))
    }
}

/// Sequential reader over one file of fixed-width records.
pub(super) struct RecordReader<const N: usize> {
    reader: BufReader<File>,
    remaining: u64,
}

impl<const N: usize> RecordReader<N> {
    fn open(path: &Path, records: u64) -> io::Result<Self> {
        Ok(Self {
            reader: BufReader::with_capacity(IO_BUFFER_BYTES, File::open(path)?),
            remaining: records,
        })
    }

    /// Returns the next record, or `None` after the recorded count.
    pub(super) fn next_record(&mut self) -> io::Result<Option<[u8; N]>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let mut record = [0_u8; N];
        self.reader.read_exact(&mut record)?;
        self.remaining -= 1;
        Ok(Some(record))
    }
}

/// Forward-only membership test over one sorted, deduplicated id file.
pub(super) struct SortedIds {
    reader: RecordReader<ID_RECORD_BYTES>,
    head: Option<IdRecord>,
}

impl SortedIds {
    /// Opens a cursor at the first id of `file`.
    pub(super) fn open(file: &SpillFile) -> io::Result<Self> {
        let mut reader = file.reader::<ID_RECORD_BYTES>()?;
        let head = reader.next_record()?;
        Ok(Self { reader, head })
    }

    /// Reports membership; keys must be queried in increasing order.
    pub(super) fn contains(&mut self, key: &IdRecord) -> io::Result<bool> {
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
pub(super) struct ExternalSorter<const N: usize> {
    directory: Arc<GcWorkDirectory>,
    label: &'static str,
    buffer: Vec<[u8; N]>,
    run_records: usize,
    runs: Vec<SpillFile>,
    deduplicate: bool,
}

impl<const N: usize> ExternalSorter<N> {
    /// Creates a deduplicating sorter that spills runs of `run_records`.
    pub(super) fn new(
        directory: &Arc<GcWorkDirectory>,
        label: &'static str,
        run_records: usize,
    ) -> Self {
        Self::with_policy(directory, label, run_records, true)
    }

    /// Creates a sorter that keeps repeated records adjacent in its output.
    pub(super) fn new_retaining_duplicates(
        directory: &Arc<GcWorkDirectory>,
        label: &'static str,
        run_records: usize,
    ) -> Self {
        Self::with_policy(directory, label, run_records, false)
    }

    fn with_policy(
        directory: &Arc<GcWorkDirectory>,
        label: &'static str,
        run_records: usize,
        deduplicate: bool,
    ) -> Self {
        Self {
            directory: Arc::clone(directory),
            label,
            buffer: Vec::new(),
            run_records: run_records.max(1),
            runs: Vec::new(),
            deduplicate,
        }
    }

    pub(super) fn push(&mut self, record: [u8; N]) -> io::Result<()> {
        if self.buffer.len() >= self.run_records {
            self.spill()?;
        }
        self.buffer.push(record);
        Ok(())
    }

    /// Merges every record into one sorted scratch file.
    pub(super) fn finish(mut self) -> io::Result<SpillFile> {
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
                    &self.directory,
                    self.label,
                    &group,
                    self.deduplicate,
                )?);
            }
            self.runs = merged;
        }
        self.runs
            .pop()
            .ok_or_else(|| io::Error::other("GC external sorter produced no run"))
    }

    fn spill(&mut self) -> io::Result<()> {
        self.buffer.sort_unstable();
        if self.deduplicate {
            self.buffer.dedup();
        }
        let mut writer = SpillWriter::<N>::create(&self.directory, self.label)?;
        for record in &self.buffer {
            writer.push(record)?;
        }
        self.runs.push(writer.finish()?);
        self.buffer.clear();
        Ok(())
    }
}

fn merge_runs<const N: usize>(
    directory: &Arc<GcWorkDirectory>,
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

    let mut writer = SpillWriter::<N>::create(directory, label)?;
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
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture failures localize exact spill behavior.
    #![allow(clippy::expect_used)]

    use super::*;

    fn id(kind: ObjectKind, schema: u32, seed: u8) -> ContentId {
        ContentId::for_bytes(kind, schema, &[seed])
    }

    fn read_ids(file: &SpillFile) -> Vec<ContentId> {
        let mut reader = file.reader::<ID_RECORD_BYTES>().expect("open spill file");
        let mut ids = Vec::new();
        while let Some(record) = reader.next_record().expect("read spill record") {
            ids.push(decode_id(&record).expect("decode spill record"));
        }
        ids
    }

    #[test]
    fn kind_ranks_follow_wire_tag_order_and_round_trip() {
        for (rank, kind) in KINDS_BY_TAG.iter().enumerate() {
            assert_eq!(usize::from(kind_rank(*kind)), rank);
        }
        for pair in KINDS_BY_TAG.windows(2) {
            assert!(pair[0].as_str() < pair[1].as_str());
        }
        for kind in KINDS_BY_TAG {
            let original = id(kind, 7, 3);
            assert_eq!(decode_id(&encode_id(original)).expect("decode"), original);
        }
    }

    #[test]
    fn record_order_matches_manifest_identity_order() {
        let ids = [
            id(ObjectKind::Trace, 1, 1),
            id(ObjectKind::MerkleNode, 2, 1),
            id(ObjectKind::MerkleNode, 1, 2),
            id(ObjectKind::CampaignFact, 9, 3),
            id(ObjectKind::Scenario, 1, 4),
        ];
        let mut by_record = ids.to_vec();
        by_record.sort_by_key(|id| encode_id(*id));
        let mut by_manifest = ids.to_vec();
        by_manifest.sort_by(|left, right| {
            left.kind()
                .as_str()
                .cmp(right.kind().as_str())
                .then_with(|| left.schema_version().cmp(&right.schema_version()))
                .then_with(|| left.digest().cmp(&right.digest()))
        });
        assert_eq!(by_record, by_manifest);
    }

    #[test]
    fn external_sort_spills_merges_in_groups_and_deduplicates() {
        let parent = tempfile::tempdir().expect("spill parent");
        let directory = GcWorkDirectory::create(parent.path()).expect("work directory");
        // Three-record runs over 1,000 pushes force more runs than one merge
        // may read, so the result passes through a second merge level.
        let mut sorter = ExternalSorter::<ID_RECORD_BYTES>::new(&directory, "ids", 3);
        let mut expected = Vec::new();
        for value in 0..1_000_u32 {
            let seed = (value * 7_919 % 500) as u8;
            let schema = value % 500 / 256 + 1;
            let content = id(ObjectKind::Observation, schema, seed);
            sorter.push(encode_id(content)).expect("push id");
            expected.push(content);
        }
        expected.sort_by_key(|id| encode_id(*id));
        expected.dedup();

        let sorted = sorter.finish().expect("finish sort");

        assert_eq!(read_ids(&sorted), expected);
        assert_eq!(sorted.records(), expected.len() as u64);
    }

    #[test]
    fn retaining_sorter_keeps_repeated_records_adjacent() {
        let parent = tempfile::tempdir().expect("spill parent");
        let directory = GcWorkDirectory::create(parent.path()).expect("work directory");
        let mut sorter =
            ExternalSorter::<ID_RECORD_BYTES>::new_retaining_duplicates(&directory, "ids", 2);
        let repeated = id(ObjectKind::Finding, 1, 9);
        let other = id(ObjectKind::CampaignFact, 1, 4);
        for content in [repeated, other, repeated, repeated] {
            sorter.push(encode_id(content)).expect("push id");
        }

        let sorted = sorter.finish().expect("finish sort");

        assert_eq!(read_ids(&sorted), vec![other, repeated, repeated, repeated]);
    }

    #[test]
    fn empty_sorter_yields_an_empty_run() {
        let parent = tempfile::tempdir().expect("spill parent");
        let directory = GcWorkDirectory::create(parent.path()).expect("work directory");
        let sorter = ExternalSorter::<ID_RECORD_BYTES>::new(&directory, "ids", RUN_RECORDS);

        let sorted = sorter.finish().expect("finish sort");

        assert_eq!(sorted.records(), 0);
        assert!(read_ids(&sorted).is_empty());
    }

    #[test]
    fn work_directory_and_files_are_removed_when_the_last_handle_drops() {
        let parent = tempfile::tempdir().expect("spill parent");
        let directory = GcWorkDirectory::create(parent.path()).expect("work directory");
        let mut sorter = ExternalSorter::<ID_RECORD_BYTES>::new(&directory, "ids", 2);
        for seed in 0..5 {
            sorter
                .push(encode_id(id(ObjectKind::Trace, 1, seed)))
                .expect("push id");
        }
        let sorted = sorter.finish().expect("finish sort");
        drop(directory);
        assert_eq!(
            fs::read_dir(parent.path()).expect("parent").count(),
            1,
            "a live spill file keeps its work directory"
        );

        drop(sorted);

        assert_eq!(fs::read_dir(parent.path()).expect("parent").count(), 0);
    }
}
